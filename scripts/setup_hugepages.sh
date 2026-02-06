#!/bin/bash
#
# setup_hugepages.sh - Configure huge pages for the io_uring server
#
# The buffer ring requires ~8MB (4096 buffers * 2KB each + ring overhead)
# Each huge page is 2MB, so we need at least 4 pages (8MB)
# Reserve 8 pages (16MB) to be safe
#

set -e

HUGEPAGES_REQUIRED=8

echo "=== Huge Pages Setup ==="
echo ""

# Check current status
echo "Current huge pages status:"
grep -i hugepages /proc/meminfo
echo ""

# Check if we have enough
CURRENT=$(cat /proc/sys/vm/nr_hugepages)
if [ "$CURRENT" -ge "$HUGEPAGES_REQUIRED" ]; then
    echo "Already have $CURRENT huge pages (need $HUGEPAGES_REQUIRED). OK."
    exit 0
fi

# Need root to configure
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root to configure huge pages"
    echo "Usage: sudo $0"
    exit 1
fi

# Reserve huge pages
echo "Reserving $HUGEPAGES_REQUIRED huge pages ($(($HUGEPAGES_REQUIRED * 2))MB)..."
echo $HUGEPAGES_REQUIRED > /proc/sys/vm/nr_hugepages

# Verify
NEW_TOTAL=$(cat /proc/sys/vm/nr_hugepages)
NEW_FREE=$(grep HugePages_Free /proc/meminfo | awk '{print $2}')

echo ""
echo "New huge pages status:"
grep -i hugepages /proc/meminfo
echo ""

if [ "$NEW_FREE" -ge "$HUGEPAGES_REQUIRED" ]; then
    echo "SUCCESS: $NEW_FREE huge pages available"
else
    echo "WARNING: Only $NEW_FREE free huge pages (requested $HUGEPAGES_REQUIRED)"
    echo "         System may be under memory pressure"
fi
