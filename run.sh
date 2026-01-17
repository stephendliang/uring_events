#!/bin/bash
set -e

CC="${CC:-gcc}"
CFLAGS="-std=gnu11 -Wall -Wextra"

# Maximal optimization flags
OPT_FLAGS=(
    -O3
    -march=native              # Use all CPU features available
    -mtune=native              # Tune for this specific CPU
    -fomit-frame-pointer       # Free up RBP register
    -fno-stack-protector       # No stack canaries (perf)
    -fno-plt                   # Direct calls, no PLT indirection
    -ffast-math                # Aggressive FP optimizations (not used here, but doesn't hurt)
    -flto                      # Link-time optimization
    -fno-semantic-interposition # Better inlining with LTO
    -fvisibility=hidden        # Hide symbols by default
    -DNDEBUG                   # Disable asserts
)

# Optional: PGO (Profile-Guided Optimization) - uncomment for 2-pass build
# PASS1: -fprofile-generate
# PASS2: -fprofile-use

echo "=== Compiler ==="
$CC --version | head -1

echo ""
echo "=== Building with flags ==="
echo "${OPT_FLAGS[*]}"
echo ""

$CC $CFLAGS "${OPT_FLAGS[@]}" event.c -o event

echo "=== Binary info ==="
ls -la event
file event
echo ""

echo "=== Hugepage status ==="
echo "HugePages configured:"
grep -E "^Huge" /proc/meminfo
echo ""

# Check if we can allocate hugepages
echo "Attempting to reserve 64 x 2MB hugepages for testing..."
CURRENT=$(cat /proc/sys/vm/nr_hugepages)
if [ "$CURRENT" -eq 0 ]; then
    echo "No hugepages currently reserved."
    echo "To enable (requires root): echo 64 > /proc/sys/vm/nr_hugepages"
    echo ""

    # Try to allocate if we're root
    if [ "$(id -u)" -eq 0 ]; then
        echo "Running as root, attempting to allocate..."
        echo 64 > /proc/sys/vm/nr_hugepages 2>/dev/null || true
        sleep 0.1
        NEW=$(cat /proc/sys/vm/nr_hugepages)
        if [ "$NEW" -gt 0 ]; then
            echo "Successfully allocated $NEW hugepages!"
            grep -E "^Huge" /proc/meminfo
        else
            echo "Failed to allocate hugepages (memory fragmentation?)"
        fi
    fi
else
    echo "Hugepages already available: $CURRENT"
fi
echo ""

echo "=== Starting server on port ${1:-8080} (CPU ${2:-0}) ==="
PORT="${1:-8080}"
CPU="${2:-0}"
./event "$PORT" "$CPU" &
PID=$!
sleep 0.3

if kill -0 $PID 2>/dev/null; then
    echo "Server running (PID: $PID)"
    ss -tlnp | grep ":$PORT" || true
    echo ""
    echo "Press Ctrl+C to stop..."
    wait $PID
else
    echo "Server failed to start!"
    exit 1
fi
