#!/bin/bash
# VPS Unikernel Optimization - Run after RAM/CPU upgrade
# Configures CPU isolation and 1GB hugepages

set -e

# Backup current grub config
cp /etc/default/grub /etc/default/grub.bak

# New kernel parameters for unikernel-like setup
UNIKERNEL_PARAMS="isolcpus=1 nohz_full=1 rcu_nocbs=1 hugepagesz=1G hugepages=1 default_hugepagesz=1G nosoftlockup nowatchdog mitigations=off"

# Update GRUB_CMDLINE_LINUX_DEFAULT
sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"loglevel=3 $UNIKERNEL_PARAMS\"/" /etc/default/grub

echo "Updated /etc/default/grub with:"
echo "  $UNIKERNEL_PARAMS"
echo ""
echo "Review changes:"
grep "GRUB_CMDLINE_LINUX" /etc/default/grub
echo ""
echo "To apply, run:"
echo "  grub-mkconfig -o /boot/grub/grub.cfg"
echo "  reboot"
echo ""
echo "After reboot, verify with:"
echo "  cat /proc/cmdline"
echo "  cat /proc/meminfo | grep -i huge"
echo "  cat /sys/devices/system/cpu/isolated"
