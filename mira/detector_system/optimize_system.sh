#!/bin/bash
# MIRA DDoS Detector - System Optimization Script
# Optimizes CPU and system settings for maximum packet processing throughput

set -e

echo "========================================="
echo "MIRA System Optimization for 25G Line Rate"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo)"
    exit 1
fi

echo "[1/7] Setting CPU governor to performance mode..."
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [ -f "$cpu" ]; then
        echo performance > "$cpu"
    fi
done
echo "  ✓ CPU governor set to performance"

echo ""
echo "[2/7] Disabling CPU idle states (C-states) for lower latency..."
for cpu in /sys/devices/system/cpu/cpu*/cpuidle/state*/disable; do
    if [ -f "$cpu" ]; then
        echo 1 > "$cpu"
    fi
done
echo "  ✓ CPU idle states disabled"

echo ""
echo "[3/7] Disabling IRQ balance (DPDK will handle affinity)..."
if systemctl is-active --quiet irqbalance; then
    systemctl stop irqbalance
    echo "  ✓ IRQ balance stopped"
else
    echo "  ℹ IRQ balance already stopped"
fi

echo ""
echo "[4/7] Setting NUMA balancing..."
if [ -f /proc/sys/kernel/numa_balancing ]; then
    echo 0 > /proc/sys/kernel/numa_balancing
    echo "  ✓ NUMA balancing disabled"
fi

echo ""
echo "[5/7] Increasing network buffer sizes..."
# Increase default and max socket buffer sizes
sysctl -w net.core.rmem_default=268435456 > /dev/null
sysctl -w net.core.rmem_max=268435456 > /dev/null
sysctl -w net.core.wmem_default=268435456 > /dev/null
sysctl -w net.core.wmem_max=268435456 > /dev/null
echo "  ✓ Network buffers increased to 256MB"

echo ""
echo "[6/7] Setting I/O scheduler to 'none' for NVMe/SSD..."
for disk in /sys/block/nvme*/queue/scheduler; do
    if [ -f "$disk" ]; then
        echo none > "$disk" 2>/dev/null || true
    fi
done
echo "  ✓ I/O scheduler optimized"

echo ""
echo "[7/7] Verifying hugepages..."
HUGEPAGES=$(cat /proc/meminfo | grep HugePages_Total | awk '{print $2}')
if [ "$HUGEPAGES" -gt 0 ]; then
    echo "  ✓ Hugepages configured: $HUGEPAGES pages"
else
    echo "  ⚠ WARNING: No hugepages configured!"
    echo "    Run: sudo dpdk-hugepages.py -p 2M --setup 2G"
fi

echo ""
echo "========================================="
echo "System optimization complete!"
echo "========================================="
echo ""
echo "Current system status:"
echo "  - CPU frequency: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo 'N/A') kHz"
echo "  - Hugepages: $HUGEPAGES pages"
echo ""
echo "To revert changes after testing:"
echo "  1. systemctl start irqbalance"
echo "  2. cpupower frequency-set -g powersave"
echo ""
echo "Now compile and run the detector:"
echo "  cd $(dirname $0)"
echo "  make clean && make"
echo "  sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0"
echo ""
