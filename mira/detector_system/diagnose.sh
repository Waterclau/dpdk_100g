#!/bin/bash
# Diagnostic script for MIRA throughput issues

echo "========================================="
echo "MIRA Throughput Diagnostic"
echo "========================================="
echo ""

NIC_PCI="0000:41:00.0"

echo "[1] NIC Information:"
lspci -s $NIC_PCI -vvv | grep -E "Device|Speed|Width|Ethernet"
echo ""

echo "[2] Current NIC statistics (before test):"
ethtool -S $(ls /sys/bus/pci/devices/$NIC_PCI/net/) | head -20
echo ""

echo "[3] RSS configuration:"
ethtool -x $(ls /sys/bus/pci/devices/$NIC_PCI/net/) 2>/dev/null || echo "  RSS info not available"
echo ""

echo "[4] CPU frequency (should be at max):"
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq | head -5
echo "  (Expected: 2990000-3000000 kHz for max performance)"
echo ""

echo "[5] IRQ affinity for NIC:"
NIC_NAME=$(ls /sys/bus/pci/devices/$NIC_PCI/net/)
echo "  NIC name: $NIC_NAME"
grep $NIC_NAME /proc/interrupts | head -5
echo ""

echo "[6] Hugepages status:"
grep Huge /proc/meminfo
echo ""

echo "[7] NUMA nodes:"
numactl --hardware | grep -E "available|node.*cpus"
echo ""

echo "========================================="
echo "Recommendations:"
echo "========================================="
echo ""

# Check CPU frequency
MIN_FREQ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq)
MAX_FREQ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq)
CUR_FREQ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)

if [ "$CUR_FREQ" -lt "$MAX_FREQ" ]; then
    echo "⚠ CPU not at max frequency!"
    echo "  Run: sudo cpupower frequency-set -g performance"
    echo ""
fi

# Check hugepages
HUGEPAGES=$(grep HugePages_Total /proc/meminfo | awk '{print $2}')
if [ "$HUGEPAGES" -lt 1024 ]; then
    echo "⚠ Low hugepages!"
    echo "  Run: sudo dpdk-hugepages.py -p 2M --setup 4G"
    echo ""
fi

echo "✓ Run traffic generator with HIGH rate:"
echo "  - Use small packets (64-128 bytes)"
echo "  - Target >15-20 Gbps to saturate CPU"
echo "  - Vary source IPs to trigger RSS distribution"
echo ""

echo "✓ Monitor per-queue statistics:"
echo "  ethtool -S $NIC_NAME | grep rx_queue"
echo ""
