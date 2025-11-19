# HTTP Flood Experiment - Complete Setup Guide

## Prerequisites
- Repository cloned on both nodes
- Network interfaces connected (100G link)
- Root access on both machines

---

## Node 1: Detector (DPDK)

### Step 1: Configure Hugepages

```bash
# Check current hugepages
cat /proc/meminfo | grep Huge

# Configure hugepages (2GB)
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Mount hugepages (if not already mounted)
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Verify
cat /proc/meminfo | grep Huge
```

### Step 2: Configure Network Interface for DPDK

**IMPORTANT:** You have Mellanox ConnectX-5 NICs which use the mlx5 PMD. These work with DPDK **without unbinding** from the kernel driver.

```bash
# Check network interfaces
dpdk-devbind.py --status

# Your interfaces:
# 0000:41:00.0 'MT27800 Family [ConnectX-5]' if=ens1f0 drv=mlx5_core
# 0000:41:00.1 'MT27800 Family [ConnectX-5]' if=ens1f1 drv=mlx5_core

# For Mellanox NICs, you DON'T need to unbind from kernel
# DPDK uses mlx5 PMD which works alongside mlx5_core driver

# Just ensure the interface is UP
sudo ip link set ens1f0 up

# Verify interface is active
ip link show ens1f0
```

**Note:** The mlx5 PMD requires:
- `libibverbs` installed
- `libmlx5` installed
- Interface must be UP (not down)

### Step 3: Build the Detector

```bash
cd /local/dpdk_100g/http_flood_advance/detector_system
 sudo apt-get update
  sudo apt-get install -y dpdk dpdk-dev libdpdk-dev
# Clean and build
make clean
make

# Verify build
ls -la build/http_flood_detector
```

### Step 4: Create Results Directory

```bash
mkdir -p /local/dpdk_100g/results
```

### Step 5: Run the Detector

```bash
cd /local/dpdk_100g/http_flood_advance/detector_system

# Run detector for 510 seconds (experiment + margin)
# For Mellanox ConnectX-5, use the PCI address with -a flag
sudo rm -rf /var/run/dpdk/*
sudo rm -rf /dev/hugepages/*
sudo umount /mnt/huge 2>/dev/null
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
grep Huge /proc/meminfo
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages


sudo timeout 510 ./http_flood_detector -l 1-2 -n 4 -w 0000:41:00.0 -- -p 0 #2>&1 | tee ../../results/results_http_flood_500s_2.log
```

**Parameters:**
- `-l 1-2`: Use CPU cores 1-2
- `-n 4`: 4 memory channels
- `-w 0000:41:00.0`: PCI address of NIC (ens1f0)
- `-- -p 0`: Port 0
- `timeout 510`: Run for 510 seconds

**Alternative if -a doesn't work:**
```bash
# Use --vdev for mlx5 devices
sudo timeout 510 ./build/http_flood_detector -l 1-2 -n 4 --vdev="net_mlx5_0,iface=ens1f0" -- -p 0 2>&1 | tee ../../results/results_http_flood_500s_2.log
```

---

## Node 2: Traffic Generator (tcpreplay)

### Step 1: Verify Network Interface

```bash
# Check interface is up
sudo ip link show ens1f0

# If down, bring it up
sudo ip link set ens1f0 up

# Verify
ifconfig ens1f0
```

### Step 2: Verify PCAP Files

```bash
cd /local/dpdk_100g/http_flood_advance

# Check pcap files exist
ls -lh *.pcap

# Should see:
# - baseline_5M.pcap
# - attack_mixed_1M.pcap
```

### Step 3: Wait for Detector to Start

Wait 5 seconds after starting the detector on Node 1 before generating traffic.

### Step 4: Start Baseline Traffic (0-500 seconds)

```bash
cd /local/dpdk_100g/http_flood_advance

# 25 instances × 50,000 pps = 1.25M pps (~7 Gbps, ~28% of 25G link)
for i in {1..25}; do
    sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=50000 --loop=0 --quiet baseline_5M.pcap &
done

# Verify processes started
ps aux | grep tcpreplay | wc -l
# Should show ~25 processes
```

### Step 5: Start Attack Traffic (after 200 seconds)

**Wait 200 seconds** after starting baseline, then run:

```bash
cd /local/dpdk_100g/http_flood_advance

# 50 instances × 37,500 pps = 1.875M pps (~10.5 Gbps)
# Total with baseline: ~3.125M pps (~17.5 Gbps, ~70% of 25G link)
# Ratio: 40% baseline / 60% attack
for i in {1..50}; do
    sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=37500 --loop=0 --quiet attack_mixed_1M.pcap &
done

# Verify processes
ps aux | grep tcpreplay | wc -l
# Should show ~75 processes (25 baseline + 50 attack)
```

---

## Timeline

```
Time    Node 1 (Detector)              Node 2 (Traffic Generator)
────────────────────────────────────────────────────────────────────
0s      Start detector                 -
5s      -                              Start baseline (25 instances)
5-200s  Monitoring baseline            Baseline running (~1.25M pps, ~7 Gbps)
205s    -                              Start attack (50 instances)
205-500s Detecting attack              Baseline + Attack (~3.125M pps, ~17.5 Gbps)
500s    -                              Traffic stops
510s    Detector stops                 -
```

---

## Monitoring (Optional)

### On Node 1 (Detector)

```bash
# Watch detector output in real-time
tail -f /local/dpdk_100g/results/results_http_flood_500s_2.log
```

### On Node 2 (Traffic Generator)

```bash
# Monitor network throughput
watch -n 1 'sar -n DEV 1 1 | grep ens1f0'

# Or with ifstat
ifstat -i ens1f0 1

# Count active tcpreplay processes
watch -n 5 'ps aux | grep tcpreplay | wc -l'
```

---

## Stop Experiment Early (if needed)

### On Node 2:
```bash
# Kill all tcpreplay processes
sudo pkill tcpreplay

# Verify
ps aux | grep tcpreplay
```

### On Node 1:
```bash
# Stop detector (Ctrl+C in terminal, or)
sudo pkill http_flood_detector
```

---

## After Experiment

### Step 1: Copy Results to Analysis Machine

```bash
# On your local machine
scp node1:/local/dpdk_100g/results/results_http_flood_500s_2.log ./results/
```

### Step 2: Run Analysis

```bash
cd http_flood_advance/analysis

python3 analyze_results_2.py
```

This generates:
- `01_traffic_overview.png`
- `02_detection_efficacy.png`
- `03_baseline_vs_attack.png`
- `04_link_utilization.png`

---

## Troubleshooting

### Detector won't start

```bash
# Check hugepages
cat /proc/meminfo | grep HugePages_Free

# Check DPDK status
dpdk-devbind.py --status

# For Mellanox ConnectX-5, check:
# 1. Interface is UP
ip link show ens1f0

# 2. Required libraries are installed
ldconfig -p | grep mlx5
ldconfig -p | grep ibverbs

# 3. If libraries missing, install:
sudo apt-get install libibverbs-dev libmlx5-1 rdma-core

# 4. Check PCI address
lspci | grep -i mellanox
```

### Low traffic throughput

```bash
# Reduce number of instances if system is overloaded
# Baseline: 25 instead of 50
# Attack: 50 instead of 100

# Or increase per-instance PPS
--pps=80000 instead of --pps=40000
```

### tcpreplay errors

```bash
# Check interface exists
ip link show ens1f0

# Check pcap files
tcpdump -r baseline_5M.pcap -c 5

# Run single instance to test
sudo tcpreplay --intf1=ens1f0 --pps=1000 --loop=1 baseline_5M.pcap
```

### Detector not detecting attack

```bash
# Check if traffic is reaching detector
# Look for increasing packet counters in log

# Verify PCI address is correct
dpdk-devbind.py --status
```

---

## Quick Reference - All Commands

### Node 1 (Detector)

```bash
# Setup (one time)
sudo su
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /mnt/huge && mount -t hugetlbfs nodev /mnt/huge

# Ensure interface is up (Mellanox doesn't need unbinding)
ip link set ens1f0 up

# Build
cd /local/dpdk_100g/http_flood_advance/detector_system
make clean && make

# Create results directory
mkdir -p /local/dpdk_100g/results

# Run
sudo rm -rf /var/run/dpdk/*
sudo rm -rf /dev/hugepages/*
sudo umount /mnt/huge 2>/dev/null
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
grep Huge /proc/meminfo
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages


sudo timeout 510 ./http_flood_detector -l 1-2 -n 4 -w 0000:41:00.0 -- -p 0
sudo timeout 110 ./http_flood_detector -l 1-2 -n 4 -w 0000:41:00.0 -- -p 0

```

### Node 2 (Traffic Generator)

```bash
cd /local/dpdk_100g/http_flood_advance

# Baseline (immediately after detector starts)
for i in {1..25}; do sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=50000 --loop=0 --quiet baseline_5M.pcap & done
for i in {1..25}; do sudo timeout 100 tcpreplay --intf1=ens1f0 --pps=50000 --loop=0 --quiet baseline_5M.pcap & done

sudo tcpreplay --intf1=ens1f0 --pps=50000 --loop=0 --quiet baseline_5M.pcap

# Attack (200 seconds later)
for i in {1..50}; do sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=37500 --loop=0 --quiet attack_mixed_5M.pcap & done
for i in {1..50}; do sudo timeout 50 tcpreplay --intf1=ens1f0 --pps=37500 --loop=0 --quiet attack_mixed_5M.pcap & done

```

---

## Expected Results (25G Link)

| Metric | Expected Value |
|--------|----------------|
| Baseline duration | 200 seconds |
| Attack duration | 300 seconds |
| Baseline throughput | ~7 Gbps (1.25M pps) |
| Attack throughput | ~10.5 Gbps (1.875M pps) |
| Total during attack | ~17.5 Gbps (3.125M pps) |
| Link utilization (baseline) | ~28% of 25G |
| Link utilization (attack) | ~70% of 25G |
| Baseline/Attack ratio | 40%/60% |
| Detection delay | < 5 seconds |
