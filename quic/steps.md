# QUIC Optimistic ACK Experiment - Complete Setup Guide

## Prerequisites
- Repository cloned on all three nodes (controller, tg, monitor)
- Network interfaces connected (25G/100G link)
- Root access on all machines

---

## Overview

This experiment uses three nodes:
- **controller**: Sends baseline QUIC traffic
- **tg**: Sends attack Optimistic ACK traffic
- **monitor**: Runs the DPDK detector, receives both traffic streams

---

## Phase 1: Generate PCAP Files

### On controller: Generate Baseline QUIC Traffic

```bash
cd /local/dpdk_100g/quic/benign_generator

# Install dependencies
sudo apt-get update
sudo apt-get install -y python3-pip
pip3 install scapy

# Generate 5M packets of legitimate QUIC traffic
python3 generate_baseline_quic.py \
    --output ../baseline_quic_5M.pcap \
    --packets 5000000 \
    --dst-mac 0c:42:a1:dd:5b:28 \
    --client-range 192.168.1.0/24 \
    --server-ip 10.0.0.1 \
    --flows 1000

# Verify PCAP
ls -lh ../baseline_quic_5M.pcap
tcpdump -r ../baseline_quic_5M.pcap -c 10
```

**Note**: Replace `--dst-mac` with the actual MAC address of the monitor's receiving interface.

### On tg: Generate Attack QUIC Traffic

```bash
cd /local/dpdk_100g/quic/attack_generator

# Install dependencies
sudo apt-get update
sudo apt-get install -y python3-pip
pip3 install scapy

# Generate 1M packets of Optimistic ACK attack
python3 generate_optimistic_ack_attack.py \
    --output ../attack_quic_optimistic_ack_5M.pcap \
    --packets 5000000 \
    --dst-mac 0c:42:a1:dd:5b:28 \
    --attack-range 203.0.113.0/24 \
    --server-ip 10.0.0.1 \
    --attackers 500 \
    --jump-factor 100 \
    --acks-per-packet 3

# Or generate mixed intensity attack
python3 generate_optimistic_ack_attack.py \
    --output ../attack_quic_mixed_1M.pcap \
    --packets 1000000 \
    --dst-mac 0c:42:a1:dd:5b:28 \
    --mixed

# Verify PCAP
ls -lh ../attack_quic_*.pcap
tcpdump -r ../attack_quic_optimistic_ack_1M.pcap -c 10
```

---

## Phase 2: Setup Monitor Node (Detector)

### Step 1: Configure Hugepages

```bash
# Check current hugepages
cat /proc/meminfo | grep Huge

# Clean up and configure
sudo rm -rf /var/run/dpdk/*
sudo rm -rf /dev/hugepages/*
sudo umount /mnt/huge 2>/dev/null
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Configure hugepages (2GB)
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Verify
grep Huge /proc/meminfo
```

### Step 2: Configure Network Interface

For Mellanox ConnectX-5, the interface works with DPDK without unbinding:

```bash
# Check DPDK status
dpdk-devbind.py --status

# Ensure interface is UP
sudo ip link set ens1f0 up

# Verify
ip link show ens1f0
```

### Step 3: Build the Detector

```bash
cd /local/dpdk_100g/quic/detector_system

# Install DPDK development packages
sudo apt-get update
sudo apt-get install -y dpdk dpdk-dev libdpdk-dev

# Clean and build
make clean
make

# Verify build
ls -la quic_optimistic_ack_detector
```

### Step 4: Create Results Directory

```bash
mkdir -p /local/dpdk_100g/quic/results
```

### Step 5: Run the Detector

```bash
cd /local/dpdk_100g/quic/detector_system

# Run detector for 510 seconds
sudo timeout 510 ./quic_optimistic_ack_detector \
    -l 1-2 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../results/results_quic_optimistic_ack.log
```

**Parameters:**
- `-l 1-2`: Use CPU cores 1-2
- `-n 4`: 4 memory channels
- `-w 0000:41:00.0`: PCI address of NIC (adjust for your system)
- `-- -p 0`: Port 0
- `timeout 510`: Run for 510 seconds

---

## Phase 3: Traffic Generation

### On controller: Install tcpreplay

```bash
sudo apt-get update
sudo apt-get install -y tcpreplay

# Verify network interface
sudo ip link set ens1f0 up
ip link show ens1f0
```

### On tg: Install tcpreplay

```bash
sudo apt-get update
sudo apt-get install -y tcpreplay

# Verify network interface
sudo ip link set ens1f0 up
ip link show ens1f0
```

---

## Phase 4: Run Experiment

### Timeline

```
Time     Monitor            Controller           TG
────────────────────────────────────────────────────────────────
0s       Start detector     -                    -
5s       -                  Start baseline       -
5-200s   Monitoring         Baseline running     -
205s     -                  -                    Start attack
205-500s Detecting          Baseline continues   Attack running
500s     -                  Traffic stops        Traffic stops
510s     Detector stops     -                    -
```

### Step 1: Start Detector (Monitor)

Wait until the detector shows "Press Ctrl+C to exit..." before starting traffic.

### Step 2: Start Baseline Traffic (Controller, wait 5s after detector)

```bash
cd /local/dpdk_100g/quic

# 25 instances x 50,000 pps = 1.25M pps (~7 Gbps, ~28% of 25G)
for i in {1..25}; do
    sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=50000 --loop=0 baseline_quic_5M.pcap &
done

# Verify processes started
ps aux | grep tcpreplay | wc -l
# Should show ~25 processes
```

### Step 3: Start Attack Traffic (TG, wait 200s after baseline)

**IMPORTANT**: Wait 200 seconds after starting baseline traffic.

```bash
cd /local/dpdk_100g/quic

# 50 instances x 37,500 pps = 1.875M pps (~10.5 Gbps)
# Total with baseline: ~3.125M pps (~17.5 Gbps, ~70% of 25G)
for i in {1..50}; do
    sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=37500 --loop=0 attack_quic_optimistic_ack_1M.pcap &
done

# Verify processes
ps aux | grep tcpreplay | wc -l
# Should show ~50 processes
```

---

## Monitoring (Optional)

### On Monitor

```bash
# Watch detector output in real-time
tail -f /local/dpdk_100g/quic/results/results_quic_optimistic_ack.log
```

### On Controller/TG

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

### On Controller/TG:
```bash
# Kill all tcpreplay processes
sudo pkill tcpreplay

# Verify
ps aux | grep tcpreplay
```

### On Monitor:
```bash
# Stop detector (Ctrl+C in terminal, or)
sudo pkill quic_optimistic_ack_detector
```

---

## After Experiment

### Step 1: Copy Results to Analysis Machine

```bash
# On your local machine
scp monitor:/local/dpdk_100g/quic/results/results_quic_optimistic_ack.log ./
```

### Step 2: Run Analysis

```bash
cd /local/dpdk_100g/quic/analysis

python3 analyze_quic_results.py
```

This generates:
- `01_traffic_overview.png`
- `02_detection_efficacy.png`
- `03_baseline_vs_attack.png`
- `04_link_utilization.png`
- `05_ack_analysis.png`

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
| Bytes OUT/IN ratio during attack | > 10 |

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

### No QUIC packets detected

```bash
# Check if traffic is reaching monitor
tcpdump -i ens1f0 'udp port 443' -c 10

# Check PCAP files
tcpdump -r baseline_quic_5M.pcap 'udp port 443' -c 5
```

### tcpreplay errors

```bash
# Check interface exists
ip link show ens1f0

# Check pcap files
tcpdump -r baseline_quic_5M.pcap -c 5

# Run single instance to test
sudo tcpreplay --intf1=ens1f0 --pps=1000 --loop=1 baseline_quic_5M.pcap
```

### Detector not detecting attack

Possible issues:
1. ACK threshold too high - try reducing `ACK_RATE_THRESHOLD` to 3000
2. Bytes ratio threshold too high - try reducing `BYTES_RATIO_THRESHOLD` to 5.0
3. PCAP not generating proper attack pattern

```bash
# Verify attack PCAP has optimistic ACKs
tcpdump -r attack_quic_optimistic_ack_1M.pcap -X | head -100
```

---

## Quick Reference - All Commands

### Monitor (Detector)

```bash
# Setup (one time)
sudo su
echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /mnt/huge && mount -t hugetlbfs nodev /mnt/huge
ip link set ens1f0 up

# Build
cd /local/dpdk_100g/quic/detector_system
make clean && make

# Create results directory
mkdir -p /local/dpdk_100g/quic/results

# Run
sudo timeout 510 ./quic_optimistic_ack_detector -l 1-2 -n 4 -w 0000:41:00.0 -- -p 0 2>&1 | tee ../results/results_quic_optimistic_ack.log
```

### Controller (Baseline)

```bash
cd /local/dpdk_100g/quic

# Generate PCAP (one time)
cd benign_generator
python3 generate_baseline_quic.py --output ../baseline_quic_5M.pcap --packets 5000000 --dst-mac 0c:42:a1:dd:5b:28

# Send traffic (after detector starts)
cd /local/dpdk_100g/quic
for i in {1..25}; do sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=50000 --loop=0 baseline_quic_5M.pcap & done
```

### TG (Attack)

```bash
cd /local/dpdk_100g/quic

# Generate PCAP (one time)
cd attack_generator
python3 generate_optimistic_ack_attack.py --output ../attack_quic_optimistic_ack_1M.pcap --packets 1000000 --dst-mac 0c:42:a1:dd:5b:28

# Send traffic (200 seconds after baseline)
cd /local/dpdk_100g/quic
for i in {1..50}; do sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=37500 --loop=0 attack_quic_optimistic_ack_1M.pcap & done
```

---

## Variants

### High intensity (100G link)

```bash
# Baseline: 100 instances x 100,000 pps = 10M pps
for i in {1..100}; do sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=100000 --loop=0 baseline_quic_5M.pcap & done

# Attack: 200 instances x 75,000 pps = 15M pps
for i in {1..200}; do sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=75000 --loop=0 attack_quic_optimistic_ack_1M.pcap & done
```

### Low intensity (testing)

```bash
# Baseline: 10 instances x 25,000 pps = 250K pps
for i in {1..10}; do sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=25000 --loop=0 baseline_quic_5M.pcap & done

# Attack: 20 instances x 20,000 pps = 400K pps
for i in {1..20}; do sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=20000 --loop=0 attack_quic_optimistic_ack_1M.pcap & done
```
