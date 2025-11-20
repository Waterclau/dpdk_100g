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
sudo python3 generate_baseline_quic.py \
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

# Generate 5M packets of Optimistic ACK attack WITH amplification (45x like Chromium)
# IMPORTANT: With amplification=45x, 5M total packets = ~108K client ACKs + ~4.89M server responses
sudo python3 generate_optimistic_ack_attack.py \
    --output ../attack_quic_optimistic_ack_5M.pcap \
    --packets 5000000 \
    --dst-mac 0c:42:a1:dd:5b:28 \
    --attack-range 203.0.113.0/24 \
    --server-ip 10.0.0.1 \
    --attackers 500 \
    --jump-factor 500 \
    --acks-per-packet 5 \
    --amplification-factor 45

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

# Run detector for 460 seconds (+ 10s buffer)
sudo timeout 470 ./quic_optimistic_ack_detector \
    -l 1-2 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../results/results_quic_optimistic_ack.log
```

**Parameters:**
- `-l 1-2`: Use CPU cores 1-2
- `-n 4`: 4 memory channels
- `-w 0000:41:00.0`: PCI address of NIC (adjust for your system)
- `-- -p 0`: Port 0
- `timeout 470`: Run for 470 seconds (460s + 10s buffer)

**Detection thresholds (updated):**
- ACK Rate: >1000 ACKs/s per IP (was 5000)
- Bytes Ratio: OUT/IN > 1.5 (was 8.0) - detects amplification
- Heavy Hitter: >5000 ACKs per IP (was 10000)

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
5-130s   Monitoring         Baseline running     -
130s     -                  -                    Start attack
130-450s Detecting          Baseline continues   Attack running
450s     -                  Traffic stops        Traffic stops
460s     Detector stops     -                    -
```

**Key changes from HTTP flood experiment:**
- Attack starts at **130s** (not 205s) to get longer attack observation period
- Total experiment duration: **460s** (not 510s)
- Baseline alone period: **125s** (130s - 5s)
- Attack period: **320s** (450s - 130s)

### Step 1: Start Detector (Monitor)

Wait until the detector shows "Press Ctrl+C to exit..." before starting traffic.

### Step 2: Start Baseline Traffic (Controller, wait 5s after detector)

```bash
cd /local/dpdk_100g/quic

# 25 instances x 50,000 pps = 1.25M pps (~7 Gbps, ~28% of 25G)
# Duration: 445s (to stop at t=450s)
for i in {1..25}; do
    sudo timeout 445 tcpreplay --intf1=ens1f0 --pps=50000 --loop=0 baseline_quic_5M.pcap &
done

# Verify processes started
ps aux | grep tcpreplay | wc -l
# Should show ~25 processes
```

### Step 3: Start Attack Traffic (TG, wait 125s after baseline starts)

**IMPORTANT**: Wait 125 seconds after starting baseline traffic (attack starts at t=130s).

```bash
cd /local/dpdk_100g/quic

# Wait until t=130s (5s detector start + 125s baseline alone)
sleep 125

# 50 instances x 37,500 pps = 1.875M pps (~10.5 Gbps from attack PCAP)
# BUT: With 45x amplification, actual traffic will be MUCH higher
# - Client ACKs: ~108K packets/file × 50 instances = 5.4M ACKs total
# - Server responses: ~4.89M packets/file × 50 instances = 244M responses
# This creates realistic Optimistic ACK amplification attack
# Duration: 320s (to stop at t=450s)
for i in {1..50}; do
    sudo timeout 320 tcpreplay --intf1=ens1f0 --pps=37500 --loop=0 attack_quic_optimistic_ack_5M.pcap &
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
| Baseline duration | 125 seconds (5-130s) |
| Attack duration | 320 seconds (130-450s) |
| Baseline throughput | ~7 Gbps (1.25M pps) |
| Attack throughput (with amplification) | ~15-20 Gbps |
| Total during attack | ~22-27 Gbps |
| Link utilization (baseline) | ~28% of 25G |
| Link utilization (attack) | ~80-90% of 25G |
| Baseline/Attack ratio | ~25%/75% during attack |
| Detection delay | < 5 seconds |
| **Bytes OUT/IN ratio during attack** | **> 40x** (Optimistic ACK amplification) |
| ACK rate from attack IPs | > 100K ACKs/s |
| True positive rate | > 95% |
| False positive rate | < 5% |

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

**Updated detection thresholds (already applied):**
1. `ACK_RATE_THRESHOLD = 1000` (reduced from 5000)
2. `BYTES_RATIO_THRESHOLD = 1.5` (reduced from 8.0)
3. `HEAVY_HITTER_THRESHOLD = 5000` (reduced from 10000)

If still not detecting:
```bash
# Verify attack PCAP has amplification
tcpdump -r attack_quic_optimistic_ack_5M.pcap -c 100 | grep -E '(203.0.113|10.0.0.1)'
# Should see both client->server (203.0.113) and server->client (10.0.0.1) packets
# Server responses should be ~45x more than client ACKs

# Check bytes ratio in real-time
tail -f ../results/results_quic_optimistic_ack.log | grep "Ratio OUT/IN"
# Should show ratio > 40 during attack
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
sudo timeout 470 ./quic_optimistic_ack_detector -l 1-2 -n 4 -w 0000:41:00.0 -- -p 0 2>&1 | tee ../results/results_quic_optimistic_ack.log
```

### Controller (Baseline)

```bash
cd /local/dpdk_100g/quic

# Generate PCAP (one time)
cd benign_generator
python3 generate_baseline_quic.py --output ../baseline_quic_5M.pcap --packets 5000000 --dst-mac 0c:42:a1:dd:5b:28

# Send traffic (after detector starts, wait 5s)
cd /local/dpdk_100g/quic
for i in {1..25}; do sudo timeout 445 tcpreplay --intf1=ens1f0 --pps=50000 --loop=0 baseline_quic_5M.pcap & done
```

### TG (Attack)

```bash
cd /local/dpdk_100g/quic

# Generate PCAP with 45x amplification (one time)
cd attack_generator
python3 generate_optimistic_ack_attack.py \
    --output ../attack_quic_optimistic_ack_5M.pcap \
    --packets 5000000 \
    --dst-mac 0c:42:a1:dd:5b:28 \
    --attackers 500 \
    --jump-factor 500 \
    --acks-per-packet 5 \
    --amplification-factor 45

# Send traffic (125 seconds after baseline, attack starts at t=130s)
cd /local/dpdk_100g/quic
sleep 125
for i in {1..50}; do sudo timeout 320 tcpreplay --intf1=ens1f0 --pps=37500 --loop=0 attack_quic_optimistic_ack_5M.pcap & done
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
