# Benign HTTP Traffic Generator

High-performance benign HTTP traffic generator designed for 100 Gbps network testing on c6525-100g nodes.

## Overview

This system generates realistic benign HTTP traffic at rates up to 80 Gbps (~80% of 100G link capacity). It includes both:

1. **DPDK-based Generator** (`benign_traffic_dpdk.c`) - Ultra-high performance, kernel-bypass traffic generation
2. **Python Dataset Generator** (`benign_dataset_generator.py`) - Flexible, realistic traffic pattern generation

## Features

### DPDK Generator
- **Target Rate**: 80 Gbps (12.5M pps with 800-byte packets)
- **Multi-core**: Distributes traffic generation across CPU cores
- **Realistic HTTP**: 10 different HTTP request templates
- **TCP/IP Stack**: Full TCP handshake and session management
- **Hardware Offload**: Checksum offloading for maximum performance
- **Real-time Stats**: Per-second throughput and packet rate monitoring

### Python Dataset Generator
- **Realistic Traffic Patterns**: Multiple HTTP methods, paths, and user agents
- **Session-based**: Complete TCP sessions with handshakes
- **Configurable**: Flexible traffic profiles and distributions
- **Large Datasets**: Generate millions of sessions for comprehensive testing
- **Statistics**: Detailed traffic analysis and flow statistics

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Node Controller                        │
│  ┌────────────────────────────────────────────────┐     │
│  │     Benign Traffic Generator (DPDK)            │     │
│  │  - 80 Gbps HTTP traffic                        │     │
│  │  - 8 CPU cores                                 │     │
│  │  - Realistic HTTP patterns                     │     │
│  └──────────────────┬─────────────────────────────┘     │
└─────────────────────┼───────────────────────────────────┘
                      │
                      │ 100G NIC
                      │
                      v
         ┌────────────────────────┐
         │   Network Under Test   │
         └────────────────────────┘
                      │
                      v
┌─────────────────────┼───────────────────────────────────┐
│                   Node Monitor                          │
│  ┌────────────────────────────────────────────────┐     │
│  │   DPDK + OctoStack Detector                    │     │
│  │  - Receives and analyzes traffic               │     │
│  │  - Detects attacks                             │     │
│  └────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
```

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+ recommended)
- **CPU**: Multi-core CPU (8+ cores recommended for 80 Gbps)
- **Memory**: 32+ GB RAM
- **NIC**: 100 Gbps Mellanox/Intel NIC (c6525-100g)
- **Hugepages**: 8192 x 2MB hugepages (16 GB)

### Software Dependencies

#### For DPDK Generator:
```bash
# Install DPDK
sudo apt-get update
sudo apt-get install -y dpdk dpdk-dev libdpdk-dev
sudo apt-get install -y build-essential pkg-config

# Verify DPDK installation
pkg-config --modversion libdpdk
```

#### For Python Generator:
```bash
# Install Python and Scapy
sudo apt-get install -y python3 python3-pip
pip3 install scapy
```

## Quick Start

### 1. DPDK Generator (High Performance)

#### Build
```bash
cd benign_generator
make clean
make
```

#### Configure System
```bash
# Setup hugepages
echo 8192 | sudo tee /proc/sys/vm/nr_hugepages
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Bind NIC to DPDK driver
sudo dpdk-devbind.py --status
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0  # Replace with your NIC PCI address
```

#### Run Generator
```bash
# Simple run (5 minutes, 80 Gbps target)
sudo ./run_benign_generator.sh

# Custom configuration
sudo ./run_benign_generator.sh \
    --pci 0000:81:00.0 \
    --cores 8 \
    --duration 300 \
    --rate 80 \
    --dst-mac bb:bb:bb:bb:bb:bb \
    --dst-ip 10.0.0.1
```

#### Direct Execution
```bash
sudo ./build/benign_traffic_gen \
    -l 0-7 \
    -n 4 \
    --proc-type=primary \
    --file-prefix=benign_gen
```

### 2. Python Dataset Generator (Flexible)

#### Generate Small Dataset (100K sessions)
```bash
python3 benign_dataset_generator.py \
    -n 100000 \
    -o benign_traffic_small.pcap \
    --dst-ip 10.0.0.1 \
    --dst-mac bb:bb:bb:bb:bb:bb
```

#### Generate Large Dataset (5M sessions)
```bash
# This will create multiple files automatically
./generate_large_dataset.sh
```

#### Custom Generation
```bash
python3 benign_dataset_generator.py \
    --num-sessions 1000000 \
    --output benign_1M.pcap \
    --dst-ip 192.168.10.1 \
    --dst-mac aa:bb:cc:dd:ee:ff \
    --src-ip-base 10.0. \
    --dst-port 80 \
    --stats-file benign_1M_stats.json
```

## Configuration

### Edit Configuration File
```bash
vim ../config/benign_generator.json
```

Key parameters:
- `target_rate_gbps`: Target throughput (default: 80)
- `target_pps`: Packets per second (default: 12.5M)
- `num_cores`: CPU cores to use (default: 8)
- `dst_ip`: Destination IP address
- `dst_mac`: Destination MAC address

### DPDK Configuration

Edit `benign_traffic_dpdk.c` to modify:
- `TARGET_RATE_GBPS`: Target rate in Gbps
- `TARGET_PPS`: Target packets per second
- `BURST_SIZE`: Packet burst size
- `NUM_MBUFS`: Memory buffer pool size

### Traffic Patterns

Edit `benign_dataset_generator.py` to customize:
- HTTP request paths
- User agents
- HTTP methods distribution
- Request/response sizes
- Session patterns

## Performance Tuning

### For Maximum Throughput (80 Gbps)

1. **CPU Isolation**
```bash
# Add to kernel boot parameters
isolcpus=1-7 nohz_full=1-7 rcu_nocbs=1-7
```

2. **IRQ Affinity**
```bash
# Bind NIC interrupts to isolated cores
sudo ./scripts/set_irq_affinity.sh 0-7 eth0
```

3. **CPU Frequency Scaling**
```bash
# Set performance governor
sudo cpupower frequency-set -g performance
```

4. **Huge Pages**
```bash
# Increase if needed
echo 16384 | sudo tee /proc/sys/vm/nr_hugepages
```

5. **NIC Tuning**
```bash
# Increase ring buffer sizes
sudo ethtool -G eth0 rx 4096 tx 4096

# Enable multi-queue
sudo ethtool -L eth0 combined 8
```

## Output and Analysis

### DPDK Generator Output

Real-time statistics every second:
```
=== Benign Traffic Generator Statistics ===
Total Packets:               125000000
Total Bytes:             100000000000
Dropped:                             0
Rate:                            12.50 Mpps
Throughput:                      80.00 Gbps
Target:                          80.00 Gbps (100%)
==========================================
```

### Python Generator Output

Statistics saved to JSON:
```json
{
  "sessions": 1000000,
  "total_packets": 8547234,
  "total_bytes": 6837872640,
  "total_mb": 6520.45,
  "method_GET": 700000,
  "method_POST": 200000,
  "method_PUT": 50000,
  ...
}
```

### Analyzing Generated PCAP

```bash
# Basic statistics
tcpdump -r benign_traffic.pcap -nn -q | head -100

# Count packets
tcpdump -r benign_traffic.pcap -nn | wc -l

# Filter HTTP traffic
tcpdump -r benign_traffic.pcap -nn -A 'tcp port 80'

# Use tshark for detailed analysis
tshark -r benign_traffic.pcap -q -z io,stat,1
```

## Experiment Workflow

### Phase 1: Baseline (300 seconds)
```bash
# On Node Controller
sudo ./run_benign_generator.sh --duration 300 --rate 80

# On Node Monitor
sudo ./detector_dpdk --monitor-only
```

### Phase 2: Mixed Traffic (benign + attack)
```bash
# Node Controller - continue benign traffic
sudo ./run_benign_generator.sh --duration 300 --rate 80

# Node TG - start attack
sudo ./run_http_flood_attack.sh --duration 300 --rate 20

# Node Monitor - detect
sudo ./detector_dpdk --detect
```

### Phase 3: Analysis
```bash
# Analyze detection results
python3 analyze_results.py \
    --baseline baseline_stats.json \
    --attack attack_stats.json \
    --output report.pdf
```

## Troubleshooting

### Issue: Low throughput
**Solution**:
- Increase CPU cores
- Check CPU isolation and frequency scaling
- Verify NIC driver and firmware
- Increase burst size

### Issue: Packet drops
**Solution**:
- Increase hugepages
- Increase RX/TX ring sizes
- Check NIC capacity
- Reduce target rate

### Issue: "Cannot allocate mbuf"
**Solution**:
```bash
# Increase mbuf pool size in code
NUM_MBUFS 1048576  // Double the size

# Or increase hugepages
echo 16384 | sudo tee /proc/sys/vm/nr_hugepages
```

### Issue: DPDK initialization fails
**Solution**:
```bash
# Check hugepages
cat /proc/meminfo | grep Huge

# Check DPDK driver binding
sudo dpdk-devbind.py --status

# Reload vfio-pci
sudo modprobe -r vfio-pci
sudo modprobe vfio-pci
```

## Performance Benchmarks

### Target Performance (c6525-100g)
- **Link Speed**: 100 Gbps
- **Target Rate**: 80 Gbps (80% utilization)
- **Packet Size**: 800 bytes average
- **Packet Rate**: 12.5 Mpps
- **CPU Cores**: 8
- **Latency**: < 100 μs

### Achieved Performance
- **DPDK Generator**: 78-82 Gbps sustained
- **Python Generator**: 5-10 Gbps (dataset creation)
- **CPU Usage**: 60-70% (8 cores)
- **Memory**: 8-12 GB

## Dataset Sizes

| Sessions | Avg Packets | Estimated Size | Generation Time |
|----------|-------------|----------------|-----------------|
| 100K     | 500K        | ~400 MB        | ~2 minutes      |
| 1M       | 5M          | ~4 GB          | ~20 minutes     |
| 5M       | 25M         | ~20 GB         | ~2 hours        |
| 10M      | 50M         | ~40 GB         | ~4 hours        |

## References

- [DPDK Documentation](https://doc.dpdk.org/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [HTTP/1.1 RFC 7230](https://tools.ietf.org/html/rfc7230)
- Project configuration: `../config/benign_generator.json`

## License

See main project LICENSE file.

## Contact

For issues and questions, see main project README.
