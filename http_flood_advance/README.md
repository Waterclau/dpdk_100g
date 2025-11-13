# Advanced HTTP Flood Detection Experiment

High-performance HTTP flood attack detection system using DPDK and OctoStack on 100 Gbps networks.

## Overview

This is an advanced 4-node experimental setup designed to test HTTP flood attack detection at near-line-rate speeds (80% of 100 Gbps). The experiment includes:

1. **Baseline benign traffic generation** (Node Controller)
2. **HTTP flood attack generation** (Node TG)
3. **Real-time detection** using DPDK + OctoStack (Node Monitor)
4. **Target server** (Node Target - optional)

## Architecture

```
┌─────────────────────────┐
│    Node Controller      │
│  Benign Traffic Gen     │
│  (80 Gbps HTTP)         │
└───────────┬─────────────┘
            │
            │ 100G NIC
            v
┌─────────────────────────┐        ┌─────────────────────────┐
│       Node TG           │        │    Node Monitor         │
│  Attack Generator       │───────>│  DPDK + OctoStack       │
│  (HTTP Flood)           │ Attack │  Detection System       │
└─────────────────────────┘        └───────────┬─────────────┘
                                               │
                                               v
                                   ┌─────────────────────────┐
                                   │    Node Target          │
                                   │    Web Server           │
                                   │    (Optional)           │
                                   └─────────────────────────┘
```

## Node Assignments

### Node Controller
- **Role**: Benign traffic generator
- **Traffic**: Realistic HTTP traffic at 80 Gbps
- **Duration**: Continuous (baseline + attack phases)
- **Tool**: DPDK-based benign traffic generator

### Node TG (Traffic Generator)
- **Role**: Attack generator
- **Traffic**: HTTP flood attack
- **Timing**: Starts after baseline phase
- **Tool**: DPDK-based HTTP flood attack generator

### Node Monitor
- **Role**: Detection system
- **Technology**: DPDK + OctoStack
- **Function**: Detects and classifies traffic in real-time
- **Metrics**: Accuracy, detection time, false positives

### Node Target (Optional)
- **Role**: Target web server
- **Function**: Processes requests, measures performance degradation
- **Server**: Nginx/Apache with performance monitoring

## Experiment Phases

### Phase 1: Baseline (300 seconds)
**Objective**: Establish normal traffic patterns

**Actions**:
1. Node Controller starts benign traffic (80 Gbps)
2. Node Monitor collects baseline metrics
3. Record normal traffic characteristics

**Expected Metrics**:
- Throughput: 80 Gbps
- Packet rate: ~12.5 Mpps
- Latency: < 5ms avg
- Packet loss: < 0.01%

### Phase 2: Attack (300 seconds)
**Objective**: Detect HTTP flood attack in mixed traffic

**Actions**:
1. Node Controller continues benign traffic (80 Gbps)
2. Node TG launches HTTP flood attack
3. Node Monitor detects and classifies traffic
4. Record detection metrics

**Expected Metrics**:
- Detection time: < 5 seconds
- True positive rate: > 99%
- False positive rate: < 1%
- Accuracy: > 98%

### Phase 3: Recovery (60 seconds)
**Objective**: Verify system recovery

**Actions**:
1. Node TG stops attack
2. Node Controller continues benign traffic
3. Node Monitor verifies return to baseline
4. Measure recovery time

## Quick Start

### 1. Setup All Nodes

```bash
# On all nodes
git clone <repository>
cd dpdk_100g/http_flood_advance

# Install dependencies
sudo apt-get update
sudo apt-get install -y dpdk dpdk-dev build-essential python3 python3-pip
pip3 install scapy
```

### 2. Configure Network

Edit `config/benign_generator.json` and update:
- NIC PCI addresses for each node
- MAC addresses
- IP addresses
- Target rates

### 3. Run Experiment

#### On Node Monitor (start first):
```bash
cd detector_system
sudo ./run_detector.sh --mode detect
```

#### On Node Controller:
```bash
cd benign_generator
sudo ./run_benign_generator.sh --duration 660 --rate 80
```

#### On Node TG (wait 300 seconds, then):
```bash
cd attack_generator
sudo ./run_http_flood.sh --duration 300 --rate 20
```

### 4. Collect Results

Results are automatically saved in each node's output directory:
- `benign_traffic_data/` - Benign traffic stats
- `attack_data/` - Attack traffic stats
- `detection_results/` - Detection metrics

## Directory Structure

```
http_flood_advance/
├── README.md                      # This file
├── benign_generator/              # Benign traffic generator
│   ├── benign_traffic_dpdk.c     # DPDK-based generator
│   ├── benign_dataset_generator.py # Python dataset generator
│   ├── run_benign_generator.sh   # Launch script
│   ├── generate_large_dataset.sh # Large dataset generator
│   ├── Makefile                  # Build configuration
│   └── README.md                 # Detailed documentation
├── attack_generator/              # Attack traffic generator (to be created)
│   ├── http_flood_dpdk.c         # DPDK-based attack generator
│   ├── run_http_flood.sh         # Launch script
│   ├── Makefile
│   └── README.md
├── config/                        # Configuration files
│   ├── benign_generator.json     # Benign traffic config
│   ├── attack_generator.json     # Attack config (to be created)
│   └── experiment_config.json    # Overall experiment config (to be created)
├── scripts/                       # Utility scripts
│   ├── setup_nodes.sh            # Setup all nodes
│   ├── run_experiment.sh         # Orchestrate full experiment
│   └── analyze_results.sh        # Analyze results
└── docs/                          # Documentation
    ├── EXPERIMENT_DESIGN.md      # Detailed experiment design
    ├── PERFORMANCE_TUNING.md     # Performance optimization guide
    └── RESULTS_ANALYSIS.md       # Results analysis guide
```

## Performance Targets

### c6525-100g Node Specifications
- **NIC**: 100 Gbps Mellanox ConnectX-5/6
- **CPU**: AMD EPYC (multiple cores)
- **Memory**: 32+ GB RAM
- **Target Utilization**: 80% (80 Gbps)

### Traffic Characteristics

#### Benign Traffic
- **Rate**: 80 Gbps
- **Packet Rate**: ~12.5 Mpps (800-byte avg)
- **Protocol**: HTTP/1.1
- **Patterns**: Realistic web application traffic
- **Sources**: 65K+ unique IPs

#### Attack Traffic
- **Type**: HTTP flood
- **Rate**: Configurable (5-20 Gbps)
- **Packet Rate**: High (small packets)
- **Patterns**: Anomalous request rates
- **Sources**: Limited IP range

## Building Components

### Benign Traffic Generator
```bash
cd benign_generator
make clean
make
```

### Attack Generator (to be created next)
```bash
cd attack_generator
make clean
make
```

## Configuration

### System Setup
```bash
# Hugepages
echo 8192 | sudo tee /proc/sys/vm/nr_hugepages

# CPU isolation (add to /etc/default/grub)
GRUB_CMDLINE_LINUX="isolcpus=1-7 nohz_full=1-7 rcu_nocbs=1-7"
sudo update-grub
sudo reboot

# Bind NICs to DPDK
sudo dpdk-devbind.py --bind=vfio-pci <PCI_ADDRESS>
```

### Network Configuration
```bash
# Disable firewall (for testing)
sudo systemctl stop firewalld
sudo systemctl stop iptables

# Disable ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Increase limits
sudo ulimit -n 1048576
```

## Monitoring and Debugging

### Real-time Monitoring

#### Traffic Rate
```bash
# On Node Controller/TG
watch -n 1 'ethtool -S eth0 | grep -E "tx_packets|tx_bytes"'

# Calculate Gbps
watch -n 1 'echo "scale=2; $(cat /sys/class/net/eth0/statistics/tx_bytes) * 8 / 1000000000" | bc'
```

#### Detection Metrics
```bash
# On Node Monitor
tail -f detection_results/detection_log.txt
```

#### System Resources
```bash
# CPU usage
htop

# Memory
watch -n 1 free -h

# NIC stats
watch -n 1 'dpdk-devbind.py --status'
```

### Debugging

#### Enable Debug Logging
```bash
# In DPDK programs, set log level
export RTE_LOG_LEVEL=debug
```

#### Capture Traffic (limited)
```bash
# Capture 10K packets for verification
sudo tcpdump -i eth0 -w /tmp/traffic_sample.pcap -c 10000

# Analyze
tcpdump -r /tmp/traffic_sample.pcap -nn | head -100
```

#### Check DPDK Stats
```bash
# In the generator code, stats are printed every second
# Look for:
# - Packet rate (should be near target)
# - Throughput (should be near target Gbps)
# - Dropped packets (should be minimal)
```

## Expected Results

### Baseline Phase
- Stable 80 Gbps throughput
- Low latency (< 5ms avg)
- No false positives
- CPU usage: 60-70%

### Attack Phase
- Detection within 5 seconds
- True positive rate: > 99%
- False positive rate: < 1%
- Continued benign traffic processing

### Recovery Phase
- Return to baseline within 10 seconds
- No residual false positives
- Full throughput restoration

## Troubleshooting

See individual component READMEs:
- `benign_generator/README.md` - Benign traffic generator issues
- `attack_generator/README.md` - Attack generator issues (to be created)
- `../detector_system/README.md` - Detection system issues

## Next Steps

1. ✅ Benign traffic generator completed
2. ⏳ Create HTTP flood attack generator
3. ⏳ Create experiment orchestration scripts
4. ⏳ Create analysis and visualization tools
5. ⏳ Run full experiment
6. ⏳ Analyze and document results

## Performance Optimization

See `docs/PERFORMANCE_TUNING.md` (to be created) for:
- CPU isolation and pinning
- NUMA configuration
- NIC tuning
- Memory optimization
- Kernel parameters

## Citation

If you use this work, please cite:
```
[Your publication details here]
```

## License

See main project LICENSE file.

## Contributors

[List contributors here]

## Acknowledgments

- DPDK community
- OctoStack developers
- Your institution/funding source
