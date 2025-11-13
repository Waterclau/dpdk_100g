# Getting Started - Advanced HTTP Flood Experiment

Quick start guide for setting up and running the advanced HTTP flood detection experiment.

## Prerequisites

- 4 nodes with c6525-100g specifications (100 Gbps NICs)
- Ubuntu 20.04+ or similar Linux distribution
- Root/sudo access on all nodes
- Network connectivity between nodes

## Quick Setup (All Nodes)

### Step 1: Clone Repository

```bash
# On all 4 nodes
git clone <repository-url>
cd dpdk_100g/http_flood_advance
```

### Step 2: Run Setup Script

The automated setup script will configure your node based on its role.

```bash
# On each node
cd scripts
sudo ./setup_node.sh
```

The script will:
1. Detect and configure node role (Controller/TG/Monitor/Target)
2. Install all dependencies (DPDK, Python, Scapy, etc.)
3. Setup hugepages (8192 x 2MB = 16 GB)
4. Configure CPU isolation (optional but recommended)
5. Bind NIC to DPDK driver
6. Build required components
7. Create output directories

**Note**: You may need to reboot after setup for CPU isolation to take effect.

### Step 3: Verify Setup

After setup (and reboot if needed), verify configuration:

```bash
# Check hugepages
cat /proc/meminfo | grep Huge

# Check DPDK NIC binding
sudo dpdk-devbind.py --status

# Check DPDK version
pkg-config --modversion libdpdk

# Check Python dependencies
python3 -c "import scapy; print('Scapy OK')"

# Verify builds
ls -lh benign_generator/build/
```

## Node-Specific Configuration

### Node Controller (Benign Traffic)

#### Configure Generator

Edit `config/benign_generator.json`:
```json
{
  "dpdk_config": {
    "nic_pci": "0000:81:00.0",    // Your NIC PCI address
    "num_cores": 8                 // Number of CPU cores
  },
  "network": {
    "dst_ip": "10.0.0.1",         // Monitor node IP
    "dst_mac": "bb:bb:bb:bb:bb:bb" // Monitor node MAC
  },
  "traffic_profile": {
    "target_rate_gbps": 80         // Target: 80% of 100G
  }
}
```

#### Test Generator

```bash
cd benign_generator

# Quick test (10 seconds)
sudo ./run_benign_generator.sh --duration 10 --rate 10

# Check output
ls -lh benign_traffic_data/
```

### Node TG (Attack Traffic)

**Note**: Attack generator to be implemented next. This is a placeholder.

```bash
cd attack_generator

# Configuration file
vim ../config/attack_generator.json

# Test run
sudo ./run_http_flood.sh --duration 10 --rate 5
```

### Node Monitor (Detection)

```bash
cd ../detector_system

# Configure detector
vim config.py

# Test detection
sudo ./run_detector.sh --mode detect --duration 60
```

### Node Target (Optional Web Server)

```bash
# Nginx is already installed by setup script

# Configure Nginx for high performance
sudo vim /etc/nginx/nginx.conf

# Increase worker connections, buffers, etc.

# Restart Nginx
sudo systemctl restart nginx

# Test
curl http://localhost/
```

## Running the Experiment

### Full Experiment (Automated)

**Coming soon**: Orchestration script that coordinates all nodes.

### Manual Experiment

#### Phase 1: Baseline (300 seconds)

**On Node Monitor** (start first):
```bash
cd detector_system
sudo ./run_detector.sh --mode baseline --duration 300
```

**On Node Controller**:
```bash
cd benign_generator
sudo ./run_benign_generator.sh --duration 660 --rate 80
```

Wait 300 seconds for baseline phase...

#### Phase 2: Attack (300 seconds)

**On Node TG** (after 300 seconds):
```bash
cd attack_generator
sudo ./run_http_flood.sh --duration 300 --rate 20
```

Monitor continues running, collecting detection metrics...

#### Phase 3: Recovery (60 seconds)

Node TG automatically stops after 300 seconds.
Controller continues for final 60 seconds.
Monitor observes recovery.

### Collecting Results

After experiment completes:

```bash
# On Node Controller
ls -lh benign_generator/benign_traffic_data/

# On Node TG
ls -lh attack_generator/attack_data/

# On Node Monitor
ls -lh detection_results/
```

Copy all results to a central location for analysis.

## Generating Datasets (Offline)

### Small Dataset (Testing)

```bash
cd benign_generator

# Generate 100K sessions (~800 MB)
python3 benign_dataset_generator.py -n 100000 -o test_dataset.pcap

# View statistics
cat test_dataset_stats.json
```

### Large Dataset (Production)

```bash
cd benign_generator

# Generate 5M sessions (~40 GB) - takes ~2 hours
./generate_large_dataset.sh

# Datasets are split into multiple files
ls -lh benign_traffic_data/dataset_*/
```

### Custom Dataset

```bash
python3 benign_dataset_generator.py \
    --num-sessions 1000000 \
    --output my_dataset.pcap \
    --dst-ip 192.168.10.1 \
    --dst-mac aa:bb:cc:dd:ee:ff \
    --dst-port 8080
```

## Monitoring During Experiment

### Real-time Traffic Rate

```bash
# On traffic generator nodes
watch -n 1 'ethtool -S eth0 | grep -E "tx_packets|tx_bytes"'

# Calculate Gbps
watch -n 1 'echo "scale=2; $(cat /sys/class/net/eth0/statistics/tx_bytes) * 8 / 1000000000" | bc'
```

### Detection Metrics

```bash
# On Monitor node
tail -f detection_results/detection_log.txt
```

### System Resources

```bash
# CPU and memory
htop

# Per-core CPU usage
mpstat -P ALL 1

# Network interface stats
watch -n 1 'ip -s link show eth0'
```

## Common Issues and Solutions

### Issue: Low throughput (< 50 Gbps)

**Possible causes**:
- Insufficient CPU cores
- CPU not isolated
- Insufficient hugepages
- NIC driver issues

**Solutions**:
```bash
# Check CPU isolation
cat /proc/cmdline | grep isolcpus

# Check hugepages
cat /proc/meminfo | grep Huge

# Increase CPU cores in config
vim config/benign_generator.json
# Change num_cores to higher value

# Set CPU to performance mode
sudo cpupower frequency-set -g performance
```

### Issue: "Cannot allocate mbuf"

**Solution**:
```bash
# Increase hugepages
echo 16384 | sudo tee /proc/sys/vm/nr_hugepages

# Or recompile with larger mbuf pool
# Edit benign_traffic_dpdk.c:
# NUM_MBUFS 1048576
make clean && make
```

### Issue: "No Ethernet ports available"

**Solution**:
```bash
# Check NIC binding
sudo dpdk-devbind.py --status

# Rebind NIC
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0
```

### Issue: Packet drops

**Solution**:
```bash
# Increase NIC ring buffers
sudo ethtool -G eth0 rx 4096 tx 4096

# Check for buffer overruns
ethtool -S eth0 | grep -i drop

# Reduce target rate temporarily
sudo ./run_benign_generator.sh --rate 60
```

## Performance Tuning

### For Maximum Throughput

1. **CPU Isolation**: Isolate cores 1-7, leave 0 for OS
2. **CPU Frequency**: Set to performance governor
3. **NUMA**: Pin to correct NUMA node
4. **Hugepages**: Use 1GB pages if available
5. **NIC**: Update firmware, tune ring buffers

See `PERFORMANCE_TUNING.md` for detailed tuning guide.

### Quick Performance Checks

```bash
# Check CPU frequency
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Check NUMA topology
numactl --hardware

# Check NIC ring buffer sizes
ethtool -g eth0

# Check for PCIe errors
lspci -vv | grep -i error
```

## Next Steps

1. **Verify Setup**: Run test traffic generation on each node
2. **Baseline Test**: Run 5-minute baseline traffic test
3. **Attack Test**: Create attack generator (next development step)
4. **Full Experiment**: Run complete 3-phase experiment
5. **Analysis**: Analyze results and generate reports

## Getting Help

- **Benign Generator Issues**: See `benign_generator/README.md`
- **Attack Generator Issues**: See `attack_generator/README.md` (TBD)
- **Detection Issues**: See `../detector_system/README.md`
- **General Questions**: See main `README.md`

## Useful Commands Reference

```bash
# DPDK
dpdk-devbind.py --status           # Show NIC binding status
dpdk-testpmd                       # Test DPDK installation

# Network
ethtool -S eth0                    # NIC statistics
ip link show eth0                  # Interface status
tcpdump -i eth0 -c 100            # Capture packets

# System
numactl --hardware                 # NUMA topology
lscpu                             # CPU information
free -h                           # Memory usage
df -h                             # Disk usage

# Monitoring
htop                              # Interactive process viewer
mpstat -P ALL 1                   # Per-CPU statistics
sar -n DEV 1                      # Network statistics
```

## Experiment Checklist

Before running full experiment:

- [ ] All 4 nodes setup complete
- [ ] Hugepages configured on all nodes
- [ ] NICs bound to DPDK drivers
- [ ] CPU isolation configured (optional)
- [ ] All components built successfully
- [ ] Test runs completed successfully
- [ ] Network connectivity verified
- [ ] Monitoring tools ready
- [ ] Output directories created
- [ ] Experiment timeline planned

## Timeline Example

```
T=0:     Start Monitor (baseline mode)
T=0:     Start Controller (80 Gbps benign)
T=300:   Start TG (attack)
T=600:   Stop TG
T=660:   Stop Controller
T=660:   Stop Monitor
T=660+:  Collect and analyze results
```

Good luck with your experiment! 🚀
