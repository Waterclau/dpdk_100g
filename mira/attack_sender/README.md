# DPDK PCAP Sender - Attack Traffic

High-performance PCAP replayer using DPDK for sending Mirai-style attack traffic.

## Features

- **High-rate transmission**: Configured for 24 Gbps target (to achieve ~10 Gbps real at detector)
- **Zero-copy**: Direct NIC transmission via DPDK
- **Loop replay**: Continuously replays attack PCAP in a loop
- **Real-time stats**: Shows throughput every 5 seconds
- **Instant cleanup**: No soft lockup on Ctrl+C

## Build

```bash
# Install dependencies
sudo apt-get install -y libpcap-dev pkg-config

# Compile
make clean
make
```

## Usage

```bash
# Basic usage
sudo ./build/dpdk_pcap_sender -l 0-7 -n 4 -w 0000:41:00.0 -- ../attack_mixed_10M.pcap

# Parameters:
#   -l 0-7        : Use CPU cores 0-7
#   -n 4          : Memory channels
#   -w 0000:41:00.0 : PCI address of NIC (see lspci | grep Mellanox)
#   -- /path/to/attack_mixed_10M.pcap : Attack PCAP file to replay
```

## Example for MIRA experiment

### On node-tg (attack sender):
```bash
cd /local/dpdk_100g/mira/attack_sender

# Build
make clean && make

# Send attack traffic at 24 Gbps target (~10 Gbps real)
sudo ./build/dpdk_pcap_sender -l 0-7 -n 4 -w 0000:41:00.0 -- ../attack_mixed_10M.pcap
```

### On node-monitor (detector):
```bash
cd /local/dpdk_100g/mira/detector_system

# Run detector with 10 cores (8 workers + 1 coordinator)
sudo ./mira_ddos_detector -l 0-9 -n 4 -w 0000:41:00.0 -- -p 0
```

## Expected Performance

On a 25G link with ConnectX-5:
- **Target throughput:** 24 Gbps
- **Real throughput at detector:** ~10 Gbps
- **Packet rate:** 10-15 Mpps (depending on packet size)
- **Cleanup on Ctrl+C:** < 0.5 seconds ✅

## Configuration

### Adjust transmission rate

Edit `dpdk_pcap_sender.c` line 28:

```c
#define TARGET_GBPS 24.0  // Change this value
```

**Ratio:** TARGET_GBPS × 0.41 = Real Gbps at detector

Examples:
- 24 Gbps target → ~10 Gbps real
- 17 Gbps target → ~7 Gbps real
- 12 Gbps target → ~5 Gbps real

## Technical Details

- **Burst size**: 512 packets
- **TX ring size**: 8192 descriptors
- **Mbuf pool**: 262,144 buffers
- **Max PCAP size**: 10M packets (loaded into RAM)
- **Storage method**: Simple struct array (not pre-loaded mbufs)

## Troubleshooting

### "No Ethernet ports available"
- Check NIC binding: `sudo dpdk-devbind.py --status`
- Bind to DPDK: `sudo dpdk-devbind.py -b vfio-pci 0000:41:00.0`

### Low throughput
- Increase CPU cores: `-l 0-15`
- Check NIC offloads: `ethtool -k ens1f0`
- Verify hugepages: `cat /proc/meminfo | grep Huge`

### Compilation errors
- Install DPDK dev packages: `sudo apt-get install dpdk dpdk-dev`
- Check pkg-config: `pkg-config --libs libdpdk`

## Difference from benign_sender

- **Target rate**: 24 Gbps (vs 17 Gbps for benign)
- **Purpose**: Attack traffic generation (Mirai-style DDoS)
- **PCAP**: Uses `attack_mixed_10M.pcap` (mixed UDP/SYN/HTTP/ICMP floods)
- **Node**: Runs on node-tg (vs node-controller for benign)

## Attack Types in PCAP

The `attack_mixed_10M.pcap` contains:
- 40% UDP Flood (DNS, NTP amplification)
- 30% SYN Flood (TCP exhaustion)
- 20% HTTP Flood (application layer)
- 10% ICMP Flood (ping flood)

All from source network: 203.0.113.0/24
