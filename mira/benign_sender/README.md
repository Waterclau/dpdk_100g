# DPDK PCAP Sender - Line-rate PCAP Replay

High-performance PCAP replayer using DPDK for line-rate packet transmission.

## Features

- **Line-rate transmission**: Capable of saturating 25G/100G links
- **Zero-copy**: Direct NIC transmission via DPDK
- **Loop replay**: Continuously replays PCAP in a loop
- **Real-time stats**: Shows throughput every 5 seconds

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
sudo ./build/dpdk_pcap_sender -l 0-7 -n 4 -a 0000:41:00.0 -- /path/to/file.pcap

# Parameters:
#   -l 0-7        : Use CPU cores 0-7
#   -n 4          : Memory channels
#   -a 0000:41:00.0 : PCI address of NIC (see lspci | grep Mellanox)
#   -- /path/to/file.pcap : PCAP file to replay
```

## Example for MIRA experiment

### On node-controller (sender):
```bash
cd /local/dpdk_100g/mira/benign_sender

# Send baseline MIRA traffic at line-rate
sudo ./build/dpdk_pcap_sender -l 0-7 -n 4 -a 0000:41:00.0 -- ../benign_10M.pcap
```

### On node-monitor (detector):
```bash
cd /local/dpdk_100g/mira/detector_system

# Run detector
sudo ./mira_detector -l 1-2 -n 4 -w 0000:41:00.0 -- -p 0 --stats=1
```

## Expected Performance

On a 25G link with ConnectX-5:
- **Throughput**: 18-22 Gbps (80-90% line-rate)
- **Packet rate**: 15-25 Mpps (depending on packet size)
- **Drops**: < 5% at maximum rate

## Technical Details

- **Burst size**: 512 packets
- **TX ring size**: 4096 descriptors
- **Mbuf pool**: 262,144 buffers
- **Max PCAP size**: 10M packets (loaded into RAM)

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
