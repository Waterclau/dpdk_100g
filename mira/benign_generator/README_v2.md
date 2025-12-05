# Benign Traffic Generator v2.0 - ML-Enhanced

## Overview

The v2.0 generator creates **realistic benign network traffic** with temporal variations and jitter, making it ideal for training ML models that need to distinguish between normal and attack traffic.

## What's New in v2.0

### 1. Temporal Traffic Phases (Automatic)

The generator simulates realistic network behavior by dividing traffic into 4 phases:

| Phase | Duration | Description | Intensity | Jitter |
|-------|----------|-------------|-----------|--------|
| **HTTP Peak** | 33% | High HTTP activity (morning peak) | 1.3× | 20ms |
| **DNS Burst** | 20% | DNS-heavy period (bursts) | 0.8× | 50ms |
| **SSH Stable** | 27% | Long SSH sessions (stable) | 0.6× | 10ms |
| **UDP Light** | 20% | Background UDP traffic | 0.5× | 80ms |

### 2. Realistic Variations

- **Variable Packet Sizes:** ±20-50% jitter around base sizes
- **Inter-Packet Timing:** 10-80ms jitter depending on phase
- **Traffic Intensity:** Varies from 0.5× to 1.3× across phases
- **Protocol Mix:** Dynamic distribution per phase

### 3. Better for ML Training

- **Feature Diversity:** More varied feature values → better generalization
- **Temporal Patterns:** Not constant → closer to real networks
- **Reduced Overfitting:** Model learns patterns, not constants

## Usage

### Basic Command

```bash
python3 generate_benign_traffic_v2.py --output benign_10M_v2.pcap --packets 10000000
```

### All Parameters

```bash
python3 generate_benign_traffic_v2.py \
    --output benign_10M_v2.pcap \
    --packets 10000000 \
    --src-mac 00:00:00:00:00:01 \
    --dst-mac 0c:42:a1:dd:5b:28 \
    --client-range 192.168.1.0/24 \
    --server-ip 10.0.0.1 \
    --clients 500
```

### Parameters Explained

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--output` | `benign_10M_v2.pcap` | Output PCAP filename |
| `--packets` | `10000000` | Total packets to generate |
| `--src-mac` | `00:00:00:00:00:01` | Source MAC address |
| `--dst-mac` | `0c:42:a1:dd:5b:28` | Destination MAC (monitor NIC) |
| `--client-range` | `192.168.1.0/24` | Client IP range (baseline traffic) |
| `--server-ip` | `10.0.0.1` | Server IP address |
| `--clients` | `500` | Number of simulated client IPs |

## Example Output

```
================================================================================
MIRA Benign Traffic Generator v2.0 - ML-Enhanced
================================================================================
Target packets: 10,000,000
Output file: benign_10M_v2.pcap

Traffic Phases:
  1. HTTP Peak     - 33% (3,300,000 pkts) - Intensity: 1.3x, Jitter: 20ms
  2. DNS Burst     - 20% (2,000,000 pkts) - Intensity: 0.8x, Jitter: 50ms
  3. SSH Stable    - 27% (2,700,000 pkts) - Intensity: 0.6x, Jitter: 10ms
  4. UDP Light     - 20% (2,000,000 pkts) - Intensity: 0.5x, Jitter: 80ms

Starting packet generation with temporal phases...

Phase 1/4: HTTP Peak (target: 3,300,000 packets)
  Progress: 1,000,000/10,000,000 (10%)
  ...
  Phase HTTP Peak complete: 3,300,000 packets generated

...

Total packets generated: 10,000,000
File size: 850.23 MB

Traffic Statistics:
  HTTP:    4,500,000 packets (45%)
  DNS:     2,200,000 packets (22%)
  SSH:     2,100,000 packets (21%)
  ICMP:      800,000 packets ( 8%)
  UDP:       400,000 packets ( 4%)

================================================================================
Generation complete!
================================================================================
```

## Performance

- **Generation speed:** ~400-600K packets/min (depends on system)
- **File size:** ~85 MB per million packets
- **Memory usage:** <500 MB peak
- **Duration (10M pkts):** ~15-25 minutes

## Traffic Characteristics

### Phase 1: HTTP Peak (33% - Morning Peak)

```
Time: 0-5 minutes (simulated)
Traffic: 70% HTTP, 15% DNS, 5% SSH, 5% ICMP, 5% UDP
Intensity: 1.3× normal
Packet sizes: 200-1200 bytes (HTTP responses)
Jitter: 20ms (moderate)
```

**Use case:** Simulates morning peak when users access web services heavily.

### Phase 2: DNS Burst (20% - DNS Heavy)

```
Time: 5-8 minutes (simulated)
Traffic: 30% HTTP, 50% DNS, 5% SSH, 10% ICMP, 5% UDP
Intensity: 0.8× normal
Packet sizes: 50-300 bytes (DNS queries/responses)
Jitter: 50ms (high - bursts)
```

**Use case:** Simulates DNS burst periods (e.g., after network restart, cache expiry).

### Phase 3: SSH Stable (27% - Stable Sessions)

```
Time: 8-12 minutes (simulated)
Traffic: 35% HTTP, 10% DNS, 40% SSH, 5% ICMP, 10% UDP
Intensity: 0.6× normal (quieter)
Packet sizes: 50-500 bytes (SSH encrypted data)
Jitter: 10ms (low - stable)
```

**Use case:** Simulates stable SSH sessions for remote management.

### Phase 4: UDP Light (20% - Background)

```
Time: 12-15 minutes (simulated)
Traffic: 25% HTTP, 15% DNS, 10% SSH, 15% ICMP, 35% UDP
Intensity: 0.5× normal (low traffic)
Packet sizes: 50-400 bytes (UDP services)
Jitter: 80ms (very high - background services)
```

**Use case:** Simulates background UDP services (NTP, SNMP, mDNS).

## Comparison: v1 vs v2

| Feature | v1 (Original) | v2 (ML-Enhanced) |
|---------|---------------|------------------|
| **Traffic Pattern** | Constant, uniform | 4 temporal phases |
| **Packet Sizes** | Fixed ranges | Variable ±20-50% jitter |
| **Timing** | Regular intervals | 10-80ms jitter per phase |
| **Intensity** | Constant | Varies 0.5× to 1.3× |
| **Protocol Mix** | Static 50/20/15/10/5 | Dynamic per phase |
| **Realism** | Moderate | High |
| **ML Training** | Good | Excellent |
| **Use Case** | Simple experiments | ML model training |

## When to Use v1 vs v2

### Use v1 (Original) when:
- Quick testing needed
- Simple baseline required
- Constant traffic pattern preferred
- Faster generation needed (~2× faster)

### Use v2 (ML-Enhanced) when:
- Training ML models
- Need realistic traffic patterns
- Testing temporal detection algorithms
- Better feature diversity required
- Preparing production-like datasets

## Verification

After generation, verify the PCAP:

```bash
# Check file exists and size
ls -lh benign_10M_v2.pcap

# View first 100 packets
tcpdump -r benign_10M_v2.pcap -n | head -100

# Count by protocol
tcpdump -r benign_10M_v2.pcap -n 'tcp port 80' | wc -l  # HTTP
tcpdump -r benign_10M_v2.pcap -n 'udp port 53' | wc -l  # DNS
tcpdump -r benign_10M_v2.pcap -n 'tcp port 22' | wc -l  # SSH
tcpdump -r benign_10M_v2.pcap -n 'icmp' | wc -l         # ICMP
tcpdump -r benign_10M_v2.pcap -n 'udp and not port 53' | wc -l  # UDP (non-DNS)
```

## Integration with MIRA Detector

Use the generated PCAP with MIRA detector for data collection:

```bash
# Terminal 1: Start detector
cd /local/dpdk_100g/mira/detector_system
sudo timeout 300 ./mira_ddos_detector \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../ml_system/datasets/raw_logs/benign_baseline_v2.log

# Terminal 2: Send traffic (wait 5s)
cd /local/dpdk_100g/mira/benign_sender
sleep 5
sudo timeout 295 ./build/dpdk_pcap_sender \
    -l 0-7 -n 4 -w 0000:41:00.0 -- ../benign_10M_v2.pcap
```

## Troubleshooting

### Issue: Generation is slow

**Solution:** This is normal. v2 generates more complex patterns. Expected: 15-25 minutes for 10M packets.

### Issue: Memory error

**Solution:** Reduce `--packets` to 5M or less, or increase system RAM.

### Issue: Scapy not found

**Solution:**
```bash
pip3 install scapy
```

### Issue: Permission denied on write

**Solution:**
```bash
# Check directory permissions
ls -ld .
# Or write to different directory
python3 generate_benign_traffic_v2.py --output /tmp/benign_10M_v2.pcap
```

## Technical Details

### Packet Structure

All packets maintain proper structure:
- Ethernet (14 bytes): src/dst MAC
- IP (20 bytes): src/dst IP
- TCP/UDP/ICMP (20/8/8 bytes): protocol headers
- Payload: Variable (phase-dependent)

### TCP Flows (HTTP, SSH)

Complete 3-way handshake + data + FIN/ACK teardown:
```
SYN → SYN-ACK → ACK → DATA → FIN → FIN-ACK → ACK
```

### UDP Flows (DNS)

Query + Response:
```
DNS Query → DNS Response
```

### Randomization

- Source ports: 49152-65535 (ephemeral range)
- Sequence numbers: Random 32-bit
- Payload data: Random bytes (except HTTP/DNS headers)
- Client IPs: Spread across range (default: 500 clients)

## Future Enhancements

Potential improvements for v3.0:
- [ ] User-configurable phases
- [ ] HTTPS/TLS encrypted traffic
- [ ] More application protocols (FTP, SMTP, etc.)
- [ ] Packet loss simulation
- [ ] Network delay simulation
- [ ] Real PCAP trace replay with modifications

## License

Part of MIRA DDoS Detection System
Author: MIRA Team
Version: 2.0
Date: 2025-12-05
