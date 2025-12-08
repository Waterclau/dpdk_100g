# MIRA Attack Generator v2.0 - Mirai-Style DDoS with Temporal Phases

## Overview

`generate_mirai_attacks_v2.py` generates realistic DDoS attack traffic with temporal phases and Mirai botnet signatures for ML-enhanced detector training.

## Features

### 1. Attack Phases (Escalating Attack Patterns)

| Phase | Duration % | Name | Intensity | Jitter | Description |
|-------|-----------|------|-----------|--------|-------------|
| 1 | 10% | Warm-up Scan | 0.3× | 200ms | Reconnaissance, port scanning |
| 2 | 40% | SYN Flood Peak | 5.0× | 5ms | Main attack wave, high intensity |
| 3 | 30% | Mixed Bot Waves | 3.0× | 50ms | Distributed attack patterns |
| 4 | 20% | Random Spikes | 2.0× | 150ms | Unpredictable bursts |

### 2. Attack Vectors

- **SYN Flood**: Target ports 80, 443, 22, 23, 2323, 37215, 52869, 5555
- **UDP Flood**: 516-byte payloads (CICDDoS2019 style)
- **HTTP Flood**: Complete TCP handshake with Mirai HTTP payloads
- **DNS Amplification**: DNS ANY queries
- **ACK Scans**: Reconnaissance scans

### 3. Mirai Signatures

Real botnet payloads based on Mirai malware analysis:
- IoT exploit requests (`/setup.cgi`, `/cgi-bin/admin.cgi`)
- Port scanning patterns
- Randomized User-Agent strings
- Typical botnet handshake patterns

### 4. CloudLab Compliance

**⚠️ IMPORTANT:** Always use CloudLab internal network IPs!

- ✅ **Attacker IPs**: `10.10.2.0/24` (default, CloudLab internal)
- ✅ **Target IP**: `10.10.1.2` (default, CloudLab internal)
- ❌ **NEVER**: `192.168.x.x` (public control network - will get experiment terminated!)

### 5. Timestamp Compression

Same `--speedup` parameter as benign generator:
- Compresses timeline by factor N
- Preserves attack phases and patterns
- Example: `--speedup 50` → 300s becomes 6s (50× faster)

---

## Usage Examples

### Basic Usage (10M packets, mixed attack)

```bash
python3 generate_mirai_attacks_v2.py \
    --output ../attack_mirai_10M_v2.pcap \
    --packets 10000000 \
    --attack-type mixed \
    --attacker-range 10.10.2.0/24 \
    --target-ip 10.10.1.2
```

### High-Speed ML Training (50× faster)

```bash
python3 generate_mirai_attacks_v2.py \
    --output ../attack_mirai_10M_v2_fast.pcap \
    --packets 10000000 \
    --attack-type mixed \
    --speedup 50 \
    --intensity 1.5 \
    --attacker-range 10.10.2.0/24 \
    --target-ip 10.10.1.2
```

### Specific Attack Types

#### SYN Flood Only (High Intensity)

```bash
python3 generate_mirai_attacks_v2.py \
    --output ../attack_syn_5M_v2.pcap \
    --packets 5000000 \
    --attack-type syn \
    --intensity 3.0 \
    --attacker-range 10.10.2.0/24 \
    --target-ip 10.10.1.2
```

#### UDP Flood Only

```bash
python3 generate_mirai_attacks_v2.py \
    --output ../attack_udp_5M_v2.pcap \
    --packets 5000000 \
    --attack-type udp \
    --intensity 2.0 \
    --speedup 50 \
    --attacker-range 10.10.2.0/24 \
    --target-ip 10.10.1.2
```

#### HTTP Flood Only (Application Layer)

```bash
python3 generate_mirai_attacks_v2.py \
    --output ../attack_http_5M_v2.pcap \
    --packets 5000000 \
    --attack-type http \
    --intensity 1.5 \
    --attacker-range 10.10.2.0/24 \
    --target-ip 10.10.1.2
```

#### DNS Amplification

```bash
python3 generate_mirai_attacks_v2.py \
    --output ../attack_dns_5M_v2.pcap \
    --packets 5000000 \
    --attack-type dns \
    --intensity 2.0 \
    --attacker-range 10.10.2.0/24 \
    --target-ip 10.10.1.2
```

#### Random Attack Pattern

```bash
python3 generate_mirai_attacks_v2.py \
    --output ../attack_random_10M_v2.pcap \
    --packets 10000000 \
    --attack-type random \
    --intensity 5.0 \
    --speedup 50 \
    --attacker-range 10.10.2.0/24 \
    --target-ip 10.10.1.2
```

---

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--output` | `attack_mirai_10M_v2.pcap` | Output PCAP file path |
| `--packets` | `10000000` | Total number of packets to generate |
| `--attack-type` | `mixed` | Attack type: mixed, syn, udp, http, dns, random |
| `--intensity` | `1.0` | Attack intensity multiplier (1.0-5.0) |
| `--speedup` | `1.0` | Timestamp compression factor (e.g., 50 = 50× faster) |
| `--attacker-range` | `10.10.2.0/24` | Attacker IP range (CIDR notation) |
| `--target-ip` | `10.10.1.2` | Target/victim IP address |
| `--attackers` | `200` | Number of unique attacker IPs (botnet size) |
| `--src-mac` | Auto-generated | Source MAC address |
| `--dst-mac` | Auto-generated | Destination MAC address |

---

## Attack Types

| Type | Description | Protocols | Use Case |
|------|-------------|-----------|----------|
| `mixed` | All attack vectors mixed realistically | SYN, UDP, HTTP, DNS, ACK | ML training, realistic scenario |
| `syn` | SYN flood only | TCP SYN | SYN-specific detection testing |
| `udp` | UDP flood only | UDP (random ports) | UDP-specific detection testing |
| `http` | HTTP flood with handshake | TCP + HTTP | Application-layer attack testing |
| `dns` | DNS amplification | UDP port 53 | DNS-specific testing |
| `random` | Randomized attack per phase | All | Unpredictable attack simulation |

---

## Intensity Levels

| Intensity | Description | Effect | Use Case |
|-----------|-------------|--------|----------|
| 1.0 | Normal (default) | Baseline attack rate | Moderate attacks |
| 2.0 | Medium | 2× more packets | Medium-intensity testing |
| 3.0 | High | 3× more packets | High-intensity testing |
| 5.0 | Maximum | 5× more packets | Extreme stress testing |

**Note:** Intensity multiplier is applied ON TOP of phase intensity (e.g., SYN Flood Peak phase has 5.0× base intensity, so `--intensity 2.0` results in 10× total).

---

## ML Training Workflow

### Step 1: Generate Attack PCAPs

Generate one PCAP per attack type for ML training:

```bash
cd /local/dpdk_100g/mira/attack_generator

# 1. Mixed attack (all types)
python3 generate_mirai_attacks_v2.py \
    --output ../attack_mirai_10M_v2_fast.pcap \
    --packets 10000000 --attack-type mixed --speedup 50 \
    --attacker-range 10.10.2.0/24 --target-ip 10.10.1.2

# 2. SYN flood
python3 generate_mirai_attacks_v2.py \
    --output ../attack_syn_5M_v2_fast.pcap \
    --packets 5000000 --attack-type syn --speedup 50 \
    --attacker-range 10.10.2.0/24 --target-ip 10.10.1.2

# 3. UDP flood
python3 generate_mirai_attacks_v2.py \
    --output ../attack_udp_5M_v2_fast.pcap \
    --packets 5000000 --attack-type udp --speedup 50 \
    --attacker-range 10.10.2.0/24 --target-ip 10.10.1.2

# 4. HTTP flood
python3 generate_mirai_attacks_v2.py \
    --output ../attack_http_5M_v2_fast.pcap \
    --packets 5000000 --attack-type http --speedup 50 \
    --attacker-range 10.10.2.0/24 --target-ip 10.10.1.2

# 5. DNS amplification
python3 generate_mirai_attacks_v2.py \
    --output ../attack_dns_5M_v2_fast.pcap \
    --packets 5000000 --attack-type dns --speedup 50 \
    --attacker-range 10.10.2.0/24 --target-ip 10.10.1.2
```

**Duration:** ~10-15 minutes total for all attack types

### Step 2: Collect Detector Logs

Run detector and replay each attack PCAP:

```bash
# Example for mixed attack
# Terminal 1 - Monitor node
cd /local/dpdk_100g/mira/detector_system
sudo timeout 30 ./mira_ddos_detector \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../ml_system/datasets/raw_logs/mixed_attack_v2.log

# Terminal 2 - TG node
cd /local/dpdk_100g/mira/attack_sender
sleep 5
sudo timeout 25 ./build/dpdk_pcap_sender \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2_fast.pcap
```

Repeat for all attack types.

### Step 3: Extract Features and Train

```bash
cd /local/dpdk_100g/mira/ml_system/01_data_collection

# Extract features from each log
python3 feature_extractor.py \
    --input ../datasets/raw_logs/mixed_attack_v2.log \
    --output ../datasets/processed/mixed_attack_v2.csv \
    --label mixed_attack

# (Repeat for all attack types)

# Train model
cd ../02_training
python3 export_lightgbm_model.py \
    --train ../datasets/splits/train.csv \
    --output ../../detector_system_ml/lightgbm_model.txt
```

---

## Comparison: Benign vs Attack Traffic

| Aspect | Benign Traffic v2 | Attack Traffic v2 |
|--------|------------------|-------------------|
| **Purpose** | Normal network behavior | DDoS attack simulation |
| **Source IPs** | 10.10.1.0/24 (500 clients) | 10.10.2.0/24 (200 bots) |
| **Target** | 10.10.1.2 (server) | 10.10.1.2 (victim) |
| **Phases** | HTTP/DNS/SSH/UDP normal | Scan/Peak/Waves/Spikes |
| **Intensity** | 0.5×-1.3× (moderate) | 0.3×-5.0× (extreme) |
| **Protocols** | HTTP, DNS, SSH, ICMP, UDP | SYN flood, UDP flood, HTTP flood, DNS amp, ACK scan |
| **Timing Jitter** | 10-80ms (realistic) | 5-200ms (varied by phase) |
| **Realism** | Normal network | Mirai botnet behavior |
| **ML Class** | Benign | Attack (5 subtypes) |

---

## Verification

### Check PCAP Stats

```bash
# View PCAP details
tcpdump -r ../attack_mirai_10M_v2.pcap -n | head -100

# Count packet types
tcpdump -r ../attack_mirai_10M_v2.pcap -n 'tcp[tcpflags] == tcp-syn' | wc -l  # SYN
tcpdump -r ../attack_mirai_10M_v2.pcap -n 'udp and not port 53' | wc -l       # UDP flood
tcpdump -r ../attack_mirai_10M_v2.pcap -n 'tcp port 80' | wc -l               # HTTP
tcpdump -r ../attack_mirai_10M_v2.pcap -n 'udp port 53' | wc -l               # DNS

# Verify timestamp compression
tcpdump -r ../attack_mirai_10M_v2.pcap -n -tttt | head -10        # Normal
tcpdump -r ../attack_mirai_10M_v2_fast.pcap -n -tttt | head -10  # Compressed
```

### Expected Output (Mixed Attack)

```
================================================================================
MIRA Attack Generator v2.0 - Mirai-Style DDoS with Temporal Phases
================================================================================
Target packets: 10,000,000
Output file: ../attack_mirai_10M_v2.pcap
Attack type: mixed
Intensity: 1.0×
Attackers: 200 botnet IPs (10.10.2.0/24)
Target: 10.10.1.2

Attack Phases:
  1. Warm-up Scan   - 10% (1,000,000 pkts) - Intensity: 0.3×, Jitter: 200ms
  2. SYN Flood Peak - 40% (4,000,000 pkts) - Intensity: 5.0×, Jitter: 5ms
  3. Mixed Bot Waves- 30% (3,000,000 pkts) - Intensity: 3.0×, Jitter: 50ms
  4. Random Spikes  - 20% (2,000,000 pkts) - Intensity: 2.0×, Jitter: 150ms

Starting attack generation with temporal phases...

Phase 1/4: Warm-up Scan (target: 1,000,000 packets)
  Progress: 1,000,000/10,000,000 (10%)
  Phase Warm-up Scan complete: 1,000,000 packets generated

Phase 2/4: SYN Flood Peak (target: 4,000,000 packets)
  Progress: 2,000,000/10,000,000 (20%)
  Progress: 3,000,000/10,000,000 (30%)
  Progress: 4,000,000/10,000,000 (40%)
  Progress: 5,000,000/10,000,000 (50%)
  Phase SYN Flood Peak complete: 4,000,000 packets generated

Phase 3/4: Mixed Bot Waves (target: 3,000,000 packets)
  Progress: 6,000,000/10,000,000 (60%)
  Progress: 7,000,000/10,000,000 (70%)
  Progress: 8,000,000/10,000,000 (80%)
  Phase Mixed Bot Waves complete: 3,000,000 packets generated

Phase 4/4: Random Spikes (target: 2,000,000 packets)
  Progress: 9,000,000/10,000,000 (90%)
  Phase Random Spikes complete: 2,000,000 packets generated

Total packets generated: 10,000,000
Writing packets to ../attack_mirai_10M_v2.pcap...
File size: 620.45 MB

Attack Statistics:
  SYN Flood:    4,200,000 packets (42%)
  UDP Flood:    2,800,000 packets (28%)
  HTTP Flood:   1,500,000 packets (15%)
  DNS Amplif:   1,200,000 packets (12%)
  ACK Scan:       300,000 packets ( 3%)

Mirai Signatures:
  IoT Exploit Requests:    150,000
  Port Scan Attempts:      300,000
  Botnet Handshakes:       450,000

================================================================================
Attack generation complete!
================================================================================
```

---

## CloudLab Network Warning

**⚠️ CRITICAL: Always use CloudLab internal network (10.x.x.x), NEVER use public control network (192.168.x.x)!**

### Correct Usage:
```bash
--attacker-range 10.10.2.0/24  # ✅ Internal network
--target-ip 10.10.1.2          # ✅ Internal network
```

### Wrong Usage (DO NOT USE):
```bash
--attacker-range 192.168.2.0/24  # ❌ Control network - EXPERIMENT WILL BE TERMINATED!
--target-ip 192.168.1.2          # ❌ Control network - EXPERIMENT WILL BE TERMINATED!
```

If CloudLab sends a warning about control network traffic:
1. **STOP all traffic immediately**: `sudo pkill dpdk_pcap_sender`
2. **Respond to CloudLab**: Explain you were using wrong IPs and have fixed it
3. **Regenerate all PCAPs**: Use correct 10.x.x.x IPs
4. **Verify before replay**: `tcpdump -r file.pcap -n | head` (should show 10.x.x.x, NOT 192.168.x.x)

See `URGENTE_CLOUDLAB_FIX.md` for detailed recovery steps.

---

## File Locations

```
mira/
├── attack_generator/
│   ├── generate_mirai_attacks_v2.py     # This script
│   └── README_v2.md                      # This file
├── attack_mirai_10M_v2.pcap              # Generated attack PCAPs
├── attack_mirai_10M_v2_fast.pcap         # With --speedup 50
├── attack_syn_5M_v2_fast.pcap
├── attack_udp_5M_v2_fast.pcap
├── attack_http_5M_v2_fast.pcap
└── attack_dns_5M_v2_fast.pcap
```

---

## Version History

**v2.0** (2025-12-08):
- ✅ Temporal attack phases (Warm-up → Peak → Waves → Spikes)
- ✅ Timestamp compression (`--speedup` parameter)
- ✅ CloudLab internal network compliance (10.x.x.x)
- ✅ Mirai botnet signatures
- ✅ Multiple attack vectors (SYN, UDP, HTTP, DNS, ACK)
- ✅ Intensity control (1.0-5.0×)
- ✅ Better ML training (phase diversity)

**v1.0** (Previous):
- Basic attack generation
- Fixed patterns
- No temporal phases
- No timestamp compression

---

## References

- Mirai botnet analysis: https://github.com/jgamblin/Mirai-Source-Code
- CICDDoS2019 dataset: https://www.unb.ca/cic/datasets/ddos-2019.html
- CloudLab documentation: https://docs.cloudlab.us/

---

**Document Version:** 1.0
**Last Updated:** 2025-12-08
**Author:** Claude Code
