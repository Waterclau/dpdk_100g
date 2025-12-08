# DPDK PCAP Sender v2.0 - Attack Traffic Replay

This directory contains the DPDK-based PCAP sender for replaying **attack traffic** with temporal capabilities.

## Files

- `dpdk_pcap_sender.c` - Original sender (v1, fast mode only)
- `dpdk_pcap_sender_v2.c` - **Enhanced sender (v2, temporal + adaptive modes)**
- `Makefile` - Build configuration for v1
- `Makefile_v2` - Build configuration for v2
- `phases_example.json` - Example phase configuration for adaptive mode

## Building

### Build v1 (original, fast mode only)
```bash
make
```

### Build v2 (enhanced, with temporal and adaptive modes)
```bash
make -f Makefile_v2 v2
```

## v2 Features

The v2 sender adds three replay modes:

1. **Fast mode** (default, same as v1) - Maximum speed (~12Gbps)
2. **Timed mode** (`--pcap-timed`) - Respects PCAP timestamps for realistic replay
3. **Adaptive mode** (`--adaptive`) - Continuous high-speed traffic with phase-based protocol distribution

### New Parameters (v2)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--pcap-timed` | Respect PCAP timestamps (realistic temporal replay) | Off |
| `--speedup N` | Speed multiplier for timed mode (e.g., 50 = 50× faster) | 1.0 |
| `--jitter X` | Add ±X% random timing variation | 0 |
| `--adaptive` | Enable adaptive mode (continuous traffic) | Off |
| `--rate-gbps N` | Target rate for adaptive mode (Gbps) | 12.0 |
| `--phases FILE` | JSON file with phase definitions | Built-in phases |
| `--loop` | Loop indefinitely in adaptive mode | Off |
| `--duration N` | Run for N seconds (adaptive mode) | Infinite |

## Usage Examples

### 1. Fast Mode (Standard, ~12Gbps)

Use this for **quick ML data collection** with attack PCAPs generated using `--speedup 50`:

```bash
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2_fast.pcap
```

**When to use:**
- ✅ Attack PCAPs generated with `--speedup 50`
- ✅ Fast ML training data collection (~6s for 10M packets)
- ✅ Maximum throughput testing

### 2. Timed Mode (Realistic Temporal Replay)

Use this for **realistic attack simulation** with temporal phases:

```bash
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2.pcap --pcap-timed --jitter 10
```

**Parameters:**
- `--pcap-timed`: Respects PCAP timestamps (realistic phases)
- `--jitter 10`: Adds ±10% timing variation (more realistic)

**When to use:**
- ✅ Attack PCAPs with realistic timestamps (no speedup)
- ✅ Research requiring temporal accuracy
- ✅ Realistic attack behavior analysis

**Speed:** ~500Mbps (slower, but realistic)

### 3. Adaptive Mode (Continuous Attack Traffic)

Use this for **long-running attack simulations** with continuous high-speed traffic:

```bash
# Example 1: Continuous attack traffic (loop forever at 12Gbps)
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2.pcap --adaptive --loop

# Example 2: Attack for 5 minutes with custom phases
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2.pcap --adaptive --duration 300 --phases phases_attack.json

# Example 3: Attack at 10Gbps with jitter
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2.pcap --adaptive --rate-gbps 10 --jitter 15 --loop
```

**When to use:**
- ✅ Long-running attack simulations (hours/days)
- ✅ Continuous stress testing
- ✅ Production-like attack scenarios
- ✅ Detector endurance testing

**Note:** Adaptive mode uses PCAP as a packet pool, not a sequence. It randomly selects packets based on protocol distribution per phase.

## ML Training Workflow

### Step 1: Generate Attack PCAPs with Speedup

```bash
cd /local/dpdk_100g/mira/attack_generator

# Generate fast attack PCAP (50× compressed)
python3 generate_mirai_attacks_v2.py \
    --output ../attack_mirai_10M_v2_fast.pcap \
    --packets 10000000 \
    --attack-type mixed \
    --speedup 50 \
    --attacker-range 10.10.2.0/24 \
    --target-ip 10.10.1.2
```

### Step 2: Collect Detector Logs (Fast Mode)

```bash
# Terminal 1 - Monitor node (detector)
cd /local/dpdk_100g/mira/detector_system
sudo timeout 30 ./mira_ddos_detector \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../ml_system/datasets/raw_logs/mixed_attack_v2.log

# Terminal 2 - TG node (attack sender) - WAIT 5 seconds!
cd /local/dpdk_100g/mira/attack_sender
sleep 5
sudo timeout 25 ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2_fast.pcap
```

**Duration:** ~6-8 seconds total (vs ~300s without speedup)

### Step 3: Repeat for All Attack Types

```bash
# SYN flood
python3 generate_mirai_attacks_v2.py --attack-type syn --speedup 50 --output ../attack_syn_5M_v2_fast.pcap

# UDP flood
python3 generate_mirai_attacks_v2.py --attack-type udp --speedup 50 --output ../attack_udp_5M_v2_fast.pcap

# HTTP flood
python3 generate_mirai_attacks_v2.py --attack-type http --speedup 50 --output ../attack_http_5M_v2_fast.pcap

# DNS amplification
python3 generate_mirai_attacks_v2.py --attack-type dns --speedup 50 --output ../attack_dns_5M_v2_fast.pcap
```

Then replay each with the v2 sender.

## Mode Comparison

| Feature | Fast Mode | Timed Mode | Adaptive Mode |
|---------|-----------|------------|---------------|
| Speed | ~12 Gbps | ~500 Mbps | ~12 Gbps |
| Duration | PCAP length | PCAP length | Infinite |
| Phases | No (flat) | Yes (realistic) | Yes (loop) |
| Timestamps | Ignored | Respected | Generated |
| Use case | Fast collection | Research | Long-running |
| Best for | ML training | Temporal analysis | Stress testing |

## CloudLab Network Compliance

**⚠️ IMPORTANT:** Always use CloudLab internal network IPs!

When generating attack PCAPs, use:
- ✅ Attacker IPs: `10.10.2.0/24` (internal network)
- ✅ Target IP: `10.10.1.2` (internal network)
- ❌ **NEVER**: `192.168.x.x` (control network - experiment will be terminated!)

Verify before sending:
```bash
tcpdump -r ../attack_mirai_10M_v2_fast.pcap -n | head -20
# Should show 10.10.2.x → 10.10.1.2, NOT 192.168.x.x
```

## Troubleshooting

### Issue: "No such file or directory" when running v2

**Solution:** Build v2 first:
```bash
make -f Makefile_v2 v2
ls -lh dpdk_pcap_sender_v2  # Verify binary exists
```

### Issue: Adaptive mode not working

**Solution:** Check that you're using `--adaptive` flag:
```bash
# Wrong (fast mode)
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- file.pcap

# Correct (adaptive mode)
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- file.pcap --adaptive --loop
```

### Issue: Timed mode too slow

**Solution:** Use speedup multiplier or switch to fast mode:
```bash
# Option 1: Speed up timed replay 10×
sudo ./dpdk_pcap_sender_v2 ... -- file.pcap --pcap-timed --speedup 10

# Option 2: Use fast mode with pre-compressed PCAP (recommended)
# Generate PCAP with --speedup 50, then replay in fast mode (no --pcap-timed)
sudo ./dpdk_pcap_sender_v2 ... -- file_fast.pcap
```

## Version History

**v2.0** (2025-12-08):
- ✅ Temporal replay mode (`--pcap-timed`, `--speedup`, `--jitter`)
- ✅ Adaptive mode (`--adaptive`, `--loop`, `--duration`, `--phases`)
- ✅ Protocol-based packet classification
- ✅ Phase-based traffic generation
- ✅ JSON phase configuration support

**v1.0** (Original):
- Fast mode only (~12Gbps)
- No temporal support
- Sequential PCAP replay

---

**See also:**
- `../attack_generator/README_v2.md` - Attack traffic generation guide
- `../stepsML.md` - Complete ML training workflow
- `../benign_sender/README_v2.md` - Benign sender documentation (same features)

---

**Document Version:** 1.0
**Last Updated:** 2025-12-08
**Location:** `mira/attack_sender/`
