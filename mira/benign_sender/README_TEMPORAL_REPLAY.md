# DPDK PCAP Sender v2.0 - Temporal Replay Support

## Overview

Version 2.0 adds **timestamp-based replay** to the DPDK PCAP sender, allowing benign traffic with temporal phases (like `benign_10M_v2.pcap`) to be replayed **realistically** instead of at maximum speed.

## Problem Solved

**Before v2.0:**
- All traffic sent at max speed (~12 Gbps constant)
- Temporal phases in PCAP are ignored
- Traffic appears "flat" to detector
- ML features lose temporal characteristics

**With v2.0:**
- Traffic phases are preserved (HTTP peak → DNS burst → SSH stable → UDP light)
- Realistic timing between packets
- Optional jitter adds variability
- Better for ML training data collection

---

## New Features

### 1. `--pcap-timed`: Timestamp-Based Replay

Respects the original PCAP timestamps, recreating the temporal phases.

```bash
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- benign_10M_v2.pcap --pcap-timed
```

**What happens:**
- Reads timestamp from each packet
- Calculates delta from previous packet
- Waits (`rte_delay_us_block`) for that duration
- Sends packet

**Result:** Traffic phases manifest in real-time!

---

### 2. `--jitter <percent>`: Timing Jitter

Adds random variability to inter-packet delays.

```bash
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- benign_10M_v2.pcap --pcap-timed --jitter 15
```

**Effect:**
- Each delay is multiplied by random factor: `1.0 ± (jitter/100)`
- Example: `--jitter 15` → delays vary ±15% randomly
- Makes traffic more realistic (networks aren't perfectly timed)

**Typical values:**
- `--jitter 5`: Low jitter (stable networks)
- `--jitter 15`: Moderate jitter (realistic)
- `--jitter 30`: High jitter (congested networks)

---

### 3. `--phase-mode`: Adaptive Phase Pacing

Enables adaptive pacing for phase-based traffic (future enhancement).

```bash
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- benign_10M_v2.pcap --phase-mode
```

**Currently:** Activates timed replay mode (same as `--pcap-timed`)
**Future:** Will auto-detect phases and adjust pacing

---

### 4. `--speedup <factor>`: Speedup Factor

Replay faster than real-time (for testing).

```bash
# 10x faster replay
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- benign_10M_v2.pcap --pcap-timed --speedup 10
```

**Use cases:**
- `--speedup 1`: Real-time (default)
- `--speedup 10`: 10× faster (300s PCAP → 30s)
- `--speedup 100`: 100× faster (for quick tests)

**Note:** Phases are preserved, just compressed in time.

---

## Backward Compatibility

**Without any new flags → identical to v1 (original behavior):**

```bash
# This works exactly like dpdk_pcap_sender (v1)
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- attack_udp_5M.pcap
```

- Max speed transmission (~12 Gbps)
- No timestamp consideration
- Original rate limiting
- Fast burst mode

---

## Usage Examples

### Example 1: Realistic Benign Traffic (ML Training)

```bash
# Generate ML-enhanced benign PCAP (if not done)
cd /local/dpdk_100g/mira/benign_generator
python3 generate_benign_traffic_v2.py \
    --output ../benign_10M_v2.pcap \
    --packets 10000000

# Send with temporal replay + jitter
cd /local/dpdk_100g/mira/benign_sender
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../benign_10M_v2.pcap --pcap-timed --jitter 15
```

**Expected behavior:**
- Phases visible in detector logs
- HTTP peak → higher PPS at start
- DNS burst → spike in DNS queries
- SSH stable → lower, steady traffic
- UDP light → background UDP packets

---

### Example 2: Fast Testing (10x Speedup)

```bash
# Replay 300s PCAP in 30s
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../benign_10M_v2.pcap --pcap-timed --speedup 10
```

**Use case:** Quick validation that temporal features work.

---

### Example 3: Attack Traffic (Original Mode)

```bash
# Attack traffic → still use max speed (no timing needed)
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_udp_5M.pcap
```

**No flags → original behavior:** Max speed, rate-limited to 12 Gbps.

---

### Example 4: Mixed Scenario (Benign + Attack)

```bash
# Terminal 1: Detector
cd /local/dpdk_100g/mira/detector_system
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0

# Terminal 2: Benign traffic (timed)
cd /local/dpdk_100g/mira/benign_sender
sudo timeout 300 ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../benign_10M_v2.pcap --pcap-timed --jitter 10

# Terminal 3: Attack traffic (after 130s, fast mode)
cd /local/dpdk_100g/mira/attack_sender
sleep 130
sudo timeout 170 ./dpdk_pcap_sender -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mixed_10M.pcap
```

**Result:** Realistic benign baseline + high-speed attack overlay.

---

## Command-Line Reference

```
Usage: dpdk_pcap_sender_v2 [EAL options] -- <pcap_file> [OPTIONS]

OPTIONS:
  --pcap-timed              Replay PCAP respecting timestamps (temporal phases)
  --jitter <percent>        Add timing jitter (±X%, e.g., 10 for ±10%)
  --phase-mode              Enable adaptive phase-based pacing
  --speedup <factor>        Speedup factor (1=realtime, 10=10x faster, default: 1)

EXAMPLES:
  # Original mode (max speed):
  dpdk_pcap_sender_v2 -l 0-7 -- traffic.pcap

  # Timed replay with jitter (realistic):
  dpdk_pcap_sender_v2 -l 0-7 -- benign_10M_v2.pcap --pcap-timed --jitter 15

  # Timed replay 10x faster:
  dpdk_pcap_sender_v2 -l 0-7 -- benign_10M_v2.pcap --pcap-timed --speedup 10
```

---

## Output Examples

### Timed Mode Output

```
Loading PCAP file: benign_10M_v2.pcap
Loaded 10000000 packets from PCAP

[TIMED MODE] PCAP temporal analysis:
  First timestamp: 1733419200.000000
  Last timestamp:  1733419500.123456
  Total duration:  300.12 seconds
  Average PPS:     33330 packets/sec
  Speedup factor:  1x
  Jitter:          ±15.0%

╔═══════════════════════════════════════════════════════════╗
║         DPDK PCAP SENDER v2.0 - TIMED REPLAY MODE        ║
╚═══════════════════════════════════════════════════════════╝

Replaying PCAP with timestamp-based pacing...
Jitter: ±15.0%  |  Speedup: 1x
Press Ctrl+C to stop

[5.0s] Sent: 166650/10000000 pkts (1.7%) | 0.03 Mpps | 0.45 Gbps
[10.0s] Sent: 333300/10000000 pkts (3.3%) | 0.03 Mpps | 0.46 Gbps
[15.0s] Sent: 500200/10000000 pkts (5.0%) | 0.03 Mpps | 0.44 Gbps
...
[300.0s] Sent: 10000000/10000000 pkts (100.0%) | 0.03 Mpps | 0.45 Gbps

=== TIMED REPLAY COMPLETE ===
Total packets sent:  10000000
Total bytes sent:    8500000000
Duration:            300.45 seconds
Average throughput:  0.45 Gbps
Average pps:         0.03 Mpps
```

### Fast Mode Output (Original)

```
╔═══════════════════════════════════════════════════════════╗
║      DPDK PCAP SENDER - 12.0 Gbps baseline transmission     ║
╚═══════════════════════════════════════════════════════════╝

Starting packet transmission at 12.0 Gbps...
Press Ctrl+C to stop

[5.0s] Sent: 2500000 pkts (0.50 Mpps) | Cumulative: 11.8 Gbps | Instant: 11.9 Gbps
[10.0s] Sent: 5000000 pkts (0.50 Mpps) | Cumulative: 12.0 Gbps | Instant: 12.1 Gbps
...
```

---

## Performance Comparison

| Mode | Throughput | Duration (10M pkts) | Phases Preserved | Use Case |
|------|-----------|---------------------|------------------|----------|
| **v1 (fast)** | ~12 Gbps | ~6 seconds | ❌ No | Attack traffic, speed tests |
| **v2 --pcap-timed** | ~0.4-2 Gbps | ~300 seconds | ✅ Yes | Benign traffic, ML training |
| **v2 --speedup 10** | ~4-20 Gbps | ~30 seconds | ✅ Yes (compressed) | Fast phase testing |

---

## Technical Details

### Timestamp Handling

```c
struct packet_data {
    uint8_t data[2048];
    uint16_t len;
    struct timeval timestamp;  /* NEW: PCAP timestamp */
};

// Calculate inter-packet delay
uint64_t delta_us = timeval_diff_us(&prev_timestamp, &current_timestamp);

// Apply speedup
delta_us = delta_us / speedup_factor;

// Apply jitter
if (jitter_pct > 0) {
    double jitter_mult = 1.0 + random(-jitter_pct, +jitter_pct);
    delta_us = (uint64_t)(delta_us * jitter_mult);
}

// Wait
rte_delay_us_block(delta_us);
```

### Jitter Algorithm

```c
// Random multiplier: 1.0 ± (jitter_pct / 100)
double jitter_factor = jitter_pct / 100.0;
double random_val = (double)rand() / RAND_MAX;  // 0.0 to 1.0
double jitter = (random_val * 2.0 - 1.0) * jitter_factor;  // -jitter to +jitter
double multiplier = 1.0 + jitter;

// Example: jitter_pct = 15
// → jitter_factor = 0.15
// → random_val = 0.7 (example)
// → jitter = (0.7 * 2 - 1) * 0.15 = 0.4 * 0.15 = 0.06
// → multiplier = 1.06 (6% increase)
```

---

## Building

### Build Both Versions

```bash
cd /local/dpdk_100g/mira/benign_sender

# Build using new Makefile
make -f Makefile_v2 all
```

**Output:**
- `dpdk_pcap_sender` (v1 - original)
- `dpdk_pcap_sender_v2` (v2 - temporal replay)

### Build v2 Only

```bash
make -f Makefile_v2 v2
```

---

## Integration with stepsML.md

Updated Phase 1 commands to use v2 with temporal replay:

### Old (Phase 1):

```bash
# Terminal 2 - Controller node
sudo timeout 195 ./build/dpdk_pcap_sender \
    -l 0-7 -n 4 -w 0000:41:00.0 -- ../benign_10M.pcap
```

### New (Phase 1 - ML Enhanced):

```bash
# Terminal 2 - Controller node
sudo timeout 300 ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../benign_10M_v2.pcap --pcap-timed --jitter 10
```

**Benefits:**
- Detector sees realistic traffic phases
- ML features have temporal diversity
- Better training data

---

## Troubleshooting

### Issue: Timed mode too slow

**Cause:** Real-time replay of 300s PCAP takes 300s.

**Solution:** Use `--speedup` factor:
```bash
--pcap-timed --speedup 10  # 10x faster
```

---

### Issue: Traffic still appears flat

**Possible causes:**
1. PCAP doesn't have timestamps → Check with `tcpdump -r file.pcap -tttt | head`
2. Timestamps are all identical → Regenerate PCAP with v2 generator
3. Forgot `--pcap-timed` flag → Add it

**Verify:**
```bash
# Check PCAP has varying timestamps
tcpdump -r benign_10M_v2.pcap -tttt | head -20
```

---

### Issue: Jitter too high/low

**Adjust percentage:**
- Too predictable → Increase: `--jitter 25`
- Too chaotic → Decrease: `--jitter 5`

**Recommended values:**
- Benign traffic: `--jitter 10` to `--jitter 15`
- Attack traffic: No jitter needed (use v1 fast mode)

---

## Future Enhancements

- [ ] Auto-detect traffic phases from PCAP
- [ ] Per-phase jitter configuration
- [ ] Real-time rate adjustment based on detector feedback
- [ ] Multi-PCAP interleaving (benign + attack)
- [ ] PCAP timestamp normalization

---

## Version History

**v2.0 (2025-12-05):**
- Added `--pcap-timed` for timestamp-based replay
- Added `--jitter` for timing variability
- Added `--phase-mode` for adaptive pacing
- Added `--speedup` for faster/slower replay
- Backward compatible with v1

**v1.0:**
- Original sender (max speed, rate-limited to 12 Gbps)

---

## License

Part of MIRA DDoS Detection System
Version: 2.0
Date: 2025-12-05
