# Attack Generator Usage Guide

## Quick Start

### Prerequisites

```bash
# Install Python dependencies
pip3 install scapy numpy scipy pandas
```

### Basic Commands

#### 1. Generate Single Attack (Pure)

```bash
# SYN Flood
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --attack syn_flood \
  --num-packets 100000 \
  --pps 10000 \
  --output-dir /local/pcaps

# UDP Flood
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --attack udp_flood \
  --num-packets 150000 \
  --pps 15000 \
  --output-dir /local/pcaps
```

Output: `/local/pcaps/syn_flood.pcap`, `/local/pcaps/udp_flood.pcap`

#### 2. Generate Benign Traffic

```bash
# Generate realistic benign traffic
sudo python3 -m attack_generator \
  --benign-only \
  --output /local/pcaps/benign_traffic.pcap \
  --benign-duration 120 \
  --benign-profile normal \
  --seed 42
```

**Profiles**:
- `light`: ~1K PPS
- `normal`: ~5K PPS (default)
- `heavy`: ~20K PPS

#### 3. Generate Mixed Traffic (Attack + Benign)

```bash
# Mix attack with existing benign PCAP
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --attack syn_flood \
  --num-packets 100000 \
  --pps 10000 \
  --mix-benign /local/pcaps/benign_traffic.pcap \
  --attack-ratio 0.3 \
  --output-dir /local/pcaps
```

Output:
- `/local/pcaps/syn_flood.pcap` (pure attack)
- `/local/pcaps/syn_flood_mixed.pcap` (30% attack, 70% benign)

## Advanced Usage

### Configuration File Method (Recommended)

#### Create Configuration JSON

```bash
cat > attacks_config.json << 'EOF'
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 100000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000},
    {"type": "icmp_flood", "num_packets": 60000, "pps": 6000}
  ]
}
EOF
```

#### Execute with Config File

```bash
sudo python3 -m attack_generator --config attacks_config.json
```

#### Execute with stdin (Inline JSON)

```bash
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --mix-benign /local/pcaps/benign_traffic.pcap \
  --attack-ratio 0.3 \
  --config - <<'EOF'
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 100000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000}
  ]
}
EOF
```

## Complete Experiment Workflow

### Step 1: Generate Benign Traffic

```bash
cd /local/dpdk_100g

# Create benign background traffic
sudo python3 -m attack_generator \
  --benign-only \
  --output /local/pcaps/benign_traffic.pcap \
  --benign-duration 120 \
  --benign-profile heavy \
  --seed 42

# Verify generated PCAP
ls -lh /local/pcaps/benign_traffic.pcap
tcpdump -r /local/pcaps/benign_traffic.pcap -c 10
```

### Step 2: Generate Attack PCAPs with Mixing

```bash
# Generate all attack types with benign mixing
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --mix-benign /local/pcaps/benign_traffic.pcap \
  --attack-ratio 0.3 \
  --config - <<'EOF'
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 100000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000},
    {"type": "dns_amp", "num_packets": 80000, "pps": 8000},
    {"type": "http_flood", "num_packets": 50000, "pps": 5000},
    {"type": "icmp_flood", "num_packets": 60000, "pps": 6000}
  ]
}
EOF
```

### Step 3: Verify Generated Files

```bash
# List all generated PCAPs
ls -lh /local/pcaps/

# Expected output:
# - benign_traffic.pcap
# - syn_flood.pcap
# - syn_flood_mixed.pcap
# - udp_flood.pcap
# - udp_flood_mixed.pcap
# - ...
# - metadata.json

# Inspect a PCAP
tcpdump -r /local/pcaps/syn_flood_mixed.pcap -c 20 -n

# View metadata
cat /local/pcaps/metadata.json | jq '.'
```

### Step 4: Quick Stats

```bash
# Packet counts
for pcap in /local/pcaps/*.pcap; do
  count=$(capinfos -c "$pcap" 2>/dev/null | grep "Number of packets" | awk '{print $NF}')
  echo "$(basename $pcap): $count packets"
done
```

## Helper Scripts

### Regenerate Mixed Attacks

```bash
cd /local/dpdk_100g/attack_generator

# Full regeneration (all attacks)
./regenerate_mixed_attacks.sh

# Simple regeneration (SYN + UDP)
./regenerate_simple_mixed.sh

# Quick test
./test_mix.sh
```

## Common Patterns

### Pattern 1: Quick Test (Single Attack)

```bash
# Generate + verify in one go
sudo python3 -m attack_generator \
  --attack syn_flood \
  --num-packets 10000 \
  --pps 1000 \
  --output-dir /tmp/test && \
ls -lh /tmp/test/ && \
tcpdump -r /tmp/test/syn_flood.pcap -c 5 -n
```

### Pattern 2: Reproducible Experiment

```bash
# Same seed = exact same packets
SEED=12345

# Run 1
sudo python3 -m attack_generator \
  --attack syn_flood \
  --num-packets 10000 \
  --seed $SEED \
  --output-dir /tmp/run1

# Run 2 (identical output)
sudo python3 -m attack_generator \
  --attack syn_flood \
  --num-packets 10000 \
  --seed $SEED \
  --output-dir /tmp/run2

# Verify identical
md5sum /tmp/run1/syn_flood.pcap /tmp/run2/syn_flood.pcap
```

### Pattern 3: Batch Generation for ML

```bash
# Generate multiple variations for training
for ratio in 0.1 0.3 0.5 0.7; do
  sudo python3 -m attack_generator \
    --target-ip 10.10.1.2 \
    --attack syn_flood \
    --num-packets 50000 \
    --mix-benign /local/pcaps/benign_traffic.pcap \
    --attack-ratio $ratio \
    --output-dir /local/pcaps/dataset_ratio_${ratio} \
    --seed $RANDOM
done
```

### Pattern 4: High-Rate Attack

```bash
# Generate high-intensity attack for stress testing
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --attack udp_flood \
  --num-packets 1000000 \
  --pps 100000 \
  --output-dir /local/pcaps
```

## CloudLab Workflow

### Full CloudLab Experiment Script

```bash
#!/bin/bash
# generate_and_test.sh

set -e

# Configuration
TARGET_IP="10.10.1.2"
PCAP_DIR="/local/pcaps"
SEED=42

echo "[1/3] Generating benign traffic..."
cd /local/dpdk_100g
sudo python3 -m attack_generator \
  --benign-only \
  --output $PCAP_DIR/benign.pcap \
  --benign-duration 60 \
  --benign-profile normal \
  --seed $SEED

echo "[2/3] Generating attacks with mixing..."
sudo python3 -m attack_generator \
  --target-ip $TARGET_IP \
  --mix-benign $PCAP_DIR/benign.pcap \
  --attack-ratio 0.3 \
  --config - <<EOF
{
  "target_ip": "$TARGET_IP",
  "output_dir": "$PCAP_DIR",
  "seed": $SEED,
  "attacks": [
    {"type": "syn_flood", "num_packets": 100000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000}
  ]
}
EOF

echo "[3/3] Verification..."
ls -lh $PCAP_DIR/*.pcap

echo "Generation complete! Ready for experiments."
echo "Next: Start detector and run ./run_mixed_experiment.sh"
```

### Make Executable and Run

```bash
chmod +x generate_and_test.sh
sudo ./generate_and_test.sh
```

## Troubleshooting

### Error: Permission Denied

```bash
# Solution: Use sudo
sudo python3 -m attack_generator ...
```

### Error: Module not found

```bash
# Solution: Install from project root
cd /local/dpdk_100g
pip3 install scapy numpy scipy

# Or run as module from project root
cd /local/dpdk_100g
sudo python3 -m attack_generator ...
```

### Error: No benign PCAP when mixing

```bash
# Solution: Generate benign traffic first
sudo python3 -m attack_generator \
  --benign-only \
  --output /local/pcaps/benign.pcap \
  --benign-duration 60
```

### Large PCAP Generation is Slow

```bash
# Solution: Reduce packet count or use higher PPS
# Instead of 1M packets at 10K PPS (100 seconds)
sudo python3 -m attack_generator --num-packets 1000000 --pps 10000

# Use 100K packets at 10K PPS (10 seconds)
sudo python3 -m attack_generator --num-packets 100000 --pps 10000
```

## Parameter Reference

### Required Parameters

- `--target-ip IP`: Target/victim IP address

### Attack Generation

- `--attack TYPE`: Attack type (syn_flood, udp_flood, icmp_flood, http_flood, dns_amp)
- `--num-packets N`: Number of packets to generate
- `--pps RATE`: Packets per second (attack rate)
- `--output-dir DIR`: Output directory for PCAPs (default: ./pcaps)

### Configuration

- `--config FILE`: JSON configuration file (or `-` for stdin)
- `--seed N`: Random seed for reproducibility

### Mixing

- `--mix-benign FILE`: Benign PCAP file to mix with attacks
- `--attack-ratio RATIO`: Attack traffic ratio (0.0-1.0, default: 0.3)

### Benign Traffic

- `--benign-only`: Generate only benign traffic
- `--benign-duration SECS`: Duration of benign traffic (default: 60)
- `--benign-profile PROF`: Traffic profile (light, normal, heavy)
- `--output FILE`: Output file for benign-only mode

## Examples by Use Case

### Use Case 1: Quick Detection Test

```bash
# Generate small mixed traffic for quick test
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --attack syn_flood \
  --num-packets 10000 \
  --pps 5000 \
  --mix-benign /local/pcaps/benign.pcap \
  --attack-ratio 0.5 \
  --output-dir /tmp/quick_test
```

### Use Case 2: ML Training Dataset

```bash
# Generate diverse dataset with different attack types and ratios
# See Pattern 3 in Common Patterns section
```

### Use Case 3: Stress Testing

```bash
# High-rate volumetric attack
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --attack udp_flood \
  --num-packets 500000 \
  --pps 50000 \
  --output-dir /local/pcaps/stress
```

### Use Case 4: Multi-Vector Attack

```bash
# Combination of multiple attack types
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --config - <<'EOF'
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps/multi_vector",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 50000, "pps": 8000},
    {"type": "udp_flood", "num_packets": 100000, "pps": 12000},
    {"type": "http_flood", "num_packets": 30000, "pps": 3000}
  ]
}
EOF
```

## Next Steps

- For architecture details, see `ARCHITECTURE.md`
- For experiment workflow, see main project `EXPERIMENTS.md`
- For detector integration, see `../detector_system/README.md`
