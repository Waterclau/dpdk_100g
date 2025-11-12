# Attack Generator - Code Analysis

## Important Code Explanation

This document explains the key code sections in the Attack Generator module.

## Core Files

### 1. `generator.py` - Main Orchestrator

#### Class: AttackPcapGenerator

**Purpose**: Main orchestrator that coordinates attack generation, mixing, and metadata creation.

**Key Method: `__init__()`**
```python
def __init__(self, config: Dict):
    self.config = config
    self.target_ip = config['target_ip']
    self.output_dir = Path(config.get('output_dir', './pcaps'))
    self.seed = config.get('seed', int(time.time()))
    self.sampler = None
    if config.get('dataset_path'):
        self.sampler = self._load_dataset(config['dataset_path'])
```

**What it does**:
- Initializes the generator with configuration
- Sets up output directory for PCAPs
- Configures random seed for reproducibility
- Optionally loads statistical distributions from real datasets

**Key Method: `generate_attack()`**
```python
def generate_attack(self, attack_type: str, num_packets: int,
                   pps: int, dry_run: bool = False) -> Dict:
    generator_class = ATTACK_GENERATORS[attack_type]
    generator = generator_class(self.target_ip, seed=self.seed,
                               sampler=self.sampler)
    packets = generator.generate(num_packets, pps)
    wrpcap(output_file, packets)
```

**What it does**:
1. Looks up the appropriate attack generator class (SYN, UDP, etc.)
2. Instantiates it with target IP and seed
3. Calls `generate()` to create packet list
4. Writes packets to PCAP file using Scapy's `wrpcap()`

**Key Method: `mix_with_benign()`**
```python
def mix_with_benign(self, attack_pcap, benign_pcap, attack_ratio):
    attack_pkts = rdpcap(attack_pcap)
    benign_pkts = rdpcap(benign_pcap)

    # Calculate how many benign packets needed
    total_attack = len(attack_pkts)
    total_benign_needed = int(total_attack * (1 - attack_ratio) / attack_ratio)

    # Sample or replicate benign traffic
    if len(benign_pkts) > total_benign_needed:
        benign_pkts = random.sample(benign_pkts, total_benign_needed)
    else:
        # Replicate to reach needed count
        benign_pkts = (benign_pkts * multiplier)[:total_benign_needed]

    # Assign timestamps and merge
    all_pkts = attack_pkts + benign_pkts
    all_pkts.sort(key=lambda x: x.time)
    wrpcap(output_mixed, all_pkts)
```

**What it does**:
1. Loads both attack and benign PCAPs into memory
2. Calculates required benign packet count based on attack ratio
3. Samples or replicates benign packets to match ratio
4. Assigns temporal timestamps to all packets
5. Sorts by timestamp to create realistic interleaved traffic
6. Writes merged PCAP

**Why it's important**: This creates realistic mixed traffic scenarios where attacks are hidden among legitimate traffic, essential for testing ML-based detectors.

---

### 2. `attacks.py` - Attack Implementations

#### Base Class: AttackGenerator

```python
class AttackGenerator:
    def __init__(self, target_ip, seed=None, sampler=None):
        self.target_ip = target_ip
        self.seed = seed
        self.sampler = sampler
        random.seed(seed)

    def generate(self, num_packets, pps):
        raise NotImplementedError("Subclasses must implement generate()")
```

**What it does**:
- Provides common interface for all attack types
- Handles seed initialization for reproducibility
- Optional sampler for realistic distributions

#### Class: SYNFloodGenerator

**Key Method: `generate()`**
```python
def generate(self, num_packets, pps):
    packets = []
    inter_packet_delay = 1.0 / pps
    current_time = 0

    for i in range(num_packets):
        # Random source IP (spoofing)
        src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}." \
                 f"{random.randint(0,255)}.{random.randint(0,255)}"

        # Random source port
        src_port = random.randint(1024, 65535)

        # Target port (common services)
        dst_port = random.choice([80, 443, 22, 3389, 8080])

        # Create SYN packet
        pkt = Ether() / IP(src=src_ip, dst=self.target_ip) / \
              TCP(sport=src_port, dport=dst_port, flags='S')

        # Assign timestamp
        pkt.time = current_time
        current_time += inter_packet_delay

        packets.append(pkt)

    return packets
```

**What it does**:
1. Calculates inter-packet delay from PPS rate
2. For each packet:
   - Generates random source IP (spoofing simulation)
   - Random source port from ephemeral range
   - Targets common service ports
   - Creates TCP packet with SYN flag set
   - Assigns precise timestamp for replay timing
3. Returns list of packets

**Why this matters**:
- **Spoofed IPs**: Simulates distributed attack from many sources
- **Timing precision**: Accurate PPS for realistic load
- **Port targeting**: Mimics real SYN flood patterns

#### Class: UDPFloodGenerator

**Key Differences**:
```python
# Variable payload sizes (realistic)
payload_size = random.randint(64, 1400)
payload = b'X' * payload_size

# Random destination ports (harder to filter)
dst_port = random.randint(1, 65535)

# Create UDP packet
pkt = Ether() / IP(src=src_ip, dst=self.target_ip) / \
      UDP(sport=src_port, dport=dst_port) / Raw(load=payload)
```

**What makes UDP floods different**:
- Variable payload sizes (64-1400 bytes)
- Random destination ports (not just common ports)
- No TCP state (can't be filtered by connection tracking)
- Higher bandwidth consumption due to payloads

#### Class: HTTPFloodGenerator

**Key Feature: Valid HTTP Payloads**
```python
http_payloads = [
    "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "GET /index.php HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
    "POST /login HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n"
]

http_request = random.choice(http_payloads).format(self.target_ip)

# TCP with PSH+ACK flags (data transfer)
pkt = Ether() / IP(src=src_ip, dst=self.target_ip) / \
      TCP(sport=src_port, dport=80, flags='PA') / \
      Raw(load=http_request.encode())
```

**Why HTTP floods are different**:
- Application-layer attack (Layer 7)
- Valid HTTP syntax passes WAF inspection
- Lower PPS but higher computational cost on server
- Uses TCP PSH+ACK flags (not SYN)

---

### 3. `benign_traffic.py` - Realistic Background Traffic

#### Function: `generate_benign_pcap()`

**Traffic Profile Selection**:
```python
PROFILES = {
    'light': {
        'avg_pps': 1000,
        'tcp_ratio': 0.7,    # 70% TCP
        'udp_ratio': 0.2,    # 20% UDP
        'icmp_ratio': 0.1    # 10% ICMP
    },
    'normal': {
        'avg_pps': 5000,
        'tcp_ratio': 0.75,
        'udp_ratio': 0.2,
        'icmp_ratio': 0.05
    },
    'heavy': {
        'avg_pps': 20000,
        'tcp_ratio': 0.8,
        'udp_ratio': 0.15,
        'icmp_ratio': 0.05
    }
}
```

**Why profiles matter**: Different network loads for testing detector performance under varying background traffic conditions.

**TCP Session Generation**:
```python
def generate_tcp_flow():
    src_ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    dst_ip = f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"

    # 3-way handshake
    syn = TCP(flags='S', seq=1000)
    syn_ack = TCP(flags='SA', seq=2000, ack=1001)
    ack = TCP(flags='A', seq=1001, ack=2001)

    # Data transfer
    data_packets = []
    for i in range(random.randint(1, 10)):
        data_pkt = TCP(flags='PA', seq=seq, ack=ack)
        data_packets.append(data_pkt)
        seq += random.randint(100, 1460)

    # Connection teardown
    fin = TCP(flags='FA', seq=seq)
    fin_ack = TCP(flags='A', ack=seq+1)

    return [syn, syn_ack, ack] + data_packets + [fin, fin_ack]
```

**What it does**:
1. Creates complete TCP session lifecycle
2. Proper 3-way handshake (SYN, SYN-ACK, ACK)
3. Multiple data packets with incrementing sequence numbers
4. Proper connection teardown (FIN, ACK)

**Why it's realistic**:
- Complete TCP state machine
- Realistic sequence number progression
- Variable data packet counts
- Proper connection cleanup

**Inter-Arrival Times (Poisson Distribution)**:
```python
def calculate_inter_arrival_time(avg_pps):
    # Poisson: exponential inter-arrival times
    lambda_rate = avg_pps
    return random.expovariate(lambda_rate)

# Apply to packet generation
current_time = 0
for pkt in packets:
    current_time += calculate_inter_arrival_time(profile['avg_pps'])
    pkt.time = current_time
```

**Why Poisson**: Models real network traffic arrival patterns - packets don't arrive at perfectly uniform intervals but cluster and spread naturally.

---

### 4. `utils.py` - Helper Functions

#### Function: `random_ip()`

```python
def random_ip(subnet="0.0.0.0/0", exclude_private=False):
    if exclude_private:
        # Avoid 10.x.x.x, 192.168.x.x, 172.16-31.x.x
        first_octet = random.choice([1-9, 11-126, 128-172, 173-191, 193-223])
    else:
        first_octet = random.randint(1, 223)

    return f"{first_octet}.{random.randint(0,255)}." \
           f"{random.randint(0,255)}.{random.randint(0,255)}"
```

**Why exclude private**: Some experiments want "internet-like" source IPs that wouldn't come from internal networks.

#### Class: DistributionSampler

**Purpose**: Sample from real traffic distributions for realistic packets

```python
class DistributionSampler:
    def __init__(self, seed=None):
        self.distributions = {}
        self.seed = seed

    def add_distribution(self, name, values):
        # Fit to empirical distribution
        self.distributions[name] = {
            'min': min(values),
            'max': max(values),
            'mean': np.mean(values),
            'std': np.std(values),
            'percentiles': np.percentile(values, [25, 50, 75])
        }

    def sample(self, name):
        if name not in self.distributions:
            return None

        dist = self.distributions[name]
        # Sample from normal distribution with observed parameters
        value = np.random.normal(dist['mean'], dist['std'])
        # Clamp to observed min/max
        return np.clip(value, dist['min'], dist['max'])
```

**Use case**:
```python
# Extract packet sizes from real PCAP
real_pcap = rdpcap("real_traffic.pcap")
packet_sizes = [len(pkt) for pkt in real_pcap]

# Use in attack generation
sampler = DistributionSampler()
sampler.add_distribution('packet_size', packet_sizes)

# Generate attack with realistic sizes
pkt_size = int(sampler.sample('packet_size'))
payload = b'X' * pkt_size
```

**Why it matters**: Attacks using realistic packet size distributions are harder to detect with simple statistical filters.

---

### 5. Shell Scripts - Automation Helpers

The attack generator includes three important shell scripts that automate the dataset generation workflow. These scripts wrap the Python module and handle common operations.

#### Script: `regenerate_mixed_attacks.sh`

**Purpose**: One-step generation of attacks with automatic benign traffic mixing using the generator's built-in `--mix-benign` functionality.

**Usage**:
```bash
./regenerate_mixed_attacks.sh [TARGET_IP] [ATTACK_RATIO] [PCAP_DIR]
# Example:
./regenerate_mixed_attacks.sh 10.10.1.2 0.25 /local/pcaps
```

**Key Workflow**:
```bash
# Step 1: Generate benign traffic (if not exists)
if [ ! -f "$BENIGN_PCAP" ]; then
    sudo python3 -m attack_generator \
      --benign-only \
      --output "$BENIGN_PCAP" \
      --benign-duration 120 \
      --benign-profile heavy \
      --seed 42
fi

# Step 2: Generate attacks WITH automatic mixing
sudo python3 -m attack_generator \
  --target-ip "$TARGET_IP" \
  --mix-benign "$BENIGN_PCAP" \
  --attack-ratio "$ATTACK_RATIO" \
  --config - <<EOF
{
  "target_ip": "$TARGET_IP",
  "output_dir": "$PCAP_DIR",
  "seed": 42,
  "mix_benign": "$BENIGN_PCAP",
  "attack_ratio": 0.25,
  "attacks": [
    {"type": "syn_flood", "num_packets": 50000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000},
    ...
  ]
}
EOF
```

**What it does**:
1. **Checks for benign traffic**: If `benign_traffic.pcap` doesn't exist, generates it first
2. **Benign generation parameters**:
   - 120 seconds duration
   - "heavy" profile (20K PPS average)
   - Seed 42 for reproducibility
3. **Passes mixing parameters to generator**: The Python code handles the mixing internally
4. **Output**: Creates `*_mixed.pcap` files with specified attack ratio

**Attack Ratio Explanation**:
```bash
ATTACK_RATIO=0.25  # 25% attack, 75% benign
# If attack has 50K packets, benign will have 150K packets
# Total: 200K packets (25% attack)
```

**When to use**: When you want the generator to handle mixing internally with precise ratio control.

---

#### Script: `regenerate_simple_mixed.sh`

**Purpose**: Two-step workflow that generates pure attacks first, then mixes them manually using inline Python/Scapy.

**Usage**:
```bash
./regenerate_simple_mixed.sh [TARGET_IP] [PCAP_DIR]
# Example:
./regenerate_simple_mixed.sh 10.10.1.2 /local/pcaps
```

**Key Workflow**:
```bash
# Step 1: Generate benign traffic (same as above)

# Step 2: Generate PURE attacks (WITHOUT mixing)
sudo python3 -m attack_generator \
  --target-ip "$TARGET_IP" \
  --config - <<EOF
{
  "target_ip": "$TARGET_IP",
  "output_dir": "$PCAP_DIR",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 50000, "pps": 10000},
    ...
  ]
}
EOF

# Step 3: Mix each attack manually with inline Python
mix_pcaps() {
    local attack_pcap=$1
    local output_pcap=$2

    python3 << PYMIX
from scapy.all import rdpcap, wrpcap

# Load both PCAPs
attack = rdpcap("${attack_pcap}")
benign = rdpcap("${BENIGN_PCAP}")

# Combine ALL packets (no ratio control)
mixed = list(attack) + list(benign)

# Sort by timestamp
mixed.sort(key=lambda p: p.time if hasattr(p, 'time') else 0)

# Save
wrpcap("${output_pcap}", mixed)
PYMIX
}

# Call for each attack type
for attack in "${ATTACK_TYPES[@]}"; do
    mix_pcaps "$PCAP_DIR/${attack}.pcap" "$PCAP_DIR/${attack}_mixed.pcap"
done
```

**What it does**:
1. **Generates pure attack PCAPs** without any mixing
2. **Uses inline Python** (heredoc) to mix each attack separately
3. **Simple concatenation**: Adds ALL benign packets to each attack (no ratio calculation)
4. **Sorts by timestamp**: Ensures temporal ordering

**Key Difference from `regenerate_mixed_attacks.sh`**:
- **No ratio control**: Adds the entire benign PCAP to each attack
- **Post-processing approach**: Mixing happens after generation
- **Simpler logic**: Just concatenate and sort
- **More flexible**: Can customize mixing logic inline

**When to use**: When you want full benign traffic added to each attack without ratio constraints, or when you want to customize the mixing logic.

---

#### Script: `test_mix.sh`

**Purpose**: Quick validation script to verify that the mixing workflow works correctly. Generates a small test case.

**Usage**:
```bash
./test_mix.sh
```

**Key Workflow**:
```bash
# Generate small benign traffic (30 seconds)
if [ ! -f "/local/pcaps/benign_traffic.pcap" ]; then
    sudo python3 -m attack_generator \
      --benign-only \
      --output /local/pcaps/benign_traffic.pcap \
      --benign-duration 30 \
      --benign-profile normal \
      --seed 42
fi

# Generate single attack (5000 packets)
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --config - <<'EOF'
{
  "attacks": [
    {"type": "syn_flood", "num_packets": 5000, "pps": 5000}
  ]
}
EOF

# Mix using mergecap (if available) or Python fallback
if command -v mergecap &> /dev/null; then
    mergecap -w /local/pcaps/syn_flood_mixed.pcap \
             /local/pcaps/syn_flood.pcap \
             /local/pcaps/benign_traffic.pcap
else
    # Python fallback (same logic as regenerate_simple_mixed.sh)
    python3 << 'PYMIX'
from scapy.all import rdpcap, wrpcap
attack = rdpcap("/local/pcaps/syn_flood.pcap")
benign = rdpcap("/local/pcaps/benign_traffic.pcap")
mixed = list(attack) + list(benign)
mixed.sort(key=lambda p: p.time if hasattr(p, 'time') else 0)
wrpcap("/local/pcaps/syn_flood_mixed.pcap", mixed)
PYMIX
fi

# Verify and display results
tcpdump -r /local/pcaps/syn_flood_mixed.pcap -n -c 10
```

**What it does**:
1. **Generates minimal test data**: 30 seconds benign + 5000 packet attack
2. **Tests two mixing methods**:
   - **mergecap** (Wireshark tool) if available - faster, native binary
   - **Python/Scapy** fallback if mergecap not installed
3. **Validates output**: Uses `tcpdump` to verify mixed PCAP structure
4. **Quick feedback**: Completes in seconds for rapid iteration

**Why two mixing methods**:
```bash
# mergecap: Fast, native tool from Wireshark
mergecap -w output.pcap input1.pcap input2.pcap
# Pros: Very fast, low memory
# Cons: Requires Wireshark installation

# Python/Scapy: Always available
rdpcap() + wrpcap()
# Pros: No dependencies (Scapy already required)
# Cons: Slower, higher memory usage
```

**When to use**: When you're developing/debugging the mixing functionality or verifying the setup on a new machine.

---

## Script Comparison Table

| Feature | regenerate_mixed_attacks.sh | regenerate_simple_mixed.sh | test_mix.sh |
|---------|----------------------------|----------------------------|-------------|
| **Mixing approach** | Built-in (generator does it) | Manual (post-processing) | Manual (test) |
| **Ratio control** | ✅ Precise (0.25 = 25% attack) | ❌ No (adds all benign) | ❌ No |
| **Performance** | Faster (single pass) | Slower (two passes) | Fast (small data) |
| **Flexibility** | Limited to generator logic | High (customize Python code) | High (test tool) |
| **Output** | `*_mixed.pcap` with ratio | `*_mixed.pcap` without ratio | Single test PCAP |
| **Use case** | Production datasets | Exploratory analysis | Development/testing |

---

## Common Workflow Scenarios

### Scenario 1: Generate ML Training Dataset (with precise ratios)
```bash
# Use regenerate_mixed_attacks.sh for controlled ratios
./regenerate_mixed_attacks.sh 10.10.1.2 0.10 /local/pcaps
# Result: 10% attack, 90% benign (realistic imbalance)
```

### Scenario 2: Generate Analysis Dataset (all benign + each attack)
```bash
# Use regenerate_simple_mixed.sh for full benign background
./regenerate_simple_mixed.sh 10.10.1.2 /local/pcaps
# Result: Each attack PCAP contains full benign traffic
```

### Scenario 3: Quick Verification
```bash
# Use test_mix.sh to verify setup
./test_mix.sh
# Result: Small test PCAP in seconds
```

### Scenario 4: Custom Ratio Not Supported by Generator
```bash
# Modify regenerate_simple_mixed.sh inline Python:
mixed = attack[:5000] + benign[:20000]  # Custom 1:4 ratio
```

---

## Important Implementation Details

### 1. Seed Consistency
All scripts use `seed: 42` for reproducibility:
```bash
# Same seed across all generations
--seed 42

# This ensures:
# - Identical output on re-runs
# - Reproducible experiments
# - Consistent baselines
```

### 2. Benign Profile Selection
```bash
# Heavy profile for mixed attacks (more realistic)
--benign-profile heavy  # 20K PPS, 80% TCP

# Normal profile for testing (faster)
--benign-profile normal  # 5K PPS, 75% TCP
```

**Why heavy for production**: ML detectors need realistic background noise to avoid overfitting to low-traffic scenarios.

### 3. PCAP Naming Convention
```bash
# Pure attacks (no benign)
/local/pcaps/syn_flood.pcap

# Mixed attacks (with benign)
/local/pcaps/syn_flood_mixed.pcap

# Benign reference
/local/pcaps/benign_traffic.pcap
```

This naming allows easy filtering:
```bash
# List only mixed PCAPs
ls /local/pcaps/*_mixed.pcap

# List only pure attacks
ls /local/pcaps/*.pcap | grep -v "_mixed"
```

### 4. Error Handling
```bash
set -e  # Exit on any error

# Prevents partial generation:
# - If benign generation fails, attacks won't be created
# - If mixing fails, incomplete PCAPs won't be used
```

---

## Key Design Patterns



### 1. Strategy Pattern (Attack Types)

```python
ATTACK_GENERATORS = {
    'syn_flood': SYNFloodGenerator,
    'udp_flood': UDPFloodGenerator,
    'http_flood': HTTPFloodGenerator,
    # ...
}

# Usage
generator_class = ATTACK_GENERATORS[attack_type]
generator = generator_class(target_ip, seed)
```

**Benefits**:
- Easy to add new attack types
- Uniform interface for all attacks
- Runtime selection of attack strategy

### 2. Builder Pattern (Packet Construction)

```python
# Layered packet construction
pkt = Ether() / \
      IP(src=src_ip, dst=dst_ip) / \
      TCP(sport=src_port, dport=dst_port, flags='S')
```

**Benefits**:
- Clear protocol layering
- Scapy automatically handles checksums and lengths
- Easy to modify individual layers

### 3. Streaming Write Pattern

```python
# Don't do this (memory explosion):
packets = []
for i in range(1000000):
    packets.append(create_packet())
wrpcap(file, packets)

# Do this (streaming):
with PcapWriter(file) as writer:
    for i in range(1000000):
        pkt = create_packet()
        writer.write(pkt)
```

**Benefits**:
- Constant memory usage
- Can generate multi-GB PCAPs
- Faster for large experiments

---

## Performance Considerations

### Memory Usage

**Bad**:
```python
# Loads entire PCAP into memory
attack_pkts = rdpcap("huge_attack.pcap")  # Could be GB!
```

**Good**:
```python
# Streaming processing
with PcapReader("huge_attack.pcap") as reader:
    for pkt in reader:
        process(pkt)
```

### Generation Speed

**Typical Performance**:
- 100K packets: ~10 seconds
- 1M packets: ~100 seconds
- Bottleneck: Scapy packet creation, not I/O

**Optimization**:
```python
# Pre-create template, randomize fields
template = Ether() / IP(dst=target_ip) / TCP(dport=80, flags='S')

for i in range(num_packets):
    pkt = template.copy()
    pkt[IP].src = random_ip()
    pkt[TCP].sport = random.randint(1024, 65535)
    packets.append(pkt)
```

---

## Testing Considerations

### Reproducibility

**Always use seeds for experiments**:
```python
# Experiment 1
generator = AttackPcapGenerator({'seed': 42, ...})
generator.generate_attack('syn_flood', 10000, 1000)

# Experiment 2 (identical output)
generator = AttackPcapGenerator({'seed': 42, ...})
generator.generate_attack('syn_flood', 10000, 1000)

# md5sum will match!
```

### Validation

**Check generated PCAPs**:
```python
# Packet count
print(f"Packets: {len(rdpcap('attack.pcap'))}")

# Protocols
from collections import Counter
protos = Counter(pkt[IP].proto for pkt in rdpcap('attack.pcap'))
print(f"Protocols: {protos}")

# Timing
pkts = rdpcap('attack.pcap')
actual_pps = len(pkts) / (pkts[-1].time - pkts[0].time)
print(f"Actual PPS: {actual_pps:.0f}")
```

---

## Common Pitfalls

### 1. Timestamp Precision

**Wrong**:
```python
pkt.time = int(time.time())  # Second precision only!
```

**Right**:
```python
pkt.time = time.time()  # Float with microsecond precision
```

### 2. Scapy Layer Access

**Wrong**:
```python
if pkt.haslayer('TCP'):  # String doesn't work
```

**Right**:
```python
from scapy.all import TCP
if pkt.haslayer(TCP):  # Use class
```

### 3. Checksum Calculation

**Don't manually calculate**:
```python
# Scapy does this automatically
del pkt[IP].chksum
del pkt[TCP].chksum
# Scapy recalculates on write
```

---

## Extension Points

### Adding New Attack Type

1. Create class inheriting from `AttackGenerator`
2. Implement `generate()` method
3. Register in `ATTACK_GENERATORS`

```python
class NewAttackGenerator(AttackGenerator):
    def generate(self, num_packets, pps):
        packets = []
        # ... implementation
        return packets

ATTACK_GENERATORS['new_attack'] = NewAttackGenerator
```

### Custom Benign Profiles

```python
PROFILES['custom'] = {
    'avg_pps': 15000,
    'tcp_ratio': 0.9,
    'udp_ratio': 0.08,
    'icmp_ratio': 0.02,
    'protocols': {
        'http': 0.6,
        'https': 0.2,
        'ssh': 0.1,
        'dns': 0.1
    }
}
```

---

## Summary

The attack generator uses:
1. **Scapy** for packet creation and manipulation
2. **Strategy pattern** for pluggable attack types
3. **Streaming writes** for memory efficiency
4. **Seeded randomness** for reproducibility
5. **Realistic distributions** from real traffic samples
6. **Proper protocol layering** with complete TCP state machines

This produces high-quality, realistic attack traffic suitable for ML training and detection system validation.
