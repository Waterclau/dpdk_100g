# Attack Generator Architecture

## Code Structure

```
attack_generator/
├── __init__.py              # Package initialization
├── __main__.py              # CLI entry point
├── generator.py             # Main generator class
├── attacks.py               # Attack implementations
├── benign_traffic.py        # Benign traffic generator
├── utils.py                 # Helper functions
├── regenerate_mixed_attacks.sh    # Full mixed traffic generation
├── regenerate_simple_mixed.sh    # Simple mixed generation
└── test_mix.sh              # Quick test script
```

## Core Components

### 1. Main Entry Point (`__main__.py`)

**Purpose**: Command-line interface and argument parsing

**Key Functions**:
- `main()`: Entry point, parses CLI arguments
- Handles stdin JSON config input
- Validates and normalizes arguments

**Flow**:
```python
User Command
    ↓
Parse Arguments (argparse)
    ↓
Read Config (JSON or args)
    ↓
Initialize Generator
    ↓
Execute Generation
```

### 2. Generator Core (`generator.py`)

**Purpose**: Main orchestration of traffic generation

**Class**: `AttackGenerator`

**Key Methods**:

```python
class AttackGenerator:
    def __init__(self, config):
        # Initialize with configuration

    def generate_attacks(self):
        # Main generation loop
        # For each attack in config:
        #   1. Generate pure attack PCAP
        #   2. If mixing enabled, create mixed PCAP

    def mix_with_benign(self, attack_pcap, benign_pcap, ratio):
        # Merge attack and benign traffic
        # Uses temporal interleaving
```

**Generation Algorithm**:

```
For each attack_config:
    1. Create AttackHandler instance
    2. Generate attack_packets[]
    3. Write to attack.pcap

    If mix_benign:
        4. Load benign_traffic.pcap
        5. Compute target_ratio
        6. Interleave packets by timestamp
        7. Write to attack_mixed.pcap
```

### 3. Attack Implementations (`attacks.py`)

**Purpose**: Specific attack packet generation

**Classes**:

#### `SYNFloodAttack`
```python
def generate(self, num_packets, pps):
    for i in range(num_packets):
        pkt = IP(src=random_ip(), dst=target_ip) /
              TCP(sport=random_port(), dport=80, flags="S")
        packets.append(pkt)
    return packets
```

**Characteristics**:
- Random source IPs from various subnets
- TCP SYN flag set
- Common target ports (80, 443, 22)
- No payload

#### `UDPFloodAttack`
```python
def generate(self, num_packets, pps):
    for i in range(num_packets):
        pkt = IP(src=random_ip(), dst=target_ip) /
              UDP(sport=random_port(), dport=random_port()) /
              Raw(load="X" * random.randint(64, 1400))
        packets.append(pkt)
    return packets
```

**Characteristics**:
- Random source/destination ports
- Variable payload sizes (64-1400 bytes)
- High packet rate

#### `ICMPFloodAttack`
```python
def generate(self, num_packets, pps):
    for i in range(num_packets):
        pkt = IP(src=random_ip(), dst=target_ip) /
              ICMP(type=8, code=0) /
              Raw(load="X" * 56)
        packets.append(pkt)
    return packets
```

**Characteristics**:
- ICMP Echo Request (type 8)
- 56-byte payload (standard ping size)
- Spoofed source IPs

#### `HTTPFloodAttack`
```python
def generate(self, num_packets, pps):
    for i in range(num_packets):
        http_payload = "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n"
        pkt = IP(src=random_ip(), dst=target_ip) /
              TCP(sport=random_port(), dport=80, flags="PA") /
              Raw(load=http_payload)
        packets.append(pkt)
    return packets
```

**Characteristics**:
- HTTP GET requests
- TCP PSH+ACK flags
- Realistic HTTP headers

#### `DNSAmplificationAttack`
```python
def generate(self, num_packets, pps):
    for i in range(num_packets):
        dns_query = DNS(rd=1, qd=DNSQR(qname="example.com", qtype="ANY"))
        pkt = IP(src=target_ip, dst=dns_server) /
              UDP(sport=random_port(), dport=53) /
              dns_query
        packets.append(pkt)
    return packets
```

**Characteristics**:
- Source IP is the victim (reflection)
- DNS "ANY" queries for amplification
- Targets open DNS resolvers

### 4. Benign Traffic Generator (`benign_traffic.py`)

**Purpose**: Generate realistic background traffic

**Class**: `BenignTrafficGenerator`

**Key Methods**:

```python
class BenignTrafficGenerator:
    def generate(self, duration, profile="normal"):
        # Generate benign traffic for 'duration' seconds

    def _generate_tcp_flow(self):
        # Simulate TCP 3-way handshake + data + teardown

    def _generate_udp_packet(self):
        # DNS, NTP, or generic UDP

    def _generate_icmp_packet(self):
        # Ping or other ICMP
```

**Traffic Profiles**:

```python
PROFILES = {
    "light": {
        "avg_pps": 1000,
        "tcp_ratio": 0.7,
        "udp_ratio": 0.2,
        "icmp_ratio": 0.1
    },
    "normal": {
        "avg_pps": 5000,
        "tcp_ratio": 0.75,
        "udp_ratio": 0.2,
        "icmp_ratio": 0.05
    },
    "heavy": {
        "avg_pps": 20000,
        "tcp_ratio": 0.8,
        "udp_ratio": 0.15,
        "icmp_ratio": 0.05
    }
}
```

**Statistical Distributions**:

- **Inter-Arrival Time**: Poisson distribution (exponential inter-arrival)
- **Packet Size**: Normal distribution (mean=800, std=400)
- **Port Selection**: Weighted random (common ports more likely)

### 5. Utility Functions (`utils.py`)

**Purpose**: Helper functions for packet manipulation

**Key Functions**:

```python
def random_ip(subnet="0.0.0.0/0"):
    # Generate random IP from subnet

def random_port(common=True):
    # Return random port (weighted if common=True)

def calculate_pps_delay(pps):
    # Convert PPS to inter-packet delay

def merge_pcaps(pcap1, pcap2, output, ratio):
    # Merge two PCAPs with specified ratio

def set_seed(seed):
    # Set random seed for reproducibility
```

## Traffic Mixing Algorithm

**Goal**: Create realistic mixed traffic with specified attack ratio

**Algorithm**:

```python
def mix_with_benign(attack_pcap, benign_pcap, attack_ratio):
    # 1. Load both PCAPs
    attack_pkts = rdpcap(attack_pcap)
    benign_pkts = rdpcap(benign_pcap)

    # 2. Calculate target counts
    total_attack = len(attack_pkts)
    total_benign_needed = int(total_attack * (1 - attack_ratio) / attack_ratio)

    # 3. Sample or replicate benign to match count
    if len(benign_pkts) > total_benign_needed:
        benign_pkts = random.sample(benign_pkts, total_benign_needed)
    else:
        # Replicate benign traffic to reach needed count
        benign_pkts = (benign_pkts * (total_benign_needed // len(benign_pkts) + 1))[:total_benign_needed]

    # 4. Assign timestamps
    duration = max([pkt.time for pkt in attack_pkts])
    for pkt in benign_pkts:
        pkt.time = random.uniform(0, duration)

    # 5. Merge and sort by timestamp
    all_pkts = attack_pkts + benign_pkts
    all_pkts.sort(key=lambda x: x.time)

    # 6. Write to output PCAP
    wrpcap(output_pcap, all_pkts)
```

**Key Considerations**:

- **Temporal Distribution**: Packets are distributed across the attack duration
- **Ratio Accuracy**: Actual ratio may vary slightly due to rounding
- **Timestamp Adjustment**: All packets get absolute timestamps

## Configuration Format

**JSON Configuration**:

```json
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {
      "type": "syn_flood",
      "num_packets": 100000,
      "pps": 10000
    },
    {
      "type": "udp_flood",
      "num_packets": 150000,
      "pps": 15000
    }
  ]
}
```

**CLI Arguments**:

- `--target-ip`: Victim IP address
- `--attack <type>`: Single attack type
- `--num-packets`: Number of packets to generate
- `--pps`: Packets per second (attack rate)
- `--config`: JSON config file or `-` for stdin
- `--mix-benign`: Path to benign PCAP for mixing
- `--attack-ratio`: Ratio of attack traffic (0.0-1.0)
- `--seed`: Random seed for reproducibility
- `--output-dir`: Output directory for PCAPs

## Performance Optimizations

### Memory Management

- **Streaming Writes**: Write packets to PCAP as generated (not buffering all in memory)
- **Chunk Processing**: Process benign traffic in chunks when replicating

### Generation Speed

- **Pre-computed Templates**: Cache packet templates, randomize fields
- **Batch Operations**: Generate multiple packets before writing

### PCAP Size Optimization

- **Compression**: Use `.pcap.gz` for storage (if needed)
- **Minimal Payloads**: Attack packets use minimal required payload

## Dependencies

- **Scapy**: Packet creation and manipulation
- **NumPy**: Statistical distributions
- **SciPy**: Advanced distributions (if needed)

## Error Handling

- **Invalid Config**: Validates all config parameters before generation
- **Missing Benign PCAP**: Error if mixing requested but no benign file
- **Disk Space**: Checks available space before large generations
- **Permission Errors**: Handles read/write permission issues

## Logging

```python
import logging

logging.info(f"Generating {attack_type} with {num_packets} packets at {pps} PPS")
logging.warning(f"Attack ratio {ratio} is very high, may not be realistic")
logging.error(f"Failed to write PCAP: {error}")
```

## Extension Points

### Adding New Attack Types

1. Create new class in `attacks.py` inheriting from `AttackBase`
2. Implement `generate()` method
3. Register attack type in `ATTACK_REGISTRY`

```python
class NewAttack(AttackBase):
    def generate(self, num_packets, pps):
        # Implementation
        return packets

ATTACK_REGISTRY["new_attack"] = NewAttack
```

### Custom Benign Profiles

Add new profile to `PROFILES` dict in `benign_traffic.py`:

```python
PROFILES["custom"] = {
    "avg_pps": 10000,
    "tcp_ratio": 0.9,
    "udp_ratio": 0.05,
    "icmp_ratio": 0.05
}
```

## Testing

- `test_mix.sh`: Quick test of mixing functionality
- Unit tests should cover:
  - Packet generation for each attack type
  - Traffic mixing ratios
  - PCAP file integrity

## Future Enhancements

- Packet fragmentation support
- IPv6 attack vectors
- More sophisticated benign traffic patterns
- Real PCAP-based benign traffic replay
