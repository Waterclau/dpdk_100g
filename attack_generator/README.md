# DDoS Attack Traffic Generator

## Overview

The Attack Generator is a Python-based tool designed to create realistic DDoS attack traffic patterns for security research and network testing. It generates both malicious attack traffic and benign background traffic, enabling comprehensive testing of DDoS detection systems in controlled environments.

## Purpose

This module empowers researchers and network engineers to:

1. **Generate Multiple Attack Types**: Create various DDoS attack patterns including SYN Flood, UDP Flood, ICMP Flood, HTTP Flood, and DNS Amplification attacks with configurable parameters
2. **Create Mixed Traffic Scenarios**: Combine malicious attack traffic with benign background traffic at configurable ratios to simulate real-world conditions
3. **Ensure Reproducible Experiments**: Use seeded random generation for consistent, repeatable experiments that can be validated across research teams
4. **Generate Realistic Traffic Patterns**: Create statistically realistic benign traffic using proper probability distributions (Poisson, Normal) alongside attack traffic
5. **Support High-Rate Testing**: Generate traffic patterns suitable for testing 100G networks with precise packet-per-second (PPS) control

## Experiment Workflow

### 1. Traffic Generation Phase

The generator creates PCAP files containing network traffic:

```
┌─────────────────────┐
│  Attack Generator   │
│                     │
│  • Attack Config    │──────> SYN Flood PCAP
│  • Traffic Params   │──────> UDP Flood PCAP
│  • Mixing Options   │──────> Mixed Traffic PCAP
└─────────────────────┘
```

### 2. Attack Types Supported

- **SYN Flood**: TCP SYN packets with spoofed source IPs, overwhelming the target's connection table
- **UDP Flood**: High-rate UDP packets to arbitrary ports, consuming bandwidth and resources
- **ICMP Flood**: ICMP Echo Request floods (ping floods)
- **HTTP Flood**: Application-layer attacks with HTTP GET requests
- **DNS Amplification**: Exploits DNS recursion for bandwidth amplification

### 3. Traffic Mixing

The generator can create realistic scenarios by mixing attack traffic with benign traffic:

```
Benign PCAP + Attack Traffic = Mixed PCAP
   (70%)          (30%)         (Realistic)
```

This allows testing of detection systems under realistic conditions where attacks are mixed with legitimate traffic.

## Key Features

### Configurable Attack Parameters

- **Packet Count**: Control the number of packets per attack
- **Packets Per Second (PPS)**: Set the attack rate/intensity
- **Target IP**: Specify the victim IP address
- **Source IP Spoofing**: Randomize source IPs to simulate distributed attacks
- **Port Randomization**: Vary destination ports for certain attack types

### Benign Traffic Generation

- **Statistical Realism**: Uses realistic distributions for packet sizes and timing
- **Multiple Profiles**: Light, normal, and heavy traffic profiles
- **Protocol Mix**: TCP, UDP, and ICMP in realistic proportions

### Reproducibility

- **Seeded Random Generation**: Ensures experiments can be exactly reproduced
- **Metadata Generation**: Outputs JSON metadata with experiment parameters
- **Version Control**: Track experiment configurations

## Output Files

Each generation session creates:

1. **Attack PCAPs**: `<attack_type>.pcap` - Pure attack traffic for isolation testing
2. **Mixed PCAPs**: `<attack_type>_mixed.pcap` - Attack traffic interleaved with benign traffic for realistic scenarios
3. **Metadata Files**: `metadata.json` - Complete experiment parameters, generation statistics, and packet counts for reproducibility

**File Locations**: By default, all files are saved to the `output_dir` specified in configuration (default: `./pcaps/`)

## Use Cases

### Security Research

- Test IDS/IPS systems against various attack vectors
- Benchmark detection accuracy and performance
- Study attack patterns and characteristics

### Network Testing

- Validate network capacity under attack conditions
- Test DDoS mitigation systems
- Measure throughput and latency under stress

### Education

- Demonstrate DDoS attack mechanics
- Train security analysts on attack recognition
- Develop detection algorithms

## Integration with Detection System

The generated PCAPs are replayed using `tcpreplay` to the detector node:

```
Generator Node          Detector Node
┌──────────────┐       ┌──────────────┐
│ PCAP Files   │──────>│ DPDK Detector│
│ (tcpreplay)  │ 100G  │ (Sketches)   │
└──────────────┘       └──────────────┘
```

The detector processes the traffic in real-time, extracting features and classifying packets as benign or malicious.

## Experiment Design Considerations

### Attack Intensity

- **Low**: 1K-10K PPS - Simulates reconnaissance or low-rate attacks
- **Medium**: 10K-100K PPS - Typical DDoS attack rates
- **High**: 100K+ PPS - Volumetric attacks targeting high-capacity networks

### Traffic Mixing Ratios

- **Pure Attack** (100% malicious): Tests detection under ideal conditions
- **High Mix** (70%+ malicious): Tests under heavy attack
- **Realistic Mix** (20-30% malicious): Simulates real-world scenarios
- **Low Mix** (5-10% malicious): Tests sensitivity and false positive rates

### Duration

- Short experiments (10-30s) for quick validation
- Medium experiments (1-5min) for statistical significance
- Long experiments (10+ min) for sustained load testing

## Technical Details

### Traffic Generation Algorithms

- **Poisson Distribution**: Inter-arrival times for benign traffic
- **Uniform Distribution**: Port and IP randomization
- **Normal Distribution**: Packet size variation

### PCAP Format

Generated files use standard PCAP format with Ethernet framing:
- Ethernet Header (14 bytes)
- IP Header (20 bytes)
- Protocol Header (TCP: 20 bytes, UDP: 8 bytes, ICMP: 8 bytes)
- Optional Payload

## Performance

- **Generation Speed**: 100K+ packets/second
- **Memory Efficient**: Streaming writes to PCAP
- **Scalable**: Can generate multi-GB PCAP files

## Safety and Ethics

⚠️ **WARNING**: This tool generates malicious network traffic. Use only in:
- Isolated lab environments
- Authorized security testing
- Educational settings with proper controls

**Never** use this tool against:
- Production networks
- Systems without explicit authorization
- Public infrastructure

## Next Steps

See `ARCHITECTURE.md` for implementation details and `USAGE.md` for command examples.
