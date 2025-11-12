# DDoS Detection System with DPDK and Machine Learning

## Overview

This project implements a complete end-to-end DDoS detection and analysis system designed for high-performance networks (up to 100 Gbps). The system combines three integrated components: a Python-based traffic generator for creating realistic attack scenarios, a DPDK-based real-time detector using probabilistic data structures, and an automated analysis tool with machine learning capabilities. Together, these components enable comprehensive security research, network testing, and DDoS mitigation validation in controlled lab environments.

**Key Capabilities**:
- **Line-rate packet processing** at 100G using DPDK (kernel bypass)
- **Multiple attack types**: SYN Flood, UDP Flood, ICMP Flood, HTTP Flood, DNS Amplification
- **Probabilistic algorithms**: Count-Min Sketch, HyperLogLog for memory-efficient monitoring
- **Machine learning ready**: 19 extracted features for classification and anomaly detection
- **Reproducible experiments**: Seeded random generation and comprehensive logging

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DDoS Detection Experiment                     │
└─────────────────────────────────────────────────────────────────┘

    Generator Node (TG)              Detector Node
    ┌──────────────────┐            ┌──────────────────┐
    │ Attack Generator │            │  DPDK Detector   │
    │                  │            │                  │
    │ • Generate PCAPs │            │ • Packet Capture │
    │ • Mix Traffic    │  ──────>   │ • Sketches       │
    │ • tcpreplay      │   100G     │ • Feature Extract│
    └──────────────────┘            │ • ML Classifier  │
                                    └──────────────────┘
                                            │
                                            ▼
                                    ┌──────────────────┐
                                    │  Analysis Tool   │
                                    │                  │
                                    │ • Visualizations │
                                    │ • Metrics        │
                                    │ • Classification │
                                    └──────────────────┘
```

## Project Components

### 1. Attack Generator (`attack_generator/`)

**Purpose**: Generate realistic DDoS attack traffic and benign background traffic for controlled security testing

**Key Features**:
- **Five attack types**: SYN Flood (connection exhaustion), UDP Flood (bandwidth saturation), ICMP Flood (ping floods), HTTP Flood (application layer), DNS Amplification (reflection/amplification)
- **Realistic benign traffic**: Uses Poisson distributions for arrival times, normal distributions for packet sizes
- **Configurable mixing**: Combine attack and benign traffic at any ratio (e.g., 30% malicious, 70% legitimate)
- **Reproducible experiments**: Seeded random generation ensures identical traffic across test runs
- **PCAP output**: Standard format compatible with tcpreplay, Wireshark, and analysis tools
- **High-rate capable**: Generate traffic suitable for multi-Gbps network testing

**Technologies**: Python 3.7+, Scapy (packet crafting), NumPy (statistical distributions)

**See**: `attack_generator/README.md`, `ARCHITECTURE.md`, and `CODE_ANALYSIS.md` for complete documentation

### 2. Detector System (`detector_system/`)

**Purpose**: Real-time DDoS detection using DPDK for high-speed packet processing and probabilistic data structures

**Key Features**:
- **DPDK-based packet processing**: Zero-copy architecture bypasses kernel for line-rate performance at 100G
- **Probabilistic data structures**:
  - **Count-Min Sketch**: Efficient flow frequency counting (32KB memory for billions of packets)
  - **HyperLogLog**: Cardinality estimation for unique IPs/ports (16KB memory, ~1% error)
  - **Bloom Filter**: Fast membership testing for seen IPs
- **Real-time feature extraction**: 19 ML features computed per second including ratios, entropy, cardinality
- **Multi-layer detection**: Rule-based thresholds + ML-ready feature export
- **Three log types**: Basic statistics (detection.log), ML features (ml_features.csv), alerts (alerts.log)
- **Configurable thresholds**: Adjust sensitivity based on network baseline

**Technologies**: C (core detector), DPDK 20.11+ (packet processing), Python 3.7+ (analysis), XGBoost/scikit-learn (optional ML)

**Performance**: ~20 Mpps on single core, <1μs latency per packet, ~175KB memory for sketches

**See**: `detector_system/README.md` and `CODE_ANALYSIS.md` for architecture and implementation details

### 3. Analysis Tool (`analisis/`)

**Purpose**: Automated post-experiment analysis and professional visualization of DDoS detection results

**Key Features**:
- **Automatic attack classification**: Heuristic-based detection of attack type (SYN Flood, UDP Flood, HTTP Flood, etc.) without manual labeling
- **Four-level severity**: CRITICAL (>100K PPS), HIGH, MEDIUM, LOW based on traffic intensity
- **Comprehensive visualizations**: 8 plots across 2 high-resolution images (300 DPI)
  - **Main analysis**: Attack identification panel, throughput over time, protocol distribution, SYN/ACK ratio
  - **Detailed metrics**: Protocol pie chart, TCP flags bar chart, traffic intensity heatmap, summary table
- **Statistical analysis**: Complete metrics including average/peak PPS, Gbps, protocol percentages, TCP flag analysis
- **Publication-ready**: Professional formatting suitable for research papers and presentations
- **Zero configuration**: Works directly with detector logs, no preprocessing required

**Technologies**: Python 3.7+, Pandas (data analysis), Matplotlib/Seaborn (visualization), NumPy (statistics)

**Outputs**:
- Terminal: Formatted statistical summary table
- `attack_main_analysis.png`: Primary visualizations (4 plots)
- `attack_detailed_metrics.png`: Detailed analysis (4 plots)

**See**: `analisis/README.md` and `CODE_ANALYSIS.md` for usage examples and implementation details

## Quick Start

### Prerequisites

**Generator Node**:
```bash
# Install Python dependencies
pip3 install scapy numpy scipy pandas

# Install tcpreplay
sudo apt install tcpreplay
```

**Detector Node**:
```bash
# Install DPDK
sudo apt install dpdk dpdk-dev

# Install Python for analysis
pip3 install pandas numpy scikit-learn
```

### Running a Complete Experiment

#### Step 1: Generate Traffic (Generator Node)

```bash
cd /local/dpdk_100g

# Generate benign traffic
sudo python3 -m attack_generator \
  --benign-only \
  --output /local/pcaps/benign_traffic.pcap \
  --benign-duration 120 \
  --benign-profile normal

# Generate attacks with mixing
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --mix-benign /local/pcaps/benign_traffic.pcap \
  --attack-ratio 0.3 \
  --seed 42
```

#### Step 2: Start Detector (Detector Node)

```bash
cd /local/dpdk_100g/detector_system

# Compile detector
./scripts/build.sh

# Start in background
sudo ./scripts/run_background.sh 0000:41:00.0

# Monitor in separate terminal
tail -f /local/logs/detection.log
```

#### Step 3: Replay Traffic (Generator Node)

```bash
cd /local/dpdk_100g

# Replay mixed traffic
sudo ./run_mixed_experiment.sh ens1f0 /local/pcaps 2000
```

#### Step 4: Analyze Results (Any Node)

```bash
cd /local/dpdk_100g/analisis

# Copy detection.log from detector node
# Then paste into detection_log.txt

# Run analysis
python3 analyze_attack.py

# Output:
# - Terminal: Statistical summary
# - attack_main_analysis.png: Main visualizations
# - attack_detailed_metrics.png: Detailed metrics
```

## Repository Structure

```
dpdk_100g/
├── attack_generator/          # Traffic generation module
│   ├── README.md             # Module overview
│   ├── ARCHITECTURE.md       # Code architecture
│   ├── USAGE.md              # Command examples
│   ├── CODE_ANALYSIS.md      # Code explanation
│   ├── generator.py          # Main generator
│   ├── attacks.py            # Attack implementations
│   ├── benign_traffic.py     # Benign traffic generator
│   └── utils.py              # Helper functions
│
├── detector_system/           # DPDK-based detector
│   ├── README.md             # Module overview
│   ├── ARCHITECTURE.md       # System design
│   ├── USAGE.md              # Deployment guide
│   ├── CODE_ANALYSIS.md      # Code explanation
│   ├── detector_dpdk.c       # Core detector (DPDK)
│   ├── scripts/              # Build and run scripts
│   └── python/               # Analysis scripts
│
├── analisis/                  # Results analysis
│   ├── README.md             # Tool overview
│   ├── CODE_ANALYSIS.md      # Code explanation
│   ├── analyze_attack.py     # Main analysis script
│   └── detection_log.txt     # Input file (paste logs here)
│
├── old/                       # Deprecated files
│
├── README.md                  # This file
├── EXPERIMENTS.md             # Detailed experiment guide
├── QUICKSTART.md              # Quick start guide
├── run_experiment.sh          # Experiment orchestration
└── run_mixed_experiment.sh    # Mixed traffic experiments
```

## Documentation

- **EXPERIMENTS.md**: Detailed step-by-step experiment procedures
- **QUICKSTART.md**: Fast setup for experienced users
- **attack_generator/**: Traffic generation documentation
  - README.md: Overview and purpose
  - ARCHITECTURE.md: Code structure and algorithms
  - USAGE.md: Command-line examples
  - CODE_ANALYSIS.md: Important code explanation
- **detector_system/**: Detection system documentation
  - README.md: System overview
  - ARCHITECTURE.md: DPDK and sketch design
  - USAGE.md: Compilation and deployment
  - CODE_ANALYSIS.md: Core detector code
- **analisis/**: Analysis tool documentation
  - README.md: Tool capabilities
  - CODE_ANALYSIS.md: Visualization code

## Use Cases

### 1. Security Research
- **Algorithm Development**: Test and validate novel DDoS detection algorithms with ground-truth labeled data
- **Performance Benchmarking**: Compare detection accuracy, false positive rates, and latency across different approaches
- **Attack Characterization**: Study statistical properties of various attack types using extracted features
- **Evasion Techniques**: Research attack obfuscation methods and develop robust detection mechanisms
- **Dataset Generation**: Create reproducible, labeled traffic datasets for the research community

### 2. Network Testing and Validation
- **High-speed Performance**: Validate 100G network equipment under realistic attack conditions
- **Mitigation Testing**: Test DDoS mitigation appliances (scrubbing centers, firewalls, IDS/IPS) with controlled attacks
- **Capacity Planning**: Measure actual throughput, latency, and packet loss under various attack intensities
- **Stress Testing**: Identify infrastructure breaking points and bottlenecks before production deployment
- **Compliance Validation**: Demonstrate security controls meet regulatory requirements

### 3. Machine Learning Applications
- **Supervised Learning**: Generate labeled datasets with precise attack types for classifier training
- **Feature Engineering**: Test importance of 19 extracted features for attack classification
- **Model Validation**: Evaluate trained models on realistic mixed traffic (benign + malicious)
- **Anomaly Detection**: Develop unsupervised models using normal traffic baselines
- **Online Learning**: Test adaptive models that learn from streaming traffic

### 4. Education and Training
- **Hands-on Learning**: Demonstrate real DDoS attack mechanics in safe lab environments
- **Security Analysis Training**: Train SOC analysts to recognize attack patterns in traffic data
- **Incident Response**: Practice detection, analysis, and mitigation workflows
- **Academic Courses**: Provide complete platform for network security and systems courses
- **Certification Prep**: Practical experience for security certifications (CISSP, CEH, etc.)

### 5. CloudLab/Testbed Experiments
- **Reproducible Research**: Leverage seeded generation for consistent results across experiment runs
- **Multi-node Setup**: Distribute generator and detector across CloudLab nodes with high-speed links
- **Resource Isolation**: Test detection on dedicated hardware without production impact
- **Collaboration**: Share experiment configurations via JSON for reproducibility

## Ethical Considerations

⚠️ **Use only in authorized environments**:
- Academic research labs
- Authorized penetration testing
- Isolated CloudLab experiments
- Educational demonstrations

❌ **Never use for**:
- Attacking production systems
- Unauthorized network testing
- Malicious purposes
- Public infrastructure

## Support

For questions, issues, or contributions:
- Open an issue on GitHub
- Documentation: See individual module READMEs
- Detailed guides: EXPERIMENTS.md and QUICKSTART.md

---

**Ready to start?** See `QUICKSTART.md` for a fast setup guide, or `EXPERIMENTS.md` for detailed procedures.
