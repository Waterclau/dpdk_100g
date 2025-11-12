# DDoS Detector - DPDK + Sketches + ML

Complete real-time DDoS attack detection system for high-speed networks (100G) using DPDK, probabilistic data structures (Sketches), and Machine Learning.

## Features

### Detector Core (C + DPDK)
- **Zero-copy packet processing** with DPDK for maximum throughput (line-rate capable)
- **Count-Min Sketch** for efficient flow counting and heavy hitter detection
- **HyperLogLog** for cardinality estimation of unique IPs/ports with minimal memory
- **Bloom Filter** for fast membership testing of seen IPs
- **Real-time extraction of 19 ML features** for attack classification
- **Configurable thresholds** for rule-based detection alongside ML
- **Structured logging** (CSV format) for offline analysis and model training

### Analysis System (Python)
- **Feature Extractor**: Extracts statistical characteristics from detector logs
- **Model Inferencer**: ML inference with pre-trained models (XGBoost, Random Forest, etc.)
- **Attack type detection**: Identifies SYN flood, UDP flood, HTTP flood, DNS amplification, and more
- **Real-time and post-mortem analysis** capabilities

## Architecture

```
detector_system/
├── detector_dpdk.c          # Core DPDK detector in C
├── config.py                # Centralized configuration
├── feature_extractor.py     # Feature extraction module
├── model_inferencer.py      # ML inference module
├── scripts/
│   ├── build.sh            # Build detector binary
│   ├── run.sh              # Run in foreground (debug mode)
│   ├── run_background.sh   # Run as background daemon
│   └── analyze.py          # Log analysis script
└── README.md
```

## Requirements

### System Dependencies
```bash
# Ubuntu 20.04+ / CloudLab
sudo apt update
sudo apt install -y build-essential pkg-config python3 python3-pip

# DPDK (pre-installed on CloudLab, otherwise install manually)
sudo apt install -y dpdk dpdk-dev

# Additional libraries
sudo apt install -y libdpdk-dev libnuma-dev
```

### Python Dependencies
```bash
pip3 install pandas numpy scikit-learn xgboost matplotlib seaborn
```

**Note**: The detector requires DPDK 20.11 or higher and Python 3.7+.

## Installation and Compilation

### 1. Clone or Copy the Project
```bash
cd /local
git clone <your-repo> dpdk_100g
cd dpdk_100g/detector_system
```

### 2. Compile the DPDK Detector
```bash
chmod +x scripts/*.sh
./scripts/build.sh
```

This generates the `detector_dpdk` binary in the current directory.

### 3. Verify Your Network Interface Card (NIC)
```bash
# List DPDK-compatible devices
dpdk-devbind.py --status

# Example output:
# 0000:41:00.0 'Ethernet Controller 10G X550T' drv=vfio-pci unused=ixgbe
# This shows a 10G Intel NIC bound to DPDK
```

**Important**: Note the PCI address (e.g., `0000:41:00.0`) - you'll need this for all run commands.

## Usage

### Mode 1: Foreground Execution (Recommended for Debugging)

```bash
# Run with your PCI address
sudo ./scripts/run.sh 0000:41:00.0
```

You'll see real-time output on the terminal:

```
Timestamp         PPS       Gbps        TCP        UDP        SYN
════════════════════════════════════════════════════════════════
1705334401     125340      11.23     95000      30000      65000
1705334402     130250      12.05    100000      30000      70000
```

To stop: Press `Ctrl+C`

**Use this mode when**: Testing configuration, debugging, or monitoring traffic patterns in real-time.

### Mode 2: Background Execution (Production Mode)

```bash
# Start detector as background daemon
sudo ./scripts/run_background.sh 0000:41:00.0

# Monitor logs in real-time (open multiple terminals)
tail -f /local/logs/detection.log      # Basic traffic statistics
tail -f /local/logs/ml_features.csv    # ML features (19 columns)
tail -f /local/logs/alerts.log         # Attack alerts

# Stop the detector
sudo pkill -9 detector_dpdk
```

**Use this mode for**: Long-running experiments, automated testing, production deployments.

### Mode 3: Log Analysis (Post-Mortem or Real-Time)

Once the detector is running and generating logs:

```bash
# Basic analysis (statistics only)
python3 scripts/analyze.py

# ML-based classification (requires trained model)
python3 scripts/analyze.py --model-path /local/models/xgboost_detector.pkl

# Export features for model training
python3 scripts/analyze.py --export-features /local/training_data.csv

# Custom analysis window (30 second intervals)
python3 scripts/analyze.py --window-size 30
```

## Generated Log Files

The detector creates 3 log files in `/local/logs/`:

### 1. `detection.log` - Basic Traffic Statistics
```csv
timestamp,pps,gbps,tcp,udp,icmp,syn,ack,rst,fin,frag
1705334401,125340,11.23,95000,30000,340,65000,80000,200,150,50
```

**Purpose**: Basic per-second traffic counters for quick analysis and visualization.

**Columns**: Unix timestamp, packets per second, gigabits per second, protocol counts, TCP flag counts, fragmented packet count.

### 2. `ml_features.csv` - ML Features (19 columns)
```csv
timestamp,gbps,pps,avg_pkt_size,std_dev,tcp_ratio,udp_ratio,icmp_ratio,syn_ratio,ack_ratio,rst_ratio,fin_ratio,frag_ratio,small_pkt_ratio,entropy_src_ip,entropy_dst_port,unique_src_ips,unique_dst_ports,syn_per_sec,ack_per_sec
1705334401,11.23,125340,950.2,142.5,0.758,0.239,0.003,0.684,0.842,0.002,0.001,0.0004,0.123,7.82,9.45,15234,8945,65000,80000
```

**Purpose**: Complete feature set for machine learning classification and attack detection.

**Use cases**: Model training, inference, feature importance analysis, attack characterization.

### 3. `alerts.log` - Security Alerts
```csv
timestamp,alert_type,severity,details
1705334401,SYN_FLOOD,CRITICAL,syn_ratio=0.78
1705334402,HIGH_PPS,HIGH,pps=250000
```

**Purpose**: Real-time attack alerts based on threshold violations.

**Severity levels**: CRITICAL (immediate response), HIGH (investigate), MEDIUM (monitor), LOW (informational).

## Extracted Features (19 Total)

| Feature | Description | Attack Indicator |
|---------|-------------|------------------|
| `gbps` | Gigabits per second | Volumetric attacks (high) |
| `pps` | Packets per second | Packet-rate attacks (high) |
| `avg_pkt_size` | Average packet size (bytes) | Small packets indicate certain attack types |
| `std_dev` | Standard deviation of packet size | Low variance may indicate attack |
| `tcp_ratio` | TCP packets / Total packets | TCP-based attacks (high) |
| `udp_ratio` | UDP packets / Total packets | UDP floods (high) |
| `icmp_ratio` | ICMP packets / Total packets | ICMP floods (high) |
| `syn_ratio` | SYN / Total TCP packets | SYN floods (very high, >0.7) |
| `ack_ratio` | ACK / Total TCP packets | Normal traffic (high), SYN flood (low) |
| `rst_ratio` | RST / Total TCP packets | Scan activity (high) |
| `fin_ratio` | FIN / Total TCP packets | Normal teardowns |
| `frag_ratio` | Fragmented packets / Total | Fragmentation attacks (high) |
| `small_pkt_ratio` | Packets < 100 bytes / Total | Certain attack types prefer small packets |
| `entropy_src_ip` | Source IP entropy | Low entropy indicates single source |
| `entropy_dst_port` | Destination port entropy | Low entropy indicates port targeting |
| `unique_src_ips` | Unique source IPs (HyperLogLog) | DDoS: high, single attacker: low |
| `unique_dst_ports` | Unique destination ports (HyperLogLog) | Port scans: high |
| `syn_per_sec` | SYN packets per second | SYN flood indicator (absolute count) |
| `ack_per_sec` | ACK packets per second | Normal traffic indicator |

**Note**: All ratio features are normalized (0.0 - 1.0). Cardinality features use HyperLogLog for memory efficiency.

## Detection Thresholds (Configurable in `config.py`)

```python
THRESHOLDS = {
    'pps_threshold': 100000,         # PPS for volumetric attack alert
    'gbps_threshold': 10.0,          # Gbps threshold for bandwidth attacks
    'syn_ratio_threshold': 0.7,      # SYN flood detection (70% of TCP are SYN)
    'udp_ratio_threshold': 0.8,      # UDP flood detection (80% UDP traffic)
    'frag_ratio_threshold': 0.3,     # Fragmentation attack (30% fragmented)
    'entropy_threshold_low': 3.0,    # Low entropy indicates single source/target
    'small_packet_ratio': 0.6,       # Many small packets (60% < 100 bytes)
}
```

**Customization**: Adjust thresholds based on your network baseline. Lower thresholds increase sensitivity but may cause false positives.

**Recommendation**: Run benign traffic first to establish baseline, then set thresholds 2-3 standard deviations above normal.

## Integration with Attack Generator

### Complete Experiment Workflow:

```bash
# Terminal 1: Start detector in background
cd /local/dpdk_100g/detector_system
sudo ./scripts/run_background.sh 0000:41:00.0

# Terminal 2: Generate attack PCAPs
cd /local/dpdk_100g
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
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

# Terminal 3: Replay traffic with tcpreplay
sudo tcpreplay -i <interface> --mbps 10000 /local/pcaps/syn_flood.pcap

# Terminal 4: Monitor logs in real-time
tail -f /local/logs/ml_features.csv

# After experiment: Analyze results
cd /local/dpdk_100g/detector_system
python3 scripts/analyze.py \
  --export-features /local/experiment_features.csv
```

**Tip**: For mixed traffic experiments, use `--mix-benign` flag in attack generator to simulate realistic scenarios.

## Advanced Configuration

### Adjusting Sketch Parameters

Edit `detector_dpdk.c`:

```c
// For higher precision (more memory):
#define CM_WIDTH 4096      // Default: 2048 (doubles memory, ~0.06% error)
#define CM_DEPTH 6         // Default: 4 (improves accuracy)
#define HLL_PRECISION 16   // Default: 14 (2^16 = 65536 buckets, ~0.4% error)
```

Then recompile:
```bash
./scripts/build.sh
```

**Trade-offs**:
- **Higher WIDTH/DEPTH**: Better accuracy, more memory, slightly slower
- **Higher HLL_PRECISION**: Better cardinality estimates, exponentially more memory

### Adjusting DPDK Parameters

Edit `config.py`:

```python
class DetectorConfig:
    RX_RING_SIZE = 4096      # Default: 2048 (higher = more buffering)
    NUM_MBUFS = 32767        # Default: 16383 (must be 2^n - 1)
    BURST_SIZE = 128         # Default: 64 (higher = better throughput)
```

**Guidelines**:
- **RX_RING_SIZE**: Increase for high packet loss, but uses more memory
- **NUM_MBUFS**: Increase for high-rate traffic (formula: 2 × RX_RING_SIZE + burst_size)
- **BURST_SIZE**: Optimal is 32-128 packets; higher may increase latency

### Using Multiple CPU Cores

Modify `scripts/run.sh`:

```bash
# Use cores 0-3 for packet processing
sudo ./detector_dpdk -l 0-3 -a 0000:41:00.0 --
```

**Performance tip**: Pin detector to isolated cores for consistent performance:
```bash
# Isolate cores 2-3 for DPDK (add to kernel boot params)
isolcpus=2,3
```

## Detected Attack Types

The detector identifies the following attack patterns:

1. **SYN Flood**: High `syn_ratio` (>0.7), low `ack_ratio` (<0.3), many unique source IPs
2. **UDP Flood**: High `udp_ratio` (>0.8), high `pps`, random ports
3. **HTTP Flood**: High `tcp_ratio`, moderate SYN ratio (normal handshakes), application-layer
4. **DNS Amplification**: Small packets, high UDP ratio, low unique sources, high bandwidth
5. **Fragmentation Attack**: High `frag_ratio` (>0.3), used to evade detection or exhaust resources
6. **Volumetric Attack**: Very high `gbps` or `pps` regardless of protocol

**Detection Confidence**: Combining multiple features improves accuracy. For example, SYN Flood detection uses `syn_ratio`, `ack_ratio`, `unique_src_ips`, and `pps` together.

## Troubleshooting

### Error: "No hay puertos disponibles"
```bash
# Verificar binding DPDK
dpdk-devbind.py --status

# Bind a DPDK si es necesario
sudo dpdk-devbind.py --bind=vfio-pci 0000:41:00.0
```

### Error de compilación
```bash
# Verificar instalación DPDK
pkg-config --modversion libdpdk

# Reinstalar si es necesario
sudo apt install --reinstall dpdk dpdk-dev
```

### Logs vacíos
```bash
# Verificar permisos
sudo chmod 777 /local/logs

# Verificar que hay tráfico
tcpdump -i <interface> -c 10
```

### Alto uso de CPU
```bash
# Reducir BURST_SIZE en config.py
BURST_SIZE = 32  # Default: 64

# Limitar core affinity
sudo ./detector_dpdk -l 0 -a 0000:41:00.0 --
```

## Ejemplo Completo: Experimento CloudLab

```bash
#!/bin/bash
# Experimento completo en CloudLab

# 1. Compilar detector
cd /local/dpdk_100g/detector_system
./scripts/build.sh

# 2. Generar tráfico benigno
cd /local/dpdk_100g
sudo python3 -m attack_generator \
  --benign-only \
  --output /local/pcaps/benign.pcap \
  --benign-duration 60 \
  --benign-profile normal

# 3. Generar ataques
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --attack syn_flood \
  --num-packets 100000 \
  --pps 10000 \
  --mix-benign /local/pcaps/benign.pcap \
  --attack-ratio 0.3

# 4. Iniciar detector
cd /local/dpdk_100g/detector_system
sudo ./scripts/run_background.sh 0000:41:00.0

# 5. Replay tráfico
sudo tcpreplay -i enp65s0f0 --mbps 1000 \
  /local/pcaps/syn_flood_mixed.pcap

# 6. Esperar a que termine
sleep 20

# 7. Detener detector
sudo pkill detector_dpdk

# 8. Analizar resultados
python3 scripts/analyze.py \
  --export-features /local/experiment_results.csv

echo "Resultados en:"
echo "  /local/logs/detection.log"
echo "  /local/logs/ml_features.csv"
echo "  /local/logs/alerts.log"
echo "  /local/experiment_results.csv"
```

## Estructura de Datos (Sketches)

### Count-Min Sketch
- **Uso**: Conteo de paquetes por IP origen
- **Tamaño**: 2048 × 4 = 8,192 counters (32 KB)
- **Error**: ε = e/width ≈ 0.13%

### HyperLogLog
- **Uso**: Cardinalidad de IPs únicas y puertos únicos
- **Tamaño**: 2^14 = 16,384 registros (16 KB)
- **Error**: ±1.04/√m ≈ 0.8%

### Bloom Filter
- **Uso**: Set membership para IPs vistas
- **Tamaño**: 1,000,000 bits = 125 KB
- **False positive**: (1 - e^(-kn/m))^k ≈ 0.01%

**Memoria total**: ~175 KB para sketches

## Performance

En nodo CloudLab (Intel Xeon 2.4 GHz):

- **Throughput**: ~20 Mpps (línea 100G)
- **Latencia**: <1 µs por paquete
- **CPU**: ~80% en 1 core @ 10 Mpps
- **Memoria**: ~2 GB (DPDK mempools)

## Licencia

Uso académico y educativo. Prohibido uso malicioso.

## Referencias

- DPDK: https://www.dpdk.org/
- Count-Min Sketch: Cormode & Muthukrishnan (2005)
- HyperLogLog: Flajolet et al. (2007)
- CloudLab: https://www.cloudlab.us/
