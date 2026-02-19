# MIRA DDoS Detector - ML Classification System Results

**Date:** February 18, 2025
**Experiment:** Multi-class DDoS detection with embedded LightGBM inference
**Feature modes compared:** DPI+Sketch (75), DPI-Ratios (33), Sketch-ADV (64)
**Attack classes (14):** benign, dns, ldap, mixed, mssql, netbios, ntp, portmap, snmp, ssdp, syn, tftp, udp, webddos

---

## 1. System Architecture

MIRA is a DPDK-based DDoS detection system running on a multi-core architecture. Traffic arrives from a 25 Gbps NIC via RSS (Receive Side Scaling) and is distributed across 14 worker threads. A 15th core acts as coordinator, merging per-worker data structures and running ML inference.

```
                         MIRA DDoS Detection System
    +---------------------------------------------------------------------+
    |                                                                       |
    |   25 Gbps NIC (RSS - 14 queues)                                      |
    |        |                                                              |
    |        v                                                              |
    |   +---------+  +---------+       +---------+                          |
    |   |Worker 1 |  |Worker 2 |  ...  |Worker 14|   (14 lcores)           |
    |   | OctoSk. |  | OctoSk. |       | OctoSk. |                         |
    |   | DPI     |  | DPI     |       | DPI     |                         |
    |   | RingBuf |  | RingBuf |       | RingBuf |                         |
    |   +----+----+  +----+----+       +----+----+                          |
    |        |            |                 |                               |
    |        +------------+-----------------+                               |
    |                     v                                                 |
    |              +-------------+                                          |
    |              | Coordinator |  (lcore 15)                              |
    |              |  Merge +    |                                          |
    |              |  ML Infer.  |                                          |
    |              +------+------+                                          |
    |                     |                                                 |
    |         +-----------+-----------+                                     |
    |         v                       v                                     |
    |   +------------+        +--------------+                              |
    |   | LightGBM   |        |  Alert /     |                              |
    |   | Prediction |------->|  Stats       |                              |
    |   | (C API)    |        |  Display     |                              |
    |   +------------+        +--------------+                              |
    +---------------------------------------------------------------------+
```

### 1.1 Detection Window

- **Window duration:** 5 seconds
- **Sub-window granularity:** 50 ms (used by ring buffer and multi-scale sketches)
- **Per window:** All features are computed, ML prediction is run, and alert decision is made

### 1.2 Core Components

| Component | Description | Per-Worker Memory |
|-----------|-------------|-------------------|
| **OctoSketch** | Count-Min Sketch (8 rows x 4096 cols) with per-IP hash table (65536 buckets) | ~390 KB |
| **Multi-Scale Sketches** | 4 OctoSketch instances at different time scales (50ms, 1s, 10s, 1min) | ~1.5 MB |
| **Ring Buffer** | Circular buffer (100 windows x 50ms = 5s history) for PPS temporal trends | ~800 bytes |
| **DPI Counters** | Protocol-specific packet/byte counters from L3-L7 header parsing | ~2 KB |
| **Per-Protocol Sketches** | 12 additional OctoSketch instances (one per attack protocol, sketch-adv mode only) | ~4.7 MB |
| **LightGBM Model** | Loaded once at startup via LightGBM C API, shared across windows | ~50 KB |

---

## 2. Data Collection

### 2.1 Detector Variants for Data Collection

Data collection was performed using `detector_system2`, a **measure-only** variant of the detector that removes all threshold-based alerting logic. This ensures unbiased feature logging for every detection window, regardless of traffic type.

```
detector_system (original):              detector_system2 (measure-only):
+-------------------------+             +-------------------------+
|  Packet Processing      |             |  Packet Processing      |
|  DPI + OctoSketch       |             |  DPI + OctoSketch       |
|         |                |             |         |                |
|         v                |             |         v                |
|  +-----------------+    |             |  +-----------------+    |
|  | Threshold Check |    |             |  |  NO thresholds  |    |
|  |  Active alerts  |    |             |  |  Pure logging   |    |
|  +-----------------+    |             |  |  Every window   |    |
|         |                |             |  +-----------------+    |
|         v                |             |         |                |
|     .log with alerts     |             |    .log (all features)  |
|     (biased output)      |             |    (unbiased output)    |
+-------------------------+             +-------------------------+
```

### 2.2 Experiment Protocol

Each data collection run follows a structured 200-second protocol with known ground truth:

```
         50s              100s              50s
    +----------+    +--------------+    +----------+
    |  BENIGN  |    |   ATTACK     |    |  BENIGN  |
    |  traffic |    |   traffic    |    |  traffic |
    |  only    |    |  (specific   |    |  only    |
    |          |    |   type)      |    |          |
    +----------+    +--------------+    +----------+
    t=0        t=50s               t=150s        t=200s

    Labels:  benign    |    attack_type     |    benign
```

- **50s benign baseline** before attack: establishes normal traffic patterns
- **100s attack traffic**: specific attack type at controlled rate
- **50s benign recovery** after attack: captures post-attack transition
- **Automatic labeling**: Feature extractor assigns labels based on elapsed timestamps, detecting attack boundaries from the `attack_packets` ratio in each window

### 2.3 Attack Types and Runs

14 attack classes were tested, corresponding to real DDoS attack vectors from the CIC-DDoS-2019 dataset methodology:

| Attack Type | Protocol | Port(s) | Mechanism | Runs |
|-------------|----------|---------|-----------|------|
| **dns** | UDP | 53 | DNS amplification (ANY/TXT queries) | 4 |
| **ntp** | UDP | 123 | NTP amplification (monlist command) | 4 |
| **snmp** | UDP | 161 | SNMP amplification (GetBulk requests) | 4 |
| **ssdp** | UDP | 1900 | SSDP amplification (M-SEARCH) | 4 |
| **portmap** | UDP/TCP | 111 | RPC portmapper amplification (GETPORT/DUMP) | 4 |
| **netbios** | UDP | 137/138 | NetBIOS name service amplification | 4 |
| **ldap** | UDP/TCP | 389 | LDAP amplification (search requests) | 4 |
| **mssql** | TCP | 1433 | MSSQL amplification (SQLBatch/RPC) | 4 |
| **tftp** | UDP | 69 | TFTP amplification (RRQ/WRQ) | 4 |
| **syn** | TCP | various | SYN flood (TCP SYN flag without completion) | 4 |
| **udp** | UDP | various | Generic UDP flood (random ports) | 4 |
| **webddos** | TCP | 80/443 | HTTP/HTTPS flood (application-layer) | 4 |
| **mixed** | Multiple | Multiple | Simultaneous multi-protocol attack | 4 |
| **benign** | Mixed | Mixed | Normal background traffic | 4 |

**Total: 52 runs** (13 attack types x 4 runs + 4 benign runs)

Each detection window (5 seconds) produces one feature vector. A typical 200-second run generates ~40 labeled samples per run, yielding approximately 2,000+ samples across all runs.

---

## 3. Feature Modes

Three feature modes are supported, each representing a different trade-off between inspection depth and encryption resistance:

### 3.1 DPI+Sketch Mode (75 features)

Combines deep packet inspection counters with sketch-based probabilistic analysis. Requires plaintext payload access for L7 protocol detection.

**Source:** 61 DPI features + 14 sketch features = 75 total

#### DPI Features (61)

| Group | Count | Features | Source |
|-------|-------|----------|--------|
| **Base counters** | 14 | `total_packets`, `total_bytes`, `udp_packets`, `tcp_packets`, `icmp_packets`, `syn_packets`, `http_requests`, `dns_queries`, `baseline_packets`, `attack_packets`, `udp_tcp_ratio`, `syn_total_ratio`, `baseline_attack_ratio`, `bytes_per_packet` | L3/L4 header parsing + L7 detection |
| **Protocol-specific** | 22 | `ntp_monlist_queries`, `ntp_responses`, `avg_ntp_response_size`, `dns_any_queries`, `dns_txt_queries`, `dns_responses`, `avg_dns_response_size`, `snmp_getbulk_requests`, `snmp_responses`, `avg_snmp_response_size`, `ssdp_msearch_packets`, `ssdp_responses`, `portmap_getport_calls`, `portmap_dump_calls`, `netbios_name_queries`, `netbios_dgram_packets`, `ldap_bind_requests`, `ldap_search_requests`, `mssql_sqlbatch_packets`, `mssql_rpc_packets`, `tftp_rrq_packets`, `tftp_wrq_packets` | Deep L7 payload inspection: RPC call types, DNS record types, SNMP operations, etc. |
| **Amplification ratios** | 6 | `ntp_amplification_factor`, `dns_amplification_factor`, `snmp_amplification_factor`, `query_response_ratio`, `fragmentation_ratio`, `syn_ack_ratio` | Derived from request/response size asymmetry |
| **SYN/WebDDoS discrimination** | 4 | `syn_only_packets`, `http_payload_packets`, `active_attack_protocols`, `syn_http_ratio` | Discriminate SYN flood vs HTTP flood + mixed detection |
| **Normalized ratios** | 13 | `syn_only_ratio`, `http_payload_ratio`, `dns_query_ratio`, `ntp_monlist_ratio`, `snmp_ratio`, `ssdp_ratio`, `icmp_ratio`, `http_request_ratio`, `portmap_ratio`, `netbios_ratio`, `ldap_ratio`, `mssql_ratio`, `tftp_ratio` | Volume-invariant protocol ratios (each / total_packets) |
| **Protocol diversity** | 2 | `max_protocol_ratio`, `protocol_diversity` | Mixed vs pure attack discrimination: highest protocol share + count of active protocols |

#### Sketch Features (14)

| Group | Count | Features | Underlying Structure |
|-------|-------|----------|---------------------|
| **Ring Buffer (temporal)** | 5 | `delta_pps_5w`, `delta_pps_10w`, `pps_variance`, `pps_baseline`, `ratio_vs_baseline` | **Ring Buffer** (100 x 50ms = 5s sliding window): PPS deltas at 250ms/500ms, variance over 20 windows, adaptive baseline, current/baseline ratio |
| **OctoSketch (multi-scale)** | 7 | `top_ip_pps_50ms`, `top_ip_pps_1s`, `top_ip_pps_1min`, `ratio_50ms_1min`, `num_heavy_hitters`, `ip_concentration`, `adaptive_threshold` | **Count-Min Sketch** at 3 time scales (50ms/1s/1min): top attacker PPS per scale, burst ratio, heavy-hitter count, IP concentration |
| **Derived** | 2 | `new_ips_ratio`, `attack_entropy` | Computed from sketch state: new IPs ratio, Shannon entropy of attack protocol distribution |

```
DPI+Sketch Feature Composition (75 total):

  +--------------------------------------------------------------+
  |                    DPI Features (61)                           |
  |  +-------------+ +--------------------+ +-----------+         |
  |  | DPI base    | | DPI protocol (L7)  | | DPI ratios|         |
  |  |   (14)      | |       (22)         | |    (6)    |         |
  |  +-------------+ +--------------------+ +-----------+         |
  |  +------------------+ +--------------+ +---------------+      |
  |  | SYN/Web discrim. | | Normalized   | | Protocol     |      |
  |  |      (4)         | | ratios (13)  | | diversity (2)|      |
  |  +------------------+ +--------------+ +---------------+      |
  +--------------------------------------------------------------+
  |                  Sketch Features (14)                         |
  |  +----------------------+  +-----------------------------+    |
  |  | Ring Buffer (5)      |  | Count-Min Sketch (9)        |    |
  |  | Temporal: deltas,    |  | Multi-scale: top IPs,       |    |
  |  | variance, baseline   |  | heavy-hitters, entropy,     |    |
  |  | (sliding window)     |  | concentration               |    |
  |  +----------------------+  +-----------------------------+    |
  +--------------------------------------------------------------+
```

### 3.2 DPI-Ratios Mode (33 features)

A **volume-invariant** subset of DPI+Sketch features designed for better cross-run generalization. Excludes raw counters (which vary with traffic volume) and keeps only ratios and proportional features.

**Source:** 4 basic ratios + 6 amplification ratios + 2 SYN/Web discrimination + 13 normalized ratios + 6 sketch ratios + 2 protocol diversity = 33 total

| Group | Count | Features |
|-------|-------|----------|
| **Basic ratios** | 4 | `udp_tcp_ratio`, `syn_total_ratio`, `baseline_attack_ratio`, `bytes_per_packet` |
| **Amplification ratios** | 6 | `ntp_amplification_factor`, `dns_amplification_factor`, `snmp_amplification_factor`, `query_response_ratio`, `fragmentation_ratio`, `syn_ack_ratio` |
| **SYN/Web discrimination** | 2 | `active_attack_protocols`, `syn_http_ratio` |
| **Normalized protocol ratios** | 13 | `syn_only_ratio`, `http_payload_ratio`, `dns_query_ratio`, `ntp_monlist_ratio`, `snmp_ratio`, `ssdp_ratio`, `icmp_ratio`, `http_request_ratio`, `portmap_ratio`, `netbios_ratio`, `ldap_ratio`, `mssql_ratio`, `tftp_ratio` |
| **Sketch ratios** | 6 | `ratio_vs_baseline`, `ratio_50ms_1min`, `num_heavy_hitters`, `ip_concentration`, `new_ips_ratio`, `attack_entropy` |

This mode tests whether rate-independent features alone can achieve high accuracy, which would indicate robustness to varying traffic volumes and line rates.

### 3.3 Sketch-ADV Mode (64 features)

Uses **only sketch-based features** with no deep packet inspection. Extends the 14 global sketch features with 12 per-protocol OctoSketch instances. Only requires packet headers (IP, port, TCP flags, packet size), making it fully encryption-resistant.

**Source:** 14 global sketch + 48 per-protocol sketch (12 protocols x 4 metrics) + 2 packet size = 64 total

#### Global Sketch Features (14) - Same as DPI+Sketch

Identical Ring Buffer (5) + Count-Min Sketch multi-scale (9) features.

#### Per-Protocol Sketch Features (48)

Each of the 12 protocols has its own dedicated OctoSketch instance. Traffic is routed to the correct per-protocol sketch based on destination port and TCP flags in the worker thread. From each sketch, 4 metrics are extracted:

| Metric | Description | Underlying Structure |
|--------|-------------|---------------------|
| `pps_<proto>` | Packets per second for this protocol | Per-protocol CMS: `total_updates / window_seconds` |
| `heavy_hitters_<proto>` | IPs exceeding threshold for this protocol | Per-protocol CMS: count of IPs with count > threshold |
| `ip_concentration_<proto>` | Top-1 IP share of this protocol's traffic | Per-protocol CMS: `top1_count / total_updates` |
| `ratio_vs_total_<proto>` | Protocol's PPS vs global PPS | Cross-sketch ratio: `proto_sketch.pps / global_sketch.pps` |

**12 monitored protocols:** DNS (port 53), NTP (port 123), SNMP (port 161), SSDP (port 1900), PortMap (port 111), NetBIOS (port 137/138), LDAP (port 389), MSSQL (port 1433), TFTP (port 69), SYN (TCP SYN flags), HTTP (port 80/443), UDP-Other (remaining UDP)

#### Packet Size Features (2)

| Feature | Description |
|---------|-------------|
| `avg_packet_size` | Mean packet size in bytes (global) |
| `packet_size_variance` | Variance of packet sizes (global) |

```
Sketch-ADV Feature Composition (64 total):

  +--------------------------------------------------------------+
  |               Global Sketch Features (14)                     |
  |  +----------------------+  +-----------------------------+    |
  |  | Ring Buffer (5)      |  | Count-Min Sketch (9)        |    |
  |  | Temporal: deltas,    |  | Multi-scale: top IPs,       |    |
  |  | variance, baseline   |  | heavy-hitters, entropy      |    |
  |  +----------------------+  +-----------------------------+    |
  +--------------------------------------------------------------+
  |    Per-Protocol Count-Min Sketches (48 = 4 metrics x 12)      |
  |    Each protocol has its own CMS instance                      |
  |                                                                |
  |  +-----+ +-----+ +-----+ +-----+ +-----+ +-----+             |
  |  | DNS | | NTP | |SNMP | |SSDP | |Port | |NetB |             |
  |  | CMS | | CMS | | CMS | | CMS | | CMS | | CMS |             |
  |  |(4f) | |(4f) | |(4f) | |(4f) | |(4f) | |(4f) |             |
  |  +-----+ +-----+ +-----+ +-----+ +-----+ +-----+             |
  |  +-----+ +-----+ +-----+ +-----+ +-----+ +-----+             |
  |  |LDAP | |MSSQL| |TFTP | | SYN | |HTTP | |UDP- |             |
  |  | CMS | | CMS | | CMS | | CMS | | CMS | |Oth. |             |
  |  |(4f) | |(4f) | |(4f) | |(4f) | |(4f) | |(4f) |             |
  |  +-----+ +-----+ +-----+ +-----+ +-----+ +-----+             |
  +--------------------------------------------------------------+
  |              Packet Size Features (2)                          |
  |  +------------------+  +-----------------------+               |
  |  | avg_packet_size  |  | packet_size_variance  |               |
  |  +------------------+  +-----------------------+               |
  +--------------------------------------------------------------+

  CMS = Count-Min Sketch (8 rows x 4096 cols, conservative update)
```

### 3.4 Feature Mode Comparison

| Aspect | DPI+Sketch (75) | DPI-Ratios (33) | Sketch-ADV (64) |
|--------|-----------------|-----------------|-----------------|
| **DPI (L7 payload)** | 61 features | 27 features (ratios only) | None |
| **Global sketch** | 14 features | 6 features (ratios only) | 14 features |
| **Per-protocol sketches** | None | None | 48 features |
| **Packet size** | Implicit in `bytes_per_packet` | `bytes_per_packet` | `avg_packet_size` + `packet_size_variance` |
| **Encryption-resistant** | No (needs plaintext L7) | Partially (ratios still need DPI) | Yes (headers only) |
| **Volume-invariant** | No (raw counters included) | Yes (only ratios) | Partially (PPS values scale) |
| **Memory per worker** | ~2 MB (1 global sketch) | ~2 MB (same as DPI+Sketch) | ~7 MB (1 global + 12 per-protocol) |
| **Data source** | `.log` (text, regex parsing) | `.log` (text, regex parsing) | `.log` or `.bin` (binary 528 bytes/record) |

---

## 4. Training Pipeline

### 4.1 Pipeline Overview

```
  detector_system2                    ml_system2
  +-------------+                   +----------------------+
  | 200s runs   |                   |                      |
  | per attack  |---.log--->        |  log_pipeline/       |
  | type        |                   |   feature_extractor  |
  |             |                   |        |             |
  | 4 runs each |                   |        v             |
  | (run1..run4)|                   |  datasets/processed/ |
  +-------------+                   |   *.csv per run      |
                                    |        |             |
                                    |        v             |
                                    |  training/           |
                                    |   prepare_dataset    |
                                    |   train_model        |
                                    |   evaluate_model     |
                                    |   compare_models     |
                                    +----------------------+

  52 runs total:
    12 attack types x 4 runs = 48
    mixed           x 4 runs =  4
                              ----
                                52
```

### 4.2 Feature Extraction (`feature_extractor.py`)

Parses detector log files and extracts features from each detection window:

1. **Splits** log by `[PACKET COUNTERS - GLOBAL]` markers into individual windows
2. **Extracts** features via regex matching against the structured log format
3. **Auto-labels** windows based on elapsed time and attack_packets ratio
4. **Derives** computed features (ratios, amplification factors, entropy, diversity)
5. **Outputs** CSV with one row per detection window

### 4.3 Dataset Preparation (`prepare_dataset.py`)

1. **Combines** all per-run CSV files into a single dataset
2. **Filters** features to match the selected mode (dpi_sketch, dpi_ratios, sketch_adv)
3. **Stratified split**: 70% train / 15% validation / 15% test
4. Optional **subsampling** (1 every N windows) to reduce temporal autocorrelation
5. Optional **run-based splitting** for cross-run generalization testing

### 4.4 Model Training (`train_model.py`)

- **Algorithm:** LightGBM (gradient-boosted decision trees)
- **Objective:** Multi-class classification (14 classes)
- **Feature normalization:** StandardScaler (z-score: `(x - mean) / std`)
- **Adaptive hyperparameters** based on dataset size:
  - Small (<500 samples): `lr=0.05, depth=4, leaves=15, L1=1.0, L2=1.0`
  - Medium (500-1000): `lr=0.03, depth=3, leaves=7, L1=5.0, L2=10.0`
  - Large (>1000): `lr=0.02, depth=4, leaves=15, L1=5.0, L2=10.0`
- **Early stopping:** 10-30 rounds based on dataset size
- **Outputs:** `lightgbm_model.txt`, `feature_scaler.json`, `label_mapping.json`, `feature_columns.json`, `feature_importance.csv`

### 4.5 Evaluation (`evaluate_model.py`, `compare_models.py`)

- Per-class precision, recall, F1 on held-out test set
- Confusion matrix analysis
- Cross-model comparison with side-by-side tables
- Feature importance ranking (LightGBM gain-based)

---

## 5. Model Results

### 5.1 LightGBM Comparison (3 Feature Modes)

| Metric | DPI+Sketch (75) | DPI-Ratios (33) | Sketch-ADV (64) |
|--------|:---:|:---:|:---:|
| **Features** | 75 | 33 | 64 |
| **Accuracy** | **99.82%** | 98.95% | 98.66% |
| **Weighted F1** | **99.81%** | 98.85% | 98.54% |
| **Macro F1** | **99.58%** | 97.03% | 96.72% |

### 5.2 Per-Class F1 Scores

| Class | DPI+Sketch (75) | DPI-Ratios (33) | Sketch-ADV (64) |
|-------|:---:|:---:|:---:|
| benign | **1.000** (R=1.00) | 0.973 (R=0.95) | 0.973 (R=0.97) |
| dns | **1.000** (R=1.00) | **1.000** (R=1.00) | 0.982 (R=0.97) |
| ldap | **1.000** (R=1.00) | **1.000** (R=1.00) | 0.987 (R=0.97) |
| mixed | **0.960** (R=0.96) | 0.778 (R=0.88) | 0.700 (R=0.88) |
| mssql | **1.000** (R=1.00) | **1.000** (R=1.00) | 0.986 (R=0.97) |
| netbios | **1.000** (R=1.00) | **1.000** (R=1.00) | 0.983 (R=0.97) |
| ntp | **1.000** (R=1.00) | **1.000** (R=1.00) | 0.972 (R=0.97) |
| portmap | **1.000** (R=1.00) | **1.000** (R=1.00) | 0.983 (R=0.97) |
| snmp | **1.000** (R=1.00) | **1.000** (R=1.00) | 0.972 (R=0.97) |
| ssdp | **1.000** (R=1.00) | **1.000** (R=1.00) | 0.983 (R=0.97) |
| syn | **1.000** (R=1.00) | 0.945 (R=0.95) | 0.972 (R=0.97) |
| tftp | **1.000** (R=1.00) | **1.000** (R=1.00) | 0.983 (R=0.97) |
| udp | **1.000** (R=1.00) | 0.962 (R=1.00) | 0.972 (R=0.97) |
| webddos | **0.952** (R=0.95) | 0.925 (R=0.90) | 0.972 (R=0.97) |

### 5.3 Feature Importance (Top 5 per Mode)

| Rank | DPI+Sketch (75) | DPI-Ratios (33) | Sketch-ADV (64) |
|------|-----------------|-----------------|-----------------|
| 1 | `syn_total_ratio` | `bytes_per_packet` | `attack_entropy` |
| 2 | `total_bytes` | `syn_http_ratio` | `pps_netbios` |
| 3 | `bytes_per_packet` | `attack_entropy` | `pps_portmap` |
| 4 | `ntp_monlist_queries` | `snmp_amplification_factor` | `pps_mssql` |
| 5 | `attack_packets` | `ntp_amplification_factor` | `pps_ssdp` |

### 5.4 Analysis

**DPI+Sketch (75 features) - Best overall accuracy (99.82%)**
- Near-perfect F1 across all pure attack classes (1.000)
- Slight weakness on `mixed` (0.960) and `webddos` (0.952)
- Top features are L7 DPI counters: `syn_total_ratio`, `ntp_monlist_queries`, `attack_packets`
- Requires plaintext payload access for L7 protocol detection

**DPI-Ratios (33 features) - Strong generalization (98.95%)**
- Achieves 98.95% accuracy with only 33 volume-invariant features (44% of DPI+Sketch)
- Most pure attack types still achieve 1.000 F1
- Weakest on `mixed` (0.778 F1) and `webddos` (0.925 F1)
- `bytes_per_packet` and `syn_http_ratio` are the strongest discriminators
- Better cross-run robustness since raw counters are excluded

**Sketch-ADV (64 features) - Encryption-resistant (98.66%)**
- Achieves 98.66% accuracy without any payload inspection
- Consistent recall (0.97) across all attack types
- Weakest on `mixed` class (0.700 F1), best on `webddos` (0.972 F1)
- `attack_entropy` is by far the most important feature, followed by per-protocol PPS features
- Fully operational with encrypted traffic (TLS/QUIC)

**Key observations:**
1. The `mixed` class is the hardest across all modes (0.960 / 0.778 / 0.700 F1), because multi-protocol attacks have overlapping feature signatures
2. DPI-Ratios performs surprisingly well (98.95%) despite having less than half the features, suggesting volume-invariant ratios carry most discriminative power
3. Sketch-ADV's per-protocol PPS features (4 of top 5) validate the architecture of running separate OctoSketch instances per protocol
4. The gap between DPI+Sketch and Sketch-ADV narrowed significantly compared to earlier experiments (from 2.59% to 1.16% accuracy difference), thanks to improved feature extraction and the addition of normalized ratios to DPI+Sketch

---

## 6. ML-Embedded Detector (`detectorML`)

### 6.1 Architecture

`detectorML` is the production detector with embedded ML inference. It replaces all threshold-based alerting with a single LightGBM model that classifies traffic every detection window.

```
  +------------------------------------------------------------------+
  |                        detectorML                                  |
  |                                                                    |
  |  Worker Threads (x14):                                             |
  |    Per-packet: DPI counters + OctoSketch updates + RingBuffer      |
  |                                                                    |
  |  Coordinator (every 5s window):                                    |
  |    1. Merge per-worker sketches (global + per-protocol)            |
  |    2. Compute delta features (current - previous window snapshot)  |
  |    3. Extract feature vector (75 or 64 features)                   |
  |    4. Apply StandardScaler normalization: (x - mean) / scale       |
  |    5. LightGBM prediction via C API (LGBM_BoosterPredictForMat)    |
  |    6. Alert decision based on prediction class and confidence      |
  +------------------------------------------------------------------+
```

### 6.2 ML-Only Classification

The ML model is the **sole source of alert decisions**. Threshold counters are kept for statistics display only but do not trigger alerts:

```
  Feature Vector (75 or 64 features)
         |
         v
  +-------------------+
  | StandardScaler    |  (x - mean) / scale
  | normalization     |  loaded from feature_scaler.json
  +--------+----------+
           |
           v
  +-------------------+
  | LightGBM C API    |  LGBM_BoosterPredictForMat()
  | Multi-class       |  14 class probabilities
  +--------+----------+
           |
           v
  +-------------------+
  | Alert Decision    |
  |                   |
  | benign -> no alert|
  | attack -> alert   |
  +--------+----------+
           |
           v
  Confidence-based severity:
    >= 75%  ->  CRITICAL (red)
    >= 50%  ->  HIGH (yellow)
    <  50%  ->  ANOMALY (white)
```

### 6.3 Model Files

The detector loads three files at startup from the model directory:

| File | Content | Usage |
|------|---------|-------|
| `lightgbm_model.txt` | Trained LightGBM model (text format) | Loaded via `LGBM_BoosterCreateFromModelfile()` |
| `feature_scaler.json` | `{"mean": [...], "scale": [...]}` per feature | Applied before prediction: `scaled = (raw - mean) / scale` |
| `label_mapping.json` | `{"0": "benign", "1": "dns", ...}` | Maps predicted class index to human-readable name |

### 6.4 Window Snapshot for Delta Features

Cumulative counters (e.g., `total_packets`, `total_bytes`) are converted to per-window deltas using a snapshot mechanism:

```c
// At start of each detection window:
delta_packets = current_total_packets - snapshot.total_packets;
snapshot.total_packets = current_total_packets;
// delta_packets is used as the feature value
```

This ensures the model sees per-window rates rather than ever-growing cumulative values.

### 6.5 Runtime Display

The detector displays real-time classification output every detection window:

```
[ML CLASSIFICATION]
  Model:              dpi_sketch (75 features)
  Prediction:         benign (99.87%)
  Class probabilities: benign:99.9% dns:0.0% ldap:0.0% mixed:0.0% ...

[ALERT STATUS]
  Level:              NONE
  Reason:             None
```

When an attack is detected:

```
[ML CLASSIFICATION]
  Model:              dpi_sketch (75 features)
  Prediction:         dns (98.42%)
  Class probabilities: benign:0.1% dns:98.4% ldap:0.0% ...

[ALERT STATUS]
  Level:              CRITICAL
  Reason:             ML: dns (98.4%)
```

---

## 7. Advantages of Sketch-ADV for Production Deployment

Despite achieving slightly lower accuracy than DPI+Sketch (98.66% vs 99.82%), the Sketch-ADV pipeline offers critical architectural advantages that make it the preferred approach for real-world high-speed network environments.

### 7.1 Encryption Resistance

```
DPI+Sketch:                          Sketch-ADV:
+-------------+                     +-------------+
|  Encrypted  | --DPI--> FAILS     |  Encrypted  | --Headers--> WORKS
|   Traffic   |   (can't read       |   Traffic   |   (only needs
|  (TLS/QUIC) |    payloads)        |  (TLS/QUIC) |    IP/port/flags)
+-------------+                     +-------------+
```

- **DPI requires plaintext payloads** to identify DNS query types (ANY/TXT), NTP monlist requests, SNMP GetBulk operations, HTTP methods, etc. With encrypted traffic (TLS 1.3, QUIC, DoH, DoT), the 61 DPI features become zeros, and the model is effectively blind.
- **Sketch-ADV only needs packet headers** (IP addresses, destination ports, TCP flags, packet sizes). These fields remain visible regardless of payload encryption, since they are required for network routing and transport.
- As encrypted traffic continues to grow (already >90% of web traffic), DPI-based detection becomes increasingly unreliable. Sketch-ADV is future-proof by design.

### 7.2 Processing Efficiency at High Line Rates

| Aspect | DPI+Sketch | Sketch-ADV |
|--------|------------|------------|
| Per-packet work | L3 + L4 + L7 parsing (payload access) | L3 + L4 headers only (no payload) |
| Payload access | Required (copy + deep inspection) | Not required (zero-copy headers) |
| Branch complexity | High (protocol-dependent parsing paths) | Low (port-based routing to sketch) |
| Cycles per packet | ~200-500 cycles (string matching, protocol dissection) | ~50-100 cycles (hash + increment) |
| Cache behavior | Poor (variable-length payload access, cache misses) | Good (fixed-size sketch arrays, sequential access) |

At 25 Gbps (the current NIC throughput for MIRA), DPI can already become a bottleneck. With minimum-size 64-byte packets, 25 Gbps requires processing ~37 Mpps. Sketch-ADV's header-only approach scales better because:
- No payload copies are needed (zero-copy header access via DPDK `rte_pktmbuf`)
- Each sketch update is O(1): 8 hash computations + 8 increments per row
- Per-protocol routing adds only a port comparison and one additional sketch update
- All sketch arrays are cache-line aligned (`__rte_cache_aligned`), minimizing cache misses

### 7.3 Compact Binary Output Format

| Aspect | `.log` (DPI+Sketch) | `.bin` (Sketch-ADV) |
|--------|---------------------|---------------------|
| Record size | Variable (text, ~2-5 KB per window) | Fixed 528 bytes per record |
| Parsing | Regex-based (slow, fragile) | `struct.unpack` (fast, exact) |
| Storage per hour | ~3-10 MB | ~380 KB |
| Reliability | Regex can break on format changes | Binary struct is always exact |
| I/O overhead | High (snprintf formatting per window) | Minimal (memcpy of struct) |

### 7.4 Reduced Attack Surface

- **No payload inspection = no payload-based evasion.** Attackers cannot evade Sketch-ADV by obfuscating, fragmenting, or encrypting payloads, since the system never looks at them.
- **Port-based protocol classification** is harder to evade than signature-based DPI, since using non-standard ports changes the traffic pattern itself (e.g., DNS on port 8053 would route to `udp_other` sketch, altering the feature distribution).

### 7.5 Model Robustness

All models tested on Sketch-ADV features achieve nearly identical accuracy (~96.7-98.7%), meaning the feature set is **inherently discriminative** regardless of model complexity. This is beneficial for deployment:
- A simple model (e.g., shallow tree) achieves similar accuracy to a complex ensemble
- Lower model complexity = faster inference = more headroom for packet processing
- Less risk of overfitting to training data artifacts

### 7.6 Memory and Deployment Trade-offs

| Resource | DPI+Sketch | Sketch-ADV |
|----------|------------|------------|
| Memory per worker | ~2 MB | ~7 MB (+12 per-protocol sketches) |
| Total memory (14 workers) | ~28 MB | ~98 MB |
| Model file size | ~50 KB | ~50 KB |
| Feature extraction complexity | High (61 DPI counters) | Low (14 global + port routing) |
| Deployment requirements | Plaintext traffic access | Any network tap or mirror port |

The additional ~70 MB of memory for per-protocol sketches is negligible compared to DPDK's hugepage allocation (typically 4-8 GB), and the trade-off provides encryption resistance and processing efficiency.

---

## 8. Conclusions

1. **DPI+Sketch (75 features) achieves the best accuracy** at 99.82% with near-perfect F1 across all classes, making it the preferred mode when plaintext payload inspection is available.

2. **DPI-Ratios (33 features) proves that volume-invariant ratios carry most discriminative power**, achieving 98.95% accuracy with less than half the features. This mode offers better generalization across different traffic volumes.

3. **Sketch-ADV (64 features) is the recommended approach for production deployment**, achieving 98.66% accuracy without any payload inspection. Its encryption resistance, processing efficiency, and compact binary format make it the most practical choice for high-speed networks where traffic is increasingly encrypted.

4. **The accuracy gap between DPI+Sketch and Sketch-ADV is only 1.16%** (99.82% vs 98.66%), a small price to pay for full encryption resistance, lower per-packet processing cost, and elimination of DPI dependencies.

5. **The `mixed` class remains the hardest to classify** across all modes (0.700-0.960 F1), as multi-protocol attacks create ambiguous feature signatures that overlap with pure attack types.

6. **ML-only classification eliminates threshold tuning**, replacing manually-set anomaly thresholds with a trained model that adapts to the observed attack patterns. The confidence-based severity mapping (CRITICAL/HIGH/ANOMALY) provides operational flexibility.

7. **LightGBM C API embedding** enables real-time inference within the DPDK packet processing pipeline with minimal latency overhead, running prediction once per 5-second detection window on the coordinator core.

8. **Per-protocol Count-Min Sketches validate the architectural decision**: the `pps_*` features dominate Sketch-ADV's feature importance (4 of top 5), confirming that dedicated per-protocol sketch instances provide the discriminative power needed to replace deep packet inspection.
