# MIRA DDoS Detector - Feature Pipeline Comparison Results

**Date:** February 11, 2025
**Experiment:** DPI+Sketch (56 features) vs Sketch-ADV (64 features) for multi-class DDoS detection
**Attack classes (14):** benign, dns, ldap, mixed, mssql, netbios, ntp, portmap, snmp, ssdp, syn, tftp, udp, webddos

---

## 1. System Architecture Overview

```
                         MIRA DDoS Detection System
    ┌─────────────────────────────────────────────────────────────────┐
    │                                                                 │
    │   25 Gbps NIC (RSS)                                             │
    │        │                                                        │
    │        ▼                                                        │
    │   ┌─────────┐  ┌─────────┐       ┌─────────┐                   │
    │   │Worker 1 │  │Worker 2 │  ...  │Worker 14│   (14 lcores)     │
    │   │ OctoSk. │  │ OctoSk. │       │ OctoSk. │                   │
    │   │ DPI     │  │ DPI     │       │ DPI     │                   │
    │   └────┬────┘  └────┬────┘       └────┬────┘                   │
    │        │            │                 │                         │
    │        └────────────┼─────────────────┘                         │
    │                     ▼                                           │
    │              ┌─────────────┐                                    │
    │              │ Coordinator │  (lcore 15)                        │
    │              │  Merge +    │                                    │
    │              │  Features   │                                    │
    │              └──────┬──────┘                                    │
    │                     │                                           │
    │         ┌───────────┴───────────┐                               │
    │         ▼                       ▼                               │
    │   ┌───────────┐          ┌───────────┐                         │
    │   │  .log     │          │  .bin     │                         │
    │   │ DPI+Sketch│          │ Sketch-ADV│                         │
    │   │ 56 feat.  │          │ 64 feat.  │                         │
    │   └───────────┘          └───────────┘                         │
    └─────────────────────────────────────────────────────────────────┘
```

---

## 2. Feature Set Description

### 2.1 DPI+Sketch Pipeline (56 features)

This pipeline combines **Deep Packet Inspection** counters with **OctoSketch** probabilistic analysis. Features are extracted from text `.log` files via regex parsing.

#### DPI Features (42) - Packet-Level Inspection

| Group | # | Columns | Source |
|-------|---|---------|--------|
| **DPI (base)** | 14 | `total_packets`, `total_bytes`, `udp_packets`, `tcp_packets`, `icmp_packets`, `syn_packets`, `http_requests`, `dns_queries`, `baseline_packets`, `attack_packets`, `udp_tcp_ratio`, `syn_total_ratio`, `baseline_attack_ratio`, `bytes_per_packet` | L3/L4 header parsing + L7 protocol detection |
| **DPI protocol** | 22 | `ntp_monlist_queries`, `ntp_responses`, `avg_ntp_response_size`, `dns_any_queries`, `dns_txt_queries`, `dns_responses`, `avg_dns_response_size`, `snmp_getbulk_requests`, `snmp_responses`, `avg_snmp_response_size`, `ssdp_msearch_packets`, `ssdp_responses`, `portmap_getport_calls`, `portmap_dump_calls`, `netbios_name_queries`, `netbios_dgram_packets`, `ldap_bind_requests`, `ldap_search_requests`, `mssql_sqlbatch_packets`, `mssql_rpc_packets`, `tftp_rrq_packets`, `tftp_wrq_packets` | Deep L7 payload inspection: RPC call types, DNS record types (ANY/TXT), SNMP operations (GetBulk), etc. |
| **DPI ratios** | 6 | `ntp_amplification_factor`, `dns_amplification_factor`, `snmp_amplification_factor`, `query_response_ratio`, `fragmentation_ratio`, `syn_ack_ratio` | Derived from request/response asymmetry (amplification detection) |

#### Sketch Features (14) - OctoSketch + Ring Buffer

These 14 features come from two data structures:

- **OctoSketch** = Count-Min Sketch (conservative update, minimum across rows) for per-IP packet counting. Memory-efficient (640 KB per worker), probabilistic, tracks per-IP rates without storing individual IPs.
- **Top-K / Heavy-hitters** = list of top IPs derived from the sketch counters (IPs exceeding an adaptive threshold).
- **Ring Buffer** = circular buffer (100 windows x 50ms = 5s history) for temporal trend analysis. Not a sketch, but a simple sliding window over PPS values.

| Group | # | Columns | Underlying Structure |
|-------|---|---------|---------------------|
| **Ring Buffer (temporal)** | 5 | `delta_pps_5w`, `delta_pps_10w`, `pps_variance`, `pps_baseline`, `ratio_vs_baseline` | **Ring Buffer** (100 x 50ms): PPS deltas at 250ms/500ms, variance over 20 windows, adaptive baseline, current/baseline ratio |
| **OctoSketch (multi-scale)** | 7 | `top_ip_pps_50ms`, `top_ip_pps_1s`, `top_ip_pps_1min`, `ratio_50ms_1min`, `num_heavy_hitters`, `ip_concentration`, `adaptive_threshold` | **Count-Min Sketch** with 3 time scales (50ms/1s/1min): top attacker PPS, burst ratio, heavy-hitter count, IP concentration |
| **Derived (from sketch)** | 2 | `new_ips_ratio`, `attack_entropy` | Computed from sketch state: new IPs vs known IPs ratio, Shannon entropy of IP distribution |

```
DPI+Sketch Feature Composition (56 total):

  ┌──────────────────────────────────────────────────────────────┐
  │                    DPI Features (42)                         │
  │  ┌─────────────┐ ┌──────────────────────┐ ┌──────────────┐  │
  │  │  DPI base   │ │  DPI protocol (L7)   │ │ DPI ratios   │  │
  │  │   (14)      │ │       (22)           │ │    (6)       │  │
  │  │ counters +  │ │ NTP/DNS/SNMP/SSDP/   │ │ amplificat.  │  │
  │  │ ratios      │ │ PortMap/NetBIOS/...  │ │ factors      │  │
  │  └─────────────┘ └──────────────────────┘ └──────────────┘  │
  ├──────────────────────────────────────────────────────────────┤
  │                  Sketch Features (14)                       │
  │  ┌──────────────────────┐  ┌─────────────────────────────┐  │
  │  │ Ring Buffer (5)      │  │ Count-Min Sketch (9)        │  │
  │  │ Temporal: deltas,    │  │ Multi-scale: top IPs,       │  │
  │  │ variance, baseline   │  │ heavy-hitters, entropy,     │  │
  │  │ (sliding window)     │  │ concentration (probabilist.)│  │
  │  └──────────────────────┘  └─────────────────────────────┘  │
  └──────────────────────────────────────────────────────────────┘
```

### 2.2 Sketch-ADV Pipeline (64 features)

This pipeline uses **only sketch-based features** (no DPI). It extends the 14 global sketch features with **per-protocol OctoSketch instances** (12 separate sketches, one per attack protocol). Features are extracted from compact binary `.bin` files (528 bytes/record).

#### Global Sketch Features (14) - Same as DPI+Sketch

Identical Ring Buffer (5) + Count-Min Sketch multi-scale (9) features as described above.

#### Per-Protocol Sketch Features (48) - 12 Per-Protocol Count-Min Sketches

The same OctoSketch (Count-Min Sketch with conservative update) is **replicated for each protocol/port**. Each of the 12 protocols has its own dedicated Count-Min Sketch instance that only tracks traffic matching that protocol. From each per-protocol sketch, 4 metrics are extracted:

| Metric | Description | Underlying Structure |
|--------|-------------|---------------------|
| `pps_<proto>` | Packets per second for this protocol | Per-protocol Count-Min Sketch: `total_updates / window_seconds` |
| `heavy_hitters_<proto>` | Number of IPs exceeding threshold for this protocol | Per-protocol Count-Min Sketch: count of IPs with estimated count > threshold |
| `ip_concentration_<proto>` | Top-1 IP share of this protocol's traffic | Per-protocol Count-Min Sketch: `top1_count / total_updates` |
| `ratio_vs_total_<proto>` | This protocol's PPS vs global PPS | Cross-sketch ratio: `proto_sketch.pps / global_sketch.pps` |

**12 Protocols monitored:** DNS (port 53), NTP (port 123), SNMP (port 161), SSDP (port 1900), PortMap (port 111), NetBIOS (port 137/138), LDAP (port 389), MSSQL (port 1433), TFTP (port 69), SYN (TCP SYN flags), HTTP (port 80/443), UDP-Other (remaining UDP)

#### Packet Size Features (2)

| Feature | Description |
|---------|-------------|
| `avg_packet_size` | Mean packet size in bytes (from global sketch) |
| `packet_size_variance` | Variance of packet sizes (from global sketch) |

```
Sketch-ADV Feature Composition (64 total):

  ┌──────────────────────────────────────────────────────────────┐
  │               Global Sketch Features (14)                   │
  │  ┌──────────────────────┐  ┌─────────────────────────────┐  │
  │  │ Ring Buffer (5)      │  │ Count-Min Sketch (9)        │  │
  │  │ Temporal: deltas,    │  │ Multi-scale: top IPs,       │  │
  │  │ variance, baseline   │  │ heavy-hitters, entropy      │  │
  │  └──────────────────────┘  └─────────────────────────────┘  │
  ├──────────────────────────────────────────────────────────────┤
  │    Per-Protocol Count-Min Sketches (48 = 4 metrics x 12)    │
  │    Each protocol has its own CMS instance                    │
  │                                                              │
  │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐          │
  │  │ DNS │ │ NTP │ │SNMP │ │SSDP │ │Port │ │NetB │          │
  │  │ CMS │ │ CMS │ │ CMS │ │ CMS │ │ CMS │ │ CMS │          │
  │  │(4f) │ │(4f) │ │(4f) │ │(4f) │ │(4f) │ │(4f) │          │
  │  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘          │
  │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐          │
  │  │LDAP │ │MSSQL│ │TFTP │ │ SYN │ │HTTP │ │UDP- │          │
  │  │ CMS │ │ CMS │ │ CMS │ │ CMS │ │ CMS │ │Oth. │          │
  │  │(4f) │ │(4f) │ │(4f) │ │(4f) │ │(4f) │ │(4f) │          │
  │  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘          │
  ├──────────────────────────────────────────────────────────────┤
  │              Packet Size Features (2)                       │
  │  ┌──────────────────┐  ┌───────────────────────┐            │
  │  │ avg_packet_size  │  │ packet_size_variance  │            │
  │  └──────────────────┘  └───────────────────────┘            │
  └──────────────────────────────────────────────────────────────┘

  CMS = Count-Min Sketch (conservative update, min across rows)
```

### 2.3 Feature-to-Structure Mapping

The table below explicitly maps each feature column to its underlying data structure:

| Feature Column | DPI+Sketch | Sketch-ADV | Underlying Structure |
|---|:---:|:---:|---|
| `total_packets`, `total_bytes`, `tcp_packets`, `udp_packets`, `icmp_packets` | x | - | DPI: L3/L4 header counters |
| `syn_packets`, `http_requests`, `dns_queries` | x | - | DPI: L4/L7 protocol detection |
| `baseline_packets`, `attack_packets` | x | - | DPI: subnet-based classification |
| `udp_tcp_ratio`, `syn_total_ratio`, `baseline_attack_ratio`, `bytes_per_packet` | x | - | Derived ratios from DPI counters |
| `ntp_monlist_queries` ... `tftp_wrq_packets` (22 cols) | x | - | DPI: deep L7 payload parsing |
| `ntp_amplification_factor` ... `syn_ack_ratio` (6 cols) | x | - | Derived ratios from DPI protocol counters |
| `delta_pps_5w`, `delta_pps_10w`, `pps_variance`, `pps_baseline`, `ratio_vs_baseline` | x | x | **Ring Buffer** (100 x 50ms sliding window) |
| `top_ip_pps_50ms`, `top_ip_pps_1s`, `top_ip_pps_1min`, `ratio_50ms_1min` | x | x | **Count-Min Sketch** (3 time scales) |
| `num_heavy_hitters`, `ip_concentration`, `adaptive_threshold` | x | x | **Count-Min Sketch** (top-K extraction) |
| `new_ips_ratio`, `attack_entropy` | x | x | **Derived** from Count-Min Sketch state |
| `pps_<proto>` (12 cols) | - | x | **Per-protocol Count-Min Sketch** (updates/window) |
| `heavy_hitters_<proto>` (12 cols) | - | x | **Per-protocol Count-Min Sketch** (top-K per proto) |
| `ip_concentration_<proto>` (12 cols) | - | x | **Per-protocol Count-Min Sketch** (top1/total) |
| `ratio_vs_total_<proto>` (12 cols) | - | x | **Cross-sketch ratio** (proto CMS / global CMS) |
| `avg_packet_size`, `packet_size_variance` | - | x | **Global accumulator** (running mean + variance) |

### 2.4 Key Differences Between Feature Sets

| Aspect | DPI+Sketch (56) | Sketch-ADV (64) |
|--------|-----------------|-----------------|
| **DPI (L7 payload parsing)** | 42 features from deep packet inspection | None - no payload access needed |
| **Global sketch** | 14 (Ring Buffer + OctoSketch) | 14 (identical) |
| **Per-protocol sketches** | None | 48 (12 OctoSketch instances x 4 metrics) |
| **Packet size** | Implicit in `bytes_per_packet` | Explicit `avg_packet_size` + `packet_size_variance` |
| **Total memory per worker** | 640 KB (1 OctoSketch) | ~8.3 MB (1 global + 12 per-protocol OctoSketches) |
| **Data format** | Text `.log` (regex parsing) | Binary `.bin` (528 bytes/record, struct.unpack) |
| **Encryption-resistant** | No - DPI requires plaintext payloads | Yes - only uses packet headers (IP/port/flags) |
| **Processing overhead** | Higher (L7 parsing per packet) | Lower (only L3/L4 header + sketch updates) |

---

## 3. Experimental Results

### 3.1 Dataset Summary

| | DPI+Sketch | Sketch-ADV |
|---|---|---|
| Train samples | 4,457 | 1,892 |
| Validation samples | 2,183 | 946 |
| Test samples | 2,202 | 946 |
| Features | 56 | 64 |
| Classes | 14 | 14 |
| Data source | `.log` (text) | `.bin` (binary) |
| Detector | detector_system (original) | detector_system (--sketch-adv) |

### 3.2 LightGBM Comparison (Primary Model)

| Metric | DPI+Sketch (56f) | Sketch-ADV (64f) | Difference |
|--------|:-:|:-:|:-:|
| **Val Accuracy** | **99.37%** | 96.83% | -2.54% |
| **Test Accuracy** | **99.31%** | 96.72% | -2.59% |
| **Weighted F1** | **0.999** | 0.969 | -0.030 |
| **Macro F1** | **0.990** | 0.965 | -0.025 |
| Best iteration | 65 rounds | 120 rounds | +55 rounds |

#### Per-Class Test F1 Comparison (LightGBM)

| Class | DPI+Sketch F1 | Sketch-ADV F1 | Delta |
|-------|:---:|:---:|:---:|
| benign | **1.000** | 0.819 | -0.181 |
| dns | **1.000** | 0.974 | -0.026 |
| ldap | **1.000** | 0.991 | -0.009 |
| mixed | **1.000** | 1.000 | 0.000 |
| mssql | **1.000** | 0.966 | -0.034 |
| netbios | **1.000** | 0.983 | -0.017 |
| ntp | **0.996** | 0.974 | -0.022 |
| portmap | **1.000** | 0.974 | -0.026 |
| snmp | **0.997** | 0.974 | -0.023 |
| ssdp | **1.000** | 0.983 | -0.017 |
| syn | **0.997** | 0.974 | -0.023 |
| tftp | **1.000** | 0.983 | -0.017 |
| udp | **1.000** | 0.957 | -0.043 |
| webddos | 0.940 | **0.956** | +0.016 |

#### Feature Importance Comparison (LightGBM)

```
DPI+Sketch - Top 10:                    Sketch-ADV - Top 15:
─────────────────────                   ──────────────────────
1. syn_total_ratio      24792           1. attack_entropy        13158
2. ntp_monlist_queries   19229          2. pps_netbios            5254
3. bytes_per_packet     17892           3. pps_portmap            5197
4. attack_packets       15579           4. pps_mssql              4989
5. dns_any_queries      15315           5. pps_ssdp               4872
6. snmp_getbulk_requests 14798          6. ratio_vs_total_snmp    4746
7. netbios_name_queries 14514           7. pps_ldap               4470
8. portmap_getport_calls 13703          8. delta_pps_5w           4399
9. ldap_search_requests 13447           9. pps_tftp               4021
10. tftp_rrq_packets    12750          10. pps_dns                3856
                                       11. pps_http               3337
  DPI features dominate: 9 of           Per-protocol sketch PPS
  top 10 are L7 DPI counters            features dominate top 15
```

### 3.3 Full Model Comparison

#### DPI+Sketch (56 features) - All Models

| Model | Val Acc | Test Acc |
|-------|:---:|:---:|
| **LightGBM** | **99.37%** | **99.31%** |
| XGBoost | 94.27% | **99.86%** |
| HistGradientBoosting | 95.24% | 99.64% |
| LSTM (seq_len=12) | - | 98.56% |
| RandomForest | 98.63% | 98.00% |
| SGDClassifier | 96.52% | 97.87% |
| MLP | 97.07% | 97.77% |
| KNN | 95.37% | 96.46% |

#### Sketch-ADV (64 features) - All Models

| Model | Val Acc | Test Acc |
|-------|:---:|:---:|
| **LightGBM** | **96.83%** | **96.72%** |
| SGDClassifier | 96.62% | 96.83% |
| MLP | 96.72% | 96.72% |
| KNN | 96.72% | 96.72% |
| RandomForest | 96.83% | 96.62% |
| HistGradientBoosting | 96.83% | 96.62% |
| XGBoost | 96.62% | 96.62% |
| LSTM (seq_len=12) | 93.94% | 93.94% |

#### Side-by-Side Best Test Accuracy

```
                    DPI+Sketch (56f)    Sketch-ADV (64f)
                    ────────────────    ────────────────
  XGBoost           ██████████ 99.36%
  HistGBM           ██████████ 99.34%
  LightGBM          █████████▉ 99.31%
  LSTM (dpi)        █████████▊ 98.56%
  RandomForest      █████████▊ 98.00%
  SGD               █████████▋ 97.87%
  MLP               █████████▋ 97.77%
  LightGBM (SA)                         █████████▋ 96.83%
  SGD (SA)                              █████████▋ 96.83%
  MLP (SA)                              █████████▋ 96.72%
  KNN (SA)                              █████████▋ 96.72%
  RF (SA)                               █████████▋ 96.62%
  HistGBM (SA)                          █████████▋ 96.62%
  XGBoost (SA)                          █████████▋ 96.62%
  KNN               █████████▋ 96.46%
  LSTM (SA)                             █████████▍ 95.94%
```

### 3.4 Critical Issue: Benign Classification in Sketch-ADV

The most notable weakness of the Sketch-ADV pipeline is the **benign class precision = 0.69** across all models. The confusion matrix reveals that attack samples are systematically misclassified as benign:

```
Sketch-ADV Confusion Matrix (LightGBM) - Benign column:

  True class → Misclassified as benign
  ─────────────────────────────────────
  dns          2 samples → benign
  ldap         1 sample  → benign
  mssql        2 samples → benign
  netbios      1 sample  → benign
  ntp          2 samples → benign
  portmap      1 sample  → benign
  snmp         3 samples → benign
  ssdp         1 sample  → benign
  syn          3 samples → benign
  tftp         2 samples → benign
  udp          4 samples → benign
  webddos      4 samples → benign
  ─────────────────────────────────────
  Total:      26 attack samples misclassified as benign

  Impact: In a real DDoS detector, these are MISSED ATTACKS (false negatives)
```

This issue does **not** exist in the DPI+Sketch pipeline, where benign precision = 1.00 and recall = 1.00.

---

## 4. Advantages of Sketch-ADV Despite Lower Accuracy

Although the DPI+Sketch pipeline achieves higher accuracy (99.31% vs 96.72%), the Sketch-ADV approach has significant **architectural advantages** that make it the preferred direction for future development:

### 4.1 Encryption Resistance

```
DPI+Sketch:                          Sketch-ADV:
┌─────────────┐                     ┌─────────────┐
│  Encrypted  │ ──DPI──▶ FAILS     │  Encrypted  │ ──Headers──▶ WORKS
│   Traffic   │   (can't read       │   Traffic   │   (only needs
│  (TLS/QUIC) │    payloads)        │  (TLS/QUIC) │    IP/port/flags)
└─────────────┘                     └─────────────┘
```

- **DPI requires plaintext payloads** to identify DNS query types, NTP monlist requests, SNMP GetBulk, HTTP methods, etc. With encrypted traffic (TLS 1.3, QUIC, encrypted DNS), 42 DPI features become zeros.
- **Sketch-ADV only needs packet headers** (IP addresses, ports, TCP flags, packet sizes). These remain visible even with full payload encryption.

### 4.2 Processing Efficiency

| Aspect | DPI+Sketch | Sketch-ADV |
|--------|------------|------------|
| Per-packet work | L3 + L4 + L7 parsing | L3 + L4 headers only |
| Payload access | Required (copy + parse) | Not required |
| Cycles per packet | Higher (string matching, protocol dissection) | Lower (hash + increment) |
| Cache friendliness | Poor (variable-length payload access) | Good (fixed-size sketch updates) |

### 4.3 Binary Output Format

| Aspect | `.log` (DPI+Sketch) | `.bin` (Sketch-ADV) |
|--------|---------------------|---------------------|
| Record size | Variable (text) | Fixed 528 bytes |
| Parsing | Regex (slow, fragile) | struct.unpack (fast, exact) |
| Storage | ~10x larger | Compact binary |
| Reliability | Regex can break on format changes | Binary struct is exact |

### 4.4 Scalability to Higher Line Rates

At 100 Gbps (the target throughput), DPI becomes the bottleneck. Sketch-ADV's header-only approach scales better because:
- No payload copies needed (zero-copy header access)
- Sketch updates are O(1) per packet (hash + increment)
- 12 per-protocol sketch updates add ~12 hash computations, still faster than L7 parsing

### 4.5 Model Homogeneity

All Sketch-ADV models achieve nearly identical accuracy (~96.6-96.8%), meaning the **feature set is robust** regardless of model choice. This is beneficial for deployment where model complexity matters (e.g., deploying a simpler KNN or SGD achieves the same accuracy as a complex ensemble).

---

## 5. The detector_system2 Approach: Measure-Only Mode

### 5.1 Motivation

The original `detector_system` combines **detection** (threshold-based alerting) with **measurement** (feature logging). This coupling creates problems for ML training:

1. **Alert bias**: Detection thresholds influence log output (some sections only appear when alerts fire)
2. **Missing data**: Features tied to alert logic may be absent during benign periods
3. **Circular dependency**: Training an ML model on data produced by a threshold-based detector

### 5.2 Architecture

`detector_system2` is a **measure-only** variant that removes all threshold-based detection logic while preserving the complete feature extraction pipeline:

```
detector_system (original):              detector_system2:
┌─────────────────────────┐             ┌─────────────────────────┐
│  Packet Processing      │             │  Packet Processing      │
│  DPI + OctoSketch       │             │  DPI + OctoSketch       │
│         │                │             │         │                │
│         ▼                │             │         ▼                │
│  ┌─────────────────┐    │             │  ┌─────────────────┐    │
│  │ Threshold Check │    │             │  │  NO thresholds  │    │
│  │  Attack alerts  │    │             │  │  Pure logging   │    │
│  │  Heavy-hitter   │    │             │  │  Every window   │    │
│  │  notifications  │    │             │  │                 │    │
│  └────────┬────────┘    │             │  └────────┬────────┘    │
│           │              │             │           │              │
│           ▼              │             │           ▼              │
│     .log with alerts     │             │    .log (all features)  │
│     (biased output)      │             │    (unbiased output)    │
└─────────────────────────┘             └─────────────────────────┘
```

### 5.3 Key Differences

| Aspect | detector_system | detector_system2 |
|--------|----------------|-----------------|
| Mode | Detection + Alerting | Measure-only |
| Thresholds | Active (adaptive) | Removed |
| Alert sections in log | Yes (when triggered) | No (never) |
| Feature logging | Every window | Every window |
| Output bias | Alert-dependent | Unbiased |
| Use case | Production deployment | ML training data collection |
| `--log-output <path>` | Not available | Custom log output path |

### 5.4 Structured Experiment Protocol

`detector_system2` enables controlled 200-second experiments with known ground truth:

```
         50s              100s              50s
    ┌──────────┐    ┌──────────────┐    ┌──────────┐
    │  BENIGN  │    │   ATTACK     │    │  BENIGN  │
    │  traffic │    │   traffic    │    │  traffic │
    │  only    │    │  (specific   │    │  only    │
    │          │    │   type)      │    │          │
    └──────────┘    └──────────────┘    └──────────┘
    t=0        t=50s               t=150s        t=200s

    Labels:  benign    │    attack_type     │    benign
```

This temporal structure allows **automatic labeling** based on timestamps: the feature extractor assigns labels according to when each measurement window falls within the 200s experiment window. This eliminates manual labeling and ensures precise ground truth.

### 5.5 Training Pipeline

```
  detector_system2                    ml_system2
  ┌─────────────┐                   ┌──────────────────────┐
  │ 200s runs   │                   │                      │
  │ per attack  │──.log──▶          │  log_pipeline/       │
  │ type        │                   │   feature_extractor  │
  │             │                   │        │             │
  │ 4 runs each │                   │        ▼             │
  │ (run1..run4)│                   │  datasets/processed/ │
  └─────────────┘                   │   *.csv (56 features)│
                                    │        │             │
                                    │        ▼             │
                                    │  training/           │
                                    │   prepare_dataset    │
                                    │   train_model        │
                                    │   evaluate_model     │
                                    │   model_compare      │
                                    └──────────────────────┘

  52 runs total:
    12 attack types x 4 runs = 48
    mixed           x 4 runs =  4
                              ────
                                52
```

---

## 6. Conclusions

1. **DPI+Sketch (56f) achieves superior accuracy** (99.31% vs 96.72%) thanks to deep L7 packet inspection features that directly identify attack-specific protocol signatures (NTP monlist, DNS ANY, SNMP GetBulk, etc.).

2. **Sketch-ADV (64f) is the future-proof approach** for encrypted traffic environments. Its header-only analysis achieves 96.7% accuracy without any payload inspection, making it resilient to TLS/QUIC encryption.

3. **The benign precision problem** (0.69 in Sketch-ADV) is the main issue to address. Attack traffic leaks into the benign class because without DPI, some attacks appear similar to benign traffic at the sketch level. This is a critical false-negative risk for production deployment.

4. **Model choice is irrelevant for Sketch-ADV** (all models ~96.7%), but matters for DPI+Sketch (XGBoost reaches 99.86% while KNN only 96.46%). This suggests DPI features have richer discriminative patterns that complex models can exploit.

5. **detector_system2 with structured 200s experiments** (next phase) will provide cleaner training data with automatic temporal labeling, potentially improving both pipelines by eliminating the bias introduced by threshold-based alert logging.

6. **The per-protocol `pps_*` sketch features** in Sketch-ADV are the most important discriminators (9 of top 15), validating the architectural decision to add 12 per-protocol OctoSketch instances.
