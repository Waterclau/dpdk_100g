# ML Enhancement Preparation Report
**Date**: December 11, 2025
**Project**: MIRA - High-Speed DDoS Detection with DPDK + Machine Learning

---

## Executive Summary

We are preparing a DPDK-based DDoS detection system enhanced with embedded machine learning. The goal is to combine hardware-accelerated packet processing with intelligent classification to achieve significantly faster detection than pure ML approaches while maintaining high accuracy.

**Current Status**: ML code prepared and ready for integration testing. Infrastructure code written but awaiting CloudLab node repairs to begin execution and validation. This document outlines our preparation work and implementation plan.

---

## System Architecture

Our testbed consists of three CloudLab nodes working together:

```
┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│    Controller       │      │         TG          │      │       Monitor       │
│  (Benign Traffic)   │      │  (Attack Traffic)   │      │     (Detector)      │
│                     │      │                     │      │                     │
│  ┌───────────────┐  │      │  ┌───────────────┐  │      │  ┌───────────────┐  │
│  │ DPDK Sender   │  │      │  │ DPDK Sender   │  │      │  │ DPDK Workers  │  │
│  │ Benign v2.0   │──┼──────┼──┼─Attack v2.0   │──┼──────┼─→│ (14 threads)  │  │
│  │ (4 phases)    │  │      │  │ (5 types)     │  │      │  │               │  │
│  └───────────────┘  │      │  └───────────────┘  │      │  └───────┬───────┘  │
│                     │      │                     │      │          │          │
│  - HTTP traffic     │      │  - SYN Flood        │      │  ┌───────▼───────┐  │
│  - DNS queries      │      │  - UDP Flood        │      │  │  OctoSketch   │  │
│  - SSH sessions     │      │  - HTTP Flood       │      │  │ (flow track)  │  │
│  - UDP services     │      │  - DNS Amplif.      │      │  └───────┬───────┘  │
│                     │      │  - ICMP Flood       │      │          │          │
│                     │      │  - Mixed Attack     │      │  ┌───────▼───────┐  │
│                     │      │                     │      │  │  Coordinator  │  │
│                     │      │                     │      │  │  + LightGBM   │  │
│                     │      │                     │      │  └───────┬───────┘  │
│                     │      │                     │      │          │          │
│                     │      │                     │      │  ┌───────▼───────┐  │
│                     │      │                     │      │  │ Logs/Alerts   │  │
│                     │      │                     │      │  └───────────────┘  │
└─────────────────────┘      └─────────────────────┘      └─────────────────────┘
   ~7 Gbps Benign            ~10 Gbps Attack              Target: <50ms detect
                                                          Total: ~17 Gbps peak
```

**Traffic Flow**:
1. **Controller** generates and sends realistic benign traffic (temporal phases)
2. **TG (Traffic Generator)** generates and sends various attack types
3. **Monitor** receives all traffic, processes with DPDK, detects attacks using hybrid threshold + ML

---

## Preparation Work Completed

The following components have been developed and are ready for testing once CloudLab infrastructure is available:

### 1. ML-Enhanced Traffic Generators (v2.0)

#### Benign Traffic Generator
- **File**: `generate_benign_traffic_v2.py`
- **Purpose**: Generate realistic benign network traffic for ML training
- **Planned Features**:
  - 4 temporal phases with realistic protocol distributions
  - Variable packet sizes (±20-50% jitter)
  - Traffic intensity variations (0.5× to 1.3×)
  - Timestamp compression support (`--speedup N`)
- **Expected Output**: Standard PCAP + compressed PCAP for 50× faster replay

**Temporal Phase Structure**:
```
Phase 1 (0-75s)    Phase 2 (75-150s)  Phase 3 (150-225s)  Phase 4 (225-300s)
HTTP Peak          DNS Burst          SSH Stable          UDP Light
├─ HTTP: 60%       ├─ HTTP: 40%       ├─ HTTP: 30%        ├─ HTTP: 30%
├─ DNS:  20%       ├─ DNS:  40%       ├─ DNS:  20%        ├─ DNS:  15%
├─ SSH:  10%       ├─ SSH:  10%       ├─ SSH:  30%        ├─ SSH:  20%
└─ UDP:  10%       └─ UDP:  10%       └─ UDP:  20%        └─ UDP:  35%
```

#### Attack Traffic Generator
- **File**: `generate_mirai_attacks_v2.py`
- **Purpose**: Generate diverse attack traffic patterns for ML training
- **Planned Attack Types**: SYN Flood, UDP Flood, HTTP Flood, DNS Amplification, Mixed Attack
- **Designed Features**:
  - 4 escalating phases (Warm-up → Peak → Mixed → Spikes)
  - Real Mirai botnet signatures
  - Intensity levels 1.0×-5.0×
  - CloudLab network compliance (10.10.x.x IPs)

**Attack Phase Escalation**:
```
Phase 1 (0-25%)    Phase 2 (25-50%)   Phase 3 (50-75%)   Phase 4 (75-100%)
Warm-up Scan       SYN Peak           Mixed Waves         Random Spikes
├─ SYN: 30%        ├─ SYN: 60%        ├─ SYN: 40%         ├─ All: Random
├─ UDP: 20%        ├─ UDP: 20%        ├─ UDP: 40%         ├─ Bursts
└─ Probe: 50%      └─ HTTP: 20%       └─ HTTP: 20%        └─ Variability
```

---

### 2. DPDK High-Speed Senders (v2.0)

- **Files**: `dpdk_pcap_sender_v2.c` (benign/attack versions)
- **Purpose**: Replay generated PCAP files at high speed for detector testing
- **Planned Modes**:
  - Standard replay: Target ~12 Gbps sustained
  - Temporal replay (`--pcap-timed`): Respects PCAP timestamps
  - Jitter mode (`--jitter X`): ±X% timing variability
  - Adaptive mode (`--adaptive`): Continuous 12 Gbps indefinitely
- **Expected Performance**: 10-15 Gbps sustained with low packet loss

---

### 3. ML-Integrated Detector

#### Core Implementation
- **File**: `detector_system_ml/detectorML.c`
- **Purpose**: Detect DDoS attacks using hybrid threshold + ML approach
- **Architecture**: 14 worker threads + 1 coordinator + 1 main
- **Target Goals**:
  - Detection latency: Sub-50ms (compared to MULTI-LF: 866ms)
  - Throughput: 10+ Gbps sustained
  - Low packet loss (<1%)
  - Accurate multi-attack classification

#### OctoSketch Memory Structure
```
Per-Worker Sketch (384 KB):
┌──────────────────────────────────────┐
│ Hash Row 0: [4096 counters] (32 KB) │
│ Hash Row 1: [4096 counters] (32 KB) │
│ Hash Row 2: [4096 counters] (32 KB) │
│ Hash Row 3: [4096 counters] (32 KB) │
│ Hash Row 4: [4096 counters] (32 KB) │
│ Hash Row 5: [4096 counters] (32 KB) │
│ Hash Row 6: [4096 counters] (32 KB) │
│ Hash Row 7: [4096 counters] (32 KB) │
└──────────────────────────────────────┘
Total: 14 workers × 384 KB = 5.3 MB
```

#### ML Integration (5 Modifications)

**Modification 1**: Header include
```c
#include "ml_inference.h"
```

**Modification 2**: Global model variable
```c
static ml_model_handle g_ml_model = NULL;
#define ML_CONFIDENCE_THRESHOLD 0.75f
```

**Modification 3**: ML prediction in `detect_attacks()`
- Extract 13 features from OctoSketch statistics
- Call LightGBM prediction (~1-3ms)
- Apply hybrid decision logic

**Modification 4**: Model initialization
```c
g_ml_model = ml_init("./lightgbm_model.txt");
```

**Modification 5**: Cleanup
```c
ml_cleanup(g_ml_model);
```

---

### 4. Machine Learning Model

#### Why LightGBM?

We chose **LightGBM (Light Gradient Boosting Machine)** for our ML classifier due to several key advantages:

1. **Fast Inference**: 1-3ms per prediction, suitable for real-time detection
2. **C API Support**: Can be embedded directly into DPDK C code without external processes
3. **High Accuracy on Tabular Data**: Gradient boosting excels at learning patterns from structured features
4. **Small Model Size**: Typical models are 2-5 MB, easily deployable
5. **Interpretability**: Tree-based models allow understanding which features drive decisions
6. **Low Memory Footprint**: Efficient for production deployment

**Model Architecture**:
- **Type**: Multi-class classifier (gradient boosting decision trees)
- **Input**: 13 statistical features extracted from network traffic
- **Output**: 5-class probabilities (benign + 4 attack types)
- **Training**: Supervised learning on labeled traffic samples
- **Deployment**: Embedded C library (no Python runtime needed)

**How it integrates**:
```
Flow Traffic → DPDK Workers → OctoSketch Stats → Extract 13 Features
                                                          ↓
                                                   LightGBM Model
                                                          ↓
                                              [0.05, 0.02, 0.89, 0.01, 0.03]
                                                          ↓
                                              Class 2: SYN Flood (89% conf)
```

The model runs locally within the detector process, adding minimal overhead (~3-5ms) to the baseline detection latency.

---

### 5. ML Feature Engineering

#### 13-Feature Vector
```
Raw Counters (8 features):
├─ total_packets          # Total packet count
├─ total_bytes            # Total byte count
├─ udp_packets            # UDP protocol count
├─ tcp_packets            # TCP protocol count
├─ icmp_packets           # ICMP protocol count
├─ syn_packets            # SYN flag count
├─ http_requests          # HTTP detection count
├─ baseline_packets       # Normal source traffic
└─ attack_packets         # Attack source traffic

Derived Features (5 features):
├─ udp_tcp_ratio          # UDP/TCP ratio
├─ syn_total_ratio        # SYN/Total ratio
├─ baseline_attack_ratio  # Baseline/Attack ratio
├─ bytes_per_packet       # Average packet size
└─ (normalized values)
```

#### 5-Class Classification
```
0: benign        - Normal traffic
1: udp_flood     - UDP flood attack
2: syn_flood     - SYN flood attack
3: icmp_flood    - ICMP flood attack
4: mixed_attack  - Multi-vector attack
```

---

### 6. Hybrid Detection Logic

The system combines threshold-based detection with ML predictions:

```
┌─────────────────────────────────────────────────────────┐
│          Detection Window (50ms)                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌───────────────┐       ┌───────────────┐            │
│  │  OctoSketch   │──────→│   Threshold   │            │
│  │   Statistics  │       │   Detection   │            │
│  └───────────────┘       └───────┬───────┘            │
│          │                       │                     │
│          │                       ↓                     │
│          │              ┌─────────────────┐            │
│          └─────────────→│  ML Inference   │            │
│                         │   (LightGBM)    │            │
│                         └────────┬────────┘            │
│                                  │                     │
│                                  ↓                     │
│                         ┌─────────────────┐            │
│                         │ Hybrid Decision │            │
│                         └────────┬────────┘            │
│                                  │                     │
└──────────────────────────────────┼─────────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ↓              ↓              ↓
              CRITICAL          HIGH         ANOMALY
           (Both agree)    (Threshold)     (ML only)
           Confidence>75%   ML disagrees   Confidence>75%
```

**Decision Matrix**:

| Threshold | ML | Confidence | Result | Meaning |
|-----------|-------|------------|---------|---------|
| ✓ | ✓ | >75% | **CRITICAL** | Both systems agree - highest confidence |
| ✓ | ✗ | - | **HIGH** | Threshold detects - possible false positive |
| ✗ | ✓ | >75% | **ANOMALY** | ML detects - subtle attack pattern |
| ✗ | ✗ | - | None | No attack detected |

---

### 7. Training Pipeline (Ready)

#### Phase 1: Data Collection
```bash
# Run detector with different traffic types
./mira_ddos_detector    # Collect baseline logs
# Then run with: benign, udp_flood, syn_flood, http_flood, dns_flood, mixed
```

#### Phase 2: Feature Extraction
```bash
cd ml_system/01_data_collection
python3 feature_extractor.py --logs ../../results/*.log --output features.csv
```

#### Phase 3: Model Training
```bash
cd ml_system/02_training
python3 export_lightgbm_model.py \
    --train ../datasets/splits/train.csv \
    --output ../../detector_system_ml/lightgbm_model.txt
# Target: 95%+ accuracy, <2% false positives
```

#### Phase 4: Compilation & Execution
```bash
cd detector_system_ml
make clean && make
sudo ./detectorML -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0
```

---

## Target Performance vs State-of-the-Art

### MIRA Goals vs MULTI-LF (2025)

| Metric | MULTI-LF (2025) | MIRA Target | Expected Improvement |
|--------|-----------------|-------------|---------------------|
| **Detection Latency** | 866 ms | <50 ms | **~17× faster** |
| **Throughput** | 66K pps | 10M pps | **~150× higher** |
| **Detection Window** | 1000 ms | 50 ms | **20× finer granularity** |
| **Memory (Flow Tracking)** | 3.63 MB | ~5 MB | O(1) vs O(flows) |
| **Deployment** | Docker-NS3 | Real NICs + DPDK | Bare-metal hardware |
| **Multi-attack Detection** | Sequential | Simultaneous | Parallel classification |

**MULTI-LF** (Rustam et al., 2025): Pure ML approach with two-tier models (M1 lightweight + M2 high-accuracy), continuous learning, 866ms detection latency.

**MIRA** (This project): Planned hybrid approach combining DPDK kernel bypass, OctoSketch memory-efficient tracking, and embedded LightGBM for sub-50ms detection while maintaining high accuracy.

---

## Implementation Status

### Code Preparation Complete ✓
- [x] ML-enhanced traffic generators v2.0 code written (temporal phases)
- [x] DPDK senders v2.0 code written (adaptive replay, jitter, temporal modes)
- [x] Detector with OctoSketch implementation code written
- [x] ML integration code written (550+ lines: detectorML.c + ml_inference.c/h)
- [x] Hybrid detection logic designed (CRITICAL/HIGH/ANOMALY)
- [x] 13-feature vector design
- [x] 5-class classification design
- [x] Training pipeline framework scripts written
- [x] Documentation (README, HOW_TO_ADD_ML, STATUS, stepsML)

### Blocked - Awaiting Infrastructure ⚠️
**Status**: CloudLab node is currently down, waiting for repairs before we can proceed with testing.

Once node is available:
- [ ] Generate traffic PCAPs (benign + attack types)
- [ ] Test DPDK senders at high speed
- [ ] Run detector and collect logs for training data
- [ ] Train ML model with collected data
- [ ] Compile ML-enhanced detector
- [ ] Execute and validate performance
- [ ] Compare ML vs threshold-only approaches

### Future Work ◯
- [ ] Performance validation and benchmarking
- [ ] False positive/negative analysis
- [ ] Multi-attack classification accuracy testing
- [ ] Long-duration stability testing
- [ ] Optimization and tuning

---

## Key Technical Decisions

### Why Hybrid (Threshold + ML)?
1. **Fast baseline**: Thresholds provide 30ms detection without ML overhead
2. **Intelligent enhancement**: ML reduces false positives and detects subtle patterns
3. **Explainability**: Threshold alerts are deterministic and understandable
4. **Graceful degradation**: System works without ML model if training fails

### Why LightGBM?
1. **C API availability**: Direct embedding without HTTP/sockets
2. **Fast inference**: 1-3ms per prediction
3. **Small model size**: <5MB for typical models
4. **High accuracy**: Gradient boosting for tabular data
5. **Low latency overhead**: +9% on 34ms baseline = 37ms total

### Why OctoSketch?
1. **O(1) memory**: 384 KB per worker regardless of flow count
2. **Lock-free updates**: Per-worker sketches, no contention
3. **Conservative estimates**: MIN across 8 rows avoids over-counting
4. **Fast queries**: 8 memory reads + MIN operation (~10 CPU cycles)
5. **Mergeable**: Aggregate worker sketches in <1ms

### Why 50ms Detection Windows?
1. **Balances latency vs accuracy**: Enough packets for statistics, fast enough for response
2. **20× finer than MULTI-LF**: 1000ms → 50ms windows
3. **Realistic**: Network admins can react within seconds, not minutes
4. **Validated**: 2,409 detections per attack type over 3.3 hours

---

## Code Organization

```
mira/
├── benign_generator/
│   └── generate_benign_traffic_v2.py      (✓ 1500+ lines, 4 phases)
├── attack_generator/
│   └── generate_mirai_attacks_v2.py       (✓ 1200+ lines, 5 attack types)
├── benign_sender/
│   └── dpdk_pcap_sender_v2.c              (✓ Temporal replay, adaptive mode)
├── attack_sender/
│   └── dpdk_pcap_sender_v2.c              (✓ Same as benign, attack traffic)
├── detector_system/
│   ├── mira_ddos_detector.c               (✓ Threshold-only, 34.33ms validated)
│   ├── octosketch.h                       (✓ 8×4096 counter matrix)
│   └── Makefile                           (✓ DPDK build)
├── detector_system_ml/                    (✓ ML-enhanced version)
│   ├── detectorML.c                       (✓ Detector + 5 ML modifications)
│   ├── ml_inference.c                     (✓ LightGBM C API, 150 lines)
│   ├── ml_inference.h                     (✓ API header, 13 features, 5 classes)
│   ├── octosketch.h                       (✓ Copied from detector_system)
│   ├── Makefile                           (✓ DPDK + LightGBM build)
│   ├── README.md                          (✓ System documentation)
│   ├── HOW_TO_ADD_ML.md                  (✓ Integration guide)
│   ├── STATUS.md                          (✓ Phase 4 complete)
│   └── VERIFICATION_CHECKLIST.md         (✓ Validation steps)
├── ml_system/
│   ├── 01_data_collection/
│   │   └── feature_extractor.py           (✓ Log parser, CSV generator)
│   └── 02_training/
│       ├── export_lightgbm_model.py       (✓ Model training script)
│       └── evaluate_model.py              (✓ Model evaluation script)
├── analysis/
│   └── analyze_mira_octosketch.py         (✓ Results visualization)
├── results/
│   └── (log files, experiment results)
├── README.md                              (✓ MIRA overview)
├── progress.md                            (✓ Detailed experiment progress)
└── stepsML.md                             (✓ Complete ML workflow, 1500+ lines)
```

---

## Expected Performance Metrics

### Target System Goals

**Detection Performance**:
- Detection latency: <50ms per window
- Throughput: 10-15 Gbps sustained
- Packet loss: <1%
- Detection window: 50ms

**ML Accuracy Goals**:
- Overall accuracy: >95%
- False positive rate: <2%
- False negative rate: <5%
- Multi-attack classification: Simultaneous detection of all types

**Resource Utilization**:
- CPU: 80-90% across 14 cores (efficient use)
- Memory: ~5-6 MB for flow tracking (OctoSketch)
- Latency overhead from ML: <10% (target: 3-5ms added to baseline)

### Validation Plan

Once infrastructure is available, we will validate:
1. **Long-duration stability**: Run for 3+ hours continuously
2. **High-speed throughput**: Test at 10-17 Gbps range
3. **Multi-attack detection**: Simultaneous classification of all attack types
4. **Latency measurement**: Measure detection latency per window
5. **ML accuracy**: Compare predictions against ground truth labels
6. **Comparison study**: ML-enhanced vs threshold-only detection

---

## Next Steps

### Phase 1: Infrastructure Setup (When node is repaired)
1. Verify CloudLab node connectivity
2. Confirm DPDK environment setup
3. Test basic DPDK packet transmission
4. Validate NIC configuration

### Phase 2: Traffic Generation (Week 1)
5. Run traffic generators to create PCAP files
6. Generate benign traffic (4 temporal phases)
7. Generate attack traffic (5 attack types)
8. Verify PCAP file quality and characteristics

### Phase 3: Data Collection (Week 1-2)
9. Run DPDK senders to replay traffic
10. Execute detector and collect logs for each traffic type
11. Extract features using `feature_extractor.py`
12. Prepare train/validation/test splits (70/15/15)

### Phase 4: Model Training (Week 2-3)
13. Train LightGBM model with `export_lightgbm_model.py`
14. Validate model accuracy (target: >95%)
15. Generate `lightgbm_model.txt` for C API
16. Review model performance metrics

### Phase 5: ML Integration Testing (Week 3-4)
17. Compile `detectorML` binary with trained model
18. Execute ML-enhanced detector
19. Compare performance: ML vs threshold-only
20. Analyze false positives/negatives
21. Tune confidence threshold if needed

### Phase 6: Validation & Documentation (Week 4+)
22. Long-duration stability testing
23. Multi-attack simultaneous detection validation
24. Performance benchmarking
25. Document results and findings
26. Prepare thesis chapter and/or paper

---

## Conclusion

We have prepared all necessary code and infrastructure for an ML-enhanced hybrid DDoS detection system that aims to combine:

1. **Hardware acceleration** (DPDK kernel bypass)
2. **Memory efficiency** (OctoSketch O(1) tracking)
3. **Machine learning** (LightGBM embedded inference)
4. **Realistic traffic generation** (temporal phases, Mirai signatures)

The goal is to achieve significantly faster detection than state-of-the-art pure ML approaches (target: sub-50ms vs 866ms) while maintaining high accuracy through a hybrid threshold + ML approach.

**Current Blocker**: CloudLab infrastructure node is down. Once repaired, we can proceed with traffic generation, data collection, model training, and full system validation.

**Expected Timeline**: 4-6 weeks from infrastructure availability to complete validation and benchmarking.

---

*Report Generated*: December 11, 2025
*Project Phase*: Code Preparation - COMPLETE
*Current Status*: BLOCKED (waiting for CloudLab node repair)
*Next Phase*: Traffic Generation & Data Collection - READY TO START
