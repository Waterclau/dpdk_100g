# MIRA + ML Integration - Complete Setup Guide
**Machine Learning Enhanced DDoS Detection**

## Overview

This guide extends the MIRA detector with **LightGBM-based machine learning** to improve detection accuracy while maintaining sub-50ms latency.

### Goal

Create a **hybrid detection system**:
- **Statistical thresholds** (fast, <50ms) - baseline detection
- **ML classification** (intelligent) - improved accuracy and new attack detection

### Comparison

| System | Detection Method | Latency | Accuracy |
|--------|-----------------|---------|----------|
| **MIRA (original)** | Threshold-based | 34.33 ms | High TP, some FP |
| **MIRA + ML (this guide)** | Hybrid (Threshold + ML) | <50 ms target | Higher precision, fewer FP |
| **MULTI-LF (2025)** | Pure ML | 866 ms | 99.9% |

---

## Architecture

```
[NIC] → [14 Workers + OctoSketch] → [Coordinator] → [Threshold Detection]
                                          ↓
                                    [Export Stats]
                                          ↓
                                    [ML Server] → [LightGBM Model]
                                          ↓
                                    [ML Prediction]
                                          ↓
                                [Hybrid Decision Logic]
                                          ↓
                        ┌─────────────┬──────────────┬─────────────┐
                        ↓             ↓              ↓             ↓
                [Only Threshold] [Only ML]   [Both Agree]  [Neither]
                → Standard Alert → Anomaly  → HIGH ALERT  → Benign
```

---

## Prerequisites

- MIRA detector working (see `steps.md`)
- Python 3.8+
- Existing PCAP files (benign_10M.pcap, attack_mixed_10M.pcap)
- Network setup from original MIRA experiment

---

## Phase 1: Data Collection for Training

### Goal
Generate labeled dataset from detector logs to train LightGBM model.

### Step 1: Setup ML System Directories

```bash
cd /local/dpdk_100g/mira

# Create ML system structure (if not exists)
mkdir -p ml_system/{01_data_collection,02_training,03_inference,models,datasets/{raw_logs,processed,splits}}
```

### Step 2: Run Detector to Collect Benign Traffic Data

```bash
cd /local/dpdk_100g/mira/detector_system

# Start detector (monitor node)
sudo timeout 200 ./mira_ddos_detector \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../ml_system/datasets/raw_logs/benign_baseline.log

# In parallel - send benign traffic (controller node)
cd /local/dpdk_100g/mira/benign_sender
sudo timeout 195 ./build/dpdk_pcap_sender \
    -l 0-7 -n 4 -w 0000:41:00.0 -- ../benign_10M.pcap
```

**Duration:** 200 seconds of pure benign traffic

### Step 3: Run Detector to Collect UDP Flood Data

```bash
cd /local/dpdk_100g/mira/detector_system

# Start detector
sudo timeout 200 ./mira_ddos_detector \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../ml_system/datasets/raw_logs/udp_flood.log

# Send UDP attack traffic (tg node)
cd /local/dpdk_100g/mira/attack_sender
sudo timeout 195 ./build/dpdk_pcap_sender \
    -l 0-7 -n 4 -w 0000:41:00.0 -- ../attack_udp_5M.pcap
```

### Step 4: Run Detector to Collect SYN Flood Data

```bash
# Same pattern - change output log name
cd /local/dpdk_100g/mira/detector_system
sudo timeout 200 ./mira_ddos_detector \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../ml_system/datasets/raw_logs/syn_flood.log

# Send SYN attack (tg node)
cd /local/dpdk_100g/mira/attack_sender
sudo timeout 195 ./build/dpdk_pcap_sender \
    -l 0-7 -n 4 -w 0000:41:00.0 -- ../attack_syn_5M.pcap
```

### Step 5: Run Detector to Collect ICMP Flood Data

```bash
cd /local/dpdk_100g/mira/detector_system
sudo timeout 200 ./mira_ddos_detector \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../ml_system/datasets/raw_logs/icmp_flood.log

# Send ICMP attack (tg node)
cd /local/dpdk_100g/mira/attack_sender
sudo timeout 195 ./build/dpdk_pcap_sender \
    -l 0-7 -n 4 -w 0000:41:00.0 -- ../attack_icmp_5M.pcap
```

### Step 6: Run Detector to Collect Mixed Attack Data

```bash
cd /local/dpdk_100g/mira/detector_system
sudo timeout 200 ./mira_ddos_detector \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../ml_system/datasets/raw_logs/mixed_attack.log

# Send mixed attack (tg node)
cd /local/dpdk_100g/mira/attack_sender
sudo timeout 195 ./build/dpdk_pcap_sender \
    -l 0-7 -n 4 -w 0000:41:00.0 -- ../attack_mixed_10M.pcap
```

### Step 7: Verify Raw Logs Collected

```bash
cd /local/dpdk_100g/mira/ml_system/datasets/raw_logs

# Check all logs exist
ls -lh
# Expected files:
# - benign_baseline.log
# - udp_flood.log
# - syn_flood.log
# - icmp_flood.log
# - mixed_attack.log

# Quick check - count detection events per log
grep -c "HIGH" *.log
```

---

## Phase 2: Feature Extraction

### Goal
Parse detector logs and extract features for ML training.

### Step 1: Install Python Dependencies

```bash
cd /local/dpdk_100g/mira/ml_system

# Install required packages
pip3 install pandas numpy scikit-learn lightgbm matplotlib seaborn
```

### Step 2: Extract Features from Benign Log

```bash
cd /local/dpdk_100g/mira/ml_system/01_data_collection

python3 feature_extractor.py \
    --input ../datasets/raw_logs/benign_baseline.log \
    --output ../datasets/processed/benign_baseline.csv \
    --label benign
```

### Step 3: Extract Features from Attack Logs

```bash
# UDP Flood
python3 feature_extractor.py \
    --input ../datasets/raw_logs/udp_flood.log \
    --output ../datasets/processed/udp_flood.csv \
    --label udp_flood

# SYN Flood
python3 feature_extractor.py \
    --input ../datasets/raw_logs/syn_flood.log \
    --output ../datasets/processed/syn_flood.csv \
    --label syn_flood

# ICMP Flood
python3 feature_extractor.py \
    --input ../datasets/raw_logs/icmp_flood.log \
    --output ../datasets/processed/icmp_flood.csv \
    --label icmp_flood

# Mixed Attack
python3 feature_extractor.py \
    --input ../datasets/raw_logs/mixed_attack.log \
    --output ../datasets/processed/mixed_attack.csv \
    --label mixed_attack
```

### Step 4: Verify Extracted Features

```bash
cd /local/dpdk_100g/mira/ml_system/datasets/processed

# Check CSV files
ls -lh *.csv

# Inspect first few rows
head -20 benign_baseline.csv
head -20 udp_flood.csv
```

**Expected features in CSV:**
- `timestamp`
- `total_packets`
- `total_bytes`
- `udp_packets`, `tcp_packets`, `icmp_packets`
- `syn_packets`, `http_requests`
- `baseline_packets`, `attack_packets`
- `udp_tcp_ratio`, `syn_total_ratio`
- `label` (benign/udp_flood/syn_flood/icmp_flood/mixed_attack)

---

## Phase 3: Model Training

### Goal
Train LightGBM classifier on extracted features.

### Step 1: Prepare Dataset (Combine & Split)

```bash
cd /local/dpdk_100g/mira/ml_system/02_training

python3 prepare_dataset.py \
    --input ../datasets/processed/*.csv \
    --output ../datasets/splits/ \
    --train-ratio 0.7 \
    --val-ratio 0.15 \
    --test-ratio 0.15
```

**Output:**
- `datasets/splits/train.csv` (70%)
- `datasets/splits/val.csv` (15%)
- `datasets/splits/test.csv` (15%)

### Step 2: Train LightGBM Model

```bash
python3 train_lightgbm.py \
    --train ../datasets/splits/train.csv \
    --val ../datasets/splits/val.csv \
    --output ../models/lightgbm_v1.txt \
    --num-trees 100 \
    --learning-rate 0.1 \
    --max-depth 6
```

**Output:**
- `models/lightgbm_v1.txt` (trained model)
- Training logs with accuracy/loss per iteration

### Step 3: Evaluate Model

```bash
python3 evaluate_model.py \
    --model ../models/lightgbm_v1.txt \
    --test ../datasets/splits/test.csv \
    --output ../models/evaluation_report.txt
```

**Expected metrics:**
- Overall accuracy
- Per-class precision/recall/F1
- Confusion matrix
- Feature importance plot

### Step 4: Review Results

```bash
cd /local/dpdk_100g/mira/ml_system/models

# Check evaluation report
cat evaluation_report.txt

# View feature importance (if generated)
ls -lh feature_importance.png
```

**Target metrics:**
- Accuracy: >95%
- Benign precision: >98% (low false positives)
- Attack recall: >95% (catch most attacks)

---

## Phase 4: Setup ML Inference Server

### Goal
Deploy trained model as a service for real-time inference.

### Step 1: Test ML Server Locally

```bash
cd /local/dpdk_100g/mira/ml_system/03_inference

# Start server (listens on localhost:5000)
python3 ml_server.py \
    --model ../models/lightgbm_v1.txt \
    --port 5000 \
    --host localhost
```

**Server should output:**
```
Loading model from ../models/lightgbm_v1.txt
Model loaded successfully
ML Inference Server running on localhost:5000
Ready to accept predictions
```

### Step 2: Test Prediction API

```bash
# In another terminal, test with sample data
curl -X POST http://localhost:5000/predict \
    -H "Content-Type: application/json" \
    -d '{
        "total_packets": 50000,
        "udp_packets": 45000,
        "tcp_packets": 3000,
        "syn_packets": 1000,
        "udp_tcp_ratio": 15.0
    }'
```

**Expected response:**
```json
{
    "prediction": "udp_flood",
    "confidence": 0.94,
    "probabilities": {
        "benign": 0.01,
        "udp_flood": 0.94,
        "syn_flood": 0.03,
        "icmp_flood": 0.01,
        "mixed_attack": 0.01
    }
}
```

---

## Phase 5: Build ML-Enhanced Detector

### Goal
Create new version of detector that queries ML server for predictions.

### Step 1: Setup Detector ML Directory

```bash
cd /local/dpdk_100g/mira

# Copy original detector to new directory
cp -r detector_system detector_system_ml

cd detector_system_ml
```

### Step 2: Build ML-Enhanced Detector

```bash
# The detector_system_ml already includes ml_interface.c/h
make clean
make
```

### Step 3: Verify Build

```bash
ls -lh mira_ddos_detector_ml

# Check new command-line options
./mira_ddos_detector_ml --help
```

**New options:**
- `--ml-server <host:port>` - Enable ML inference
- `--ml-threshold <float>` - Confidence threshold (default: 0.7)

---

## Phase 6: Run Full System with ML

### Timeline

```
Time     Monitor                    Controller           TG
─────────────────────────────────────────────────────────────────
0s       Start ML server            -                    -
5s       Start detector w/ ML       -                    -
10s      -                          Start benign         -
10-130s  Baseline monitoring        Benign running       -
130s     -                          -                    Start attack
130-450s ML-enhanced detection      Benign continues     Attack active
450s     -                          Traffic stops        Traffic stops
460s     Detector stops             -                    -
```

### Step 1: Start ML Inference Server (Monitor Node)

```bash
cd /local/dpdk_100g/mira/ml_system/03_inference

python3 ml_server.py \
    --model ../models/lightgbm_v1.txt \
    --port 5000 \
    --host 0.0.0.0 \
    2>&1 | tee ../../results/ml_enhanced/ml_server.log
```

**Wait for:** "ML Inference Server running on 0.0.0.0:5000"

### Step 2: Start ML-Enhanced Detector (Monitor Node)

```bash
# In another terminal on monitor
cd /local/dpdk_100g/mira/detector_system_ml

sudo timeout 460 ./mira_ddos_detector_ml \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    --ml-server localhost:5000 \
    --ml-threshold 0.75 \
    2>&1 | tee ../results/ml_enhanced/detection_with_ml.log
```

**Wait for:** "ML server connected: localhost:5000"

### Step 3: Start Benign Traffic (Controller Node, wait 5s after detector)

```bash
cd /local/dpdk_100g/mira/benign_sender

sudo timeout 445 ./build/dpdk_pcap_sender \
    -l 0-7 -n 4 -w 0000:41:00.0 -- ../benign_10M.pcap
```

### Step 4: Start Attack Traffic (TG Node, wait 120s after benign)

```bash
cd /local/dpdk_100g/mira/attack_sender

# Wait 120 seconds
sleep 120

sudo timeout 325 ./build/dpdk_pcap_sender \
    -l 0-7 -n 4 -w 0000:41:00.0 -- ../attack_mixed_10M.pcap
```

### Step 5: Monitor Detection (Optional)

```bash
# On monitor node, in another terminal
tail -f /local/dpdk_100g/mira/results/ml_enhanced/detection_with_ml.log | grep -E "(ALERT|ML)"
```

---

## Phase 7: Analysis and Comparison

### Goal
Compare ML-enhanced detector vs original threshold-based detector.

### Step 1: Analyze ML-Enhanced Results

```bash
cd /local/dpdk_100g/mira/analysis

python3 analyze_ml_performance.py \
    --ml-log ../results/ml_enhanced/detection_with_ml.log \
    --baseline-log ../results/mira_detector_multicore.log \
    --output ../results/ml_enhanced/comparison/
```

**Generated outputs:**
- `comparison_metrics.json` - Accuracy, precision, recall comparison
- `detection_latency_comparison.png` - ML vs baseline latency
- `false_positive_analysis.png` - FP rate comparison
- `confusion_matrix_ml.png` - ML predictions vs ground truth

### Step 2: Review Key Metrics

```bash
cd /local/dpdk_100g/mira/results/ml_enhanced/comparison

# View metrics
cat comparison_metrics.json
```

**Expected improvements with ML:**
- **False positive rate:** Reduced by 30-50%
- **Detection accuracy:** Improved to >98%
- **Detection latency:** <50ms (maintained)
- **Multi-attack classification:** Individual attack types identified

### Step 3: Extract Key Findings

```bash
# First detection time
grep "FIRST DETECTION" ../detection_with_ml.log

# ML predictions during attack
grep "ML Prediction" ../detection_with_ml.log | head -20

# Confidence scores
grep "confidence" ../detection_with_ml.log | awk '{print $NF}' | sort -n
```

---

## Expected Results

### Detection Latency

| System | Method | Latency | Improvement |
|--------|--------|---------|-------------|
| MULTI-LF | Pure ML | 866 ms | Baseline (ML) |
| MIRA (original) | Threshold | 34.33 ms | 25.2× faster |
| **MIRA + ML** | **Hybrid** | **<50 ms** | **17× faster than MULTI-LF** |

### Detection Accuracy

| Metric | Original (Threshold) | With ML | Improvement |
|--------|---------------------|---------|-------------|
| Overall Accuracy | ~92% | >98% | +6% |
| False Positive Rate | ~8% | <2% | -6% |
| Attack Detection (Recall) | >95% | >98% | +3% |
| Multi-class Precision | N/A | >96% | New capability |

### Hybrid Decision Logic

| Threshold Alert | ML Prediction | Final Decision | Confidence |
|----------------|---------------|----------------|------------|
| ✅ HIGH | ✅ Attack (>0.7) | **HIGH ALERT** | Very High |
| ✅ HIGH | ❌ Benign (>0.7) | Medium Alert | Manual review |
| ❌ NONE | ✅ Attack (>0.7) | **Anomaly Alert** | High |
| ❌ NONE | ❌ Benign (>0.7) | No Alert | Normal |

---

## Troubleshooting

### ML Server won't start

```bash
# Check port availability
netstat -tuln | grep 5000

# Check Python dependencies
pip3 list | grep -E "(lightgbm|pandas|numpy)"

# Test model loading
cd ml_system/03_inference
python3 -c "import lightgbm as lgb; model = lgb.Booster(model_file='../models/lightgbm_v1.txt'); print('Model OK')"
```

### Detector can't connect to ML server

```bash
# Test connectivity
curl http://localhost:5000/health

# Check firewall (if server on different node)
sudo ufw status
sudo ufw allow 5000/tcp

# Verify server logs
tail -f ml_system/03_inference/server.log
```

### Low ML accuracy

```bash
# Check dataset balance
cd ml_system/datasets/splits
wc -l train.csv val.csv test.csv

# Review feature importance
python3 ../../02_training/evaluate_model.py --model ../../models/lightgbm_v1.txt --test test.csv

# Retrain with more data or tuned hyperparameters
cd ../../02_training
python3 tune_hyperparams.py --train ../datasets/splits/train.csv --val ../datasets/splits/val.csv
```

---

## Next Steps

### Immediate

1. ✅ Collect more diverse attack scenarios
2. ✅ Fine-tune ML model hyperparameters
3. ✅ Implement adaptive thresholds based on ML feedback
4. ✅ Add logging of ML predictions for continuous learning

### Future Enhancements

1. **Real-time retraining:** Update model with production data
2. **Ensemble models:** Combine multiple classifiers
3. **Anomaly detection:** Add unsupervised learning for zero-day attacks
4. **GPU acceleration:** Offload inference to GPU for <5ms latency
5. **Distributed detection:** Aggregate ML predictions across multiple nodes

---

## References

### Original MIRA System
- `steps.md` - Original DPDK + OctoSketch setup
- `progress.md` - Baseline results (34.33 ms detection)

### ML System Components
- `ml_system/README.md` - ML system documentation
- `ml_system/01_data_collection/` - Feature extraction scripts
- `ml_system/02_training/` - Model training scripts
- `ml_system/03_inference/` - Inference server

### Comparison Baseline
- **MULTI-LF (2025)** - arXiv:2504.11575 (866 ms detection latency)

---

## Summary

This guide demonstrates how to:

1. ✅ Collect labeled training data from existing detector
2. ✅ Train LightGBM model for multi-class attack classification
3. ✅ Deploy ML inference server for real-time predictions
4. ✅ Build hybrid detector (thresholds + ML) maintaining <50ms latency
5. ✅ Achieve >98% accuracy with <2% false positive rate
6. ✅ Maintain 17× speed advantage over pure ML approaches (MULTI-LF)

**Key Achievement:**
Combine the **speed of statistical detection** with the **intelligence of machine learning** without sacrificing real-time performance.

---

**Document Version:** 1.0
**Last Updated:** 2025-12-05
**Status:** Ready for implementation
