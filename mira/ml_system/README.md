# MIRA ML System - Machine Learning Pipeline

Complete ML pipeline for training and deploying LightGBM models with MIRA detector.

## Directory Structure

```
ml_system/
├── 01_data_collection/
│   └── feature_extractor.py     # Extract features from detector logs
├── 02_training/
│   ├── prepare_dataset.py       # Combine and split datasets
│   ├── export_lightgbm_model.py # Train and export LightGBM model
│   └── evaluate_model.py        # Evaluate trained model
└── datasets/
    ├── raw_logs/                # Raw detector logs
    │   ├── benign_baseline.log
    │   ├── attack_cic_ids.log
    │   └── mixed_traffic.log
    ├── processed/               # Extracted features (CSV)
    │   ├── benign_baseline.csv
    │   ├── attack_cic_ids.csv
    │   └── mixed_traffic.csv
    └── splits/                  # Train/val/test splits
        ├── train.csv
        ├── val.csv
        └── test.csv
```

## Quick Start

### Phase 1: Data Collection

Run the MIRA detector (WITHOUT ML) and collect logs:

```bash
# Terminal 1 - Detector
cd /local/dpdk_100g/mira/detector_system
sudo timeout 120 ./mira_ddos_detector \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../ml_system/datasets/raw_logs/benign_baseline.log

# Terminal 2 - Traffic sender
cd /local/dpdk_100g/mira/benign_sender
sleep 5
sudo timeout 115 ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../benign_10M.pcap --adaptive --rate-gbps 12 --jitter 15 --loop
```

Repeat for attack traffic and mixed traffic (see `stepsML.md` Phase 1).

### Phase 2: Feature Extraction

Extract features from raw logs:

```bash
cd /local/dpdk_100g/mira/ml_system/01_data_collection

# Extract benign features
python3 feature_extractor.py \
    --input ../datasets/raw_logs/benign_baseline.log \
    --output ../datasets/processed/benign_baseline.csv \
    --label benign

# Extract attack features
python3 feature_extractor.py \
    --input ../datasets/raw_logs/attack_cic_ids.log \
    --output ../datasets/processed/attack_cic_ids.csv \
    --label attack

# Extract mixed traffic features
python3 feature_extractor.py \
    --input ../datasets/raw_logs/mixed_traffic.log \
    --output ../datasets/processed/mixed_traffic.csv \
    --label mixed
```

### Phase 3: Dataset Preparation

Combine CSVs and split into train/val/test:

```bash
cd /local/dpdk_100g/mira/ml_system/02_training

python3 prepare_dataset.py \
    --input ../datasets/processed/*.csv \
    --output ../datasets/splits/ \
    --train-ratio 0.7 \
    --val-ratio 0.15 \
    --test-ratio 0.15
```

### Phase 4: Model Training

Train LightGBM model and export for C API:

```bash
cd /local/dpdk_100g/mira/ml_system/02_training

python3 export_lightgbm_model.py \
    --train ../datasets/splits/train.csv \
    --output ../../detector_system_ml/lightgbm_model.txt
```

This creates:
- `detector_system_ml/lightgbm_model.txt` - Model file for C API
- `detector_system_ml/label_mapping.json` - Label mapping

### Phase 5: Model Evaluation

Evaluate model on test set:

```bash
cd /local/dpdk_100g/mira/ml_system/02_training

python3 evaluate_model.py \
    --model ../../detector_system_ml/lightgbm_model.txt \
    --test ../datasets/splits/test.csv
```

### Phase 6: Deployment

Compile and run ML-enhanced detector:

```bash
cd /local/dpdk_100g/mira/detector_system_ml

# Compile
make clean && make

# Run detector with ML
sudo ./detectorML -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0
```

## Features Extracted (13 total)

1. **Volume metrics:**
   - `total_packets` - Total packet count
   - `total_bytes` - Total byte count

2. **Protocol distribution:**
   - `tcp_packets` - TCP packet count
   - `udp_packets` - UDP packet count
   - `icmp_packets` - ICMP packet count

3. **Application-level:**
   - `syn_packets` - SYN packet count
   - `http_requests` - HTTP request count
   - `dns_queries` - DNS query count

4. **Source classification:**
   - `baseline_packets` - Benign source packets (10.10.1.x)
   - `attack_packets` - Attack source packets (10.10.2.x)

5. **Derived ratios:**
   - `udp_tcp_ratio` - UDP/TCP ratio
   - `syn_total_ratio` - SYN/Total ratio
   - `baseline_attack_ratio` - Baseline/Attack ratio
   - `bytes_per_packet` - Average bytes per packet

## Labels

- `benign` - Normal traffic only
- `attack` - DDoS attack traffic
- `mixed` - Combination of benign and attack

## Python Dependencies

Install required packages:

```bash
pip3 install --user pandas numpy scikit-learn lightgbm matplotlib seaborn
```

## Expected Performance

- **Accuracy:** >95%
- **Precision:** >90% (per class)
- **Recall:** >90% (per class)
- **F1-Score:** >90% (weighted)

## Troubleshooting

### No features extracted

Check that log file contains detector output with format:
```
[PACKET COUNTERS - GLOBAL]
  Total packets:      ...
  Baseline (10.10.1.x): ...
  Attack (10.10.2.x): ...
```

### Model training fails

- Check that train.csv exists and has correct format
- Verify all 13 feature columns are present
- Check label column has valid values (benign/attack/mixed)

### Low model accuracy

- Collect more training data (longer collection periods)
- Balance dataset (similar number of benign/attack samples)
- Check for data quality issues (corrupted logs, wrong labels)

## Integration with Detector

The trained model (`lightgbm_model.txt`) is loaded by the ML-enhanced detector at startup:

```c
// In detectorML.c
g_ml_model = ml_init("./lightgbm_model.txt");
```

Predictions are made every detection window (50ms) using 13 extracted features.

## Complete Workflow

```
1. Collect logs      → datasets/raw_logs/*.log
2. Extract features  → datasets/processed/*.csv
3. Prepare dataset   → datasets/splits/{train,val,test}.csv
4. Train model       → detector_system_ml/lightgbm_model.txt
5. Evaluate model    → Check metrics (accuracy, precision, recall)
6. Deploy model      → Run detectorML with trained model
```

For detailed instructions, see `../stepsML.md`.
