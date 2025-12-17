# ML Training Recommendations - Improving Model Performance

## Current Status

**Model Performance: 72.22% accuracy** ❌ (Target: >95%)

### Test Results Analysis:
```
Overall Accuracy: 72.22%

Per-Class Performance:
- attack:  100% precision, 100% recall ✅ PERFECT
- benign:  0% precision, 0% recall   ❌ FAILED
- mixed:   70% precision, 78% recall  ⚠️ ACCEPTABLE

Dataset Size:
- Test samples: 18 (TOO SMALL!)
- Estimated total: ~120 samples
- Minimum needed: >1000 samples
```

### Root Cause: **INSUFFICIENT TRAINING DATA**

## 🎯 Immediate Solutions

### Solution 1: Collect More Data (CRITICAL)

**Problem:** Short simulations generate too few detection windows

**Current Setup:**
- 2-3 minute simulations → ~24-36 detection windows per log
- 3 logs × 30 windows = ~90 training samples
- **This is 10× too small!**

**Recommended Setup:**

#### Option A: Longer Single Runs (EASIEST)
```bash
# Benign traffic - 30 minutes instead of 2
sudo timeout 1800 ./mira_ddos_detector ... \
    2>&1 | tee benign_30min.log

sudo timeout 1795 ./dpdk_pcap_sender_v2 \
    -- ../benign_10M.pcap --adaptive --rate-gbps 12 --jitter 15 --loop

# Expected: ~360 detection windows (1 per 5 seconds)
```

#### Option B: Multiple Runs with Different Traffic Patterns
```bash
# Run 1: Low traffic (6 Gbps, 10 min)
# Run 2: Medium traffic (10 Gbps, 10 min)
# Run 3: High traffic (12 Gbps, 10 min)
# Run 4: Variable traffic (--jitter 30, 10 min)

# Total: 4 runs × 120 windows = 480 samples
```

#### Option C: Batch Collection Script (BEST)
Create `collect_training_data.sh`:

```bash
#!/bin/bash
# Automated training data collection

RUNS=5
DURATION=600  # 10 minutes per run

for i in $(seq 1 $RUNS); do
    echo "[RUN $i/$RUNS] Collecting benign traffic..."

    # Start detector
    sudo timeout $DURATION ./mira_ddos_detector \
        -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
        2>&1 | tee ../ml_system/datasets/raw_logs/benign_run${i}.log &

    DETECTOR_PID=$!
    sleep 5

    # Start sender with varying parameters
    JITTER=$((10 + i * 5))  # 15, 20, 25, 30, 35
    RATE=$((8 + i))         # 9, 10, 11, 12, 13 Gbps

    sudo timeout $((DURATION - 5)) ./dpdk_pcap_sender_v2 \
        -l 0-7 -n 4 -w 0000:41:00.0 \
        -- ../benign_10M.pcap --adaptive --rate-gbps $RATE --jitter $JITTER --loop

    wait $DETECTOR_PID

    echo "[RUN $i/$RUNS] Complete. Waiting 10s before next run..."
    sleep 10
done

echo "Collection complete: $RUNS runs × ~120 windows = ~$((RUNS * 120)) samples"
```

**Expected Results:**
- 5 runs × 10 min = 50 minutes total
- 5 runs × 120 windows = **600 benign samples** ✅
- Repeat for attack and mixed → **1800 total samples**

---

### Solution 2: Balance Dataset (IMPORTANT)

**Problem:** Class imbalance causes model to ignore minority class

**Current Distribution (estimated):**
```
benign: ~30 samples (25%)
attack: ~40 samples (33%)
mixed:  ~50 samples (42%)
```

**Recommended:**
```bash
# Collect equal amounts of each class
benign: 500 samples (33%)
attack: 500 samples (33%)
mixed:  500 samples (33%)
Total:  1500 samples
```

**How to achieve:**
```bash
# Benign: 5 runs × 10 min
# Attack: 5 runs × 10 min (different attack types each)
# Mixed:  5 runs × 10 min (60s benign + rest mixed)
```

---

### Solution 3: Improve Feature Quality

**Current Features (14):** May have redundancy or low signal

**Recommendations:**

#### A. Add Temporal Features
```python
# In feature_extractor.py, add:

features['pps_rate'] = (
    features['total_packets'] / window_duration
    if window_duration > 0 else 0.0
)

features['gbps_rate'] = (
    (features['total_bytes'] * 8.0) / (window_duration * 1e9)
    if window_duration > 0 else 0.0
)

features['syn_ack_ratio'] = (
    features['syn_packets'] / features['tcp_packets']
    if features['tcp_packets'] > 0 else 0.0
)

features['protocol_entropy'] = calculate_entropy([
    features['tcp_packets'],
    features['udp_packets'],
    features['icmp_packets']
])
```

#### B. Normalize Features
```python
from sklearn.preprocessing import StandardScaler

# After loading data, before training:
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
```

#### C. Feature Selection
```python
from sklearn.feature_selection import SelectKBest, f_classif

# Select top 10 features
selector = SelectKBest(f_classif, k=10)
X_train_selected = selector.fit_transform(X_train, y_train)
X_test_selected = selector.transform(X_test)

# Print selected features
feature_scores = pd.DataFrame({
    'feature': feature_cols,
    'score': selector.scores_
}).sort_values('score', ascending=False)
print(feature_scores)
```

---

### Solution 4: Hyperparameter Tuning

**Current LightGBM parameters** may not be optimal for small datasets

**Modify `export_lightgbm_model.py`:**

```python
# For small datasets (<500 samples)
params_small_dataset = {
    'objective': 'multiclass',
    'num_class': len(label_encoder.classes_),
    'metric': 'multi_logloss',
    'learning_rate': 0.05,      # Lower = less overfitting
    'max_depth': 4,             # Shallower trees
    'num_leaves': 15,           # Fewer leaves
    'min_data_in_leaf': 5,      # Lower minimum (was 20)
    'feature_fraction': 0.8,
    'bagging_fraction': 0.8,
    'bagging_freq': 5,
    'lambda_l1': 0.1,           # L1 regularization
    'lambda_l2': 0.1,           # L2 regularization
    'verbose': -1,
    'seed': 42
}

# Increase boosting rounds
num_boost_round = 200  # was 100

# Add early stopping
early_stopping_callback = lgb.early_stopping(stopping_rounds=20)

model = lgb.train(
    params_small_dataset,
    train_data,
    num_boost_round=num_boost_round,
    valid_sets=[train_data, val_data],
    callbacks=[
        lgb.log_evaluation(period=20),
        early_stopping_callback
    ]
)
```

---

### Solution 5: Use Cross-Validation

For small datasets, use k-fold cross-validation:

**Create `train_with_cv.py`:**

```python
from sklearn.model_selection import StratifiedKFold
import lightgbm as lgb
import numpy as np

def train_with_cross_validation(X, y, n_splits=5):
    """Train with k-fold cross-validation"""

    kfold = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    cv_scores = []

    for fold, (train_idx, val_idx) in enumerate(kfold.split(X, y), 1):
        print(f"\n[FOLD {fold}/{n_splits}]")

        X_train, X_val = X[train_idx], X[val_idx]
        y_train, y_val = y[train_idx], y[val_idx]

        train_data = lgb.Dataset(X_train, label=y_train)
        val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)

        model = lgb.train(params, train_data, num_boost_round=200,
                         valid_sets=[val_data],
                         callbacks=[lgb.early_stopping(20)])

        y_pred = np.argmax(model.predict(X_val), axis=1)
        accuracy = accuracy_score(y_val, y_pred)
        cv_scores.append(accuracy)

        print(f"Fold {fold} Accuracy: {accuracy*100:.2f}%")

    print(f"\n[CROSS-VALIDATION RESULTS]")
    print(f"Mean Accuracy: {np.mean(cv_scores)*100:.2f}%")
    print(f"Std Accuracy:  {np.std(cv_scores)*100:.2f}%")

    return cv_scores
```

---

## 📋 Action Plan (Priority Order)

### 🔴 CRITICAL (Do First)
1. **Collect more data** - Run batch collection script
   - Target: 1500+ total samples (500 per class)
   - Use longer simulations (10 min each)
   - Multiple runs with traffic variations

### 🟡 HIGH (Do Next)
2. **Balance dataset** - Ensure equal class representation
3. **Add feature normalization** - StandardScaler
4. **Tune hyperparameters** - Adjust for small dataset

### 🟢 MEDIUM (Nice to Have)
5. **Add temporal features** - PPS, Gbps, entropy
6. **Feature selection** - Find most important features
7. **Cross-validation** - Better evaluation for small data

---

## 🎯 Target Metrics After Improvements

```
Minimum Acceptable:
- Overall Accuracy: >90%
- Per-class Recall: >85%
- Per-class Precision: >85%
- Dataset size: >1000 samples

Excellent Performance:
- Overall Accuracy: >95%
- Per-class Recall: >90%
- Per-class Precision: >90%
- Dataset size: >2000 samples
```

---

## 📝 Next Steps

1. **Immediate (Today):**
   ```bash
   # Create batch collection script
   vim collect_training_data.sh
   chmod +x collect_training_data.sh

   # Run overnight collection
   nohup ./collect_training_data.sh > collection.log 2>&1 &
   ```

2. **Tomorrow:**
   ```bash
   # Extract features from new logs
   for log in benign_run*.log; do
       python3 feature_extractor.py --input $log --output ${log%.log}.csv --label benign
   done

   # Prepare dataset
   python3 prepare_dataset.py --input *.csv --output ../datasets/splits/

   # Retrain model
   python3 export_lightgbm_model.py --train ../datasets/splits/train.csv

   # Evaluate
   python3 evaluate_model.py --model ../../detector_system_ml/lightgbm_model.txt
   ```

3. **If still <90% accuracy:**
   - Implement feature normalization
   - Try cross-validation
   - Add temporal features
   - Check for data quality issues

---

## 📈 Expected Timeline

- **Week 1:** Collect sufficient training data (1500+ samples)
- **Week 2:** Feature engineering and hyperparameter tuning
- **Week 3:** Final model training and validation
- **Week 4:** Deployment and testing in production

**Estimated effort:** 1-2 weeks to achieve >90% accuracy
