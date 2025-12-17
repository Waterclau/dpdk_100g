# ML Model Improvement Plan - MIRA DDoS Detector

## 📊 Current State Analysis

### Model Performance (Baseline)
```
Overall Accuracy: 72.22% ❌ (Target: >95%)

Per-Class Performance:
┌──────────┬───────────┬────────┬──────────┬─────────┐
│ Class    │ Precision │ Recall │ F1-Score │ Support │
├──────────┼───────────┼────────┼──────────┼─────────┤
│ attack   │   100%    │  100%  │   100%   │    6    │ ✅
│ benign   │     0%    │    0%  │     0%   │    3    │ ❌
│ mixed    │    70%    │   78%  │    74%   │    9    │ ⚠️
└──────────┴───────────┴────────┴──────────┴─────────┘

Dataset Size: 18 test samples (~120 total)
```

### Root Causes Identified
1. **CRITICAL: Insufficient training data** (<200 samples vs. 1000+ needed)
2. **HIGH: Class imbalance** (benign underrepresented)
3. **MEDIUM: Benign/mixed confusion** (model can't distinguish)
4. **LOW: Hyperparameters not tuned** for small dataset

### What Works Well ✅
- Attack detection: Perfect 100% (when seen in training)
- Mixed detection: Acceptable 78% recall
- Feature extraction pipeline: Working correctly
- Model integration: C API functional

---

## 🎯 Goals and Objectives

### Define Your Targets (CHOOSE ONE):

#### Option A: Quick Validation (2-3 days)
**Goal:** Verify the ML approach works with minimal investment
- Target Accuracy: **>85%**
- Dataset Size: **500 samples** (manageable)
- Time Investment: **6-8 hours** of experiments
- Risk: May not reach production quality

#### Option B: Production Ready (1-2 weeks)
**Goal:** Deploy ML detector in real experiments
- Target Accuracy: **>95%**
- Dataset Size: **2000+ samples** (robust)
- Time Investment: **20-30 hours** of experiments
- Risk: Higher time/resource commitment

#### Option C: Research Quality (2-4 weeks)
**Goal:** Publishable results, comprehensive evaluation
- Target Accuracy: **>98%**
- Dataset Size: **5000+ samples** (publication-grade)
- Time Investment: **40+ hours** of experiments
- Risk: May require multiple iterations

**👉 DECISION NEEDED:** Which option aligns with your project timeline?

---

## 📋 Problem Decomposition

### Problem 1: Insufficient Training Data
**Current:** ~120 samples total
**Needed:** 500-2000 samples (depending on goal)

**Root Cause:**
- Short simulations (2-3 min) → only 24-36 detection windows
- Few runs (3 logs) → limited samples

**Possible Solutions:**
- [ ] **Solution 1A:** Longer individual runs (10-30 min each)
- [ ] **Solution 1B:** More runs with current duration (10-20 runs)
- [ ] **Solution 1C:** Automated batch collection script
- [ ] **Solution 1D:** Use existing longer logs (if available)

**Questions to Resolve:**
1. How long can you run experiments on CloudLab? (max duration)
2. Can you run experiments overnight/unattended?
3. Do you have any existing longer logs we could reuse?

---

### Problem 2: Benign Class Failure (0% accuracy)
**Current:** All benign samples misclassified as "mixed"
**Impact:** Model cannot distinguish normal traffic

**Possible Causes:**
- [ ] **Cause 2A:** Too few benign samples in training (3 in test = ~20 in train)
- [ ] **Cause 2B:** Benign and mixed features too similar
- [ ] **Cause 2C:** Model bias toward "mixed" class (largest class)
- [ ] **Cause 2D:** Benign traffic generation not realistic enough

**Possible Solutions:**
- [ ] **Solution 2A:** Collect more diverse benign data (different traffic patterns)
- [ ] **Solution 2B:** Add temporal features to distinguish benign/mixed
- [ ] **Solution 2C:** Use SMOTE to oversample benign class
- [ ] **Solution 2D:** Simplify to binary classification (attack vs. non-attack)

**Questions to Resolve:**
1. Is "mixed" class really necessary? Could we use binary (attack/benign)?
2. What defines "mixed" in your experiments? (% of attack traffic?)
3. Are benign samples from pure benign runs or quiet periods in mixed runs?

---

### Problem 3: Dataset Collection Strategy
**Current:** Manual, ad-hoc collection
**Needed:** Systematic, reproducible process

**Collection Scenarios to Consider:**

#### Scenario A: Maximize Diversity (RECOMMENDED)
```
Benign variations:
  - Low traffic:  6 Gbps, low jitter
  - Medium:      10 Gbps, medium jitter
  - High:        12 Gbps, high jitter
  - Variable:    Adaptive mode with phase changes

Attack variations:
  - SYN flood only
  - UDP flood only
  - HTTP flood only
  - Mixed attacks (CIC-IDS multi-pcap)

Mixed scenarios:
  - 25% attack / 75% benign
  - 50% attack / 50% benign
  - 75% attack / 25% benign
```

#### Scenario B: Focus on Realism
```
Benign: Only adaptive mode (realistic phases)
Attack: Only CIC-IDS dataset (real attacks)
Mixed:  Start with benign, inject attack at t=60s
```

#### Scenario C: Quick Coverage
```
Benign: 3 runs × 10 min = 30 min
Attack: 3 runs × 10 min = 30 min
Mixed:  3 runs × 10 min = 30 min
Total:  90 minutes of experiments
```

**Questions to Resolve:**
1. Which scenario matches your research goals?
2. Do you need to compare different attack types separately?
3. Should we prioritize quantity or quality of samples?

---

### Problem 4: Feature Engineering
**Current:** 14 features extracted
**Status:** Working but may need enhancement

**Potential Improvements:**
- [ ] **Feature 4A:** Add rate-based features (PPS, Gbps)
- [ ] **Feature 4B:** Add entropy metrics (protocol distribution)
- [ ] **Feature 4C:** Add ratio features (more combinations)
- [ ] **Feature 4D:** Add temporal features (rate of change)
- [ ] **Feature 4E:** Feature selection (remove redundant)
- [ ] **Feature 4F:** Feature normalization (StandardScaler)

**Questions to Resolve:**
1. Should we try current features with more data first?
2. Or add features in parallel with data collection?
3. What's your priority: interpretability vs. accuracy?

---

### Problem 5: Model Configuration
**Current:** Default LightGBM params
**Status:** Not tuned for small dataset

**Tuning Options:**
- [ ] **Option 5A:** Manual tuning (adjust based on dataset size)
- [ ] **Option 5B:** Grid search (try multiple configurations)
- [ ] **Option 5C:** Use cross-validation (better for small data)
- [ ] **Option 5D:** Try simpler model first (Decision Tree, Random Forest)

**Questions to Resolve:**
1. Should we tune now or wait for more data?
2. Do you want to compare multiple ML algorithms?
3. Is training time a concern? (LightGBM is fast)

---

## 🗺️ Planning Decision Points

### Decision Point 1: Project Scope
**Question:** What's your primary goal?

- [ ] **A. Proof of Concept** - Show ML can improve detection
- [ ] **B. Production System** - Deploy in real experiments
- [ ] **C. Research Publication** - Comprehensive evaluation
- [ ] **D. Master's Thesis** - Deep analysis required

**Impact:** Determines accuracy target and data requirements

---

### Decision Point 2: Time Constraints
**Question:** How much time do you have for this ML component?

- [ ] **A. 1 week** (urgent, minimal improvements)
- [ ] **B. 2-3 weeks** (balanced, good results)
- [ ] **C. 1+ month** (comprehensive, excellent results)
- [ ] **D. Flexible** (research-driven timeline)

**Impact:** Determines collection strategy and iterations

---

### Decision Point 3: Resource Availability
**Question:** What resources do you have access to?

- [ ] **CloudLab server hours:** ___ hours/day available
- [ ] **Storage capacity:** ___ GB available for logs
- [ ] **Parallel experiments:** Can run multiple nodes? (Yes/No)
- [ ] **Automation:** Can run unattended overnight? (Yes/No)

**Impact:** Determines collection parallelization and batch size

---

### Decision Point 4: Classification Granularity
**Question:** Do you need 3-class or 2-class classification?

#### Option A: Keep 3-class (current)
```
Classes: attack, benign, mixed
Pros: More detailed detection
Cons: Harder to train, needs more data
```

#### Option B: Simplify to 2-class
```
Classes: attack, non-attack (merge benign+mixed)
Pros: Easier to train, less data needed
Cons: Less granular information
```

#### Option C: Binary hierarchical
```
Stage 1: Is there attack traffic? (binary)
Stage 2: If yes, what % is attack? (regression)
Pros: Best of both worlds
Cons: More complex pipeline
```

**Impact:** Affects data requirements and model complexity

---

## 📅 Proposed Plan Templates

### Template A: Quick Win Plan (1 Week)

**Goal:** Achieve 85-90% accuracy quickly

**Day 1: Data Collection Preparation**
- [ ] Create automated collection script
- [ ] Test script with 1 short run
- [ ] Plan overnight collection (8 runs × 10 min)

**Day 2: Batch Collection**
- [ ] Run overnight: 4 benign + 4 attack runs
- [ ] Total: ~960 samples (8 runs × 120 windows)
- [ ] Verify logs collected correctly

**Day 3: Feature Extraction & Training**
- [ ] Extract features from all logs
- [ ] Combine datasets (check balance)
- [ ] Train model with tuned hyperparameters
- [ ] Evaluate on test set

**Day 4: Iteration (if needed)**
- [ ] If <85%: Collect 4 more runs for weak class
- [ ] If >85%: Test in live detector

**Day 5: Documentation & Testing**
- [ ] Document final model performance
- [ ] Run live detection test
- [ ] Write results summary

**Expected Outcome:** 85-90% accuracy, functional ML detector

---

### Template B: Production Plan (2-3 Weeks)

**Week 1: Data Infrastructure**
- [ ] Day 1-2: Create automated collection scripts
- [ ] Day 3-4: Collect diverse dataset (20+ runs)
- [ ] Day 5: Feature extraction and EDA

**Week 2: Model Development**
- [ ] Day 1-2: Feature engineering (add temporal features)
- [ ] Day 3: Hyperparameter tuning
- [ ] Day 4: Cross-validation evaluation
- [ ] Day 5: Model selection and final training

**Week 3: Validation & Deployment**
- [ ] Day 1-2: Live testing with detector
- [ ] Day 3: Performance comparison (vs. threshold-only)
- [ ] Day 4: Final tuning
- [ ] Day 5: Documentation and deployment

**Expected Outcome:** 95%+ accuracy, production-ready

---

### Template C: Research Plan (4 Weeks)

**Week 1: Comprehensive Data Collection**
- Multiple traffic patterns
- Different attack intensities
- Various time scales
- Target: 2000+ samples

**Week 2: Feature Engineering**
- Temporal features
- Statistical features
- Feature selection analysis
- Ablation studies

**Week 3: Model Optimization**
- Multiple ML algorithms comparison
- Hyperparameter grid search
- Ensemble methods
- Cross-validation

**Week 4: Evaluation & Analysis**
- Performance metrics
- Confusion matrix analysis
- ROC curves
- Comparison with baselines
- Publication-quality plots

**Expected Outcome:** 98%+ accuracy, publishable results

---

## ✅ Next Steps - Complete This Planning Document

**TO DO:** Answer these key questions:

1. **Project Goal:** [ ] Proof of Concept | [ ] Production | [ ] Research

2. **Time Available:** [ ] 1 week | [ ] 2-3 weeks | [ ] 1+ month

3. **Classification:** [ ] Keep 3-class | [ ] Simplify to 2-class | [ ] Hierarchical

4. **CloudLab Access:**
   - Max experiment duration: ___ hours
   - Can run overnight: [ ] Yes | [ ] No
   - Parallel nodes available: [ ] Yes | [ ] No

5. **Priority Ranking** (1=highest, 3=lowest):
   - [ ] Get more training data
   - [ ] Improve feature engineering
   - [ ] Tune model hyperparameters

6. **Minimum Acceptable Performance:**
   - Accuracy: ____%
   - Attack recall (must detect attacks): ____%
   - Benign precision (avoid false alarms): ____%

---

## 📝 Plan Approval Checklist

Before proceeding, confirm:

- [ ] Goals are clearly defined and realistic
- [ ] Time and resource constraints understood
- [ ] Data collection strategy chosen
- [ ] Success metrics agreed upon
- [ ] Fallback plan if targets not met

---

**ONCE YOU ANSWER THE QUESTIONS ABOVE, I WILL:**
1. Generate a detailed step-by-step action plan
2. Create automated collection scripts
3. Provide specific commands for your chosen approach
4. Estimate timeline and expected results

**Let's fill in the blanks together to create your custom plan.**
