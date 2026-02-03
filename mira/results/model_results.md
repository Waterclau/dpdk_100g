# Multi-Class DDoS Attack Classification Results

**Date:** 2026-01-29
**Dataset:** MIRA Detector Logs
**Task:** 14-class traffic classification (benign + 13 attack types)

---

## 1. Overview

We trained and evaluated multiple machine learning models to classify network traffic into specific DDoS attack types. The goal is to provide fine-grained attack identification beyond simple binary (attack/benign) detection, enabling targeted mitigation strategies.

### Objective
- Classify traffic into **14 distinct categories**: benign, DNS amplification, LDAP, mixed attacks, MSSQL, NetBIOS, NTP amplification, Portmap, SNMP, SSDP, SYN flood, TFTP, UDP flood, and WebDDoS.
- Complement the DPDK-based threshold detector with ML-based multi-class labeling.
- Provide interpretable feature importance for security analysis.

---

## 2. Dataset Composition

### Data Sources
- Multi-run detector logs capturing **benign** and **per-attack** traffic patterns
- **42 engineered features** per 5-second window, including:
  - General traffic metrics: `total_packets`, `total_bytes`, `udp_packets`, `tcp_packets`, `icmp_packets`
  - Protocol-specific counters: DNS ANY/TXT queries, NTP monlist, SNMP GetBulk, SSDP M-SEARCH, Portmap GetPort, MSSQL SQLBatch, TFTP RRQ, NetBIOS name queries
  - Ratio features: `syn_total_ratio`, `syn_ack_ratio`, `avg_dns_response_size`

### Split Statistics

| Split | Samples | Percentage |
|-------|---------|------------|
| Train | 5,446   | 70%        |
| Val   | 1,167   | 15%        |
| Test  | 1,167   | 15%        |

### Class Distribution (Training Set)

| Class   | Train Samples | Percentage |
|---------|---------------|------------|
| benign  | 376           | 6.9%       |
| dns     | 376           | 6.9%       |
| ldap    | 376           | 6.9%       |
| mixed   | 600           | 11.0%      |
| mssql   | 376           | 6.9%       |
| netbios | 376           | 6.9%       |
| ntp     | 375           | 6.9%       |
| portmap | 376           | 6.9%       |
| snmp    | 376           | 6.9%       |
| ssdp    | 376           | 6.9%       |
| syn     | 376           | 6.9%       |
| tftp    | 376           | 6.9%       |
| udp     | 376           | 6.9%       |
| webddos | 335           | 6.2%       |

The dataset is well-balanced across classes, with "mixed" having slightly more samples to capture multi-vector attack scenarios.

---

## 3. LightGBM (Primary Model)

### Training Configuration

| Parameter          | Value |
|--------------------|-------|
| Boosting rounds    | 300 (max) |
| Best iteration     | 185   |
| Max depth          | 8     |
| Num leaves         | 63    |
| Learning rate      | 0.05  |
| L1 regularization  | 0.5   |
| L2 regularization  | 0.5   |
| Normalization      | StandardScaler (mean=0, std=1) |

### Performance Summary

| Metric             | Validation | Test   |
|--------------------|------------|--------|
| **Accuracy**       | 98.37%     | 99.14% |
| **Weighted F1**    | 0.98       | 0.992  |
| **Macro Precision**| 0.99       | 0.99   |
| **Macro Recall**   | 0.98       | 0.99   |

### Per-Class Test Results

| Class   | Precision | Recall | F1-Score | Support |
|---------|-----------|--------|----------|---------|
| benign  | 1.000     | 0.950  | 0.974    | 80      |
| dns     | 1.000     | 1.000  | 1.000    | 81      |
| ldap    | 1.000     | 0.988  | 0.994    | 80      |
| mixed   | 0.985     | 0.992  | 0.988    | 129     |
| mssql   | 1.000     | 0.988  | 0.994    | 81      |
| netbios | 1.000     | 1.000  | 1.000    | 80      |
| ntp     | 1.000     | 1.000  | 1.000    | 81      |
| portmap | 1.000     | 0.988  | 0.994    | 81      |
| snmp    | 1.000     | 1.000  | 1.000    | 81      |
| ssdp    | 1.000     | 1.000  | 1.000    | 80      |
| syn     | 1.000     | 0.988  | 0.994    | 80      |
| tftp    | 1.000     | 1.000  | 1.000    | 80      |
| udp     | 1.000     | 0.988  | 0.994    | 81      |
| webddos | 0.900     | 1.000  | 0.947    | 72      |

### Confusion Matrix Analysis (Test Set)

Key observations from the 1167-sample test set:
- **Perfect classification (100%)**: dns, netbios, ntp, snmp, ssdp, tftp, webddos
- **Minor misclassifications**:
  - 4 benign samples misclassified (2 as mixed, 2 as webddos)
  - 8 samples from various classes (ldap, mssql, portmap, syn, udp, mixed) misclassified as webddos
- **WebDDoS precision (0.90)**: Some attack traffic predicted as webddos when it belongs to other classes

### Feature Importance (Top 10)

| Rank | Feature                  | Importance Score |
|------|--------------------------|------------------|
| 1    | syn_total_ratio          | 29,113.6         |
| 2    | syn_ack_ratio            | 20,920.7         |
| 3    | dns_any_queries          | 16,676.7         |
| 4    | ntp_monlist_queries      | 16,373.6         |
| 5    | ssdp_msearch_packets     | 16,045.6         |
| 6    | avg_dns_response_size    | 15,861.5         |
| 7    | portmap_getport_calls    | 15,375.3         |
| 8    | mssql_sqlbatch_packets   | 15,322.0         |
| 9    | tftp_rrq_packets         | 15,126.6         |
| 10   | netbios_name_queries     | 14,650.9         |

These features align with expected protocol-specific attack signatures, confirming the model learns meaningful patterns.

---

## 4. Model Comparison

Six alternative models were evaluated on the same train/val/test splits with identical preprocessing.

### Accuracy Summary

| Model                 | Val Accuracy | Test Accuracy | Notes |
|-----------------------|--------------|---------------|-------|
| **LightGBM**          | 98.37%       | 99.14%        | Primary model with feature importance |
| RandomForest          | 98.37%       | 99.14%        | Confusion into "mixed" class |
| HistGradientBoosting  | 98.46%       | 99.14%        | Confusion into "webddos" |
| MLP                   | 98.46%       | 99.14%        | Lower DNS precision in validation |
| KNN                   | 98.20%       | **99.23%**    | Best test accuracy |
| SGDClassifier         | 98.20%       | **99.23%**    | Tied best test accuracy |
| XGBoost               | 98.37%       | 99.14%        | Similar to RandomForest |

### Detailed Model Analysis

#### RandomForest / XGBoost
- **Confusion pattern**: Several classes leak into **"mixed"** (benign, ldap, mssql, portmap, syn, udp)
- **Test precision for mixed**: 0.93 (absorbs false positives from other classes)
- Strong overall performance but less precise boundary between mixed and single-vector attacks

#### HistGradientBoosting
- **Confusion pattern**: Similar to LightGBM, leakage into **"webddos"**
- Slightly higher validation accuracy (98.46%) but same test accuracy
- Lower webddos precision (0.90) due to false positives

#### MLP (Multi-Layer Perceptron)
- **Confusion pattern**: Multiple classes misclassified as **"dns"** in validation
- Validation DNS precision: 0.84 (recovered to 0.90 on test)
- Good generalization but neural network training introduces different error patterns

#### KNN (K-Nearest Neighbors)
- **Best test accuracy**: 99.23%
- **Confusion pattern**: Similar to RandomForest (leakage into "mixed")
- Non-parametric approach captures local decision boundaries well
- No interpretable feature importance

#### SGDClassifier
- **Tied best test accuracy**: 99.23%
- **Confusion pattern**: Multiple classes leak into **"mssql"** (particularly tftp, syn)
- Validation mssql precision: 0.82 (improved to 0.90 on test)
- Fast training, linear decision boundaries

### Per-Model Test Metrics

| Model                 | Weighted F1 | Macro Precision | Macro Recall |
|-----------------------|-------------|-----------------|--------------|
| LightGBM              | 0.992       | 0.99            | 0.99         |
| RandomForest          | 0.99        | 0.99            | 0.99         |
| HistGradientBoosting  | 0.99        | 0.99            | 0.99         |
| MLP                   | 0.99        | 0.99            | 0.99         |
| KNN                   | 0.99        | 1.00            | 0.99         |
| SGDClassifier         | 0.99        | 0.99            | 0.99         |
| XGBoost               | 0.99        | 0.99            | 0.99         |

---

## 5. Prediction Confidence

Sample predictions from LightGBM (first 10 test samples):

| Index | True Label | Predicted | Confidence |
|-------|------------|-----------|------------|
| 0     | snmp       | snmp      | 0.999      |
| 1     | ntp        | ntp       | 0.999      |
| 2     | syn        | syn       | 0.998      |
| 3     | netbios    | netbios   | 0.999      |
| 4     | ldap       | ldap      | 0.999      |
| 5     | benign     | benign    | 0.994      |
| 6     | netbios    | netbios   | 0.999      |
| 7     | snmp       | snmp      | 0.999      |
| 8     | portmap    | portmap   | 0.999      |
| 9     | udp        | udp       | 0.999      |

All models show high confidence (>0.99) for most predictions, indicating well-separated classes in feature space.

---

## 6. Key Findings

### Strengths
1. **High accuracy across all models** (99.14-99.23% test accuracy)
2. **Protocol-specific features work well**: syn_ratio, dns_any, ntp_monlist, etc. are top predictors
3. **Balanced performance**: No single class dominates errors
4. **High prediction confidence**: Most predictions exceed 0.99 confidence

### Weaknesses
1. **WebDDoS precision (LightGBM: 0.90)**: Some non-web traffic misclassified as webddos
2. **Benign recall (0.95)**: A few benign windows incorrectly labeled as attack
3. **"Mixed" class ambiguity**: Attracts false positives from single-attack classes

### Model Selection Rationale
**LightGBM is recommended** as the primary model because:
- Matches top-tier accuracy (99.14%)
- Provides interpretable feature importance (critical for security analysis)
- Fast inference suitable for real-time detection
- Smaller model footprint than ensemble methods

---

## 7. Limitations and Future Work

### Current Limitations
- **Same-run splits**: Train/val/test may share temporal patterns from the same capture runs
- **Limited attack variations**: Each attack type from controlled lab conditions
- **WebDDoS boundary**: Needs better separation from other TCP-based attacks

### Recommended Next Steps
1. **Per-run holdout validation**: Hold out entire capture runs as test set to measure true generalization
2. **Temporal validation**: Test on traffic captured at different times/network conditions
3. **WebDDoS feature engineering**: Add HTTP-specific features to improve webddos precision
4. **Production monitoring**: Deploy model with confidence thresholding and fallback to threshold detector for low-confidence predictions

---

## 8. Exported Artifacts

| File | Description |
|------|-------------|
| `lightgbm_model.txt` | Trained LightGBM model |
| `label_mapping.json` | Class index to label mapping |
| `feature_scaler.pkl` | StandardScaler for feature normalization |

---

## 9. Conclusion

All evaluated models achieve strong performance (>99% test accuracy) on this 14-class DDoS classification task. LightGBM provides the best balance of accuracy, interpretability, and inference speed for production deployment. The main area for improvement is validation on held-out capture runs to ensure the model generalizes beyond the training distribution.

Ring Buffer de Features - Explicación Completa                                                                                                                                                                                                                
  
  Concepto                                                                                                                                                                                                                                                         
  En lugar de escribir cada ventana a disco, guardamos las últimas N ventanas en un array circular en memoria:                                                                                                                                                  
  
  ┌────────────────────────────────────────────────────────────────────────┐
  │                         RING BUFFER (100 ventanas)                      │
  │                                                                        │
  │  Índice:    [0]   [1]   [2]   [3]  ...  [97]  [98]  [99]              │
  │              │     │     │     │          │     │     │                │
  │              ▼     ▼     ▼     ▼          ▼     ▼     ▼                │
  │  Features:  F₀    F₁    F₂    F₃   ...   F₉₇   F₉₈   F₉₉              │
  │             42    42    42    42         42    42    42    floats      │
  │                                                 ▲                      │
  │                                                 │                      │
  │                                            write_idx                   │
  │                                                                        │
  │  Cuando write_idx llega a 100 → vuelve a 0 (sobrescribe el más viejo) │
  └────────────────────────────────────────────────────────────────────────┘

  Flujo Actual vs Propuesto

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  FLUJO ACTUAL                                                           │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  Coordinator (cada 50ms)                                                │
  │       │                                                                 │
  │       ├── Agregar contadores de workers                                 │
  │       ├── Calcular 42 features                                          │
  │       ├── Detectar por thresholds                                       │
  │       │                                                                 │
  │       └── fprintf(log_file, ...) ──────► DISCO (.log)                  │
  │                      │                        │                         │
  │                 [BLOQUEANTE]            [I/O LENTO]                     │
  │                                               │                         │
  │                                               ▼                         │
  │                                    Python lee .log                      │
  │                                    Entrena modelo                       │
  │                                    Exporta .model                       │
  │                                               │                         │
  │                                               ▼                         │
  │                               Detector carga modelo (siguiente sesión)  │
  │                                                                         │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  FLUJO PROPUESTO (Ring Buffer)                                          │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  Coordinator (cada 50ms)                                                │
  │       │                                                                 │
  │       ├── Agregar contadores de workers                                 │
  │       ├── Calcular 42 features                                          │
  │       ├── Detectar por thresholds                                       │
  │       │                                                                 │
  │       ├── ring_buffer[idx++] = features ──► MEMORIA (0.001ms)          │
  │       │              │                                                  │
  │       │         [NO BLOQUEANTE]                                         │
  │       │                                                                 │
  │       └── ML inference sobre ring_buffer ──► Clasificación inmediata   │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  Estructura de Datos

  /* ============== Ring Buffer para ML ============== */

  #define RING_BUFFER_SIZE 100      /* Últimas 100 ventanas (5 segundos) */
  #define ML_FEATURE_COUNT 42

  /* Una entrada del ring buffer = 1 ventana de 50ms */
  struct feature_window {
      /* Timestamp */
      uint64_t timestamp_tsc;       /* Ciclos de CPU */
      uint64_t window_id;           /* Número de ventana secuencial */

      /* 42 features (mismo formato que ML) */
      float features[ML_FEATURE_COUNT];

      /* Metadata para debugging */
      uint8_t attack_detected;      /* 0=no, 1=sí (por thresholds) */
      uint8_t attack_type;          /* Tipo detectado por thresholds */
      uint8_t ml_prediction;        /* Predicción del modelo */
      float ml_confidence;          /* Confianza del modelo */
  } __attribute__((packed));        /* 42*4 + 8 + 8 + 4 = 188 bytes */

  /* Ring buffer global */
  struct feature_ring_buffer {
      struct feature_window windows[RING_BUFFER_SIZE];
      uint32_t write_idx;           /* Siguiente posición a escribir */
      uint32_t count;               /* Ventanas válidas (hasta llenar) */
      uint64_t total_windows;       /* Total histórico */

      /* Estadísticas del buffer */
      uint64_t overwrites;          /* Veces que sobrescribimos */
  } __rte_cache_aligned;

  static struct feature_ring_buffer g_ring_buffer;

  Memoria total: 188 bytes × 100 ventanas = ~19 KB (vs MBs en disco)

  Cómo cambia el Coordinator

  /* Función para guardar ventana en ring buffer */
  static inline void ring_buffer_push(const struct ml_features *features,
                                       bool attack_detected,
                                       uint8_t attack_type)
  {
      uint32_t idx = g_ring_buffer.write_idx;
      struct feature_window *w = &g_ring_buffer.windows[idx];

      /* Guardar timestamp */
      w->timestamp_tsc = rte_rdtsc();
      w->window_id = g_ring_buffer.total_windows++;

      /* Copiar features */
      memcpy(w->features, features, sizeof(float) * ML_FEATURE_COUNT);

      /* Metadata */
      w->attack_detected = attack_detected ? 1 : 0;
      w->attack_type = attack_type;
      w->ml_prediction = 0;    /* Se llenará después de inference */
      w->ml_confidence = 0.0f;

      /* Avanzar índice circular */
      g_ring_buffer.write_idx = (idx + 1) % RING_BUFFER_SIZE;
      if (g_ring_buffer.count < RING_BUFFER_SIZE) {
          g_ring_buffer.count++;
      } else {
          g_ring_buffer.overwrites++;
      }
  }

  /* En detect_attacks(), después de calcular features: */
  static void detect_attacks(uint64_t cur_tsc, uint64_t hz)
  {
      // ... código existente de detección ...

      /* Construir vector de features */
      struct ml_features features;
      build_feature_vector(&features, ...);  /* Rellena las 42 features */

      /* ========== CAMBIO: Ring buffer en vez de log ========== */
      ring_buffer_push(&features, attack_detected, detected_attack_type);

      /* ML inference INMEDIATO (sin I/O) */
      if (g_ml_model != NULL) {
          struct ml_prediction pred;
          ml_predict(g_ml_model, &features, &pred);

          /* Guardar predicción en el buffer */
          uint32_t last_idx = (g_ring_buffer.write_idx + RING_BUFFER_SIZE - 1)
                             % RING_BUFFER_SIZE;
          g_ring_buffer.windows[last_idx].ml_prediction = pred.predicted_class;
          g_ring_buffer.windows[last_idx].ml_confidence = pred.confidence;
      }
      /* ======================================================= */
  }

  Ventajas del Ring Buffer

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  COMPARACIÓN DE RENDIMIENTO                                             │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  Operación          │  Log a Disco    │  Ring Buffer                   │
  │  ───────────────────┼─────────────────┼────────────────────────────────│
  │  Latencia escritura │  0.1 - 10 ms    │  < 0.001 ms (memcpy)           │
  │  Bloqueante         │  SÍ (I/O)       │  NO                            │
  │  Memoria usada      │  Crece sin fin  │  Fija (19 KB)                  │
  │  Pierde datos       │  NO (persiste)  │  SÍ (sobrescribe viejos)       │
  │  ML inference       │  Offline        │  INLINE (mismo ciclo)          │
  │  Acceso histórico   │  5+ segundos    │  Inmediato (en RAM)            │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  Casos de Uso del Ring Buffer

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  1. ML INFERENCE EN TIEMPO REAL                                         │
  │  ───────────────────────────────                                        │
  │  Cada 50ms:                                                             │
  │    features = ring_buffer[current]                                      │
  │    prediction = ml_predict(model, features)                             │
  │    → Clasificación en < 5ms                                             │
  │                                                                         │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  2. DETECCIÓN DE TENDENCIAS (últimos 5 segundos)                        │
  │  ──────────────────────────────────────────────                         │
  │  Analizar últimas 100 ventanas:                                         │
  │    avg_attack_pps = promedio(ring_buffer[*].features[ATTACK_PPS])       │
  │    if (tendencia_creciente(avg_attack_pps))                             │
  │        → "Ataque escalando"                                             │
  │                                                                         │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  3. EXPORTAR PARA ENTRENAMIENTO (bajo demanda)                          │
  │  ─────────────────────────────────────────────                          │
  │  Cuando el usuario lo pida (SIGURS1 o comando):                         │
  │    dump_ring_buffer_to_file("session_features.bin")                     │
  │    → Solo escribe a disco cuando es necesario                           │
  │                                                                         │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  4. DETECCIÓN DE ANOMALÍAS (comparación temporal)                       │
  │  ────────────────────────────────────────────────                       │
  │  current = ring_buffer[now]                                             │
  │  historical_avg = promedio(ring_buffer[now-100 : now-1])                │
  │  if (divergencia(current, historical_avg) > threshold)                  │
  │      → "Comportamiento anómalo detectado"                               │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  Arquitectura Completa con Ring Buffer

                           ┌────────────────────┐
                           │        NIC         │
                           └─────────┬──────────┘
                                     │
                           RSS (hash 5-tupla)
                                     │
          ┌──────────┬───────────────┼───────────────┬──────────┐
          ▼          ▼               ▼               ▼          ▼
     ┌─────────┐┌─────────┐    ┌─────────┐    ┌─────────┐┌─────────┐
     │Worker 1 ││Worker 2 │    │Worker 3 │    │  ...    ││Worker 14│
     │ +Sketch ││ +Sketch │    │ +Sketch │    │         ││ +Sketch │
     └────┬────┘└────┬────┘    └────┬────┘    └────┬────┘└────┬────┘
          │          │              │              │          │
          └──────────┴──────────────┼──────────────┴──────────┘
                                    │
                           Cada 50ms (merge)
                                    │
                      ┌─────────────▼─────────────┐
                      │       COORDINATOR          │
                      │                            │
                      │  1. Merge sketches         │
                      │  2. Agregar contadores     │
                      │  3. Calcular 42 features   │
                      │  4. Threshold detection    │
                      │           │                │
                      │           ▼                │
                      │  ┌─────────────────────┐   │
                      │  │    RING BUFFER      │   │
                      │  │  [w0][w1]...[w99]   │   │
                      │  │      (19 KB)        │   │
                      │  └──────────┬──────────┘   │
                      │             │              │
                      │             ▼              │
                      │  5. ML Inference (1-3ms)   │
                      │             │              │
                      │             ▼              │
                      │  6. Clasificación final    │
                      │     (14 clases, 98.41%)    │
                      │                            │
                      └────────────────────────────┘
                                    │
                      ┌─────────────┴─────────────┐
                      ▼                           ▼
              [ALERT: SYN_FLOOD]          [Dump a disco]
              (tiempo real)               (bajo demanda)

  Implicaciones
  ┌──────────────────┬───────────────────────────────────────────────────────────────────────────────┐
  │     Aspecto      │                                  Implicación                                  │
  ├──────────────────┼───────────────────────────────────────────────────────────────────────────────┤
  │ Pérdida de datos │ Solo guardamos últimos 5s. Para training, necesitamos exportar periódicamente │
  ├──────────────────┼───────────────────────────────────────────────────────────────────────────────┤
  │ Persistencia     │ Si el detector muere, perdemos el buffer. Solución: dump cada N segundos      │
  ├──────────────────┼───────────────────────────────────────────────────────────────────────────────┤
  │ Entrenamiento    │ Ya no es automático. Hay que exportar explícitamente para reentrenar          │
  ├──────────────────┼───────────────────────────────────────────────────────────────────────────────┤
  │ Rendimiento      │ Eliminamos I/O completamente del fast-path                                    │
  ├──────────────────┼───────────────────────────────────────────────────────────────────────────────┤
  │ Complejidad      │ Código más complejo, pero mejor arquitectura                                  │
  └──────────────────┴───────────────────────────────────────────────────────────────────────────────┘