# Sketch Model - Entrenamiento con features de OctoSketch

Entrenamiento de modelos ML usando **solo features de sketch** (14 features del OctoSketch
multi-escala + Ring Buffer temporal), extraidas de los mismos logs del detector.

Los modelos DPI (42 features) y DPI+Sketch (56 features) ya estan entrenados en `ml_system/`.
Este directorio entrena el tercer caso: **solo sketch**.

## Features de Sketch (14)

| # | Feature | Fuente |
|---|---------|--------|
| 1 | `delta_pps_5w` | Ring Buffer - cambio PPS en 250ms |
| 2 | `delta_pps_10w` | Ring Buffer - cambio PPS en 500ms |
| 3 | `pps_variance` | Ring Buffer - varianza ultimas 20 ventanas |
| 4 | `pps_baseline` | Ring Buffer - media movil |
| 5 | `ratio_vs_baseline` | Ring Buffer - ratio actual/baseline |
| 6 | `top_ip_pps_50ms` | OctoSketch - top IP PPS escala 50ms |
| 7 | `top_ip_pps_1s` | OctoSketch - top IP PPS escala 1s |
| 8 | `top_ip_pps_1min` | OctoSketch - top IP PPS escala 1min |
| 9 | `ratio_50ms_1min` | OctoSketch - burst ratio 50ms/1min |
| 10 | `num_heavy_hitters` | OctoSketch - IPs sobre threshold |
| 11 | `ip_concentration` | OctoSketch - top1/total |
| 12 | `new_ips_ratio` | Ratio IPs nuevas vs conocidas |
| 13 | `attack_entropy` | Entropia distribucion de ataques |
| 14 | `adaptive_threshold` | Threshold adaptativo calculado |

## Clases (14)

`benign`, `mixed`, `dns`, `ldap`, `mssql`, `netbios`, `ntp`, `portmap`, `snmp`, `ssdp`, `syn`, `tftp`, `udp`, `webddos`

## Directory Structure

```
sketch_model/
├── feature_groups.py              # Definicion de los 3 grupos de features
├── 01_data_collection/
│   └── feature_extractor.py       # Extrae las 56 features de logs (misma que original)
├── 02_training/
│   ├── prepare_dataset.py         # Combina CSVs + split train/val/test
│   ├── train_ablation.py          # LightGBM con --feature-group sketch
│   ├── evaluate_ablation.py       # Evaluacion del modelo entrenado
│   ├── run_full_ablation.py       # Automatizado: entrena + evalua + compara
│   └── model_compare/
│       └── run_compare.py         # RF/XGB/MLP/KNN/SGD con --feature-group sketch
├── datasets/
│   ├── processed/                 # CSVs extraidos de los logs
│   └── splits/                    # train.csv, val.csv, test.csv
└── README.md
```

## Quick Start (en CloudLab node-monitor)

### Step 1: Extraer features de los logs

```bash
cd /local/dpdk_100g/mira/ml_system/sketch_model/01_data_collection

# Benign
for f in ../../datasets/raw_logs/2/benign_baseline_run*.log; do
    run=$(echo $f | grep -oP 'run\d+')
    python3 feature_extractor.py \
        --input "$f" \
        --output ../datasets/processed/benign_${run}.csv \
        --label benign
done

# Cada tipo de ataque
for attack in dns ldap mssql netbios ntp portmap snmp ssdp syn tftp udp webddos; do
    for f in ../../datasets/raw_logs/2/attack_${attack}_run*.log; do
        run=$(echo $f | grep -oP 'run\d+')
        python3 feature_extractor.py \
            --input "$f" \
            --output ../datasets/processed/${attack}_${run}.csv \
            --label ${attack}
    done
done

# Mixed
for f in ../../datasets/raw_logs/2/mixed_traffic_run*.log; do
    run=$(echo $f | grep -oP 'run\d+')
    python3 feature_extractor.py \
        --input "$f" \
        --output ../datasets/processed/mixed_${run}.csv \
        --label mixed
done
```

### Step 2: Preparar dataset (combinar + split)

```bash
cd /local/dpdk_100g/mira/ml_system/sketch_model/02_training

python3 prepare_dataset.py \
    --input ../datasets/processed/*.csv \
    --output ../datasets/splits/ \
    --train-ratio 0.7 \
    --val-ratio 0.15 \
    --test-ratio 0.15
```

### Step 3: Entrenar y evaluar (solo sketch)

```bash
# Opcion A: Todo automatico (LightGBM + RF + XGB + MLP + KNN + SGD)
python3 run_full_ablation.py \
    --train ../datasets/splits/train.csv \
    --val ../datasets/splits/val.csv \
    --test ../datasets/splits/test.csv \
    --output ./results/ \
    --groups sketch

# Opcion B: Solo LightGBM (mas rapido)
python3 run_full_ablation.py \
    --train ../datasets/splits/train.csv \
    --val ../datasets/splits/val.csv \
    --test ../datasets/splits/test.csv \
    --output ./results/ \
    --groups sketch \
    --lightgbm-only
```

### Step 3b: Paso a paso manual

```bash
# 1. Entrenar LightGBM con sketch
python3 train_ablation.py \
    --train ../datasets/splits/train.csv \
    --val ../datasets/splits/val.csv \
    --output ./results/sketch/lightgbm/ \
    --feature-group sketch

# 2. Evaluar en test set
python3 evaluate_ablation.py \
    --model ./results/sketch/lightgbm/lightgbm_model.txt \
    --test ../datasets/splits/test.csv

# 3. Comparacion de modelos alternativos
cd model_compare
python3 run_compare.py \
    --train ../../datasets/splits/train.csv \
    --val ../../datasets/splits/val.csv \
    --test ../../datasets/splits/test.csv \
    --output-dir ../results/sketch/alt_models/ \
    --feature-group sketch
```

## Output

```
results/
├── ablation_results.json              # Resultados combinados
├── ablation_summary.csv               # CSV para graficas
└── sketch/
    ├── lightgbm/
    │   ├── lightgbm_model.txt         # Modelo entrenado
    │   ├── evaluation_results.json    # Metricas por clase
    │   ├── feature_importance.csv     # Importancia de las 14 features
    │   ├── training_metadata.json     # Hiperparametros usados
    │   ├── label_mapping.json         # Indice -> nombre de clase
    │   └── feature_scaler.pkl         # StandardScaler
    └── alt_models/
        ├── summary.json               # Resultados de todos los modelos
        ├── randomforest/
        ├── histgradientboosting/
        ├── mlp/
        ├── knn/
        ├── sgdclassifier/
        └── xgboost/                   # (si esta instalado)
```

## Comparacion con modelos existentes

Una vez entrenado, comparar con los resultados que ya tienes en `ml_system/results/model_results.md`:

| Modelo | Features | Grupo | Accuracy esperada |
|--------|----------|-------|-------------------|
| LightGBM (existente) | 42 | DPI | 99.14% |
| LightGBM (existente) | 56 | DPI+Sketch | 99.14% |
| LightGBM (este) | 14 | **Sketch** | ~40-70% |

La diferencia demuestra el valor de la inspeccion profunda de protocolo frente a las
features estadisticas del sketch para clasificacion multi-clase (14 clases).
