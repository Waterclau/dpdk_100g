# Comandos de entrenamiento y testing - Sketch-ADV (64 features)

Ruta de los .bin: `/local/dpdk_100g/mira/ml_system/datasets/sketches/`
Ruta de los .log: `/local/dpdk_100g/mira/ml_system/datasets/raw_logs/2/`

## 0. Convertir .log a .bin (si solo tienes logs)

```bash
cd /local/dpdk_100g/mira/ml_system

# Mixed traffic (4 runs)
python3 datasets/log_to_sketch_bin.py \
    --input datasets/raw_logs/2/mixed_traffic_run1.log \
    --output datasets/sketches/mixed_sketch_adv_run1.bin

python3 datasets/log_to_sketch_bin.py \
    --input datasets/raw_logs/2/mixed_traffic_run2.log \
    --output datasets/sketches/mixed_sketch_adv_run2.bin

python3 datasets/log_to_sketch_bin.py \
    --input datasets/raw_logs/2/mixed_traffic_run3.log \
    --output datasets/sketches/mixed_sketch_adv_run3.bin

python3 datasets/log_to_sketch_bin.py \
    --input datasets/raw_logs/2/mixed_traffic_run4.log \
    --output datasets/sketches/mixed_sketch_adv_run4.bin

# O todos de golpe:
python3 datasets/log_to_sketch_bin.py \
    --input-dir datasets/raw_logs/2 \
    --output-dir datasets/sketches \
    --pattern "mixed_traffic_run*.log"

# Tambien sirve para cualquier otro .log:
python3 datasets/log_to_sketch_bin.py \
    --input-dir datasets/raw_logs/2 \
    --output-dir datasets/sketches \
    --pattern "*.log"
```

## 1. Convertir .bin a CSV

```bash
cd /local/dpdk_100g/mira/ml_system/sketch_adv_model

# DNS
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/dns_sketch_adv_run1.bin \
    --output datasets/processed/dns_run1.csv \
    --attack-type dns \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/dns_sketch_adv_run2.bin \
    --output datasets/processed/dns_run2.csv \
    --attack-type dns \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# NTP
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/ntp_sketch_adv_run1.bin \
    --output datasets/processed/ntp_run1.csv \
    --attack-type ntp \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# SNMP
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/snmp_sketch_adv_run1.bin \
    --output datasets/processed/snmp_run1.csv \
    --attack-type snmp \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# SSDP
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/ssdp_sketch_adv_run1.bin \
    --output datasets/processed/ssdp_run1.csv \
    --attack-type ssdp \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# PORTMAP
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/portmap_sketch_adv_run1.bin \
    --output datasets/processed/portmap_run1.csv \
    --attack-type portmap \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# NETBIOS
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/netbios_sketch_adv_run1.bin \
    --output datasets/processed/netbios_run1.csv \
    --attack-type netbios \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# LDAP
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/ldap_sketch_adv_run1.bin \
    --output datasets/processed/ldap_run1.csv \
    --attack-type ldap \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# MSSQL
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/mssql_sketch_adv_run1.bin \
    --output datasets/processed/mssql_run1.csv \
    --attack-type mssql \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# TFTP
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/tftp_sketch_adv_run1.bin \
    --output datasets/processed/tftp_run1.csv \
    --attack-type tftp \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# SYN
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/syn_sketch_adv_run1.bin \
    --output datasets/processed/syn_run1.csv \
    --attack-type syn \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# UDP
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/udp_sketch_adv_run1.bin \
    --output datasets/processed/udp_run1.csv \
    --attack-type udp \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# WEBDDOS
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/webddos_sketch_adv_run1.bin \
    --output datasets/processed/webddos_run1.csv \
    --attack-type webddos \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# MIXED (multiples ataques simultaneos)
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/mixed_sketch_adv_run1.bin \
    --output datasets/processed/mixed_run1.csv \
    --attack-type mixed \
    --baseline-before 50 --attack-duration 100 --baseline-after 50

# BENIGN (solo baseline, sin ataque)
python3 01_data_collection/bin_to_csv.py \
    --input /local/dpdk_100g/mira/ml_system/datasets/sketches/benign_sketch_adv_run1.bin \
    --output datasets/processed/benign_run1.csv \
    --attack-type benign \
    --baseline-before 200 --attack-duration 0 --baseline-after 0
```

### Shortcut: convertir todos los .bin de golpe

```bash
cd /local/dpdk_100g/mira/ml_system/sketch_adv_model

for f in /local/dpdk_100g/mira/ml_system/datasets/sketches/*.bin; do
    fname=$(basename "$f" .bin)
    attack=$(echo "$fname" | sed -E 's/^([a-z_]+)_sketch_adv.*/\1/')
    run=$(echo "$fname" | grep -oP 'run\d+' || echo "run1")
    echo "Converting: $fname -> ${attack}_${run}.csv"
    python3 01_data_collection/bin_to_csv.py \
        --input "$f" \
        --output datasets/processed/${attack}_${run}.csv \
        --attack-type "$attack" \
        --baseline-before 50 --attack-duration 100 --baseline-after 50
done
```

## 2. Preparar dataset (split train/val/test)

```bash
python3 02_training/prepare_dataset.py \
    --input datasets/processed/*.csv \
    --output datasets/splits/ \
    --train-ratio 0.7 --val-ratio 0.15 --test-ratio 0.15
```

## 3. Entrenar LightGBM

```bash
python3 02_training/train_sketch_adv.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --output 02_training/results/sketch_adv/lightgbm/
```

## 4. Evaluar en test set

```bash
python3 02_training/evaluate_sketch_adv.py \
    --model 02_training/results/sketch_adv/lightgbm/lightgbm_model.txt \
    --test datasets/splits/test.csv
```

## 5. Comparar modelos (RF, HistGBM, MLP, KNN, SGD, XGBoost)

```bash
python3 02_training/model_compare/run_compare.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --test datasets/splits/test.csv \
    --output-dir 02_training/results/sketch_adv/alt_models/
```

## 6. Pipeline completo (pasos 3+4+5 juntos)

```bash
python3 02_training/run_full_pipeline.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --test datasets/splits/test.csv \
    --output 02_training/results/

# Solo LightGBM (sin comparacion):
python3 02_training/run_full_pipeline.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --test datasets/splits/test.csv \
    --output 02_training/results/ \
    --lightgbm-only
```

## Resumen de archivos generados

```
02_training/results/
  sketch_adv/
    lightgbm/
      lightgbm_model.txt          # Modelo entrenado
      label_mapping.json          # Mapeo clase -> indice
      feature_scaler.pkl          # StandardScaler
      feature_columns.json        # Lista de 64 features
      training_metadata.json      # Metadata del entrenamiento
      feature_importance.csv      # Importancia de features
      evaluation_results.json     # Metricas en test set
    alt_models/
      summary.json                # Comparacion de todos los modelos
      randomforest/model.pkl
      histgradientboosting/model.pkl
      mlp/model.pkl
      knn/model.pkl
      sgdclassifier/model.pkl
      xgboost/model.pkl           # (si esta instalado)
```
