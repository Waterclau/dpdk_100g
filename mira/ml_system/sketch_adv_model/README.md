# sketch_adv_model: ML Pipeline para Sketch-ADV (64 features)

Pipeline de ML para entrenar modelos con las 64 features del modo `--sketch-adv` del detector.

## Input

Archivos `.bin` producidos por `detector_system` con `--sketch-adv`:
```bash
cd mira/detector_system
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- \
    --sketch-adv /tmp/dns_sketch_adv_run1.bin -p 0
```

## Estructura

```
sketch_adv_model/
  feature_groups.py              # 64 features (14 global + 48 per-proto + 2 pkt size)
  run_pipeline.sh                # Pipeline completo .bin -> modelo
  README.md

  01_data_collection/
    bin_to_csv.py                # .bin -> .csv (struct.unpack + etiquetado temporal)

  02_training/
    prepare_dataset.py           # Combina CSVs + split train/val/test
    train_sketch_adv.py          # Entrena LightGBM (64 features)
    evaluate_sketch_adv.py       # Evalua modelo en test set
    run_full_pipeline.py         # Pipeline completo: LightGBM + comparacion
    model_compare/
      run_compare.py             # Compara RF, HistGBM, MLP, KNN, SGD, XGBoost

  datasets/
    processed/                   # CSVs individuales por run
    splits/                      # train.csv, val.csv, test.csv
```

## 64 Features

| Grupo | Cantidad | Descripcion |
|-------|----------|-------------|
| Global sketch | 14 | OctoSketch multi-escala + Ring Buffer temporal |
| Per-protocol | 48 | 4 metricas x 12 protocolos (DNS, NTP, SNMP, ...) |
| Packet size | 2 | avg_packet_size, packet_size_variance |

### Per-protocol (12 protocolos):
DNS, NTP, SNMP, SSDP, PortMap, NetBIOS, LDAP, MSSQL, TFTP, SYN, HTTP, UDP-Other

### 4 metricas por protocolo:
- `pps_<proto>`: Packets per second
- `heavy_hitters_<proto>`: IPs que exceden umbral
- `ip_concentration_<proto>`: Concentracion del top IP
- `ratio_vs_total_<proto>`: Ratio vs trafico global

## Uso rapido

```bash
# Pipeline completo
bash run_pipeline.sh /tmp/

# Espera archivos como: /tmp/dns_sketch_adv_run1.bin
```

## Paso a paso

### 1. Convertir .bin a CSV
```bash
python3 01_data_collection/bin_to_csv.py \
    --input /tmp/dns_sketch_adv_run1.bin \
    --output datasets/processed/dns_run1.csv \
    --attack-type dns \
    --baseline-before 50 --attack-duration 100 --baseline-after 50
```

### 2. Preparar dataset
```bash
python3 02_training/prepare_dataset.py \
    --input datasets/processed/*.csv \
    --output datasets/splits/
```

### 3. Entrenar
```bash
python3 02_training/train_sketch_adv.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --output 02_training/results/sketch_adv/lightgbm/
```

### 4. Evaluar
```bash
python3 02_training/evaluate_sketch_adv.py \
    --model 02_training/results/sketch_adv/lightgbm/lightgbm_model.txt \
    --test datasets/splits/test.csv
```

### 5. Comparar modelos
```bash
python3 02_training/model_compare/run_compare.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --test datasets/splits/test.csv \
    --output-dir 02_training/results/sketch_adv/alt_models/
```

## Formato binario (.bin)

Record de 528 bytes (packed, little-endian):

| Offset | Bytes | Tipo | Campo |
|--------|-------|------|-------|
| 0 | 4 | uint32 | Magic (0x534B4156 "SKAV") |
| 4 | 4 | uint32 | Version (1) |
| 8 | 8 | uint64 | timestamp_ns |
| 16 | 112 | double[14] | 14 global sketch features |
| 128 | 96 | double[12] | pps_proto[12] |
| 224 | 96 | double[12] | heavy_hitters_proto[12] |
| 320 | 96 | double[12] | ip_concentration_proto[12] |
| 416 | 96 | double[12] | ratio_vs_total_proto[12] |
| 512 | 8 | double | avg_packet_size |
| 520 | 8 | double | packet_size_variance |

## Etiquetado temporal

Para experimentos estructurados (50s + 100s + 50s = 200s):

```
t=0         t=50s       t=150s      t=200s
|-- benign --|-- attack --|-- benign --|
```

Etiquetado automatico por `bin_to_csv.py` basado en `timestamp_ns`.
