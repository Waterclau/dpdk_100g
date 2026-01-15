# Dataset Collection Strategy - CIC-DDoS-2019

## Tu Setup Actual (PCAPs Mezclados)

Tienes los PCAPs del CIC-DDoS-2019 remapeados en:
```
/proj/softmeasure-PG0/CICD/remapped/
```

**Problema:** Cuando envías con `--pcap-dir`, TODOS los PCAPs se envían mezclados.
**Resultado:** El log contiene tráfico de TODOS los ataques (NTP, DNS, SNMP, SSDP, etc.) mezclados.

---

## Opción 1: Sistema de 3 Clases (RECOMENDADO para empezar)

### Ventajas
- ✅ Funciona con tu setup actual (no cambios)
- ✅ Las 46 features siguen siendo útiles
- ✅ Hiperparámetros anti-overfitting aplicados
- ✅ Menos tiempo de recolección

### Cómo Hacerlo

```bash
cd /local/dpdk_100g/mira/detector_system_ml

# ========== RECOLECTA DATOS (3 clases × 3 runs = 9 runs totales) ==========

# 1. Benign (3 runs × 30 min = 90 min)
for i in 1 2 3; do
    echo "=== Benign Run $i ==="

    # Lanzar detector
    sudo timeout 1800 ./detectorML -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
        2>&1 | tee ../ml_system/datasets/raw_logs/benign_run${i}.log &

    DETECTOR_PID=$!
    sleep 5

    # Lanzar sender (desde node-controller)
    sudo timeout 1795 /local/dpdk_100g/mira/benign_generator/dpdk_pcap_sender \
        -l 0-7 -n 4 -w 0000:41:00.0 -- \
        /local/dpdk_100g/mira/benign_20M.pcap \
        --adaptive --rate-gbps 12 --loop

    wait $DETECTOR_PID
    echo "Benign run $i completed"
done

# 2. Attack (3 runs × 30 min = 90 min) - TODOS LOS ATAQUES MEZCLADOS
for i in 1 2 3; do
    echo "=== Attack (Mixed) Run $i ==="

    # Lanzar detector
    sudo timeout 1800 ./detectorML -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
        2>&1 | tee ../ml_system/datasets/raw_logs/attack_run${i}.log &

    DETECTOR_PID=$!
    sleep 5

    # Lanzar sender con TODOS los PCAPs (desde node-tg)
    sudo timeout 1795 /local/dpdk_100g/mira/attack_sender/dpdk_pcap_sender_v2 \
        -l 0-7 -n 4 -w 0000:41:00.0 -- \
        --pcap-dir /proj/softmeasure-PG0/CICD/remapped/ \
        --rate-gbps 12

    wait $DETECTOR_PID
    echo "Attack run $i completed"
done

# 3. Mixed (3 runs × 30 min = 90 min) - Benign + Attack simultáneo
for i in 1 2 3; do
    echo "=== Mixed Run $i ==="

    # Lanzar detector
    sudo timeout 1800 ./detectorML -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
        2>&1 | tee ../ml_system/datasets/raw_logs/mixed_run${i}.log &

    DETECTOR_PID=$!
    sleep 5

    # Lanzar benign sender (desde node-controller)
    sudo timeout 1795 /local/dpdk_100g/mira/benign_generator/dpdk_pcap_sender \
        -l 0-7 -n 4 -w 0000:41:00.0 -- \
        /local/dpdk_100g/mira/benign_20M.pcap \
        --adaptive --rate-gbps 6 --loop &

    # Lanzar attack sender (desde node-tg)
    sudo timeout 1795 /local/dpdk_100g/mira/attack_sender/dpdk_pcap_sender_v2 \
        -l 0-7 -n 4 -w 0000:41:00.1 -- \
        --pcap-dir /proj/softmeasure-PG0/CICD/remapped/ \
        --rate-gbps 6 &

    wait
    wait $DETECTOR_PID
    echo "Mixed run $i completed"
done

echo "=== DATA COLLECTION COMPLETE ==="
echo "Total time: 270 minutes (4.5 hours)"
echo "Expected samples: ~2700 (9 runs × 300 samples/run)"
```

### Extracción de Features

```bash
cd /local/dpdk_100g/mira/ml_system/01_data_collection

# Extraer features con etiquetas de 3 clases
for i in 1 2 3; do
    python3 feature_extractor.py \
        --input ../datasets/raw_logs/benign_run${i}.log \
        --output ../datasets/processed/benign_run${i}.csv \
        --label benign

    python3 feature_extractor.py \
        --input ../datasets/raw_logs/attack_run${i}.log \
        --output ../datasets/processed/attack_run${i}.csv \
        --label attack    # <-- Genérico: todos los ataques mezclados

    python3 feature_extractor.py \
        --input ../datasets/raw_logs/mixed_run${i}.log \
        --output ../datasets/processed/mixed_run${i}.csv \
        --label mixed
done

echo "Feature extraction complete"
echo "Files created: 9 CSV files"
```

### Resultado Esperado

```
Classes: ['benign', 'attack', 'mixed']
Features: 46 (14 original + 26 protocol-specific + 6 derived)
Samples: ~2700 total (900 per class)
Validation accuracy: 85-95% (realistic, not 100%)

Per-class performance:
  benign: 90-95% precision/recall
  attack: 88-94% precision/recall (all attack types lumped together)
  mixed:  85-92% precision/recall
```

**Qué aprenderá el modelo:**
- ✅ Distingue tráfico benign vs attack
- ✅ Las features de protocolo (NTP, DNS, SNMP) ayudan aunque no sepa el nombre
- ✅ Aprende patrones generales de DDoS
- ❌ NO puede identificar tipo específico de ataque (solo sabe que es "attack")

---

## Opción 2: Multi-Class Real (Ataques Separados)

### Requisitos
1. Necesitas organizar los PCAPs por tipo de ataque
2. Enviar cada tipo separadamente
3. Mucho más tiempo de recolección (8-15 horas)

### Paso 1: Identificar Qué PCAP Contiene Qué Ataque

Los PCAPs del CIC-DDoS-2019 probablemente tienen nombres como:
```
DrDoS_NTP.pcap
DrDoS_DNS.pcap
DrDoS_SNMP.pcap
DrDoS_SSDP.pcap
Portmap.pcap
NetBIOS.pcap
LDAP.pcap
MSSQL.pcap
UDP-lag.pcap
Syn.pcap
```

**Script para listar PCAPs por tipo:**

```bash
#!/bin/bash
# Analizar nombres de archivos en la carpeta remapped

cd /proj/softmeasure-PG0/CICD/remapped/

echo "=== ANALYZING PCAP FILES IN REMAPPED DIRECTORY ==="
echo ""

# NTP
echo "[NTP Attack]"
ls -lh *ntp* *NTP* 2>/dev/null | awk '{print $9, $5}'

# DNS
echo -e "\n[DNS Attack]"
ls -lh *dns* *DNS* 2>/dev/null | awk '{print $9, $5}'

# SNMP
echo -e "\n[SNMP Attack]"
ls -lh *snmp* *SNMP* 2>/dev/null | awk '{print $9, $5}'

# SSDP
echo -e "\n[SSDP Attack]"
ls -lh *ssdp* *SSDP* 2>/dev/null | awk '{print $9, $5}'

# PortMap
echo -e "\n[PortMap Attack]"
ls -lh *portmap* *Portmap* 2>/dev/null | awk '{print $9, $5}'

# NetBIOS
echo -e "\n[NetBIOS Attack]"
ls -lh *netbios* *NetBIOS* 2>/dev/null | awk '{print $9, $5}'

# LDAP
echo -e "\n[LDAP Attack]"
ls -lh *ldap* *LDAP* 2>/dev/null | awk '{print $9, $5}'

# MSSQL
echo -e "\n[MSSQL Attack]"
ls -lh *mssql* *MSSQL* 2>/dev/null | awk '{print $9, $5}'

# UDP
echo -e "\n[UDP Flood]"
ls -lh *udp* *UDP* 2>/dev/null | grep -v lag | awk '{print $9, $5}'

# UDP-Lag
echo -e "\n[UDP-Lag Attack]"
ls -lh *lag* *Lag* 2>/dev/null | awk '{print $9, $5}'

# SYN
echo -e "\n[SYN Flood]"
ls -lh *syn* *Syn* *SYN* 2>/dev/null | awk '{print $9, $5}'

# WebDDoS
echo -e "\n[WebDDoS Attack]"
ls -lh *web* *Web* *http* *HTTP* 2>/dev/null | awk '{print $9, $5}'

# TFTP
echo -e "\n[TFTP Attack]"
ls -lh *tftp* *TFTP* 2>/dev/null | awk '{print $9, $5}'

echo -e "\n=== ANALYSIS COMPLETE ==="
```

### Paso 2: Organizar PCAPs por Carpeta

```bash
#!/bin/bash
# Organizar PCAPs en carpetas por tipo de ataque

REMAPPED_DIR="/proj/softmeasure-PG0/CICD/remapped"
ORGANIZED_DIR="/proj/softmeasure-PG0/CICD/organized"

mkdir -p ${ORGANIZED_DIR}/{ntp,dns,snmp,ssdp,portmap,netbios,ldap,mssql,udp,udp_lag,syn,webddos,tftp}

cd ${REMAPPED_DIR}

# Copiar (no mover) PCAPs a sus carpetas respectivas
# NTP
cp *ntp* *NTP* ${ORGANIZED_DIR}/ntp/ 2>/dev/null

# DNS
cp *dns* *DNS* ${ORGANIZED_DIR}/dns/ 2>/dev/null

# SNMP
cp *snmp* *SNMP* ${ORGANIZED_DIR}/snmp/ 2>/dev/null

# SSDP
cp *ssdp* *SSDP* ${ORGANIZED_DIR}/ssdp/ 2>/dev/null

# PortMap
cp *portmap* *Portmap* ${ORGANIZED_DIR}/portmap/ 2>/dev/null

# NetBIOS
cp *netbios* *NetBIOS* ${ORGANIZED_DIR}/netbios/ 2>/dev/null

# LDAP
cp *ldap* *LDAP* ${ORGANIZED_DIR}/ldap/ 2>/dev/null

# MSSQL
cp *mssql* *MSSQL* ${ORGANIZED_DIR}/mssql/ 2>/dev/null

# UDP (excluir lag)
cp *udp* *UDP* ${ORGANIZED_DIR}/udp/ 2>/dev/null
rm ${ORGANIZED_DIR}/udp/*lag* 2>/dev/null

# UDP-Lag
cp *lag* *Lag* ${ORGANIZED_DIR}/udp_lag/ 2>/dev/null

# SYN
cp *syn* *Syn* *SYN* ${ORGANIZED_DIR}/syn/ 2>/dev/null

# WebDDoS
cp *web* *Web* *http* *HTTP* ${ORGANIZED_DIR}/webddos/ 2>/dev/null

# TFTP
cp *tftp* *TFTP* ${ORGANIZED_DIR}/tftp/ 2>/dev/null

echo "=== ORGANIZATION COMPLETE ==="
echo "Check ${ORGANIZED_DIR}/ for organized PCAPs"
```

### Paso 3: Recolección Multi-Class (Día 1: Training)

```bash
#!/bin/bash
# Recolección de training data - Día 1 (7 tipos × 3 runs = 21 runs)

ATTACK_TYPES=("portmap" "netbios" "ldap" "mssql" "udp" "udp_lag" "syn")

cd /local/dpdk_100g/mira/detector_system_ml

# Benign baseline (3 runs × 30 min = 90 min)
for i in 1 2 3; do
    echo "=== Benign Run $i ==="
    sudo timeout 1800 ./detectorML -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
        2>&1 | tee ../ml_system/datasets/raw_logs/benign_run${i}.log &
    sleep 5
    sudo timeout 1795 /path/to/dpdk_pcap_sender ... benign_20M.pcap ...
    wait
done

# Attack types (7 types × 3 runs × 20 min = 420 min = 7 hours)
for attack in "${ATTACK_TYPES[@]}"; do
    for i in 1 2 3; do
        echo "=== ${attack} Run $i ==="
        sudo timeout 1200 ./detectorML -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
            2>&1 | tee ../ml_system/datasets/raw_logs/${attack}_run${i}.log &
        sleep 5
        sudo timeout 1195 /path/to/dpdk_pcap_sender_v2 ... \
            --pcap-dir /proj/softmeasure-PG0/CICD/organized/${attack}/ \
            --rate-gbps 12
        wait
    done
done

echo "Day 1 training data collection complete"
echo "Total time: 90 + 420 = 510 minutes (8.5 hours)"
```

### Resultado Multi-Class

```
Classes: ['benign', 'portmap', 'netbios', 'ldap', 'mssql', 'udp', 'udp_lag', 'syn']
Features: 46
Samples: ~5100 (8 classes × 3 runs × ~80 samples/run)
Validation accuracy: 85-92% (realistic)

Per-class performance:
  benign:  90-95% precision/recall
  ntp:     85-92% precision/recall
  dns:     83-90% precision/recall
  syn:     88-94% precision/recall
  ...
```

---

## Comparación de Opciones

| Aspecto | Opción 1 (3 clases) | Opción 2 (Multi-class) |
|---------|---------------------|------------------------|
| **Tiempo de recolección** | 4.5 horas | 8-15 horas |
| **Clases** | 3 (benign/attack/mixed) | 8-14 (tipos específicos) |
| **Setup requerido** | Ninguno (usa actual) | Organizar PCAPs por tipo |
| **Accuracy esperado** | 85-95% | 85-92% |
| **Identifica tipo de ataque** | ❌ No | ✅ Sí |
| **Útil para investigación** | ⭐⭐⭐ Bueno | ⭐⭐⭐⭐⭐ Excelente |
| **Complejidad** | Baja | Media-Alta |

---

## Recomendación

**Para empezar:**
1. Usa **Opción 1** (3 clases) para validar que todo funciona
2. Recolecta ~2700 muestras (4.5 horas)
3. Entrena y verifica que obtienes 85-95% accuracy (no 100%)

**Si todo funciona bien:**
4. Organiza los PCAPs por tipo (Opción 2)
5. Recolecta datos multi-class (8.5 horas)
6. Entrena modelo que identifica tipos específicos de ataque

---

## Verificación de Progreso

### Después de Opción 1 (3 clases)

```bash
# Verificar archivos generados
ls -lh ml_system/datasets/raw_logs/*.log
# Debería mostrar: 9 archivos .log (3 benign, 3 attack, 3 mixed)

ls -lh ml_system/datasets/processed/*.csv
# Debería mostrar: 9 archivos .csv

# Verificar número de samples
wc -l ml_system/datasets/processed/*.csv
# Total debería ser ~2700 líneas (sin contar headers)
```

### Después de Training

```bash
# Verificar accuracy
grep "Validation Accuracy" ml_system/02_training/training_output.log
# Debería mostrar: 85-95% (NO 100%)

# Verificar que usó hiperparámetros correctos
grep "max_depth\|num_leaves" ml_system/02_training/training_output.log
# Debería mostrar: max_depth: 3, num_leaves: 7
```
