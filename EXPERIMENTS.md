# Guía de Experimentación Completa - CloudLab

Guía paso a paso para ejecutar experimentos completos de generación, detección y análisis de ataques DDoS en CloudLab.

## Topología CloudLab

```
┌──────────────────┐           ┌──────────────────┐
│   Nodo TG        │           │  Nodo Detector   │
│  (Generator)     │  ──────>  │    (Target)      │
│                  │  100G NIC │                  │
│ - Genera PCAPs   │           │ - DPDK Detector  │
│ - tcpreplay      │           │ - Sketches       │
└──────────────────┘           └──────────────────┘
```

## Preparación Inicial (Una sola vez)

### En Nodo TG (Traffic Generator)

```bash
# 1. Clonar repositorio
cd /local
git clone <tu-repo> dpdk_100g
cd dpdk_100g

# 2. Instalar dependencias Python
pip3 install --user scapy numpy scipy pandas scikit-learn xgboost

# 3. Instalar tcpreplay
sudo apt update
sudo apt install -y tcpreplay

# 4. Verificar interfaz de red
ip -br link show
# Anota el nombre de tu interfaz 100G (ej: enp65s0f0)
```

### En Nodo Detector

```bash
# 1. Clonar repositorio
cd /local
git clone <tu-repo> dpdk_100g
cd dpdk_100g

# 2. Instalar dependencias
sudo apt update
sudo apt install -y dpdk dpdk-dev python3-pip
pip3 install --user pandas numpy scikit-learn

# 3. Compilar detector
cd detector_system
./scripts/build.sh

# 4. Verificar NIC DPDK
dpdk-devbind.py --status
# Anota el PCI address (ej: 0000:41:00.0)

# 5. Bind a DPDK (si es necesario)
sudo dpdk-devbind.py --bind=vfio-pci 0000:41:00.0
```

## Experimento Completo: Paso a Paso

### PASO 1: Generar Tráfico Benigno (Nodo TG)

```bash
cd /local/dpdk_100g

# Generar tráfico benigno realista
sudo python3 -m attack_generator \
  --benign-only \
  --output /local/pcaps/benign_traffic.pcap \
  --benign-duration 120 \
  --benign-profile heavy \
  --seed 42

# Verificar
ls -lh /local/pcaps/benign_traffic.pcap
tcpdump -r /local/pcaps/benign_traffic.pcap -c 10
```

### PASO 2: Generar Ataques DDoS (Nodo TG)

**Opción A: Ataques puros (sin mezcla)**

```bash
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --config - <<'EOF'
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 100000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000},
    {"type": "dns_amp", "num_packets": 80000, "pps": 8000},
    {"type": "http_flood", "num_packets": 50000, "pps": 5000},
    {"type": "icmp_flood", "num_packets": 60000, "pps": 6000}
  ]
}
EOF
```

**Opción B: Ataques mezclados con tráfico benigno (Recomendado para ML)**

```bash
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --mix-benign /local/pcaps/benign_traffic.pcap \
  --attack-ratio 0.3 \
  --config - <<'EOF'
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 100000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000}
  ]
}
EOF
```

**Verificar PCAPs generados:**

```bash
ls -lh /local/pcaps/
# Deberías ver:
# - syn_flood.pcap
# - syn_flood_mixed.pcap (si usaste --mix-benign)
# - udp_flood.pcap
# - udp_flood_mixed.pcap
# - metadata.json
```

### PASO 3: Iniciar Detector (Nodo Detector)

```bash
cd /local/dpdk_100g/detector_system

# Iniciar en background
sudo ./scripts/run_background.sh 0000:41:00.0

# Verificar que está corriendo
ps aux | grep detector_dpdk

# Monitorear logs en tiempo real (terminal separado)
tail -f /local/logs/detection.log
tail -f /local/logs/ml_features.csv
tail -f /local/logs/alerts.log
```

### PASO 4: Ejecutar Experimento de Replay (Nodo TG)

**Opción A: Reproducir todos los PCAPs automáticamente**

```bash
cd /local/dpdk_100g

# Con configuración por defecto (1000 Mbps)
sudo ./run_experiment.sh

# Con rate personalizado (5000 Mbps)
sudo ./run_experiment.sh -r 5000

# Con nombre de experimento
sudo ./run_experiment.sh -n "exp_syn_udp_mixed" -r 2000
```

**Opción B: Reproducir PCAPs específicos**

```bash
# Solo SYN flood
sudo ./run_experiment.sh specific syn_flood_mixed.pcap

# Múltiples ataques específicos
sudo ./run_experiment.sh specific syn_flood_mixed.pcap udp_flood_mixed.pcap

# Con rate alto
sudo ./run_experiment.sh -r 8000 specific syn_flood.pcap
```

**Opción C: Modo interactivo**

```bash
sudo ./run_experiment.sh interactive
# Te mostrará un menú para seleccionar qué PCAP reproducir
```

**Opción D: Modo secuencial con delays**

```bash
# Reproducir todos con 10 segundos entre cada uno
sudo ./run_experiment.sh sequential 10

# Útil para dar tiempo al detector de procesar
```

**Monitoreo durante el experimento:**

```bash
# Ver estadísticas de red en tiempo real
watch -n 1 'ifstat -i enp65s0f0 1 1'

# Ver tráfico
sudo tcpdump -i enp65s0f0 -n -c 20
```

### PASO 5: Detener Detector (Nodo Detector)

```bash
# Detener detector
sudo pkill -2 detector_dpdk  # SIGINT para shutdown limpio

# O forzar
sudo pkill -9 detector_dpdk

# Verificar logs finales
tail -20 /local/logs/detection.log
```

### PASO 6: Analizar Resultados

**En Nodo Detector:**

```bash
cd /local/dpdk_100g/detector_system

# Análisis básico
python3 scripts/analyze.py

# Con modelo ML (si tienes uno entrenado)
python3 scripts/analyze.py \
  --model-path /local/models/xgboost_detector.pkl

# Exportar features para entrenamiento
python3 scripts/analyze.py \
  --export-features /local/training_features.csv

# Análisis con ventana personalizada
python3 scripts/analyze.py --window-size 30
```

**En Nodo TG:**

```bash
# Ver reporte del experimento
cat /local/logs/experiments/exp_<timestamp>/report.txt

# Ver estadísticas detalladas
cat /local/logs/experiments/exp_<timestamp>/stats.csv
```

## Experimentos Avanzados

### Experimento 1: Comparación de Tipos de Ataque

```bash
# Nodo TG
cd /local/dpdk_100g

# Generar cada tipo de ataque por separado
for attack in syn_flood udp_flood dns_amp http_flood icmp_flood; do
  sudo python3 -m attack_generator \
    --target-ip 10.10.1.2 \
    --attack $attack \
    --num-packets 100000 \
    --pps 10000 \
    --output-dir /local/pcaps/comparison
done

# Ejecutar experimentos individuales
for pcap in /local/pcaps/comparison/*.pcap; do
  echo "Testing: $(basename $pcap)"
  sudo ./run_experiment.sh -n "exp_$(basename $pcap .pcap)" specific $(basename $pcap)
  sleep 30  # Esperar entre experimentos
done
```

### Experimento 2: Test de Escalabilidad (PPS)

```bash
# Nodo TG
cd /local/dpdk_100g

# Generar ataques con diferentes PPS
for pps in 1000 5000 10000 50000 100000; do
  sudo python3 -m attack_generator \
    --target-ip 10.10.1.2 \
    --attack syn_flood \
    --num-packets 50000 \
    --pps $pps \
    --output-dir /local/pcaps/scalability \
    --seed 42

  mv /local/pcaps/scalability/syn_flood.pcap \
     /local/pcaps/scalability/syn_flood_${pps}pps.pcap
done

# Ejecutar en orden creciente
for pps in 1000 5000 10000 50000 100000; do
  sudo ./run_experiment.sh -n "exp_${pps}pps" \
    specific scalability/syn_flood_${pps}pps.pcap
  sleep 20
done
```

### Experimento 3: Dataset para ML

```bash
# Nodo TG: Generar dataset balanceado

# 1. Tráfico normal (solo benigno)
sudo python3 -m attack_generator \
  --benign-only \
  --output /local/pcaps/ml_dataset/normal_1.pcap \
  --benign-duration 60 \
  --benign-profile normal \
  --seed 100

# 2. Múltiples ataques mezclados
for i in {1..5}; do
  sudo python3 -m attack_generator \
    --target-ip 10.10.1.2 \
    --mix-benign /local/pcaps/benign_traffic.pcap \
    --attack-ratio 0.3 \
    --seed $((100 + i)) \
    --config - <<EOF
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps/ml_dataset",
  "attacks": [
    {"type": "syn_flood", "num_packets": 50000, "pps": 8000}
  ]
}
EOF
  mv /local/pcaps/ml_dataset/syn_flood_mixed.pcap \
     /local/pcaps/ml_dataset/attack_syn_${i}.pcap
done

# Ejecutar todo el dataset
sudo ./run_experiment.sh -d /local/pcaps/ml_dataset sequential 15

# Nodo Detector: Etiquetar dataset
python3 scripts/analyze.py \
  --export-features /local/ml_dataset_features.csv
```

## Recolección de Resultados

### Copiar Logs desde CloudLab a Local

```bash
# Desde tu máquina local

# Logs del detector
scp -r <user>@<detector-node>.cloudlab.us:/local/logs /local/results/detector_logs

# Logs de experimentos
scp -r <user>@<tg-node>.cloudlab.us:/local/logs/experiments /local/results/experiments

# PCAPs generados (si los necesitas)
scp -r <user>@<tg-node>.cloudlab.us:/local/pcaps /local/results/pcaps
```

## Troubleshooting

### Problema: tcpreplay no envía paquetes

```bash
# Verificar que la interfaz está UP
sudo ip link set enp65s0f0 up

# Verificar permisos
sudo chmod 644 /local/pcaps/*.pcap

# Probar con un PCAP pequeño
sudo tcpreplay -i enp65s0f0 --topspeed /local/pcaps/test.pcap
```

### Problema: Detector no ve tráfico

```bash
# Verificar que NIC está en modo promiscuo
sudo ip link set enp65s0f0 promisc on

# Verificar con tcpdump
sudo tcpdump -i enp65s0f0 -n -c 100

# Verificar binding DPDK
dpdk-devbind.py --status
```

### Problema: Rate muy bajo

```bash
# Deshabilitar offloading
sudo ethtool -K enp65s0f0 gso off tso off gro off

# Usar --topspeed en lugar de --mbps
sudo tcpreplay -i enp65s0f0 --topspeed test.pcap

# Verificar CPU governor
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
# Debería ser "performance", no "powersave"
```

## Scripts de Automatización Completa

### Script Todo-en-Uno (Nodo TG)

```bash
cat > /local/full_experiment.sh << 'BASH'
#!/bin/bash
set -e

echo "Experimento Completo DDoS - CloudLab"
echo "===================================="

# 1. Generar tráfico benigno
echo "[1/4] Generando tráfico benigno..."
cd /local/dpdk_100g
sudo python3 -m attack_generator \
  --benign-only \
  --output /local/pcaps/benign.pcap \
  --benign-duration 60 \
  --benign-profile normal \
  --seed 42

# 2. Generar ataques
echo "[2/4] Generando ataques..."
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --mix-benign /local/pcaps/benign.pcap \
  --attack-ratio 0.3 \
  --config attacks_config.json

# 3. Esperar a que el detector esté listo
echo "[3/4] Esperando detector..."
read -p "¿Detector listo? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Abortando."
    exit 1
fi

# 4. Ejecutar experimento
echo "[4/4] Ejecutando experimento..."
sudo ./run_experiment.sh -n "exp_full_$(date +%Y%m%d_%H%M%S)" -r 2000

echo "Experimento completado!"
BASH

chmod +x /local/full_experiment.sh
```

## Checklist Pre-Experimento

- [ ] Nodo TG: PCAPs generados y verificados
- [ ] Nodo TG: tcpreplay instalado
- [ ] Nodo TG: Interfaz de red configurada
- [ ] Nodo Detector: Detector compilado
- [ ] Nodo Detector: NIC bound a DPDK
- [ ] Nodo Detector: Directorios de logs creados
- [ ] Ambos nodos: Conectividad de red verificada
- [ ] Ambos nodos: Suficiente espacio en disco (/local)

## Checklist Post-Experimento

- [ ] Detector detenido limpiamente
- [ ] Logs del detector guardados
- [ ] Reporte de experimento generado
- [ ] Features exportadas para análisis
- [ ] Resultados copiados a máquina local
- [ ] Recursos liberados (pkill, cleanup)

---

**¡Listo para experimentar!** 🚀

Para más detalles:
- Generador de ataques: `attack_generator/README.md`
- Sistema de detección: `detector_system/README.md`
