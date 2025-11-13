# Quick Start - Generador Baseline (5 minutos)

Guía ultra-rápida para generar tráfico baseline realista.

---

## ⚡ Setup Rápido (2 minutos)

```bash
# 1. Hugepages
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages

# 2. Bind NIC (ajusta el PCI address)
sudo modprobe vfio-pci
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0

# 3. Verificar
sudo dpdk-devbind.py --status
cat /proc/meminfo | grep Huge
```

---

## 🔨 Compilar (30 segundos)

```bash
cd dpdk_100g/http_flood_advance/benign_generator
make clean && make

# Verificar
ls -lh build/
# Deberías ver: baseline_traffic_gen
```

---

## 🚀 Ejecutar (2 minutos)

### Opción 1: DPDK (Tiempo Real) ← RECOMENDADO

```bash
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary
```

**Detener**: `Ctrl+C`

### Opción 2: Python (Dataset)

```bash
python3 baseline_dataset_generator.py -d 300 -p medium
```

**Detener**: `Ctrl+C` o espera a que termine

---

## 📊 Salida Esperada

### DPDK Generator

```
=== Realistic Baseline Traffic Generator ===
Base Rate:         50000 pps (50.00 Kpps)
Profile:           VARIABLE (realistic)
Worker Cores:      4

=== Baseline Traffic Generator Statistics ===
Total Packets:              600000
Current Rate:             49850 pps (49.85 Kpps)
Throughput:                39.88 Mbps (0.040 Gbps)
Avg Packet:                800 bytes
```

### Python Generator

```
=== Realistic Baseline Traffic Generator ===
Generating baseline traffic for 300 seconds...
Profile: Medium traffic - popular website
Base rate: 10000 req/sec

Generated 3000000 packets in 300.45 seconds
Average rate: 9985.04 pps

PCAP file: baseline_medium_20251113_143022.pcap
Stats file: baseline_medium_20251113_143022_stats.json
```

---

## 🔍 Monitorear (opcional)

En otra terminal:

```bash
# Ver packets en tiempo real
watch -n 1 'ethtool -S eth0 | grep tx_packets'

# O capturar algunos
sudo tcpdump -i eth0 -c 20 -nn
```

---

## ✅ Verificar que Funciona

Deberías ver:
- ✅ Paquetes incrementando constantemente
- ✅ Rate cerca de 50K pps (perfil medium)
- ✅ Sin "dropped packets"
- ✅ CPU usage 40-60% en 4 cores

---

## 🛠️ Si Algo Sale Mal

### "No Ethernet ports available"
```bash
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0
```

### "Cannot allocate mbuf"
```bash
echo 8192 | sudo tee /proc/sys/vm/nr_hugepages
```

### Rate muy bajo
```bash
sudo cpupower frequency-set -g performance
```

---

## 📚 Más Información

- **Guía completa**: `docs/NODE_CONTROLLER_MANUAL.md`
- **Configuración**: `config/node_controller_baseline.json`
- **README**: `README_BASELINE.md`

---

## 🎯 Perfiles Disponibles

```bash
# Muy bajo (100 rps)
python3 baseline_dataset_generator.py -d 300 -p very_low

# Bajo (1K rps)
python3 baseline_dataset_generator.py -d 300 -p low

# Medio (10K rps) ← RECOMENDADO
python3 baseline_dataset_generator.py -d 300 -p medium

# Alto (50K rps)
python3 baseline_dataset_generator.py -d 300 -p high

# Muy alto (100K rps)
python3 baseline_dataset_generator.py -d 300 -p very_high
```

---

## ⏱️ Duración Recomendada

| Fase | Duración | Propósito |
|------|----------|-----------|
| Test | 60s | Verificar que funciona |
| Baseline | 300s | Establecer baseline |
| Full Experiment | 660s | Baseline + ataque + recovery |

---

## 💾 Resultados

Los resultados se guardan en:
```
baseline_traffic_data/
├── baseline_*.pcap       # Captura de tráfico
└── baseline_*_stats.json # Estadísticas
```

---

**¡Listo!** Tu generador baseline está corriendo. 🎉

**Próximo paso**: Ver `docs/NODE_CONTROLLER_MANUAL.md` para uso avanzado.
