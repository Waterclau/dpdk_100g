# Node Controller - Manual Operation Guide

Guía paso a paso para configurar y operar manualmente el **Node Controller** que genera tráfico baseline realista.

---

## Objetivo

El Node Controller genera **tráfico HTTP baseline realista** que simula el comportamiento normal de un servidor web. Este tráfico tiene:
- Variaciones naturales (hora del día, patrones diarios)
- Distribución realista de requests (GET 75%, POST 20%, etc.)
- Múltiples IPs de origen (simula muchos usuarios)
- Think time y pausas realistas

**NO es tráfico de ataque** - es el comportamiento normal contra el cual se detectarán los ataques.

---

## Hardware Requerido

- 1 nodo c6525-100g
- NIC 100 Gbps (Mellanox ConnectX-5/6)
- 8+ cores CPU
- 16+ GB RAM
- Ubuntu 20.04+

---

## Paso 1: Preparación del Sistema

### 1.1 Instalar Dependencias

```bash
# Actualizar sistema
sudo apt-get update

# Instalar DPDK
sudo apt-get install -y dpdk dpdk-dev libdpdk-dev build-essential pkg-config

# Instalar Python y Scapy
sudo apt-get install -y python3 python3-pip
pip3 install scapy

# Verificar instalación
pkg-config --modversion libdpdk
python3 -c "import scapy; print('Scapy OK')"
```

### 1.2 Configurar Hugepages

```bash
# Configurar 4096 hugepages de 2MB (8 GB total)
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages

# Verificar
cat /proc/meminfo | grep Huge

# Debería mostrar:
# HugePages_Total:    4096
# Hugepagesize:       2048 kB

# Montar hugetlbfs
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Verificar montaje
mount | grep huge
```

### 1.3 Identificar y Bindear NIC a DPDK

```bash
# Listar NICs disponibles
sudo dpdk-devbind.py --status

# Ejemplo de output:
# Network devices using kernel driver
# ===================================
# 0000:81:00.0 'MT27800 Family [ConnectX-5]' if=eth0 drv=mlx5_core

# Tomar nota del PCI address (ej: 0000:81:00.0)

# Cargar driver VFIO
sudo modprobe vfio-pci

# Bindear NIC a DPDK
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0

# Verificar binding
sudo dpdk-devbind.py --status

# Debería mostrar:
# Network devices using DPDK-compatible driver
# =============================================
# 0000:81:00.0 'MT27800 Family [ConnectX-5]' drv=vfio-pci
```

---

## Paso 2: Configuración de Red

### 2.1 Identificar Configuración de Red

Necesitas saber:
- **IP destino**: IP del nodo que recibirá el tráfico (ej: Monitor node)
- **MAC destino**: MAC address del nodo destino
- **PCI address**: De tu NIC (del paso 1.3)

```bash
# Ver MAC del NIC destino (en el nodo destino)
ip addr show eth0 | grep ether

# Ver IP del nodo destino
ip addr show eth0 | grep inet
```

### 2.2 Editar Configuración

```bash
cd dpdk_100g/http_flood_advance
vim config/node_controller_baseline.json
```

Actualiza estos valores:
```json
{
  "network": {
    "dst_ip": "10.0.0.1",              // IP del nodo destino
    "dst_mac": "bb:bb:bb:bb:bb:bb",    // MAC del nodo destino
    "src_ip_base": "192.168.0.0"       // Base para IPs de origen
  },
  "dpdk_config": {
    "nic_pci": "0000:81:00.0",         // Tu NIC PCI address
    "num_cores": 4                      // Usar 4 cores para baseline
  },
  "traffic_profiles": {
    "selected_profile": "medium"        // Perfil de tráfico
  }
}
```

---

## Paso 3: Compilar Generadores

### 3.1 Compilar

```bash
cd benign_generator

# Limpiar builds anteriores
make clean

# Compilar
make

# Verificar binarios creados
ls -lh build/

# Deberías ver:
# baseline_traffic_gen  <- Generador baseline (USAR ESTE)
# benign_traffic_gen    <- Generador alto rendimiento (legacy)
```

---

## Paso 4: Ejecutar Generador (Método Recomendado)

### Opción A: Generador DPDK (Tiempo Real)

**Recomendado para experimentos en tiempo real**

```bash
cd benign_generator

# Ejecutar con configuración básica
# -l 0-3: usar cores 0 a 3 (4 cores)
# -n 4: 4 memory channels
# --proc-type=primary: proceso principal
# --file-prefix=baseline: prefix para archivos DPDK

sudo ./build/baseline_traffic_gen \
    -l 0-3 \
    -n 4 \
    --proc-type=primary \
    --file-prefix=baseline
```

**Salida esperada:**
```
Found 1 Ethernet ports
Port 0 MAC: aa:aa:aa:aa:aa:aa

=== Realistic Baseline Traffic Generator ===
Base Rate:         50000 pps (50.00 Kpps)
Rate Range:        10000 - 200000 pps
Profile:           VARIABLE (realistic)
Variations:        ENABLED
Worker Cores:      4
HTTP Templates:    20 (weighted distribution)
Press Ctrl+C to stop...

=== Baseline Traffic Generator Statistics ===
Total Packets:              300000
Total Bytes:              240000000 (240.00 MB)
Dropped:                        0
Current Rate:             49850.23 pps (49.85 Kpps)
Throughput:                39.88 Mbps (0.040 Gbps)
Avg Packet:                800.00 bytes
Base Rate:                 50000 pps
=============================================
```

**Para detener:** Presiona `Ctrl+C`

### Opción B: Generador Python (Datasets)

**Recomendado para generar datasets grandes offline**

```bash
cd benign_generator

# Test rápido (60 segundos)
python3 baseline_dataset_generator.py \
    -d 60 \
    -p medium \
    -o baseline_test.pcap

# Baseline completo (5 minutos)
python3 baseline_dataset_generator.py \
    -d 300 \
    -p medium \
    -o baseline_5min.pcap \
    --dst-ip 10.0.0.1 \
    --dst-mac bb:bb:bb:bb:bb:bb

# Experimento completo (11 minutos)
python3 baseline_dataset_generator.py \
    -d 660 \
    -p medium \
    -o baseline_full.pcap \
    --start-hour 14 \
    --dst-ip 10.0.0.1
```

**Argumentos importantes:**
- `-d`: Duración en segundos
- `-p`: Perfil de tráfico (very_low, low, **medium**, high, very_high)
- `-o`: Archivo PCAP de salida
- `--start-hour`: Hora simulada de inicio (0-23)
- `--dst-ip`: IP destino
- `--dst-mac`: MAC destino

**Salida esperada:**
```
=== Realistic Baseline Traffic Generator ===
Configuration:
  Duration:        300 seconds
  Profile:         medium
  Destination IP:  10.0.0.1
  Time Variations: Enabled
  Start Hour:      14:00

Generating baseline traffic for 300 seconds...
Profile: Medium traffic - popular website (RECOMMENDED for baseline)
Base rate: 10000 req/sec
Peak rate: 30000 req/sec

  Progress: 60/300s - Generated 600000 packets (current rate: 9850 rps)
  Progress: 120/300s - Generated 1200000 packets (current rate: 10120 rps)
  ...

Generated 3000000 packets in 300.45 seconds
Average rate: 9985.04 pps

=== Baseline Traffic Statistics ===
Profile:            Medium traffic - popular website
Total Sessions:     900000
Total Packets:      3000000
Total Bytes:        2,400,000,000
Total MB:           2288.82

HTTP Methods:
  GET     : 2250000 (75.00%)
  POST    :  600000 (20.00%)
  PUT     :   90000 ( 3.00%)
  ...

Baseline dataset generation complete!
PCAP file: baseline_5min.pcap
Stats file: baseline_5min_stats.json
```

---

## Paso 5: Monitoreo Durante Ejecución

### En una Terminal Separada

```bash
# Ver estadísticas de NIC en tiempo real
watch -n 1 'ethtool -S eth0 | grep -E "tx_packets|tx_bytes"'

# Calcular rate en Gbps
watch -n 1 'echo "scale=3; $(cat /sys/class/net/eth0/statistics/tx_bytes) * 8 / 1000000000" | bc'

# Capturar algunos paquetes para verificar
sudo tcpdump -i eth0 -c 20 -nn -v

# Ver uso de CPU y memoria
htop

# Ver uso por core
mpstat -P ALL 1
```

---

## Paso 6: Resultados y Análisis

### 6.1 Ubicación de Resultados

```bash
cd baseline_traffic_data

# Listar archivos generados
ls -lh

# Deberías ver:
# baseline_5min.pcap           <- Captura de tráfico
# baseline_5min_stats.json     <- Estadísticas
```

### 6.2 Analizar PCAP

```bash
# Contar paquetes
tcpdump -r baseline_5min.pcap -nn | wc -l

# Ver primeros 100 paquetes
tcpdump -r baseline_5min.pcap -nn -q | head -100

# Filtrar solo HTTP
tcpdump -r baseline_5min.pcap -nn -A 'tcp port 80' | head -50

# Estadísticas detalladas con tshark
tshark -r baseline_5min.pcap -q -z io,stat,1
```

### 6.3 Ver Estadísticas JSON

```bash
# Ver estadísticas
cat baseline_5min_stats.json | python3 -m json.tool

# Extraer métricas clave
cat baseline_5min_stats.json | jq '.total_packets, .total_bytes, .sessions'
```

---

## Perfiles de Tráfico Disponibles

| Perfil | Rate Base | Rate Peak | Descripción | Uso |
|--------|-----------|-----------|-------------|-----|
| `very_low` | 100 pps | 300 pps | Website muy pequeño | Testing |
| `low` | 1K pps | 3K pps | Sitio pequeño | Baseline ligero |
| **`medium`** | **10K pps** | **30K pps** | **Website popular** | **RECOMENDADO** |
| `high` | 50K pps | 150K pps | E-commerce grande | Baseline alto |
| `very_high` | 100K pps | 300K pps | Plataforma mayor | Stress test |

**Para cambiar perfil:**
```bash
# En Python
python3 baseline_dataset_generator.py -d 300 -p high

# En DPDK: editar código fuente y recompilar
# O ajustar gen_config.base_rate_pps en código
```

---

## Variaciones Temporales

El generador simula patrones diarios realistas:

```
Hora del Día          Rate Multiplier
-----------------------------------------
00:00 - 06:00 (Noche) 0.3x (30% del base rate)
06:00 - 12:00 (Mañana)0.5x - 1.0x (subiendo)
12:00 - 18:00 (Tarde) 1.0x - 1.2x (PEAK)
18:00 - 24:00 (Noche) 0.6x - 0.3x (bajando)
```

**Plus:** Ruido aleatorio de ±15% para hacer el tráfico más realista.

---

## Troubleshooting

### Problema: "No Ethernet ports available"

```bash
# Verificar binding
sudo dpdk-devbind.py --status

# Rebindear si es necesario
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0
```

### Problema: "Cannot allocate mbuf"

```bash
# Aumentar hugepages
echo 8192 | sudo tee /proc/sys/vm/nr_hugepages

# Verificar
cat /proc/meminfo | grep Huge
```

### Problema: Rate muy bajo

```bash
# 1. Verificar CPU frequency
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 2. Set to performance
sudo cpupower frequency-set -g performance

# 3. Usar más cores (editar comando -l 0-7 en vez de 0-3)

# 4. Verificar que NIC esté bien bindeado
sudo dpdk-devbind.py --status
```

### Problema: Python generator muy lento

**Es normal** - el generador Python es para datasets offline, no tiempo real.

Para tiempo real usa el generador DPDK.

---

## Workflow Completo para Experimento

### Antes del Experimento

```bash
# 1. Setup sistema
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0

# 2. Build
cd benign_generator
make clean && make

# 3. Test corto (60 segundos)
python3 baseline_dataset_generator.py -d 60 -p low
```

### Durante el Experimento

```bash
# Terminal 1: Ejecutar generador baseline (11 minutos)
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# Terminal 2: Monitorear
watch -n 1 'ethtool -S eth0 | grep tx_packets'

# Dejar correr durante:
# - 5 min: Fase baseline
# - 5 min: Fase ataque (generador continúa)
# - 1 min: Fase recovery
# Total: 11 minutos
```

### Después del Experimento

```bash
# Detener generador (Ctrl+C)

# Copiar resultados
mkdir -p ~/experiment_results/baseline
cp baseline_traffic_data/* ~/experiment_results/baseline/

# Unbind NIC (opcional)
sudo dpdk-devbind.py --bind=mlx5_core 0000:81:00.0
```

---

## Comandos de Referencia Rápida

```bash
# Setup
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0

# Build
cd benign_generator && make clean && make

# Run DPDK (tiempo real)
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# Run Python (dataset)
python3 baseline_dataset_generator.py -d 300 -p medium -o baseline.pcap

# Monitor
watch -n 1 'ethtool -S eth0 | grep tx_packets'
sudo tcpdump -i eth0 -c 100 -nn

# Cleanup
sudo dpdk-devbind.py --bind=mlx5_core 0000:81:00.0
```

---

## Notas Importantes

1. **Baseline vs Attack**: Este generador produce tráfico NORMAL, no ataques
2. **Realismo**: El tráfico tiene variaciones naturales (hora del día, ruido)
3. **Perfil Medium**: Recomendado para la mayoría de experimentos
4. **4 Cores**: Suficientes para baseline realista (no necesitas 8)
5. **DPDK vs Python**: DPDK para tiempo real, Python para datasets
6. **Duración**: Fase baseline típica es 300 segundos (5 minutos)
7. **Monitoreo**: Siempre monitorea en terminal separada

---

## Próximos Pasos

Una vez que el baseline funciona correctamente:
1. ✅ Generador baseline operando
2. ⏳ Configurar generador de ataque (próximo paso)
3. ⏳ Configurar detector en Node Monitor
4. ⏳ Ejecutar experimento completo de 3 fases

---

**¿Problemas?** Revisa troubleshooting arriba o consulta `config/node_controller_baseline.json` para más detalles.
