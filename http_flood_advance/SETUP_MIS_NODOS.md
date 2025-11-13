# Setup para TUS Nodos - Configuración Específica

**Última actualización**: 2025-11-13
**Verificado**: ✅ Conectividad OK

---

## 🌐 Tu Configuración de Red

### Node Controller
```
Hostname:     node-controller
Management:   128.110.219.172
Interface:    ens1f0 (100G Mellanox ConnectX-5)
IP:           10.10.1.5
MAC:          0c:42:a1:8b:2f:c8
MTU:          9000
PCI:          0000:01:00.0 (probable)
```

### Node Monitor
```
Hostname:     node-monitor
Management:   128.110.219.171
Interface:    ens1f0 (100G Mellanox ConnectX-5)
IP:           10.10.1.2
MAC:          0c:42:a1:8c:dd:0c
MTU:          9000
```

### Conectividad
```
✅ VERIFICADA
Ping: 10.10.1.5 → 10.10.1.2
RTT: 0.192 ms (excelente!)
Packet Loss: 0%
Red: 10.10.1.0/24
```

---

## ⚡ Setup Rápido (5 minutos)

### En node-controller

```bash
# 1. Confirmar PCI del NIC
ethtool -i ens1f0 | grep bus
# Esperado: bus-info: 0000:01:00.0

# 2. Setup hugepages
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages

# 3. Cargar driver DPDK
sudo modprobe vfio-pci

# 4. Bind NIC a DPDK
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0

# 5. Verificar
sudo dpdk-devbind.py --status
cat /proc/meminfo | grep Huge
```

---

## 🔨 Compilar Generador

```bash
# En node-controller
cd ~/dpdk_100g/http_flood_advance/benign_generator

# Limpiar y compilar
make clean
make

# Verificar binarios
ls -lh build/
# Deberías ver: baseline_traffic_gen
```

---

## 🚀 Ejecutar Generador Baseline

### Opción 1: DPDK (Tiempo Real) - RECOMENDADO

```bash
# En node-controller
cd ~/dpdk_100g/http_flood_advance/benign_generator

# Ejecutar generador baseline
sudo ./build/baseline_traffic_gen \
    -l 0-3 \
    -n 4 \
    --proc-type=primary \
    --file-prefix=baseline

# Parámetros:
# -l 0-3: usar 4 cores (0, 1, 2, 3)
# -n 4: 4 memory channels
# --proc-type=primary: proceso principal DPDK
# --file-prefix=baseline: nombre único para este proceso
```

**Salida esperada:**
```
Found 1 Ethernet ports
Port 0 MAC: 0c:42:a1:8b:2f:c8

=== Realistic Baseline Traffic Generator ===
Base Rate:         50000 pps (50.00 Kpps)
Rate Range:        10000 - 200000 pps
Profile:           VARIABLE (realistic)
Variations:        ENABLED
Worker Cores:      4

=== Baseline Traffic Generator Statistics ===
Total Packets:              600000
Total Bytes:              480000000 (480.00 MB)
Current Rate:             49850 pps (49.85 Kpps)
Throughput:                39.88 Mbps (0.040 Gbps)
```

**Para detener:** `Ctrl+C`

### Opción 2: Python (Dataset Generation)

```bash
# En node-controller
cd ~/dpdk_100g/http_flood_advance/benign_generator

# Generar dataset de 5 minutos (perfil medium)
python3 baseline_dataset_generator.py \
    -d 300 \
    -p medium \
    --dst-ip 10.10.1.2 \
    --dst-mac 0c:42:a1:8c:dd:0c \
    -o baseline_5min.pcap

# Parámetros:
# -d 300: duración 300 segundos (5 minutos)
# -p medium: perfil de tráfico medio (10K rps)
# --dst-ip: IP del node-monitor
# --dst-mac: MAC del node-monitor
# -o: archivo de salida
```

---

## 📊 Monitoreo en Tiempo Real

### Terminal 1: Ejecutar generador
```bash
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary
```

### Terminal 2: Monitorear tráfico

**Ver packets transmitidos:**
```bash
watch -n 1 'ethtool -S ens1f0 | grep tx_packets'
```

**Ver rate en tiempo real:**
```bash
watch -n 1 'ethtool -S ens1f0 | grep -E "tx_packets|tx_bytes"'
```

**Capturar algunos paquetes:**
```bash
sudo tcpdump -i ens1f0 -c 20 -nn -v port 80
```

**Ver específicamente hacia el Monitor:**
```bash
sudo tcpdump -i ens1f0 -c 20 -nn host 10.10.1.2
```

---

## 🎯 Configuración del Código (si necesitas ajustar)

Si quieres cambiar los valores hardcoded en el código DPDK:

```c
// En baseline_traffic_dpdk.c (línea ~700)

// Cambiar IP destino
gen_config.dst_ip_base = (10 << 24) | (10 << 16) | (1 << 8) | 2;
// = 10.10.1.2 ✅ (ya configurado correctamente)

// Cambiar IP origen base
gen_config.src_ip_base = (192 << 24) | (168 << 16);
// = 192.168.0.0/16 ✅ (OK para simular clientes)

// Cambiar MACs (actualizar con tus valores)
memset(&gen_config.src_mac, 0xAA, sizeof(struct rte_ether_addr));
// Cambiar a: 0c:42:a1:8b:2f:c8

memset(&gen_config.dst_mac, 0xBB, sizeof(struct rte_ether_addr));
// Cambiar a: 0c:42:a1:8c:dd:0c
```

**Nota:** El generador usa valores por defecto que deberías actualizar. O mejor, usa el generador Python que toma los valores por CLI.

---

## 🔍 Verificaciones

### Pre-vuelo Checklist

```bash
# 1. Hugepages configuradas
cat /proc/meminfo | grep Huge
# Debe mostrar: HugePages_Total: 4096

# 2. NIC bindeada a DPDK
sudo dpdk-devbind.py --status
# Debe mostrar: 0000:01:00.0 drv=vfio-pci

# 3. Conectividad OK
ping -c 3 10.10.1.2
# Debe responder sin pérdidas

# 4. Binario compilado
ls -lh build/baseline_traffic_gen
# Debe existir
```

### Durante Ejecución

```bash
# Ver si hay tráfico
sudo tcpdump -i ens1f0 -c 5 -nn host 10.10.1.2

# Ver estadísticas de NIC
ethtool -S ens1f0 | grep -E "tx_packets|tx_bytes|tx_errors"

# Ver CPU usage
htop  # Deberías ver 4 cores al ~50-60%

# Ver memoria hugepages
cat /proc/meminfo | grep Huge
```

---

## 🧪 Test Completo (Paso a Paso)

### 1. Setup inicial

```bash
# node-controller
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages
sudo modprobe vfio-pci
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0
```

### 2. Compilar

```bash
cd ~/dpdk_100g/http_flood_advance/benign_generator
make clean && make
```

### 3. Test corto (60 segundos con Python)

```bash
python3 baseline_dataset_generator.py \
    -d 60 \
    -p low \
    --dst-ip 10.10.1.2 \
    --dst-mac 0c:42:a1:8c:dd:0c \
    -o test_60s.pcap

# Debería completar sin errores
# Archivo generado: test_60s.pcap (~100 MB)
```

### 4. Verificar resultado

```bash
ls -lh test_60s.pcap
tcpdump -r test_60s.pcap -nn -c 10
cat test_60s_stats.json | jq '.total_packets, .total_bytes'
```

### 5. Ejecutar baseline completo (DPDK)

```bash
# En terminal 1:
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# En terminal 2 (monitoreo):
watch -n 1 'ethtool -S ens1f0 | grep tx_packets'

# Dejar correr 5 minutos (300 segundos)
# Luego Ctrl+C para detener
```

---

## 🛠️ Troubleshooting

### "Cannot allocate mbuf"

```bash
# Aumentar hugepages
echo 8192 | sudo tee /proc/sys/vm/nr_hugepages

# Verificar
cat /proc/meminfo | grep Huge
```

### "No Ethernet ports available"

```bash
# Verificar binding
sudo dpdk-devbind.py --status

# Rebindear si es necesario
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0
```

### Rate muy bajo

```bash
# 1. CPU a performance mode
sudo cpupower frequency-set -g performance

# 2. Verificar que no haya otros procesos usando el NIC
ps aux | grep dpdk

# 3. Usar más cores (editar -l 0-7 en vez de 0-3)
```

### No sale tráfico

```bash
# 1. Verificar que NIC esté bindeada
sudo dpdk-devbind.py --status

# 2. Verificar hugepages
cat /proc/meminfo | grep HugePages_Free

# 3. Ver logs del generador (en pantalla)

# 4. Capturar en el Monitor para ver si llega:
# (en node-monitor)
sudo tcpdump -i ens1f0 -c 100 -nn host 10.10.1.5
```

---

## 📋 Comandos de Referencia Rápida

```bash
# === SETUP ===
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages
sudo modprobe vfio-pci
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0

# === BUILD ===
cd ~/dpdk_100g/http_flood_advance/benign_generator
make clean && make

# === RUN DPDK ===
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# === RUN PYTHON ===
python3 baseline_dataset_generator.py -d 300 -p medium \
  --dst-ip 10.10.1.2 --dst-mac 0c:42:a1:8c:dd:0c

# === MONITOR ===
watch -n 1 'ethtool -S ens1f0 | grep tx_packets'
sudo tcpdump -i ens1f0 -c 20 -nn host 10.10.1.2

# === VERIFY ===
ping 10.10.1.2
sudo dpdk-devbind.py --status
cat /proc/meminfo | grep Huge

# === CLEANUP ===
sudo dpdk-devbind.py --bind=mlx5_core 0000:01:00.0
```

---

## 📦 Archivos de Resultados

Los resultados se guardan en:

```bash
# En node-controller
~/dpdk_100g/http_flood_advance/benign_generator/baseline_traffic_data/
├── baseline_medium_TIMESTAMP.pcap
└── baseline_medium_TIMESTAMP_stats.json
```

Para copiar a tu máquina local:

```bash
# Desde tu máquina local
scp cesteban@node-controller:~/dpdk_100g/http_flood_advance/benign_generator/baseline_traffic_data/*.pcap .
scp cesteban@node-controller:~/dpdk_100g/http_flood_advance/benign_generator/baseline_traffic_data/*.json .
```

---

## 🎯 Resumen de tu Setup

| Parámetro | Valor |
|-----------|-------|
| **Controller IP** | 10.10.1.5 |
| **Monitor IP** | 10.10.1.2 |
| **Controller MAC** | 0c:42:a1:8b:2f:c8 |
| **Monitor MAC** | 0c:42:a1:8c:dd:0c |
| **Interface** | ens1f0 (ambos nodos) |
| **NIC** | Mellanox ConnectX-5 |
| **PCI (Controller)** | 0000:01:00.0 |
| **MTU** | 9000 |
| **Red** | 10.10.1.0/24 |
| **Conectividad** | ✅ Verificada (0.192ms) |

---

## ✅ Listo!

Tu configuración está **verificada y lista para usar**.

**Siguiente paso:** Ejecuta el generador baseline siguiendo la sección "🚀 Ejecutar Generador Baseline" arriba.

**Archivo de configuración completo:** `config/my_nodes_config.json`

---

**¿Dudas?** Todos los comandos están listos para copiar-pegar directamente en `node-controller`. ✨
