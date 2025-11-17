# Comandos para Detector HTTP Flood
## DPDK + OctoSketch en Monitor

---

## 🔧 1. Compilar Detector

**En Monitor:**

```bash
cd /local/dpdk_100g/http_flood_advance/detector_system

# Compilar
make clean
make

# Verificar
ls -lh http_flood_detector
```

---

## 🚀 2. Ejecutar Detector

### Configurar Hugepages (si no está hecho)
```bash
# Verificar hugepages
grep HugePages /proc/meminfo

# Si es necesario, configurar
sudo sysctl -w vm.nr_hugepages=2048
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

### Bind NIC a DPDK
```bash
# Ver NICs disponibles
sudo dpdk-devbind.py --status

# Bind NIC a driver DPDK (mlx5 para Mellanox)
sudo dpdk-devbind.py --bind=vfio-pci 0000:03:00.0

# O si usas driver nativo Mellanox (recomendado):
# No necesitas hacer bind, mlx5 soporta DPDK directamente
```

### Ejecutar Detector Básico
```bash
sudo ./http_flood_detector -l 0-1 -n 4 -- -p 0
```

### Ejecutar Detector con Más Cores
```bash
sudo ./http_flood_detector -l 0-3 -n 4 -a 0000:03:00.0 -- -p 0
```

---

## 🎬 3. Escenario Completo de Detección

### Terminal 1 - Monitor (Detector)
```bash
cd /local/dpdk_100g/http_flood_advance/detector_system

# Lanzar detector
sudo ./http_flood_detector -l 0-1 -n 4 -- -p 0
```

### Terminal 2 - Controlador (Baseline)
```bash
cd /local/dpdk_100g/http_flood_advance/benign_generator

# Tráfico baseline continuo a 10 Gbps
sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q
```

### Terminal 3 - Atacante (Ataque después de 30 seg)
```bash
cd /local/dpdk_100g/http_flood_advance/attack_generator

# Esperar establecer baseline
sleep 30

# Lanzar ataque a 5 Gbps
sudo ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 5000 -q
```

---

## 📊 4. Salida del Detector

### Durante Baseline (Normal):
```
╔══════════════════════════════════════════════════════════════════════╗
║               HTTP FLOOD DETECTOR - STATISTICS                      ║
╚══════════════════════════════════════════════════════════════════════╝

[PACKET COUNTERS]
  Total packets:      5234567
  HTTP packets:       5234567
  Baseline (192.168): 5234567 (100.0%)
  Attack (203.0.113): 0 (0.0%)

[TRAFFIC ANALYSIS]
  Unique IPs:         8234
  Heavy hitters:      0

[HTTP METHODS]
  GET:                4711110 (90.0%)
  POST:               523457 (10.0%)
  Other:              0

[URL CONCENTRATION]
  Top URL:            /
  Top URL count:      523456 (10.0%)

[ALERT STATUS]
  Alert level:        NONE
```

### Durante Ataque (Detectado):
```
╔══════════════════════════════════════════════════════════════════════╗
║               HTTP FLOOD DETECTOR - STATISTICS                      ║
╚══════════════════════════════════════════════════════════════════════╝

[PACKET COUNTERS]
  Total packets:      15234567
  HTTP packets:       15234567
  Baseline (192.168): 5234567 (34.4%)
  Attack (203.0.113): 10000000 (65.6%)

[TRAFFIC ANALYSIS]
  Unique IPs:         158
  Heavy hitters:      145

[HTTP METHODS]
  GET:                14923456 (98.0%)
  POST:               311111 (2.0%)
  Other:              0

[URL CONCENTRATION]
  Top URL:            /
  Top URL count:      12000000 (78.8%)

[ALERT STATUS]
  Alert level:        HIGH
  Reason:             HIGH ATTACK RATE: 8456 pps from botnet (65.6% of traffic) | URL CONCENTRATION: 78.8% to '/' | METHOD ANOMALY: 98.0% GET requests
```

---

## 🔍 5. Reglas de Detección

| Regla | Umbral | Descripción |
|-------|--------|-------------|
| **Rate Anomaly** | >10K pps/IP | IP individual con tráfico alto |
| **URL Concentration** | >80% misma URL | Ataque focalizado |
| **Botnet Detection** | >50 IPs únicas | Muchas IPs, bajo rate c/u |
| **Heavy Hitters** | >1000 paquetes/IP | IPs sospechosas |
| **Method Anomaly** | >98% GET | Ratio GET anormal |

---

## 📝 6. Niveles de Alerta

| Nivel | Color | Condición |
|-------|-------|-----------|
| **NONE** | Blanco | Tráfico normal |
| **LOW** | Amarillo | Sospechoso (Heavy Hitters o Method Anomaly) |
| **MEDIUM** | Naranja | Probable ataque (URL Concentration o Botnet) |
| **HIGH** | Rojo | Ataque confirmado (Alta tasa desde botnet) |
| **CRITICAL** | Rojo intenso | Ataque severo |

---

## 🛠️ 7. Troubleshooting

### Error: "Cannot create mbuf pool"
```bash
# Aumentar hugepages
echo 4096 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

### Error: "Cannot init port"
```bash
# Verificar NIC con DPDK
sudo dpdk-devbind.py --status

# Si usas Mellanox, verificar driver mlx5
modprobe mlx5_core
```

### No recibe paquetes
```bash
# Verificar que NIC está en modo promiscuo
sudo ethtool -K ens1f0 promisc on

# O usar tcpdump para verificar tráfico
sudo tcpdump -i ens1f0 -c 10
```

### Detector muy lento
```bash
# Usar más cores
sudo ./http_flood_detector -l 0-7 -n 4 -- -p 0

# Optimizar NIC
sudo ethtool -C ens1f0 adaptive-rx off rx-usecs 0
```

---

## 🎯 8. Parámetros DPDK

```bash
# Básico (1 core worker)
-l 0-1        # Usar cores 0 (main) y 1 (worker)
-n 4          # 4 memory channels

# Multi-core (4 workers)
-l 0-4        # Cores 0-4
-n 4

# Con NIC específica
-a 0000:03:00.0   # PCI address de la NIC

# Más memoria
--socket-mem=2048,2048   # 2GB por socket
```

---

## 📈 9. Monitoreo Avanzado

### Ver estadísticas en tiempo real
El detector muestra stats cada 5 segundos automáticamente.

### Guardar logs
```bash
sudo ./http_flood_detector -l 0-1 -n 4 -- -p 0 2>&1 | tee detector_log.txt
```

### Análisis posterior
```bash
# Buscar alertas en log
grep "Alert level" detector_log.txt

# Ver solo alertas HIGH
grep "HIGH" detector_log.txt
```

---

## 🔧 10. Ajuste de Umbrales

Editar en `http_flood_detector.c`:

```c
/* Detection thresholds */
#define RATE_THRESHOLD_PPS 10000      // Ajustar según baseline
#define URL_CONCENTRATION_THRESHOLD 0.80  // 80% → Más estricto: 0.70
#define BOTNET_IPS_THRESHOLD 50       // Ajustar según red
#define HEAVY_HITTER_THRESHOLD 1000   // Paquetes para ser heavy hitter

/* Time window */
#define DETECTION_WINDOW_SEC 1        // Ventana de detección
#define STATS_INTERVAL_SEC 5          // Intervalo de stats
```

Recompilar después de modificar:
```bash
make clean && make
```

---

## ✅ 11. Verificación de Funcionamiento

### Paso 1: Solo Baseline (No debe detectar)
```bash
# Monitor
sudo ./http_flood_detector -l 0-1 -n 4 -- -p 0

# Controlador
sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q

# Resultado esperado: Alert level = NONE
```

### Paso 2: Baseline + Ataque (Debe detectar)
```bash
# Monitor (detector corriendo)

# Controlador (baseline)
sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q

# Atacante (después de 30 seg)
sleep 30 && sudo ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 5000 -q

# Resultado esperado: Alert level = HIGH o MEDIUM
```

---

## 🔑 Configuración

- **Monitor Interface:** ens1f0
- **Monitor IP:** 10.0.0.1
- **Baseline IPs:** 192.168.1.X
- **Attack IPs:** 203.0.113.X
- **Detection Window:** 1 segundo
- **Stats Interval:** 5 segundos
