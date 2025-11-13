# Generador de Tráfico Baseline Realista

Sistema de generación de tráfico HTTP baseline para establecer comportamiento normal de servidor web antes de ataques DDoS.

## 🎯 Objetivo

Generar **tráfico HTTP baseline realista** que simula el comportamiento normal de un servidor web con:
- ✅ Variaciones temporales naturales (hora del día)
- ✅ Distribución realista de requests (GET 75%, POST 20%, etc.)
- ✅ Múltiples fuentes (65K+ IPs únicas)
- ✅ Patrones de sesión realistas
- ✅ Think time y pausas naturales

**Esto NO es tráfico de ataque** - es el baseline normal contra el cual se detectarán ataques.

---

## 📊 Perfiles de Tráfico Disponibles

| Perfil | Rate Base | Rate Peak | Throughput | Descripción |
|--------|-----------|-----------|------------|-------------|
| `very_low` | 100 rps | 300 rps | ~0.1 Mbps | Website muy pequeño |
| `low` | 1K rps | 3K rps | ~1 Mbps | Sitio personal/pequeño |
| **`medium`** | **10K rps** | **30K rps** | **~10 Mbps** | **Website popular (RECOMENDADO)** |
| `high` | 50K rps | 150K rps | ~50 Mbps | E-commerce grande |
| `very_high` | 100K rps | 300K rps | ~100 Mbps | Plataforma mayor |

**rps** = requests per second

---

## 🚀 Quick Start (3 minutos)

### 1. Setup Sistema

```bash
# Hugepages
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages

# Bind NIC a DPDK
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0  # Cambia PCI address
```

### 2. Compilar

```bash
cd benign_generator
make clean && make
```

### 3. Ejecutar

**Opción A: DPDK (Tiempo Real)**
```bash
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary
```

**Opción B: Python (Dataset)**
```bash
python3 baseline_dataset_generator.py -d 300 -p medium -o baseline.pcap
```

**Detener:** `Ctrl+C`

---

## 📁 Archivos Principales

```
benign_generator/
├── baseline_traffic_dpdk.c           # Generador DPDK (tiempo real)
├── baseline_dataset_generator.py     # Generador Python (datasets)
├── benign_traffic_dpdk.c             # Legacy (alto rendimiento)
├── benign_dataset_generator.py       # Legacy (datasets grandes)
├── Makefile                          # Compilación
└── README.md                         # Docs detalladas
```

---

## 🔧 Configuración

### Manual: Node Controller

Ver: `config/node_controller_baseline.json`

Configurar:
- `dst_ip`: IP del nodo destino (ej: "10.0.0.1")
- `dst_mac`: MAC del nodo destino
- `nic_pci`: PCI address de tu NIC
- `selected_profile`: Perfil de tráfico ("medium" recomendado)

### Generador DPDK

El generador DPDK usa valores por defecto razonables:
- **Base rate**: 50K pps (configurable en código)
- **Cores**: 4 (usa `-l 0-3`)
- **Variaciones**: Habilitadas (simula hora del día)
- **HTTP templates**: 20 tipos diferentes de requests

Para ajustar, editar `baseline_traffic_dpdk.c`:
```c
#define DEFAULT_BASE_RATE_PPS 50000      // Cambiar rate base
#define MIN_RATE_PPS 10000
#define MAX_RATE_PPS 200000
```

### Generador Python

Configurable por línea de comandos:
```bash
python3 baseline_dataset_generator.py \
    -d 300 \                          # Duración (segundos)
    -p medium \                       # Perfil
    --dst-ip 10.0.0.1 \              # IP destino
    --dst-mac bb:bb:bb:bb:bb:bb \    # MAC destino
    --start-hour 14                  # Hora simulada de inicio
```

---

## 📈 Variaciones Temporales

El generador simula patrones diarios realistas:

| Hora del Día | Rate Multiplier | Descripción |
|--------------|-----------------|-------------|
| 00:00 - 06:00 | 0.3x | Tráfico nocturno bajo |
| 06:00 - 12:00 | 0.5x → 1.0x | Subiendo gradualmente |
| 12:00 - 18:00 | 1.0x → 1.2x | **PEAK HOURS** |
| 18:00 - 24:00 | 0.6x → 0.3x | Bajando gradualmente |

**Plus:** Ruido aleatorio de ±15% para realismo adicional.

---

## 📊 Distribución de Tráfico HTTP

### Métodos HTTP
- **GET**: 75%
- **POST**: 20%
- **PUT**: 3%
- **DELETE**: 1%
- **HEAD**: 1%

### Tipos de Contenido
- **Páginas HTML**: 40%
- **API calls**: 25%
- **Recursos estáticos**: 20%
- **Contenido dinámico**: 15%

### Patrones de Sesión
- **70%**: Requests individuales
- **30%**: Sesiones multi-request (1-10 requests)
- **Promedio**: 3.5 requests por sesión

---

## 🎬 Uso en Experimentos

### Fase 1: Baseline (5 minutos)

```bash
# Iniciar generador baseline
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# Dejar correr 300 segundos
# El detector establece métricas baseline
```

### Fase 2: Ataque (5 minutos)

```bash
# Generador baseline CONTINÚA corriendo
# Mientras tanto, en otro nodo se inicia el ataque
# El detector ve tráfico mixto (baseline + ataque)
```

### Fase 3: Recovery (1 minuto)

```bash
# Ataque se detiene
# Baseline continúa solo
# El detector verifica recuperación
```

**Total:** 11 minutos (660 segundos)

---

## 🔍 Monitoreo

### Ver Estadísticas en Tiempo Real

```bash
# El generador DPDK imprime stats cada segundo:
=== Baseline Traffic Generator Statistics ===
Total Packets:              600000
Total Bytes:              480000000 (480.00 MB)
Dropped:                        0
Current Rate:             49850.23 pps (49.85 Kpps)
Throughput:                39.88 Mbps (0.040 Gbps)
Avg Packet:                800.00 bytes
Base Rate:                 50000 pps
=============================================
```

### Monitoreo Externo

```bash
# Terminal separada

# Ver packets transmitidos
watch -n 1 'ethtool -S eth0 | grep tx_packets'

# Ver rate en Gbps
watch -n 1 'echo "scale=3; $(cat /sys/class/net/eth0/statistics/tx_bytes) * 8 / 1000000000" | bc'

# Capturar algunos paquetes
sudo tcpdump -i eth0 -c 20 -nn -v
```

---

## 📦 Resultados

### Ubicación

```
baseline_traffic_data/
├── baseline_medium_20251113_143022.pcap       # Captura de tráfico
└── baseline_medium_20251113_143022_stats.json # Estadísticas
```

### Estadísticas Incluidas

```json
{
  "profile": "Medium traffic - popular website",
  "total_sessions": 900000,
  "total_packets": 3000000,
  "total_bytes": 2400000000,
  "method_GET": 2250000,
  "method_POST": 600000,
  "...": "..."
}
```

---

## 🆚 DPDK vs Python

| Característica | DPDK Generator | Python Generator |
|----------------|----------------|------------------|
| **Velocidad** | Muy alta (50K+ pps) | Moderada (~10K pps) |
| **Uso** | Tiempo real | Datasets offline |
| **Latencia** | Muy baja | No crítica |
| **Flexibilidad** | Baja (recompilación) | Alta (CLI args) |
| **PCAP** | No (por rendimiento) | Sí (siempre) |
| **Recomendado para** | Experimentos en vivo | Generación de datasets |

---

## 🛠️ Troubleshooting

### "No Ethernet ports available"

```bash
sudo dpdk-devbind.py --status
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0
```

### "Cannot allocate mbuf"

```bash
echo 8192 | sudo tee /proc/sys/vm/nr_hugepages
cat /proc/meminfo | grep Huge
```

### Rate muy bajo

```bash
# CPU frequency to performance
sudo cpupower frequency-set -g performance

# Usar más cores
sudo ./build/baseline_traffic_gen -l 0-7 -n 4 --proc-type=primary
```

---

## 📚 Documentación Completa

- **Guía Manual Node Controller**: `docs/NODE_CONTROLLER_MANUAL.md`
- **Configuración Detallada**: `config/node_controller_baseline.json`
- **README Completo**: `benign_generator/README.md`

---

## ⚡ Comandos de Referencia Rápida

```bash
# Setup
echo 4096 | sudo tee /proc/sys/vm/nr_hugepages
sudo dpdk-devbind.py --bind=vfio-pci 0000:81:00.0

# Build
cd benign_generator && make

# Run DPDK
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# Run Python
python3 baseline_dataset_generator.py -d 300 -p medium

# Monitor
watch -n 1 'ethtool -S eth0 | grep tx_packets'

# Stop
Ctrl+C
```

---

## 🎓 Conceptos Clave

1. **Baseline**: Comportamiento normal del sistema antes del ataque
2. **Realismo**: El tráfico debe parecer natural (variaciones, diversidad)
3. **Perfil Medium**: 10K rps base, mejor para la mayoría de casos
4. **Variaciones**: El rate cambia según hora del día + ruido aleatorio
5. **4 Cores**: Suficientes para baseline (no necesitas 8 como en alto rendimiento)

---

## 📊 Ejemplo de Salida (5 minutos @ medium)

```
Profile:         Medium traffic - popular website
Duration:        300 seconds
Total Packets:   3,000,000
Total Bytes:     2.4 GB
Avg Rate:        10,000 pps
Peak Rate:       12,000 pps (hora 14:00)
Min Rate:        8,500 pps (hora 04:00)
Sessions:        900,000
Unique IPs:      65,536
Methods:         GET (75%), POST (20%), Other (5%)
```

---

## ✅ Checklist Pre-Experimento

- [ ] Hugepages configuradas (4096+)
- [ ] NIC bindeada a DPDK
- [ ] Generadores compilados
- [ ] Config actualizada (IP, MAC, PCI)
- [ ] Perfil seleccionado (medium recomendado)
- [ ] Test corto ejecutado (60s) exitosamente
- [ ] Terminal de monitoreo preparada

---

## 🔗 Próximos Pasos

1. ✅ **Generador baseline funcionando**
2. ⏳ Crear generador de ataque HTTP flood
3. ⏳ Configurar detector en Node Monitor
4. ⏳ Ejecutar experimento completo de 3 fases
5. ⏳ Analizar resultados y métricas de detección

---

**¿Listo para empezar?** → `docs/NODE_CONTROLLER_MANUAL.md`

**¿Problemas?** → Ver sección Troubleshooting arriba
