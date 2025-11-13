# 📋 Resumen de Configuración - TUS Nodos

**Generado**: 2025-11-13
**Estado**: ✅ Completo y Listo

---

## 🎯 Lo que se Actualizó

He actualizado **TODO** el sistema para usar la configuración real de tus nodos CloudLab:

### ✅ Archivos Creados para TI

1. **`START_HERE.md`** ⭐
   - Punto de inicio principal
   - Setup en 3 comandos
   - Incluye tus IPs, MACs, PCI

2. **`SETUP_MIS_NODOS.md`** 📘
   - Guía completa paso a paso
   - Todos los comandos con tus valores reales
   - Troubleshooting específico

3. **`config/my_nodes_config.json`** ⚙️
   - Tu configuración completa en JSON
   - Incluye toda la topología
   - Comandos de referencia

4. **`scripts/setup_my_controller.sh`** 🤖
   - Script automático de setup
   - Detecta y usa tus valores
   - Hace TODO el setup

---

## 🌐 Tu Configuración Real

### Node Controller (Generador Baseline)
```
Hostname:   node-controller
Management: 128.110.219.172

Data Plane (ens1f0):
├── IP:     10.10.1.5
├── MAC:    0c:42:a1:8b:2f:c8
├── PCI:    0000:01:00.0
├── NIC:    Mellanox ConnectX-5
└── MTU:    9000
```

### Node Monitor (Detector)
```
Hostname:   node-monitor
Management: 128.110.219.171

Data Plane (ens1f0):
├── IP:     10.10.1.2
├── MAC:    0c:42:a1:8c:dd:0c
├── NIC:    Mellanox ConnectX-5
└── MTU:    9000
```

### Conectividad
```
✅ Ping: 10.10.1.5 → 10.10.1.2
✅ RTT: 0.192 ms (excelente!)
✅ Loss: 0%
✅ Red: 10.10.1.0/24
```

---

## 🚀 Cómo Usar (3 pasos)

### Paso 1: Setup Automático

```bash
# En node-controller
cd ~/dpdk_100g/http_flood_advance
sudo ./scripts/setup_my_controller.sh
```

El script hace:
- ✅ Verifica conectividad con 10.10.1.2
- ✅ Configura 4096 hugepages
- ✅ Carga driver vfio-pci
- ✅ Bindea ens1f0 (0000:01:00.0) a DPDK
- ✅ Verifica compilación
- ✅ Crea directorio de datos
- ✅ Genera archivo MY_COMMANDS.txt

### Paso 2: Ejecutar Generador

**Opción A - DPDK (tiempo real):**
```bash
cd benign_generator
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary
```

**Opción B - Python (datasets):**
```bash
cd benign_generator
python3 baseline_dataset_generator.py -d 300 -p medium \
  --dst-ip 10.10.1.2 \
  --dst-mac 0c:42:a1:8c:dd:0c \
  -o baseline_5min.pcap
```

### Paso 3: Monitorear

```bash
# En otra terminal
watch -n 1 'ethtool -S ens1f0 | grep tx_packets'
```

---

## 📂 Estructura de Archivos

```
http_flood_advance/
│
├── START_HERE.md                    ⭐ EMPIEZA AQUÍ
├── SETUP_MIS_NODOS.md              📘 Guía completa paso a paso
├── RESUMEN_CONFIGURACION.md        📋 Este archivo
│
├── config/
│   └── my_nodes_config.json        ⚙️ Tu configuración en JSON
│
├── scripts/
│   └── setup_my_controller.sh      🤖 Setup automático
│
├── benign_generator/
│   ├── baseline_traffic_dpdk.c     🔵 Generador DPDK
│   ├── baseline_dataset_generator.py 🟢 Generador Python
│   ├── Makefile                    🔧 Compilación
│   └── baseline_traffic_data/      📦 Resultados (se crea auto)
│
└── docs/
    └── NODE_CONTROLLER_MANUAL.md   📖 Manual completo
```

---

## 💾 Valores Configurados

### Red
| Parámetro | Valor |
|-----------|-------|
| **Red experimental** | 10.10.1.0/24 |
| **Controller IP** | 10.10.1.5 |
| **Monitor IP** | 10.10.1.2 |
| **Controller MAC** | 0c:42:a1:8b:2f:c8 |
| **Monitor MAC** | 0c:42:a1:8c:dd:0c |
| **Puerto destino** | 80 |
| **MTU** | 9000 |

### Hardware
| Parámetro | Valor |
|-----------|-------|
| **Interface** | ens1f0 (ambos nodos) |
| **NIC** | Mellanox ConnectX-5 |
| **PCI Controller** | 0000:01:00.0 |
| **Velocidad** | 100 Gbps |
| **Driver DPDK** | vfio-pci |

### DPDK
| Parámetro | Valor |
|-----------|-------|
| **Hugepages** | 4096 x 2MB (8 GB) |
| **Cores** | 4 (0-3) |
| **Memory channels** | 4 |
| **Process type** | primary |

### Tráfico
| Parámetro | Valor |
|-----------|-------|
| **Perfil** | medium |
| **Base rate** | 50K pps (10-30K variable) |
| **IPs origen** | 192.168.0.0/16 (65K IPs) |
| **Variaciones** | Habilitadas (hora del día) |

---

## 🎯 Comandos de Referencia

### Setup (una vez)
```bash
cd ~/dpdk_100g/http_flood_advance
sudo ./scripts/setup_my_controller.sh
```

### Ejecutar DPDK
```bash
cd benign_generator
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary
```

### Ejecutar Python
```bash
cd benign_generator
python3 baseline_dataset_generator.py -d 300 -p medium \
  --dst-ip 10.10.1.2 --dst-mac 0c:42:a1:8c:dd:0c
```

### Monitorear
```bash
# Packets
watch -n 1 'ethtool -S ens1f0 | grep tx_packets'

# Capturar
sudo tcpdump -i ens1f0 -c 20 -nn host 10.10.1.2

# Verificar
ping 10.10.1.2
```

### Verificar Setup
```bash
# Hugepages
cat /proc/meminfo | grep Huge

# NIC binding
sudo dpdk-devbind.py --status

# Binario
ls -lh build/baseline_traffic_gen
```

### Cleanup
```bash
# Unbind NIC
sudo dpdk-devbind.py --bind=mlx5_core 0000:01:00.0
```

---

## 📊 Qué Esperar

### Durante Ejecución (DPDK)

```
=== Realistic Baseline Traffic Generator ===
Base Rate:         50000 pps (50.00 Kpps)
Profile:           VARIABLE (realistic)
Worker Cores:      4

=== Baseline Traffic Generator Statistics ===
Total Packets:              600000
Total Bytes:              480000000 (480.00 MB)
Current Rate:             49850 pps (49.85 Kpps)
Throughput:                39.88 Mbps (0.040 Gbps)
```

### Salida Python

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

## ✅ Checklist de Verificación

Antes de ejecutar, verifica:

- [ ] Script de setup ejecutado exitosamente
- [ ] Hugepages: 4096 (cat /proc/meminfo | grep HugePages_Total)
- [ ] NIC bindeada: 0000:01:00.0 drv=vfio-pci
- [ ] Conectividad: ping 10.10.1.2 funciona
- [ ] Compilado: build/baseline_traffic_gen existe
- [ ] Directorio: baseline_traffic_data/ creado

Si todo ✅, estás listo para ejecutar!

---

## 🔧 Si Algo Falla

### Setup automático falla
```bash
# Ver guía manual
cat SETUP_MIS_NODOS.md
```

### No bindea NIC
```bash
# Manual
sudo modprobe vfio-pci
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0
```

### No compila
```bash
# Instalar deps
sudo apt-get install -y dpdk dpdk-dev libdpdk-dev build-essential
cd benign_generator
make clean && make
```

### No hay tráfico
```bash
# Verificar NIC
sudo dpdk-devbind.py --status

# Verificar hugepages
cat /proc/meminfo | grep Huge

# Ver logs del generador (en pantalla)
```

---

## 📚 Documentación

| Archivo | Para qué |
|---------|----------|
| **START_HERE.md** | Inicio rápido (lee este primero) |
| **SETUP_MIS_NODOS.md** | Guía paso a paso completa |
| **config/my_nodes_config.json** | Tu config en JSON |
| **scripts/setup_my_controller.sh** | Setup automático |
| **README_BASELINE.md** | Info general de baseline |
| **docs/NODE_CONTROLLER_MANUAL.md** | Manual detallado |
| **QUICK_START_BASELINE.md** | Quick start genérico |

---

## 🎓 Conceptos Clave

1. **Controller (10.10.1.5)** → Genera tráfico baseline
2. **Monitor (10.10.1.2)** → Recibe y analiza tráfico
3. **Baseline** → Tráfico normal (no ataque)
4. **ens1f0** → Interface 100G en ambos nodos
5. **DPDK** → Bypass kernel para alta velocidad
6. **Hugepages** → Memoria para DPDK
7. **vfio-pci** → Driver DPDK para NIC

---

## 🚀 Flujo de Trabajo

```
1. Setup (una vez)
   └─> sudo ./scripts/setup_my_controller.sh

2. Ejecutar generador
   └─> sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

3. Monitorear (otra terminal)
   └─> watch -n 1 'ethtool -S ens1f0 | grep tx_packets'

4. Ver resultados
   └─> ls baseline_traffic_data/

5. Cleanup (opcional)
   └─> sudo dpdk-devbind.py --bind=mlx5_core 0000:01:00.0
```

---

## 💡 Tips Importantes

- 🔵 **Setup automático primero** - usa el script
- 🟢 **Test corto primero** - 60s para verificar
- 🟡 **Monitorea siempre** - en terminal separada
- 🔴 **SSH management OK** - usa eno33 (no se afecta)
- ⚪ **Python más fácil** - para empezar

---

## 📞 Ayuda Rápida

**¿Por dónde empiezo?**
→ Lee `START_HERE.md`

**¿Necesito todos los pasos?**
→ No, usa el script: `sudo ./scripts/setup_my_controller.sh`

**¿Qué comandos uso?**
→ El script genera `MY_COMMANDS.txt` con todo

**¿Dónde están mis valores?**
→ `config/my_nodes_config.json`

**¿Cómo sé que funciona?**
→ `watch -n 1 'ethtool -S ens1f0 | grep tx_packets'`

---

## 🎯 TL;DR

```bash
# Todo en 3 comandos:

# 1. Setup (una vez)
cd ~/dpdk_100g/http_flood_advance
sudo ./scripts/setup_my_controller.sh

# 2. Ejecutar
cd benign_generator
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# 3. Monitorear (otra terminal)
watch -n 1 'ethtool -S ens1f0 | grep tx_packets'
```

---

**¡TODO ESTÁ CONFIGURADO CON TUS VALORES REALES!**

No necesitas editar ningún archivo. Los scripts y comandos ya usan:
- ✅ Tu IP: 10.10.1.5
- ✅ Monitor IP: 10.10.1.2
- ✅ Tu MAC: 0c:42:a1:8b:2f:c8
- ✅ Monitor MAC: 0c:42:a1:8c:dd:0c
- ✅ Tu PCI: 0000:01:00.0
- ✅ Interface: ens1f0

**Solo ejecuta el script y listo!** 🚀
