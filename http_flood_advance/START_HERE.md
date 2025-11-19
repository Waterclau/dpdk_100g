# 🚀 START HERE - Setup para TUS Nodos

**Última actualización**: 2025-11-13
**Estado**: ✅ Configuración verificada

---

## 📍 Tu Configuración

```
┌─────────────────────────────────┐
│   node-controller               │
│   128.110.219.172 (management)  │
│                                 │
│   ens1f0 (100G)                 │
│   IP:  10.10.1.5                │
│   MAC: 0c:42:a1:8b:2f:c8        │
│   PCI: 0000:01:00.0             │
└───────────────┬─────────────────┘
                │
                │ Baseline Traffic
                │ (HTTP)
                v
┌─────────────────────────────────┐
│   node-monitor                  │
│   128.110.219.171 (management)  │
│                                 │
│   ens1f0 (100G)                 │
│   IP:  10.10.1.2                │
│   MAC: 0c:42:a1:8c:dd:0c        │
└─────────────────────────────────┘

✅ Conectividad verificada: 0.192ms
✅ Red: 10.10.1.0/24
✅ MTU: 9000 (jumbo frames)
```

---

## ⚡ Opción 1: Setup Automático (RECOMENDADO)

### En node-controller:

```bash
# 1. Ir al directorio
cd ~/dpdk_100g/http_flood_advance

# 2. Ejecutar setup automático
sudo ./scripts/setup_my_controller.sh

# El script hace TODO automáticamente:
# ✅ Verifica conectividad con Monitor
# ✅ Configura hugepages
# ✅ Carga driver DPDK
# ✅ Bindea NIC automáticamente
# ✅ Verifica compilación
# ✅ Crea directorio de datos
# ✅ Genera archivo de comandos
```

### 3. Ejecutar generador:

```bash
cd benign_generator

# DPDK (tiempo real)
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# O Python (dataset)
python3 baseline_dataset_generator.py -d 1000 -p heavy \
  --dst-ip 10.10.1.2 --dst-mac 0c:42:a1:8c:dd:0c
```

**¡Listo!** El script lo hace todo por ti. ✨

---

## 🔧 Opción 2: Setup Manual

Si prefieres hacerlo paso a paso, sigue: **`SETUP_MIS_NODOS.md`**

---

## 📚 Documentación Disponible

| Archivo | Descripción |
|---------|-------------|
| **`START_HERE.md`** | ⭐ Este archivo - Inicio rápido |
| **`SETUP_MIS_NODOS.md`** | 📘 Guía completa paso a paso con tus valores |
| **`config/my_nodes_config.json`** | ⚙️ Tu configuración en JSON |
| **`scripts/setup_my_controller.sh`** | 🤖 Script de setup automático |
| **`MY_COMMANDS.txt`** | 📋 Comandos de referencia (generado por script) |
| **`README_BASELINE.md`** | 📖 Documentación general del baseline |
| **`QUICK_START_BASELINE.md`** | ⚡ Quick start genérico |

---

## 🎯 Comandos Esenciales

### Setup (una vez)
```bash
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
# En otra terminal
watch -n 1 'ethtool -S ens1f0 | grep tx_packets'
```

### Detener
```
Ctrl+C
```

---

## 🔍 Verificar que Funciona

### 1. Ver tráfico saliendo:
```bash
watch -n 1 'ethtool -S ens1f0 | grep tx_packets'
# Deberías ver el contador incrementando
```

### 2. Capturar algunos paquetes:
```bash
sudo tcpdump -i ens1f0 -c 10 -nn host 10.10.1.2
# Deberías ver paquetes HTTP
```

### 3. En el Monitor (opcional):
```bash
# Conectarse a node-monitor
ssh node-monitor

# Ver si llega tráfico
sudo tcpdump -i ens1f0 -c 10 -nn host 10.10.1.5
```

---

## 📊 Perfiles Disponibles

| Perfil | Rate | Uso |
|--------|------|-----|
| `very_low` | 100 rps | Testing |
| `low` | 1K rps | Sitio pequeño |
| **`medium`** | **10K rps** | **RECOMENDADO** |
| `high` | 50K rps | E-commerce grande |
| `very_high` | 100K rps | Plataforma mayor |

Para cambiar perfil en Python:
```bash
python3 baseline_dataset_generator.py -d 300 -p high \
  --dst-ip 10.10.1.2 --dst-mac 0c:42:a1:8c:dd:0c
```

---

## 🛠️ Troubleshooting Rápido

### Script falla en binding
```bash
# Bindear manualmente
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0
```

### "Cannot allocate mbuf"
```bash
# Más hugepages
echo 8192 | sudo tee /proc/sys/vm/nr_hugepages
```

### No compila
```bash
# Instalar dependencias
sudo apt-get update
sudo apt-get install -y dpdk dpdk-dev libdpdk-dev build-essential
```

### Rate muy bajo
```bash
# CPU a performance
sudo cpupower frequency-set -g performance
```

---

## 📦 Resultados

Los datos se guardan en:
```
benign_generator/baseline_traffic_data/
├── baseline_*.pcap
└── baseline_*_stats.json
```

Para copiar a tu máquina:
```bash
scp cesteban@node-controller:~/dpdk_100g/http_flood_advance/benign_generator/baseline_traffic_data/*.pcap .
```

---

## ✅ Checklist Pre-Ejecución

- [ ] Script de setup ejecutado exitosamente
- [ ] Hugepages configuradas (4096+)
- [ ] NIC bindeada a DPDK
- [ ] Ping a Monitor funciona (10.10.1.2)
- [ ] Binario compilado (`build/baseline_traffic_gen`)
- [ ] Terminal de monitoreo lista

---

## 🎓 Próximos Pasos

1. **Ahora**: Ejecutar generador baseline (5 min)
2. **Después**: Crear generador de ataque (próximo desarrollo)
3. **Luego**: Configurar detector en node-monitor
4. **Final**: Experimento completo (baseline + ataque)

---

## 💡 Tips

- 🔵 **Usa el script automático** para setup rápido
- 🟢 **Perfil medium** es lo mejor para comenzar
- 🟡 **Monitorea siempre** en terminal separada
- 🔴 **Test corto primero** (60s) antes de runs largos
- ⚪ **Python es más fácil** que DPDK para empezar

---

## 📞 Ayuda

**Setup automático falla?** → Ver `SETUP_MIS_NODOS.md` para manual

**Comandos olvidados?** → Ver `MY_COMMANDS.txt` (generado por script)

**Config detallada?** → Ver `config/my_nodes_config.json`

**Todo lo demás?** → Ver `README_BASELINE.md`

---

## 🚀 TL;DR (3 comandos)

```bash
# 1. Setup (una vez)
sudo ./scripts/setup_my_controller.sh

# 2. Ejecutar (cada experimento)
cd benign_generator
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# 3. Monitorear (otra terminal)
watch -n 1 'ethtool -S ens1f0 | grep tx_packets'
```

---

**¡Ya estás listo!** Ejecuta el script y comienza a generar tráfico baseline. 🎉
