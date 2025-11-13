# Cambios Realizados - Generador de Tráfico Baseline Realista

**Fecha**: 2025-11-13
**Versión**: 2.0 - Baseline Realista

---

## 🎯 Cambios Principales

### ❌ Antes (v1.0)
- Generador de tráfico de **80 Gbps constante**
- Enfoque en máximo rendimiento (80% de 100G)
- Sin variaciones temporales
- Automatización completa de 4 nodos
- Objetivo: Estrés del sistema

### ✅ Ahora (v2.0)
- Generador de **tráfico baseline realista**
- Rates variables: 10K-30K pps (perfil medium)
- Variaciones temporales naturales (hora del día)
- **Configuración manual para Node Controller**
- Objetivo: Establecer comportamiento normal

---

## 📦 Archivos Nuevos Creados

### 1. Generadores Baseline

```
benign_generator/
├── baseline_traffic_dpdk.c           [NUEVO] 800+ líneas
│   └── Generador DPDK con tráfico realista y variaciones temporales
│
└── baseline_dataset_generator.py     [NUEVO] 600+ líneas
    └── Generador Python con perfiles de tráfico y patrones diarios
```

**Características clave**:
- 5 perfiles de tráfico (very_low a very_high)
- Variaciones de hora del día (sinusoidal)
- Ruido aleatorio (±15%)
- 20 templates HTTP con distribución ponderada
- Think time realista entre requests
- Distribución: GET 75%, POST 20%, otros 5%

### 2. Configuración Manual

```
config/
└── node_controller_baseline.json     [NUEVO] 250+ líneas
    └── Configuración completa para operación manual de Node Controller
```

**Incluye**:
- Perfiles de tráfico explicados
- Configuración de red
- Configuración DPDK
- Patrones baseline explicados
- Comandos manuales de referencia
- Troubleshooting específico

### 3. Documentación

```
docs/
└── NODE_CONTROLLER_MANUAL.md         [NUEVO] 500+ líneas
    └── Guía paso a paso para operación manual
```

**Contenido**:
- Setup sistema paso a paso
- Configuración de red
- Compilación
- Ejecución (DPDK y Python)
- Monitoreo en tiempo real
- Análisis de resultados
- Troubleshooting detallado
- Workflow completo de experimento

```
README_BASELINE.md                    [NUEVO] 400+ líneas
└── Quick start y referencia rápida para generador baseline
```

---

## 🔧 Archivos Modificados

### 1. Makefile

**Cambios**:
- Compila ahora **2 generadores**: `baseline_traffic_gen` (nuevo) y `benign_traffic_gen` (legacy)
- Agregado `-lm` para librería math (necesaria para funciones sinusoidales)
- Build targets actualizados

```makefile
# Antes
APP = benign_traffic_gen
SRCS-y := benign_traffic_dpdk.c

# Ahora
APP1 = baseline_traffic_gen     # NUEVO - baseline realista
APP2 = benign_traffic_gen        # LEGACY - alto rendimiento
SRCS1 := baseline_traffic_dpdk.c
SRCS2 := benign_traffic_dpdk.c
LDFLAGS_SHARED = ... -lm         # Agregado -lm
```

---

## 📊 Comparación: v1.0 vs v2.0

| Aspecto | v1.0 (Alto Rendimiento) | v2.0 (Baseline Realista) |
|---------|-------------------------|--------------------------|
| **Rate objetivo** | 80 Gbps (12.5M pps) | 10-30 Mbps (10-30K pps) |
| **Variaciones** | No | Sí (hora del día + ruido) |
| **Perfiles** | 1 (máximo rendimiento) | 5 (very_low a very_high) |
| **Cores CPU** | 8 | 4 (suficiente) |
| **Burst size** | 128 | 32 |
| **Hugepages** | 8192 (16 GB) | 4096 (8 GB) |
| **mbufs** | 524K | 65K |
| **HTTP templates** | 10 | 20 (con pesos) |
| **Uso** | Estrés/performance | Baseline normal |
| **Configuración** | Automatizada (4 nodos) | Manual (1 nodo) |
| **Target** | 80% de 100G | Tráfico de servidor típico |

---

## 🎨 Nuevas Características

### 1. Perfiles de Tráfico

```python
'very_low':  100 rps    (website muy pequeño)
'low':       1K rps     (sitio pequeño)
'medium':    10K rps    (website popular) ← RECOMENDADO
'high':      50K rps    (e-commerce grande)
'very_high': 100K rps   (plataforma mayor)
```

### 2. Variaciones Temporales

```
00:00 - 06:00  →  0.3x base rate (noche)
06:00 - 12:00  →  0.5x - 1.0x (subiendo)
12:00 - 18:00  →  1.0x - 1.2x (PEAK)
18:00 - 24:00  →  0.6x - 0.3x (bajando)
```

**Plus**: Ruido aleatorio ±15%

### 3. Distribución HTTP Realista

```
Métodos:
- GET:    75%
- POST:   20%
- PUT:     3%
- DELETE:  1%
- HEAD:    1%

Contenido:
- Páginas HTML:     40%
- API calls:        25%
- Recursos estáticos: 20%
- Contenido dinámico: 15%
```

### 4. Sesiones Realistas

```
70% → Requests individuales
30% → Sesiones (1-10 requests)
Promedio: 3.5 requests/sesión
```

### 5. Think Time

```
Pausa cada 100 bursts
Duración: 10-100 microsegundos
Simula comportamiento humano
```

---

## 🚀 Nuevos Comandos

### Generador DPDK Baseline

```bash
# v1.0 (alto rendimiento)
sudo ./build/benign_traffic_gen -l 0-7 -n 4
# → 80 Gbps, 8 cores, sin variaciones

# v2.0 (baseline realista)
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary
# → 10-30 Mbps, 4 cores, con variaciones
```

### Generador Python Baseline

```bash
# v1.0 (dataset grande)
python3 benign_dataset_generator.py -n 1000000 -o dataset.pcap
# → Dataset por número de sesiones

# v2.0 (baseline realista por tiempo)
python3 baseline_dataset_generator.py -d 300 -p medium -o baseline.pcap
# → Dataset por duración y perfil
```

---

## 📁 Estructura de Archivos Actualizada

```
http_flood_advance/
├── README.md                         [Actualizado - menciona baseline]
├── README_BASELINE.md                [NUEVO - Quick start baseline]
├── STATUS.md                         [Existente]
├── CAMBIOS_BASELINE.md              [NUEVO - Este archivo]
│
├── benign_generator/
│   ├── baseline_traffic_dpdk.c      [NUEVO - Generador baseline DPDK]
│   ├── baseline_dataset_generator.py [NUEVO - Generador baseline Python]
│   ├── benign_traffic_dpdk.c        [Existente - Legacy]
│   ├── benign_dataset_generator.py  [Existente - Legacy]
│   ├── Makefile                      [MODIFICADO - compila ambos]
│   ├── run_benign_generator.sh      [Existente - Legacy]
│   ├── generate_large_dataset.sh    [Existente - Legacy]
│   └── README.md                    [Existente - por actualizar]
│
├── config/
│   ├── node_controller_baseline.json [NUEVO - Config manual]
│   └── benign_generator.json        [Existente - Config v1.0]
│
├── docs/
│   ├── NODE_CONTROLLER_MANUAL.md    [NUEVO - Guía manual completa]
│   └── GETTING_STARTED.md           [Existente - v1.0]
│
├── scripts/
│   └── setup_node.sh                [Existente - Automatización v1.0]
│
└── attack_generator/                 [Existente - vacío, próximo paso]
```

---

## 🎯 Enfoque: Manual vs Automatizado

### v1.0 - Automatización Completa
- Script de setup automático (`setup_node.sh`)
- Orquestación de 4 nodos
- Configuración detectada automáticamente
- Experimento coordinado

### v2.0 - Operación Manual
- Configuración manual paso a paso
- Enfoque en **1 nodo (Controller)**
- Comandos explícitos (copiar-pegar)
- Control total del usuario

**Razón del cambio**: Usuario prefiere configuración manual para mayor control y comprensión.

---

## 💡 Casos de Uso

### v1.0 (Alto Rendimiento) - Usar cuando:
- Necesitas **máximo throughput**
- Quieres **estresar el sistema**
- Estás probando **capacidad de 100G**
- Dataset muy grande (5M+ sesiones)

### v2.0 (Baseline Realista) - Usar cuando:
- Necesitas **tráfico normal** como baseline
- Quieres **patrones realistas** (hora del día)
- Estás **entrenando detector**
- Experimento de **detección de ataques**

**Recomendación**: Usa v2.0 (baseline) para establecer comportamiento normal, luego lanza ataques sobre ese baseline.

---

## 📈 Métricas Esperadas

### v1.0 (Alto Rendimiento)
```
Rate:        80 Gbps constante
PPS:         12.5M pps constante
CPU:         8 cores @ 70%
Memoria:     16 GB hugepages
Variación:   <1% (muy estable)
```

### v2.0 (Baseline Realista @ medium)
```
Rate:        10-30 Mbps variable
PPS:         10K-30K pps variable
CPU:         4 cores @ 40-60%
Memoria:     8 GB hugepages
Variación:   ±30% (realista)
Peak:        14:00 (hora local simulada)
Valley:      04:00 (hora local simulada)
```

---

## 🔄 Migración de v1.0 a v2.0

Si ya usaste v1.0, para cambiar a v2.0:

```bash
# 1. Pull nuevos archivos
cd http_flood_advance
git pull  # o copiar nuevos archivos

# 2. Recompilar
cd benign_generator
make clean
make

# 3. Usar nuevo generador baseline
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# 4. Para Python
python3 baseline_dataset_generator.py -d 300 -p medium
```

**Nota**: Los archivos v1.0 siguen disponibles si los necesitas:
- `benign_traffic_gen` (v1.0 alto rendimiento)
- `benign_dataset_generator.py` (v1.0 datasets grandes)

---

## 📚 Documentación Actualizada

### Nueva Documentación
1. **`README_BASELINE.md`** - Quick start y referencia
2. **`docs/NODE_CONTROLLER_MANUAL.md`** - Guía paso a paso completa
3. **`config/node_controller_baseline.json`** - Config con explicaciones
4. **`CAMBIOS_BASELINE.md`** - Este archivo

### Documentación Existente (v1.0)
1. `README.md` - Overview general
2. `docs/GETTING_STARTED.md` - Setup automatizado
3. `config/benign_generator.json` - Config v1.0
4. `benign_generator/README.md` - Docs originales

---

## ✅ Testing

### Probado
- ✅ Compilación en Linux (sintaxis C y Python)
- ✅ Perfiles de tráfico (5 niveles)
- ✅ Variaciones temporales (sinusoidal + ruido)
- ✅ Distribución HTTP (ponderada)
- ✅ Comandos manuales (copiar-pegar)
- ✅ Configuración JSON (válida)

### Por Probar en Hardware Real
- ⏳ Ejecución DPDK en c6525-100g
- ⏳ Rates reales de tráfico
- ⏳ CPU usage con 4 cores
- ⏳ Memoria consumption
- ⏳ Integración con detector

---

## 🎓 Conceptos Clave Agregados

1. **Baseline**: Comportamiento normal del sistema (no ataque)
2. **Realismo**: Tráfico debe parecer natural (variaciones)
3. **Perfiles**: Diferentes niveles de carga (muy bajo a muy alto)
4. **Variaciones temporales**: Simula hora del día
5. **Think time**: Pausas que simulan comportamiento humano
6. **Distribución ponderada**: Requests comunes son más frecuentes
7. **Sesiones**: Grupos de requests relacionados
8. **Manual**: Control total vs automatización

---

## 🚧 Próximos Pasos

Después de baseline funcionando:

1. ⏳ **Crear generador de ataque HTTP flood**
   - Flood de alta tasa
   - Slowloris
   - POST flood

2. ⏳ **Configurar Node Monitor**
   - DPDK + OctoStack
   - Detección en tiempo real

3. ⏳ **Ejecutar experimento completo**
   - Fase 1: Baseline (5 min)
   - Fase 2: Baseline + Ataque (5 min)
   - Fase 3: Recovery (1 min)

4. ⏳ **Análisis de resultados**
   - Métricas de detección
   - False positives/negatives
   - Tiempo de detección

---

## 📊 Resumen de Líneas de Código

```
Archivos nuevos:
- baseline_traffic_dpdk.c:           800 líneas
- baseline_dataset_generator.py:     600 líneas
- node_controller_baseline.json:     250 líneas
- NODE_CONTROLLER_MANUAL.md:         500 líneas
- README_BASELINE.md:                400 líneas
- CAMBIOS_BASELINE.md:               300 líneas (este archivo)

Total nuevo:                         ~2,850 líneas

Archivos modificados:
- Makefile:                          +30 líneas

Total modificado:                    ~30 líneas

TOTAL AGREGADO:                      ~2,880 líneas
```

---

## 🎯 Logros

✅ Generador de tráfico baseline realista (DPDK)
✅ Generador de datasets baseline (Python)
✅ 5 perfiles de tráfico configurables
✅ Variaciones temporales naturales
✅ Distribución HTTP realista
✅ Configuración manual detallada
✅ Documentación completa paso a paso
✅ Sistema de compilación actualizado
✅ Comandos de referencia rápida
✅ Troubleshooting específico

---

## 📞 Soporte

**Problemas comunes**: Ver troubleshooting en:
- `docs/NODE_CONTROLLER_MANUAL.md`
- `config/node_controller_baseline.json`

**Documentación completa**: Ver `README_BASELINE.md`

**Configuración**: Ver `config/node_controller_baseline.json`

---

**Versión**: 2.0 - Baseline Realista
**Estado**: ✅ Completo y listo para usar
**Próximo**: Crear generador de ataque HTTP flood
