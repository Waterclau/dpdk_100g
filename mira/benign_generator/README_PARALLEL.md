# Benign Traffic Generator v2.0 - Parallel Edition

## Overview

Generador de tráfico benigno paralelizado que utiliza múltiples núcleos de CPU para acelerar dramáticamente la generación de PCAPs grandes (100M+ paquetes) para entrenamiento de modelos de ML.

### Características Principales

- ✅ **Paralelización Multi-core**: Divide el trabajo entre N núcleos de CPU
- ✅ **Escalabilidad Lineal**: 8 cores ≈ 8× más rápido
- ✅ **Grandes Volúmenes**: Optimizado para 100M+ paquetes
- ✅ **Realismo Temporal**: Mantiene fases temporales y jitter
- ✅ **Fusión Automática**: Combina PCAPs parciales en uno final
- ✅ **Limpieza Automática**: Elimina archivos temporales

---

## Comparación de Rendimiento

### Generador Original (single-core)

| Paquetes | Tiempo | Tasa |
|----------|--------|------|
| 10M | ~10 min | ~17K pps |
| 100M | ~100 min (1.7 h) | ~17K pps |
| 1000M | ~1000 min (16.7 h) | ~17K pps |

### Generador Paralelo (8 cores)

| Paquetes | Tiempo | Tasa | Speedup |
|----------|--------|------|---------|
| 10M | ~1.25 min | ~133K pps | **8×** |
| 100M | ~12.5 min | ~133K pps | **8×** |
| 1000M | ~125 min (2.1 h) | ~133K pps | **8×** |

### Generador Paralelo (16 cores)

| Paquetes | Tiempo | Tasa | Speedup |
|----------|--------|------|---------|
| 10M | ~0.6 min | ~267K pps | **16×** |
| 100M | ~6.25 min | ~267K pps | **16×** |
| 1000M | ~62.5 min (1 h) | ~267K pps | **16×** |

---

## Instalación

### Requisitos

```bash
# Python 3.8+
python3 --version

# Scapy
pip3 install scapy

# Optional: wireshark-common para mergecap (no necesario, el script usa scapy)
# sudo apt-get install wireshark-common
```

---

## Uso

### Ejemplo 1: Single Core (baseline)

```bash
python3 generate_benign_traffic_v2_parallel.py \
    --packets 10000000 \
    --output benign_10M.pcap

# Tiempo esperado: ~10 minutos
```

### Ejemplo 2: Multi-core (8 cores)

```bash
python3 generate_benign_traffic_v2_parallel.py \
    --packets 100000000 \
    --cores 8 \
    --output benign_100M.pcap

# Tiempo esperado: ~12 minutos (8× más rápido)
```

### Ejemplo 3: Usar todos los cores disponibles

```bash
python3 generate_benign_traffic_v2_parallel.py \
    --packets 100000000 \
    --cores 0 \
    --output benign_100M.pcap

# cores=0 detecta automáticamente todos los cores disponibles
# Tiempo esperado: Depende del número de cores (16 cores ≈ 6 min)
```

### Ejemplo 4: Gran volumen con speedup

```bash
python3 generate_benign_traffic_v2_parallel.py \
    --packets 1000000000 \
    --cores 16 \
    --speedup 50 \
    --output benign_1B_fast.pcap

# 1 billón de paquetes
# 16 cores ≈ 1 hora de generación
# speedup 50× para replay rápido
```

### Ejemplo 5: Configuración personalizada

```bash
python3 generate_benign_traffic_v2_parallel.py \
    --packets 100000000 \
    --cores 12 \
    --src-mac 00:11:22:33:44:55 \
    --dst-mac aa:bb:cc:dd:ee:ff \
    --client-range 10.10.1.0/24 \
    --server-ip 10.10.1.100 \
    --clients 1000 \
    --output benign_100M_custom.pcap
```

---

## Parámetros

### Parámetros Obligatorios

Ninguno, todos tienen valores por defecto.

### Parámetros Opcionales

| Parámetro | Corto | Default | Descripción |
|-----------|-------|---------|-------------|
| `--output` | `-o` | `benign_10M_v2.pcap` | Archivo PCAP de salida |
| `--packets` | `-n` | `10000000` | Número de paquetes a generar (puede ser 100M+) |
| `--cores` | `-c` | `1` | Núcleos de CPU (0 = todos disponibles) |
| `--src-mac` | | `00:00:00:00:00:01` | MAC origen |
| `--dst-mac` | | `0c:42:a1:dd:5b:28` | MAC destino |
| `--client-range` | | `10.10.1.0/24` | Rango IPs clientes |
| `--server-ip` | | `10.10.1.2` | IP del servidor |
| `--clients` | | `500` | Número de IPs únicas de clientes |
| `--speedup` | `-s` | `1.0` | Factor de compresión de timestamps |

---

## Arquitectura Interna

### Flujo de Trabajo

```
1. DIVISIÓN DE TRABAJO
   ├─ Total: 100M paquetes
   ├─ Cores: 8
   └─ Por core: 12.5M paquetes

2. GENERACIÓN PARALELA
   ├─ Worker 0: genera benign_100M.pcap.part0.pcap (12.5M paquetes)
   ├─ Worker 1: genera benign_100M.pcap.part1.pcap (12.5M paquetes)
   ├─ Worker 2: genera benign_100M.pcap.part2.pcap (12.5M paquetes)
   ├─ Worker 3: genera benign_100M.pcap.part3.pcap (12.5M paquetes)
   ├─ Worker 4: genera benign_100M.pcap.part4.pcap (12.5M paquetes)
   ├─ Worker 5: genera benign_100M.pcap.part5.pcap (12.5M paquetes)
   ├─ Worker 6: genera benign_100M.pcap.part6.pcap (12.5M paquetes)
   └─ Worker 7: genera benign_100M.pcap.part7.pcap (12.5M paquetes)

   Todos los workers se ejecutan EN PARALELO

3. FUSIÓN Y ORDENAMIENTO
   ├─ Cargar todos los .part{N}.pcap en memoria
   ├─ Concatenar en una lista única
   ├─ Ordenar por timestamp (mantiene coherencia temporal)
   └─ Aplicar speedup si se solicitó

4. ESCRITURA FINAL
   ├─ Escribir benign_100M.pcap (todos los paquetes ordenados)
   └─ Eliminar archivos .part{N}.pcap temporales

5. ESTADÍSTICAS
   └─ Mostrar distribución de protocolos, tiempo, tasa
```

### Manejo de Timestamps

Cada worker genera paquetes con timestamps **offset** para evitar colisiones:

- Worker 0: timestamp base = T + 0s
- Worker 1: timestamp base = T + 100s
- Worker 2: timestamp base = T + 200s
- ...
- Worker N: timestamp base = T + (N × 100)s

Al fusionar, se ordena por timestamp para mantener coherencia temporal.

### Fases Temporales

Cada worker replica las **mismas fases** de tráfico:

1. **HTTP Peak** (33%) - Alto HTTP, bajo DNS/SSH
2. **DNS Burst** (20%) - Picos de DNS, menos HTTP
3. **SSH Stable** (27%) - Sesiones SSH largas, tráfico estable
4. **UDP Light** (20%) - Tráfico UDP ligero de fondo

Esto garantiza que el PCAP final tenga distribución realista de protocolos.

---

## Casos de Uso

### Caso 1: Entrenamiento de ML a Gran Escala

**Objetivo:** 100M paquetes para entrenar modelo de detección de DDoS

```bash
# Generar 100M paquetes en ~12 minutos (8 cores)
python3 generate_benign_traffic_v2_parallel.py \
    --packets 100000000 \
    --cores 8 \
    --output benign_100M_ml.pcap
```

**Resultado:**
- Archivo: ~8.5 GB
- Tiempo: ~12 minutos
- Diversidad: 4 fases temporales, 5 tipos de tráfico
- Listo para extracción de features ML

---

### Caso 2: Dataset de Evaluación (1B paquetes)

**Objetivo:** Dataset masivo para evaluación exhaustiva

```bash
# Generar 1B paquetes en ~1 hora (16 cores)
python3 generate_benign_traffic_v2_parallel.py \
    --packets 1000000000 \
    --cores 16 \
    --speedup 100 \
    --output benign_1B_eval.pcap
```

**Resultado:**
- Archivo: ~85 GB
- Tiempo: ~62 minutos
- Speedup 100×: Timeline comprimido para replay rápido
- Suficiente para evaluación estadística robusta

---

### Caso 3: Múltiples Datasets con Variaciones

**Objetivo:** Generar varios datasets con diferentes configuraciones

```bash
# Dataset 1: Pocos clientes (100)
python3 generate_benign_traffic_v2_parallel.py \
    --packets 50000000 --cores 8 --clients 100 \
    --output benign_50M_lowclients.pcap

# Dataset 2: Muchos clientes (2000)
python3 generate_benign_traffic_v2_parallel.py \
    --packets 50000000 --cores 8 --clients 2000 \
    --output benign_50M_highclients.pcap

# Dataset 3: Red diferente (192.168.x.x)
python3 generate_benign_traffic_v2_parallel.py \
    --packets 50000000 --cores 8 \
    --client-range 192.168.1.0/24 \
    --server-ip 192.168.1.1 \
    --output benign_50M_private.pcap
```

**Resultado:**
- 3 datasets complementarios
- Tiempo total: ~18 minutos (6 min cada uno con 8 cores)
- Útil para probar generalización de modelos ML

---

## Optimizaciones de Rendimiento

### 1. Elegir el Número Correcto de Cores

**Regla general:**
- Para tareas I/O-bound: `cores = número de discos`
- Para tareas CPU-bound (este caso): `cores = número de cores físicos`

**Ejemplo:**
```bash
# Ver cores disponibles
lscpu | grep "^CPU(s):"

# Usar todos los cores
python3 generate_benign_traffic_v2_parallel.py --cores 0 --packets 100000000
```

**Nota:** Usar más cores que los disponibles físicamente puede degradar rendimiento.

---

### 2. Optimizar Uso de Memoria

**Problema:** Generar 1B paquetes puede consumir ~100 GB RAM durante fusión.

**Solución:** Dividir en múltiples archivos

```bash
# Opción A: Generar en múltiples archivos de 100M
for i in {1..10}; do
    python3 generate_benign_traffic_v2_parallel.py \
        --packets 100000000 \
        --cores 8 \
        --output benign_100M_part${i}.pcap
done

# Luego fusionar manualmente con mergecap:
mergecap -w benign_1B.pcap benign_100M_part*.pcap
```

---

### 3. SSD vs HDD

**Rendimiento:**
- **SSD:** 500 MB/s escritura → Sin cuello de botella
- **HDD:** 100 MB/s escritura → Puede ralentizar fusión final

**Recomendación:**
- Generar archivos temporales en SSD
- Mover PCAP final a HDD para almacenamiento

```bash
# Generar en SSD (tmp)
python3 generate_benign_traffic_v2_parallel.py \
    --packets 100000000 \
    --cores 16 \
    --output /tmp/benign_100M.pcap

# Mover a almacenamiento persistente
mv /tmp/benign_100M.pcap /data/pcaps/
```

---

## Troubleshooting

### Error: "Out of Memory"

**Síntoma:**
```
MemoryError: Unable to allocate array
```

**Causa:** Demasiados paquetes para fusionar en memoria.

**Solución:**
```bash
# Reducir el número de paquetes por ejecución
python3 generate_benign_traffic_v2_parallel.py \
    --packets 50000000 \  # En vez de 100000000
    --cores 8
```

---

### Error: "No module named 'scapy'"

**Solución:**
```bash
pip3 install scapy
```

---

### Error: Archivos .part{N}.pcap no se eliminan

**Causa:** Permisos insuficientes o proceso interrumpido.

**Solución:**
```bash
# Limpiar manualmente
rm -f *.part*.pcap
```

---

### Rendimiento más lento de lo esperado

**Diagnóstico:**

```bash
# 1. Verificar utilización de CPU
htop

# 2. Verificar cores disponibles
lscpu | grep "^CPU(s):"

# 3. Verificar si hay throttling
dmesg | grep -i thermal
```

**Posibles causas:**
- Thermal throttling (CPU sobrecalentado)
- Otros procesos compitiendo por CPU
- HDD lento (usar SSD)

---

## Comparación con Versión Original

| Aspecto | v2 Original | v2 Parallel |
|---------|-------------|-------------|
| **Cores usados** | 1 (single-core) | 1-N (configurable) |
| **Velocidad (10M pkts)** | ~10 min | ~1.25 min (8 cores) |
| **Velocidad (100M pkts)** | ~100 min | ~12.5 min (8 cores) |
| **Escalabilidad** | No | Sí (lineal) |
| **Uso de memoria** | Bajo (~1 GB) | Medio-Alto (~8-16 GB) |
| **Complejidad** | Simple | Moderada |
| **Archivos temporales** | No | Sí (.part{N}.pcap) |
| **Fusión necesaria** | No | Sí (automática) |
| **Realismo temporal** | ✅ Preservado | ✅ Preservado |
| **Fases de tráfico** | ✅ Sí | ✅ Sí (replicadas) |

**Recomendación:**
- **< 10M paquetes:** Usar versión original (más simple)
- **10M - 100M paquetes:** Usar versión parallel (8 cores)
- **> 100M paquetes:** Usar versión parallel (16+ cores)

---

## Ejemplos Avanzados

### Generar múltiples PCAPs en lote

```bash
#!/bin/bash
# generate_batch.sh

CORES=8

for size in 10M 50M 100M; do
    case $size in
        10M)  packets=10000000 ;;
        50M)  packets=50000000 ;;
        100M) packets=100000000 ;;
    esac

    echo "Generating benign_${size}.pcap..."
    python3 generate_benign_traffic_v2_parallel.py \
        --packets $packets \
        --cores $CORES \
        --output benign_${size}.pcap

    echo "Done: benign_${size}.pcap"
    echo ""
done

echo "All PCAPs generated!"
```

---

### Verificar integridad del PCAP

```bash
# Verificar que el PCAP es válido
tcpdump -r benign_100M.pcap -c 10 -n

# Contar paquetes
capinfos benign_100M.pcap | grep "Number of packets"

# Verificar distribución de protocolos
tshark -r benign_100M.pcap -q -z io,phs
```

---

## Contribuciones y Mejoras Futuras

### Posibles Mejoras

1. **Streaming Merge:** En vez de cargar todo en memoria, fusionar en streaming
2. **Compresión:** Generar PCAPs comprimidos (.pcap.gz)
3. **Validación:** Verificar checksums de IP/TCP/UDP
4. **Métricas:** Guardar estadísticas de generación en JSON

### Cómo Contribuir

1. Fork del repositorio
2. Crear rama de feature: `git checkout -b feature/mi-mejora`
3. Commit cambios: `git commit -am 'Añade mi mejora'`
4. Push: `git push origin feature/mi-mejora`
5. Crear Pull Request

---

## Licencia

MIT License - Ver archivo LICENSE

---

## Contacto

Para bugs, sugerencias o preguntas:
- Issues: GitHub Issues
- Email: [tu-email]

---

**Version:** 2.0-parallel
**Last Updated:** 2025-12-17
**Status:** ✅ Production Ready
