# Experimento HTTP Flood - 500 Segundos

## Configuración del Experimento

**Duración Total**: 500 segundos (8 minutos 20 segundos)

### Fases del Experimento

1. **Fase Baseline**: 0-200s (200 segundos)
   - Tráfico: Solo baseline normal
   - Instancias: 50 procesos paralelos
   - Rate: 200,000 pps por instancia
   - **Total esperado**: ~10M pps

2. **Fase de Ataque**: 200-500s (300 segundos)
   - Tráfico: Baseline + Ataque HTTP Flood
   - Baseline: 50 instancias (continúa)
   - Ataque: 100 instancias adicionales
   - Rate ataque: 150,000 pps por instancia
   - **Total esperado**: ~25M pps (10M baseline + 15M ataque)

## Instrucciones de Ejecución

### Terminal 1: Detector DPDK

```bash
cd /root/dpdk_100g/http_flood_advance/detector_system

sudo timeout 510 ./build/http_flood_detector -l 0-3 -n 4 -- -p 0x1 2>&1 | tee ../../results/results_http_flood_500s.log
```

**Parámetros del detector:**
- `-l 0-3`: Usa cores 0-3
- `-n 4`: 4 canales de memoria
- `-- -p 0x1`: Puerto 0
- `timeout 510`: Ejecuta por 510 segundos (500s + margen)
- Output: `results/results_http_flood_500s.log`

### Terminal 2: Generador de Tráfico (esperar 5 segundos)

```bash
cd /root/dpdk_100g/http_flood_advance

# Dar permisos de ejecución
chmod +x experiment_500s.sh

# Ejecutar experimento
sudo ./experiment_500s.sh
```

### Terminal 3: Monitoreo (opcional)

```bash
# Monitoreo en tiempo real del tráfico
watch -n 1 'sar -n DEV 1 1 | grep ens1f0'

# O con ifstat
ifstat -i ens1f0 1
```

## Timeline del Experimento

```
0s      ├─────────────────────────────────────┤ Baseline (10M pps)
        │                                      │
200s    ├──────────────────────────────────────────────────────┤ Baseline + Ataque (25M pps)
        │                                      │                │
        │                                      │                │
500s    └──────────────────────────────────────────────────────┘
```

## Comandos Rápidos

### Ejecutar experimento completo

```bash
# Terminal 1 - Detector
cd /root/dpdk_100g/http_flood_advance/detector_system
sudo timeout 510 ./build/http_flood_detector -l 0-3 -n 4 -- -p 0x1 2>&1 | tee ../../results/results_http_flood_500s.log

# Terminal 2 - Tráfico (esperar 5s después del detector)
cd /root/dpdk_100g/http_flood_advance
sudo ./experiment_500s.sh
```

### Detener experimento manualmente

```bash
# Detener generadores de tráfico
sudo pkill tcpreplay

# Detener detector (Ctrl+C en su terminal)
```

## Análisis de Resultados

Después del experimento, analizar los resultados:

```bash
cd /root/dpdk_100g/http_flood_advance/analysis

python3 analyze_results.py
```

Esto generará:
- Métricas completas del experimento
- Gráficas guardadas en `analysis/`:
  - `01_traffic_analysis.png`
  - `02_detection_metrics.png`
  - `03_attack_effectiveness.png`

## Ajustes de Intensidad

Si quieres modificar la intensidad del experimento, edita estas variables en `experiment_500s.sh`:

```bash
# Para más tráfico baseline (ej. 20M pps)
BASELINE_INSTANCES=100
BASELINE_PPS=200000

# Para ataque más intenso (ej. 30M pps)
ATTACK_INSTANCES=200
ATTACK_PPS=150000
```

## Notas Importantes

1. **Orden de inicio**: Siempre iniciar el detector PRIMERO, luego el tráfico
2. **Logs**: El detector guarda en `results/results_http_flood_500s.log`
3. **Capacidad**: ~25M pps ≈ 20-30% de la capacidad de 100Gbps
4. **Memoria**: Asegúrate de tener suficientes hugepages configuradas
5. **Tiempo**: El experimento completo dura ~8.5 minutos

## Troubleshooting

### Si el detector no inicia:
```bash
# Verificar hugepages
cat /proc/meminfo | grep Huge

# Verificar binding DPDK
dpdk-devbind.py --status
```

### Si hay poco tráfico:
```bash
# Verificar procesos tcpreplay
ps aux | grep tcpreplay | wc -l

# Debería mostrar 50 (baseline) o 150 (baseline+ataque)
```

### Si el sistema se satura:
```bash
# Reducir instancias en experiment_500s.sh
BASELINE_INSTANCES=25  # Reduce a 5M pps
ATTACK_INSTANCES=50    # Reduce a 7.5M pps
```
cd /local/dpdk_100g/http_flood_advance/detector_system
  sudo timeout 510 ./build/http_flood_detector -l 1-2 -n 4 -a 0000:41:00.0 -- -p 0 2>&1 | tee ../../results/results_http_flood_500s.log

  ---
  Terminal 2: Tráfico Baseline (esperar 5s después del detector)

  cd /local/dpdk_100g/http_flood_advance

  for i in {1..50}; do sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=200000 --loop=0 --quiet baseline_5M.pcap & done

  ---
  Terminal 3: Ataque (ejecutar después de 200 segundos)

  cd /local/dpdk_100g/http_flood_advance

  for i in {1..100}; do sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=150000 --loop=0 --quiet attack_mixed_1M.pcap & done

---

## Configuración Ajustada para Enlace 100G (Realista)

La configuración original (10M + 15M = 25M pps) excede la capacidad del enlace de 100G (~140 Gbps teóricos).

### Configuración Realista (~28% utilización del enlace)

**Objetivo**:
- Proporción 40% baseline / 60% attack durante fase de ataque
- Utilización ~28 Gbps del enlace de 100G
- Total durante ataque: ~5M pps

### Parámetros Ajustados

| Fase | Instancias | PPS/instancia | Total PPS | Gbps (~700 bytes/pkt) |
|------|------------|---------------|-----------|------------------------|
| Baseline | 50 | 40,000 | 2M | ~11 Gbps |
| Attack | 100 | 30,000 | 3M | ~17 Gbps |
| **Total (ataque)** | 150 | - | **5M** | **~28 Gbps** |

### Comandos Ajustados

#### Terminal 1: Detector DPDK

```bash
cd /local/dpdk_100g/http_flood_advance/detector_system
sudo timeout 510 ./build/http_flood_detector -l 1-2 -n 4 -a 0000:41:00.0 -- -p 0 2>&1 | tee ../../results/results_http_flood_500s_2.log
```

#### Terminal 2: Tráfico Baseline (esperar 5s después del detector)

```bash
cd /local/dpdk_100g/http_flood_advance

# 50 instancias × 40,000 pps = 2M pps (~11 Gbps)
for i in {1..50}; do sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=40000 --loop=0 --quiet baseline_5M.pcap & done
```

#### Terminal 3: Ataque (ejecutar después de 200 segundos)

```bash
cd /local/dpdk_100g/http_flood_advance

# 100 instancias × 30,000 pps = 3M pps (~17 Gbps)
for i in {1..100}; do sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=30000 --loop=0 --quiet attack_mixed_1M.pcap & done
```

### Resultados Esperados

- **Fase Baseline (0-200s)**: 2M pps, 100% tráfico legítimo
- **Fase Ataque (200-500s)**: 5M pps total
  - Baseline: 2M pps (40%)
  - Attack: 3M pps (60%)
- **Utilización enlace**: ~28% de 100G

### Timeline Ajustado

```
0s      ├─────────────────────────────────────┤ Baseline (2M pps, ~11 Gbps)
        │                                      │
200s    ├──────────────────────────────────────────────────────┤ Total (5M pps, ~28 Gbps)
        │  40% Baseline (2M pps)               │                │
        │  60% Attack (3M pps)                 │                │
500s    └──────────────────────────────────────────────────────┘
```

### Variantes de Intensidad

#### Alta utilización (~56 Gbps, ~56% del enlace)

```bash
# Baseline: 100 instancias × 40,000 pps = 4M pps
for i in {1..100}; do sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=40000 --loop=0 --quiet baseline_5M.pcap & done

# Attack: 200 instancias × 30,000 pps = 6M pps
for i in {1..200}; do sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=30000 --loop=0 --quiet attack_mixed_1M.pcap & done
```

#### Baja utilización (~14 Gbps, ~14% del enlace)

```bash
# Baseline: 25 instancias × 40,000 pps = 1M pps
for i in {1..25}; do sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=40000 --loop=0 --quiet baseline_5M.pcap & done

# Attack: 50 instancias × 30,000 pps = 1.5M pps
for i in {1..50}; do sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=30000 --loop=0 --quiet attack_mixed_1M.pcap & done
```