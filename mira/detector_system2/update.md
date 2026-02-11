# detector_system2: Measure-Only Mode

## Resumen de cambios

`detector_system2` es una copia de `detector_system` con las siguientes modificaciones:

### Eliminado: Toda la logica de deteccion por umbrales

Se ha eliminado completamente la logica de alertas basada en umbrales fijos. El detector ahora solo **mide** y **registra** estadisticas. La clasificacion ataque/benigno se delega al modelo ML.

**Bloques eliminados en `detect_attacks()`:**
- Deteccion de UDP flood, SYN flood, ICMP flood, HTTP flood
- Deteccion de UDP-Lag (latencia)
- Deteccion de amplificacion: DNS, NTP, SNMP, SSDP, PortMap, NetBIOS, LDAP, MSSQL, TFTP
- Tracking de timestamps de deteccion (first detection latency, packets until detection)
- Alertas de heavy-hitter (se mantiene el conteo pero sin generar alertas)
- Deteccion de tendencias (trend detection)
- Deteccion de bursts (burst detection)
- Variables `attack_detected`, `alert_level`, `alert_reason`

**Bloques eliminados en `print_stats()`:**
- Seccion `[ATTACK DETECTIONS - Cumulative Events]` (todos serian 0)
- Seccion `[ALERT STATUS]` (nunca hay alertas)
- Seccion `[MULTI-LF (2025) COMPARISON]` (no hay deteccion que comparar)
- Seccion `[MULTIPLE DETECTION STATISTICS]` (histograma de latencias)

### Mantenido: Todo lo de medicion

- Contadores de paquetes por protocolo (DPI)
- OctoSketch global (per-worker + merge)
- OctoSketch per-protocol (12 sketches, modo `--sketch-adv`)
- Ring buffer temporal (100 ventanas x 50ms)
- Multi-scale sketches (50ms, 1s, 10s, 1min)
- Heavy-hitter counting (informativo, sin alertas)
- Escritura binaria `.bin` con 64 features (modo `--sketch-adv`)
- Escritura de log `.log` con todas las estadisticas
- `threshold_detected` siempre vale 0 en feature_window

### Cambios en print_stats()

- Banner cambiado a "MEASURE-ONLY MODE"
- OctoSketch metrics y heavy-hitter info ahora se imprimen siempre (antes solo con `detection_triggered`)
- Ring buffer features se imprimen siempre
- Mode indica "MEASURE-ONLY (no thresholds)"

---

## Estructura de experimentos (Opcion B)

Cada experimento sigue el patron: **50s baseline -> 100s ataque -> 50s baseline** (200s total).
El etiquetado se hace por tiempo, no por alertas del detector.

### Los 4 runs

#### Run 1: DPI + Sketch antiguo (56 features) - detector_system original

```bash
# Terminal 1 - Detector (detector_system original)
cd mira/detector_system
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- \
    --binary-log /tmp/run1_dpi_sketch.bin -p 0 2>&1 | tee /tmp/run1_dpi_sketch.log

# Terminal 2 - Generador
# t=0s:   baseline 50s
cd mira/traffic_generator
sudo ./mira_traffic_gen -l 16-19 -n 4 -w 0000:41:00.1 -- \
    --baseline-rate 1000000 --attack-rate 0 --duration 50 -p 0

# t=50s:  ataque 100s
sudo ./mira_traffic_gen -l 16-19 -n 4 -w 0000:41:00.1 -- \
    --baseline-rate 1000000 --attack-rate 5000000 --attack-type dns_amp --duration 100 -p 0

# t=150s: baseline 50s
sudo ./mira_traffic_gen -l 16-19 -n 4 -w 0000:41:00.1 -- \
    --baseline-rate 1000000 --attack-rate 0 --duration 50 -p 0
```

**Features**: 42 DPI + 14 sketch = 56 columnas
**Extraccion**: `feature_extractor.py` parsea el `.log`

#### Run 2: Sketch antiguo solo (14 features) - detector_system2

```bash
# Terminal 1 - Detector (detector_system2, SIN --sketch-adv)
cd mira/detector_system2
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 2>&1 | tee /tmp/run2_sketch_old.log

# Terminal 2 - Generador (mismo patron 50-100-50)
# ... (mismos 3 comandos que Run 1, cambiando tipo de ataque si se desea)
```

**Features**: 14 sketch (del .log, seccion Ring Buffer + Multi-Scale)
**Extraccion**: `feature_extractor.py` parsea el `.log` (solo extrae 14 features de sketch)

#### Run 3: Sketch-ADV nuevo (64 features) - detector_system2

```bash
# Terminal 1 - Detector (detector_system2, CON --sketch-adv)
cd mira/detector_system2
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- \
    --sketch-adv /tmp/run3_sketch_adv.bin -p 0

# Terminal 2 - Generador (mismo patron 50-100-50)
# ... (mismos 3 comandos)
```

**Features**: 14 global + 48 per-protocol + 2 packet size = 64 columnas
**Extraccion**: `sketch_adv_to_csv.py` (pendiente) lee el `.bin` directamente
**Formato binario**: Records de 528 bytes con magic `SKAV` (ver sketch_feb.md)

#### Run 4: Repetir Run 3 con otro tipo de ataque

```bash
# Terminal 1 - Detector (igual que Run 3)
cd mira/detector_system2
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- \
    --sketch-adv /tmp/run4_sketch_adv_syn.bin -p 0

# Terminal 2 - Generador (patron 50-100-50 pero con SYN flood)
sudo ./mira_traffic_gen ... --attack-type syn_flood --duration 100 ...
```

### Etiquetado por tiempo

Para cada run de 200s (ventanas de 50ms = 4000 ventanas):
- Ventanas 0-999 (0-50s): **label = 0** (baseline)
- Ventanas 1000-2999 (50-150s): **label = 1** (ataque)
- Ventanas 3000-3999 (150-200s): **label = 0** (baseline)

El etiquetado se aplica en el script de conversion a CSV, basado en el timestamp de cada record.

### Comparacion de modelos

| Aspecto | Run 1 (DPI+Sketch) | Run 2 (Sketch-old) | Run 3/4 (Sketch-ADV) |
|---------|--------------------|--------------------|----------------------|
| Features | 56 | 14 | 64 |
| DPI | Si (L7 parsing) | No | No |
| Per-protocol | No (global) | No (global) | Si (12 sketches) |
| Formato | .log -> CSV | .log -> CSV | .bin -> CSV |
| Overhead | Alto (DPI) | Bajo | Medio (~65 MB extra) |
| Detector | detector_system | detector_system2 | detector_system2 |
