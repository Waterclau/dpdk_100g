# DPDK PCAP Sender v2.0 - Adaptive Attack Mode 🔥

## Overview

El modo `--adaptive-attack` convierte el sender en un **generador continuo de tráfico DDoS** de alta velocidad con:

- ⚡ **Alta velocidad**: 10-12 Gbps sostenidos
- 🎯 **Fases de ataque dinámicas**: Cambio automático entre diferentes patrones de ataque
- 🔄 **Modo infinito**: Loop continuo hasta Ctrl+C
- 📊 **Estadísticas en tiempo real**: PPS, Gbps, distribución de ataques por tipo
- 🎲 **Variabilidad**: Jitter configurable para simular tráfico realista
- 🔥 **Multi-ataque**: SYN flood, UDP flood, HTTP flood, DNS flood, ICMP/random

## Características Clave

### 1. Uso del PCAP como Pool de Paquetes

**NO reproduce el PCAP secuencialmente**. En su lugar:
- Carga el PCAP completo en memoria
- Clasifica cada paquete por tipo de ataque (SYN, UDP, HTTP, DNS, ICMP)
- Crea índices para acceso aleatorio rápido
- Selecciona paquetes aleatoriamente según la fase activa

### 2. Fases de Ataque Dinámicas

Define diferentes "olas" de ataque con distribuciones variables:

```json
[
  {
    "duration": 20,
    "syn": 0.60,     // 60% SYN flood
    "udp": 0.20,     // 20% UDP flood
    "http": 0.10,    // 10% HTTP flood
    "dns": 0.05,     // 5% DNS flood
    "icmp": 0.05     // 5% ICMP/random
  },
  {
    "duration": 15,
    "syn": 0.30,     // Cambia a 30% SYN
    "udp": 0.50,     // 50% UDP (fase UDP dominante)
    "http": 0.10,
    "dns": 0.05,
    "icmp": 0.05
  },
  {
    "duration": 30,
    "syn": 0.20,
    "udp": 0.10,
    "http": 0.40,    // Fase HTTP/DNS dominante
    "dns": 0.25,
    "icmp": 0.05
  }
]
```

### 3. Clasificación Automática de Paquetes

El sender analiza cada paquete y lo clasifica como:

| Tipo | Criterio | Uso |
|------|----------|-----|
| **SYN** | TCP con flag SYN activado | SYN flood, SYN-ACK flood |
| **UDP Flood** | UDP a puertos != 53 | UDP amplification, UDP flood |
| **HTTP Flood** | TCP a puertos 80, 443, 8080 | HTTP GET/POST flood |
| **DNS Flood** | UDP a puerto 53 | DNS query flood, DNS amplification |
| **ICMP/Random** | ICMP u otros protocolos | ICMP flood, otros ataques |

### 4. Control de Velocidad y Jitter

```bash
--rate-gbps 10      # Target: 10 Gbps
--jitter 15         # ±15% variación en PPS (más realista)
```

## Uso Básico

### Compilar

```bash
cd /local/dpdk_100g/mira/attack_sender
make -f Makefile_v2 v2
```

### Ejemplo 1: Ataque Continuo Básico (12 Gbps, loop infinito)

```bash
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2.pcap \
    --adaptive-attack \
    --loop
```

**Salida esperada:**
```
╔══════════════════════════════════════════════════════════════════╗
║      DPDK PCAP SENDER v2.0 - ADAPTIVE ATTACK REPLAY MODE        ║
╚══════════════════════════════════════════════════════════════════╝

⚡ Attack Mode: ENABLED
🎯 Target rate: 12.0 Gbps  |  Jitter: ±0.0%  |  Loop: YES (infinite)
⏱️  Duration: Infinite (until Ctrl+C)
📊 Attack Phases: 3 loaded
🔥 Multi-core: Enabled (using all assigned cores)
🛑 Press Ctrl+C to stop

[ADAPTIVE-ATTACK] Using default attack phases (no file specified):
  Phase 1: 20s - SYN:60% UDP:20% HTTP:10% DNS:5% ICMP:5%
  Phase 2: 15s - SYN:30% UDP:50% HTTP:10% DNS:5% ICMP:5%
  Phase 3: 30s - SYN:20% UDP:10% HTTP:40% DNS:25% ICMP:5%

[ATTACK CLASSIFICATION]
  SYN/ACK:      4,200,000 packets (42.0%)
  UDP Flood:    2,800,000 packets (28.0%)
  HTTP Flood:   1,500,000 packets (15.0%)
  DNS Flood:    1,200,000 packets (12.0%)
  ICMP/Random:    300,000 packets ( 3.0%)

🔴 [PHASE 1/3] Starting Attack - 20s - SYN:60% UDP:20% HTTP:10% DNS:5% ICMP:5%
[5.0s] Phase 1/3 | 7200000 pkts (1.44 Mpps) | Avg: 11.98 Gbps | Inst: 12.01 Gbps
       Attack Mix: SYN:60% UDP:20% HTTP:10% DNS:6% ICMP:4%
[10.0s] Phase 1/3 | 14400000 pkts (1.44 Mpps) | Avg: 12.00 Gbps | Inst: 12.02 Gbps
       Attack Mix: SYN:61% UDP:19% HTTP:10% DNS:5% ICMP:5%
...
🔴 [PHASE 2/3] Switching Attack - 15s - SYN:30% UDP:50% HTTP:10% DNS:5% ICMP:5%
[25.0s] Phase 2/3 | 36000000 pkts (1.44 Mpps) | Avg: 12.00 Gbps | Inst: 11.99 Gbps
       Attack Mix: SYN:30% UDP:50% HTTP:10% DNS:5% ICMP:5%
...
```

### Ejemplo 2: Ataque con Fases Personalizadas

```bash
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2.pcap \
    --adaptive-attack \
    --attack-phases phases_attack.json \
    --rate-gbps 10 \
    --jitter 15 \
    --loop
```

### Ejemplo 3: Ataque con Duración Limitada (5 minutos)

```bash
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2.pcap \
    --adaptive-attack \
    --rate-gbps 10 \
    --duration 300 \
    --jitter 10
```

**Sin `--loop`**: Se detiene después de completar todas las fases una vez (o al alcanzar `--duration`).

### Ejemplo 4: Ataque Intenso sin Jitter

```bash
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mixed_10M.pcap \
    --adaptive-attack \
    --rate-gbps 12 \
    --loop
```

## Parámetros

| Parámetro | Descripción | Default | Rango |
|-----------|-------------|---------|-------|
| `--adaptive-attack` | Activa modo ataque adaptivo | OFF | - |
| `--rate-gbps <N>` | Velocidad objetivo en Gbps | 12.0 | 0.1-100 |
| `--jitter <N>` | Variación de PPS (±N%) | 0 | 0-100 |
| `--attack-phases <file>` | Archivo JSON con fases | Fases por defecto | - |
| `--loop` | Loop infinito (hasta Ctrl+C) | OFF | - |
| `--duration <N>` | Duración en segundos (0=infinito) | 0 | 0-999999 |

## Formato del Archivo de Fases

Archivo JSON con array de objetos:

```json
[
  {
    "duration": 20,    // Duración de la fase en segundos
    "syn": 0.60,       // % de paquetes SYN (0.0-1.0)
    "udp": 0.20,       // % de paquetes UDP flood
    "http": 0.10,      // % de paquetes HTTP flood
    "dns": 0.05,       // % de paquetes DNS flood
    "icmp": 0.05       // % de paquetes ICMP/otros
  },
  // ... más fases
]
```

**Requisitos:**
- La suma de porcentajes debe ser ~1.0 (100%)
- Mínimo 1 fase, máximo 16 fases
- `duration` > 0

## Fases por Defecto

Si no especificas `--attack-phases`, usa estas fases:

| Fase | Duración | SYN | UDP | HTTP | DNS | ICMP | Descripción |
|------|----------|-----|-----|------|-----|------|-------------|
| 1 | 20s | 60% | 20% | 10% | 5% | 5% | SYN flood dominante |
| 2 | 15s | 30% | 50% | 10% | 5% | 5% | UDP flood wave |
| 3 | 30s | 20% | 10% | 40% | 25% | 5% | HTTP/DNS mixed attack |

## Comparación de Modos

| Feature | Fast Mode | Timed Mode | Adaptive (Benign) | **Adaptive-Attack** |
|---------|-----------|------------|-------------------|---------------------|
| Velocidad | ~12 Gbps | ~500 Mbps | ~12 Gbps | **~12 Gbps** |
| Duración | PCAP length | PCAP length | Infinita | **Infinita** |
| Fases | No | Sí (secuencial) | Sí (loop) | **Sí (loop ataque)** |
| Timestamps | Ignorados | Respetados | Generados | **Generados** |
| Pool aleatorio | No | No | Sí | **Sí** |
| Clasificación | No | No | Protocolo | **Tipo de ataque** |
| Uso | Fast collection | Research | Benign traffic | **DDoS simulation** |

## Workflow Típico

### 1. Generar PCAP de Ataque

```bash
cd /local/dpdk_100g/mira/attack_generator
python3 generate_mirai_attacks_v2.py \
    --output ../attack_mirai_10M_v2.pcap \
    --packets 10000000 \
    --attack-type mixed \
    --attacker-range 10.10.2.0/24 \
    --target-ip 10.10.1.2
```

### 2. Verificar PCAP

```bash
tcpdump -r ../attack_mirai_10M_v2.pcap -n | head -100

# Verificar IPs (deben ser 10.10.x.x, NO 192.168.x.x)
tcpdump -r ../attack_mirai_10M_v2.pcap -n | grep "10.10.2" | head -10
```

### 3. Compilar Sender v2

```bash
cd /local/dpdk_100g/mira/attack_sender
make -f Makefile_v2 v2
```

### 4. Lanzar Ataque Continuo

```bash
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2.pcap \
    --adaptive-attack \
    --rate-gbps 10 \
    --jitter 15 \
    --loop
```

### 5. Monitorear en Detector

```bash
# Terminal en nodo detector
cd /local/dpdk_100g/mira/detector_system
sudo ./mira_ddos_detector \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../attack_detection.log
```

## Estadísticas en Tiempo Real

Cada 5 segundos muestra:

```
[15.0s] Phase 2/3 | 21600000 pkts (1.44 Mpps) | Avg: 12.00 Gbps | Inst: 12.01 Gbps
       Attack Mix: SYN:30% UDP:50% HTTP:10% DNS:5% ICMP:5%
```

Donde:
- **Phase**: Fase actual / total de fases
- **pkts**: Total de paquetes enviados
- **Mpps**: Millones de paquetes por segundo
- **Avg**: Promedio de Gbps desde el inicio
- **Inst**: Gbps instantáneos (últimos 5s)
- **Attack Mix**: Distribución real de tipos de ataque enviados

## Estadísticas Finales

Al detener con Ctrl+C:

```
╔══════════════════════════════════════════════════════════════════╗
║                   ATTACK STATISTICS - FINAL                      ║
╚══════════════════════════════════════════════════════════════════╝

Total attack packets:  150000000
Total bytes sent:      97500000000
Attack duration:       104.52 seconds
Average throughput:    10.15 Gbps
Average pps:           1.43 Mpps

Attack Type Distribution:
  SYN/ACK:      60000000 packets (40.0%)
  UDP Flood:    45000000 packets (30.0%)
  HTTP Flood:   30000000 packets (20.0%)
  DNS Flood:    12000000 packets (8.0%)
  ICMP/Random:   3000000 packets (2.0%)

Phases completed:      1 cycles

🛑 Attack terminated.
```

## Advertencias Importantes

### ⚠️ Red Interna de CloudLab

**SIEMPRE usa la red interna (10.x.x.x):**

```bash
# ✅ CORRECTO
--attacker-range 10.10.2.0/24
--target-ip 10.10.1.2

# ❌ INCORRECTO (te cerrarán el experimento!)
--attacker-range 192.168.2.0/24
--target-ip 192.168.1.2
```

### ⚠️ Interfaz Correcta

**SIEMPRE usa la NIC experimental (ens1f0, PCI 0000:41:00.0):**

```bash
# ✅ CORRECTO
-w 0000:41:00.0

# ❌ NUNCA uses eno33 (control network)
```

### ⚠️ Verificación Antes de Enviar

```bash
# Verifica que el PCAP use IPs internas
tcpdump -r attack.pcap -n | head -20
# Debes ver 10.10.2.x → 10.10.1.2

# Verifica la NIC
sudo ethtool -i ens1f0 | grep bus-info
# Debe mostrar: 0000:41:00.0
```

## Troubleshooting

### Problema: "No classified attack packets available!"

**Causa:** El PCAP no contiene paquetes que puedan clasificarse como ataques.

**Solución:**
```bash
# Genera un PCAP con ataques válidos
python3 generate_mirai_attacks_v2.py \
    --output attack.pcap \
    --attack-type mixed \
    --packets 5000000
```

### Problema: Velocidad muy baja (<5 Gbps)

**Causas posibles:**
- Jitter muy alto (`--jitter > 30`)
- Rate objetivo muy bajo (`--rate-gbps < 5`)
- Pocos cores asignados (`-l 0-1` en lugar de `-l 0-7`)

**Solución:**
```bash
# Usa más cores y menos jitter
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- attack.pcap \
    --adaptive-attack \
    --rate-gbps 12 \
    --jitter 5 \
    --loop
```

### Problema: Fases no cambian

**Causa:** Solo hay 1 fase o `duration` es muy largo.

**Solución:**
- Verifica que el archivo JSON tenga múltiples fases
- Reduce `duration` en cada fase (ej: 20s en lugar de 300s)

### Problema: Warning "No SYN/ACK attack packets found!"

**Causa:** El PCAP no contiene paquetes TCP con flag SYN.

**Solución:**
```bash
# Genera PCAP con SYN flood
python3 generate_mirai_attacks_v2.py \
    --attack-type syn \
    --packets 5000000 \
    --output attack_syn.pcap
```

## Integración con Detector ML

### Workflow Completo

```bash
# Terminal 1: Detector ML
cd /local/dpdk_100g/mira/detector_system_ml
sudo ./detectorML \
    -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | tee ../results/attack_test_ml.log

# Terminal 2: Attack sender (espera 5s)
cd /local/dpdk_100g/mira/attack_sender
sleep 5
sudo ./dpdk_pcap_sender_v2 \
    -l 0-7 -n 4 -w 0000:41:00.0 \
    -- ../attack_mirai_10M_v2.pcap \
    --adaptive-attack \
    --rate-gbps 10 \
    --jitter 15 \
    --duration 300
```

**Resultado esperado:**
- Detector debe mostrar alertas ML clasificando los ataques
- Logs deben mostrar fases de ataque detectadas
- Estadísticas de distribución de ataques deben coincidir

## Ejemplos Avanzados

### Ejemplo 1: Ataque Progresivo (Escalada)

`phases_escalation.json`:
```json
[
  {"duration": 30, "syn": 0.90, "udp": 0.05, "http": 0.03, "dns": 0.01, "icmp": 0.01},
  {"duration": 30, "syn": 0.70, "udp": 0.20, "http": 0.05, "dns": 0.03, "icmp": 0.02},
  {"duration": 30, "syn": 0.50, "udp": 0.30, "http": 0.10, "dns": 0.05, "icmp": 0.05},
  {"duration": 30, "syn": 0.30, "udp": 0.30, "http": 0.20, "dns": 0.15, "icmp": 0.05}
]
```

Uso:
```bash
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- attack.pcap --adaptive-attack --attack-phases phases_escalation.json --loop
```

### Ejemplo 2: Ataque Tipo-Específico Rotatorio

`phases_rotating.json`:
```json
[
  {"duration": 20, "syn": 1.0, "udp": 0.0, "http": 0.0, "dns": 0.0, "icmp": 0.0},
  {"duration": 20, "syn": 0.0, "udp": 1.0, "http": 0.0, "dns": 0.0, "icmp": 0.0},
  {"duration": 20, "syn": 0.0, "udp": 0.0, "http": 1.0, "dns": 0.0, "icmp": 0.0},
  {"duration": 20, "syn": 0.0, "udp": 0.0, "http": 0.0, "dns": 1.0, "icmp": 0.0}
]
```

**Útil para:** Probar detección tipo-específica del detector ML.

### Ejemplo 3: Ataque con Jitter Alto (Evasión)

```bash
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 \
    -- attack.pcap \
    --adaptive-attack \
    --rate-gbps 8 \
    --jitter 50 \
    --loop
```

**Útil para:** Probar robustez del detector ante variabilidad alta.

---

## Referencias

- DPDK Documentation: https://doc.dpdk.org/
- Mirai Botnet Analysis: https://github.com/jgamblin/Mirai-Source-Code
- CloudLab Internal Network: https://docs.cloudlab.us/

---

**Versión:** 2.0
**Fecha:** 2025-12-08
**Autor:** Claude Code
**Directorio:** `mira/attack_sender/`
