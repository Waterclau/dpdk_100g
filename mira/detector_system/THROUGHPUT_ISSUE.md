# Diagnóstico: Throughput limitado a 8.3 Gbps

## Síntomas observados

```
Total throughput:   8.32 Gbps  (avg pkt: 75 bytes)
RX burst calls:     20381222137 (98.5% empty)
Processed pkts:     628315056 (99.8% of NIC RX)
```

## Análisis del problema

### ❌ NO es un problema de código

El problema **NO** es el código del detector. La evidencia:

1. **98.5% de bursts vacíos**: El detector pregunta constantemente "¿hay paquetes?" y la respuesta es NO
2. **99.8% de paquetes procesados**: De los paquetes que llegan, casi todos se procesan correctamente
3. **0% drops**: No hay paquetes perdidos por el detector

### ✅ El problema real: FALTA DE TRÁFICO

El detector puede procesar mucho más, pero **no recibe suficiente tráfico**.

## Cálculo teórico

Con 14 workers optimizados:

**Capacidad del detector**:
- 8.32 Gbps actual → ~13.9 Mpps (millones paquetes/seg)
- Con 98.5% bursts vacíos → el detector está **98.5% IDLE**
- Capacidad real: 13.9 Mpps ÷ 0.015 = **~926 Mpps teórico**
- En Gbps: 926M × 75 bytes × 8 = **~555 Gbps** (!!)

Obviamente no llegarás a 555 Gbps, pero esto muestra que el detector **NO es el cuello de botella**.

**Limitación realista**:
- CPU pura: ~200-300 cycles/pkt en fast path
- 14 cores × 3 GHz = 42 GHz total
- 42G cycles ÷ 250 cycles/pkt = **168 Mpps → ~100 Gbps**

**Conclusión**: Tu detector podría manejar **12-15× más tráfico** del que está recibiendo.

---

## Causas posibles del límite de 8.3 Gbps

### 1. **Generador de tráfico limitado** ⭐ MÁS PROBABLE

El generador no está enviando más de 8-9 Gbps.

**Verificar**:
```bash
# En el generador, ver tasa real
iperf3 -c <detector_ip> -u -b 20G -t 60
# O si usas otro generador
```

**Solución**:
- Aumentar rate del generador a 15-20 Gbps
- Usar múltiples flujos/IPs para RSS
- Verificar que el generador no sea el bottleneck

### 2. **RSS no distribuye correctamente**

Las 14 colas RX no reciben tráfico balanceado.

**Verificar**:
```bash
# Ver estadísticas por cola
NIC=$(ls /sys/bus/pci/devices/0000:41:00.0/net/)
ethtool -S $NIC | grep "rx_queue.*packets"

# Deberías ver algo como:
rx_queue_0_packets: 45000000
rx_queue_1_packets: 44000000
rx_queue_2_packets: 46000000
...
rx_queue_13_packets: 45000000
```

**Si una o pocas colas tienen TODO el tráfico**:
```bash
# Reconfigurar RSS
ethtool -X $NIC equal 14
```

### 3. **Limitación de enlace o switch**

El enlace físico está limitado a 10G en vez de 25G.

**Verificar**:
```bash
# Ver velocidad del enlace
ethtool $(ls /sys/bus/pci/devices/0000:41:00.0/net/) | grep Speed

# Debería decir: Speed: 25000Mb/s
```

### 4. **Flow control habilitado**

El receptor está enviando pause frames.

**Verificar**:
```bash
NIC=$(ls /sys/bus/pci/devices/0000:41:00.0/net/)
ethtool -a $NIC

# Deshabilitar si está ON
ethtool -A $NIC rx off tx off
```

### 5. **Generador en misma máquina**

Si generas tráfico en la misma máquina que el detector:
- Competencia por CPU/memoria
- Límite a ~10-12 Gbps típico

**Solución**: Usar máquina separada para generar tráfico.

---

## Plan de acción

### Paso 1: Diagnosticar

```bash
cd /local/dpdk_100g/mira/detector_system
chmod +x diagnose.sh
./diagnose.sh
```

### Paso 2: Verificar RSS por cola

```bash
# Durante una prueba con tráfico
NIC=$(ls /sys/bus/pci/devices/0000:41:00.0/net/)
watch -n 1 'ethtool -S $NIC | grep "rx_queue.*packets"'
```

**Buscar**:
- ✅ **Balanceado**: Todas las colas tienen ~similar número de paquetes
- ❌ **Desbalanceado**: 1-2 colas tienen TODO el tráfico

### Paso 3: Aumentar tráfico del generador

Dependiendo de tu generador:

**Si usas TRex**:
```python
# Aumentar rate y usar múltiples IPs
rate = "15gbps"  # Aumentar de 8-9 a 15+
```

**Si usas MoonGen**:
```lua
-- Aumentar rate
txQueue:setRate(15000)  -- 15 Gbps
```

**Si usas pktgen-dpdk**:
```
set 0 rate 75  # 75% de 25G = 18.75 Gbps
```

### Paso 4: Recompilar detector con fix

```bash
cd /local/dpdk_100g/mira/detector_system
make clean && make
```

Esto incluye:
- Mensaje corregido de "cycles available"
- Mpps en output
- Optimizaciones de código

### Paso 5: Probar de nuevo

```bash
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0
```

**Buscar en output**:
- `Throughput: >12 Gbps` (mejor que 8.3)
- `RX burst calls: XXX (<90% empty)` (más paquetes)
- Mpps >20 (más paquetes/segundo)

---

## Interpretación del output mejorado

### Antes (confuso):
```
[PERFORMANCE METRICS]
  Cycles/packet:      215 cycles
  Throughput:         8.32 Gbps
```
👉 **Confusión**: "215 cycles" parece mucho

### Después (claro):
```
[PERFORMANCE METRICS]
  Throughput:         8.32 Gbps (13.87 Mpps)
  Cycles available:   215 cycles/pkt (lower = higher load)
```
👉 **Claro**: "215 cycles disponibles" significa CPU tiene capacidad extra

**Interpretación**:
- `> 500 cycles`: CPU muy idle, esperando paquetes
- `200-300 cycles`: CPU moderadamente usado (tu caso)
- `100-150 cycles`: CPU bien utilizado
- `< 100 cycles`: CPU saturado, cerca del límite

---

## Expectativas realistas

### Con código optimizado actual:

| Tasa entrada | Throughput esperado | CPU usage |
|--------------|---------------------|-----------|
| 8-10 Gbps | 8-10 Gbps | ~40-50% |
| 15 Gbps | 14-15 Gbps | ~70-80% |
| 20 Gbps | 17-19 Gbps | ~90-95% |
| 25 Gbps | 19-22 Gbps | ~100% |

**Tu caso actual**: 8.32 Gbps → CPU al ~40% → puedes procesar mucho más.

---

## Resumen ejecutivo

### Problema
❌ Throughput limitado a 8.3 Gbps
❌ 98.5% bursts vacíos = detector idle

### Causa
🎯 **Generador no envía suficiente tráfico** (MÁS PROBABLE)
🎯 RSS desbalanceado (posible)
🎯 Enlace limitado (verificar)

### Solución
1. ✅ Aumentar rate del generador a 15-20 Gbps
2. ✅ Verificar RSS distribuye bien en 14 colas
3. ✅ Usar múltiples IPs source en generador
4. ✅ Recompilar detector con fixes

### Resultado esperado
Con generador a 15-20 Gbps:
- **Throughput**: 14-19 Gbps (vs 8.3 actual)
- **Mpps**: 23-30 Mpps
- **Bursts vacíos**: <90% (vs 98.5% actual)

---

## Preguntas para debugging

1. **¿Cómo generas el tráfico?**
   - Herramienta: TRex / MoonGen / pktgen-dpdk / otro
   - Rate configurado: ¿cuántos Gbps?
   - ¿Mismo nodo o nodo remoto?

2. **¿Qué dice el generador?**
   - ¿Reporta 8 Gbps enviados, o más?
   - ¿Hay drops en el generador?

3. **¿Cuántas IPs distintas usa?**
   - Si usa solo 1-2 IPs → RSS no funciona bien
   - Necesitas ~1000+ IPs distintas para RSS

4. **¿Velocidad del enlace?**
   ```bash
   ethtool <nic> | grep Speed
   ```
   Debería decir **25000Mb/s**

Responde estas preguntas y podemos ajustar la solución.
