# Experimento Completo: Detección de HTTP Flood
## Controlador → Monitor ← Atacante

Este documento contiene los comandos para ejecutar el experimento completo de detección de ataques HTTP flood.

---

## 📋 Configuración del Experimento

| Componente | Nodo | Función | Tráfico |
|------------|------|---------|---------|
| **Baseline Generator** | Controlador | Genera tráfico HTTP normal | 192.168.1.X → 10.0.0.1 |
| **Attack Generator** | Atacante | Genera ataque HTTP flood | 203.0.113.X → 10.0.0.1 |
| **Detector** | Monitor | Detecta ataques con DPDK+OctoSketch | Escucha en ens1f0 |

---

## 🎯 Secuencia de Ejecución

### Fase 1: Preparación (hacer una vez)

#### En Controlador - Generar PCAP Baseline
```bash
cd /local/dpdk_100g/http_flood_advance/benign_generator

# Generar PCAP de baseline (5M paquetes, ~750 MB)
python3 generate_baseline_pcap.py \
    -n 5000000 \
    -o baseline_5M.pcap \
    -s 192.168.1.0 \
    -d 10.0.0.1 \
    --dst-mac 0c:42:a1:8c:dd:0c \
    -v

# Verificar
ls -lh baseline_5M.pcap
```

#### En Atacante - Generar PCAP Attack
```bash
cd /local/dpdk_100g/http_flood_advance/attack_generator

# Generar PCAP de ataque mixed (1M paquetes, ~150 MB)
python3 generate_http_flood.py \
    -t mixed \
    -n 1000000 \
    -o attack_mixed_1M.pcap \
    -d 10.0.0.1 \
    --dst-mac 0c:42:a1:8c:dd:0c \
    -b 100 \
    -v

# Verificar
ls -lh attack_mixed_1M.pcap
```

---

### Fase 2: Ejecución del Experimento

#### Terminal 1 - Monitor (Detector con logs)
```bash
cd /local/dpdk_100g/http_flood_advance/detector_system

# Crear directorio para resultados
mkdir -p /local/dpdk_100g/results
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="/local/dpdk_100g/results/detector_${TIMESTAMP}.log"

# Ejecutar detector por 120 segundos, guardando logs
sudo timeout 120 ./http_flood_detector -l 1-2 -n 4 -a 0000:41:00.0 -- -p 0 2>&1 | tee $LOGFILE
sudo timeout 120 ./http_flood_detector -l 1-2 -n 4 -a 0000:41:00.0 -- -p 0
# El detector mostrará estadísticas cada 5 segundos
# Ctrl+C para detener antes, o esperará 120 segundos
```

#### Terminal 2 - Controlador (Baseline continuo)
```bash
cd /local/dpdk_100g/http_flood_advance/benign_generator

# Enviar tráfico baseline a 10 Gbps durante 120 segundos
sudo timeout 120 ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 30000 -q
sudo timeout 120 ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q
```

#### Terminal 3 - Atacante (Ataque después de 30 seg)
```bash
cd /local/dpdk_100g/http_flood_advance/attack_generator

# Esperar 30 segundos para establecer baseline
sleep 30

# Lanzar ataque a 5 Gbps durante 60 segundos
sudo timeout 60 ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 5000 -q
sleep 30
sudo timeout 60 ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 20000 -q
```

---

## 📊 Resultados Esperados

### Primeros 30 segundos (solo baseline):
```
[PACKET COUNTERS]
  HTTP packets:       ~5,000,000
  Baseline (192.168): 100%
  Attack (203.0.113): 0%

[ALERT STATUS]
  Alert level:        NONE o LOW
```

### 30-90 segundos (baseline + ataque):
```
[PACKET COUNTERS]
  HTTP packets:       ~15,000,000
  Baseline (192.168): ~60%
  Attack (203.0.113): ~40%

[ALERT STATUS]
  Alert level:        HIGH
  Reason:             HIGH ATTACK RATE: XXXXX pps from botnet (XX%)
                      | HEAVY HITTERS: XXX IPs suspicious
```

### Últimos 30 segundos (solo baseline de nuevo):
```
[PACKET COUNTERS]
  Baseline (192.168): vuelve a ~100%
  Attack (203.0.113): ~0%

[ALERT STATUS]
  Alert level:        NONE o LOW
```

---

## 🔄 Variantes del Experimento

### Experimento 1: Baseline puro (sin ataque)
```bash
# Monitor
sudo timeout 60 ./http_flood_detector -l 1-2 -n 4 -a 0000:41:00.0 -- -p 0 2>&1 | tee /local/dpdk_100g/results/exp1_baseline_only.log

# Controlador
sudo timeout 60 ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q

# Atacante: NO ejecutar nada
```

**Resultado esperado:** Alert level = NONE

---

### Experimento 2: Ataque bajo (1 Gbps)
```bash
# Monitor
sudo timeout 90 ./http_flood_detector -l 1-2 -n 4 -a 0000:41:00.0 -- -p 0 2>&1 | tee /local/dpdk_100g/results/exp2_low_attack.log

# Controlador
sudo timeout 90 ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q

# Atacante (30 seg después, 1 Gbps)
sleep 30 && sudo timeout 30 ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 1000 -q
```

**Resultado esperado:** Alert level = LOW o MEDIUM

---

### Experimento 3: Ataque medio (5 Gbps)
```bash
# Monitor
sudo timeout 90 ./http_flood_detector -l 1-2 -n 4 -a 0000:41:00.0 -- -p 0 2>&1 | tee /local/dpdk_100g/results/exp3_medium_attack.log

# Controlador
sudo timeout 90 ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q

# Atacante (30 seg después, 5 Gbps)
sleep 30 && sudo timeout 30 ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 5000 -q
```

**Resultado esperado:** Alert level = HIGH

---

### Experimento 4: Ataque intenso (10 Gbps)
```bash
# Monitor
sudo timeout 90 ./http_flood_detector -l 1-2 -n 4 -a 0000:41:00.0 -- -p 0 2>&1 | tee /local/dpdk_100g/results/exp4_high_attack.log

# Controlador
sudo timeout 90 ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q

# Atacante (30 seg después, 10 Gbps)
sleep 30 && sudo timeout 30 ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 10000 -q
```

**Resultado esperado:** Alert level = HIGH o CRITICAL

---

### Experimento 5: Tipos de ataque diferentes

#### 5a. GET Flood
```bash
# En Atacante, generar PCAP específico
python3 generate_http_flood.py -t get_flood -n 1000000 -o attack_get.pcap --dst-mac 0c:42:a1:8c:dd:0c -v

# Ejecutar
sleep 30 && sudo timeout 30 ./replay_attack.sh -i ens1f0 -f attack_get.pcap -r 5000 -q
```

#### 5b. POST Flood
```bash
python3 generate_http_flood.py -t post_flood -n 1000000 -o attack_post.pcap --dst-mac 0c:42:a1:8c:dd:0c -v
sleep 30 && sudo timeout 30 ./replay_attack.sh -i ens1f0 -f attack_post.pcap -r 5000 -q
```

#### 5c. Random GET
```bash
python3 generate_http_flood.py -t random_get -n 1000000 -o attack_random.pcap --dst-mac 0c:42:a1:8c:dd:0c -v
sleep 30 && sudo timeout 30 ./replay_attack.sh -i ens1f0 -f attack_random.pcap -r 5000 -q
```

---

## 📁 Archivos de Resultados

Los logs se guardan en: `/local/dpdk_100g/results/`

```bash
# Ver logs generados
ls -lh /local/dpdk_100g/results/

# Ejemplo de nombres:
# detector_20251117_143000.log
# exp1_baseline_only.log
# exp2_low_attack.log
# exp3_medium_attack.log
# exp4_high_attack.log
```

---

## 🔍 Análisis de Logs (después del experimento)

### Buscar alertas en logs
```bash
# Ver solo alertas HIGH
grep "Alert level:.*HIGH" /local/dpdk_100g/results/*.log

# Ver razones de alertas
grep "Reason:" /local/dpdk_100g/results/*.log

# Contar paquetes HTTP totales
grep "HTTP packets:" /local/dpdk_100g/results/*.log | tail -1

# Ver distribución baseline vs attack
grep "Baseline\|Attack" /local/dpdk_100g/results/*.log
```

### Extraer métricas clave
```bash
# Crear resumen de experimento
LOGFILE="/local/dpdk_100g/results/detector_XXXXXX.log"  # Cambiar por tu log

echo "=== RESUMEN DEL EXPERIMENTO ==="
echo "Paquetes HTTP totales:"
grep "HTTP packets:" $LOGFILE | tail -1

echo -e "\nDistribución tráfico final:"
grep -A 2 "PACKET COUNTERS" $LOGFILE | tail -5

echo -e "\nAlertas detectadas:"
grep "Alert level:" $LOGFILE | sort | uniq -c

echo -e "\nRazones de alerta:"
grep "Reason:" $LOGFILE
```

---

## 🛑 Detener Experimento

Si necesitas detener antes de que termine el timeout:

```bash
# En cada nodo, ejecutar:
sudo pkill http_flood_detector  # Monitor
sudo pkill tcpreplay            # Controlador y Atacante
```

---

## ✅ Checklist de Experimento

Antes de ejecutar:
- [ ] PCAPs generados en Controlador y Atacante
- [ ] Interfaces UP en todos los nodos (`ip link show`)
- [ ] Directorio `/local/dpdk_100g/results/` creado
- [ ] Espacio en disco suficiente (`df -h /local`)

Durante ejecución:
- [ ] Detector muestra estadísticas cada 5 seg
- [ ] Controlador envía paquetes (ver stats de tcpreplay)
- [ ] Atacante espera 30 seg antes de iniciar
- [ ] Monitor muestra incremento en "Attack packets"

Después:
- [ ] Log guardado en `/local/dpdk_100g/results/`
- [ ] Alert level = HIGH detectado durante ataque
- [ ] Alert level vuelve a NONE después del ataque

---

## 📊 Métricas a Extraer (análisis posterior)

Del log del detector:
1. **Total packets processed**
2. **HTTP packets count**
3. **Baseline percentage** (timeline)
4. **Attack percentage** (timeline)
5. **Alert level** (timeline)
6. **Alert reasons**
7. **Unique IPs**
8. **Heavy hitters count**
9. **GET/POST ratio**
10. **Top URL concentration**

---

## 🎓 Configuración para Paper/Tesis

### Experimento Completo Documentado
```bash
# Crear directorio con timestamp
EXPDIR="/local/dpdk_100g/results/experiment_$(date +%Y%m%d_%H%M%S)"
mkdir -p $EXPDIR

# Guardar configuración
echo "Experiment: HTTP Flood Detection" > $EXPDIR/config.txt
echo "Date: $(date)" >> $EXPDIR/config.txt
echo "Baseline rate: 10 Gbps" >> $EXPDIR/config.txt
echo "Attack rate: 5 Gbps" >> $EXPDIR/config.txt
echo "Attack start: 30 seconds" >> $EXPDIR/config.txt
echo "Total duration: 120 seconds" >> $EXPDIR/config.txt

# Ejecutar con logs
cd /local/dpdk_100g/http_flood_advance/detector_system
sudo timeout 120 ./http_flood_detector -l 1-2 -n 4 -a 0000:41:00.0 -- -p 0 2>&1 | tee $EXPDIR/detector.log

# Después, copiar PCAPs usados
cp /local/dpdk_100g/http_flood_advance/benign_generator/baseline_5M.pcap $EXPDIR/
cp /local/dpdk_100g/http_flood_advance/attack_generator/attack_mixed_1M.pcap $EXPDIR/
```

---

## 📝 Notas Importantes

1. **Timing**: El Atacante debe esperar 30 seg para establecer baseline claro
2. **Duración**: 120 seg total permite ver baseline → ataque → baseline
3. **Logs**: Usar `tee` para ver output Y guardarlo
4. **PCI Address**: Siempre usar `-a 0000:41:00.0` en Monitor
5. **Timeout**: Usar `timeout` para evitar procesos colgados
6. **Resultados**: Los logs están en `/local/dpdk_100g/results/`

---

## 🚀 Comando Rápido (Experimento Estándar)

```bash
# Monitor
cd /local/dpdk_100g/http_flood_advance/detector_system && mkdir -p /local/dpdk_100g/results && sudo timeout 120 ./http_flood_detector -l 1-2 -n 4 -a 0000:41:00.0 -- -p 0 2>&1 | tee /local/dpdk_100g/results/experiment_$(date +%Y%m%d_%H%M%S).log

# Controlador
cd /local/dpdk_100g/http_flood_advance/benign_generator && sudo timeout 120 ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q

# Atacante
cd /local/dpdk_100g/http_flood_advance/attack_generator && sleep 30 && sudo timeout 60 ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 5000 -q
```

---

**¡Experimento listo para ejecutar!** 🎉
