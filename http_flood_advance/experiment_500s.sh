#!/bin/bash

# Experimento HTTP Flood de 500 segundos
# Baseline: 0-200s (200 segundos)
# Ataque: 200-500s (300 segundos)

INTERFACE="ens1f0"
BASELINE_PCAP="baseline_5M.pcap"
ATTACK_PCAP="attack_http_flood.pcap"

# Configuración de intensidad
BASELINE_INSTANCES=50
BASELINE_PPS=200000
ATTACK_INSTANCES=100
ATTACK_PPS=150000

# Tiempos
BASELINE_DURATION=200
ATTACK_DURATION=300
TOTAL_DURATION=500

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║         EXPERIMENTO HTTP FLOOD - 500 SEGUNDOS                     ║"
echo "╠════════════════════════════════════════════════════════════════════╣"
echo "║  Duración total:      500 segundos                                ║"
echo "║  Fase baseline:       0-200s (200 segundos)                       ║"
echo "║  Fase ataque:         200-500s (300 segundos)                     ║"
echo "║                                                                    ║"
echo "║  BASELINE:                                                         ║"
echo "║    Instancias:        $BASELINE_INSTANCES                         ║"
echo "║    PPS/instancia:     $BASELINE_PPS                               ║"
echo "║    Total:             $((BASELINE_INSTANCES * BASELINE_PPS)) pps (~10M pps)  ║"
echo "║                                                                    ║"
echo "║  ATAQUE:                                                           ║"
echo "║    Instancias:        $ATTACK_INSTANCES                           ║"
echo "║    PPS/instancia:     $ATTACK_PPS                                 ║"
echo "║    Total:             $((ATTACK_INSTANCES * ATTACK_PPS)) pps (~15M pps)      ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# Validar PCAPs
if [ ! -f "$BASELINE_PCAP" ]; then
    echo "ERROR: No se encuentra $BASELINE_PCAP"
    exit 1
fi

if [ ! -f "$ATTACK_PCAP" ]; then
    echo "ERROR: No se encuentra $ATTACK_PCAP"
    exit 1
fi

# Limpiar procesos previos
sudo pkill tcpreplay 2>/dev/null

echo "[$(date '+%H:%M:%S')] FASE 1: Iniciando tráfico BASELINE ($BASELINE_INSTANCES instancias, 10M pps)..."

# Lanzar baseline para 500 segundos completos
for i in $(seq 1 $BASELINE_INSTANCES); do
    sudo timeout $TOTAL_DURATION tcpreplay \
        --intf1="$INTERFACE" \
        --pps="$BASELINE_PPS" \
        --loop=0 \
        --quiet \
        "$BASELINE_PCAP" &

    # Pequeña pausa para evitar picos
    if [ $((i % 10)) -eq 0 ]; then
        sleep 0.5
    fi
done

echo "[$(date '+%H:%M:%S')] Baseline iniciado - Esperando $BASELINE_DURATION segundos antes del ataque..."
echo ""

# Esperar 200 segundos
sleep $BASELINE_DURATION

echo "[$(date '+%H:%M:%S')] FASE 2: Iniciando ATAQUE HTTP FLOOD ($ATTACK_INSTANCES instancias, 15M pps)..."

# Lanzar ataque para los últimos 300 segundos
for i in $(seq 1 $ATTACK_INSTANCES); do
    sudo timeout $ATTACK_DURATION tcpreplay \
        --intf1="$INTERFACE" \
        --pps="$ATTACK_PPS" \
        --loop=0 \
        --quiet \
        "$ATTACK_PCAP" &

    # Pequeña pausa para evitar picos
    if [ $((i % 10)) -eq 0 ]; then
        sleep 0.5
    fi
done

echo "[$(date '+%H:%M:%S')] Ataque iniciado - Esperando $ATTACK_DURATION segundos..."
echo ""
echo "Tráfico combinado esperado: ~25M pps (10M baseline + 15M ataque)"
echo ""
echo "Para monitorear:"
echo "  watch -n 1 'sar -n DEV 1 1 | grep $INTERFACE'"
echo ""
echo "Para detener manualmente:"
echo "  sudo pkill tcpreplay"
echo ""

# Esperar que termine el ataque
sleep $ATTACK_DURATION

echo ""
echo "[$(date '+%H:%M:%S')] Experimento completado (500 segundos total)"

# Limpiar cualquier proceso residual
sudo pkill tcpreplay 2>/dev/null

echo "═══════════════════════════════════════════════════════════════════"
