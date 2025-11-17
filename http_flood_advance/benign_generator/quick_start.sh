#!/bin/bash
#
# Quick Start - Generación y replay rápido de tráfico baseline
#

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  HTTP Baseline Traffic - Quick Start          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}\n"

# Verificar dependencias
echo -e "${YELLOW}[1/5] Verificando dependencias...${NC}"

# Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 no encontrado${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓ Python 3${NC}"

# Scapy
if ! python3 -c "import scapy" 2>/dev/null; then
    echo -e "${YELLOW}  ! Scapy no encontrado, instalando...${NC}"
    pip install scapy
fi
echo -e "${GREEN}  ✓ Scapy${NC}"

# Tcpreplay
if ! command -v tcpreplay &> /dev/null; then
    echo -e "${YELLOW}  ! Tcpreplay no encontrado${NC}"
    echo -e "${YELLOW}    Instalar con: sudo apt-get install tcpreplay${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓ Tcpreplay${NC}"

# Generar PCAP si no existe
PCAP_FILE="baseline_traffic.pcap"

if [ ! -f "$PCAP_FILE" ]; then
    echo -e "\n${YELLOW}[2/5] Generando PCAP baseline (100K paquetes)...${NC}"
    python3 generate_baseline_pcap.py -n 100000 -o "$PCAP_FILE"
else
    echo -e "\n${GREEN}[2/5] PCAP ya existe: $PCAP_FILE${NC}"
    PCAP_SIZE=$(stat -c%s "$PCAP_FILE" 2>/dev/null || stat -f%z "$PCAP_FILE" 2>/dev/null)
    PCAP_SIZE_MB=$(echo "scale=2; $PCAP_SIZE / 1024 / 1024" | bc)
    echo -e "${GREEN}       Tamaño: ${PCAP_SIZE_MB} MB${NC}"
fi

# Listar interfaces
echo -e "\n${YELLOW}[3/5] Interfaces de red disponibles:${NC}"
ip link show | grep '^[0-9]' | awk '{print "  - " $2}' | sed 's/:$//'

# Pedir interfaz
echo -e "\n${YELLOW}[4/5] Configuración de replay${NC}"
read -p "Ingresa la interfaz de red (ej: eth0, ens3f0): " INTERFACE

if [ -z "$INTERFACE" ]; then
    echo -e "${RED}Error: Interfaz requerida${NC}"
    exit 1
fi

# Verificar interfaz
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${RED}Error: Interfaz $INTERFACE no encontrada${NC}"
    exit 1
fi

# Pedir tasa
echo -e "\nOpciones de tasa:"
echo "  1) 1 Gbps (testing)"
echo "  2) 10 Gbps (recomendado para baseline)"
echo "  3) 40 Gbps (alto rendimiento)"
echo "  4) 100 Gbps (máximo, requiere NIC 100G)"
echo "  5) Topspeed (máxima velocidad posible)"
read -p "Selecciona opción [1-5] (default: 2): " RATE_OPTION

RATE_MBPS=""
TOPSPEED_FLAG=""

case $RATE_OPTION in
    1) RATE_MBPS=1000 ;;
    2) RATE_MBPS=10000 ;;
    3) RATE_MBPS=40000 ;;
    4) RATE_MBPS=100000 ;;
    5) TOPSPEED_FLAG="-t" ;;
    "") RATE_MBPS=10000 ;;  # Default
    *) echo "Opción inválida, usando 10 Gbps"; RATE_MBPS=10000 ;;
esac

# Loop count
read -p "Número de loops (0 = infinito, default: 0): " LOOP_COUNT
LOOP_COUNT=${LOOP_COUNT:-0}

# Construir comando
REPLAY_CMD="sudo ./replay_baseline.sh -i $INTERFACE -f $PCAP_FILE"

if [ -n "$TOPSPEED_FLAG" ]; then
    REPLAY_CMD="$REPLAY_CMD $TOPSPEED_FLAG"
elif [ -n "$RATE_MBPS" ]; then
    REPLAY_CMD="$REPLAY_CMD -r $RATE_MBPS"
fi

if [ "$LOOP_COUNT" -ne 0 ]; then
    REPLAY_CMD="$REPLAY_CMD -l $LOOP_COUNT"
fi

# Mostrar resumen
echo -e "\n${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}Resumen de configuración:${NC}"
echo -e "  Interfaz:  $INTERFACE"
echo -e "  PCAP:      $PCAP_FILE"
if [ -n "$TOPSPEED_FLAG" ]; then
    echo -e "  Modo:      Topspeed (máxima velocidad)"
else
    echo -e "  Tasa:      $RATE_MBPS Mbps ($(echo "scale=1; $RATE_MBPS / 1000" | bc) Gbps)"
fi
if [ "$LOOP_COUNT" -eq 0 ]; then
    echo -e "  Loops:     Infinito (Ctrl+C para detener)"
else
    echo -e "  Loops:     $LOOP_COUNT"
fi
echo -e "${BLUE}═══════════════════════════════════════════${NC}\n"

# Confirmar
read -p "¿Comenzar replay? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo -e "${YELLOW}Cancelado${NC}"
    exit 0
fi

# Ejecutar
echo -e "\n${YELLOW}[5/5] Iniciando replay...${NC}\n"
$REPLAY_CMD

echo -e "\n${GREEN}[✓] Completado${NC}"
