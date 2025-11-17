#!/bin/bash
#
# Script para reproducir tráfico baseline con tcpreplay
# Optimizado para alto rendimiento (40-100 Gbps)
#

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración por defecto
PCAP_FILE="baseline_traffic.pcap"
INTERFACE=""
RATE_MBPS=1000  # 1 Gbps por defecto
LOOP_COUNT=0    # 0 = infinito
MULTIPLIER=""
TOPSPEED=false
PRELOAD_PCAP=false

# Función de ayuda
usage() {
    cat << EOF
${BLUE}=== Tcpreplay Baseline Traffic Replayer ===${NC}

Uso: $0 -i <interface> [opciones]

Opciones obligatorias:
  -i <interface>      Interfaz de red (ej: eth0, ens3f0)

Opciones de tráfico:
  -f <pcap_file>      Archivo PCAP a reproducir (default: baseline_traffic.pcap)
  -r <rate_mbps>      Tasa en Mbps (default: 1000)
  -m <multiplier>     Multiplicador de velocidad (ej: 2.5x)
  -t                  Modo topspeed (máxima velocidad posible)
  -l <count>          Número de loops (default: 0 = infinito)

Opciones de rendimiento:
  -p                  Preload PCAP en RAM (mejor para archivos grandes)
  -q                  Modo quiet (menos output)

Ejemplos:
  # Replay básico a 1 Gbps
  $0 -i eth0

  # Replay a 10 Gbps
  $0 -i eth0 -r 10000

  # Replay a máxima velocidad (topspeed)
  $0 -i eth0 -t

  # Replay con multiplicador 5x
  $0 -i eth0 -m 5

  # Replay 10 veces a 40 Gbps con preload
  $0 -i eth0 -r 40000 -l 10 -p

  # Replay PCAP personalizado
  $0 -i eth0 -f my_traffic.pcap -r 100000

EOF
    exit 1
}

# Parsear argumentos
QUIET=false
while getopts "i:f:r:m:l:tpqh" opt; do
    case $opt in
        i) INTERFACE="$OPTARG" ;;
        f) PCAP_FILE="$OPTARG" ;;
        r) RATE_MBPS="$OPTARG" ;;
        m) MULTIPLIER="$OPTARG" ;;
        l) LOOP_COUNT="$OPTARG" ;;
        t) TOPSPEED=true ;;
        p) PRELOAD_PCAP=true ;;
        q) QUIET=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validar parámetros obligatorios
if [ -z "$INTERFACE" ]; then
    echo -e "${RED}Error: Interfaz de red requerida (-i)${NC}"
    usage
fi

if [ ! -f "$PCAP_FILE" ]; then
    echo -e "${RED}Error: Archivo PCAP no encontrado: $PCAP_FILE${NC}"
    exit 1
fi

# Verificar que tcpreplay está instalado
if ! command -v tcpreplay &> /dev/null; then
    echo -e "${RED}Error: tcpreplay no está instalado${NC}"
    echo "Instalar con: sudo apt-get install tcpreplay"
    exit 1
fi

# Verificar que la interfaz existe
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${RED}Error: Interfaz $INTERFACE no encontrada${NC}"
    echo "Interfaces disponibles:"
    ip link show | grep '^[0-9]' | awk '{print "  - " $2}' | sed 's/:$//'
    exit 1
fi

# Información del PCAP
echo -e "${BLUE}=== Configuración de Replay ===${NC}"
echo "Archivo PCAP:     $PCAP_FILE"
echo "Interfaz:         $INTERFACE"

PCAP_SIZE=$(stat -c%s "$PCAP_FILE" 2>/dev/null || stat -f%z "$PCAP_FILE" 2>/dev/null)
PCAP_SIZE_MB=$(echo "scale=2; $PCAP_SIZE / 1024 / 1024" | bc)
echo "Tamaño PCAP:      ${PCAP_SIZE_MB} MB"

# Obtener info del PCAP con capinfos si está disponible
if command -v capinfos &> /dev/null; then
    PACKET_COUNT=$(capinfos -c "$PCAP_FILE" 2>/dev/null | grep "Number of packets" | awk '{print $NF}')
    if [ -n "$PACKET_COUNT" ]; then
        echo "Paquetes:         $PACKET_COUNT"
    fi
fi

# Construir comando tcpreplay
TCPREPLAY_CMD="tcpreplay -i $INTERFACE"

# Añadir opciones de tasa
if [ "$TOPSPEED" = true ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --topspeed"
    echo "Modo:             Topspeed (máxima velocidad)"
elif [ -n "$MULTIPLIER" ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --multiplier=$MULTIPLIER"
    echo "Multiplicador:    ${MULTIPLIER}x"
elif [ -n "$RATE_MBPS" ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --mbps=$RATE_MBPS"
    echo "Tasa objetivo:    $RATE_MBPS Mbps ($(echo "scale=2; $RATE_MBPS / 1000" | bc) Gbps)"
fi

# Loop count
if [ "$LOOP_COUNT" -eq 0 ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --loop=0"
    echo "Loops:            Infinito (Ctrl+C para detener)"
elif [ "$LOOP_COUNT" -gt 1 ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --loop=$LOOP_COUNT"
    echo "Loops:            $LOOP_COUNT"
fi

# Preload PCAP
if [ "$PRELOAD_PCAP" = true ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --preload-pcap"
    echo "Preload:          Habilitado (cargando PCAP en RAM)"
fi

# Opciones adicionales para máximo rendimiento
TCPREPLAY_CMD="$TCPREPLAY_CMD --timer=nano"  # Usar nanotimers para mejor precisión

# Quiet mode
if [ "$QUIET" = true ]; then
    TCPREPLAY_CMD="$TCPREPLAY_CMD --quiet"
fi

# Estadísticas
TCPREPLAY_CMD="$TCPREPLAY_CMD --stats=1"  # Mostrar stats cada 1 segundo

echo -e "${BLUE}===================================${NC}\n"

# Verificar que la interfaz está UP
echo -e "${YELLOW}[*] Verificando interfaz $INTERFACE...${NC}"
LINK_STATE=$(cat /sys/class/net/$INTERFACE/operstate 2>/dev/null || echo "unknown")
if [ "$LINK_STATE" != "up" ]; then
    echo -e "${YELLOW}[!] Advertencia: Interfaz $INTERFACE no está UP (estado: $LINK_STATE)${NC}"
    echo -e "${YELLOW}[!] Intentando levantar la interfaz...${NC}"
    sudo ip link set $INTERFACE up
    sleep 2
    LINK_STATE=$(cat /sys/class/net/$INTERFACE/operstate)
    if [ "$LINK_STATE" != "up" ]; then
        echo -e "${RED}[!] Error: No se pudo levantar la interfaz${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}[✓] Interfaz $INTERFACE está UP${NC}"

# Verificar permisos
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Advertencia: No estás ejecutando como root${NC}"
    echo -e "${YELLOW}[!] tcpreplay puede requerir privilegios root${NC}"
    echo -e "${YELLOW}[!] Si falla, ejecuta con: sudo $0 $@${NC}\n"
fi

# Optimizaciones opcionales de la interfaz
echo -e "${YELLOW}[*] Aplicando optimizaciones de interfaz (opcional)...${NC}"
sudo ethtool -K $INTERFACE gro off gso off tso off 2>/dev/null && \
    echo -e "${GREEN}[✓] Offloads deshabilitados${NC}" || \
    echo -e "${YELLOW}[!] No se pudieron deshabilitar offloads (puede ser normal)${NC}"

# Mostrar comando final
echo -e "\n${BLUE}[*] Comando tcpreplay:${NC}"
echo "    $TCPREPLAY_CMD $PCAP_FILE"
echo ""

# Esperar confirmación si no está en quiet mode
if [ "$QUIET" = false ]; then
    echo -e "${YELLOW}Presiona Enter para comenzar el replay (Ctrl+C para cancelar)...${NC}"
    read
fi

# Ejecutar tcpreplay
echo -e "${GREEN}[*] Iniciando replay de tráfico...${NC}\n"
echo -e "${BLUE}=== Estadísticas de Tcpreplay ===${NC}"

# Trap para manejar Ctrl+C
trap 'echo -e "\n${YELLOW}[!] Replay interrumpido${NC}"; exit 0' INT TERM

# Ejecutar
$TCPREPLAY_CMD "$PCAP_FILE"

echo -e "\n${GREEN}[✓] Replay completado exitosamente${NC}"
