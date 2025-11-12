#!/bin/bash
#
# Script para reproducir SOLO PCAPs mezclados
# Versión simplificada y robusta
#

# NO usar set -e para evitar salidas prematuras
set +e

# Configuración
INTERFACE="${1:-ens1f0}"
PCAP_DIR="${2:-/local/pcaps}"
RATE="${3:-2000}"
LOG_DIR="/local/logs/experiments"
EXPERIMENT_NAME="exp_mixed_$(date +%Y%m%d_%H%M%S)"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_info() { echo -e "${YELLOW}[*]${NC} $1"; }

# Verificar root
if [ "$EUID" -ne 0 ]; then
    print_error "Este script debe ejecutarse como root (usar sudo)"
    exit 1
fi

print_header "Experimento PCAPs Mezclados - CloudLab"

# Verificar tcpreplay
if ! command -v tcpreplay &> /dev/null; then
    print_error "tcpreplay no está instalado"
    echo "Instalar con: sudo apt install tcpreplay"
    exit 1
fi
print_success "tcpreplay encontrado"

# Verificar interfaz
if ! ip link show "$INTERFACE" &> /dev/null; then
    print_error "Interfaz $INTERFACE no encontrada"
    echo "Interfaces disponibles:"
    ip -br link show
    echo ""
    echo "Uso: $0 <interface> [pcap_dir] [rate_mbps]"
    echo "Ejemplo: $0 ens1f0 /local/pcaps 2000"
    exit 1
fi
print_success "Interfaz: $INTERFACE"

# Verificar directorio
if [ ! -d "$PCAP_DIR" ]; then
    print_error "Directorio no encontrado: $PCAP_DIR"
    exit 1
fi
print_success "Directorio: $PCAP_DIR"

# Encontrar PCAPs mezclados
MIXED_PCAPS=()
while IFS= read -r pcap; do
    MIXED_PCAPS+=("$pcap")
done < <(find "$PCAP_DIR" -name "*_mixed.pcap" -type f | sort)

if [ ${#MIXED_PCAPS[@]} -eq 0 ]; then
    print_error "No se encontraron PCAPs mezclados (*_mixed.pcap) en $PCAP_DIR"
    echo ""
    echo "PCAPs disponibles:"
    ls -lh "$PCAP_DIR"/*.pcap 2>/dev/null || echo "  Ninguno"
    echo ""
    echo "SOLUCIÓN:"
    echo "  Genera ataques con --mix-benign:"
    echo "  sudo python3 -m attack_generator \\"
    echo "    --target-ip 10.10.1.2 \\"
    echo "    --mix-benign /local/pcaps/benign_traffic.pcap \\"
    echo "    --attack-ratio 0.25 \\"
    echo "    --config attacks.json"
    exit 1
fi

print_success "PCAPs mezclados encontrados: ${#MIXED_PCAPS[@]}"
echo ""

# Crear logs
mkdir -p "$LOG_DIR/$EXPERIMENT_NAME"
STATS_LOG="$LOG_DIR/$EXPERIMENT_NAME/stats.csv"
echo "timestamp,pcap,packets,duration_sec,mbps,status" > "$STATS_LOG"

print_header "Configuración"
echo "Experimento:     $EXPERIMENT_NAME"
echo "Interfaz:        $INTERFACE"
echo "Rate objetivo:   $RATE Mbps"
echo "PCAPs a replay:  ${#MIXED_PCAPS[@]}"
echo "Logs:            $LOG_DIR/$EXPERIMENT_NAME"
echo ""

# Mostrar lista
print_info "PCAPs mezclados:"
for pcap in "${MIXED_PCAPS[@]}"; do
    echo "  - $(basename "$pcap")"
done
echo ""

# Preguntar confirmación
read -p "¿Iniciar experimento? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Cancelado"
    exit 0
fi

print_header "Reproducción de PCAPs"

success_count=0
fail_count=0
total_start=$(date +%s)

for pcap_file in "${MIXED_PCAPS[@]}"; do
    pcap_name=$(basename "$pcap_file")

    echo ""
    print_info "Reproduciendo: $pcap_name"

    # Mostrar info del PCAP
    if command -v capinfos &> /dev/null; then
        packets=$(capinfos -c "$pcap_file" 2>/dev/null | grep "Number of packets" | awk '{print $NF}')
        echo "  Paquetes: $packets"
    fi

    timestamp=$(date +%Y-%m-%d_%H:%M:%S)
    start_time=$(date +%s)

    # Ejecutar tcpreplay
    print_info "Enviando a $RATE Mbps por $INTERFACE..."

    if tcpreplay -i "$INTERFACE" \
                  --mbps="$RATE" \
                  --stats=1 \
                  "$pcap_file" 2>&1; then

        end_time=$(date +%s)
        duration=$((end_time - start_time))

        print_success "Completado en ${duration}s"
        echo "$timestamp,$pcap_name,ok,$duration,$RATE,success" >> "$STATS_LOG"
        ((success_count++))
    else
        print_error "Error reproduciendo $pcap_name"
        echo "$timestamp,$pcap_name,error,0,0,failed" >> "$STATS_LOG"
        ((fail_count++))
    fi

    # Pausa entre PCAPs
    if [ $((success_count + fail_count)) -lt ${#MIXED_PCAPS[@]} ]; then
        print_info "Esperando 3 segundos antes del siguiente..."
        sleep 3
    fi
done

total_end=$(date +%s)
total_duration=$((total_end - total_start))

print_header "Resumen del Experimento"
echo "Duración total:     ${total_duration}s"
echo "PCAPs exitosos:     $success_count"
echo "PCAPs fallidos:     $fail_count"
echo "Tasa de éxito:      $(awk "BEGIN {printf \"%.1f\", ($success_count/${#MIXED_PCAPS[@]})*100}")%"
echo ""
echo "Logs guardados en:"
echo "  $LOG_DIR/$EXPERIMENT_NAME/"
echo ""

# Generar reporte
REPORT="$LOG_DIR/$EXPERIMENT_NAME/report.txt"
{
    echo "═══════════════════════════════════════════════════════════"
    echo "  Reporte de Experimento: $EXPERIMENT_NAME"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "Fecha: $(date)"
    echo "Interfaz: $INTERFACE"
    echo "Rate: $RATE Mbps"
    echo ""
    echo "Estadísticas:"
    echo "  Total PCAPs:     ${#MIXED_PCAPS[@]}"
    echo "  Exitosos:        $success_count"
    echo "  Fallidos:        $fail_count"
    echo "  Duración total:  ${total_duration}s"
    echo ""
    echo "PCAPs reproducidos:"
    for pcap in "${MIXED_PCAPS[@]}"; do
        echo "  - $(basename "$pcap")"
    done
    echo ""
    echo "Detalle (stats.csv):"
    column -t -s',' "$STATS_LOG"
} > "$REPORT"

print_success "Reporte: $REPORT"
print_success "Experimento completado!"
