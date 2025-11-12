#!/bin/bash
#
# Script de experimentación para CloudLab
# Ejecutar en nodo TG después de generar PCAPs
#

set -e

# Configuración
PCAP_DIR="${PCAP_DIR:-/local/pcaps}"
OUTPUT_INTERFACE="${OUTPUT_INTERFACE:-enp65s0f0}"
MBPS_RATE="${MBPS_RATE:-1000}"
LOG_DIR="${LOG_DIR:-/local/logs/experiments}"
EXPERIMENT_NAME="${EXPERIMENT_NAME:-exp_$(date +%Y%m%d_%H%M%S)}"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funciones de utilidad
print_header() {
    echo -e "${BLUE}"
    echo "════════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[*]${NC} $1"
}

# Verificar requisitos
check_requirements() {
    print_header "Verificando Requisitos"

    # Verificar tcpreplay
    if ! command -v tcpreplay &> /dev/null; then
        print_error "tcpreplay no está instalado"
        echo "Instalar con: sudo apt install tcpreplay"
        exit 1
    fi
    print_success "tcpreplay encontrado"

    # Verificar interfaz
    if ! ip link show "$OUTPUT_INTERFACE" &> /dev/null; then
        print_error "Interfaz $OUTPUT_INTERFACE no encontrada"
        echo "Interfaces disponibles:"
        ip -br link show
        exit 1
    fi
    print_success "Interfaz $OUTPUT_INTERFACE encontrada"

    # Verificar directorio de PCAPs
    if [ ! -d "$PCAP_DIR" ]; then
        print_error "Directorio de PCAPs no encontrado: $PCAP_DIR"
        exit 1
    fi
    print_success "Directorio de PCAPs: $PCAP_DIR"

    # Contar PCAPs
    PCAP_COUNT=$(find "$PCAP_DIR" -name "*.pcap" -type f | wc -l)
    if [ "$PCAP_COUNT" -eq 0 ]; then
        print_error "No se encontraron archivos PCAP en $PCAP_DIR"
        exit 1
    fi
    print_success "PCAPs encontrados: $PCAP_COUNT"

    echo ""
}

# Crear directorio de logs
setup_logging() {
    print_header "Configurando Logs"

    mkdir -p "$LOG_DIR/$EXPERIMENT_NAME"
    EXPERIMENT_LOG="$LOG_DIR/$EXPERIMENT_NAME/experiment.log"
    STATS_LOG="$LOG_DIR/$EXPERIMENT_NAME/stats.csv"

    print_success "Directorio de experimento: $LOG_DIR/$EXPERIMENT_NAME"

    # Crear header CSV
    echo "timestamp,pcap_file,packets_sent,duration_sec,mbps_actual,status" > "$STATS_LOG"

    echo ""
}

# Mostrar información del experimento
show_experiment_info() {
    print_header "Configuración del Experimento"

    echo "Nombre:              $EXPERIMENT_NAME"
    echo "Directorio PCAPs:    $PCAP_DIR"
    echo "Interfaz de salida:  $OUTPUT_INTERFACE"
    echo "Rate objetivo:       $MBPS_RATE Mbps"
    echo "Log directorio:      $LOG_DIR/$EXPERIMENT_NAME"
    echo ""

    echo "PCAPs a reproducir:"
    find "$PCAP_DIR" -name "*.pcap" -type f -exec basename {} \; | sort
    echo ""
}

# Obtener estadísticas de un PCAP
get_pcap_stats() {
    local pcap_file="$1"

    # Usar capinfos si está disponible, sino tcpreplay --stats
    if command -v capinfos &> /dev/null; then
        local packets=$(capinfos -c "$pcap_file" 2>/dev/null | grep "Number of packets" | awk '{print $NF}')
        local size=$(capinfos -s "$pcap_file" 2>/dev/null | grep "File size" | awk '{print $(NF-1)}')
        echo "Paquetes: $packets, Tamaño: $size bytes"
    else
        echo "Analizando con tcpreplay..."
    fi
}

# Reproducir un PCAP
replay_pcap() {
    local pcap_file="$1"
    local pcap_name=$(basename "$pcap_file")

    print_info "Reproduciendo: $pcap_name"

    # Obtener stats
    get_pcap_stats "$pcap_file"

    local start_time=$(date +%s)
    local timestamp=$(date +%Y-%m-%d_%H:%M:%S)

    # Ejecutar tcpreplay con captura de estadísticas
    print_info "Enviando tráfico a $MBPS_RATE Mbps..."

    local tcpreplay_output=$(mktemp)

    if sudo tcpreplay -i "$OUTPUT_INTERFACE" \
                      --mbps="$MBPS_RATE" \
                      --stats=1 \
                      "$pcap_file" 2>&1 | tee "$tcpreplay_output"; then

        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        # Extraer estadísticas de tcpreplay
        local packets_sent=$(grep "Actual" "$tcpreplay_output" | grep -oP '\d+(?= packets)' | head -1)
        local mbps_actual=$(grep "Actual" "$tcpreplay_output" | grep -oP '\d+\.\d+(?= Mbps)' | head -1)

        # Valores por defecto si no se pudieron extraer
        packets_sent=${packets_sent:-0}
        mbps_actual=${mbps_actual:-0}

        print_success "Completado en ${duration}s (${packets_sent} paquetes @ ${mbps_actual} Mbps)"

        # Guardar stats
        echo "$timestamp,$pcap_name,$packets_sent,$duration,$mbps_actual,success" >> "$STATS_LOG"

        rm -f "$tcpreplay_output"
        return 0
    else
        print_error "Error reproduciendo $pcap_name"
        echo "$timestamp,$pcap_name,0,0,0,failed" >> "$STATS_LOG"
        rm -f "$tcpreplay_output"
        return 1
    fi
}

# Reproducir todos los PCAPs
replay_all_pcaps() {
    print_header "Reproducción de PCAPs"

    local success_count=0
    local fail_count=0
    local total_start=$(date +%s)

    # Ordenar PCAPs (pueden ser ordenados por nombre o tipo)
    for pcap_file in $(find "$PCAP_DIR" -name "*.pcap" -type f | sort); do
        echo ""
        if replay_pcap "$pcap_file"; then
            ((success_count++))
        else
            ((fail_count++))
        fi

        # Pequeña pausa entre PCAPs
        sleep 2
    done

    local total_end=$(date +%s)
    local total_duration=$((total_end - total_start))

    echo ""
    print_header "Resumen del Experimento"
    echo "Duración total:      ${total_duration}s"
    echo "PCAPs exitosos:      $success_count"
    echo "PCAPs fallidos:      $fail_count"
    echo ""
}

# Reproducir PCAPs específicos
replay_specific_pcaps() {
    print_header "Reproducción de PCAPs Específicos"

    local pcaps=("$@")
    local success_count=0
    local fail_count=0

    for pcap_name in "${pcaps[@]}"; do
        local pcap_file="$PCAP_DIR/$pcap_name"

        if [ ! -f "$pcap_file" ]; then
            print_error "PCAP no encontrado: $pcap_name"
            ((fail_count++))
            continue
        fi

        echo ""
        if replay_pcap "$pcap_file"; then
            ((success_count++))
        else
            ((fail_count++))
        fi

        sleep 2
    done

    echo ""
    print_header "Resumen"
    echo "PCAPs exitosos:      $success_count"
    echo "PCAPs fallidos:      $fail_count"
    echo ""
}

# Modo interactivo
interactive_mode() {
    print_header "Modo Interactivo"

    echo "PCAPs disponibles:"
    local i=1
    local pcaps=()
    for pcap in $(find "$PCAP_DIR" -name "*.pcap" -type f | sort); do
        pcaps+=("$pcap")
        echo "  $i) $(basename "$pcap")"
        ((i++))
    done
    echo "  0) Reproducir todos"
    echo "  q) Salir"
    echo ""

    read -p "Seleccionar opción: " choice

    if [ "$choice" == "q" ]; then
        print_info "Saliendo..."
        exit 0
    elif [ "$choice" == "0" ]; then
        replay_all_pcaps
    elif [ "$choice" -ge 1 ] && [ "$choice" -lt "$i" ]; then
        local selected_pcap="${pcaps[$((choice-1))]}"
        replay_pcap "$selected_pcap"
    else
        print_error "Opción inválida"
        exit 1
    fi
}

# Modo secuencial con delays
sequential_mode() {
    local delay_between="${1:-5}"

    print_header "Modo Secuencial (delay: ${delay_between}s)"

    for pcap_file in $(find "$PCAP_DIR" -name "*.pcap" -type f | sort); do
        echo ""
        replay_pcap "$pcap_file"

        if [ -n "$(find "$PCAP_DIR" -name "*.pcap" -type f | grep -A1 "$pcap_file")" ]; then
            print_info "Esperando ${delay_between}s antes del siguiente PCAP..."
            sleep "$delay_between"
        fi
    done
}

# Generar reporte
generate_report() {
    print_header "Generando Reporte"

    local report_file="$LOG_DIR/$EXPERIMENT_NAME/report.txt"

    {
        echo "═══════════════════════════════════════════════════════════"
        echo "  Reporte de Experimento: $EXPERIMENT_NAME"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "Fecha: $(date)"
        echo "Interfaz: $OUTPUT_INTERFACE"
        echo "Rate objetivo: $MBPS_RATE Mbps"
        echo ""
        echo "Estadísticas por PCAP:"
        echo "───────────────────────────────────────────────────────────"
        column -t -s',' "$STATS_LOG"
        echo ""
        echo "Resumen:"
        echo "───────────────────────────────────────────────────────────"
        local total=$(tail -n +2 "$STATS_LOG" | wc -l)
        local success=$(tail -n +2 "$STATS_LOG" | grep -c "success" || echo 0)
        local failed=$(tail -n +2 "$STATS_LOG" | grep -c "failed" || echo 0)
        local total_packets=$(tail -n +2 "$STATS_LOG" | cut -d',' -f3 | awk '{s+=$1} END {print s}')
        local total_duration=$(tail -n +2 "$STATS_LOG" | cut -d',' -f4 | awk '{s+=$1} END {print s}')

        echo "Total PCAPs:           $total"
        echo "Exitosos:              $success"
        echo "Fallidos:              $failed"
        echo "Total paquetes:        $total_packets"
        echo "Duración total:        ${total_duration}s"
        echo ""
    } | tee "$report_file"

    print_success "Reporte guardado: $report_file"
}

# Función de ayuda
show_help() {
    cat << EOF
Uso: $0 [OPCIONES] [MODO]

Script para ejecutar experimentos de replay de tráfico DDoS en CloudLab.

MODOS:
  all                  Reproducir todos los PCAPs (default)
  interactive          Modo interactivo para seleccionar PCAPs
  sequential [delay]   Reproducir con delays entre PCAPs (default: 5s)
  specific <files...>  Reproducir PCAPs específicos

OPCIONES:
  -d, --pcap-dir DIR       Directorio de PCAPs (default: /local/pcaps)
  -i, --interface IFACE    Interfaz de salida (default: enp65s0f0)
  -r, --rate MBPS          Rate en Mbps (default: 1000)
  -l, --log-dir DIR        Directorio de logs (default: /local/logs/experiments)
  -n, --name NAME          Nombre del experimento (default: exp_<timestamp>)
  -h, --help               Mostrar esta ayuda

VARIABLES DE ENTORNO:
  PCAP_DIR              Directorio de PCAPs
  OUTPUT_INTERFACE      Interfaz de salida
  MBPS_RATE             Rate en Mbps
  LOG_DIR               Directorio de logs
  EXPERIMENT_NAME       Nombre del experimento

EJEMPLOS:
  # Reproducir todos los PCAPs a 1000 Mbps
  sudo $0

  # Reproducir con rate de 5000 Mbps
  sudo $0 -r 5000

  # Modo interactivo
  sudo $0 interactive

  # Reproducir secuencialmente con 10s entre PCAPs
  sudo $0 sequential 10

  # Reproducir PCAPs específicos
  sudo $0 specific syn_flood.pcap udp_flood.pcap

  # Experimento con nombre personalizado
  sudo $0 -n "experiment_syn_flood" specific syn_flood_mixed.pcap

FLUJO TÍPICO:
  1. Generar ataques: python3 -m attack_generator --config attacks.json
  2. En nodo detector: ./detector_system/scripts/run_background.sh
  3. En nodo TG: sudo ./run_experiment.sh
  4. Analizar: python3 detector_system/scripts/analyze.py

EOF
}

# Procesar argumentos
MODE="all"
SPECIFIC_PCAPS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--pcap-dir)
            PCAP_DIR="$2"
            shift 2
            ;;
        -i|--interface)
            OUTPUT_INTERFACE="$2"
            shift 2
            ;;
        -r|--rate)
            MBPS_RATE="$2"
            shift 2
            ;;
        -l|--log-dir)
            LOG_DIR="$2"
            shift 2
            ;;
        -n|--name)
            EXPERIMENT_NAME="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        all|interactive|sequential|specific)
            MODE="$1"
            shift
            if [ "$MODE" == "specific" ]; then
                SPECIFIC_PCAPS=("$@")
                break
            elif [ "$MODE" == "sequential" ] && [ -n "$1" ] && [[ "$1" =~ ^[0-9]+$ ]]; then
                SEQUENTIAL_DELAY="$1"
                shift
            fi
            ;;
        *)
            print_error "Opción desconocida: $1"
            show_help
            exit 1
            ;;
    esac
done

# Verificar que somos root
if [ "$EUID" -ne 0 ]; then
    print_error "Este script debe ejecutarse como root (usar sudo)"
    exit 1
fi

# Main
main() {
    print_header "Experimento DDoS - CloudLab"

    check_requirements
    setup_logging
    show_experiment_info

    case $MODE in
        all)
            replay_all_pcaps
            ;;
        interactive)
            interactive_mode
            ;;
        sequential)
            sequential_mode "${SEQUENTIAL_DELAY:-5}"
            ;;
        specific)
            replay_specific_pcaps "${SPECIFIC_PCAPS[@]}"
            ;;
    esac

    generate_report

    print_success "Experimento completado!"
    print_info "Resultados en: $LOG_DIR/$EXPERIMENT_NAME"
}

# Ejecutar
main
