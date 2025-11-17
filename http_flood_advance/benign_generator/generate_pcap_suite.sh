#!/bin/bash
#
# Genera un conjunto completo de PCAPs baseline para diferentes escenarios
#

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuración
SRC_IP="192.168.1.0"
DST_IP="10.0.0.1"
DST_MAC="04:3f:72:ac:cd:e7"
OUTPUT_DIR="pcaps"

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  PCAP Suite Generator - Baseline Traffic      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}\n"

# Crear directorio de salida
mkdir -p "$OUTPUT_DIR"
echo -e "${GREEN}[✓] Directorio de salida: $OUTPUT_DIR${NC}\n"

# Verificar Python y Scapy
if ! python3 -c "import scapy" 2>/dev/null; then
    echo -e "${YELLOW}[!] Instalando Scapy...${NC}"
    pip install scapy
fi

# Suite de PCAPs a generar
declare -A PCAP_SUITE=(
    ["small"]="10000"           # 10K paquetes - ~1.5 MB - Testing rápido
    ["medium"]="100000"         # 100K paquetes - ~15 MB - Testing normal
    ["large"]="1000000"         # 1M paquetes - ~150 MB - Baseline corto
    ["xlarge"]="5000000"        # 5M paquetes - ~750 MB - Baseline largo
    ["xxlarge"]="10000000"      # 10M paquetes - ~1.5 GB - Baseline extendido
)

echo -e "${YELLOW}Se generarán los siguientes PCAPs:${NC}"
echo ""
printf "  %-12s %-15s %-15s\n" "Tamaño" "Paquetes" "Aprox. Size"
echo "  ────────────────────────────────────────────"
printf "  %-12s %-15s %-15s\n" "small" "10K" "~1.5 MB"
printf "  %-12s %-15s %-15s\n" "medium" "100K" "~15 MB"
printf "  %-12s %-15s %-15s\n" "large" "1M" "~150 MB"
printf "  %-12s %-15s %-15s\n" "xlarge" "5M" "~750 MB"
printf "  %-12s %-15s %-15s\n" "xxlarge" "10M" "~1.5 GB"
echo ""

read -p "¿Continuar? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Cancelado"
    exit 0
fi

echo ""

# Generar cada PCAP
TOTAL=${#PCAP_SUITE[@]}
CURRENT=0

for size in small medium large xlarge xxlarge; do
    CURRENT=$((CURRENT + 1))
    NUM_PACKETS=${PCAP_SUITE[$size]}
    OUTPUT_FILE="$OUTPUT_DIR/baseline_${size}_${NUM_PACKETS}.pcap"

    echo -e "${BLUE}[${CURRENT}/${TOTAL}] Generando: baseline_${size}_${NUM_PACKETS}.pcap${NC}"

    if [ -f "$OUTPUT_FILE" ]; then
        echo -e "${YELLOW}    Ya existe, saltando...${NC}"
        continue
    fi

    START_TIME=$(date +%s)

    python3 generate_baseline_pcap.py \
        -n "$NUM_PACKETS" \
        -o "$OUTPUT_FILE" \
        -s "$SRC_IP" \
        -d "$DST_IP" \
        --dst-mac "$DST_MAC" \
        -v

    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))

    FILE_SIZE=$(stat -c%s "$OUTPUT_FILE" 2>/dev/null || stat -f%z "$OUTPUT_FILE" 2>/dev/null)
    FILE_SIZE_MB=$(echo "scale=2; $FILE_SIZE / 1024 / 1024" | bc)

    echo -e "${GREEN}    ✓ Completado en ${ELAPSED}s - Tamaño: ${FILE_SIZE_MB} MB${NC}\n"
done

# Resumen final
echo -e "\n${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] Suite de PCAPs generada exitosamente${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}\n"

echo "Archivos generados en $OUTPUT_DIR/:"
ls -lh "$OUTPUT_DIR"/*.pcap | awk '{print "  " $9 " - " $5}'

# Crear archivo de índice
INDEX_FILE="$OUTPUT_DIR/README.txt"
cat > "$INDEX_FILE" << EOF
PCAP Baseline Traffic Suite
============================

Generado: $(date)

Configuración:
  Source IP:      $SRC_IP/16 (randomizado)
  Destination IP: $DST_IP
  Destination MAC: $DST_MAC

Archivos:
EOF

for size in small medium large xlarge xxlarge; do
    NUM_PACKETS=${PCAP_SUITE[$size]}
    FILE="baseline_${size}_${NUM_PACKETS}.pcap"
    if [ -f "$OUTPUT_DIR/$FILE" ]; then
        FILE_SIZE=$(stat -c%s "$OUTPUT_DIR/$FILE" 2>/dev/null || stat -f%z "$OUTPUT_DIR/$FILE" 2>/dev/null)
        FILE_SIZE_MB=$(echo "scale=2; $FILE_SIZE / 1024 / 1024" | bc)
        echo "  - $FILE (${FILE_SIZE_MB} MB)" >> "$INDEX_FILE"
    fi
done

cat >> "$INDEX_FILE" << EOF

Uso:
  # Testing rápido (small)
  sudo ./replay_baseline.sh -i eth0 -f $OUTPUT_DIR/baseline_small_*.pcap -r 1000

  # Baseline normal (medium)
  sudo ./replay_baseline.sh -i eth0 -f $OUTPUT_DIR/baseline_medium_*.pcap -r 10000

  # Baseline largo (large)
  sudo ./replay_baseline.sh -i eth0 -f $OUTPUT_DIR/baseline_large_*.pcap -r 10000

  # Alto rendimiento (xlarge/xxlarge)
  sudo ./replay_baseline.sh -i eth0 -f $OUTPUT_DIR/baseline_xlarge_*.pcap -r 40000 -p
EOF

echo -e "\n${GREEN}[✓] Índice creado: $INDEX_FILE${NC}"

echo -e "\n${YELLOW}Ejemplos de uso:${NC}"
echo -e "  # Testing rápido"
echo -e "  sudo ./replay_baseline.sh -i eth0 -f $OUTPUT_DIR/baseline_small_*.pcap -r 1000"
echo ""
echo -e "  # Baseline 10 Gbps"
echo -e "  sudo ./replay_baseline.sh -i eth0 -f $OUTPUT_DIR/baseline_medium_*.pcap -r 10000"
echo ""
echo -e "  # Alto rendimiento 40 Gbps"
echo -e "  sudo ./replay_baseline.sh -i eth0 -f $OUTPUT_DIR/baseline_xlarge_*.pcap -r 40000 -p"
echo ""
