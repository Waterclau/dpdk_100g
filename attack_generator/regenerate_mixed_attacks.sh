#!/bin/bash
#
# Script para regenerar ataques CON mezcla de tráfico benigno
# Esto crea archivos *_mixed.pcap
#

set -e

TARGET_IP="${1:-10.10.1.2}"
ATTACK_RATIO="${2:-0.25}"
PCAP_DIR="${3:-/local/pcaps}"

echo "════════════════════════════════════════════════════════════════"
echo "  Regenerando Ataques con Tráfico Benigno Mezclado"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Target IP:       $TARGET_IP"
echo "Attack ratio:    $ATTACK_RATIO ($(awk "BEGIN {print $ATTACK_RATIO*100}")% ataque, $(awk "BEGIN {print (1-$ATTACK_RATIO)*100}")% benigno)"
echo "Output dir:      $PCAP_DIR"
echo ""

# Paso 1: Generar tráfico benigno si no existe
BENIGN_PCAP="$PCAP_DIR/benign_traffic.pcap"

if [ ! -f "$BENIGN_PCAP" ]; then
    echo "[1/2] Generando tráfico benigno..."
    sudo python3 -m attack_generator \
      --benign-only \
      --output "$BENIGN_PCAP" \
      --benign-duration 120 \
      --benign-profile heavy \
      --seed 42
    echo "✓ Tráfico benigno creado: $BENIGN_PCAP"
else
    echo "[1/2] ✓ Tráfico benigno ya existe: $BENIGN_PCAP"
fi

echo ""
echo "[2/2] Generando ataques mezclados..."

# Paso 2: Generar ataques CON mezcla
sudo python3 -m attack_generator \
  --target-ip "$TARGET_IP" \
  --mix-benign "$BENIGN_PCAP" \
  --attack-ratio "$ATTACK_RATIO" \
  --config - <<EOF
{
  "target_ip": "$TARGET_IP",
  "output_dir": "$PCAP_DIR",
  "seed": 42,
  "mix_benign": "$BENIGN_PCAP",
  "attack_ratio": $ATTACK_RATIO,
  "attacks": [
    {"type": "syn_flood", "num_packets": 50000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000},
    {"type": "dns_amp", "num_packets": 80000, "pps": 8000},
    {"type": "ntp_amp", "num_packets": 70000, "pps": 7000},
    {"type": "http_flood", "num_packets": 30000, "pps": 3000},
    {"type": "icmp_flood", "num_packets": 50000, "pps": 5000},
    {"type": "fragmentation", "num_packets": 60000, "pps": 5000},
    {"type": "ack_flood", "num_packets": 90000, "pps": 9000},
    {"type": "volumetric", "num_packets": 105000, "pps": 20000}
  ]
}
EOF

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Generación Completada"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "PCAPs mezclados creados:"
ls -lh "$PCAP_DIR"/*_mixed.pcap 2>/dev/null || echo "  ERROR: No se crearon archivos *_mixed.pcap"
echo ""
echo "Archivos puros (sin mezcla):"
ls -1 "$PCAP_DIR"/*.pcap 2>/dev/null | grep -v "_mixed.pcap" || true
echo ""
echo "Para reproducir solo los mezclados:"
echo "  sudo ./run_mixed_experiment.sh ens1f0 $PCAP_DIR 2000"
