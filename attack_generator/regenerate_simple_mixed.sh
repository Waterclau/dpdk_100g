#!/bin/bash
#
# Script SIMPLIFICADO para mezclar ataques
# Genera ataques puros, luego los mezcla manualmente
#

set -e

TARGET_IP="${1:-10.10.1.2}"
PCAP_DIR="${2:-/local/pcaps}"

echo "════════════════════════════════════════════════════════════════"
echo "  Generación SIMPLIFICADA de Ataques Mezclados"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Target IP:       $TARGET_IP"
echo "Output dir:      $PCAP_DIR"
echo ""

# Paso 1: Generar tráfico benigno si no existe
BENIGN_PCAP="$PCAP_DIR/benign_traffic.pcap"

if [ ! -f "$BENIGN_PCAP" ]; then
    echo "[1/3] Generando tráfico benigno..."
    sudo python3 -m attack_generator \
      --benign-only \
      --output "$BENIGN_PCAP" \
      --benign-duration 120 \
      --benign-profile heavy \
      --seed 42
    echo "✓ Tráfico benigno creado"
else
    echo "[1/3] ✓ Tráfico benigno ya existe"
fi

echo ""
echo "[2/3] Generando ataques PUROS (sin mezcla)..."

# Paso 2: Generar ataques SIN mezcla
sudo python3 -m attack_generator \
  --target-ip "$TARGET_IP" \
  --config - <<EOF
{
  "target_ip": "$TARGET_IP",
  "output_dir": "$PCAP_DIR",
  "seed": 42,
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
echo "[3/3] Mezclando cada ataque con tráfico benigno..."

# Función para mezclar con Python
mix_pcaps() {
    local attack_pcap=$1
    local output_pcap=$2

    python3 << PYMIX
from scapy.all import rdpcap, wrpcap
import sys

try:
    print("  Cargando ${attack_pcap}...")
    attack = rdpcap("${attack_pcap}")
    print(f"    Ataque: {len(attack)} paquetes")

    print("  Cargando ${BENIGN_PCAP}...")
    benign = rdpcap("${BENIGN_PCAP}")
    print(f"    Benigno: {len(benign)} paquetes")

    # Combinar TODOS los paquetes (sin ratio)
    mixed = list(attack) + list(benign)

    # Ordenar por timestamp
    mixed.sort(key=lambda p: p.time if hasattr(p, 'time') else 0)

    print(f"    Total mezclado: {len(mixed)} paquetes")

    # Guardar
    wrpcap("${output_pcap}", mixed)
    print(f"    ✓ Guardado: ${output_pcap}")

except Exception as e:
    print(f"    ERROR: {e}")
    sys.exit(1)
PYMIX
}

# Mezclar cada tipo de ataque
ATTACK_TYPES=(
    "syn_flood"
    "udp_flood"
    "dns_amp"
    "ntp_amp"
    "http_flood"
    "icmp_flood"
    "fragmentation"
    "ack_flood"
    "volumetric"
)

for attack in "${ATTACK_TYPES[@]}"; do
    attack_file="$PCAP_DIR/${attack}.pcap"
    mixed_file="$PCAP_DIR/${attack}_mixed.pcap"

    if [ -f "$attack_file" ]; then
        echo ""
        echo "[*] Mezclando $attack..."
        mix_pcaps "$attack_file" "$mixed_file"
    else
        echo "[!] Saltando $attack (no encontrado)"
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Generación Completada"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "PCAPs mezclados creados:"
ls -lh "$PCAP_DIR"/*_mixed.pcap 2>/dev/null || echo "  ERROR: No se crearon archivos mezclados"
echo ""
echo "Total mezclados: $(ls "$PCAP_DIR"/*_mixed.pcap 2>/dev/null | wc -l)"
echo ""
echo "Para reproducir:"
echo "  sudo ./run_mixed_experiment.sh ens1f0 $PCAP_DIR 2000"
