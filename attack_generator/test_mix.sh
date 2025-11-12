#!/bin/bash
#
# Test rápido para verificar que la mezcla funciona
#

set -e

echo "════════════════════════════════════════════════════════════════"
echo "  Test de Mezcla - Generando 1 ataque"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Verificar que existe tráfico benigno
if [ ! -f "/local/pcaps/benign_traffic.pcap" ]; then
    echo "[*] Generando tráfico benigno de prueba..."
    sudo python3 -m attack_generator \
      --benign-only \
      --output /local/pcaps/benign_traffic.pcap \
      --benign-duration 30 \
      --benign-profile normal \
      --seed 42
    echo "✓ Benigno creado"
fi

# Limpiar archivos de prueba anteriores
rm -f /local/pcaps/syn_flood_test.pcap
rm -f /local/pcaps/syn_flood_test_mixed.pcap

echo ""
echo "[*] Generando SYN flood con mezcla..."

# Primero generar el ataque PURO (sin mezcla)
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --config - <<'EOF'
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 5000, "pps": 5000}
  ]
}
EOF

# Ahora mezclar manualmente con mergecap
echo ""
echo "[*] Mezclando PCAPs manualmente con mergecap..."

if command -v mergecap &> /dev/null; then
    mergecap -w /local/pcaps/syn_flood_mixed.pcap \
             /local/pcaps/syn_flood.pcap \
             /local/pcaps/benign_traffic.pcap
    echo "✓ Mezclado con mergecap"
else
    echo "[!] mergecap no disponible, usando método Python..."
    python3 << 'PYMIX'
from scapy.all import rdpcap, wrpcap

print("  Cargando PCAPs...")
attack = rdpcap("/local/pcaps/syn_flood.pcap")
benign = rdpcap("/local/pcaps/benign_traffic.pcap")

print(f"  Ataque: {len(attack)} paquetes")
print(f"  Benigno: {len(benign)} paquetes")

# Combinar todos los paquetes
mixed = list(attack) + list(benign)

# Ordenar por timestamp
mixed.sort(key=lambda p: p.time if hasattr(p, 'time') else 0)

print(f"  Total mezclado: {len(mixed)} paquetes")

# Guardar
wrpcap("/local/pcaps/syn_flood_mixed.pcap", mixed)
print("  ✓ Archivo mezclado guardado")
PYMIX
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Verificando Resultados"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Verificar archivos
if [ -f "/local/pcaps/syn_flood.pcap" ]; then
    echo "✓ Archivo puro creado: syn_flood.pcap"
    ls -lh /local/pcaps/syn_flood.pcap
else
    echo "✗ ERROR: No se creó syn_flood.pcap"
fi

echo ""

if [ -f "/local/pcaps/syn_flood_mixed.pcap" ]; then
    echo "✓ Archivo mezclado creado: syn_flood_mixed.pcap"
    ls -lh /local/pcaps/syn_flood_mixed.pcap
    echo ""
    echo "Contenido del mezclado:"
    tcpdump -r /local/pcaps/syn_flood_mixed.pcap -n -c 10 2>/dev/null | head -15
    echo ""
    echo "✓✓✓ LA MEZCLA FUNCIONA! ✓✓✓"
else
    echo "✗✗✗ ERROR: No se creó syn_flood_mixed.pcap ✗✗✗"
    echo ""
    echo "Debugging:"
    echo "  - Verificar que --mix-benign se pasó correctamente"
    echo "  - Verificar logs del generador arriba"
    exit 1
fi
