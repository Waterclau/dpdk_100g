#!/bin/bash
# Test script para MIRA detector
# Prueba rápida con tráfico benign + ataques

set -e

MIRA_DIR="/local/dpdk_100g/mira"
cd $MIRA_DIR

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║       MIRA TEST - Quick Attack Detection Test                 ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# ============================================
# PASO 1: Verificar que existen los PCAPs
# ============================================
echo "[1/3] Verificando PCAPs de test..."

if [ ! -f "test_benign.pcap" ]; then
    echo "❌ ERROR: test_benign.pcap no existe"
    echo "   Ejecuta primero los comandos de generación de PCAPs"
    exit 1
fi

if [ ! -f "test_attack_mixed.pcap" ]; then
    echo "❌ ERROR: test_attack_mixed.pcap no existe"
    echo "   Ejecuta primero los comandos de generación de PCAPs"
    exit 1
fi

echo "✅ PCAPs encontrados:"
ls -lh test_*.pcap | awk '{print "   "$9" - "$5}'
echo ""

# ============================================
# PASO 2: Verificar rangos de IPs
# ============================================
echo "[2/3] Verificando rangos de IPs..."

BENIGN_IPS=$(tcpdump -r test_benign.pcap -n -c 10 2>/dev/null | grep -oE '192\.168\.[0-9]+\.[0-9]+' | sort -u | head -1)
ATTACK_IPS=$(tcpdump -r test_attack_mixed.pcap -n -c 10 2>/dev/null | grep -oE '192\.168\.[0-9]+\.[0-9]+' | sort -u | head -1)

echo "   Benign IP (ejemplo): $BENIGN_IPS"
echo "   Attack IP (ejemplo): $ATTACK_IPS"

if [[ $BENIGN_IPS == 192.168.1.* ]]; then
    echo "   ✅ Benign IPs correctas (192.168.1.x)"
else
    echo "   ⚠️  WARNING: Benign IPs no son 192.168.1.x"
fi

if [[ $ATTACK_IPS == 192.168.2.* ]]; then
    echo "   ✅ Attack IPs correctas (192.168.2.x)"
else
    echo "   ⚠️  WARNING: Attack IPs no son 192.168.2.x"
fi
echo ""

# ============================================
# PASO 3: Instrucciones para ejecutar test
# ============================================
echo "[3/3] Listo para ejecutar test"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "INSTRUCCIONES:"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Terminal 1 (MONITOR - detector):"
echo "─────────────────────────────────────────────────────────────"
echo "cd /local/dpdk_100g/mira/detector_system"
echo "sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0"
echo ""
echo "Espera a ver: 'Press Ctrl+C to exit...'"
echo ""
echo ""
echo "Terminal 2 (CONTROLLER - benign traffic):"
echo "─────────────────────────────────────────────────────────────"
echo "cd /local/dpdk_100g/mira"
echo "# Espera 5 segundos después de que el detector inicie"
echo "sleep 5"
echo "# Enviar benign baseline (2 procesos x 5 segundos = 10s baseline)"
echo "for i in {1..2}; do sudo timeout 10 tcpreplay --intf1=ens1f0 --mbps=500 --loop=0 test_benign.pcap & done"
echo ""
echo ""
echo "Terminal 3 (TG - attack traffic):"
echo "─────────────────────────────────────────────────────────────"
echo "cd /local/dpdk_100g/mira"
echo "# Espera 15 segundos (5s inicio + 10s baseline)"
echo "sleep 15"
echo "# Enviar ataques (3 procesos x 10 segundos = 30s ataque)"
echo "for i in {1..3}; do sudo timeout 10 tcpreplay --intf1=ens1f0 --mbps=800 --loop=0 test_attack_mixed.pcap & done"
echo ""
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "TIMELINE ESPERADO:"
echo "════════════════════════════════════════════════════════════════"
echo "t=0s    : Detector inicia"
echo "t=5s    : Baseline benign inicia (192.168.1.x → 10.10.1.2)"
echo "t=15s   : Ataques inician (192.168.2.x → 10.10.1.2)"
echo "t=45s   : Todo termina"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "RESULTADO ESPERADO EN DETECTOR:"
echo "════════════════════════════════════════════════════════════════"
echo "Antes del ataque (t=5-15s):"
echo "  Baseline (192.168.1): >0 pkts (should see benign traffic)"
echo "  Attack (192.168.2):   0 pkts"
echo "  Alert level:          NONE"
echo ""
echo "Durante el ataque (t=15-45s):"
echo "  Baseline (192.168.1): >0 pkts (benign continues)"
echo "  Attack (192.168.2):   >0 pkts (attack detected)"
echo "  UDP flood events:     >0"
echo "  SYN flood events:     >0"
echo "  Alert level:          HIGH"
echo "  Reason:               Multi-attack detected"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Presiona ENTER para continuar..."
read

echo "✅ Test preparado. Ejecuta los comandos en las 3 terminales."
