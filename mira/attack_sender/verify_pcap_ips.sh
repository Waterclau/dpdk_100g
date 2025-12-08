#!/bin/bash
# Script de verificación de IPs en PCAP para CloudLab
# Asegura que NO se usen IPs de red de control (192.168.x.x)

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <pcap_file>"
    echo ""
    echo "Verifica que el PCAP use IPs internas de CloudLab (10.x.x.x)"
    echo "y NO use la red de control (192.168.x.x)"
    exit 1
fi

PCAP_FILE="$1"

if [ ! -f "$PCAP_FILE" ]; then
    echo "❌ Error: File not found: $PCAP_FILE"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║              PCAP IP Verification for CloudLab                    ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "📁 File: $PCAP_FILE"
echo ""

# Check if tcpdump is available
if ! command -v tcpdump &> /dev/null; then
    echo "❌ Error: tcpdump not found. Install with: sudo apt-get install tcpdump"
    exit 1
fi

echo "🔍 Analyzing first 100 packets..."
echo ""

# Extract IPs from first 100 packets
SAMPLE=$(tcpdump -r "$PCAP_FILE" -n -c 100 2>/dev/null | head -100)

# Count 192.168.x.x IPs (CONTROL NETWORK - FORBIDDEN)
CONTROL_NET_COUNT=$(echo "$SAMPLE" | grep -oE '192\.168\.[0-9]+\.[0-9]+' | wc -l)

# Count 10.x.x.x IPs (INTERNAL NETWORK - ALLOWED)
INTERNAL_NET_COUNT=$(echo "$SAMPLE" | grep -oE '10\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)

# Count 10.10.1.x IPs (BENIGN NETWORK)
BENIGN_NET_COUNT=$(echo "$SAMPLE" | grep -oE '10\.10\.1\.[0-9]+' | wc -l)

# Count 10.10.2.x IPs (ATTACK NETWORK)
ATTACK_NET_COUNT=$(echo "$SAMPLE" | grep -oE '10\.10\.2\.[0-9]+' | wc -l)

echo "📊 IP Distribution:"
echo "   10.10.1.x (benign):  $BENIGN_NET_COUNT occurrences"
echo "   10.10.2.x (attack):  $ATTACK_NET_COUNT occurrences"
echo "   10.x.x.x (internal): $INTERNAL_NET_COUNT occurrences (total)"
echo "   192.168.x.x (CTRL):  $CONTROL_NET_COUNT occurrences ⚠️"
echo ""

# Show sample IPs
echo "🔬 Sample IPs found (first 10 unique):"
echo "$SAMPLE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | head -10
echo ""

# Verdict
if [ $CONTROL_NET_COUNT -gt 0 ]; then
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                    ❌ VERIFICATION FAILED ❌                        ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "⛔ CRITICAL: PCAP contains 192.168.x.x IPs (CloudLab CONTROL NETWORK)"
    echo ""
    echo "   This will cause your CloudLab experiment to be TERMINATED!"
    echo ""
    echo "🔧 FIX:"
    echo "   1. Regenerate PCAP with correct IPs:"
    echo "      python3 generate_mirai_attacks_v2.py \\"
    echo "          --attacker-range 10.10.2.0/24 \\"
    echo "          --target-ip 10.10.1.2 \\"
    echo "          --output attack_fixed.pcap"
    echo ""
    echo "   2. Verify benign generator settings:"
    echo "      python3 generate_benign_traffic_v2.py \\"
    echo "          --client-range 10.10.1.0/24 \\"
    echo "          --server-ip 10.10.1.2 \\"
    echo "          --output benign_fixed.pcap"
    echo ""
    exit 1
elif [ $INTERNAL_NET_COUNT -eq 0 ]; then
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                    ⚠️  WARNING: NO INTERNAL IPs  ⚠️                ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "⚠️  No 10.x.x.x IPs found in PCAP"
    echo ""
    echo "   Expected:"
    echo "   - Benign traffic: 10.10.1.x"
    echo "   - Attack traffic: 10.10.2.x"
    echo ""
    echo "🔧 FIX: Regenerate PCAP with CloudLab internal IPs (see above)"
    echo ""
    exit 1
else
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                    ✅ VERIFICATION PASSED ✅                        ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "✅ PCAP is SAFE to use on CloudLab"
    echo "✅ Uses internal network (10.x.x.x)"
    echo "✅ NO control network IPs detected (192.168.x.x)"
    echo ""

    if [ $BENIGN_NET_COUNT -gt 0 ] && [ $ATTACK_NET_COUNT -eq 0 ]; then
        echo "📌 Traffic Type: BENIGN (10.10.1.x)"
        echo "   Recommended sender: --adaptive (benign mode)"
    elif [ $ATTACK_NET_COUNT -gt 0 ] && [ $BENIGN_NET_COUNT -eq 0 ]; then
        echo "📌 Traffic Type: ATTACK (10.10.2.x)"
        echo "   Recommended sender: --adaptive-attack"
    elif [ $ATTACK_NET_COUNT -gt 0 ] && [ $BENIGN_NET_COUNT -gt 0 ]; then
        echo "📌 Traffic Type: MIXED (benign + attack)"
        echo "   Contains both 10.10.1.x and 10.10.2.x"
    fi

    echo ""
    echo "🚀 Ready to send with:"
    echo "   sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- $PCAP_FILE [OPTIONS]"
    echo ""
fi

# Additional NIC verification reminder
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚠️  REMINDER: Verify you're using the CORRECT NIC:"
echo ""
echo "   ✅ CORRECT:   -w 0000:41:00.0  (ens1f0, experimental network)"
echo "   ❌ FORBIDDEN: -w <eno33_pci>  (control network interface)"
echo ""
echo "   Check with: sudo lshw -c network -businfo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
