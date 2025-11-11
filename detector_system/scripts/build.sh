#!/bin/bash
set -e

echo "════════════════════════════════════════════════════════"
echo "  Compilando Detector DDoS con DPDK"
echo "════════════════════════════════════════════════════════"

cd "$(dirname "$0")/.."

# Limpiar procesos previos
sudo pkill -9 detector_dpdk || true
sudo rm -rf /var/run/dpdk/* || true

# Compilar
echo "[*] Compilando detector_dpdk.c..."
gcc -O3 -march=native detector_dpdk.c -o detector_dpdk \
    $(pkg-config --cflags --libs libdpdk) -lpthread -lm

if [ -f "detector_dpdk" ]; then
    echo "[+] Compilación exitosa"
    ls -lh detector_dpdk
    echo ""
    echo "Para ejecutar:"
    echo "  sudo ./detector_dpdk -l 0 -a 0000:41:00.0 --"
else
    echo "[!] Error de compilación"
    exit 1
fi
