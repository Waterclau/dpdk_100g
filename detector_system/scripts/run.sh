#!/bin/bash

echo "════════════════════════════════════════════════════════"
echo "  Iniciando Detector DDoS"
echo "════════════════════════════════════════════════════════"

cd "$(dirname "$0")/.."

# Limpiar
sudo pkill -9 detector_dpdk || true
sudo rm -rf /var/run/dpdk/* || true
sleep 2

# Crear logs
sudo mkdir -p /local/logs
sudo chmod 777 /local/logs

# Obtener PCI address (ajustar según tu NIC)
PCI_ADDR=${1:-"0000:41:00.0"}

echo "[*] Usando NIC: $PCI_ADDR"
echo "[*] Logs: /local/logs/"
echo ""

# Ejecutar en foreground
sudo ./detector_dpdk -l 0 -a $PCI_ADDR --
