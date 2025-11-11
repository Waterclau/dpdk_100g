#!/bin/bash

echo "════════════════════════════════════════════════════════"
echo "  Iniciando Detector en Background"
echo "════════════════════════════════════════════════════════"

cd "$(dirname "$0")/.."

# Limpiar
sudo pkill -9 detector_dpdk || true
sudo rm -rf /var/run/dpdk/* || true
sleep 2

# Crear logs
sudo mkdir -p /local/logs
sudo chmod 777 /local/logs

# Obtener PCI address
PCI_ADDR=${1:-"0000:41:00.0"}

echo "[*] Usando NIC: $PCI_ADDR"
echo "[*] Iniciando en background..."

# Ejecutar en background
nohup sudo ./detector_dpdk -l 0 -a $PCI_ADDR -- > /tmp/detector_dpdk.log 2>&1 &

sleep 3

# Verificar
if pgrep -f detector_dpdk > /dev/null; then
    echo "[+] Detector corriendo (PID: $(pgrep -f detector_dpdk))"
    echo ""
    echo "Ver logs en tiempo real:"
    echo "  tail -f /local/logs/detection.log"
    echo "  tail -f /local/logs/ml_features.csv"
    echo "  tail -f /local/logs/alerts.log"
    echo ""
    echo "Detener:"
    echo "  sudo pkill -9 detector_dpdk"
else
    echo "[!] Error al iniciar"
    cat /tmp/detector_dpdk.log
    exit 1
fi
