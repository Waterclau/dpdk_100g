#!/bin/bash
#
# Example script: Generate 100M packets benign traffic using parallel generator
#
# Usage:
#   bash generate_100M_example.sh
#
# This script demonstrates how to use the parallel generator for large-scale
# benign traffic generation suitable for ML training.
#

set -e  # Exit on error

# Configuration
OUTPUT_FILE="benign_100M_ml.pcap"
NUM_PACKETS=100000000  # 100 million packets
NUM_CORES=8            # Use 8 cores (adjust based on your system)
SPEEDUP=1              # No timestamp compression (use 50 for fast replay)

# Network configuration (CloudLab internal network)
SRC_MAC="00:00:00:00:00:01"
DST_MAC="0c:42:a1:dd:5b:28"
CLIENT_RANGE="10.10.1.0/24"
SERVER_IP="10.10.1.2"
NUM_CLIENTS=500

echo "=========================================="
echo "MIRA Benign Traffic Generator - Example"
echo "=========================================="
echo "Output file: $OUTPUT_FILE"
echo "Packets: $NUM_PACKETS (100M)"
echo "CPU cores: $NUM_CORES"
echo "Speedup: ${SPEEDUP}×"
echo ""

# Check if Python3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found. Please install Python 3."
    exit 1
fi

# Check if scapy is installed
if ! python3 -c "import scapy" &> /dev/null; then
    echo "Error: scapy not installed. Installing..."
    pip3 install scapy
fi

# Detect number of CPU cores
AVAILABLE_CORES=$(nproc)
echo "Available CPU cores: $AVAILABLE_CORES"

if [ $NUM_CORES -gt $AVAILABLE_CORES ]; then
    echo "Warning: Requested $NUM_CORES cores, but only $AVAILABLE_CORES available."
    echo "Adjusting to $AVAILABLE_CORES cores."
    NUM_CORES=$AVAILABLE_CORES
fi

echo ""
echo "Starting generation..."
echo "Estimated time: ~$(echo "scale=1; 100 / (17 * $NUM_CORES)" | bc) minutes"
echo ""

# Start time tracking
START_TIME=$(date +%s)

# Run parallel generator
python3 generate_benign_traffic_v2_parallel.py \
    --output "$OUTPUT_FILE" \
    --packets $NUM_PACKETS \
    --cores $NUM_CORES \
    --src-mac "$SRC_MAC" \
    --dst-mac "$DST_MAC" \
    --client-range "$CLIENT_RANGE" \
    --server-ip "$SERVER_IP" \
    --clients $NUM_CLIENTS \
    --speedup $SPEEDUP

# Calculate elapsed time
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
MINUTES=$((ELAPSED / 60))
SECONDS=$((ELAPSED % 60))

echo ""
echo "=========================================="
echo "Generation Complete!"
echo "=========================================="
echo "Output file: $OUTPUT_FILE"
echo "File size: $(du -h "$OUTPUT_FILE" | cut -f1)"
echo "Total time: ${MINUTES}m ${SECONDS}s"
echo "Packets: $NUM_PACKETS"
echo "Rate: $(echo "scale=1; $NUM_PACKETS / $ELAPSED / 1000" | bc)K packets/sec"
echo ""
echo "Next steps:"
echo "  1. Verify PCAP: tcpdump -r $OUTPUT_FILE -c 10 -n"
echo "  2. Count packets: capinfos $OUTPUT_FILE | grep 'Number of packets'"
echo "  3. Use for ML training or DPDK sender"
echo ""
