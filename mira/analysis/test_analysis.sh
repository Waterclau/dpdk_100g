#!/bin/bash
# Test script for MIRA OctoSketch analysis tool

set -e  # Exit on error

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║   MIRA ANALYSIS TOOL - TEST SCRIPT                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "[1/5] Checking Python version..."
python3 --version || { echo "❌ Python3 not found"; exit 1; }
echo "  ✓ Python3 available"

echo ""
echo "[2/5] Checking required packages..."
python3 -c "import matplotlib; import pandas; import numpy" 2>/dev/null || {
    echo "❌ Missing required packages"
    echo "   Installing matplotlib, pandas, numpy..."
    pip3 install matplotlib pandas numpy
}
echo "  ✓ All packages available"

echo ""
echo "[3/5] Checking log file..."
LOG_FILE="../results/mira_detector_multicore.log"
if [ -f "$LOG_FILE" ]; then
    echo "  ✓ Log file found: $LOG_FILE"
    LINE_COUNT=$(wc -l < "$LOG_FILE")
    echo "    File size: $(du -h "$LOG_FILE" | cut -f1)"
    echo "    Lines: $LINE_COUNT"
else
    echo "  ⚠ Warning: Log file not found: $LOG_FILE"
    echo "    The script will fail until you run the detector first."
    echo ""
    echo "    To generate the log file, run:"
    echo "    cd ../detector_system"
    echo "    sudo timeout 460 ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \\"
    echo "        2>&1 | tee ../results/mira_detector_multicore.log"
    exit 1
fi

echo ""
echo "[4/5] Creating output directory..."
mkdir -p output
echo "  ✓ Output directory ready: ./output/"

echo ""
echo "[5/5] Running analysis script..."
python3 analyze_mira_octosketch.py

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║   TEST COMPLETE                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "✅ Analysis completed successfully!"
echo ""
echo "Generated visualizations:"
ls -lh output/*.png | awk '{print "  -", $9, "(" $5 ")"}'
echo ""
echo "You can now use these visualizations in your thesis."
