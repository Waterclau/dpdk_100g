#!/bin/bash
# Script de verificación de integración ML

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║         MIRA ML Integration - Verification Script                ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0

# Check 1: Required files exist
echo "[1/8] Checking required files..."
REQUIRED_FILES=(
    "detectorML.c"
    "ml_inference.c"
    "ml_inference.h"
    "octosketch.h"
    "Makefile"
    "README.md"
    "HOW_TO_ADD_ML.md"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "  ${GREEN}✓${NC} $file"
    else
        echo -e "  ${RED}✗${NC} $file - MISSING"
        ((ERRORS++))
    fi
done

# Check 2: ML include in detectorML.c
echo ""
echo "[2/8] Checking ML include in detectorML.c..."
if grep -q '#include "ml_inference.h"' detectorML.c; then
    echo -e "  ${GREEN}✓${NC} ML header included"
else
    echo -e "  ${RED}✗${NC} ML header NOT included"
    ((ERRORS++))
fi

# Check 3: Global ML model variable
echo ""
echo "[3/8] Checking global ML model variable..."
if grep -q 'static ml_model_handle g_ml_model' detectorML.c; then
    echo -e "  ${GREEN}✓${NC} Global model variable declared"
else
    echo -e "  ${RED}✗${NC} Global model variable NOT found"
    ((ERRORS++))
fi

# Check 4: ML init in main
echo ""
echo "[4/8] Checking ML initialization in main()..."
if grep -q 'g_ml_model = ml_init' detectorML.c; then
    echo -e "  ${GREEN}✓${NC} ML initialization found"
else
    echo -e "  ${RED}✗${NC} ML initialization NOT found"
    ((ERRORS++))
fi

# Check 5: ML cleanup in signal_handler
echo ""
echo "[5/8] Checking ML cleanup in signal_handler()..."
if grep -q 'ml_cleanup(g_ml_model)' detectorML.c; then
    echo -e "  ${GREEN}✓${NC} ML cleanup found"
else
    echo -e "  ${RED}✗${NC} ML cleanup NOT found"
    ((ERRORS++))
fi

# Check 6: ML prediction in detect_attacks
echo ""
echo "[6/8] Checking ML prediction in detect_attacks()..."
if grep -q 'ml_predict' detectorML.c; then
    echo -e "  ${GREEN}✓${NC} ML prediction found"
else
    echo -e "  ${RED}✗${NC} ML prediction NOT found"
    ((ERRORS++))
fi

# Check 7: Makefile correctness
echo ""
echo "[7/8] Checking Makefile configuration..."
if grep -q 'SRCS = detectorML.c ml_inference.c' Makefile; then
    echo -e "  ${GREEN}✓${NC} Correct source files in Makefile"
else
    echo -e "  ${RED}✗${NC} Incorrect source files in Makefile"
    ((ERRORS++))
fi

if grep -q 'l_lightgbm' Makefile; then
    echo -e "  ${GREEN}✓${NC} LightGBM library linked"
else
    echo -e "  ${RED}✗${NC} LightGBM library NOT linked"
    ((ERRORS++))
fi

# Check 8: LightGBM availability (optional)
echo ""
echo "[8/8] Checking LightGBM installation (optional)..."
if ldconfig -p 2>/dev/null | grep -q lightgbm; then
    echo -e "  ${GREEN}✓${NC} LightGBM library found in system"
elif [ -f "/usr/local/lib/lib_lightgbm.so" ] || [ -f "/usr/lib/lib_lightgbm.so" ]; then
    echo -e "  ${GREEN}✓${NC} LightGBM library found"
else
    echo -e "  ${YELLOW}⚠${NC} LightGBM library not found (install before compiling)"
fi

# Summary
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
if [ $ERRORS -eq 0 ]; then
    echo -e "║  ${GREEN}✓ Integration verified successfully!${NC}                          ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Next steps:"
    echo "  1. Train model: cd ../ml_system/02_training && python3 export_lightgbm_model.py"
    echo "  2. Compile: make clean && make"
    echo "  3. Run: sudo ./detectorML -l 0-15 -n 4 -w <PCI_ADDR> -- -p 0"
    exit 0
else
    echo -e "║  ${RED}✗ Integration verification failed: $ERRORS errors${NC}                ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Please review the errors above and consult HOW_TO_ADD_ML.md"
    exit 1
fi
