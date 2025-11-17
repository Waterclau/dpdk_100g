#!/bin/bash
#
# Script de verificación de instalación
# Verifica que todas las dependencias estén instaladas
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Verificación de Instalación                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}\n"

ERRORS=0
WARNINGS=0

# Función para verificar comando
check_command() {
    local cmd=$1
    local name=$2
    local install_hint=$3

    if command -v "$cmd" &> /dev/null; then
        local version=$($cmd --version 2>&1 | head -1 || echo "unknown")
        echo -e "${GREEN}✓${NC} $name: ${GREEN}Instalado${NC}"
        echo -e "  Versión: $version"
    else
        echo -e "${RED}✗${NC} $name: ${RED}NO instalado${NC}"
        echo -e "  ${YELLOW}Instalar con: $install_hint${NC}"
        ERRORS=$((ERRORS + 1))
    fi
}

# Función para verificar módulo Python
check_python_module() {
    local module=$1
    local name=$2
    local install_hint=$3

    if python3 -c "import $module" 2>/dev/null; then
        local version=$(python3 -c "import $module; print(getattr($module, '__version__', 'unknown'))" 2>/dev/null || echo "unknown")
        echo -e "${GREEN}✓${NC} Python: $name ${GREEN}Instalado${NC}"
        echo -e "  Versión: $version"
    else
        echo -e "${RED}✗${NC} Python: $name ${RED}NO instalado${NC}"
        echo -e "  ${YELLOW}Instalar con: $install_hint${NC}"
        ERRORS=$((ERRORS + 1))
    fi
}

# Verificar Python
echo -e "${BLUE}[1] Verificando Python...${NC}"
check_command "python3" "Python 3" "sudo apt-get install python3"
echo ""

# Verificar pip
echo -e "${BLUE}[2] Verificando pip...${NC}"
check_command "pip" "pip" "sudo apt-get install python3-pip"
echo ""

# Verificar Scapy
echo -e "${BLUE}[3] Verificando Scapy...${NC}"
check_python_module "scapy" "Scapy" "pip install scapy"
echo ""

# Verificar tcpreplay
echo -e "${BLUE}[4] Verificando tcpreplay...${NC}"
check_command "tcpreplay" "Tcpreplay" "sudo apt-get install tcpreplay"
echo ""

# Verificar capinfos (opcional)
echo -e "${BLUE}[5] Verificando capinfos (opcional)...${NC}"
if command -v capinfos &> /dev/null; then
    echo -e "${GREEN}✓${NC} capinfos: ${GREEN}Instalado${NC}"
else
    echo -e "${YELLOW}!${NC} capinfos: ${YELLOW}NO instalado (opcional)${NC}"
    echo -e "  ${YELLOW}Instalar con: sudo apt-get install wireshark-common${NC}"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

# Verificar ethtool (opcional)
echo -e "${BLUE}[6] Verificando ethtool (opcional)...${NC}"
if command -v ethtool &> /dev/null; then
    echo -e "${GREEN}✓${NC} ethtool: ${GREEN}Instalado${NC}"
else
    echo -e "${YELLOW}!${NC} ethtool: ${YELLOW}NO instalado (recomendado)${NC}"
    echo -e "  ${YELLOW}Instalar con: sudo apt-get install ethtool${NC}"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

# Verificar archivos del proyecto
echo -e "${BLUE}[7] Verificando archivos del proyecto...${NC}"
FILES=(
    "generate_baseline_pcap.py"
    "replay_baseline.sh"
    "analyze_pcap.py"
    "quick_start.sh"
    "README.md"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $file"
    else
        echo -e "${RED}✗${NC} $file ${RED}NO encontrado${NC}"
        ERRORS=$((ERRORS + 1))
    fi
done
echo ""

# Verificar permisos de ejecución
echo -e "${BLUE}[8] Verificando permisos de ejecución...${NC}"
SCRIPTS=(
    "generate_baseline_pcap.py"
    "replay_baseline.sh"
    "analyze_pcap.py"
    "quick_start.sh"
)

for script in "${SCRIPTS[@]}"; do
    if [ -f "$script" ] && [ -x "$script" ]; then
        echo -e "${GREEN}✓${NC} $script es ejecutable"
    elif [ -f "$script" ]; then
        echo -e "${YELLOW}!${NC} $script ${YELLOW}NO es ejecutable${NC}"
        echo -e "  ${YELLOW}Corregir con: chmod +x $script${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
done
echo ""

# Verificar interfaces de red
echo -e "${BLUE}[9] Interfaces de red disponibles:${NC}"
if command -v ip &> /dev/null; then
    ip link show | grep '^[0-9]' | awk '{print "  " $2}' | sed 's/:$//' | while read iface; do
        state=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "unknown")
        if [ "$state" = "up" ]; then
            echo -e "  ${GREEN}✓${NC} $iface (UP)"
        else
            echo -e "  ${YELLOW}!${NC} $iface (${state})"
        fi
    done
else
    echo -e "${YELLOW}!${NC} Comando 'ip' no disponible"
fi
echo ""

# Verificar privilegios root (para tcpreplay)
echo -e "${BLUE}[10] Verificando privilegios...${NC}"
if [ "$EUID" -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Ejecutando como root"
else
    echo -e "${YELLOW}!${NC} NO ejecutando como root"
    echo -e "  ${YELLOW}tcpreplay requerirá sudo${NC}"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

# Resumen final
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Resumen de Verificación                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}\n"

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ Todo está correcto!${NC}"
    echo -e "\n${GREEN}Puedes comenzar con:${NC}"
    echo -e "  ./quick_start.sh"
    echo -e "${GREEN}o${NC}"
    echo -e "  python3 generate_baseline_pcap.py"
    echo -e "  sudo ./replay_baseline.sh -i <interfaz>"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ Advertencias: $WARNINGS${NC}"
    echo -e "${YELLOW}El sistema funcionará, pero algunas funcionalidades opcionales no están disponibles${NC}"
    echo -e "\n${GREEN}Puedes comenzar con:${NC}"
    echo -e "  ./quick_start.sh"
    exit 0
else
    echo -e "${RED}✗ Errores encontrados: $ERRORS${NC}"
    echo -e "${YELLOW}⚠ Advertencias: $WARNINGS${NC}"
    echo -e "\n${RED}Por favor corrige los errores antes de continuar${NC}"
    exit 1
fi
