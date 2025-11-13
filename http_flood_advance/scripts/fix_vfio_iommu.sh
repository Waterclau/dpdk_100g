#!/bin/bash
#
# Script para habilitar IOMMU y configurar VFIO correctamente
#
# Uso: sudo ./fix_vfio_iommu.sh
#

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Verificar root
if [ "$EUID" -ne 0 ]; then
    print_error "Este script debe ejecutarse como root (usa sudo)"
    exit 1
fi

print_header "Diagnóstico y Fix VFIO-PCI + IOMMU"

# 1. Verificar tipo de CPU (Intel o AMD)
print_header "1. Detectando CPU"

if grep -q "Intel" /proc/cpuinfo; then
    CPU_VENDOR="intel"
    IOMMU_PARAM="intel_iommu=on"
    print_info "CPU Intel detectada"
elif grep -q "AMD" /proc/cpuinfo; then
    CPU_VENDOR="amd"
    IOMMU_PARAM="amd_iommu=on"
    print_info "CPU AMD detectada"
else
    print_warning "CPU vendor desconocido"
    CPU_VENDOR="unknown"
    IOMMU_PARAM="intel_iommu=on"
fi

# 2. Verificar estado actual de IOMMU
print_header "2. Verificando IOMMU"

echo ""
print_info "Buscando IOMMU en dmesg..."
if dmesg | grep -qi "IOMMU enabled"; then
    print_info "✅ IOMMU está habilitado"
    IOMMU_ENABLED=true
else
    print_warning "❌ IOMMU NO está habilitado"
    IOMMU_ENABLED=false
fi

echo ""
print_info "Parámetros actuales del kernel:"
cat /proc/cmdline
echo ""

# 3. Verificar módulos VFIO disponibles
print_header "3. Verificando Módulos VFIO"

print_info "Buscando módulos VFIO en el sistema..."
VFIO_COUNT=$(find /lib/modules/$(uname -r) -name "vfio*" | wc -l)

if [ $VFIO_COUNT -gt 0 ]; then
    print_info "✅ Módulos VFIO encontrados: $VFIO_COUNT"
    find /lib/modules/$(uname -r) -name "vfio*" | head -n 5
else
    print_error "❌ No se encontraron módulos VFIO"
    print_info "Instalar con: sudo apt-get install linux-modules-extra-$(uname -r)"
fi

echo ""
print_info "Intentando obtener info del módulo vfio-pci..."
modinfo vfio-pci 2>&1 | head -n 10 || print_warning "No se pudo obtener info de vfio-pci"

# 4. Intentar cargar módulos VFIO paso a paso
print_header "4. Cargando Módulos VFIO (paso a paso)"

echo ""
print_info "Cargando módulo base vfio..."
modprobe vfio 2>&1 && print_info "✅ vfio cargado" || print_warning "⚠️  vfio ya cargado o no disponible"

print_info "Cargando vfio_iommu_type1..."
modprobe vfio_iommu_type1 2>&1 && print_info "✅ vfio_iommu_type1 cargado" || print_warning "⚠️  vfio_iommu_type1 ya cargado o no disponible"

print_info "Cargando vfio-pci..."
if modprobe vfio-pci 2>&1; then
    print_info "✅ vfio-pci cargado exitosamente"
    VFIO_LOADED=true
else
    print_error "❌ Error al cargar vfio-pci"
    print_info "Error detallado:"
    dmesg | tail -n 20
    VFIO_LOADED=false
fi

echo ""
print_info "Módulos cargados actualmente:"
lsmod | grep vfio

# 5. Diagnóstico y solución
print_header "5. Diagnóstico y Solución"

echo ""
if [ "$VFIO_LOADED" = true ]; then
    print_info "✅ VFIO-PCI está funcionando correctamente"
    print_info "Puedes continuar con el setup original"
    exit 0
fi

print_warning "VFIO-PCI no se pudo cargar. Causa probable: IOMMU no habilitado"

if [ "$IOMMU_ENABLED" = false ]; then
    echo ""
    print_header "SOLUCIÓN: Habilitar IOMMU en GRUB"

    echo ""
    print_info "Se necesita agregar '$IOMMU_PARAM' a los parámetros del kernel"
    echo ""
    print_warning "⚠️  ESTO REQUIERE REINICIAR EL SERVIDOR"
    echo ""

    read -p "¿Deseas modificar GRUB para habilitar IOMMU? (y/n): " enable_iommu

    if [ "$enable_iommu" = "y" ]; then
        print_info "Haciendo backup de GRUB..."
        cp /etc/default/grub /etc/default/grub.backup.$(date +%Y%m%d_%H%M%S)

        print_info "Modificando /etc/default/grub..."

        # Verificar si ya existe el parámetro
        if grep -q "GRUB_CMDLINE_LINUX.*iommu" /etc/default/grub; then
            print_warning "Ya existe configuración IOMMU en GRUB"
            print_info "Archivo actual:"
            grep "GRUB_CMDLINE_LINUX" /etc/default/grub
        else
            # Agregar parámetros IOMMU
            sed -i.bak "s/GRUB_CMDLINE_LINUX=\"\(.*\)\"/GRUB_CMDLINE_LINUX=\"\1 $IOMMU_PARAM iommu=pt\"/" /etc/default/grub
            print_info "✅ Parámetros agregados a GRUB"
        fi

        print_info "Actualizando GRUB..."
        update-grub

        echo ""
        print_header "✅ GRUB Actualizado"
        echo ""
        print_warning "⚠️  DEBES REINICIAR EL SERVIDOR para aplicar los cambios"
        echo ""
        print_info "Después del reinicio, ejecuta nuevamente:"
        echo "  sudo ./scripts/setup_my_controller.sh"
        echo ""

        read -p "¿Reiniciar ahora? (y/n): " reboot_now
        if [ "$reboot_now" = "y" ]; then
            print_info "Reiniciando en 5 segundos..."
            sleep 5
            reboot
        else
            print_info "Recuerda reiniciar manualmente: sudo reboot"
        fi
    else
        print_info "Modificación cancelada"
        echo ""
        print_info "Para habilitar IOMMU manualmente:"
        echo "  1. Editar: sudo nano /etc/default/grub"
        echo "  2. Agregar '$IOMMU_PARAM iommu=pt' a GRUB_CMDLINE_LINUX"
        echo "  3. Actualizar: sudo update-grub"
        echo "  4. Reiniciar: sudo reboot"
    fi
else
    print_warning "IOMMU parece estar habilitado, pero VFIO no carga"
    print_info "Posibles causas:"
    echo "  - Módulos del kernel no instalados"
    echo "  - Problema con la configuración del hardware"
    echo "  - BIOS/UEFI con virtualización deshabilitada"
    echo ""
    print_info "Revisar logs del kernel:"
    echo "  dmesg | grep -i vfio"
    echo "  dmesg | grep -i iommu"
fi

print_header "Fin del Diagnóstico"
