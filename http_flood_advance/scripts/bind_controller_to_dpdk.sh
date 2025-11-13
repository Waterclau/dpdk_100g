#!/bin/bash
#
# Script para bindear NIC del Controller a DPDK
# Proceso idéntico al usado en Monitor
#
# Uso: sudo ./bind_controller_to_dpdk.sh
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

# Configuración
NIC_INTERFACE="ens1f0"
NIC_PCI="0000:41:00.0"

print_header "Binding Controller NIC a DPDK"
print_info "Proceso idéntico al usado en Monitor"
echo ""

# 1. Buscar dpdk-devbind automáticamente
print_header "1. Buscando dpdk-devbind.py"

DPDK_DEVBIND=""

# Buscar en ubicaciones comunes
if command -v dpdk-devbind.py > /dev/null 2>&1; then
    DPDK_DEVBIND="dpdk-devbind.py"
    print_info "✅ Encontrado en PATH: $(which dpdk-devbind.py)"
elif [ -f "/local/dpdk/usertools/dpdk-devbind.py" ]; then
    DPDK_DEVBIND="/local/dpdk/usertools/dpdk-devbind.py"
    print_info "✅ Encontrado: $DPDK_DEVBIND"
elif [ -f "/usr/share/dpdk/usertools/dpdk-devbind.py" ]; then
    DPDK_DEVBIND="/usr/share/dpdk/usertools/dpdk-devbind.py"
    print_info "✅ Encontrado: $DPDK_DEVBIND"
elif [ -f "/usr/local/share/dpdk/usertools/dpdk-devbind.py" ]; then
    DPDK_DEVBIND="/usr/local/share/dpdk/usertools/dpdk-devbind.py"
    print_info "✅ Encontrado: $DPDK_DEVBIND"
else
    print_error "No se encuentra dpdk-devbind.py"
    print_info ""
    print_info "DPDK no está instalado. Opciones:"
    print_info ""
    print_info "Opción 1 - Instalar desde repositorio (rápido):"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install -y dpdk dpdk-dev libdpdk-dev"
    print_info ""
    print_info "Opción 2 - Compilar desde fuente:"
    echo "  cd /local"
    echo "  wget https://fast.dpdk.org/rel/dpdk-20.11.10.tar.xz"
    echo "  tar xf dpdk-20.11.10.tar.xz"
    echo "  cd dpdk-stable-20.11.10"
    echo "  meson build && cd build && ninja && sudo ninja install"
    exit 1
fi

# 2. Mostrar interfaces actuales
print_header "2. Interfaces Actuales"
ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/://'

# 3. Mostrar estado actual de NICs
print_header "3. Estado Actual de NICs"
$DPDK_DEVBIND --status

echo ""
print_info "NIC seleccionada para DPDK:"
print_info "  Interface: $NIC_INTERFACE"
print_info "  PCI:       $NIC_PCI"
echo ""

# 4. Verificar IOMMU
print_header "4. Verificando IOMMU"

if dmesg | grep -qi "IOMMU enabled"; then
    print_info "✅ IOMMU habilitado → usando vfio-pci"
    DPDK_DRIVER="vfio-pci"
    USE_VFIO=true
else
    print_warning "⚠️  IOMMU NO habilitado → usando uio_pci_generic"
    print_info "Para usar vfio-pci (como en monitor), necesitas:"
    print_info "  1. Editar /etc/default/grub"
    print_info "  2. Agregar: amd_iommu=on iommu=pt"
    print_info "  3. sudo update-grub && sudo reboot"
    echo ""
    DPDK_DRIVER="uio_pci_generic"
    USE_VFIO=false
fi

read -p "¿Continuar con $DPDK_DRIVER? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    print_info "Binding cancelado"
    exit 0
fi

# 5. Cargar módulo DPDK
print_header "5. Cargando Módulo $DPDK_DRIVER"

if [ "$USE_VFIO" = true ]; then
    # Cargar vfio-pci
    if lsmod | grep -q vfio_pci; then
        print_info "✅ vfio-pci ya está cargado"
    else
        print_info "Cargando vfio-pci..."
        modprobe vfio-pci
        if lsmod | grep -q vfio_pci; then
            print_info "✅ vfio-pci cargado"
        else
            print_error "❌ Error al cargar vfio-pci"
            exit 1
        fi
    fi
else
    # Cargar uio_pci_generic
    if lsmod | grep -q uio_pci_generic; then
        print_info "✅ uio_pci_generic ya está cargado"
    else
        print_info "Cargando uio_pci_generic..."
        modprobe uio_pci_generic
        if lsmod | grep -q uio_pci_generic; then
            print_info "✅ uio_pci_generic cargado"
        else
            print_error "❌ Error al cargar uio_pci_generic"
            exit 1
        fi
    fi
fi

lsmod | grep -E "vfio|uio"

# 6. Bajar interfaz
print_header "6. Bajando Interfaz $NIC_INTERFACE"

print_warning "⚠️  Esto desconectará $NIC_INTERFACE del kernel"
print_info "SSH seguirá funcionando (usa eno33/eno34)"
echo ""

if ip link show $NIC_INTERFACE > /dev/null 2>&1; then
    print_info "Ejecutando: ip link set $NIC_INTERFACE down"
    ip link set $NIC_INTERFACE down

    print_info "Ejecutando: ip addr flush dev $NIC_INTERFACE"
    ip addr flush dev $NIC_INTERFACE

    print_info "✅ Interfaz bajada"
else
    print_warning "Interfaz $NIC_INTERFACE no encontrada o ya está bajada"
fi

# 7. Hacer el binding
print_header "7. Haciendo Binding a DPDK"

print_info "Ejecutando: $DPDK_DEVBIND -b $DPDK_DRIVER $NIC_PCI"
$DPDK_DEVBIND -b $DPDK_DRIVER $NIC_PCI

if [ $? -eq 0 ]; then
    print_info "✅ Binding exitoso"
else
    print_error "❌ Error en el binding"
    exit 1
fi

# 8. Verificar binding
print_header "8. Verificación Final"

echo ""
print_info "NICs bindeadas a DPDK:"
$DPDK_DEVBIND --status | grep $DPDK_DRIVER

echo ""
print_info "Interfaces restantes en kernel:"
ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/://'

echo ""
print_header "✅ Binding Completo"

echo ""
echo "Configuración aplicada:"
echo "  ✅ Driver DPDK:     $DPDK_DRIVER"
echo "  ✅ NIC PCI:         $NIC_PCI"
echo "  ✅ Estado:          Bindeado a DPDK"
echo ""

print_info "Para usar desde DPDK:"
echo "  sudo ./octosketch_detector -l 1-8 -- -p 0x1"
echo ""

print_info "Para revertir al kernel:"
echo "  sudo $DPDK_DEVBIND -b mlx5_core $NIC_PCI"
echo "  sudo ip link set $NIC_INTERFACE up"
echo ""

print_info "🚀 Listo para ejecutar aplicaciones DPDK"
