#!/bin/bash
#
# Setup Script para NODE-CONTROLLER
# Configuración específica para tus nodos CloudLab
#
# Uso: sudo ./setup_my_controller.sh
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

# Configuración específica para tus nodos
NIC_PCI="0000:01:00.0"
NIC_INTERFACE="ens1f0"
CONTROLLER_IP="10.10.1.5"
CONTROLLER_MAC="0c:42:a1:8b:2f:c8"
MONITOR_IP="10.10.1.2"
MONITOR_MAC="0c:42:a1:8c:dd:0c"
HUGEPAGES=4096

print_header "Setup Node-Controller para Baseline Traffic"

echo ""
echo "Configuración detectada:"
echo "  Interface:      $NIC_INTERFACE"
echo "  IP Controller:  $CONTROLLER_IP"
echo "  IP Monitor:     $MONITOR_IP"
echo "  PCI Address:    $NIC_PCI"
echo "  Hugepages:      $HUGEPAGES"
echo ""

read -p "¿Continuar con el setup? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    print_info "Setup cancelado"
    exit 0
fi

# 1. Verificar conectividad con Monitor
print_header "1. Verificando Conectividad con Monitor"

ping -c 3 $MONITOR_IP > /dev/null 2>&1
if [ $? -eq 0 ]; then
    print_info "✅ Conectividad con Monitor OK"
else
    print_error "❌ No se puede hacer ping a Monitor ($MONITOR_IP)"
    print_warning "Verifica que node-monitor esté encendido y accesible"
    exit 1
fi

# 2. Verificar que el NIC existe
print_header "2. Verificando NIC"

if ip link show $NIC_INTERFACE > /dev/null 2>&1; then
    print_info "✅ Interface $NIC_INTERFACE encontrada"

    # Mostrar info del NIC
    actual_mac=$(ip link show $NIC_INTERFACE | grep -oP '(?<=ether\s)[a-f0-9:]{17}')
    actual_ip=$(ip addr show $NIC_INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

    echo "  MAC: $actual_mac"
    echo "  IP:  $actual_ip"

    if [ "$actual_mac" != "$CONTROLLER_MAC" ]; then
        print_warning "MAC no coincide con la esperada"
        print_warning "Esperada: $CONTROLLER_MAC"
        print_warning "Actual:   $actual_mac"
        read -p "¿Continuar de todos modos? (y/n): " cont
        if [ "$cont" != "y" ]; then
            exit 1
        fi
    fi
else
    print_error "❌ Interface $NIC_INTERFACE no encontrada"
    print_info "Interfaces disponibles:"
    ip link show
    exit 1
fi

# 3. Confirmar PCI del NIC
print_header "3. Confirmando PCI Address"

if command -v ethtool > /dev/null 2>&1; then
    actual_pci=$(ethtool -i $NIC_INTERFACE 2>/dev/null | grep "bus-info" | awk '{print $2}')
    if [ ! -z "$actual_pci" ]; then
        print_info "PCI detectado: $actual_pci"

        if [ "$actual_pci" != "$NIC_PCI" ]; then
            print_warning "PCI no coincide con el esperado"
            print_warning "Esperado: $NIC_PCI"
            print_warning "Detectado: $actual_pci"
            read -p "¿Usar el PCI detectado? (y/n): " use_detected
            if [ "$use_detected" = "y" ]; then
                NIC_PCI=$actual_pci
                print_info "Usando PCI detectado: $NIC_PCI"
            fi
        else
            print_info "✅ PCI correcto: $NIC_PCI"
        fi
    fi
else
    print_warning "ethtool no disponible, usando PCI por defecto: $NIC_PCI"
fi

# 4. Configurar Hugepages
print_header "4. Configurando Hugepages"

current_hp=$(cat /proc/sys/vm/nr_hugepages)
print_info "Hugepages actuales: $current_hp"

if [ "$current_hp" -lt "$HUGEPAGES" ]; then
    print_info "Configurando $HUGEPAGES hugepages..."
    echo $HUGEPAGES > /proc/sys/vm/nr_hugepages

    # Verificar
    new_hp=$(cat /proc/sys/vm/nr_hugepages)
    if [ "$new_hp" -eq "$HUGEPAGES" ]; then
        print_info "✅ Hugepages configuradas: $new_hp"
    else
        print_warning "Solo se pudieron configurar $new_hp hugepages (solicitadas: $HUGEPAGES)"
    fi
else
    print_info "✅ Hugepages ya configuradas: $current_hp"
fi

# Montar hugetlbfs si no está montado
if ! mount | grep -q hugetlbfs; then
    print_info "Montando hugetlbfs..."
    mkdir -p /mnt/huge
    mount -t hugetlbfs nodev /mnt/huge
    print_info "✅ hugetlbfs montado en /mnt/huge"
else
    print_info "✅ hugetlbfs ya montado"
fi

# Mostrar info de hugepages
echo ""
grep Huge /proc/meminfo

# 5. Cargar módulo VFIO-PCI
print_header "5. Cargando Módulo VFIO-PCI"

if lsmod | grep -q vfio_pci; then
    print_info "✅ Módulo vfio-pci ya cargado"
else
    print_info "Cargando módulo vfio-pci..."
    modprobe vfio-pci
    if lsmod | grep -q vfio_pci; then
        print_info "✅ Módulo vfio-pci cargado"
    else
        print_error "❌ Error al cargar módulo vfio-pci"
        exit 1
    fi
fi

# 6. Verificar que DPDK está instalado
print_header "6. Verificando DPDK"

if command -v dpdk-devbind.py > /dev/null 2>&1; then
    dpdk_version=$(pkg-config --modversion libdpdk 2>/dev/null || echo "unknown")
    print_info "✅ DPDK instalado (versión: $dpdk_version)"
else
    print_error "❌ dpdk-devbind.py no encontrado"
    print_info "Instalar DPDK con: sudo apt-get install dpdk dpdk-dev libdpdk-dev"
    exit 1
fi

# 7. Bindear NIC a DPDK
print_header "7. Bindeando NIC a DPDK"

print_warning "⚠️  Esto desconectará el NIC del kernel"
print_warning "    SSH management sigue funcionando (usa eno33)"
echo ""
read -p "¿Bindear $NIC_INTERFACE ($NIC_PCI) a DPDK? (y/n): " bind_confirm
if [ "$bind_confirm" != "y" ]; then
    print_info "Binding cancelado. Puedes hacerlo manualmente después con:"
    echo "  sudo dpdk-devbind.py --bind=vfio-pci $NIC_PCI"
else
    print_info "Bindeando $NIC_PCI a vfio-pci..."
    dpdk-devbind.py --bind=vfio-pci $NIC_PCI

    if [ $? -eq 0 ]; then
        print_info "✅ NIC bindeado exitosamente"
    else
        print_error "❌ Error al bindear NIC"
        exit 1
    fi
fi

# Mostrar estado
echo ""
print_info "Estado actual de NICs:"
dpdk-devbind.py --status

# 8. Verificar compilación
print_header "8. Verificando Compilación"

BASELINE_BIN="$HOME/dpdk_100g/http_flood_advance/benign_generator/build/baseline_traffic_gen"

if [ -f "$BASELINE_BIN" ]; then
    print_info "✅ Binario baseline_traffic_gen encontrado"
else
    print_warning "Binario no encontrado. Necesitas compilar:"
    echo ""
    echo "  cd ~/dpdk_100g/http_flood_advance/benign_generator"
    echo "  make clean"
    echo "  make"
    echo ""

    read -p "¿Compilar ahora? (y/n): " compile_now
    if [ "$compile_now" = "y" ]; then
        print_info "Compilando..."
        cd "$HOME/dpdk_100g/http_flood_advance/benign_generator"
        make clean
        make

        if [ -f "build/baseline_traffic_gen" ]; then
            print_info "✅ Compilación exitosa"
        else
            print_error "❌ Error en la compilación"
            exit 1
        fi
    fi
fi

# 9. Crear directorio de datos
print_header "9. Creando Directorio de Datos"

DATA_DIR="$HOME/dpdk_100g/http_flood_advance/benign_generator/baseline_traffic_data"
mkdir -p "$DATA_DIR"
chown $SUDO_USER:$SUDO_USER "$DATA_DIR"
print_info "✅ Directorio de datos: $DATA_DIR"

# 10. Resumen
print_header "✅ Setup Completo"

echo ""
echo "Configuración aplicada:"
echo "  ✅ Hugepages:       $(cat /proc/sys/vm/nr_hugepages)"
echo "  ✅ VFIO-PCI:        Cargado"
echo "  ✅ NIC Binding:     $NIC_PCI → vfio-pci"
echo "  ✅ Conectividad:    $CONTROLLER_IP → $MONITOR_IP OK"
echo "  ✅ Directorio:      $DATA_DIR"
echo ""

print_info "========================================="
print_info "LISTO PARA EJECUTAR GENERADOR BASELINE"
print_info "========================================="

echo ""
echo "Comandos para ejecutar:"
echo ""
echo "  # DPDK (tiempo real):"
echo "  sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary"
echo ""
echo "  # Python (dataset):"
echo "  python3 baseline_dataset_generator.py -d 300 -p medium \\"
echo "    --dst-ip $MONITOR_IP --dst-mac $MONITOR_MAC"
echo ""
echo "  # Monitoreo (en otra terminal):"
echo "  watch -n 1 'ethtool -S $NIC_INTERFACE | grep tx_packets'"
echo ""

print_info "Ver guía completa en: SETUP_MIS_NODOS.md"

# Crear archivo de comandos de referencia
COMMANDS_FILE="$HOME/dpdk_100g/http_flood_advance/MY_COMMANDS.txt"
cat > "$COMMANDS_FILE" << EOF
# Comandos de Referencia - Node Controller
# Generados por setup: $(date)

# === EJECUTAR GENERADOR DPDK ===
sudo ./build/baseline_traffic_gen -l 0-3 -n 4 --proc-type=primary

# === EJECUTAR GENERADOR PYTHON ===
python3 baseline_dataset_generator.py -d 300 -p medium \\
  --dst-ip $MONITOR_IP --dst-mac $MONITOR_MAC

# === MONITOREO ===
watch -n 1 'ethtool -S $NIC_INTERFACE | grep tx_packets'
sudo tcpdump -i $NIC_INTERFACE -c 20 -nn host $MONITOR_IP

# === VERIFICAR ===
ping $MONITOR_IP
sudo dpdk-devbind.py --status
cat /proc/meminfo | grep Huge

# === UNBIND (restaurar) ===
sudo dpdk-devbind.py --bind=mlx5_core $NIC_PCI

# === Tu Configuración ===
Controller IP:  $CONTROLLER_IP
Controller MAC: $CONTROLLER_MAC
Monitor IP:     $MONITOR_IP
Monitor MAC:    $MONITOR_MAC
NIC Interface:  $NIC_INTERFACE
NIC PCI:        $NIC_PCI
EOF

chown $SUDO_USER:$SUDO_USER "$COMMANDS_FILE"
print_info "Comandos guardados en: $COMMANDS_FILE"

echo ""
print_info "🚀 Setup completado exitosamente!"
