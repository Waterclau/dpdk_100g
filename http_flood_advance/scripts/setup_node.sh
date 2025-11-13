#!/bin/bash

# Node Setup Script for Advanced HTTP Flood Experiment
# Prepares a c6525-100g node for traffic generation or detection

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect node type
detect_node_role() {
    echo ""
    echo "Select node role:"
    echo "1) Controller - Benign traffic generator"
    echo "2) TG - Attack traffic generator"
    echo "3) Monitor - DPDK + OctoStack detector"
    echo "4) Target - Web server (optional)"
    echo ""
    read -p "Enter choice (1-4): " choice

    case $choice in
        1)
            NODE_ROLE="controller"
            ;;
        2)
            NODE_ROLE="tg"
            ;;
        3)
            NODE_ROLE="monitor"
            ;;
        4)
            NODE_ROLE="target"
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac

    print_info "Node role set to: $NODE_ROLE"
}

# Install system dependencies
install_system_deps() {
    print_header "Installing System Dependencies"

    print_info "Updating package lists..."
    apt-get update -qq

    print_info "Installing build tools..."
    apt-get install -y build-essential gcc g++ make cmake pkg-config

    print_info "Installing DPDK..."
    apt-get install -y dpdk dpdk-dev libdpdk-dev dpdk-kmods

    print_info "Installing Python and pip..."
    apt-get install -y python3 python3-pip python3-dev

    print_info "Installing network tools..."
    apt-get install -y ethtool net-tools iproute2 tcpdump wireshark-common

    print_info "Installing utilities..."
    apt-get install -y htop iotop sysstat numactl git vim tmux

    print_info "System dependencies installed successfully"
}

# Install Python dependencies
install_python_deps() {
    print_header "Installing Python Dependencies"

    print_info "Installing Scapy..."
    pip3 install --upgrade scapy

    print_info "Installing additional Python packages..."
    pip3 install numpy scipy matplotlib pandas

    print_info "Python dependencies installed successfully"
}

# Setup hugepages
setup_hugepages() {
    print_header "Setting up Hugepages"

    local HUGEPAGE_SIZE=8192  # 8192 x 2MB = 16 GB

    print_info "Configuring $HUGEPAGE_SIZE hugepages (2MB each)"

    # Set hugepages
    echo $HUGEPAGE_SIZE > /proc/sys/vm/nr_hugepages

    # Verify
    local current=$(cat /proc/sys/vm/nr_hugepages)
    if [ "$current" -eq "$HUGEPAGE_SIZE" ]; then
        print_info "Hugepages configured: $current"
    else
        print_warning "Hugepages requested: $HUGEPAGE_SIZE, got: $current"
        print_warning "You may need to reboot or adjust kernel parameters"
    fi

    # Make persistent
    if ! grep -q "vm.nr_hugepages" /etc/sysctl.conf; then
        echo "vm.nr_hugepages=$HUGEPAGE_SIZE" >> /etc/sysctl.conf
        print_info "Added hugepages to /etc/sysctl.conf"
    fi

    # Mount hugetlbfs
    if ! mount | grep -q hugetlbfs; then
        mkdir -p /mnt/huge
        mount -t hugetlbfs nodev /mnt/huge
        print_info "Mounted hugetlbfs at /mnt/huge"

        # Make persistent
        if ! grep -q "hugetlbfs" /etc/fstab; then
            echo "nodev /mnt/huge hugetlbfs defaults 0 0" >> /etc/fstab
            print_info "Added hugetlbfs to /etc/fstab"
        fi
    else
        print_info "Hugetlbfs already mounted"
    fi

    # Show hugepage info
    echo ""
    grep Huge /proc/meminfo
}

# Setup CPU isolation
setup_cpu_isolation() {
    print_header "Setting up CPU Isolation"

    print_info "Current CPU configuration:"
    lscpu | grep -E "^CPU\(s\)|^NUMA|^Core"

    echo ""
    read -p "Do you want to isolate CPUs for DPDK? (y/n): " isolate

    if [ "$isolate" = "y" ]; then
        echo ""
        echo "Enter CPU cores to isolate (e.g., 1-7 for cores 1 through 7)"
        echo "Leave core 0 for system tasks"
        read -p "Cores to isolate: " cores

        # Check if already configured
        if grep -q "isolcpus" /etc/default/grub; then
            print_warning "CPU isolation already configured in /etc/default/grub"
            print_warning "Please edit manually if you want to change it"
        else
            # Backup grub config
            cp /etc/default/grub /etc/default/grub.backup

            # Add CPU isolation parameters
            sed -i "s/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"isolcpus=$cores nohz_full=$cores rcu_nocbs=$cores /" /etc/default/grub

            print_info "Added CPU isolation parameters to /etc/default/grub"
            print_warning "You MUST reboot for CPU isolation to take effect"

            # Update grub
            if [ -f /boot/grub/grub.cfg ]; then
                update-grub
                print_info "GRUB configuration updated"
            elif [ -f /boot/grub2/grub.cfg ]; then
                grub2-mkconfig -o /boot/grub2/grub.cfg
                print_info "GRUB2 configuration updated"
            fi
        fi
    else
        print_info "Skipping CPU isolation"
    fi
}

# Setup NIC for DPDK
setup_nic() {
    print_header "Setting up NIC for DPDK"

    print_info "Available NICs:"
    dpdk-devbind.py --status-dev net

    echo ""
    read -p "Enter NIC PCI address to bind to DPDK (e.g., 0000:81:00.0): " nic_pci

    if [ -z "$nic_pci" ]; then
        print_warning "No NIC specified, skipping NIC setup"
        return
    fi

    # Load vfio-pci module
    print_info "Loading vfio-pci module..."
    modprobe vfio-pci

    # Bind NIC
    print_info "Binding NIC $nic_pci to vfio-pci..."
    dpdk-devbind.py --bind=vfio-pci $nic_pci

    if [ $? -eq 0 ]; then
        print_info "NIC bound successfully"
        echo ""
        print_info "Current NIC status:"
        dpdk-devbind.py --status-dev net
    else
        print_error "Failed to bind NIC"
    fi

    # Save NIC PCI address for later use
    echo "$nic_pci" > /tmp/dpdk_nic_pci
}

# Configure kernel parameters
configure_kernel_params() {
    print_header "Configuring Kernel Parameters"

    # Disable ASLR (for consistent performance)
    print_info "Disabling ASLR..."
    echo 0 > /proc/sys/kernel/randomize_va_space

    # Increase file descriptor limits
    print_info "Increasing file descriptor limits..."
    ulimit -n 1048576

    # Make persistent
    if ! grep -q "1048576" /etc/security/limits.conf; then
        cat >> /etc/security/limits.conf << EOF

# For DPDK applications
* soft nofile 1048576
* hard nofile 1048576
* soft memlock unlimited
* hard memlock unlimited
EOF
        print_info "Updated /etc/security/limits.conf"
    fi

    # Network tuning
    print_info "Tuning network parameters..."
    cat >> /etc/sysctl.conf << EOF

# DPDK Network Tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 40960
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
EOF

    sysctl -p > /dev/null
    print_info "Kernel parameters configured"
}

# Build components based on node role
build_components() {
    print_header "Building Components for $NODE_ROLE"

    cd "$(dirname "$0")/.."

    case $NODE_ROLE in
        controller)
            print_info "Building benign traffic generator..."
            cd benign_generator
            make clean
            make
            print_info "Benign traffic generator built successfully"
            ;;
        tg)
            print_info "Attack generator will be built in next step"
            print_warning "Not yet implemented"
            ;;
        monitor)
            print_info "Building detector system..."
            cd ../detector_system
            if [ -f Makefile ]; then
                make clean
                make
                print_info "Detector system built successfully"
            else
                print_warning "Detector Makefile not found"
            fi
            ;;
        target)
            print_info "Setting up web server..."
            apt-get install -y nginx
            systemctl enable nginx
            systemctl start nginx
            print_info "Nginx web server installed and started"
            ;;
    esac
}

# Create output directories
create_directories() {
    print_header "Creating Output Directories"

    local base_dir="$(dirname "$0")/.."

    case $NODE_ROLE in
        controller)
            mkdir -p "$base_dir/benign_generator/benign_traffic_data"
            print_info "Created benign traffic data directory"
            ;;
        tg)
            mkdir -p "$base_dir/attack_generator/attack_data"
            print_info "Created attack data directory"
            ;;
        monitor)
            mkdir -p "$base_dir/detection_results"
            print_info "Created detection results directory"
            ;;
    esac
}

# Show setup summary
show_summary() {
    print_header "Setup Summary"

    echo "Node Role:           $NODE_ROLE"
    echo "Hugepages:           $(cat /proc/sys/vm/nr_hugepages)"
    echo "DPDK Version:        $(pkg-config --modversion libdpdk 2>/dev/null || echo 'Not found')"
    echo "Python Version:      $(python3 --version 2>&1 | cut -d' ' -f2)"
    echo "Scapy Installed:     $(python3 -c 'import scapy; print(scapy.__version__)' 2>/dev/null || echo 'Not found')"

    if [ -f /tmp/dpdk_nic_pci ]; then
        echo "NIC PCI Address:     $(cat /tmp/dpdk_nic_pci)"
    fi

    echo ""
    print_info "Setup complete!"

    if grep -q "isolcpus" /etc/default/grub; then
        echo ""
        print_warning "======================================"
        print_warning "REBOOT REQUIRED for CPU isolation!"
        print_warning "======================================"
        echo ""
        read -p "Reboot now? (y/n): " reboot_now
        if [ "$reboot_now" = "y" ]; then
            print_info "Rebooting in 5 seconds..."
            sleep 5
            reboot
        fi
    fi
}

# Main setup flow
main() {
    print_header "Advanced HTTP Flood Experiment - Node Setup"

    check_root
    detect_node_role

    echo ""
    read -p "Proceed with setup for $NODE_ROLE node? (y/n): " proceed
    if [ "$proceed" != "y" ]; then
        print_info "Setup cancelled"
        exit 0
    fi

    install_system_deps
    install_python_deps
    setup_hugepages
    configure_kernel_params
    setup_cpu_isolation
    setup_nic
    create_directories
    build_components

    show_summary
}

# Run main function
main
