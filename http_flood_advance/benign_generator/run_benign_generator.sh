#!/bin/bash

# Benign Traffic Generator - Launch Script
# Optimized for c6525-100g nodes (100 Gbps NICs)

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default configuration
PORT_ID=0
NIC_PCI="0000:81:00.0"  # Update this to match your NIC
NUM_CORES=8             # Number of CPU cores to use
DURATION=300            # Duration in seconds (5 minutes)
TARGET_RATE_GBPS=80     # Target: 80 Gbps (80% of 100G)
HUGE_PAGES=8192         # Number of 2MB hugepages

# Source and destination configuration
SRC_MAC="aa:aa:aa:aa:aa:aa"
DST_MAC="bb:bb:bb:bb:bb:bb"
SRC_IP="192.168.1.0"
DST_IP="10.0.0.1"
DST_PORT=80

# Output directory
OUTPUT_DIR="./benign_traffic_data"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="${OUTPUT_DIR}/benign_traffic_${TIMESTAMP}.pcap"
STATS_FILE="${OUTPUT_DIR}/benign_stats_${TIMESTAMP}.txt"

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Setup hugepages
setup_hugepages() {
    print_info "Setting up hugepages..."

    # Check current hugepages
    current_pages=$(cat /proc/sys/vm/nr_hugepages)
    print_info "Current hugepages: $current_pages"

    if [ "$current_pages" -lt "$HUGE_PAGES" ]; then
        echo $HUGE_PAGES > /proc/sys/vm/nr_hugepages
        print_info "Set hugepages to $HUGE_PAGES"
    fi

    # Mount hugetlbfs if not mounted
    if ! mount | grep -q hugetlbfs; then
        mkdir -p /mnt/huge
        mount -t hugetlbfs nodev /mnt/huge
        print_info "Mounted hugetlbfs at /mnt/huge"
    fi
}

# Bind NIC to DPDK driver
bind_nic() {
    print_info "Binding NIC to DPDK driver..."

    # Check if NIC is already bound to DPDK driver
    if dpdk-devbind.py --status | grep -q "$NIC_PCI.*drv=vfio-pci"; then
        print_info "NIC already bound to vfio-pci"
        return 0
    fi

    # Load vfio-pci driver
    modprobe vfio-pci

    # Bind NIC
    dpdk-devbind.py --bind=vfio-pci $NIC_PCI

    if [ $? -eq 0 ]; then
        print_info "Successfully bound NIC $NIC_PCI to vfio-pci"
    else
        print_error "Failed to bind NIC to DPDK driver"
        exit 1
    fi
}

# Unbind NIC from DPDK driver
unbind_nic() {
    print_info "Unbinding NIC from DPDK driver..."
    dpdk-devbind.py --bind=mlx5_core $NIC_PCI
    print_info "NIC unbound and returned to kernel driver"
}

# Build the generator
build_generator() {
    print_info "Building benign traffic generator..."

    if [ ! -f "benign_traffic_dpdk.c" ]; then
        print_error "Source file benign_traffic_dpdk.c not found"
        exit 1
    fi

    make clean
    make

    if [ $? -eq 0 ]; then
        print_info "Build successful"
    else
        print_error "Build failed"
        exit 1
    fi
}

# Create output directory
setup_output_dir() {
    mkdir -p "$OUTPUT_DIR"
    print_info "Output directory: $OUTPUT_DIR"
}

# Run the generator
run_generator() {
    print_info "Starting benign traffic generator..."
    print_info "Target rate: ${TARGET_RATE_GBPS} Gbps"
    print_info "Using $NUM_CORES CPU cores"
    print_info "Duration: ${DURATION} seconds"
    print_info "Stats will be saved to: $STATS_FILE"

    # DPDK EAL parameters
    # -l: CPU cores to use (e.g., 0-7 for 8 cores)
    # -n: Number of memory channels (typically 4 for modern servers)
    # --proc-type: primary (this is the main process)
    # --file-prefix: Unique prefix for this DPDK instance

    CORE_LIST="0-$((NUM_CORES-1))"

    # Run generator with timeout
    timeout ${DURATION}s \
        ./build/benign_traffic_gen \
        -l $CORE_LIST \
        -n 4 \
        --proc-type=primary \
        --file-prefix=benign_gen \
        -- \
        --port-id=$PORT_ID \
        2>&1 | tee "$STATS_FILE"

    local exit_code=${PIPESTATUS[0]}

    if [ $exit_code -eq 124 ]; then
        print_info "Generator completed (timeout reached)"
    elif [ $exit_code -eq 0 ] || [ $exit_code -eq 130 ]; then
        print_info "Generator completed successfully"
    else
        print_error "Generator exited with error code $exit_code"
    fi
}

# Capture packets (optional, for verification)
capture_packets() {
    print_info "Starting packet capture for verification..."

    # Capture 10000 packets for verification
    tcpdump -i any -w "$PCAP_FILE" -c 10000 &
    TCPDUMP_PID=$!

    print_info "Packet capture started (PID: $TCPDUMP_PID)"
    print_info "Capturing to: $PCAP_FILE"
}

# Stop packet capture
stop_capture() {
    if [ ! -z "$TCPDUMP_PID" ]; then
        kill $TCPDUMP_PID 2>/dev/null
        wait $TCPDUMP_PID 2>/dev/null
        print_info "Packet capture stopped"
    fi
}

# Analyze captured traffic
analyze_traffic() {
    if [ -f "$PCAP_FILE" ]; then
        print_info "Analyzing captured traffic..."

        # Basic statistics
        echo -e "\n=== Captured Traffic Analysis ===" >> "$STATS_FILE"
        tcpdump -r "$PCAP_FILE" -nn -q 2>/dev/null | head -20 >> "$STATS_FILE"

        # Count packets
        total_packets=$(tcpdump -r "$PCAP_FILE" -nn 2>/dev/null | wc -l)
        echo "Total captured packets: $total_packets" >> "$STATS_FILE"

        print_info "Analysis complete. See $STATS_FILE for details"
    fi
}

# Cleanup function
cleanup() {
    print_info "Cleaning up..."
    stop_capture
    # Optionally unbind NIC
    # unbind_nic
}

# Signal handler
trap cleanup EXIT INT TERM

# Display configuration
show_config() {
    echo ""
    echo "==================================="
    echo "Benign Traffic Generator Configuration"
    echo "==================================="
    echo "NIC PCI Address:    $NIC_PCI"
    echo "Port ID:            $PORT_ID"
    echo "CPU Cores:          $NUM_CORES (0-$((NUM_CORES-1)))"
    echo "Target Rate:        ${TARGET_RATE_GBPS} Gbps"
    echo "Duration:           ${DURATION} seconds"
    echo "Source MAC:         $SRC_MAC"
    echo "Destination MAC:    $DST_MAC"
    echo "Source IP:          $SRC_IP/24"
    echo "Destination IP:     $DST_IP"
    echo "Destination Port:   $DST_PORT"
    echo "Output Directory:   $OUTPUT_DIR"
    echo "==================================="
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --pci)
            NIC_PCI="$2"
            shift 2
            ;;
        --cores)
            NUM_CORES="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --rate)
            TARGET_RATE_GBPS="$2"
            shift 2
            ;;
        --dst-mac)
            DST_MAC="$2"
            shift 2
            ;;
        --dst-ip)
            DST_IP="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --pci PCI_ADDR      NIC PCI address (default: $NIC_PCI)"
            echo "  --cores NUM         Number of CPU cores (default: $NUM_CORES)"
            echo "  --duration SEC      Duration in seconds (default: $DURATION)"
            echo "  --rate GBPS         Target rate in Gbps (default: $TARGET_RATE_GBPS)"
            echo "  --dst-mac MAC       Destination MAC address"
            echo "  --dst-ip IP         Destination IP address"
            echo "  --help              Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_info "=== Benign HTTP Traffic Generator ==="

    check_root
    show_config

    setup_output_dir
    setup_hugepages
    bind_nic
    build_generator

    # Optional: capture packets for verification
    # capture_packets

    run_generator

    # analyze_traffic

    print_info "=== Generation Complete ==="
    print_info "Statistics saved to: $STATS_FILE"
}

# Run main function
main
