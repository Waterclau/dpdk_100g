#!/bin/bash

# Large-Scale Benign Traffic Dataset Generator
# Generates multiple dataset files for comprehensive testing

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

# Configuration
OUTPUT_DIR="./benign_traffic_data"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATASET_DIR="${OUTPUT_DIR}/dataset_${TIMESTAMP}"

# Dataset parameters (for large dataset)
TOTAL_SESSIONS=5000000    # 5 million sessions
SESSIONS_PER_FILE=500000  # 500K sessions per file
NUM_FILES=$((TOTAL_SESSIONS / SESSIONS_PER_FILE))

# Network configuration
DST_IP="10.0.0.1"
DST_MAC="bb:bb:bb:bb:bb:bb"
SRC_IP_BASE="192.168."
DST_PORT=80

# Create output directory
mkdir -p "$DATASET_DIR"
print_info "Output directory: $DATASET_DIR"

# Save configuration
CONFIG_FILE="${DATASET_DIR}/generation_config.json"
cat > "$CONFIG_FILE" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "total_sessions": $TOTAL_SESSIONS,
  "sessions_per_file": $SESSIONS_PER_FILE,
  "num_files": $NUM_FILES,
  "dst_ip": "$DST_IP",
  "dst_mac": "$DST_MAC",
  "src_ip_base": "$SRC_IP_BASE",
  "dst_port": $DST_PORT,
  "estimated_size_mb": $((TOTAL_SESSIONS * 50 / 1024)),
  "estimated_packets": $((TOTAL_SESSIONS * 10))
}
EOF
print_info "Configuration saved to $CONFIG_FILE"

# Function to generate a single dataset file
generate_dataset_file() {
    local file_num=$1
    local sessions=$2
    local output_file="${DATASET_DIR}/benign_traffic_part${file_num}.pcap"
    local stats_file="${DATASET_DIR}/benign_stats_part${file_num}.json"

    print_info "Generating file $file_num/$NUM_FILES ($sessions sessions)..."

    python3 benign_dataset_generator.py \
        -n $sessions \
        -o "$output_file" \
        --dst-ip "$DST_IP" \
        --dst-mac "$DST_MAC" \
        --src-ip-base "$SRC_IP_BASE" \
        --dst-port $DST_PORT \
        --stats-file "$stats_file"

    if [ $? -eq 0 ]; then
        # Get file size
        local file_size=$(du -h "$output_file" | cut -f1)
        print_info "File $file_num complete: $file_size"
        return 0
    else
        print_error "Failed to generate file $file_num"
        return 1
    fi
}

# Main generation loop
print_header "Large-Scale Benign Traffic Dataset Generation"
echo "Total Sessions: $(printf "%'d" $TOTAL_SESSIONS)"
echo "Files to Generate: $NUM_FILES"
echo "Sessions per File: $(printf "%'d" $SESSIONS_PER_FILE)"
echo "Estimated Total Size: ~$((TOTAL_SESSIONS * 50 / 1024)) MB"
echo ""

START_TIME=$(date +%s)

# Check if Python script exists
if [ ! -f "benign_dataset_generator.py" ]; then
    print_error "benign_dataset_generator.py not found!"
    exit 1
fi

# Check if scapy is installed
if ! python3 -c "import scapy" 2>/dev/null; then
    print_warning "Scapy not installed. Installing..."
    pip3 install scapy
fi

# Generate all files
FAILED=0
for i in $(seq 1 $NUM_FILES); do
    if ! generate_dataset_file $i $SESSIONS_PER_FILE; then
        FAILED=$((FAILED + 1))
    fi

    # Show progress
    PROGRESS=$((i * 100 / NUM_FILES))
    print_info "Progress: $PROGRESS% ($i/$NUM_FILES files)"
    echo ""
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Generate summary
SUMMARY_FILE="${DATASET_DIR}/dataset_summary.txt"
{
    echo "=== Benign Traffic Dataset Summary ==="
    echo "Generation Timestamp: $(date)"
    echo "Duration: ${DURATION} seconds ($((DURATION / 60)) minutes)"
    echo ""
    echo "Configuration:"
    echo "  Total Sessions: $(printf "%'d" $TOTAL_SESSIONS)"
    echo "  Number of Files: $NUM_FILES"
    echo "  Sessions per File: $(printf "%'d" $SESSIONS_PER_FILE)"
    echo "  Failed Files: $FAILED"
    echo ""
    echo "Files Generated:"
    ls -lh "${DATASET_DIR}"/*.pcap 2>/dev/null || echo "  No PCAP files found"
    echo ""
    echo "Total Dataset Size:"
    du -sh "$DATASET_DIR"
    echo ""
    echo "Statistics Files:"
    ls "${DATASET_DIR}"/*.json 2>/dev/null || echo "  No stats files found"
} | tee "$SUMMARY_FILE"

# Aggregate statistics from all files
print_info "Aggregating statistics..."
AGGREGATE_STATS="${DATASET_DIR}/aggregate_stats.json"
python3 << 'PYTHON_SCRIPT'
import json
import glob
import sys

stats_files = glob.glob("${DATASET_DIR}/benign_stats_part*.json")
aggregate = {
    "total_sessions": 0,
    "total_packets": 0,
    "total_bytes": 0,
    "tcp_handshakes": 0,
    "files": []
}

method_totals = {}

for stats_file in sorted(stats_files):
    with open(stats_file, 'r') as f:
        stats = json.load(f)
        aggregate["total_sessions"] += stats.get("sessions", 0)
        aggregate["total_packets"] += stats.get("total_packets", 0)
        aggregate["total_bytes"] += stats.get("total_bytes", 0)
        aggregate["tcp_handshakes"] += stats.get("tcp_handshakes", 0)
        aggregate["files"].append(stats_file)

        # Aggregate HTTP methods
        for key, value in stats.items():
            if key.startswith("method_"):
                method_totals[key] = method_totals.get(key, 0) + value

aggregate.update(method_totals)
aggregate["total_mb"] = aggregate["total_bytes"] / (1024 * 1024)
aggregate["total_gb"] = aggregate["total_bytes"] / (1024 * 1024 * 1024)

with open("${AGGREGATE_STATS}", 'w') as f:
    json.dump(aggregate, f, indent=2)

print(f"Aggregate statistics saved to ${AGGREGATE_STATS}")
print(f"\nDataset Summary:")
print(f"  Total Sessions:  {aggregate['total_sessions']:,}")
print(f"  Total Packets:   {aggregate['total_packets']:,}")
print(f"  Total Size:      {aggregate['total_gb']:.2f} GB")
PYTHON_SCRIPT

print_header "Dataset Generation Complete!"
print_info "Dataset location: $DATASET_DIR"
print_info "Summary: $SUMMARY_FILE"
print_info "Aggregate stats: $AGGREGATE_STATS"

if [ $FAILED -gt 0 ]; then
    print_warning "$FAILED files failed to generate"
    exit 1
else
    print_info "All files generated successfully!"
    exit 0
fi
