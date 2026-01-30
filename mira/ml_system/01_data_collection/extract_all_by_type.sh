#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/local/dpdk_100g/mira/ml_system"
RAW_DIR="${ROOT_DIR}/datasets/raw_logs"
OUT_DIR="${ROOT_DIR}/datasets/processed"
EXTRACTOR="/local/dpdk_100g/mira/ml_system/01_data_collection/feature_extractor.py"

mkdir -p "${OUT_DIR}"

run_extract() {
  local label="$1"
  local input="$2"
  local output="$3"
  if [[ -f "${input}" ]]; then
    echo "[INFO] ${label}: ${input} -> ${output}"
    sudo python3 "${EXTRACTOR}" --input "${input}" --output "${output}" --label "${label}"
  else
    echo "[WARN] Missing: ${input}"
  fi
}

# Benign + mixed
for run in 1 2 3; do
  run_extract "benign" "${RAW_DIR}/benign_baseline_run${run}.log" \
    "${OUT_DIR}/benign_baseline_run${run}.csv"
  run_extract "mixed" "${RAW_DIR}/mixed_traffic_run${run}.log" \
    "${OUT_DIR}/mixed_traffic_run${run}.csv"
done

# Optional: typo file seen in some runs
run_extract "mixed" "${RAW_DIR}/atmixed_traffic_run1.log" \
  "${OUT_DIR}/atmixed_traffic_run1.csv"

# Attack types
attack_types=(ntp dns snmp ssdp portmap netbios ldap mssql udp syn webddos tftp)
for t in "${attack_types[@]}"; do
  for run in 1 2 3; do
    run_extract "${t}" "${RAW_DIR}/attack_${t}_run${run}.log" \
      "${OUT_DIR}/attack_${t}_run${run}.csv"
  done
done

echo "[DONE] Feature extraction complete."
