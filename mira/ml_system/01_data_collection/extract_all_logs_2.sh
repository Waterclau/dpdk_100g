#!/usr/bin/env bash
set -euo pipefail

cd /local/dpdk_100g/mira/ml_system/01_data_collection
mkdir -p ../datasets/processed_2

for f in ../datasets/raw_logs/*.log; do
  base=$(basename "$f" .log)
  case "$base" in
    benign_baseline_*) label=benign;;
    mixed_traffic_*|atmixed_traffic_*) label=mixed;;
    attack_cic_*) label=attack;;
    attack_udp_*) label=udp_flood;;
    attack_syn_*) label=syn_flood;;
    attack_dns_*) label=dns;;
    attack_ntp_*) label=ntp;;
    attack_snmp_*) label=snmp;;
    attack_ssdp_*) label=ssdp;;
    attack_portmap_*) label=portmap;;
    attack_netbios_*) label=netbios;;
    attack_ldap_*) label=ldap;;
    attack_mssql_*) label=mssql;;
    attack_tftp_*) label=tftp;;
    attack_webddos_*) label=webddos;;
    *) echo "SKIP $base"; continue;;
  esac

  python3 feature_extractor.py \
    --input "$f" \
    --output "../datasets/processed_2/${base}.csv" \
    --label "$label"
done
