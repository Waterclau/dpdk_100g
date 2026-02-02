#!/usr/bin/env python3
"""
Convert MIRA text logs to binary log format (mira_detector_ml.bin records).
Writes one .bin per .log with the same base name.
"""

import argparse
import re
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional

BINARY_LOG_MAGIC = 0x4D495241  # "MIRA"
BINARY_LOG_VERSION = 1
RECORD_STRUCT = struct.Struct("<IIQ" + "Q" * 33)

WINDOW_SECONDS_DEFAULT = 5.0


def _match_int(pattern: str, text: str) -> int:
    match = re.search(pattern, text, re.DOTALL)
    return int(match.group(1)) if match else 0


def _match_float(pattern: str, text: str) -> float:
    match = re.search(pattern, text, re.DOTALL)
    return float(match.group(1)) if match else 0.0


def _extract_window(window_text: str) -> Optional[Dict[str, int]]:
    total_packets = _match_int(r"Total packets:\s+(\d+)", window_text)
    if total_packets == 0:
        return None

    total_bytes = _match_int(
        r"Total received:\s+\d+ pkts.*?\|\s+[\d.]+ Gbps \|\s+(\d+) bytes",
        window_text,
    )
    if total_bytes == 0:
        avg_pkt_size = _match_float(r"avg pkt:\s+([\d.]+) bytes", window_text)
        total_bytes = int(total_packets * avg_pkt_size) if avg_pkt_size > 0 else 0

    tcp_packets = _match_int(r"TCP packets:\s+(\d+)", window_text)
    udp_packets = _match_int(r"UDP packets:\s+(\d+)", window_text)
    icmp_packets = _match_int(r"ICMP packets:\s+(\d+)", window_text)
    syn_packets = _match_int(r"SYN packets:\s+(\d+)", window_text)
    syn_ack_packets = _match_int(r"SYN-ACK packets:\s+(\d+)", window_text)
    http_requests = _match_int(r"HTTP requests:\s+(\d+)", window_text)
    dns_queries = _match_int(r"DNS queries:\s+(\d+)", window_text)

    baseline_packets = _match_int(
        r"Baseline \((?:192\.168\.1|10\.10\.2)[^)]*\):\s+(\d+)",
        window_text,
    )
    attack_packets = _match_int(
        r"Attack \((?:192\.168\.2|10\.10\.3)[^)]*\):\s+(\d+)",
        window_text,
    )

    ntp_monlist_queries = _match_int(r"Monlist queries:\s+(\d+)", window_text)
    ntp_responses = _match_int(r"NTP Amplification:.*?Responses:\s+(\d+)", window_text)
    avg_ntp_response_size = _match_int(
        r"NTP Amplification:.*?avg size:\s+(\d+) bytes", window_text
    )
    ntp_response_size_sum = ntp_responses * avg_ntp_response_size

    dns_any_queries = _match_int(r"ANY queries:\s+(\d+)", window_text)
    dns_txt_queries = _match_int(r"TXT queries:\s+(\d+)", window_text)
    dns_responses = _match_int(r"DNS Amplification:.*?Responses:\s+(\d+)", window_text)
    avg_dns_response_size = _match_int(
        r"DNS Amplification:.*?avg size:\s+(\d+) bytes", window_text
    )
    dns_response_size_sum = dns_responses * avg_dns_response_size

    snmp_getbulk_requests = _match_int(r"GetBulk requests:\s+(\d+)", window_text)
    snmp_responses = _match_int(r"SNMP Amplification:.*?Responses:\s+(\d+)", window_text)
    avg_snmp_response_size = _match_int(
        r"SNMP Amplification:.*?avg size:\s+(\d+) bytes", window_text
    )
    snmp_response_size_sum = snmp_responses * avg_snmp_response_size

    ssdp_msearch_packets = _match_int(r"M-SEARCH packets:\s+(\d+)", window_text)
    ssdp_responses = _match_int(r"SSDP:.*?Responses:\s+(\d+)", window_text)

    portmap_getport_calls = _match_int(r"GETPORT calls:\s+(\d+)", window_text)
    portmap_dump_calls = _match_int(r"DUMP calls:\s+(\d+)", window_text)

    netbios_name_queries = _match_int(r"Name queries:\s+(\d+)", window_text)
    netbios_dgram_packets = _match_int(r"Datagram packets:\s+(\d+)", window_text)

    ldap_bind_requests = _match_int(r"Bind requests:\s+(\d+)", window_text)
    ldap_search_requests = _match_int(r"Search requests:\s+(\d+)", window_text)

    mssql_sqlbatch_packets = _match_int(r"SQLBatch packets:\s+(\d+)", window_text)
    mssql_rpc_packets = _match_int(r"RPC packets:\s+(\d+)", window_text)

    tftp_rrq_packets = _match_int(r"RRQ \(read\) pkts:\s+(\d+)", window_text)
    tftp_wrq_packets = _match_int(r"WRQ \(write\) pkts:\s+(\d+)", window_text)

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
        "icmp_packets": icmp_packets,
        "syn_packets": syn_packets,
        "syn_ack_packets": syn_ack_packets,
        "http_requests": http_requests,
        "dns_queries": dns_queries,
        "baseline_packets": baseline_packets,
        "attack_packets": attack_packets,
        "ntp_monlist_queries": ntp_monlist_queries,
        "ntp_responses": ntp_responses,
        "ntp_response_size_sum": ntp_response_size_sum,
        "dns_any_queries": dns_any_queries,
        "dns_txt_queries": dns_txt_queries,
        "dns_responses": dns_responses,
        "dns_response_size_sum": dns_response_size_sum,
        "snmp_getbulk_requests": snmp_getbulk_requests,
        "snmp_responses": snmp_responses,
        "snmp_response_size_sum": snmp_response_size_sum,
        "ssdp_msearch_packets": ssdp_msearch_packets,
        "ssdp_responses": ssdp_responses,
        "portmap_getport_calls": portmap_getport_calls,
        "portmap_dump_calls": portmap_dump_calls,
        "netbios_name_queries": netbios_name_queries,
        "netbios_dgram_packets": netbios_dgram_packets,
        "ldap_bind_requests": ldap_bind_requests,
        "ldap_search_requests": ldap_search_requests,
        "mssql_sqlbatch_packets": mssql_sqlbatch_packets,
        "mssql_rpc_packets": mssql_rpc_packets,
        "tftp_rrq_packets": tftp_rrq_packets,
        "tftp_wrq_packets": tftp_wrq_packets,
    }


def _write_binary(records: List[Dict[str, int]], out_path: Path) -> None:
    with out_path.open("wb") as f:
        for idx, rec in enumerate(records):
            timestamp_ns = int(idx * WINDOW_SECONDS_DEFAULT * 1e9)
            values = [
                BINARY_LOG_MAGIC,
                BINARY_LOG_VERSION,
                timestamp_ns,
                rec["total_packets"],
                rec["total_bytes"],
                rec["tcp_packets"],
                rec["udp_packets"],
                rec["icmp_packets"],
                rec["syn_packets"],
                rec["syn_ack_packets"],
                rec["http_requests"],
                rec["dns_queries"],
                rec["baseline_packets"],
                rec["attack_packets"],
                rec["ntp_monlist_queries"],
                rec["ntp_responses"],
                rec["ntp_response_size_sum"],
                rec["dns_any_queries"],
                rec["dns_txt_queries"],
                rec["dns_responses"],
                rec["dns_response_size_sum"],
                rec["snmp_getbulk_requests"],
                rec["snmp_responses"],
                rec["snmp_response_size_sum"],
                rec["ssdp_msearch_packets"],
                rec["ssdp_responses"],
                rec["portmap_getport_calls"],
                rec["portmap_dump_calls"],
                rec["netbios_name_queries"],
                rec["netbios_dgram_packets"],
                rec["ldap_bind_requests"],
                rec["ldap_search_requests"],
                rec["mssql_sqlbatch_packets"],
                rec["mssql_rpc_packets"],
                rec["tftp_rrq_packets"],
                rec["tftp_wrq_packets"],
            ]
            f.write(RECORD_STRUCT.pack(*values))


def _convert_file(in_path: Path, out_path: Path, force: bool) -> None:
    if out_path.exists() and not force:
        print(f"[SKIP] {out_path} exists (use --force to overwrite)")
        return

    log_content = in_path.read_text(encoding="utf-8", errors="ignore")
    windows = re.split(r"\[PACKET COUNTERS - GLOBAL\]", log_content)
    records: List[Dict[str, int]] = []
    for window in windows[1:]:
        rec = _extract_window(window)
        if rec:
            records.append(rec)

    if not records:
        print(f"[WARN] No records found in {in_path}")
        return

    _write_binary(records, out_path)
    print(f"[OK] {in_path.name} -> {out_path.name} ({len(records)} records)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert MIRA text logs to binary logs."
    )
    parser.add_argument("input", help="Input .log file or directory")
    parser.add_argument("--output-dir", help="Output directory (default: input dir)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing .bin files")
    args = parser.parse_args()

    in_path = Path(args.input)
    out_dir = Path(args.output_dir) if args.output_dir else in_path.parent

    if in_path.is_dir():
        logs = sorted(in_path.glob("*.log"))
        if not logs:
            print(f"[ERROR] No .log files found in {in_path}", file=sys.stderr)
            return 1
        out_dir.mkdir(parents=True, exist_ok=True)
        for log in logs:
            out_path = out_dir / (log.stem + ".bin")
            _convert_file(log, out_path, args.force)
    else:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / (in_path.stem + ".bin")
        _convert_file(in_path, out_path, args.force)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
