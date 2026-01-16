#!/usr/bin/env python3
"""
MIRA CIC-DDoS-2019 Attack Generator v5.0 (Memory-Efficient Multiprocessing)

Features:
- MEMORY EFFICIENT: Each worker writes directly to temp file (no RAM accumulation)
- MULTIPROCESSING: Parallel packet generation with progress display
- All 13 CIC-DDoS-2019 attack types supported

Usage:
    python3 generate_cicdos2019_attacks.py -n 20000000 -w 8 -o attack.pcap

Author: MIRA Project
"""

import argparse
import random
import struct
import time
import os
import sys
import tempfile
import subprocess
import shutil
import threading
import queue as py_queue
from multiprocessing import Process, Queue, Value, Array
from ctypes import c_uint64, c_bool

# Disable Scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import wrpcap, PcapWriter, PcapReader, Ether, IP, TCP, UDP, Raw, DNS, DNSQR

# ============================================================================
# Attack Type Definitions
# ============================================================================

ATTACK_TYPES = [
    'portmap', 'netbios', 'ldap', 'mssql', 'udp', 'udp_lag',
    'syn', 'ntp', 'dns', 'snmp', 'ssdp', 'webddos', 'tftp', 'mixed'
]

# Mixed (sequential) weighted distribution, total 100%.
MIXED_WEIGHTED_ORDER = [
    'portmap', 'netbios', 'ldap', 'mssql', 'udp', 'udp_lag',
    'syn', 'ntp', 'dns', 'snmp', 'ssdp', 'webddos', 'tftp'
]

MIXED_WEIGHTED_PCTS = {
    'udp': 20,
    'syn': 15,
    'dns': 10,
    'ntp': 8,
    'snmp': 8,
    'ssdp': 6,
    'webddos': 8,
    'udp_lag': 8,
    'portmap': 5,
    'netbios': 5,
    'ldap': 5,
    'mssql': 5,
    'tftp': 5,
}

# ============================================================================
# Attack Packet Generation Functions (return raw bytes for efficiency)
# ============================================================================

def generate_portmap_attack(src_ip, dst_ip, src_mac, dst_mac):
    rpc_call = struct.pack('>I', random.randint(1, 0xFFFFFFFF))
    rpc_call += struct.pack('>I', 0)
    rpc_call += struct.pack('>I', 2)
    rpc_call += struct.pack('>I', 100000)
    rpc_call += struct.pack('>I', 2)
    rpc_call += struct.pack('>I', random.choice([3, 4]))
    rpc_call += struct.pack('>I', 0) * 4
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=111) / Raw(load=rpc_call)
    return [pkt]


def generate_netbios_attack(src_ip, dst_ip, src_mac, dst_mac):
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
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=port) / Raw(load=nbns_query)
    return [pkt]


def generate_ldap_attack(src_ip, dst_ip, src_mac, dst_mac):
    ldap_search = bytes([
        0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04, 0x00,
        0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b,
        0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73,
        0x30, 0x00
    ])
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=389) / Raw(load=ldap_search)
    return [pkt]


def generate_mssql_attack(src_ip, dst_ip, src_mac, dst_mac):
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=1434) / Raw(load=b'\x02')
    return [pkt]


def generate_udp_flood(src_ip, dst_ip, src_mac, dst_mac):
    payload = bytes([random.randint(0, 255) for _ in range(random.randint(64, 512))])
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 65535)) / Raw(load=payload)
    return [pkt]


def generate_udp_lag(src_ip, dst_ip, src_mac, dst_mac):
    payload = bytes([random.randint(0, 255) for _ in range(random.randint(1000, 1400))])
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 65535)) / Raw(load=payload)
    return [pkt]


def generate_syn_flood(src_ip, dst_ip, src_mac, dst_mac):
    target_ports = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432, 8080, 8443]
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=random.randint(1024, 65535), dport=random.choice(target_ports),
              flags='S', seq=random.randint(1000, 4000000000),
              window=random.choice([1024, 2048, 4096, 8192, 16384, 65535]))
    return [pkt]


def generate_ntp_attack(src_ip, dst_ip, src_mac, dst_mac):
    ntp_monlist = bytes([0x17, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00]) + b'\x00' * 40
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=123) / Raw(load=ntp_monlist)
    return [pkt]


def generate_dns_attack(src_ip, dst_ip, src_mac, dst_mac):
    domains = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com']
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=53) / \
          DNS(rd=1, qd=DNSQR(qname=random.choice(domains), qtype=255))
    return [pkt]


def generate_snmp_attack(src_ip, dst_ip, src_mac, dst_mac):
    snmp_request = bytes([
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
        0xa5, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00,
        0x02, 0x02, 0x07, 0xd0, 0x30, 0x0a, 0x30, 0x08,
        0x06, 0x04, 0x2b, 0x06, 0x01, 0x02, 0x05, 0x00
    ])
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=161) / Raw(load=snmp_request)
    return [pkt]


def generate_ssdp_attack(src_ip, dst_ip, src_mac, dst_mac):
    ssdp_msearch = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=1900) / Raw(load=ssdp_msearch)
    return [pkt]


def generate_webddos_attack(src_ip, dst_ip, src_mac, dst_mac):
    sport = random.randint(49152, 65535)
    dport = random.choice([80, 443])
    seq = random.randint(1000, 4000000000)
    http_req = random.choice([
        b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\n\r\n",
    ])
    syn = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=dport, flags='S', seq=seq)
    http = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
           TCP(sport=sport, dport=dport, flags='PA', seq=seq+1, ack=1) / Raw(load=http_req)
    return [syn, http]


def generate_tftp_attack(src_ip, dst_ip, src_mac, dst_mac):
    filenames = [b'test.txt', b'config.cfg', b'boot.bin', b'firmware.img']
    tftp_rrq = struct.pack('>H', 1) + random.choice(filenames) + b'\x00octet\x00'
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=69) / Raw(load=tftp_rrq)
    return [pkt]


ATTACK_GENERATORS = {
    'portmap': generate_portmap_attack, 'netbios': generate_netbios_attack,
    'ldap': generate_ldap_attack, 'mssql': generate_mssql_attack,
    'udp': generate_udp_flood, 'udp_lag': generate_udp_lag,
    'syn': generate_syn_flood, 'ntp': generate_ntp_attack,
    'dns': generate_dns_attack, 'snmp': generate_snmp_attack,
    'ssdp': generate_ssdp_attack, 'webddos': generate_webddos_attack,
    'tftp': generate_tftp_attack,
}

ATTACK_PHASES = [
    {'name': "Amplification", 'duration_pct': 30,
     'attacks': ['ntp', 'dns', 'snmp', 'ssdp', 'portmap', 'netbios', 'ldap', 'mssql', 'tftp']},
    {'name': "Volumetric", 'duration_pct': 40,
     'attacks': ['syn', 'syn', 'udp', 'udp', 'udp_lag', 'webddos']},
    {'name': "Mixed", 'duration_pct': 30,
     'attacks': list(ATTACK_GENERATORS.keys())},
]


# ============================================================================
# Worker Process (writes directly to temp file)
# ============================================================================

def worker_process(worker_id, num_packets, attack_type, intensity,
                   src_mac, dst_mac, attacker_ips, target_ip,
                   output_file, progress_array, done_flags, stats_queue):
    """Worker process that writes packets directly to a temp PCAP file."""

    random.seed(worker_id + int(time.time() * 1000) % 10000)

    # Open PCAP writer
    writer = PcapWriter(output_file, append=False, sync=True)

    current_timestamp = time.time() + (worker_id * 0.001)
    base_interval = 0.000001 / intensity

    attack_stats = {at: 0 for at in ATTACK_GENERATORS.keys()}
    packets_written = 0

    # Progress update interval
    update_interval = max(1, num_packets // 100)

    if attack_type == 'mixed':
        # Mixed attack, sequential and weighted by type.
        remaining_packets = num_packets
        attack_targets = {}
        for name in MIXED_WEIGHTED_ORDER:
            pct = MIXED_WEIGHTED_PCTS.get(name, 0)
            attack_targets[name] = int(num_packets * pct / 100)
            remaining_packets -= attack_targets[name]
        if remaining_packets > 0:
            attack_targets[MIXED_WEIGHTED_ORDER[-1]] += remaining_packets

        for selected_attack in MIXED_WEIGHTED_ORDER:
            generator = ATTACK_GENERATORS[selected_attack]
            target_packets = attack_targets[selected_attack]
            generated = 0

            while generated < target_packets and packets_written < num_packets:
                attacker_ip = random.choice(attacker_ips)
                pkts = generator(attacker_ip, target_ip, src_mac, dst_mac)

                for pkt in pkts:
                    pkt.time = current_timestamp
                    current_timestamp += base_interval + (random.random() - 0.5) * 0.0001
                    writer.write(pkt)
                    packets_written += 1
                    generated += 1
                    if generated >= target_packets or packets_written >= num_packets:
                        break

                attack_stats[selected_attack] += len(pkts)

                if packets_written % update_interval == 0:
                    progress_array[worker_id] = packets_written
    else:
        # Single attack type
        generator = ATTACK_GENERATORS.get(attack_type, generate_syn_flood)

        for i in range(num_packets):
            attacker_ip = random.choice(attacker_ips)
            pkts = generator(attacker_ip, target_ip, src_mac, dst_mac)

            for pkt in pkts:
                pkt.time = current_timestamp
                current_timestamp += base_interval + (random.random() - 0.5) * 0.0001
                writer.write(pkt)
                packets_written += 1

            attack_stats[attack_type] += len(pkts)

            if i % update_interval == 0:
                progress_array[worker_id] = packets_written

    writer.close()
    progress_array[worker_id] = packets_written
    done_flags[worker_id] = True
    stats_queue.put(attack_stats)


def display_progress(num_workers, progress_array, done_flags, total_packets, start_time, worker_packet_counts):
    """Display progress for all workers."""
    while not all(done_flags):
        time.sleep(0.5)

        elapsed = time.time() - start_time
        total_done = sum(progress_array)
        pct = total_done * 100 // total_packets if total_packets > 0 else 0
        rate = total_done / elapsed if elapsed > 0 else 0

        # Build progress display
        sys.stdout.write('\r' + ' ' * 120 + '\r')  # Clear line

        worker_status = []
        for w in range(num_workers):
            if done_flags[w]:
                worker_status.append(f"W{w}:DONE")
            else:
                denom = worker_packet_counts[w]
                wpct = progress_array[w] * 100 // denom if denom > 0 else 0
                worker_status.append(f"W{w}:{progress_array[w]:,}/{denom:,}({wpct}%)")

        status_line = f"Progress: {total_done:,}/{total_packets:,} ({pct}%) | {rate:,.0f} pkt/s | {' '.join(worker_status)}"

        sys.stdout.write(status_line)
        sys.stdout.flush()

    # Final update
    elapsed = time.time() - start_time
    total_done = sum(progress_array)
    rate = total_done / elapsed if elapsed > 0 else 0
    sys.stdout.write('\r' + ' ' * 120 + '\r')
    print(f"Generation complete: {total_done:,} packets in {elapsed:.1f}s ({rate:,.0f} pkt/s)")


# ============================================================================
# Main Generation Function
# ============================================================================

def generate_cicdos2019_attacks(output_file, num_packets, attack_type, intensity,
                                 src_mac, dst_mac, attacker_range, target_ip,
                                 num_attackers=200, speedup=1, num_workers=8,
                                 worker_batch=0):

    print("=" * 80)
    print("MIRA CIC-DDoS-2019 Attack Generator v5.0 (Memory-Efficient)")
    print("=" * 80)
    print(f"Attack type:      {attack_type.upper()}")
    print(f"Intensity:        {intensity}x")
    print(f"Total packets:    {num_packets:,}")
    print(f"Output file:      {output_file}")
    print(f"Workers:          {num_workers}")
    if worker_batch and worker_batch > 0 and worker_batch < num_workers:
        print(f"Worker batch:     {worker_batch}")
    print(f"Attacker range:   {attacker_range}")
    print(f"Target IP:        {target_ip}")
    print(f"Source MAC:       {src_mac}")
    print(f"Dest MAC:         {dst_mac}")
    print(f"Speedup:          {speedup}x")
    print("")

    # Generate attacker IPs
    base_ip = attacker_range.split('/')[0]
    ip_parts = base_ip.split('.')
    base_ip_int = (int(ip_parts[0]) << 24) | (int(ip_parts[1]) << 16) | \
                  (int(ip_parts[2]) << 8) | int(ip_parts[3])

    attacker_ips = []
    for i in range(num_attackers):
        attacker_ip_int = base_ip_int + (i % 256)
        attacker_ip = f"{(attacker_ip_int >> 24) & 0xFF}.{(attacker_ip_int >> 16) & 0xFF}." \
                     f"{(attacker_ip_int >> 8) & 0xFF}.{attacker_ip_int & 0xFF}"
        attacker_ips.append(attacker_ip)

    # Calculate packets per worker
    packets_per_worker = num_packets // num_workers
    remainder = num_packets % num_workers
    worker_packet_counts = []
    for w in range(num_workers):
        worker_packet_counts.append(packets_per_worker + (1 if w < remainder else 0))

    # Create temp directory for worker files
    temp_dir = tempfile.mkdtemp(prefix='mira_attack_')
    temp_files = [os.path.join(temp_dir, f'worker_{w}.pcap') for w in range(num_workers)]

    print(f"Temp directory: {temp_dir}")
    print(f"Packets per worker: ~{packets_per_worker:,}")
    print("")

    # Shared progress tracking
    progress_array = Array(c_uint64, num_workers)
    done_flags = Array(c_bool, num_workers)
    stats_queue = Queue()

    for i in range(num_workers):
        progress_array[i] = 0
        done_flags[i] = False

    # Start workers
    start_time = time.time()
    print(f"Starting {num_workers} worker processes...")
    print("")

    progress_thread = threading.Thread(
        target=display_progress,
        args=(num_workers, progress_array, done_flags, num_packets, start_time, worker_packet_counts),
        daemon=True,
    )
    progress_thread.start()

    batch_size = num_workers if not worker_batch or worker_batch <= 0 else min(worker_batch, num_workers)
    for batch_start in range(0, num_workers, batch_size):
        processes = []
        for w in range(batch_start, min(batch_start + batch_size, num_workers)):
            worker_packets = worker_packet_counts[w]
            p = Process(target=worker_process, args=(
                w, worker_packets, attack_type, intensity,
                src_mac, dst_mac, attacker_ips, target_ip,
                temp_files[w], progress_array, done_flags, stats_queue
            ))
            p.start()
            processes.append(p)

        for p in processes:
            p.join()

    progress_thread.join()

    generation_time = time.time() - start_time
    total_attack_stats = {at: 0 for at in ATTACK_GENERATORS.keys()}
    for _ in range(num_workers):
        try:
            worker_stats = stats_queue.get(timeout=5)
        except py_queue.Empty:
            break
        for attack_name, count in worker_stats.items():
            total_attack_stats[attack_name] = total_attack_stats.get(attack_name, 0) + count

    # Merge PCAP files
    print(f"\nMerging {num_workers} PCAP files...")
    merge_start = time.time()

    # Check if mergecap is available
    mergecap_path = shutil.which('mergecap')
    has_mergecap = bool(mergecap_path)

    if has_mergecap:
        # Use mergecap (faster)
        cmd = [mergecap_path, '-w', output_file] + temp_files
        subprocess.run(cmd, check=True)
    else:
        # Manual merge with Scapy
        print("  (mergecap not found, using Python merge - slower)")
        with PcapWriter(output_file, append=False, sync=True) as writer:
            for i, temp_file in enumerate(temp_files):
                print(f"  Reading worker {i} file...")
                with PcapReader(temp_file) as reader:
                    for pkt in reader:
                        writer.write(pkt)

    merge_time = time.time() - merge_start

    # Apply timestamp normalization and speedup
    if speedup > 1:
        print(f"\nApplying {speedup}x timestamp compression...")
        first_time = None
        with PcapReader(output_file) as reader:
            for pkt in reader:
                if first_time is None or pkt.time < first_time:
                    first_time = pkt.time

        if first_time is not None:
            temp_output = output_file + ".tmp_speed"
            max_time = None
            with PcapReader(output_file) as reader, PcapWriter(temp_output, append=False, sync=True) as writer:
                for pkt in reader:
                    pkt.time = (pkt.time - first_time) / speedup
                    max_time = pkt.time if max_time is None or pkt.time > max_time else max_time
                    writer.write(pkt)
            os.replace(temp_output, output_file)
            duration = max_time if max_time is not None else 0
            print(f"  Compressed duration: {duration:.2f} seconds")

    # Cleanup temp files
    print("\nCleaning up temp files...")
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    os.rmdir(temp_dir)

    # Statistics
    file_size = os.path.getsize(output_file)
    total_time = time.time() - start_time

    print("\n" + "=" * 80)
    print("Generation Summary:")
    print("=" * 80)
    print(f"  Total packets:     {sum(progress_array):,}")
    print(f"  Generation time:   {generation_time:.1f} seconds")
    print(f"  Merge time:        {merge_time:.1f} seconds")
    print(f"  Total time:        {total_time:.1f} seconds")
    print(f"  Generation rate:   {sum(progress_array) / generation_time:,.0f} pkt/s")
    print(f"  File size:         {file_size / (1024*1024):.2f} MB")
    print(f"  Workers used:      {num_workers}")
    total_stat_packets = sum(total_attack_stats.values())
    if total_stat_packets > 0:
        print("  Attack distribution:")
        for attack_name in sorted(total_attack_stats.keys()):
            count = total_attack_stats[attack_name]
            if count:
                pct = (count * 100.0) / total_stat_packets
                print(f"    - {attack_name}: {count:,} ({pct:.1f}%)")
    print("")
    print("Replay command:")
    print(f"  sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w <PCI> -- \\")
    print(f"      --pcap-dir <dir> --rate-gbps 12")
    print("")

    return sum(progress_array)


def main():
    parser = argparse.ArgumentParser(
        description='Generate CIC-DDoS-2019 attack traffic (Memory-Efficient)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types: portmap, netbios, ldap, mssql, udp, udp_lag, syn, ntp, dns, snmp, ssdp, webddos, tftp, mixed

Examples:
  python3 generate_cicdos2019_attacks.py -n 10000000 -w 8 -o attack.pcap
  python3 generate_cicdos2019_attacks.py -t syn -n 5000000 -w 4 -i 3.0 -o syn_flood.pcap
        """
    )

    parser.add_argument('--output', '-o', default='attack_cicdos2019.pcap')
    parser.add_argument('--packets', '-n', type=int, default=10000000)
    parser.add_argument('--attack-type', '-t', choices=ATTACK_TYPES, default='mixed')
    parser.add_argument('--intensity', '-i', type=float, default=1.0)
    parser.add_argument('--workers', '-w', type=int, default=8)
    parser.add_argument('--src-mac', default='00:00:00:00:00:02')
    parser.add_argument('--dst-mac', default='0c:42:a1:dd:57:90')
    parser.add_argument('--attacker-range', default='10.10.3.0/24')
    parser.add_argument('--target-ip', default='10.10.1.2')
    parser.add_argument('--attackers', type=int, default=200)
    parser.add_argument('--speedup', '-s', type=float, default=1.0)
    parser.add_argument('--worker-batch', type=int, default=0,
                        help='Max workers running at once (0 = all at once)')

    args = parser.parse_args()

    generate_cicdos2019_attacks(
        args.output, args.packets, args.attack_type, args.intensity,
        args.src_mac, args.dst_mac, args.attacker_range, args.target_ip,
        args.attackers, args.speedup, args.workers, args.worker_batch
    )

    return 0


if __name__ == '__main__':
    exit(main())
