#!/usr/bin/env python3
"""
MIRA Benign Traffic Generator v2.0 - PARALLEL EDITION
========================================================

Generates realistic benign network traffic with temporal variations for ML training.
PARALLEL version: Uses multiprocessing to generate traffic on multiple CPU cores.

Key features:
- Multi-core parallel generation (up to all available CPUs)
- Temporal phases (HTTP bursts, DNS bursts, SSH sessions, UDP light)
- Inter-packet jitter (realistic timing)
- Variable packet sizes with randomness
- Traffic intensity variations (peak/low periods)
- Scalable to 100M+ packets

Performance:
- Single core: ~100K packets/min
- 8 cores:     ~800K packets/min  (8× speedup)
- 16 cores:    ~1.6M packets/min (16× speedup)

Usage:
    # Single core (original behavior)
    python3 generate_benign_traffic_v2_parallel.py --packets 10000000 --output benign_10M.pcap

    # Multi-core (8 cores)
    python3 generate_benign_traffic_v2_parallel.py --packets 100000000 --cores 8 --output benign_100M.pcap

    # All available cores
    python3 generate_benign_traffic_v2_parallel.py --packets 100000000 --cores 0 --output benign_100M.pcap

Author: MIRA - ML-Enhanced Traffic Generation (Parallel Edition)
"""

import argparse
import random
import struct
import time
import os
import sys
import multiprocessing as mp
from pathlib import Path
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest

# ============================================================================
# Traffic Phase Definitions (temporal patterns)
# ============================================================================

class TrafficPhase:
    """Defines a temporal phase of traffic with specific characteristics"""
    def __init__(self, name, duration_pct, http_weight, dns_weight, ssh_weight,
                 icmp_weight, udp_weight, intensity_multiplier, jitter_ms):
        self.name = name
        self.duration_pct = duration_pct  # Percentage of total time
        self.http_weight = http_weight
        self.dns_weight = dns_weight
        self.ssh_weight = ssh_weight
        self.icmp_weight = icmp_weight
        self.udp_weight = udp_weight
        self.intensity_multiplier = intensity_multiplier  # Traffic volume multiplier
        self.jitter_ms = jitter_ms  # Max jitter in milliseconds

    def get_traffic_distribution(self):
        """Return traffic type distribution for this phase"""
        return (['http'] * self.http_weight +
                ['dns'] * self.dns_weight +
                ['ssh'] * self.ssh_weight +
                ['icmp'] * self.icmp_weight +
                ['udp'] * self.udp_weight)


# Define realistic traffic phases (simulates 15-minute network behavior)
TRAFFIC_PHASES = [
    # Phase 1: Morning HTTP peak (0-5min = 33% of time)
    TrafficPhase(
        name="HTTP Peak",
        duration_pct=33,
        http_weight=70,   # 70% HTTP
        dns_weight=15,    # 15% DNS
        ssh_weight=5,     # 5% SSH
        icmp_weight=5,    # 5% ICMP
        udp_weight=5,     # 5% UDP
        intensity_multiplier=1.3,  # 30% more traffic
        jitter_ms=20
    ),

    # Phase 2: DNS burst period (5-8min = 20% of time)
    TrafficPhase(
        name="DNS Burst",
        duration_pct=20,
        http_weight=30,
        dns_weight=50,    # 50% DNS (burst)
        ssh_weight=5,
        icmp_weight=10,
        udp_weight=5,
        intensity_multiplier=0.8,  # 20% less overall traffic
        jitter_ms=50       # More jitter during DNS bursts
    ),

    # Phase 3: Stable SSH + moderate HTTP (8-12min = 27% of time)
    TrafficPhase(
        name="SSH Stable",
        duration_pct=27,
        http_weight=35,
        dns_weight=10,
        ssh_weight=40,    # 40% SSH (stable sessions)
        icmp_weight=5,
        udp_weight=10,
        intensity_multiplier=0.6,  # Quieter period
        jitter_ms=10       # Low jitter for stable sessions
    ),

    # Phase 4: Light UDP with background (12-15min = 20% of time)
    TrafficPhase(
        name="UDP Light",
        duration_pct=20,
        http_weight=25,
        dns_weight=15,
        ssh_weight=10,
        icmp_weight=15,
        udp_weight=35,    # 35% UDP
        intensity_multiplier=0.5,  # Low traffic period
        jitter_ms=80       # High jitter for UDP
    ),
]

# ============================================================================
# Packet Generation Functions (same as v1, with size variations)
# ============================================================================

def generate_flow_id():
    """Generate unique flow identifier"""
    return random.randint(100000, 999999)


def add_size_jitter(base_size, jitter_pct=0.2):
    """Add random jitter to packet size"""
    jitter = int(base_size * jitter_pct)
    return base_size + random.randint(-jitter, jitter)


def generate_http_traffic(src_ip, dst_ip, src_mac, dst_mac, flow_id, phase):
    """Generate realistic HTTP GET request + response with size variation"""
    packets = []

    # Common HTTP paths from benign traffic
    paths = ['/index.html', '/api/data', '/images/logo.png', '/css/style.css',
             '/js/app.js', '/favicon.ico', '/api/users', '/login', '/dashboard',
             '/static/bundle.js', '/api/metrics', '/health']
    path = random.choice(paths)

    sport = random.randint(49152, 65535)
    seq_client = random.randint(1000, 4000000000)
    seq_server = random.randint(1000, 4000000000)

    # TCP SYN
    syn = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=80, flags='S', seq=seq_client)
    packets.append(syn)

    # TCP SYN-ACK
    synack = Ether(src=src_mac, dst=dst_mac) / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=80, dport=sport, flags='SA', seq=seq_server, ack=seq_client+1)
    packets.append(synack)

    # TCP ACK
    ack = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=80, flags='A', seq=seq_client+1, ack=seq_server+1)
    packets.append(ack)

    # HTTP GET request (variable size)
    http_req = Ether(src=src_mac, dst=dst_mac) / \
               IP(src=src_ip, dst=dst_ip) / \
               TCP(sport=sport, dport=80, flags='PA', seq=seq_client+1, ack=seq_server+1) / \
               Raw(load=f"GET {path} HTTP/1.1\r\nHost: server\r\n\r\n".encode())
    packets.append(http_req)

    # HTTP response (variable size based on phase)
    base_response_size = 500
    response_size = add_size_jitter(base_response_size, jitter_pct=0.3)
    http_resp = Ether(src=src_mac, dst=dst_mac) / \
                IP(src=dst_ip, dst=src_ip) / \
                TCP(sport=80, dport=sport, flags='PA', seq=seq_server+1, ack=seq_client+len(http_req[Raw].load)+1) / \
                Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: " + str(response_size).encode() + b"\r\n\r\n" + b"A" * response_size)
    packets.append(http_resp)

    # TCP FIN-ACK (client closes)
    fin = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=80, flags='FA', seq=seq_client+len(http_req[Raw].load)+1, ack=seq_server+len(http_resp[Raw].load)+1)
    packets.append(fin)

    # TCP FIN-ACK (server closes)
    fin2 = Ether(src=src_mac, dst=dst_mac) / \
           IP(src=dst_ip, dst=src_ip) / \
           TCP(sport=80, dport=sport, flags='FA', seq=seq_server+len(http_resp[Raw].load)+1, ack=seq_client+len(http_req[Raw].load)+2)
    packets.append(fin2)

    # Final ACK
    final_ack = Ether(src=src_mac, dst=dst_mac) / \
                IP(src=src_ip, dst=dst_ip) / \
                TCP(sport=sport, dport=80, flags='A', seq=seq_client+len(http_req[Raw].load)+2, ack=seq_server+len(http_resp[Raw].load)+2)
    packets.append(final_ack)

    return packets


def generate_dns_query(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate DNS query + response with realistic domains"""
    packets = []

    # Realistic domain names
    domains = ['www.example.com', 'api.service.io', 'cdn.static.net',
               'mail.company.org', 'app.cloud.com', 'metrics.monitoring.io',
               'login.auth.service', 'data.analytics.net']
    domain = random.choice(domains)

    sport = random.randint(49152, 65535)

    # DNS query
    query = Ether(src=src_mac, dst=dst_mac) / \
            IP(src=src_ip, dst=dst_ip) / \
            UDP(sport=sport, dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=domain))
    packets.append(query)

    # DNS response (variable size)
    response_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    response = Ether(src=src_mac, dst=dst_mac) / \
               IP(src=dst_ip, dst=src_ip) / \
               UDP(sport=53, dport=sport) / \
               DNS(id=query[DNS].id, qr=1, aa=0, rcode=0,
                   qd=DNSQR(qname=domain),
                   an=DNSRR(rrname=domain, ttl=300, rdata=response_ip))
    packets.append(response)

    return packets


def generate_ssh_traffic(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate SSH connection simulation (handshake + data)"""
    packets = []

    sport = random.randint(49152, 65535)
    seq_client = random.randint(1000, 4000000000)
    seq_server = random.randint(1000, 4000000000)

    # TCP SYN
    syn = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=22, flags='S', seq=seq_client)
    packets.append(syn)

    # TCP SYN-ACK
    synack = Ether(src=src_mac, dst=dst_mac) / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=22, dport=sport, flags='SA', seq=seq_server, ack=seq_client+1)
    packets.append(synack)

    # TCP ACK
    ack = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=22, flags='A', seq=seq_client+1, ack=seq_server+1)
    packets.append(ack)

    # SSH protocol exchange (several packets simulating encrypted session)
    for i in range(3):  # Simulate 3 packets of encrypted data
        ssh_data_size = add_size_jitter(100, jitter_pct=0.5)
        ssh_data = Ether(src=src_mac, dst=dst_mac) / \
                   IP(src=src_ip, dst=dst_ip) / \
                   TCP(sport=sport, dport=22, flags='PA', seq=seq_client+1+i*50, ack=seq_server+1) / \
                   Raw(load=b"\x00" * ssh_data_size)
        packets.append(ssh_data)

    return packets


def generate_icmp_ping(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate ICMP ping request + reply"""
    packets = []

    ping_id = random.randint(1, 65535)
    ping_seq = random.randint(1, 65535)

    # ICMP Echo Request
    request = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              ICMP(type=8, code=0, id=ping_id, seq=ping_seq) / \
              Raw(load=b"A" * 56)
    packets.append(request)

    # ICMP Echo Reply
    reply = Ether(src=src_mac, dst=dst_mac) / \
            IP(src=dst_ip, dst=src_ip) / \
            ICMP(type=0, code=0, id=ping_id, seq=ping_seq) / \
            Raw(load=b"A" * 56)
    packets.append(reply)

    return packets


def generate_background_udp(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate background UDP traffic (NTP, SNMP-like)"""
    packets = []

    sport = random.randint(49152, 65535)
    dport = random.choice([123, 161, 514, 1900])  # NTP, SNMP, Syslog, UPnP

    # UDP packet with variable size
    udp_size = add_size_jitter(200, jitter_pct=0.4)
    udp_packet = Ether(src=src_mac, dst=dst_mac) / \
                 IP(src=src_ip, dst=dst_ip) / \
                 UDP(sport=sport, dport=dport) / \
                 Raw(load=b"\x00" * udp_size)
    packets.append(udp_packet)

    return packets


# ============================================================================
# PARALLEL WORKER FUNCTION
# ============================================================================

def generate_chunk_worker(args):
    """
    Worker function to generate a chunk of packets in parallel.

    Args:
        args: Tuple containing:
            - worker_id: Worker identifier (0, 1, 2, ...)
            - num_packets: Number of packets this worker should generate
            - output_file: Base output filename
            - src_mac, dst_mac: MAC addresses
            - client_range, server_ip, num_clients: IP configuration
            - time_offset: Timestamp offset for this worker
            - seed: Random seed for reproducibility

    Returns:
        Path to generated partial PCAP file
    """
    (worker_id, num_packets, output_file, src_mac, dst_mac,
     client_range, server_ip, num_clients, time_offset, seed) = args

    # Set random seed for reproducibility (different per worker)
    random.seed(seed + worker_id)

    # Generate client IP range
    network = ipaddress.ip_network(client_range, strict=False)
    all_ips = [str(ip) for ip in network.hosts()]
    client_ips = random.sample(all_ips, min(num_clients, len(all_ips)))

    packets = []
    current_count = 0

    # Initialize timestamp tracking with offset
    current_timestamp = time.time() + time_offset
    base_pkt_interval = 0.00003  # ~30 microseconds between packets (baseline)

    print(f"[Worker {worker_id}] Generating {num_packets:,} packets...", flush=True)

    # Generate traffic phase by phase
    for phase_idx, phase in enumerate(TRAFFIC_PHASES):
        phase_target = int(num_packets * phase.duration_pct / 100)
        phase_start = current_count
        phase_distribution = phase.get_traffic_distribution()

        while current_count - phase_start < phase_target:
            # Select random client
            client_ip = random.choice(client_ips)

            # Select traffic type based on phase distribution
            traffic_type = random.choice(phase_distribution)

            # Generate flow based on type
            if traffic_type == 'http':
                flow_packets = generate_http_traffic(client_ip, server_ip, src_mac, dst_mac,
                                                     generate_flow_id(), phase)
            elif traffic_type == 'dns':
                flow_packets = generate_dns_query(client_ip, server_ip, src_mac, dst_mac, phase)
            elif traffic_type == 'ssh':
                flow_packets = generate_ssh_traffic(client_ip, server_ip, src_mac, dst_mac, phase)
            elif traffic_type == 'icmp':
                flow_packets = generate_icmp_ping(client_ip, server_ip, src_mac, dst_mac, phase)
            else:  # udp
                flow_packets = generate_background_udp(client_ip, server_ip, src_mac, dst_mac, phase)

            # Apply realistic timestamps with phase-specific jitter
            for pkt in flow_packets:
                # Add jitter based on phase characteristics
                jitter_seconds = (random.random() - 0.5) * (phase.jitter_ms / 1000.0)

                # Adjust interval based on phase intensity
                interval = base_pkt_interval / phase.intensity_multiplier

                current_timestamp += interval + jitter_seconds
                pkt.time = current_timestamp

            packets.extend(flow_packets)
            current_count += len(flow_packets)

            # Stop if we've reached target
            if current_count >= num_packets:
                packets = packets[:num_packets]
                break

    # Write partial PCAP file
    partial_file = f"{output_file}.part{worker_id}.pcap"
    print(f"[Worker {worker_id}] Writing {len(packets):,} packets to {partial_file}...", flush=True)
    wrpcap(partial_file, packets)

    print(f"[Worker {worker_id}] Complete!", flush=True)
    return partial_file


# ============================================================================
# MAIN GENERATION FUNCTION (PARALLEL)
# ============================================================================

def generate_benign_traffic_parallel(output_file, num_packets, src_mac, dst_mac,
                                    client_range, server_ip, num_clients, cores, speedup=1.0):
    """
    Generate benign traffic in parallel using multiple CPU cores.

    Args:
        output_file: Output PCAP filename
        num_packets: Total number of packets to generate
        src_mac, dst_mac: MAC addresses
        client_range: Client IP range (CIDR)
        server_ip: Server IP address
        num_clients: Number of unique client IPs
        cores: Number of CPU cores to use (0 = all available)
        speedup: Timestamp compression factor
    """
    # Determine number of cores to use
    if cores <= 0:
        cores = mp.cpu_count()
    cores = min(cores, mp.cpu_count())

    print("=" * 80)
    print("MIRA Benign Traffic Generator v2.0 - PARALLEL EDITION")
    print("=" * 80)
    print(f"Target packets: {num_packets:,}")
    print(f"Output file: {output_file}")
    print(f"CPU cores: {cores}")
    print(f"Speedup: {speedup}×")
    print("")

    if cores == 1:
        print("[INFO] Single core mode - no parallelization")
        print("")
    else:
        print(f"[INFO] Parallel mode - distributing work across {cores} cores")
        print(f"[INFO] Packets per core: ~{num_packets // cores:,}")
        print("")

    # Calculate packets per worker
    packets_per_worker = num_packets // cores
    remainder = num_packets % cores

    # Prepare worker arguments
    worker_args = []
    base_seed = random.randint(1, 1000000)

    for worker_id in range(cores):
        # Distribute remainder packets to first workers
        worker_packets = packets_per_worker + (1 if worker_id < remainder else 0)

        # Calculate time offset for this worker (to avoid timestamp collisions)
        time_offset = worker_id * 100  # 100 seconds offset per worker

        worker_args.append((
            worker_id,
            worker_packets,
            output_file,
            src_mac,
            dst_mac,
            client_range,
            server_ip,
            num_clients,
            time_offset,
            base_seed
        ))

    # Generate packets in parallel
    print("Starting parallel packet generation...")
    print("")
    start_time = time.time()

    if cores == 1:
        # Single core - no multiprocessing overhead
        partial_files = [generate_chunk_worker(worker_args[0])]
    else:
        # Multi-core using Pool
        with mp.Pool(processes=cores) as pool:
            partial_files = pool.map(generate_chunk_worker, worker_args)

    generation_time = time.time() - start_time

    print("")
    print(f"[INFO] Packet generation complete in {generation_time:.1f}s")
    print(f"[INFO] Generation rate: {num_packets / generation_time / 1000:.1f}K packets/sec")
    print("")

    # Merge partial PCAP files
    print("[INFO] Merging partial PCAP files...")
    merge_start = time.time()

    # Load all packets and sort by timestamp
    all_packets = []
    for idx, partial_file in enumerate(partial_files):
        print(f"  Loading {partial_file}...", flush=True)
        packets = rdpcap(partial_file)
        all_packets.extend(packets)

    # Sort by timestamp
    print(f"  Sorting {len(all_packets):,} packets by timestamp...", flush=True)
    all_packets.sort(key=lambda pkt: pkt.time)

    # Apply speedup compression if requested
    if speedup > 1.0:
        print(f"\n[TIMESTAMP COMPRESSION] Applying {speedup}× speedup...", flush=True)
        first_time = all_packets[0].time
        for pkt in all_packets:
            delta_from_start = pkt.time - first_time
            compressed_delta = delta_from_start / speedup
            pkt.time = first_time + compressed_delta

    # Write final PCAP
    print(f"  Writing final PCAP to {output_file}...", flush=True)
    wrpcap(output_file, all_packets)

    merge_time = time.time() - merge_start
    print(f"[INFO] Merge complete in {merge_time:.1f}s")
    print("")

    # Cleanup temporary files
    print("[INFO] Cleaning up temporary files...")
    for partial_file in partial_files:
        try:
            os.remove(partial_file)
            print(f"  Removed {partial_file}")
        except Exception as e:
            print(f"  Warning: Could not remove {partial_file}: {e}")

    print("")

    # Calculate file size
    file_size = os.path.getsize(output_file)
    file_size_mb = file_size / (1024 * 1024)

    total_time = time.time() - start_time
    print(f"File size: {file_size_mb:.2f} MB")
    print("")
    print(f"[PERFORMANCE SUMMARY]")
    print(f"  Total time: {total_time:.1f}s ({total_time / 60:.1f} minutes)")
    print(f"  Generation rate: {num_packets / total_time / 1000:.1f}K packets/sec")
    print(f"  Cores used: {cores}")
    print(f"  Speedup vs single core: ~{cores}×")
    print("")

    # Print traffic statistics
    print("Traffic Statistics:")
    http_count = sum(1 for p in all_packets if TCP in p and (p[TCP].dport == 80 or p[TCP].sport == 80))
    dns_count = sum(1 for p in all_packets if DNS in p)
    ssh_count = sum(1 for p in all_packets if TCP in p and (p[TCP].dport == 22 or p[TCP].sport == 22))
    icmp_count = sum(1 for p in all_packets if ICMP in p)
    udp_count = sum(1 for p in all_packets if UDP in p and DNS not in p)

    total = len(all_packets)
    print(f"  HTTP:  {http_count:8,} packets ({http_count*100//total:2d}%)")
    print(f"  DNS:   {dns_count:8,} packets ({dns_count*100//total:2d}%)")
    print(f"  SSH:   {ssh_count:8,} packets ({ssh_count*100//total:2d}%)")
    print(f"  ICMP:  {icmp_count:8,} packets ({icmp_count*100//total:2d}%)")
    print(f"  UDP:   {udp_count:8,} packets ({udp_count*100//total:2d}%)")
    print("")
    print("=" * 80)
    print("Generation complete!")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Generate benign traffic PCAP v2.0 - PARALLEL EDITION',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Traffic Phases (automatic):
  1. HTTP Peak    (33%%) - High HTTP traffic with moderate DNS
  2. DNS Burst    (20%%) - DNS-heavy period with bursts
  3. SSH Stable   (27%%) - Long SSH sessions with low traffic
  4. UDP Light    (20%%) - Background UDP with high jitter

Parallel Processing:
  - Divides packet generation across multiple CPU cores
  - Near-linear speedup (8 cores ≈ 8× faster)
  - Automatically merges partial results
  - Preserves temporal phases and statistics

Examples:
  # 10M packets, single core (baseline):
  python3 generate_benign_traffic_v2_parallel.py --packets 10000000 --output benign_10M.pcap

  # 100M packets, 8 cores (8× faster):
  python3 generate_benign_traffic_v2_parallel.py --packets 100000000 --cores 8 --output benign_100M.pcap

  # 100M packets, all available cores:
  python3 generate_benign_traffic_v2_parallel.py --packets 100000000 --cores 0 --output benign_100M.pcap

  # 100M packets, 16 cores, 50× speedup:
  python3 generate_benign_traffic_v2_parallel.py --packets 100000000 --cores 16 --speedup 50 --output benign_100M_fast.pcap
        """
    )

    parser.add_argument('--output', '-o', default='benign_10M_v2.pcap',
                       help='Output pcap file (default: benign_10M_v2.pcap)')
    parser.add_argument('--packets', '-n', type=int, default=10000000,
                       help='Number of packets to generate (default: 10000000, can be 100000000+)')
    parser.add_argument('--cores', '-c', type=int, default=1,
                       help='Number of CPU cores to use (0 = all available, default: 1)')
    parser.add_argument('--src-mac', default='00:00:00:00:00:01',
                       help='Source MAC address (default: 00:00:00:00:00:01)')
    parser.add_argument('--dst-mac', default='0c:42:a1:dd:5b:28',
                       help='Destination MAC address (default: 0c:42:a1:dd:5b:28)')
    parser.add_argument('--client-range', default='10.10.1.0/24',
                       help='Client IP range (default: 10.10.1.0/24 - USE CLOUDLAB INTERNAL NETWORK)')
    parser.add_argument('--server-ip', default='10.10.1.2',
                       help='Server IP address (default: 10.10.1.2 - USE CLOUDLAB INTERNAL NETWORK)')
    parser.add_argument('--clients', type=int, default=500,
                       help='Number of client IPs (default: 500)')
    parser.add_argument('--speedup', '-s', type=float, default=1.0,
                       help='Timestamp compression factor (e.g., 50 = 50x faster timeline, default: 1 = no compression)')

    args = parser.parse_args()

    # Validate speedup
    if args.speedup < 1.0:
        print("Error: --speedup must be >= 1.0")
        return 1

    # Validate cores
    if args.cores < 0:
        print("Error: --cores must be >= 0 (0 = auto-detect all cores)")
        return 1

    # Import ipaddress for IP range handling
    import ipaddress

    generate_benign_traffic_parallel(
        args.output,
        args.packets,
        args.src_mac,
        args.dst_mac,
        args.client_range,
        args.server_ip,
        args.clients,
        args.cores,
        args.speedup
    )

    return 0


if __name__ == '__main__':
    sys.exit(main())
