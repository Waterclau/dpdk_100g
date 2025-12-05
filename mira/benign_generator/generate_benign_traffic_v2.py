#!/usr/bin/env python3
"""
MIRA Benign Traffic Generator v2.0 - ML-Enhanced

Generates realistic benign network traffic with temporal variations for ML training.
Features time-varying patterns, jitter, and realistic traffic phases.

Key improvements over v1:
- Temporal phases (HTTP bursts, DNS bursts, SSH sessions, UDP light)
- Inter-packet jitter (realistic timing)
- Variable packet sizes with randomness
- Traffic intensity variations (peak/low periods)
- Better mix for ML feature diversity

Usage:
    python3 generate_benign_traffic_v2.py --output benign_10M.pcap --packets 10000000

Author: MIRA - ML-Enhanced Traffic Generation
"""

import argparse
import random
import struct
import time
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
             TCP(sport=80, dport=sport, flags='SA', seq=seq_server, ack=seq_client + 1)
    packets.append(synack)

    # TCP ACK
    ack = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=80, flags='A', seq=seq_client + 1, ack=seq_server + 1)
    packets.append(ack)

    # HTTP GET request
    http_req = f"GET {path} HTTP/1.1\r\nHost: server.local\r\n" \
               f"User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n"
    req = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=80, flags='PA', seq=seq_client + 1, ack=seq_server + 1) / \
          Raw(load=http_req.encode())
    packets.append(req)

    # HTTP response with variable size (phase-dependent)
    base_response_size = 800 if phase.name == "HTTP Peak" else 400
    response_size = add_size_jitter(base_response_size, 0.3)
    response_size = max(200, min(1200, response_size))  # Clamp to safe range

    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(response_size).encode() + \
                b"\r\nContent-Type: text/html\r\n\r\n" + \
                bytes([random.randint(0, 255) for _ in range(response_size)])

    resp = Ether(src=src_mac, dst=dst_mac) / \
           IP(src=dst_ip, dst=src_ip) / \
           TCP(sport=80, dport=sport, flags='PA', seq=seq_server + 1,
               ack=seq_client + 1 + len(http_req)) / \
           Raw(load=http_resp)
    packets.append(resp)

    # TCP ACK
    ack2 = Ether(src=src_mac, dst=dst_mac) / \
           IP(src=src_ip, dst=dst_ip) / \
           TCP(sport=sport, dport=80, flags='A',
               seq=seq_client + 1 + len(http_req), ack=seq_server + 1 + len(http_resp))
    packets.append(ack2)

    # TCP FIN (client closes)
    fin = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=80, flags='FA',
              seq=seq_client + 1 + len(http_req), ack=seq_server + 1 + len(http_resp))
    packets.append(fin)

    # TCP FIN-ACK (server closes)
    finack = Ether(src=src_mac, dst=dst_mac) / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=80, dport=sport, flags='FA',
                 seq=seq_server + 1 + len(http_resp), ack=seq_client + 2 + len(http_req))
    packets.append(finack)

    # Final ACK
    final_ack = Ether(src=src_mac, dst=dst_mac) / \
                IP(src=src_ip, dst=dst_ip) / \
                TCP(sport=sport, dport=80, flags='A',
                    seq=seq_client + 2 + len(http_req), ack=seq_server + 2 + len(http_resp))
    packets.append(final_ack)

    return packets


def generate_dns_query(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate DNS query + response"""
    packets = []

    domains = ['example.com', 'server.local', 'api.service.io', 'cdn.assets.net',
               'auth.domain.com', 'data.cloud.com', 'mail.google.com', 'www.github.com',
               'static.cloudfront.net', 'images.unsplash.com']
    domain = random.choice(domains)

    sport = random.randint(49152, 65535)

    # DNS query
    query = Ether(src=src_mac, dst=dst_mac) / \
            IP(src=src_ip, dst=dst_ip) / \
            UDP(sport=sport, dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=domain))
    packets.append(query)

    # DNS response (sometimes multiple answers for realism)
    num_answers = 1 if random.random() > 0.3 else random.randint(2, 4)
    answers = [DNSRR(rrname=domain, ttl=300, rdata=f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}')
               for _ in range(num_answers)]

    response = Ether(src=src_mac, dst=dst_mac) / \
               IP(src=dst_ip, dst=src_ip) / \
               UDP(sport=53, dport=sport) / \
               DNS(id=query[DNS].id, qr=1, aa=1, qd=query[DNS].qd, an=answers[0] if len(answers) == 1 else None)
    packets.append(response)

    return packets


def generate_ssh_traffic(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate SSH connection simulation (longer sessions in SSH phase)"""
    packets = []

    sport = random.randint(49152, 65535)
    seq_client = random.randint(1000, 4000000000)
    seq_server = random.randint(1000, 4000000000)

    # TCP handshake
    syn = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=22, flags='S', seq=seq_client)
    packets.append(syn)

    synack = Ether(src=src_mac, dst=dst_mac) / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=22, dport=sport, flags='SA', seq=seq_server, ack=seq_client + 1)
    packets.append(synack)

    ack = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=22, flags='A', seq=seq_client + 1, ack=seq_server + 1)
    packets.append(ack)

    # SSH data exchange (more packets during SSH Stable phase)
    num_exchanges = random.randint(5, 12) if phase.name == "SSH Stable" else random.randint(3, 6)

    for _ in range(num_exchanges):
        data_size = add_size_jitter(250, 0.4)
        data_size = max(50, min(500, data_size))
        data = bytes([random.randint(0, 255) for _ in range(data_size)])

        direction = random.choice(['client', 'server'])
        if direction == 'client':
            pkt = Ether(src=src_mac, dst=dst_mac) / \
                  IP(src=src_ip, dst=dst_ip) / \
                  TCP(sport=sport, dport=22, flags='PA') / \
                  Raw(load=data)
        else:
            pkt = Ether(src=src_mac, dst=dst_mac) / \
                  IP(src=dst_ip, dst=src_ip) / \
                  TCP(sport=22, dport=sport, flags='PA') / \
                  Raw(load=data)
        packets.append(pkt)

    return packets


def generate_icmp_ping(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate ICMP echo request + reply"""
    packets = []

    ping_id = random.randint(1, 65535)
    ping_seq = random.randint(1, 100)
    payload_size = add_size_jitter(56, 0.1)
    payload_size = max(32, min(128, payload_size))

    # Echo request
    req = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          ICMP(type=8, code=0, id=ping_id, seq=ping_seq) / \
          Raw(load=bytes([random.randint(0, 255) for _ in range(payload_size)]))
    packets.append(req)

    # Echo reply
    reply = Ether(src=src_mac, dst=dst_mac) / \
            IP(src=dst_ip, dst=src_ip) / \
            ICMP(type=0, code=0, id=ping_id, seq=ping_seq) / \
            Raw(load=req[Raw].load)
    packets.append(reply)

    return packets


def generate_background_udp(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate background UDP traffic"""
    packets = []

    # Random UDP ports (NTP, SNMP, mDNS, custom services)
    ports = [123, 161, 1900, 5353, 8888, 9000, 10001, 12345]

    # More UDP packets during UDP Light phase
    num_packets = random.randint(3, 7) if phase.name == "UDP Light" else random.randint(2, 4)

    for _ in range(num_packets):
        port = random.choice(ports)
        data_size = add_size_jitter(150, 0.5)
        data_size = max(50, min(400, data_size))

        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              UDP(sport=random.randint(49152, 65535), dport=port) / \
              Raw(load=bytes([random.randint(0, 255) for _ in range(data_size)]))
        packets.append(pkt)

    return packets


# ============================================================================
# Main Generation Function with Temporal Phases
# ============================================================================

def generate_benign_traffic(output_file, num_packets, src_mac, dst_mac,
                            client_range, server_ip, num_clients=500, speedup=1):
    """
    Generate benign traffic PCAP with temporal phases and realistic variations

    Args:
        output_file: Output pcap file path
        num_packets: Total number of packets to generate
        src_mac: Source MAC address
        dst_mac: Destination MAC address
        client_range: Client IP range (e.g., "192.168.1.0/24")
        server_ip: Server IP address
        num_clients: Number of simulated client IPs
        speedup: Timestamp compression factor (e.g., 50 = 50x faster)
    """

    print("=" * 80)
    print("MIRA Benign Traffic Generator v2.0 - ML-Enhanced")
    print("=" * 80)
    print(f"Target packets: {num_packets:,}")
    print(f"Output file: {output_file}")
    print(f"Client IP range: {client_range}")
    print(f"Server IP: {server_ip}")
    print(f"Number of clients: {num_clients}")
    print("")

    # Print phase information
    print("Traffic Phases:")
    for i, phase in enumerate(TRAFFIC_PHASES, 1):
        phase_packets = int(num_packets * phase.duration_pct / 100)
        print(f"  {i}. {phase.name:15s} - {phase.duration_pct:2d}% ({phase_packets:,} pkts) "
              f"- Intensity: {phase.intensity_multiplier:.1f}x, Jitter: {phase.jitter_ms}ms")
    print("")

    # Parse client IP range
    base_ip = client_range.split('/')[0]
    ip_parts = base_ip.split('.')
    base_ip_int = (int(ip_parts[0]) << 24) | (int(ip_parts[1]) << 16) | \
                  (int(ip_parts[2]) << 8) | int(ip_parts[3])

    # Generate client IPs
    client_ips = []
    for i in range(num_clients):
        client_ip_int = base_ip_int + (i % 256)
        client_ip = f"{(client_ip_int >> 24) & 0xFF}.{(client_ip_int >> 16) & 0xFF}." \
                   f"{(client_ip_int >> 8) & 0xFF}.{client_ip_int & 0xFF}"
        client_ips.append(client_ip)

    packets = []
    current_count = 0
    packets_per_update = max(1, num_packets // 100)  # Update every 1%

    # Initialize timestamp tracking
    current_timestamp = time.time()
    base_pkt_interval = 0.00003  # ~30 microseconds between packets (baseline)

    print("Starting packet generation with temporal phases...")
    print("")

    # Generate traffic phase by phase
    for phase_idx, phase in enumerate(TRAFFIC_PHASES):
        phase_target = int(num_packets * phase.duration_pct / 100)
        phase_start = current_count
        phase_distribution = phase.get_traffic_distribution()

        print(f"Phase {phase_idx + 1}/{len(TRAFFIC_PHASES)}: {phase.name} "
              f"(target: {phase_target:,} packets)")

        while current_count - phase_start < phase_target:
            # Progress update
            if current_count > 0 and current_count % packets_per_update == 0:
                percent = min(100, current_count * 100 // num_packets)
                print(f"  Progress: {current_count:,}/{num_packets:,} ({percent}%)", flush=True)

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

                # Adjust interval based on phase intensity (higher intensity = tighter spacing)
                interval = base_pkt_interval / phase.intensity_multiplier

                current_timestamp += interval + jitter_seconds
                pkt.time = current_timestamp

            packets.extend(flow_packets)
            current_count += len(flow_packets)

            # Stop if we've reached target
            if current_count >= num_packets:
                packets = packets[:num_packets]
                break

        print(f"  Phase {phase.name} complete: {current_count - phase_start:,} packets generated")
        print("")

    print(f"Total packets generated: {len(packets):,}")

    return packets  # Return packets list for potential timestamp compression


def apply_timestamp_compression(packets, speedup_factor, output_file):
    """
    Compress timestamps by speedup_factor while maintaining temporal phases.

    Args:
        packets: List of Scapy packets with timestamps
        speedup_factor: Compression factor (e.g., 50 = 50x faster)
        output_file: Output PCAP filename
    """
    if speedup_factor <= 1:
        # No compression needed
        print(f"Writing packets to {output_file}...")
        wrpcap(output_file, packets)
        return

    print(f"\n[TIMESTAMP COMPRESSION] Applying {speedup_factor}× speedup...")
    print(f"Original timeline will be compressed by factor {speedup_factor}")

    # Get first packet timestamp as reference
    if len(packets) == 0:
        return

    # Scapy packets have .time attribute (float timestamp)
    first_time = packets[0].time

    # Compress all timestamps relative to first packet
    compressed_count = 0
    for pkt in packets:
        original_time = pkt.time
        delta_from_start = original_time - first_time

        # Compress the delta
        compressed_delta = delta_from_start / speedup_factor

        # Set new timestamp
        pkt.time = first_time + compressed_delta
        compressed_count += 1

        if compressed_count % 1000000 == 0:
            print(f"  Compressed {compressed_count:,} timestamps...")

    # Calculate timing statistics
    original_duration = packets[-1].time - packets[0].time
    compressed_duration = original_duration / speedup_factor

    print(f"\n[TIMESTAMP COMPRESSION] Complete:")
    print(f"  Original duration:    {original_duration:.2f} seconds")
    print(f"  Compressed duration:  {compressed_duration:.2f} seconds")
    print(f"  Speedup achieved:     {speedup_factor}×")
    print(f"  Phases preserved:     ✓ Yes (just faster)")
    print("")

    # Write compressed PCAP
    print(f"Writing compressed PCAP to {output_file}...")
    wrpcap(output_file, packets)

    # Calculate file size
    import os
    file_size = os.path.getsize(output_file)
    print(f"File size: {file_size / (1024*1024):.2f} MB")
    print("")


def generate_and_save_benign_traffic(output_file, num_packets, src_mac, dst_mac,
                                      client_range, server_ip, num_clients, speedup):
    """
    Wrapper function that generates traffic and applies timestamp compression.

    Args:
        output_file: Output PCAP filename
        num_packets: Total packets to generate
        src_mac: Source MAC address
        dst_mac: Destination MAC address
        client_range: Client IP range
        server_ip: Server IP
        num_clients: Number of client IPs
        speedup: Timestamp compression factor
    """
    # Generate packets with realistic timestamps
    packets = generate_benign_traffic(
        output_file, num_packets, src_mac, dst_mac,
        client_range, server_ip, num_clients, speedup
    )

    # Apply timestamp compression if requested
    apply_timestamp_compression(packets, speedup, output_file)

    # Print statistics
    print("\nTraffic Statistics:")
    http_count = sum(1 for p in packets if TCP in p and (p[TCP].dport == 80 or p[TCP].sport == 80))
    dns_count = sum(1 for p in packets if DNS in p)
    ssh_count = sum(1 for p in packets if TCP in p and (p[TCP].dport == 22 or p[TCP].sport == 22))
    icmp_count = sum(1 for p in packets if ICMP in p)
    udp_count = sum(1 for p in packets if UDP in p and DNS not in p)

    print(f"  HTTP:  {http_count:8,} packets ({http_count*100//len(packets):2d}%)")
    print(f"  DNS:   {dns_count:8,} packets ({dns_count*100//len(packets):2d}%)")
    print(f"  SSH:   {ssh_count:8,} packets ({ssh_count*100//len(packets):2d}%)")
    print(f"  ICMP:  {icmp_count:8,} packets ({icmp_count*100//len(packets):2d}%)")
    print(f"  UDP:   {udp_count:8,} packets ({udp_count*100//len(packets):2d}%)")
    print("")
    print("=" * 80)
    print("Generation complete!")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Generate benign traffic PCAP v2.0 - ML-Enhanced with temporal phases',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Traffic Phases (automatic):
  1. HTTP Peak    (33%%) - High HTTP traffic with moderate DNS
  2. DNS Burst    (20%%) - DNS-heavy period with bursts
  3. SSH Stable   (27%%) - Long SSH sessions with low traffic
  4. UDP Light    (20%%) - Background UDP with high jitter

Features:
  - Temporal traffic variations (realistic patterns)
  - Inter-packet jitter (not constant timing)
  - Variable packet sizes (realistic distributions)
  - Traffic intensity changes (peak/low periods)
  - Timestamp compression (--speedup for faster replay)
  - Better ML training diversity

Examples:
  # Normal speed (300s timeline):
  python3 generate_benign_traffic_v2.py --packets 10000000 --output benign_10M.pcap

  # 50x faster (300s → 6s timeline, phases preserved):
  python3 generate_benign_traffic_v2.py --packets 10000000 --speedup 50 --output benign_10M_fast.pcap
        """
    )

    parser.add_argument('--output', '-o', default='benign_10M_v2.pcap',
                       help='Output pcap file (default: benign_10M_v2.pcap)')
    parser.add_argument('--packets', '-n', type=int, default=10000000,
                       help='Number of packets to generate (default: 10000000)')
    parser.add_argument('--src-mac', default='00:00:00:00:00:01',
                       help='Source MAC address (default: 00:00:00:00:00:01)')
    parser.add_argument('--dst-mac', default='0c:42:a1:dd:5b:28',
                       help='Destination MAC address (default: 0c:42:a1:dd:5b:28)')
    parser.add_argument('--client-range', default='192.168.1.0/24',
                       help='Client IP range (default: 192.168.1.0/24)')
    parser.add_argument('--server-ip', default='10.0.0.1',
                       help='Server IP address (default: 10.0.0.1)')
    parser.add_argument('--clients', type=int, default=500,
                       help='Number of client IPs (default: 500)')
    parser.add_argument('--speedup', '-s', type=float, default=1.0,
                       help='Timestamp compression factor (e.g., 50 = 50x faster timeline, default: 1 = no compression)')

    args = parser.parse_args()

    # Validate speedup
    if args.speedup < 1.0:
        print("Error: --speedup must be >= 1.0")
        return -1

    generate_and_save_benign_traffic(
        args.output,
        args.packets,
        args.src_mac,
        args.dst_mac,
        args.client_range,
        args.server_ip,
        args.clients,
        args.speedup
    )


if __name__ == '__main__':
    main()
