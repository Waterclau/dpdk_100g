#!/usr/bin/env python3
"""
MIRA Mirai-Style DDoS Attack Generator

Generates Mirai-style DDoS attacks for MULTI-LF (2025) comparison:
- UDP Flood
- SYN Flood
- HTTP Flood

Replicates attack patterns similar to CICDDoS2019 Mirai attacks.

Usage:
    python3 generate_mirai_attacks.py --output attack_mirai_5M.pcap --packets 5000000 --attack-type udp

Author: MIRA - MULTI-LF Replication and Assessment
"""

import argparse
import random
import struct
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

def generate_udp_flood(src_ip, dst_ip, src_mac, dst_mac, num_packets):
    """
    Generate UDP flood attack (classic Mirai) - SWITCH-SAFE VERSION

    Characteristics:
    - Random source ports
    - Target DNS port (53) primarily - looks more legitimate
    - SMALL fixed payloads (to avoid switch DoS protection)
    - High packet rate
    """
    packets = []

    # DNS query payloads (realistic, small, won't trigger switch filters)
    dns_queries = [
        b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01',
        b'\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01',
        b'\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01',
        b'\x00\x04\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x03net\x00\x00\x01\x00\x01',
    ]

    for i in range(num_packets):
        # Mostly DNS (port 53) with realistic queries
        payload = random.choice(dns_queries)

        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              UDP(sport=random.randint(1024, 65535), dport=53) / \
              Raw(load=payload)

        packets.append(pkt)

    return packets

def generate_syn_flood(src_ip, dst_ip, src_mac, dst_mac, num_packets):
    """
    Generate VARIED SYN flood attack (multiple attack vectors, all using TCP SYN)

    Simulates multiple DDoS attack types, but all using SYN packets to pass switch filters:
    - HTTP flood: SYN to port 80/443/8080 (40%)
    - SSH flood: SYN to port 22/2222 (20%)
    - HTTPS flood: SYN to port 443/8443 (20%)
    - Telnet flood: SYN to port 23/2323 (10%)
    - Custom services flood: SYN to ports 3389/5060/8000 (10%)

    All are SYN-only (no handshake) to pass switch, but vary in:
    - Target ports (simulates different attack vectors)
    - Window sizes (simulates different botnet clients)
    - Sequence numbers (randomized)
    - TTL values (simulates geographic distribution)
    """
    packets = []

    # Attack vectors (port groups simulating different DDoS types)
    attack_vectors = [
        # HTTP flood simulation (40%)
        {'ports': [80, 8080, 8000], 'weight': 40, 'name': 'HTTP'},
        # HTTPS flood simulation (20%)
        {'ports': [443, 8443], 'weight': 20, 'name': 'HTTPS'},
        # SSH brute-force flood simulation (20%)
        {'ports': [22, 2222], 'weight': 20, 'name': 'SSH'},
        # Telnet flood simulation (10%)
        {'ports': [23, 2323], 'weight': 10, 'name': 'Telnet'},
        # RDP/SIP flood simulation (10%)
        {'ports': [3389, 5060], 'weight': 10, 'name': 'RDP/SIP'},
    ]

    # Create weighted list for random selection
    attack_list = []
    for vector in attack_vectors:
        attack_list.extend([vector] * vector['weight'])

    # Different window sizes (simulates diverse botnet)
    window_sizes = [8192, 16384, 32768, 65535, 5840, 14600, 29200]

    # TTL values (simulates geographic diversity)
    ttl_values = [64, 128, 255, 32, 60, 120, 200]

    for i in range(num_packets):
        # Select attack vector (weighted random)
        vector = random.choice(attack_list)
        target_port = random.choice(vector['ports'])

        # Vary packet characteristics for realism
        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip, ttl=random.choice(ttl_values)) / \
              TCP(sport=random.randint(1024, 65535),
                  dport=target_port,
                  flags='S',  # SYN flag only (passes switch)
                  seq=random.randint(1000, 4000000000),
                  window=random.choice(window_sizes),
                  options=[('MSS', random.choice([1460, 1380, 1400]))])  # Vary MSS

        packets.append(pkt)

    return packets

def generate_http_flood(src_ip, dst_ip, src_mac, dst_mac, num_packets):
    """
    Generate HTTP GET flood attack (application layer)

    Characteristics:
    - Complete TCP handshake
    - HTTP GET requests with random paths
    - Mimic legitimate requests but at high rate
    - Multiple requests per connection
    """
    packets = []

    # Common paths targeted in HTTP floods
    paths = ['/', '/index.html', '/login', '/api/data', '/search',
             '/admin', '/wp-login.php', '/api/v1/users']

    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'curl/7.68.0',
        'python-requests/2.25.1'
    ]

    # Generate connections (each connection has multiple packets)
    connections_needed = num_packets // 10  # ~10 packets per connection

    for conn_id in range(connections_needed):
        src_port = random.randint(49152, 65535)
        path = random.choice(paths)
        user_agent = random.choice(user_agents)

        # TCP Handshake
        # SYN
        syn = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              TCP(sport=src_port, dport=80, flags='S',
                  seq=random.randint(1000, 4000000000))
        packets.append(syn)

        # SYN-ACK (server response - simulated)
        synack = Ether(src=dst_mac, dst=src_mac) / \
                 IP(src=dst_ip, dst=src_ip) / \
                 TCP(sport=80, dport=src_port, flags='SA',
                     seq=random.randint(1000, 4000000000), ack=syn[TCP].seq + 1)
        packets.append(synack)

        # ACK (complete handshake)
        ack = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              TCP(sport=src_port, dport=80, flags='A',
                  seq=syn[TCP].seq + 1, ack=synack[TCP].seq + 1)
        packets.append(ack)

        # Send multiple HTTP GET requests (flood)
        for req_num in range(random.randint(3, 7)):
            http_req = f"GET {path}?id={req_num} HTTP/1.1\\r\\n" \
                      f"Host: target-server.com\\r\\n" \
                      f"User-Agent: {user_agent}\\r\\n" \
                      f"Accept: */*\\r\\n" \
                      f"Connection: keep-alive\\r\\n\\r\\n"

            req = Ether(src=src_mac, dst=dst_mac) / \
                  IP(src=src_ip, dst=dst_ip) / \
                  TCP(sport=src_port, dport=80, flags='PA',
                      seq=ack[TCP].seq + req_num * 100,
                      ack=synack[TCP].seq + 1) / \
                  Raw(load=http_req.encode())
            packets.append(req)

            # Server response (simulated small response)
            resp = Ether(src=dst_mac, dst=src_mac) / \
                   IP(src=dst_ip, dst=src_ip) / \
                   TCP(sport=80, dport=src_port, flags='PA',
                       seq=synack[TCP].seq + 1 + req_num * 200,
                       ack=req[TCP].seq + len(http_req)) / \
                   Raw(load=b"HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n")
            packets.append(resp)

        # TCP FIN (client closes)
        fin = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              TCP(sport=src_port, dport=80, flags='FA',
                  seq=ack[TCP].seq + 700, ack=synack[TCP].seq + 1000)
        packets.append(fin)

        if len(packets) >= num_packets:
            break

    return packets[:num_packets]

def generate_icmp_flood(src_ip, dst_ip, src_mac, dst_mac, num_packets):
    """
    Generate ICMP flood attack (ping flood) - SWITCH-SAFE VERSION

    Characteristics:
    - ICMP echo requests
    - No replies expected
    - SMALL fixed payloads (64 bytes - standard ping size)
    - High rate
    """
    packets = []

    # Standard ping payload (56 bytes of data + 8 bytes ICMP header = 64 total)
    # Use fixed pattern instead of random to avoid switch detection
    ping_payload = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv'

    for i in range(num_packets):
        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              ICMP(type=8, code=0, id=random.randint(1, 65535), seq=i % 65536) / \
              Raw(load=ping_payload)

        packets.append(pkt)

    return packets

def generate_mirai_attack(output_file, num_packets, attack_type,
                          src_mac, dst_mac, attacker_range, target_ip,
                          num_attackers=200):
    """
    Generate Mirai-style DDoS attack PCAP

    Args:
        output_file: Output pcap file path
        num_packets: Total number of packets to generate
        attack_type: Type of attack ('udp', 'syn', 'http', 'icmp', 'mixed')
        src_mac: Source MAC address
        dst_mac: Destination MAC address
        attacker_range: Attacker IP range (e.g., "203.0.113.0/24")
        target_ip: Target server IP
        num_attackers: Number of attacker IPs (botnet size)
    """

    print(f"\\n{'='*70}")
    print(f"MIRA - Mirai-Style DDoS Attack Generator")
    print(f"{'='*70}")
    print(f"Attack type:      {attack_type.upper()}")
    print(f"Total packets:    {num_packets:,}")
    print(f"Output file:      {output_file}")
    print(f"Attacker range:   {attacker_range}")
    print(f"Target IP:        {target_ip}")
    print(f"Botnet size:      {num_attackers} IPs")
    print(f"{'='*70}\\n")

    # Parse attacker IP range
    base_ip = attacker_range.split('/')[0]
    ip_parts = base_ip.split('.')
    base_ip_int = (int(ip_parts[0]) << 24) | (int(ip_parts[1]) << 16) | \
                  (int(ip_parts[2]) << 8) | int(ip_parts[3])

    # Generate attacker IPs (botnet)
    attacker_ips = []
    for i in range(num_attackers):
        attacker_ip_int = base_ip_int + (i % 256)
        attacker_ip = f"{(attacker_ip_int >> 24) & 0xFF}.{(attacker_ip_int >> 16) & 0xFF}." \
                     f"{(attacker_ip_int >> 8) & 0xFF}.{attacker_ip_int & 0xFF}"
        attacker_ips.append(attacker_ip)

    print(f"Generated {len(attacker_ips)} attacker IPs\\n")

    packets = []
    packets_per_attacker = num_packets // num_attackers
    packets_per_update = num_packets // 100  # Update every 1%

    print(f"Generating attack packets...")
    print("")  # Empty line for visibility

    for idx, attacker_ip in enumerate(attacker_ips):
        # Print progress every 1% or every attacker, whichever is more frequent
        if idx % max(1, num_attackers // 100) == 0 and idx > 0:
            current_packets = len(packets)
            progress = (current_packets * 100) // num_packets if num_packets > 0 else 0
            print(f"  Progress: {current_packets:,}/{num_packets:,} ({progress}%) - Attacker {idx}/{num_attackers}", flush=True)

        # Generate packets from this attacker
        if attack_type == 'udp':
            attacker_packets = generate_udp_flood(attacker_ip, target_ip, src_mac, dst_mac,
                                                  packets_per_attacker)
        elif attack_type == 'syn':
            attacker_packets = generate_syn_flood(attacker_ip, target_ip, src_mac, dst_mac,
                                                  packets_per_attacker)
        elif attack_type == 'http':
            attacker_packets = generate_http_flood(attacker_ip, target_ip, src_mac, dst_mac,
                                                   packets_per_attacker)
        elif attack_type == 'icmp':
            attacker_packets = generate_icmp_flood(attacker_ip, target_ip, src_mac, dst_mac,
                                                   packets_per_attacker)
        elif attack_type == 'mixed':
            # Mixed attack: Each attacker generates a TRUE MIX of packets
            # SWITCH-SAFE PROPORTIONS: 60% SYN, 20% UDP (DNS), 10% HTTP, 10% ICMP
            # (More SYN because it passes switch filters best)
            attacker_packets = []

            # Calculate packets per type for this attacker
            syn_count = int(packets_per_attacker * 0.60)   # Majority SYN (passes switch)
            udp_count = int(packets_per_attacker * 0.20)   # DNS queries only (realistic)
            http_count = int(packets_per_attacker * 0.10)  # Some HTTP
            icmp_count = packets_per_attacker - syn_count - udp_count - http_count  # Remaining

            # Generate each type (all with switch-safe payloads)
            attacker_packets.extend(generate_syn_flood(attacker_ip, target_ip, src_mac, dst_mac, syn_count))
            attacker_packets.extend(generate_udp_flood(attacker_ip, target_ip, src_mac, dst_mac, udp_count))
            attacker_packets.extend(generate_http_flood(attacker_ip, target_ip, src_mac, dst_mac, http_count))
            attacker_packets.extend(generate_icmp_flood(attacker_ip, target_ip, src_mac, dst_mac, icmp_count))

            # Shuffle to mix packet types (important for realistic traffic pattern)
            random.shuffle(attacker_packets)
        else:
            print(f"ERROR: Unknown attack type: {attack_type}")
            return 0

        packets.extend(attacker_packets)

        if len(packets) >= num_packets:
            packets = packets[:num_packets]
            break

    print(f"\\n  Writing {len(packets):,} packets to {output_file}...")
    wrpcap(output_file, packets)

    # Calculate file size
    import os
    file_size = os.path.getsize(output_file)
    print(f"  File size: {file_size / (1024*1024):.2f} MB")

    # Statistics
    print(f"\\n{'='*70}")
    print(f"ATTACK GENERATION COMPLETE")
    print(f"{'='*70}")
    print(f"Total packets:        {len(packets):,}")
    print(f"Packets per attacker: {packets_per_attacker:,}")
    print(f"Attack type:          {attack_type.upper()}")
    print(f"File size:            {file_size / (1024*1024):.2f} MB")
    print(f"{'='*70}\\n")

    return len(packets)


def main():
    parser = argparse.ArgumentParser(
        description='Generate Mirai-style DDoS attack PCAP (MULTI-LF replication)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types:
  udp    - UDP flood (DNS queries only - switch-safe)
  syn    - VARIED SYN flood (simulates HTTP/HTTPS/SSH/Telnet/RDP floods via SYN packets)
           40%% HTTP (ports 80/8080), 20%% HTTPS (443/8443), 20%% SSH (22/2222),
           10%% Telnet (23/2323), 10%% RDP/SIP (3389/5060)
           All use SYN-only to pass switch filters
  http   - HTTP GET flood (full handshake - may be blocked by switch)
  icmp   - ICMP flood (standard ping - may be blocked by switch)
  mixed  - Mixed SYN-based attack (60%% varied SYN, 20%% DNS, 10%% HTTP, 10%% ICMP)

Examples:
  # UDP flood with 5M packets
  python3 generate_mirai_attacks.py -o attack_udp_5M.pcap -n 5000000 -t udp

  # SYN flood with custom botnet size
  python3 generate_mirai_attacks.py -o attack_syn_5M.pcap -n 5000000 -t syn --attackers 500

  # Mixed attack
  python3 generate_mirai_attacks.py -o attack_mixed_5M.pcap -n 5000000 -t mixed
        """
    )

    parser.add_argument('--output', '-o', default='attack_mirai_5M.pcap',
                       help='Output pcap file (default: attack_mirai_5M.pcap)')
    parser.add_argument('--packets', '-n', type=int, default=5000000,
                       help='Number of packets to generate (default: 5000000)')
    parser.add_argument('--attack-type', '-t', choices=['udp', 'syn', 'http', 'icmp', 'mixed'],
                       default='udp',
                       help='Attack type (default: udp)')
    parser.add_argument('--src-mac', default='00:00:00:00:00:02',
                       help='Source MAC address')
    parser.add_argument('--dst-mac', default='0c:42:a1:dd:5b:28',
                       help='Destination MAC address (monitor NIC)')
    parser.add_argument('--attacker-range', default='203.0.113.0/24',
                       help='Attacker IP range (default: 203.0.113.0/24)')
    parser.add_argument('--target-ip', default='10.0.0.1',
                       help='Target server IP (default: 10.0.0.1)')
    parser.add_argument('--attackers', type=int, default=200,
                       help='Number of attacker IPs (botnet size) (default: 200)')

    args = parser.parse_args()

    generate_mirai_attack(
        args.output,
        args.packets,
        args.attack_type,
        args.src_mac,
        args.dst_mac,
        args.attacker_range,
        args.target_ip,
        args.attackers
    )


if __name__ == '__main__':
    main()
