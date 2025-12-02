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
    Generate UDP flood attack (CICDDoS2019 style - MULTI-LF paper replication)

    Characteristics (based on CICDDoS2019 dataset observation):
    - Random source ports (1024-65535)
    - Random destination ports (NOT fixed DNS port 53)
    - Fixed payload: 516 bytes (as observed in CICDDoS2019 traces)
    - High volume flood attack
    """
    packets = []

    # Generate fixed 516-byte payload (CICDDoS2019 characteristic)
    payload = bytes([random.randint(0, 255) for _ in range(516)])

    for i in range(num_packets):
        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              UDP(sport=random.randint(1024, 65535),
                  dport=random.randint(1024, 65535)) / \
              Raw(load=payload)

        packets.append(pkt)

    return packets

def generate_syn_flood(src_ip, dst_ip, src_mac, dst_mac, num_packets):
    """
    Generate SYN flood attack (MULTI-LF paper replication - Mirai style)

    Characteristics:
    - SYN packets only (no handshake completion)
    - Target common service ports: 80 (HTTP), 443 (HTTPS), 22 (SSH)
    - Random source ports
    - Random sequence numbers
    - Simple and volumetric (typical Mirai botnet behavior)
    """
    packets = []

    # Common target ports for SYN flood (Mirai-style)
    target_ports = [80, 443, 22]

    for i in range(num_packets):
        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              TCP(sport=random.randint(1024, 65535),
                  dport=random.choice(target_ports),
                  flags='S',
                  seq=random.randint(1000, 4000000000))

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
            # SWITCH-SAFE PROPORTIONS: 50% SYN, 40% UDP (516-byte), 10% ICMP
            # Based on CloudLab switch testing - removed HTTP (bidirectional, often blocked)
            attacker_packets = []

            # Calculate packets per type for this attacker
            syn_count = int(packets_per_attacker * 0.50)   # SYN flood (passes switch)
            udp_count = int(packets_per_attacker * 0.40)   # UDP flood 516-byte (CICDDoS2019 style)
            icmp_count = packets_per_attacker - syn_count - udp_count  # Remaining ICMP

            # Generate each type (all with switch-safe payloads)
            attacker_packets.extend(generate_syn_flood(attacker_ip, target_ip, src_mac, dst_mac, syn_count))
            attacker_packets.extend(generate_udp_flood(attacker_ip, target_ip, src_mac, dst_mac, udp_count))
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
  udp    - UDP flood (516-byte payloads, random ports - CICDDoS2019 style)
  syn    - SYN flood (ports 80/443/22 - simple Mirai style)
  http   - HTTP GET flood (full handshake - may be blocked by switch)
  icmp   - ICMP flood (standard 64-byte ping)
  mixed  - Mixed attack (50%% SYN, 40%% UDP, 10%% ICMP - switch-safe)

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
    parser.add_argument('--attacker-range', default='192.168.2.0/24',
                       help='Attacker IP range (default: 192.168.2.0/24)')
    parser.add_argument('--target-ip', default='10.10.1.2',
                       help='Target server IP (default: 10.10.1.2)')
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
