#!/usr/bin/env python3
"""
MIRA Benign Traffic Generator

Generates realistic benign network traffic patterns similar to CICDDoS2019 benign samples.
Includes HTTP, HTTPS, DNS, SSH, and background TCP/UDP traffic.

Replicates MULTI-LF (2025) baseline traffic for comparison experiments.

Usage:
    python3 generate_benign_traffic.py --output benign_5M.pcap --packets 5000000

Author: MIRA - MULTI-LF Replication and Assessment
"""

import argparse
import random
import struct
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest

def generate_flow_id():
    """Generate unique flow identifier"""
    return random.randint(100000, 999999)

def generate_http_traffic(src_ip, dst_ip, src_mac, dst_mac, flow_id):
    """Generate realistic HTTP GET request + response"""
    packets = []

    # Common HTTP paths from benign traffic
    paths = ['/index.html', '/api/data', '/images/logo.png', '/css/style.css',
             '/js/app.js', '/favicon.ico', '/api/users', '/login']
    path = random.choice(paths)

    # TCP SYN
    syn = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=random.randint(49152, 65535), dport=80, flags='S',
              seq=random.randint(1000, 4000000000))
    packets.append(syn)

    # TCP SYN-ACK (server response)
    synack = Ether(src=dst_mac, dst=src_mac) / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=80, dport=syn[TCP].sport, flags='SA',
                 seq=random.randint(1000, 4000000000), ack=syn[TCP].seq + 1)
    packets.append(synack)

    # TCP ACK (complete handshake)
    ack = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=syn[TCP].sport, dport=80, flags='A',
              seq=syn[TCP].seq + 1, ack=synack[TCP].seq + 1)
    packets.append(ack)

    # HTTP GET request
    http_req = f"GET {path} HTTP/1.1\\r\\nHost: server.local\\r\\nUser-Agent: Mozilla/5.0\\r\\n\\r\\n"
    req = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=syn[TCP].sport, dport=80, flags='PA',
              seq=syn[TCP].seq + 1, ack=synack[TCP].seq + 1) / \
          Raw(load=http_req.encode())
    packets.append(req)

    # HTTP response (server)
    # Max payload: 1500 (MTU) - 14 (Eth) - 20 (IP) - 20 (TCP) - 50 (HTTP headers) = ~1396 bytes
    response_size = random.randint(200, 1200)  # Safe payload size
    http_resp = b"HTTP/1.1 200 OK\\r\\nContent-Length: " + str(response_size).encode() + b"\\r\\n\\r\\n" + \
                bytes([random.randint(0, 255) for _ in range(response_size)])
    resp = Ether(src=dst_mac, dst=src_mac) / \
           IP(src=dst_ip, dst=src_ip) / \
           TCP(sport=80, dport=syn[TCP].sport, flags='PA',
               seq=synack[TCP].seq + 1, ack=req[TCP].seq + len(http_req)) / \
           Raw(load=http_resp)
    packets.append(resp)

    # TCP ACK (client acknowledges response)
    ack2 = Ether(src=src_mac, dst=dst_mac) / \
           IP(src=src_ip, dst=dst_ip) / \
           TCP(sport=syn[TCP].sport, dport=80, flags='A',
               seq=req[TCP].seq + len(http_req), ack=resp[TCP].seq + len(http_resp))
    packets.append(ack2)

    # TCP FIN (client closes)
    fin = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=syn[TCP].sport, dport=80, flags='FA',
              seq=ack2[TCP].seq, ack=resp[TCP].seq + len(http_resp))
    packets.append(fin)

    # TCP FIN-ACK (server closes)
    finack = Ether(src=dst_mac, dst=src_mac) / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=80, dport=syn[TCP].sport, flags='FA',
                 seq=resp[TCP].seq + len(http_resp), ack=fin[TCP].seq + 1)
    packets.append(finack)

    # Final ACK
    final_ack = Ether(src=src_mac, dst=dst_mac) / \
                IP(src=src_ip, dst=dst_ip) / \
                TCP(sport=syn[TCP].sport, dport=80, flags='A',
                    seq=fin[TCP].seq + 1, ack=finack[TCP].seq + 1)
    packets.append(final_ack)

    return packets

def generate_dns_query(src_ip, dst_ip, src_mac, dst_mac):
    """Generate DNS query + response"""
    packets = []

    domains = ['example.com', 'server.local', 'api.service.io', 'cdn.assets.net',
               'auth.domain.com', 'data.cloud.com']
    domain = random.choice(domains)

    # DNS query
    query = Ether(src=src_mac, dst=dst_mac) / \
            IP(src=src_ip, dst=dst_ip) / \
            UDP(sport=random.randint(49152, 65535), dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=domain))
    packets.append(query)

    # DNS response
    response = Ether(src=dst_mac, dst=src_mac) / \
               IP(src=dst_ip, dst=src_ip) / \
               UDP(sport=53, dport=query[UDP].sport) / \
               DNS(id=query[DNS].id, qr=1, aa=1, qd=query[DNS].qd,
                   an=DNSRR(rrname=domain, ttl=300, rdata='10.0.0.100'))
    packets.append(response)

    return packets

def generate_ssh_traffic(src_ip, dst_ip, src_mac, dst_mac):
    """Generate SSH connection simulation"""
    packets = []

    # TCP handshake for SSH (port 22)
    syn = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=random.randint(49152, 65535), dport=22, flags='S',
              seq=random.randint(1000, 4000000000))
    packets.append(syn)

    synack = Ether(src=dst_mac, dst=src_mac) / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=22, dport=syn[TCP].sport, flags='SA',
                 seq=random.randint(1000, 4000000000), ack=syn[TCP].seq + 1)
    packets.append(synack)

    ack = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=syn[TCP].sport, dport=22, flags='A',
              seq=syn[TCP].seq + 1, ack=synack[TCP].seq + 1)
    packets.append(ack)

    # SSH data exchange (encrypted payloads)
    for _ in range(random.randint(3, 8)):
        data_size = random.randint(50, 500)
        data = bytes([random.randint(0, 255) for _ in range(data_size)])

        pkt = Ether(src=random.choice([src_mac, dst_mac]),
                    dst=random.choice([src_mac, dst_mac])) / \
              IP(src=random.choice([src_ip, dst_ip]),
                 dst=random.choice([src_ip, dst_ip])) / \
              TCP(sport=random.choice([syn[TCP].sport, 22]),
                  dport=random.choice([syn[TCP].sport, 22]), flags='PA') / \
              Raw(load=data)
        packets.append(pkt)

    return packets

def generate_icmp_ping(src_ip, dst_ip, src_mac, dst_mac):
    """Generate ICMP echo request + reply"""
    packets = []

    # Echo request
    req = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          ICMP(type=8, code=0, id=random.randint(1, 65535), seq=1) / \
          Raw(load=bytes([random.randint(0, 255) for _ in range(56)]))
    packets.append(req)

    # Echo reply
    reply = Ether(src=dst_mac, dst=src_mac) / \
            IP(src=dst_ip, dst=src_ip) / \
            ICMP(type=0, code=0, id=req[ICMP].id, seq=1) / \
            Raw(load=req[Raw].load)
    packets.append(reply)

    return packets

def generate_background_udp(src_ip, dst_ip, src_mac, dst_mac):
    """Generate background UDP traffic"""
    packets = []

    # Random UDP ports (NTP, SNMP, custom services)
    ports = [123, 161, 1900, 5353, 8888, 9000]

    for _ in range(random.randint(2, 5)):
        port = random.choice(ports)
        data_size = random.randint(50, 300)

        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              UDP(sport=random.randint(49152, 65535), dport=port) / \
              Raw(load=bytes([random.randint(0, 255) for _ in range(data_size)]))
        packets.append(pkt)

    return packets

def generate_benign_traffic(output_file, num_packets, src_mac, dst_mac,
                            client_range, server_ip, num_clients=500):
    """
    Generate benign traffic PCAP similar to CICDDoS2019 benign patterns

    Args:
        output_file: Output pcap file path
        num_packets: Total number of packets to generate
        src_mac: Source MAC address
        dst_mac: Destination MAC address
        client_range: Client IP range (e.g., "192.168.1.0/24")
        server_ip: Server IP address
        num_clients: Number of simulated client IPs
    """

    print(f"Generating {num_packets:,} benign packets (MULTI-LF style)...")
    print(f"Output file: {output_file}")
    print(f"Client IP range: {client_range}")
    print(f"Server IP: {server_ip}")
    print(f"Number of clients: {num_clients}")

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
    packets_per_update = num_packets // 100  # Update every 1% instead of 10%
    current_count = 0
    last_print = 0

    print("")  # Empty line for better visibility
    print("Starting packet generation...")

    # Traffic distribution (similar to benign patterns):
    # 50% HTTP, 20% DNS, 15% SSH, 10% ICMP, 5% Background UDP
    traffic_types = ['http'] * 50 + ['dns'] * 20 + ['ssh'] * 15 + ['icmp'] * 10 + ['udp'] * 5

    while current_count < num_packets:
        # Print progress more frequently (every 1% or every 50K packets, whichever is smaller)
        if current_count - last_print >= min(packets_per_update, 50000):
            percent = current_count * 100 // num_packets
            print(f"  Progress: {current_count:,}/{num_packets:,} ({percent}%)", flush=True)
            last_print = current_count

        # Select random client
        client_ip = random.choice(client_ips)

        # Select traffic type
        traffic_type = random.choice(traffic_types)

        # Generate flow
        if traffic_type == 'http':
            flow_packets = generate_http_traffic(client_ip, server_ip, src_mac, dst_mac,
                                                 generate_flow_id())
        elif traffic_type == 'dns':
            flow_packets = generate_dns_query(client_ip, server_ip, src_mac, dst_mac)
        elif traffic_type == 'ssh':
            flow_packets = generate_ssh_traffic(client_ip, server_ip, src_mac, dst_mac)
        elif traffic_type == 'icmp':
            flow_packets = generate_icmp_ping(client_ip, server_ip, src_mac, dst_mac)
        else:  # udp
            flow_packets = generate_background_udp(client_ip, server_ip, src_mac, dst_mac)

        packets.extend(flow_packets)
        current_count += len(flow_packets)

        # Stop if we've reached target
        if current_count >= num_packets:
            packets = packets[:num_packets]
            break

    print(f"  Writing {len(packets):,} packets to {output_file}...")
    wrpcap(output_file, packets)

    # Calculate file size
    import os
    file_size = os.path.getsize(output_file)
    print(f"  File size: {file_size / (1024*1024):.2f} MB")
    print(f"Done!")

    return len(packets)


def main():
    parser = argparse.ArgumentParser(
        description='Generate benign traffic PCAP (MULTI-LF replication)'
    )
    parser.add_argument('--output', '-o', default='benign_5M.pcap',
                       help='Output pcap file (default: benign_5M.pcap)')
    parser.add_argument('--packets', '-n', type=int, default=5000000,
                       help='Number of packets to generate (default: 5000000)')
    parser.add_argument('--src-mac', default='00:00:00:00:00:01',
                       help='Source MAC address')
    parser.add_argument('--dst-mac', default='0c:42:a1:dd:5b:28',
                       help='Destination MAC address (monitor NIC)')
    parser.add_argument('--client-range', default='192.168.1.0/24',
                       help='Client IP range (default: 192.168.1.0/24)')
    parser.add_argument('--server-ip', default='10.0.0.1',
                       help='Server IP address (default: 10.0.0.1)')
    parser.add_argument('--clients', type=int, default=500,
                       help='Number of client IPs (default: 500)')

    args = parser.parse_args()

    generate_benign_traffic(
        args.output,
        args.packets,
        args.src_mac,
        args.dst_mac,
        args.client_range,
        args.server_ip,
        args.clients
    )


if __name__ == '__main__':
    main()
