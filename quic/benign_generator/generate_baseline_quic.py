#!/usr/bin/env python3
"""
QUIC Baseline Traffic Generator

Genera trafico QUIC legitimo para usar como baseline en experimentos de deteccion.
El trafico simula conexiones HTTP/3 normales con handshakes, requests y ACKs coherentes.

Uso:
    python3 generate_baseline_quic.py --output baseline_quic.pcap --packets 5000000

Autor: QUIC Optimistic ACK Detector Project
"""

import argparse
import random
import struct
import os
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

# QUIC Version
QUIC_VERSION_1 = 0x00000001

# QUIC Long Header Types
QUIC_INITIAL = 0x00
QUIC_ZERO_RTT = 0x01
QUIC_HANDSHAKE = 0x02
QUIC_RETRY = 0x03

# QUIC Frame Types
FRAME_PADDING = 0x00
FRAME_PING = 0x01
FRAME_ACK = 0x02
FRAME_ACK_ECN = 0x03
FRAME_CRYPTO = 0x06
FRAME_STREAM = 0x08

def generate_connection_id(length=8):
    """Generate random QUIC Connection ID"""
    return bytes([random.randint(0, 255) for _ in range(length)])

def encode_variable_int(value):
    """Encode integer using QUIC variable-length encoding"""
    if value < 64:
        return bytes([value])
    elif value < 16384:
        return bytes([0x40 | (value >> 8), value & 0xFF])
    elif value < 1073741824:
        return bytes([0x80 | (value >> 24), (value >> 16) & 0xFF,
                     (value >> 8) & 0xFF, value & 0xFF])
    else:
        return bytes([0xC0 | (value >> 56), (value >> 48) & 0xFF,
                     (value >> 40) & 0xFF, (value >> 32) & 0xFF,
                     (value >> 24) & 0xFF, (value >> 16) & 0xFF,
                     (value >> 8) & 0xFF, value & 0xFF])

def create_quic_long_header(packet_type, version, dcid, scid, packet_number):
    """Create QUIC Long Header"""
    # First byte: Form bit (1) | Fixed bit (1) | Long Packet Type (2) | Reserved (2) | PN Length (2)
    first_byte = 0xC0 | (packet_type << 4) | 0x03  # 4-byte packet number

    header = bytes([first_byte])
    header += struct.pack('>I', version)
    header += bytes([len(dcid)]) + dcid
    header += bytes([len(scid)]) + scid

    # For Initial packets, add token length (0)
    if packet_type == QUIC_INITIAL:
        header += bytes([0])  # Token length = 0

    # Packet number (4 bytes)
    header += struct.pack('>I', packet_number)

    return header

def create_quic_short_header(dcid, packet_number):
    """Create QUIC Short Header (1-RTT)"""
    # First byte: Form bit (0) | Fixed bit (1) | Spin bit (0) | Reserved (2) | Key Phase (0) | PN Length (2)
    first_byte = 0x40 | 0x03  # Fixed bit set, 4-byte packet number

    header = bytes([first_byte])
    header += dcid
    header += struct.pack('>I', packet_number)

    return header

def create_ack_frame(largest_ack, ack_delay=0, first_ack_range=0):
    """Create QUIC ACK frame"""
    frame = bytes([FRAME_ACK])
    frame += encode_variable_int(largest_ack)      # Largest Acknowledged
    frame += encode_variable_int(ack_delay)        # ACK Delay
    frame += encode_variable_int(0)                # ACK Range Count (0 = only one range)
    frame += encode_variable_int(first_ack_range)  # First ACK Range
    return frame

def create_stream_frame(stream_id, offset, data, fin=False):
    """Create QUIC STREAM frame"""
    # Frame type: 0x08 + flags (OFF=1, LEN=1, FIN)
    frame_type = FRAME_STREAM | 0x06  # OFF and LEN bits set
    if fin:
        frame_type |= 0x01

    frame = bytes([frame_type])
    frame += encode_variable_int(stream_id)
    frame += encode_variable_int(offset)
    frame += encode_variable_int(len(data))
    frame += data
    return frame

def create_crypto_frame(offset, data):
    """Create QUIC CRYPTO frame"""
    frame = bytes([FRAME_CRYPTO])
    frame += encode_variable_int(offset)
    frame += encode_variable_int(len(data))
    frame += data
    return frame

def create_padding(length):
    """Create PADDING frames"""
    return bytes([FRAME_PADDING] * length)

def generate_baseline_quic_traffic(output_file, num_packets,
                                    src_mac, dst_mac,
                                    client_ip_range, server_ip,
                                    num_flows=1000):
    """
    Generate baseline QUIC traffic pcap

    Args:
        output_file: Output pcap file path
        num_packets: Total number of packets to generate
        src_mac: Source MAC address
        dst_mac: Destination MAC address
        client_ip_range: Client IP range (e.g., "192.168.1.0/24")
        server_ip: Server IP address
        num_flows: Number of concurrent QUIC flows to simulate
    """

    print(f"Generating {num_packets:,} baseline QUIC packets...")
    print(f"Output file: {output_file}")
    print(f"Client IP range: {client_ip_range}")
    print(f"Server IP: {server_ip}")
    print(f"Number of flows: {num_flows}")

    # Parse client IP range
    base_ip = client_ip_range.split('/')[0]
    ip_parts = base_ip.split('.')
    base_ip_int = (int(ip_parts[0]) << 24) | (int(ip_parts[1]) << 16) | \
                  (int(ip_parts[2]) << 8) | int(ip_parts[3])

    # Initialize flows
    flows = []
    for i in range(num_flows):
        client_ip_int = base_ip_int + (i % 256)
        client_ip = f"{(client_ip_int >> 24) & 0xFF}.{(client_ip_int >> 16) & 0xFF}." \
                   f"{(client_ip_int >> 8) & 0xFF}.{client_ip_int & 0xFF}"

        flow = {
            'client_ip': client_ip,
            'client_port': 50000 + (i % 15000),
            'dcid': generate_connection_id(8),
            'scid': generate_connection_id(8),
            'client_pkt_num': 0,
            'server_pkt_num': 0,
            'last_acked': 0,
            'state': 'initial',  # initial, handshake, data, closing
            'stream_offset': 0,
        }
        flows.append(flow)

    packets = []
    packets_per_update = num_packets // 10

    for i in range(num_packets):
        if i > 0 and i % packets_per_update == 0:
            print(f"  Progress: {i:,}/{num_packets:,} ({i*100//num_packets}%)")

        # Select random flow
        flow = random.choice(flows)

        # Determine packet direction (60% client->server, 40% server->client)
        is_client_to_server = random.random() < 0.6

        if is_client_to_server:
            src_ip = flow['client_ip']
            dst_ip = server_ip
            src_port = flow['client_port']
            dst_port = 443
        else:
            src_ip = server_ip
            dst_ip = flow['client_ip']
            src_port = 443
            dst_port = flow['client_port']

        # Create packet based on flow state
        if flow['state'] == 'initial':
            # Initial handshake packet
            if is_client_to_server:
                header = create_quic_long_header(QUIC_INITIAL, QUIC_VERSION_1,
                                                flow['dcid'], flow['scid'],
                                                flow['client_pkt_num'])
                # Crypto frame with simulated ClientHello
                crypto_data = bytes([random.randint(0, 255) for _ in range(200)])
                payload = create_crypto_frame(0, crypto_data)
                payload += create_padding(1200 - len(header) - len(payload))  # Pad to 1200
                flow['client_pkt_num'] += 1
            else:
                header = create_quic_long_header(QUIC_INITIAL, QUIC_VERSION_1,
                                                flow['scid'], flow['dcid'],
                                                flow['server_pkt_num'])
                # Server Initial with ACK
                largest_ack = max(0, flow['client_pkt_num'] - 1)
                payload = create_ack_frame(largest_ack, 10, 0)
                crypto_data = bytes([random.randint(0, 255) for _ in range(150)])
                payload += create_crypto_frame(0, crypto_data)
                payload += create_padding(max(0, 1200 - len(header) - len(payload)))
                flow['server_pkt_num'] += 1
                flow['last_acked'] = largest_ack

            # Progress state after some packets
            if flow['client_pkt_num'] > 2:
                flow['state'] = 'handshake'

        elif flow['state'] == 'handshake':
            # Handshake packets
            if is_client_to_server:
                header = create_quic_long_header(QUIC_HANDSHAKE, QUIC_VERSION_1,
                                                flow['dcid'], flow['scid'],
                                                flow['client_pkt_num'])
                largest_ack = max(0, flow['server_pkt_num'] - 1)
                payload = create_ack_frame(largest_ack, 5, 0)
                crypto_data = bytes([random.randint(0, 255) for _ in range(100)])
                payload += create_crypto_frame(flow['stream_offset'], crypto_data)
                flow['client_pkt_num'] += 1
            else:
                header = create_quic_long_header(QUIC_HANDSHAKE, QUIC_VERSION_1,
                                                flow['scid'], flow['dcid'],
                                                flow['server_pkt_num'])
                largest_ack = max(0, flow['client_pkt_num'] - 1)
                payload = create_ack_frame(largest_ack, 8, 0)
                crypto_data = bytes([random.randint(0, 255) for _ in range(80)])
                payload += create_crypto_frame(flow['stream_offset'], crypto_data)
                flow['server_pkt_num'] += 1
                flow['last_acked'] = largest_ack

            # Progress to data state
            if flow['client_pkt_num'] > 5:
                flow['state'] = 'data'

        else:  # data state
            # Short header data packets
            if is_client_to_server:
                header = create_quic_short_header(flow['dcid'], flow['client_pkt_num'])

                # Mix of ACKs and stream data
                if random.random() < 0.4:
                    # ACK frame - acknowledge recent server packets coherently
                    largest_ack = max(0, flow['server_pkt_num'] - 1)
                    ack_delay = random.randint(1, 50)  # Normal delay
                    payload = create_ack_frame(largest_ack, ack_delay, min(largest_ack, 5))
                else:
                    # Stream data (HTTP/3 request)
                    request_data = b"GET /index.html HTTP/3\r\nHost: server\r\n\r\n"
                    payload = create_stream_frame(0, flow['stream_offset'], request_data)
                    flow['stream_offset'] += len(request_data)

                flow['client_pkt_num'] += 1
            else:
                header = create_quic_short_header(flow['scid'], flow['server_pkt_num'])

                # Server sends data and ACKs
                if random.random() < 0.3:
                    # ACK client packets
                    largest_ack = max(0, flow['client_pkt_num'] - 1)
                    payload = create_ack_frame(largest_ack, random.randint(1, 30),
                                              min(largest_ack, 3))
                    flow['last_acked'] = largest_ack
                else:
                    # Stream data (HTTP/3 response)
                    # BALANCED: Use similar size to client to achieve ~1:1 ratio
                    # This allows clean distinction between normal traffic and Optimistic ACK amplification
                    response_data = bytes([random.randint(0, 255) for _ in range(random.randint(40, 80))])
                    payload = create_stream_frame(0, flow['stream_offset'], response_data)
                    flow['stream_offset'] += len(response_data)

                flow['server_pkt_num'] += 1

        # Build complete packet
        quic_payload = header + payload

        # Create Scapy packet
        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              UDP(sport=src_port, dport=dst_port) / \
              Raw(load=quic_payload)

        packets.append(pkt)

    print(f"  Writing {len(packets):,} packets to {output_file}...")
    wrpcap(output_file, packets)

    # Calculate file size
    file_size = os.path.getsize(output_file)
    print(f"  File size: {file_size / (1024*1024):.2f} MB")
    print(f"Done!")

    return len(packets)


def main():
    parser = argparse.ArgumentParser(description='Generate baseline QUIC traffic pcap')
    parser.add_argument('--output', '-o', default='baseline_quic_5M.pcap',
                       help='Output pcap file (default: baseline_quic_5M.pcap)')
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
    parser.add_argument('--flows', type=int, default=1000,
                       help='Number of concurrent flows (default: 1000)')

    args = parser.parse_args()

    generate_baseline_quic_traffic(
        args.output,
        args.packets,
        args.src_mac,
        args.dst_mac,
        args.client_range,
        args.server_ip,
        args.flows
    )


if __name__ == '__main__':
    main()
