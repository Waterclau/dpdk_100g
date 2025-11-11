"""
Generador de tráfico benigno realista para usar como baseline
"""
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, PcapWriter
from .utils import (
    TimestampGenerator, RealisticPayloadGenerator, IPGenerator,
    TTLDistribution, PacketSizeDistribution
)
import random
from typing import Optional, List, Dict


class BenignTrafficGenerator:
    """Generador de tráfico benigno realista"""

    def __init__(self, seed: Optional[int] = None):
        self.seed = seed or random.randint(0, 2**32 - 1)
        self.rng = random.Random(self.seed)
        self.ip_gen = IPGenerator(self.seed)
        self.payload_gen = RealisticPayloadGenerator(self.seed)

        # IPs comunes para tráfico benigno
        self.dns_servers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        self.web_servers = [f'172.217.{i}.{j}' for i in range(1, 5) for j in range(1, 10)]
        self.ntp_servers = [f'129.6.15.{i}' for i in range(1, 10)]

    def generate_http_session(self, writer: PcapWriter, client_ip: str,
                              server_ip: str, start_time: float):
        """Genera una sesión HTTP completa (3-way handshake, request, response, FIN)"""
        client_port = self.rng.randint(49152, 65535)
        server_port = 80
        ttl = TTLDistribution.sample(self.rng)

        current_time = start_time

        # Client -> Server: SYN
        syn = (Ether() /
               IP(src=client_ip, dst=server_ip, ttl=ttl) /
               TCP(sport=client_port, dport=server_port, flags='S',
                   seq=self.rng.randint(0, 2**32-1), window=65535,
                   options=[('MSS', 1460), ('WScale', 7)]))
        syn.time = current_time
        writer.write(syn)
        current_time += self.rng.uniform(0.001, 0.005)

        # Server -> Client: SYN-ACK
        syn_ack = (Ether() /
                   IP(src=server_ip, dst=client_ip, ttl=ttl) /
                   TCP(sport=server_port, dport=client_port, flags='SA',
                       seq=self.rng.randint(0, 2**32-1),
                       ack=syn[TCP].seq + 1, window=65535,
                       options=[('MSS', 1460), ('WScale', 7)]))
        syn_ack.time = current_time
        writer.write(syn_ack)
        current_time += self.rng.uniform(0.001, 0.005)

        # Client -> Server: ACK
        ack = (Ether() /
               IP(src=client_ip, dst=server_ip, ttl=ttl) /
               TCP(sport=client_port, dport=server_port, flags='A',
                   seq=syn[TCP].seq + 1, ack=syn_ack[TCP].seq + 1, window=65535))
        ack.time = current_time
        writer.write(ack)
        current_time += self.rng.uniform(0.01, 0.05)

        # Client -> Server: HTTP GET (PSH-ACK)
        http_request = self.payload_gen.http_get()
        get = (Ether() /
               IP(src=client_ip, dst=server_ip, ttl=ttl) /
               TCP(sport=client_port, dport=server_port, flags='PA',
                   seq=ack[TCP].seq, ack=ack[TCP].ack, window=65535) /
               Raw(load=http_request))
        get.time = current_time
        writer.write(get)
        current_time += self.rng.uniform(0.05, 0.2)

        # Server -> Client: HTTP 200 OK (PSH-ACK)
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 512\r\n\r\n"
            + b"<html><body>OK</body></html>" + b"X" * 470
        )
        response = (Ether() /
                    IP(src=server_ip, dst=client_ip, ttl=ttl) /
                    TCP(sport=server_port, dport=client_port, flags='PA',
                        seq=syn_ack[TCP].seq + 1,
                        ack=get[TCP].seq + len(http_request), window=65535) /
                    Raw(load=http_response))
        response.time = current_time
        writer.write(response)
        current_time += self.rng.uniform(0.001, 0.005)

        # Client -> Server: ACK
        final_ack = (Ether() /
                     IP(src=client_ip, dst=server_ip, ttl=ttl) /
                     TCP(sport=client_port, dport=server_port, flags='A',
                         seq=get[TCP].seq + len(http_request),
                         ack=response[TCP].seq + len(http_response), window=65535))
        final_ack.time = current_time
        writer.write(final_ack)
        current_time += self.rng.uniform(0.001, 0.01)

        # Client -> Server: FIN-ACK
        fin = (Ether() /
               IP(src=client_ip, dst=server_ip, ttl=ttl) /
               TCP(sport=client_port, dport=server_port, flags='FA',
                   seq=final_ack[TCP].seq, ack=final_ack[TCP].ack, window=65535))
        fin.time = current_time
        writer.write(fin)
        current_time += self.rng.uniform(0.001, 0.005)

        # Server -> Client: FIN-ACK
        fin_ack = (Ether() /
                   IP(src=server_ip, dst=client_ip, ttl=ttl) /
                   TCP(sport=server_port, dport=client_port, flags='FA',
                       seq=response[TCP].seq + len(http_response),
                       ack=fin[TCP].seq + 1, window=65535))
        fin_ack.time = current_time
        writer.write(fin_ack)
        current_time += self.rng.uniform(0.001, 0.005)

        # Client -> Server: Final ACK
        final = (Ether() /
                 IP(src=client_ip, dst=server_ip, ttl=ttl) /
                 TCP(sport=client_port, dport=server_port, flags='A',
                     seq=fin[TCP].seq + 1, ack=fin_ack[TCP].seq + 1, window=65535))
        final.time = current_time
        writer.write(final)

        return current_time

    def generate_dns_query_response(self, writer: PcapWriter, client_ip: str,
                                    dns_server: str, start_time: float):
        """Genera query DNS y respuesta"""
        client_port = self.rng.randint(49152, 65535)
        ttl = TTLDistribution.sample(self.rng)
        dns_id = self.rng.randint(1, 65535)

        domains = ['google.com', 'facebook.com', 'amazon.com', 'twitter.com',
                   'github.com', 'stackoverflow.com', 'reddit.com']
        domain = self.rng.choice(domains)

        # Query
        dns_query = DNS(id=dns_id, qr=0, opcode=0, rd=1, qd=DNSQR(qname=domain, qtype='A'))
        query_pkt = (Ether() /
                     IP(src=client_ip, dst=dns_server, ttl=ttl) /
                     UDP(sport=client_port, dport=53) /
                     dns_query)
        query_pkt.time = start_time
        writer.write(query_pkt)

        # Response
        response_time = start_time + self.rng.uniform(0.01, 0.05)
        fake_ip = self.ip_gen.random_public_ip()
        dns_response = DNS(
            id=dns_id, qr=1, opcode=0, aa=0, rd=1, ra=1,
            qd=DNSQR(qname=domain, qtype='A'),
            an=DNSRR(rrname=domain, type='A', rdata=fake_ip, ttl=300)
        )
        response_pkt = (Ether() /
                        IP(src=dns_server, dst=client_ip, ttl=ttl) /
                        UDP(sport=53, dport=client_port) /
                        dns_response)
        response_pkt.time = response_time
        writer.write(response_pkt)

        return response_time

    def generate_ssh_session(self, writer: PcapWriter, client_ip: str,
                            server_ip: str, start_time: float):
        """Genera tráfico SSH (handshake + datos encriptados)"""
        client_port = self.rng.randint(49152, 65535)
        server_port = 22
        ttl = TTLDistribution.sample(self.rng)
        current_time = start_time

        # TCP handshake (simplificado)
        syn = (Ether() /
               IP(src=client_ip, dst=server_ip, ttl=ttl) /
               TCP(sport=client_port, dport=server_port, flags='S',
                   seq=self.rng.randint(0, 2**32-1), window=65535))
        syn.time = current_time
        writer.write(syn)
        current_time += self.rng.uniform(0.01, 0.05)

        # Intercambio de claves SSH (datos encriptados simulados)
        for i in range(5):
            direction = i % 2  # 0=client->server, 1=server->client
            src = client_ip if direction == 0 else server_ip
            dst = server_ip if direction == 0 else client_ip
            sport = client_port if direction == 0 else server_port
            dport = server_port if direction == 0 else client_port

            payload_size = self.rng.randint(64, 512)
            ssh_data = self.payload_gen.random_bytes(payload_size)

            pkt = (Ether() /
                   IP(src=src, dst=dst, ttl=ttl) /
                   TCP(sport=sport, dport=dport, flags='PA',
                       seq=self.rng.randint(0, 2**32-1),
                       ack=self.rng.randint(0, 2**32-1), window=65535) /
                   Raw(load=ssh_data))
            pkt.time = current_time
            writer.write(pkt)
            current_time += self.rng.uniform(0.05, 0.2)

        return current_time

    def generate_icmp_ping(self, writer: PcapWriter, src_ip: str,
                          dst_ip: str, start_time: float):
        """Genera ping ICMP (echo request/reply)"""
        ttl = TTLDistribution.sample(self.rng)
        icmp_id = self.rng.randint(1, 65535)
        seq = self.rng.randint(1, 100)

        # Echo Request
        request = (Ether() /
                   IP(src=src_ip, dst=dst_ip, ttl=ttl) /
                   ICMP(type=8, id=icmp_id, seq=seq) /
                   Raw(load=b"X" * 56))
        request.time = start_time
        writer.write(request)

        # Echo Reply
        reply_time = start_time + self.rng.uniform(0.001, 0.05)
        reply = (Ether() /
                 IP(src=dst_ip, dst=src_ip, ttl=ttl) /
                 ICMP(type=0, id=icmp_id, seq=seq) /
                 Raw(load=b"X" * 56))
        reply.time = reply_time
        writer.write(reply)

        return reply_time

    def generate_ntp_query(self, writer: PcapWriter, client_ip: str,
                          ntp_server: str, start_time: float):
        """Genera consulta NTP"""
        client_port = self.rng.randint(49152, 65535)
        ttl = TTLDistribution.sample(self.rng)

        # NTP request (versión 4, modo cliente)
        ntp_request = b'\x1b' + b'\x00' * 47

        request_pkt = (Ether() /
                       IP(src=client_ip, dst=ntp_server, ttl=ttl) /
                       UDP(sport=client_port, dport=123) /
                       Raw(load=ntp_request))
        request_pkt.time = start_time
        writer.write(request_pkt)

        # NTP response
        response_time = start_time + self.rng.uniform(0.01, 0.1)
        ntp_response = b'\x1c' + b'\x00' * 47

        response_pkt = (Ether() /
                        IP(src=ntp_server, dst=client_ip, ttl=ttl) /
                        UDP(sport=123, dport=client_port) /
                        Raw(load=ntp_response))
        response_pkt.time = response_time
        writer.write(response_pkt)

        return response_time


class BenignTrafficMixer:
    """Genera mezclas realistas de tráfico benigno"""

    def __init__(self, seed: Optional[int] = None):
        self.seed = seed or random.randint(0, 2**32 - 1)
        self.rng = random.Random(self.seed)
        self.generator = BenignTrafficGenerator(self.seed)

    def generate_realistic_traffic(self, writer: PcapWriter, duration_sec: int = 60,
                                   traffic_profile: str = 'normal'):
        """
        Genera tráfico benigno realista con mezcla de protocolos

        Args:
            writer: PcapWriter para escribir paquetes
            duration_sec: Duración en segundos
            traffic_profile: 'light', 'normal', 'heavy'
        """
        # Definir ratios de tráfico por perfil
        profiles = {
            'light': {'http': 0.40, 'dns': 0.30, 'ssh': 0.10, 'icmp': 0.15, 'ntp': 0.05},
            'normal': {'http': 0.50, 'dns': 0.25, 'ssh': 0.10, 'icmp': 0.10, 'ntp': 0.05},
            'heavy': {'http': 0.60, 'dns': 0.20, 'ssh': 0.10, 'icmp': 0.05, 'ntp': 0.05}
        }

        # Eventos por segundo por perfil
        events_per_sec = {
            'light': 10,
            'normal': 50,
            'heavy': 200
        }

        profile_ratios = profiles.get(traffic_profile, profiles['normal'])
        eps = events_per_sec.get(traffic_profile, 50)

        total_events = int(duration_sec * eps)
        print(f"[*] Generando {total_events:,} eventos de tráfico benigno ({traffic_profile})...")

        # Generar lista de eventos según ratios
        events = []
        for proto, ratio in profile_ratios.items():
            count = int(total_events * ratio)
            events.extend([proto] * count)

        self.rng.shuffle(events)

        # Generar subnet interna para clientes
        client_ips = [f"192.168.1.{i}" for i in range(2, 254)]

        current_time = 1000.0  # Timestamp inicial
        event_count = 0

        for event_type in events:
            client_ip = self.rng.choice(client_ips)

            if event_type == 'http':
                server_ip = self.rng.choice(self.generator.web_servers)
                current_time = self.generator.generate_http_session(
                    writer, client_ip, server_ip, current_time
                )
                current_time += self.rng.uniform(0.1, 2.0)

            elif event_type == 'dns':
                dns_server = self.rng.choice(self.generator.dns_servers)
                current_time = self.generator.generate_dns_query_response(
                    writer, client_ip, dns_server, current_time
                )
                current_time += self.rng.uniform(0.1, 1.0)

            elif event_type == 'ssh':
                server_ip = self.rng.choice(self.generator.web_servers)
                current_time = self.generator.generate_ssh_session(
                    writer, client_ip, server_ip, current_time
                )
                current_time += self.rng.uniform(1.0, 5.0)

            elif event_type == 'icmp':
                dst_ip = self.generator.ip_gen.random_public_ip()
                current_time = self.generator.generate_icmp_ping(
                    writer, client_ip, dst_ip, current_time
                )
                current_time += self.rng.uniform(0.5, 3.0)

            elif event_type == 'ntp':
                ntp_server = self.rng.choice(self.generator.ntp_servers)
                current_time = self.generator.generate_ntp_query(
                    writer, client_ip, ntp_server, current_time
                )
                current_time += self.rng.uniform(1.0, 10.0)

            event_count += 1
            if event_count % 100 == 0:
                print(f"  Progreso: {event_count}/{total_events} eventos ({event_count*100/total_events:.1f}%)")

        print(f"[+] Tráfico benigno generado: {event_count} eventos")


def generate_benign_pcap(output_file: str, duration_sec: int = 60,
                        traffic_profile: str = 'normal', seed: Optional[int] = None):
    """
    Función helper para generar PCAP de tráfico benigno

    Args:
        output_file: Path del archivo de salida
        duration_sec: Duración en segundos
        traffic_profile: 'light', 'normal', 'heavy'
        seed: Seed para reproducibilidad
    """
    print(f"\n{'='*60}")
    print(f" Generador de Tráfico Benigno")
    print(f" Output: {output_file}")
    print(f" Duración: {duration_sec}s")
    print(f" Perfil: {traffic_profile}")
    if seed:
        print(f" Seed: {seed}")
    print(f"{'='*60}\n")

    mixer = BenignTrafficMixer(seed)

    with PcapWriter(output_file, sync=True) as writer:
        mixer.generate_realistic_traffic(writer, duration_sec, traffic_profile)

    import os
    file_size_mb = os.path.getsize(output_file) / (1024 * 1024)
    print(f"\n[+] PCAP generado: {output_file}")
    print(f"    Tamaño: {file_size_mb:.2f} MB")
