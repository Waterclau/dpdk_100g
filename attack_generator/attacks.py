"""
Módulos de generación de ataques DDoS realistas
"""
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, wrpcap, PcapWriter
from .utils import (
    TimestampGenerator, RealisticPayloadGenerator, IPGenerator,
    TTLDistribution, PacketSizeDistribution, DistributionSampler
)
import random
from typing import Optional, Dict, Any


class AttackGenerator:
    """Clase base para generadores de ataques"""

    def __init__(self, target_ip: str, seed: Optional[int] = None,
                 sampler: Optional[DistributionSampler] = None):
        self.target_ip = target_ip
        self.seed = seed or random.randint(0, 2**32 - 1)
        self.rng = random.Random(self.seed)
        self.ip_gen = IPGenerator(self.seed)
        self.payload_gen = RealisticPayloadGenerator(self.seed)
        self.sampler = sampler

    def generate_streaming(self, writer: PcapWriter, num_packets: int,
                          start_time: float, pps: int = 1000):
        """
        Genera paquetes en modo streaming (debe ser implementado por subclases)

        Args:
            writer: PcapWriter para escribir paquetes
            num_packets: Número de paquetes a generar
            start_time: Timestamp inicial
            pps: Paquetes por segundo
        """
        raise NotImplementedError


class SYNFloodGenerator(AttackGenerator):
    """Generador de SYN Flood realista"""

    def generate_streaming(self, writer: PcapWriter, num_packets: int,
                          start_time: float, pps: int = 10000):
        ts_gen = TimestampGenerator(start_time, pps, burst_mode=True, seed=self.seed)

        for i in range(num_packets):
            src_ip = self.ip_gen.random_public_ip()
            sport = self.rng.randint(1024, 65535)
            dport = self.rng.choice([80, 443, 8080, 8443])

            # TTL realista
            ttl = TTLDistribution.sample(self.rng)

            # Opciones TCP variables
            tcp_options = []
            if self.rng.random() < 0.8:  # 80% incluyen MSS
                tcp_options.append(('MSS', self.rng.choice([1460, 1380, 536])))
            if self.rng.random() < 0.6:  # 60% incluyen Window Scale
                tcp_options.append(('WScale', self.rng.randint(0, 8)))

            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl, id=self.rng.randint(0, 65535)) /
                   TCP(sport=sport, dport=dport, flags='S',
                       seq=self.rng.randint(0, 2**32 - 1),
                       window=self.rng.choice([5840, 8192, 16384, 65535]),
                       options=tcp_options))

            pkt.time = ts_gen.next()
            writer.write(pkt)


class UDPFloodGenerator(AttackGenerator):
    """Generador de UDP Flood realista"""

    def generate_streaming(self, writer: PcapWriter, num_packets: int,
                          start_time: float, pps: int = 15000):
        ts_gen = TimestampGenerator(start_time, pps, burst_mode=True, seed=self.seed)

        for i in range(num_packets):
            src_ip = self.ip_gen.random_public_ip()
            sport = self.rng.randint(1024, 65535)
            dport = self.rng.choice([53, 123, 161, 1900])  # DNS, NTP, SNMP, SSDP

            # Tamaño de payload variable con long tail
            payload_size = PacketSizeDistribution.sample(self.rng)
            payload = self.payload_gen.random_bytes(payload_size, long_tail=True)

            ttl = TTLDistribution.sample(self.rng)

            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl, id=self.rng.randint(0, 65535)) /
                   UDP(sport=sport, dport=dport) /
                   Raw(load=payload))

            pkt.time = ts_gen.next()
            writer.write(pkt)


class DNSAmplificationGenerator(AttackGenerator):
    """Generador de DNS Amplification realista"""

    def generate_streaming(self, writer: PcapWriter, num_packets: int,
                          start_time: float, pps: int = 8000):
        ts_gen = TimestampGenerator(start_time, pps, burst_mode=False, seed=self.seed)

        # IPs de resolvers DNS conocidos (simulando respuestas)
        dns_servers = [
            '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
            '208.67.222.222', '208.67.220.220'
        ]

        for i in range(num_packets):
            src_ip = self.rng.choice(dns_servers)
            dport = self.rng.randint(1024, 65535)

            # Genera consulta DNS realista
            dns_payload = self.payload_gen.dns_query()

            # Amplifica: respuesta típica es ~10x más grande
            amplified_data = dns_payload * self.rng.randint(8, 15)

            ttl = TTLDistribution.sample(self.rng)

            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl, id=self.rng.randint(0, 65535)) /
                   UDP(sport=53, dport=dport) /
                   Raw(load=amplified_data))

            pkt.time = ts_gen.next()
            writer.write(pkt)


class NTPAmplificationGenerator(AttackGenerator):
    """Generador de NTP Amplification realista"""

    def generate_streaming(self, writer: PcapWriter, num_packets: int,
                          start_time: float, pps: int = 7000):
        ts_gen = TimestampGenerator(start_time, pps, burst_mode=False, seed=self.seed)

        # IPs de servidores NTP conocidos
        ntp_servers = [f"129.6.15.{i}" for i in range(1, 30)]

        for i in range(num_packets):
            src_ip = self.rng.choice(ntp_servers)
            dport = self.rng.randint(1024, 65535)

            # Payload NTP monlist (típicamente 468-600 bytes de respuesta)
            ntp_payload = self.payload_gen.ntp_monlist()
            amplified = ntp_payload + self.payload_gen.random_bytes(self.rng.randint(400, 550))

            ttl = TTLDistribution.sample(self.rng)

            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl, id=self.rng.randint(0, 65535)) /
                   UDP(sport=123, dport=dport) /
                   Raw(load=amplified))

            pkt.time = ts_gen.next()
            writer.write(pkt)


class HTTPFloodGenerator(AttackGenerator):
    """Generador de HTTP Flood realista"""

    def generate_streaming(self, writer: PcapWriter, num_packets: int,
                          start_time: float, pps: int = 3000):
        ts_gen = TimestampGenerator(start_time, pps, burst_mode=False, seed=self.seed)

        for i in range(num_packets):
            src_ip = self.ip_gen.random_public_ip()
            sport = self.rng.randint(10000, 60000)
            dport = self.rng.choice([80, 443, 8080, 8000])

            # Alterna entre GET y POST
            if self.rng.random() < 0.7:
                http_payload = self.payload_gen.http_get()
            else:
                http_payload = self.payload_gen.http_post(self.rng.randint(50, 500))

            ttl = TTLDistribution.sample(self.rng)

            # Flags realistas: PSH+ACK para datos HTTP
            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl, id=self.rng.randint(0, 65535)) /
                   TCP(sport=sport, dport=dport, flags='PA',
                       seq=self.rng.randint(0, 2**32 - 1),
                       ack=self.rng.randint(0, 2**32 - 1),
                       window=self.rng.choice([5840, 8192, 16384])) /
                   Raw(load=http_payload))

            pkt.time = ts_gen.next()
            writer.write(pkt)


class ICMPFloodGenerator(AttackGenerator):
    """Generador de ICMP Flood realista"""

    def generate_streaming(self, writer: PcapWriter, num_packets: int,
                          start_time: float, pps: int = 5000):
        ts_gen = TimestampGenerator(start_time, pps, burst_mode=True, seed=self.seed)

        for i in range(num_packets):
            src_ip = self.ip_gen.random_public_ip()

            # Tipos ICMP variados
            icmp_type = self.rng.choice([
                8,   # Echo Request (ping)
                0,   # Echo Reply
                3,   # Destination Unreachable
                11   # Time Exceeded
            ])

            # Tamaño variable
            payload_size = self.rng.randint(56, 1400)
            payload = self.payload_gen.random_bytes(payload_size)

            ttl = TTLDistribution.sample(self.rng)

            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl, id=self.rng.randint(0, 65535)) /
                   ICMP(type=icmp_type, id=self.rng.randint(0, 65535)) /
                   Raw(load=payload))

            pkt.time = ts_gen.next()
            writer.write(pkt)


class FragmentationAttackGenerator(AttackGenerator):
    """Generador de ataque de fragmentación realista"""

    def generate_streaming(self, writer: PcapWriter, num_packets: int,
                          start_time: float, pps: int = 5000):
        ts_gen = TimestampGenerator(start_time, pps, burst_mode=True, seed=self.seed)

        num_complete = num_packets // 4  # Cada "paquete original" se fragmenta en ~4

        for i in range(num_complete):
            src_ip = self.ip_gen.random_public_ip()
            ttl = TTLDistribution.sample(self.rng)
            ip_id = self.rng.randint(0, 65535)

            # Número variable de fragmentos
            num_frags = self.rng.randint(3, 6)
            frag_size = self.rng.randint(8, 64)

            for frag_idx in range(num_frags):
                is_last = (frag_idx == num_frags - 1)
                flags = 0 if is_last else 1  # MF (More Fragments)
                offset = frag_idx * (frag_size // 8)

                payload = self.payload_gen.random_bytes(frag_size)

                pkt = (Ether() /
                       IP(src=src_ip, dst=self.target_ip, ttl=ttl,
                          id=ip_id, flags=flags, frag=offset) /
                       Raw(load=payload))

                pkt.time = ts_gen.next()
                writer.write(pkt)


class ACKFloodGenerator(AttackGenerator):
    """Generador de ACK Flood realista"""

    def generate_streaming(self, writer: PcapWriter, num_packets: int,
                          start_time: float, pps: int = 9000):
        ts_gen = TimestampGenerator(start_time, pps, burst_mode=True, seed=self.seed)

        for i in range(num_packets):
            src_ip = self.ip_gen.random_public_ip()
            sport = self.rng.randint(1024, 65535)
            dport = self.rng.choice([80, 443, 22, 21])

            ttl = TTLDistribution.sample(self.rng)

            # ACK con window size variable (incluso 0 para mayor impacto)
            window = self.rng.choice([0, 0, 0, 512, 1024, 5840])  # Sesgo hacia 0

            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl, id=self.rng.randint(0, 65535)) /
                   TCP(sport=sport, dport=dport, flags='A',
                       seq=self.rng.randint(0, 2**32 - 1),
                       ack=self.rng.randint(0, 2**32 - 1),
                       window=window))

            pkt.time = ts_gen.next()
            writer.write(pkt)


class VolumetricMixGenerator(AttackGenerator):
    """Generador de ataque volumétrico mixto"""

    def __init__(self, target_ip: str, seed: Optional[int] = None,
                 sampler: Optional[DistributionSampler] = None,
                 mix_ratios: Optional[Dict[str, float]] = None):
        super().__init__(target_ip, seed, sampler)

        # Ratios por defecto
        self.mix_ratios = mix_ratios or {
            'syn': 0.30,
            'udp': 0.35,
            'icmp': 0.15,
            'ack': 0.20
        }

        # Normalizar para que sumen 1.0
        total = sum(self.mix_ratios.values())
        self.mix_ratios = {k: v / total for k, v in self.mix_ratios.items()}

        # Crear generadores individuales
        self.generators = {
            'syn': SYNFloodGenerator(target_ip, seed, sampler),
            'udp': UDPFloodGenerator(target_ip, seed + 1 if seed else None, sampler),
            'icmp': ICMPFloodGenerator(target_ip, seed + 2 if seed else None, sampler),
            'ack': ACKFloodGenerator(target_ip, seed + 3 if seed else None, sampler)
        }

    def generate_streaming(self, writer: PcapWriter, num_packets: int,
                          start_time: float, pps: int = 20000):
        """Genera mezcla de ataques intercalados temporalmente"""

        # Calcular cuántos paquetes de cada tipo
        packet_counts = {
            k: int(num_packets * ratio)
            for k, ratio in self.mix_ratios.items()
        }

        # Generar paquetes de forma intercalada
        ts_gen = TimestampGenerator(start_time, pps, burst_mode=True, seed=self.seed)

        # Crear cola de tipos de ataque
        attack_queue = []
        for attack_type, count in packet_counts.items():
            attack_queue.extend([attack_type] * count)

        self.rng.shuffle(attack_queue)

        # Generar paquetes según la cola mezclada
        for attack_type in attack_queue:
            # Usar el generador apropiado para crear un paquete
            gen = self.generators[attack_type]

            # Generar un solo paquete (hack: llamamos con num_packets=1)
            # Para eficiencia, deberíamos refactorizar para generar individual
            # Aquí simplificamos llamando al método específico
            self._generate_single_packet(writer, attack_type, ts_gen)

    def _generate_single_packet(self, writer: PcapWriter, attack_type: str, ts_gen):
        """Helper para generar un solo paquete del tipo especificado"""
        gen = self.generators[attack_type]

        if attack_type == 'syn':
            src_ip = gen.ip_gen.random_public_ip()
            sport = gen.rng.randint(1024, 65535)
            dport = gen.rng.choice([80, 443, 8080])
            ttl = TTLDistribution.sample(gen.rng)
            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl) /
                   TCP(sport=sport, dport=dport, flags='S', seq=gen.rng.randint(0, 2**32-1)))

        elif attack_type == 'udp':
            src_ip = gen.ip_gen.random_public_ip()
            sport = gen.rng.randint(1024, 65535)
            dport = gen.rng.choice([53, 123, 161])
            ttl = TTLDistribution.sample(gen.rng)
            payload = gen.payload_gen.random_bytes(gen.rng.randint(64, 512))
            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl) /
                   UDP(sport=sport, dport=dport) /
                   Raw(load=payload))

        elif attack_type == 'icmp':
            src_ip = gen.ip_gen.random_public_ip()
            ttl = TTLDistribution.sample(gen.rng)
            payload = gen.payload_gen.random_bytes(gen.rng.randint(56, 1400))
            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl) /
                   ICMP(type=8) /
                   Raw(load=payload))

        elif attack_type == 'ack':
            src_ip = gen.ip_gen.random_public_ip()
            sport = gen.rng.randint(1024, 65535)
            dport = gen.rng.choice([80, 443, 22])
            ttl = TTLDistribution.sample(gen.rng)
            pkt = (Ether() /
                   IP(src=src_ip, dst=self.target_ip, ttl=ttl) /
                   TCP(sport=sport, dport=dport, flags='A',
                       seq=gen.rng.randint(0, 2**32-1),
                       ack=gen.rng.randint(0, 2**32-1),
                       window=0))

        pkt.time = ts_gen.next()
        writer.write(pkt)


# Registro de generadores disponibles
ATTACK_GENERATORS = {
    'syn_flood': SYNFloodGenerator,
    'udp_flood': UDPFloodGenerator,
    'dns_amp': DNSAmplificationGenerator,
    'ntp_amp': NTPAmplificationGenerator,
    'http_flood': HTTPFloodGenerator,
    'icmp_flood': ICMPFloodGenerator,
    'fragmentation': FragmentationAttackGenerator,
    'ack_flood': ACKFloodGenerator,
    'volumetric': VolumetricMixGenerator,
}
