"""
Utilidades para generación realista de paquetes
"""
import random
import time
import math
import json
import numpy as np
from scapy.all import Raw
from typing import Dict, List, Tuple
from collections import defaultdict


class TimestampGenerator:
    """Genera timestamps realistas con variabilidad temporal"""

    def __init__(self, start_time=None, pps=1000, burst_mode=False, seed=None):
        self.start_time = start_time or time.time()
        self.current_time = self.start_time
        self.pps = pps
        self.burst_mode = burst_mode
        self.rng = random.Random(seed)

    def next(self):
        """Obtiene el siguiente timestamp con jitter realista"""
        if self.burst_mode:
            # Modelo de ráfagas: períodos de alta actividad alternados
            if self.rng.random() < 0.3:  # 30% del tiempo en ráfaga
                interval = 1.0 / (self.pps * 5)  # 5x más rápido
            else:
                interval = 1.0 / (self.pps * 0.5)  # 2x más lento
        else:
            # Distribución normal con media = 1/pps
            interval = self.rng.gauss(1.0 / self.pps, 1.0 / (self.pps * 10))
            interval = max(0, interval)  # No negativos

        self.current_time += interval
        return self.current_time


class DistributionSampler:
    """Samplea valores desde distribuciones extraídas de datasets"""

    def __init__(self, seed=None):
        self.rng = np.random.default_rng(seed)
        self.distributions = {}

    def add_distribution(self, name: str, values: List[float], use_kde=False):
        """Agrega una distribución desde valores observados"""
        if use_kde:
            # Kernel Density Estimation para distribuciones complejas
            from scipy.stats import gaussian_kde
            kde = gaussian_kde(values)
            self.distributions[name] = ('kde', kde, min(values), max(values))
        else:
            # Histograma simple
            self.distributions[name] = ('values', values)

    def sample(self, name: str, default=None):
        """Samplea un valor de la distribución"""
        if name not in self.distributions:
            return default

        dist_type, *dist_data = self.distributions[name]

        if dist_type == 'kde':
            kde, min_val, max_val = dist_data
            val = kde.resample(1, seed=self.rng)[0][0]
            return np.clip(val, min_val, max_val)
        else:
            values = dist_data[0]
            return self.rng.choice(values)

    def load_from_json(self, filepath: str):
        """Carga distribuciones desde JSON"""
        with open(filepath, 'r') as f:
            data = json.load(f)
            for name, values in data.items():
                self.add_distribution(name, values)


class RealisticPayloadGenerator:
    """Genera payloads realistas para diferentes protocolos"""

    def __init__(self, seed=None):
        self.rng = random.Random(seed)

    def http_get(self, paths=None):
        """Genera request HTTP GET realista"""
        paths = paths or ['/', '/index.html', '/api/data', '/login', '/search']
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/95.0',
            'curl/7.68.0'
        ]

        path = self.rng.choice(paths)
        ua = self.rng.choice(user_agents)

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: example.com\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: */*\r\n"
            f"Connection: keep-alive\r\n\r\n"
        )
        return request.encode()

    def http_post(self, data_size=100):
        """Genera request HTTP POST realista"""
        data = ''.join(self.rng.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=data_size))
        request = (
            f"POST /api/submit HTTP/1.1\r\n"
            f"Host: example.com\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(data)}\r\n\r\n"
            f"{data}"
        )
        return request.encode()

    def dns_query(self, domains=None):
        """Genera consulta DNS realista"""
        from scapy.all import DNS, DNSQR

        domains = domains or [
            'google.com', 'facebook.com', 'amazon.com',
            'twitter.com', 'reddit.com', 'github.com'
        ]
        domain = self.rng.choice(domains)

        dns = DNS(
            id=self.rng.randint(1, 65535),
            qr=0,  # Query
            opcode=0,  # Standard query
            rd=1,  # Recursion desired
            qd=DNSQR(qname=domain, qtype='A')
        )
        return bytes(dns)

    def ntp_monlist(self):
        """Genera request NTP monlist (usado en amplificación)"""
        # NTP mode 7 (private), implementation 3 (XNTPD), request code 42 (MON_GETLIST_1)
        ntp_packet = b'\x17\x00\x03\x2a' + b'\x00' * 4
        return ntp_packet

    def random_bytes(self, size, long_tail=False):
        """Genera bytes aleatorios con distribución opcional long-tail"""
        if long_tail and self.rng.random() < 0.1:
            # 10% de los paquetes son mucho más grandes
            size = int(size * self.rng.uniform(2, 10))

        return bytes(self.rng.getrandbits(8) for _ in range(size))


class PacketSizeDistribution:
    """Modela distribuciones realistas de tamaños de paquete"""

    COMMON_SIZES = [
        (40, 0.15),    # TCP ACK puro
        (52, 0.10),    # TCP con opciones
        (64, 0.12),    # Mínimo Ethernet
        (128, 0.08),
        (256, 0.08),
        (512, 0.10),
        (1024, 0.12),
        (1460, 0.15),  # MSS típico
        (1500, 0.10),  # MTU Ethernet
    ]

    @staticmethod
    def sample(rng: random.Random) -> int:
        """Samplea un tamaño común de paquete"""
        sizes, weights = zip(*PacketSizeDistribution.COMMON_SIZES)
        return rng.choices(sizes, weights=weights)[0]


class TTLDistribution:
    """Modela distribuciones realistas de TTL"""

    COMMON_TTLS = [64, 128, 255]  # Linux, Windows, Cisco

    @staticmethod
    def sample(rng: random.Random) -> int:
        """Samplea un TTL realista con variación"""
        base_ttl = rng.choice(TTLDistribution.COMMON_TTLS)
        # Simular saltos: restar un valor pequeño
        hops = rng.randint(5, 20)
        return max(1, base_ttl - hops)


class IPGenerator:
    """Genera direcciones IP realistas con distribuciones configurables"""

    def __init__(self, seed=None):
        self.rng = random.Random(seed)

    def random_public_ip(self):
        """Genera IP pública aleatoria (evitando rangos privados/reservados)"""
        while True:
            a = self.rng.randint(1, 223)
            # Evitar rangos privados y especiales
            if a in [10, 127] or (a == 172 and 16 <= self.rng.randint(0, 31) <= 31) or (a == 192 and self.rng.randint(0, 255) == 168):
                continue
            b = self.rng.randint(0, 255)
            c = self.rng.randint(0, 255)
            d = self.rng.randint(1, 254)
            return f"{a}.{b}.{c}.{d}"

    def from_subnet(self, subnet: str):
        """Genera IP dentro de una subnet (ej: 192.168.1.0/24)"""
        parts = subnet.split('/')
        base = parts[0].split('.')
        prefix = int(parts[1]) if len(parts) > 1 else 24

        # Simple: solo último octeto aleatorio para /24
        if prefix == 24:
            return f"{base[0]}.{base[1]}.{base[2]}.{self.rng.randint(1, 254)}"
        else:
            # Para otros prefijos, generar según máscara
            host_bits = 32 - prefix
            base_int = sum(int(b) << (8 * (3 - i)) for i, b in enumerate(base))
            host = self.rng.randint(1, (1 << host_bits) - 2)
            ip_int = base_int + host
            return '.'.join(str((ip_int >> (8 * (3 - i))) & 0xFF) for i in range(4))


def extract_dataset_distributions(pcap_path: str, output_json: str = None) -> Dict:
    """
    Extrae distribuciones estadísticas de un PCAP de referencia

    Returns:
        Dict con distribuciones de: packet_sizes, ttls, src_ports, dst_ports, inter_arrival_times
    """
    from scapy.all import rdpcap, IP, TCP, UDP

    print(f"[*] Analizando {pcap_path}...")
    packets = rdpcap(pcap_path)

    stats = {
        'packet_sizes': [],
        'ttls': [],
        'src_ports': [],
        'dst_ports': [],
        'inter_arrival_times': []
    }

    last_time = None

    for pkt in packets:
        # Tamaños
        stats['packet_sizes'].append(len(pkt))

        # IP layer
        if IP in pkt:
            stats['ttls'].append(pkt[IP].ttl)

        # Puertos
        if TCP in pkt:
            stats['src_ports'].append(pkt[TCP].sport)
            stats['dst_ports'].append(pkt[TCP].dport)
        elif UDP in pkt:
            stats['src_ports'].append(pkt[UDP].sport)
            stats['dst_ports'].append(pkt[UDP].dport)

        # Inter-arrival times
        if hasattr(pkt, 'time'):
            if last_time is not None:
                stats['inter_arrival_times'].append(float(pkt.time - last_time))
            last_time = pkt.time

    # Guardar a JSON si se especifica
    if output_json:
        with open(output_json, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"[+] Distribuciones guardadas en {output_json}")

    print(f"[+] Estadísticas extraídas: {len(packets)} paquetes")
    return stats
