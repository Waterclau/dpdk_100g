"""
Tests unitarios para los generadores de ataques
"""
import unittest
import tempfile
import os
from pathlib import Path
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, PcapWriter

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from attacks import (
    SYNFloodGenerator, UDPFloodGenerator, DNSAmplificationGenerator,
    ICMPFloodGenerator, ACKFloodGenerator
)
from utils import TimestampGenerator, IPGenerator, RealisticPayloadGenerator


class TestTimestampGenerator(unittest.TestCase):
    """Tests para TimestampGenerator"""

    def test_timestamp_sequence(self):
        """Timestamps deben ser monótonamente crecientes"""
        ts_gen = TimestampGenerator(start_time=1000.0, pps=1000, seed=42)

        timestamps = [ts_gen.next() for _ in range(100)]

        # Verificar que son crecientes
        for i in range(1, len(timestamps)):
            self.assertGreater(timestamps[i], timestamps[i-1])

    def test_pps_aproximado(self):
        """PPS promedio debe estar cerca del objetivo"""
        ts_gen = TimestampGenerator(start_time=0.0, pps=1000, seed=42)

        timestamps = [ts_gen.next() for _ in range(10000)]
        duration = timestamps[-1] - timestamps[0]
        actual_pps = len(timestamps) / duration

        # Permitir 20% de variación
        self.assertAlmostEqual(actual_pps, 1000, delta=200)


class TestIPGenerator(unittest.TestCase):
    """Tests para IPGenerator"""

    def test_random_public_ip_formato(self):
        """IPs generadas deben tener formato válido"""
        ip_gen = IPGenerator(seed=42)

        for _ in range(100):
            ip = ip_gen.random_public_ip()
            parts = ip.split('.')

            self.assertEqual(len(parts), 4)
            for part in parts:
                num = int(part)
                self.assertGreaterEqual(num, 0)
                self.assertLessEqual(num, 255)

    def test_no_private_ips(self):
        """No debe generar IPs privadas comunes"""
        ip_gen = IPGenerator(seed=42)

        for _ in range(100):
            ip = ip_gen.random_public_ip()
            # No debe empezar con 10., 192.168., o 127.
            self.assertFalse(ip.startswith('10.'))
            self.assertFalse(ip.startswith('192.168.'))
            self.assertFalse(ip.startswith('127.'))


class TestRealisticPayloadGenerator(unittest.TestCase):
    """Tests para RealisticPayloadGenerator"""

    def test_http_get_formato(self):
        """HTTP GET debe tener formato válido"""
        payload_gen = RealisticPayloadGenerator(seed=42)

        http_request = payload_gen.http_get()

        self.assertIn(b'GET', http_request)
        self.assertIn(b'HTTP/1.1', http_request)
        self.assertIn(b'Host:', http_request)
        self.assertIn(b'\r\n\r\n', http_request)

    def test_dns_query_no_vacio(self):
        """DNS query no debe estar vacío"""
        payload_gen = RealisticPayloadGenerator(seed=42)

        dns_query = payload_gen.dns_query()

        self.assertIsInstance(dns_query, bytes)
        self.assertGreater(len(dns_query), 0)


class TestAttackGenerators(unittest.TestCase):
    """Tests para generadores de ataques"""

    def setUp(self):
        """Crear directorio temporal para tests"""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_file = os.path.join(self.temp_dir, "test.pcap")

    def tearDown(self):
        """Limpiar archivos temporales"""
        if os.path.exists(self.temp_file):
            os.remove(self.temp_file)
        os.rmdir(self.temp_dir)

    def test_syn_flood_count(self):
        """SYN flood debe generar el número correcto de paquetes"""
        generator = SYNFloodGenerator("10.10.1.2", seed=42)

        num_packets = 100
        with PcapWriter(self.temp_file, sync=True) as writer:
            generator.generate_streaming(writer, num_packets, start_time=1000.0, pps=1000)

        # Leer y verificar
        packets = rdpcap(self.temp_file)
        self.assertEqual(len(packets), num_packets)

    def test_syn_flood_flags(self):
        """SYN flood debe tener flags SYN"""
        generator = SYNFloodGenerator("10.10.1.2", seed=42)

        num_packets = 50
        with PcapWriter(self.temp_file, sync=True) as writer:
            generator.generate_streaming(writer, num_packets, start_time=1000.0, pps=1000)

        packets = rdpcap(self.temp_file)

        # Verificar que todos tienen flag SYN
        for pkt in packets:
            if TCP in pkt:
                self.assertTrue(pkt[TCP].flags & 0x02)  # SYN flag

    def test_udp_flood_protocolo(self):
        """UDP flood debe generar paquetes UDP"""
        generator = UDPFloodGenerator("10.10.1.2", seed=42)

        num_packets = 50
        with PcapWriter(self.temp_file, sync=True) as writer:
            generator.generate_streaming(writer, num_packets, start_time=1000.0, pps=1000)

        packets = rdpcap(self.temp_file)

        # Todos deben ser UDP
        for pkt in packets:
            self.assertIn(UDP, pkt)

    def test_icmp_flood_tipo(self):
        """ICMP flood debe generar paquetes ICMP"""
        generator = ICMPFloodGenerator("10.10.1.2", seed=42)

        num_packets = 50
        with PcapWriter(self.temp_file, sync=True) as writer:
            generator.generate_streaming(writer, num_packets, start_time=1000.0, pps=1000)

        packets = rdpcap(self.temp_file)

        # Todos deben ser ICMP
        for pkt in packets:
            self.assertIn(ICMP, pkt)

    def test_target_ip_correcto(self):
        """Paquetes deben tener el target IP correcto"""
        target = "10.10.1.2"
        generator = SYNFloodGenerator(target, seed=42)

        num_packets = 50
        with PcapWriter(self.temp_file, sync=True) as writer:
            generator.generate_streaming(writer, num_packets, start_time=1000.0, pps=1000)

        packets = rdpcap(self.temp_file)

        for pkt in packets:
            if IP in pkt:
                self.assertEqual(pkt[IP].dst, target)

    def test_ttl_range(self):
        """TTL debe estar en rango razonable"""
        generator = UDPFloodGenerator("10.10.1.2", seed=42)

        num_packets = 100
        with PcapWriter(self.temp_file, sync=True) as writer:
            generator.generate_streaming(writer, num_packets, start_time=1000.0, pps=1000)

        packets = rdpcap(self.temp_file)

        for pkt in packets:
            if IP in pkt:
                ttl = pkt[IP].ttl
                self.assertGreaterEqual(ttl, 1)
                self.assertLessEqual(ttl, 255)

    def test_timestamps_ordenados(self):
        """Timestamps deben estar ordenados"""
        generator = SYNFloodGenerator("10.10.1.2", seed=42)

        num_packets = 100
        with PcapWriter(self.temp_file, sync=True) as writer:
            generator.generate_streaming(writer, num_packets, start_time=1000.0, pps=1000)

        packets = rdpcap(self.temp_file)

        timestamps = [float(pkt.time) for pkt in packets]

        for i in range(1, len(timestamps)):
            self.assertGreaterEqual(timestamps[i], timestamps[i-1])


class TestReproducibilidad(unittest.TestCase):
    """Tests de reproducibilidad con seeds"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_mismo_seed_mismo_resultado(self):
        """Mismo seed debe producir mismos paquetes"""
        seed = 123456
        target = "10.10.1.2"
        num_packets = 100

        # Generar primera vez
        file1 = os.path.join(self.temp_dir, "test1.pcap")
        gen1 = SYNFloodGenerator(target, seed=seed)
        with PcapWriter(file1, sync=True) as writer:
            gen1.generate_streaming(writer, num_packets, start_time=1000.0, pps=1000)

        # Generar segunda vez con mismo seed
        file2 = os.path.join(self.temp_dir, "test2.pcap")
        gen2 = SYNFloodGenerator(target, seed=seed)
        with PcapWriter(file2, sync=True) as writer:
            gen2.generate_streaming(writer, num_packets, start_time=1000.0, pps=1000)

        # Leer ambos
        pkts1 = rdpcap(file1)
        pkts2 = rdpcap(file2)

        self.assertEqual(len(pkts1), len(pkts2))

        # Comparar IPs fuente (deberían ser idénticas con mismo seed)
        ips1 = [pkt[IP].src for pkt in pkts1 if IP in pkt]
        ips2 = [pkt[IP].src for pkt in pkts2 if IP in pkt]

        self.assertEqual(ips1, ips2)


if __name__ == '__main__':
    unittest.main()
