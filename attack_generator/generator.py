#!/usr/bin/env python3
"""
Generador de ataques DDoS realistas para simulación defensiva
"""
import argparse
import json
import time
import sys
import hashlib
from pathlib import Path
from typing import Dict, Optional, List
from scapy.all import PcapWriter, rdpcap, wrpcap

from .attacks import ATTACK_GENERATORS
from .utils import DistributionSampler, extract_dataset_distributions


class AttackPcapGenerator:
    """Orquestador principal de generación de PCAPs"""

    def __init__(self, config: Dict):
        self.config = config
        self.target_ip = config['target_ip']
        self.output_dir = Path(config.get('output_dir', './pcaps'))
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Seed para reproducibilidad
        self.seed = config.get('seed', int(time.time()))

        # Cargar sampler si hay dataset
        self.sampler = None
        if config.get('dataset_path'):
            self.sampler = self._load_dataset(config['dataset_path'])

        # Estadísticas
        self.stats = {}

    def _load_dataset(self, dataset_path: str) -> DistributionSampler:
        """Carga distribuciones desde dataset"""
        print(f"[*] Cargando dataset: {dataset_path}")

        if dataset_path.endswith('.json'):
            sampler = DistributionSampler(self.seed)
            sampler.load_from_json(dataset_path)
        elif dataset_path.endswith('.pcap'):
            # Extraer distribuciones del PCAP
            distributions = extract_dataset_distributions(dataset_path)
            sampler = DistributionSampler(self.seed)
            for name, values in distributions.items():
                if values:
                    sampler.add_distribution(name, values)
        else:
            raise ValueError(f"Formato de dataset no soportado: {dataset_path}")

        print(f"[+] Dataset cargado")
        return sampler

    def generate_attack(self, attack_type: str, num_packets: int,
                       pps: int, dry_run: bool = False) -> Dict:
        """
        Genera un tipo de ataque específico

        Args:
            attack_type: Tipo de ataque (syn_flood, udp_flood, etc.)
            num_packets: Número de paquetes a generar
            pps: Paquetes por segundo
            dry_run: Si es True, solo calcula métricas sin escribir

        Returns:
            Dict con estadísticas de generación
        """
        if attack_type not in ATTACK_GENERATORS:
            raise ValueError(f"Ataque desconocido: {attack_type}")

        output_file = self.output_dir / f"{attack_type}.pcap"

        print(f"\n[*] Generando {attack_type}...")
        print(f"    Paquetes: {num_packets:,}")
        print(f"    PPS: {pps:,}")
        print(f"    Output: {output_file}")

        start_time = time.time()
        generator_class = ATTACK_GENERATORS[attack_type]
        generator = generator_class(self.target_ip, seed=self.seed, sampler=self.sampler)

        if dry_run:
            # Modo dry-run: solo calcular métricas
            duration = num_packets / pps
            estimated_size_mb = (num_packets * 1000) / (1024 * 1024)  # Estimación ~1KB/pkt

            stats = {
                'attack_type': attack_type,
                'num_packets': num_packets,
                'pps': pps,
                'estimated_duration_sec': duration,
                'estimated_size_mb': estimated_size_mb,
                'dry_run': True
            }
        else:
            # Generación real con PcapWriter streaming
            with PcapWriter(str(output_file), append=False, sync=True) as writer:
                gen_start_time = time.time()
                generator.generate_streaming(writer, num_packets, gen_start_time, pps)

            elapsed = time.time() - start_time
            file_size_mb = output_file.stat().st_size / (1024 * 1024)

            stats = {
                'attack_type': attack_type,
                'num_packets': num_packets,
                'pps': pps,
                'duration_sec': elapsed,
                'file_size_mb': file_size_mb,
                'output_file': str(output_file),
                'dry_run': False
            }

        print(f"[+] Completado en {stats.get('duration_sec', stats.get('estimated_duration_sec')):.2f}s")

        self.stats[attack_type] = stats
        return stats

    def mix_with_benign(self, attack_pcap: str, benign_pcap: str,
                       attack_ratio: float = 0.3, output_name: str = "mixed") -> str:
        """
        Mezcla tráfico de ataque con tráfico benigno

        Args:
            attack_pcap: Path al PCAP de ataque
            benign_pcap: Path al PCAP benigno
            attack_ratio: Ratio de paquetes de ataque (0.0-1.0)
            output_name: Nombre del archivo de salida

        Returns:
            Path al PCAP mezclado
        """
        print(f"\n[*] Mezclando con tráfico benigno...")
        print(f"    Ataque: {attack_pcap}")
        print(f"    Benigno: {benign_pcap}")
        print(f"    Ratio ataque: {attack_ratio:.2%}")

        # Cargar ambos PCAPs
        attack_pkts = rdpcap(attack_pcap)
        benign_pkts = rdpcap(benign_pcap)

        print(f"    Paquetes ataque: {len(attack_pkts):,}")
        print(f"    Paquetes benignos: {len(benign_pkts):,}")

        # Calcular cuántos paquetes de cada tipo incluir
        num_attack = int(len(attack_pkts) * attack_ratio)
        num_benign = int(num_attack * (1 - attack_ratio) / attack_ratio)

        # Tomar muestras
        import random
        rng = random.Random(self.seed)
        selected_attack = rng.sample(list(attack_pkts), min(num_attack, len(attack_pkts)))
        selected_benign = rng.sample(list(benign_pkts), min(num_benign, len(benign_pkts)))

        # Mezclar por timestamp
        mixed = selected_attack + selected_benign
        mixed.sort(key=lambda p: p.time if hasattr(p, 'time') else 0)

        # Escribir
        output_file = self.output_dir / f"{output_name}.pcap"
        wrpcap(str(output_file), mixed)

        print(f"[+] PCAP mezclado: {output_file}")
        print(f"    Total paquetes: {len(mixed):,}")

        return str(output_file)

    def save_metadata(self, output_name: str = "metadata.json"):
        """Guarda metadata de la generación"""
        metadata_file = self.output_dir / output_name

        # Calcular checksum de archivos generados
        checksums = {}
        for pcap_file in self.output_dir.glob("*.pcap"):
            with open(pcap_file, 'rb') as f:
                checksums[pcap_file.name] = hashlib.sha256(f.read()).hexdigest()

        metadata = {
            'generation_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'config': self.config,
            'seed': self.seed,
            'stats': self.stats,
            'checksums': checksums
        }

        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        print(f"\n[+] Metadata guardada: {metadata_file}")

    def generate_from_config(self, attacks: List[Dict], dry_run: bool = False):
        """
        Genera múltiples ataques desde una lista de configuraciones

        Args:
            attacks: Lista de dicts con: {type, num_packets, pps}
            dry_run: Si es True, solo simula sin escribir
        """
        print("=" * 60)
        print(f" Generador de Ataques DDoS")
        print(f" Target: {self.target_ip}")
        print(f" Seed: {self.seed}")
        print(f" Output: {self.output_dir}")
        if dry_run:
            print(" [DRY RUN MODE]")
        print("=" * 60)

        for attack_cfg in attacks:
            attack_type = attack_cfg['type']
            num_packets = attack_cfg.get('num_packets', 10000)
            pps = attack_cfg.get('pps', 1000)

            self.generate_attack(attack_type, num_packets, pps, dry_run)

        # Mezcla con benigno si se especifica
        if not dry_run and self.config.get('mix_benign'):
            for attack_type in self.stats.keys():
                attack_pcap = self.output_dir / f"{attack_type}.pcap"
                if attack_pcap.exists():
                    self.mix_with_benign(
                        str(attack_pcap),
                        self.config['mix_benign'],
                        attack_ratio=self.config.get('attack_ratio', 0.3),
                        output_name=f"{attack_type}_mixed"
                    )

        # Guardar metadata
        if not dry_run:
            self.save_metadata()

        print("\n" + "=" * 60)
        print(" Generación completada")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Generador de PCAPs de ataques DDoS realistas',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Generar SYN flood básico
  %(prog)s --target-ip 10.10.1.2 --attack syn_flood --num-packets 100000 --pps 10000

  # Generar múltiples ataques desde JSON
  %(prog)s --config attacks_config.json

  # Mezclar con tráfico benigno
  %(prog)s --target-ip 10.10.1.2 --attack udp_flood --mix-benign benign.pcap

  # Dry-run para ver métricas
  %(prog)s --config attacks_config.json --dry-run

  # Usar dataset para distribuciones realistas
  %(prog)s --target-ip 10.10.1.2 --attack syn_flood --dataset cicids2017_dist.json
        """
    )

    # Parámetros básicos
    parser.add_argument('--target-ip', type=str, default='10.10.1.2',
                       help='IP destino del ataque')
    parser.add_argument('--output-dir', type=str, default='./pcaps',
                       help='Directorio de salida para PCAPs')
    parser.add_argument('--seed', type=int, default=None,
                       help='Seed para reproducibilidad')

    # Configuración de ataque
    parser.add_argument('--attack', type=str, choices=list(ATTACK_GENERATORS.keys()),
                       help='Tipo de ataque a generar')
    parser.add_argument('--num-packets', type=int, default=10000,
                       help='Número de paquetes')
    parser.add_argument('--pps', type=int, default=1000,
                       help='Paquetes por segundo')
    parser.add_argument('--duration', type=int,
                       help='Duración en segundos (alternativa a --num-packets)')

    # Configuración avanzada
    parser.add_argument('--config', type=str,
                       help='Archivo JSON con configuración completa')
    parser.add_argument('--dataset-path', type=str,
                       help='Path a dataset/PCAP para extraer distribuciones')
    parser.add_argument('--mix-benign', type=str,
                       help='PCAP con tráfico benigno para mezclar')
    parser.add_argument('--attack-ratio', type=float, default=0.3,
                       help='Ratio de ataque en mezcla (0.0-1.0)')

    # Modos especiales
    parser.add_argument('--dry-run', action='store_true',
                       help='Solo calcular métricas sin escribir PCAPs')
    parser.add_argument('--extract-dataset', type=str,
                       help='Extraer distribuciones de un PCAP a JSON')

    args = parser.parse_args()

    # Modo especial: extraer dataset
    if args.extract_dataset:
        output_json = args.extract_dataset.replace('.pcap', '_dist.json')
        extract_dataset_distributions(args.extract_dataset, output_json)
        return

    # Construir configuración
    if args.config:
        # Cargar desde JSON
        with open(args.config, 'r') as f:
            config = json.load(f)
    else:
        # Construir desde argumentos CLI
        if not args.attack:
            parser.error("Se requiere --attack o --config")

        # Calcular num_packets si se especifica duration
        num_packets = args.num_packets
        if args.duration:
            num_packets = args.duration * args.pps

        config = {
            'target_ip': args.target_ip,
            'output_dir': args.output_dir,
            'seed': args.seed,
            'dataset_path': args.dataset_path,
            'mix_benign': args.mix_benign,
            'attack_ratio': args.attack_ratio,
            'attacks': [{
                'type': args.attack,
                'num_packets': num_packets,
                'pps': args.pps
            }]
        }

    # Generar
    generator = AttackPcapGenerator(config)
    generator.generate_from_config(config['attacks'], dry_run=args.dry_run)


if __name__ == '__main__':
    main()
