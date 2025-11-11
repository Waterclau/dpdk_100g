#!/usr/bin/env python3
"""
Script standalone para generar tráfico benigno
"""
import argparse
from pathlib import Path
from benign_traffic import generate_benign_pcap


def main():
    parser = argparse.ArgumentParser(
        description='Generador de tráfico benigno realista',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Generar tráfico normal por 60 segundos
  sudo python3 -m attack_generator.generate_benign --output /local/pcaps/benign.pcap

  # Generar tráfico ligero por 120 segundos
  sudo python3 -m attack_generator.generate_benign --output benign_light.pcap --duration 120 --profile light

  # Generar tráfico pesado con seed específico
  sudo python3 -m attack_generator.generate_benign --output benign_heavy.pcap --profile heavy --seed 42
        """
    )

    parser.add_argument('--output', '-o', type=str, required=True,
                       help='Archivo PCAP de salida')
    parser.add_argument('--duration', '-d', type=int, default=60,
                       help='Duración en segundos (default: 60)')
    parser.add_argument('--profile', '-p', type=str,
                       choices=['light', 'normal', 'heavy'], default='normal',
                       help='Perfil de tráfico: light (~10 eventos/s), normal (~50 eventos/s), heavy (~200 eventos/s)')
    parser.add_argument('--seed', '-s', type=int, default=None,
                       help='Seed para reproducibilidad')

    args = parser.parse_args()

    # Crear directorio si no existe
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Generar tráfico benigno
    generate_benign_pcap(
        output_file=args.output,
        duration_sec=args.duration,
        traffic_profile=args.profile,
        seed=args.seed
    )


if __name__ == '__main__':
    main()
