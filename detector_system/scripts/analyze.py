#!/usr/bin/env python3
"""
Análisis de logs del detector en tiempo real o post-mortem
"""
import argparse
import sys
from pathlib import Path

# Añadir path al módulo
sys.path.insert(0, str(Path(__file__).parent.parent))

from feature_extractor import FeatureExtractor
from model_inferencer import ModelInferencer
from config import DetectorConfig


def main():
    parser = argparse.ArgumentParser(
        description='Análisis de logs del detector DDoS'
    )

    parser.add_argument('--detection-log', type=str,
                       default='/local/logs/detection.log',
                       help='Path al log de detección')
    parser.add_argument('--ml-features-log', type=str,
                       default='/local/logs/ml_features.csv',
                       help='Path al log de features ML')
    parser.add_argument('--model-path', type=str,
                       default='/local/models/xgboost_detector.pkl',
                       help='Path al modelo ML')
    parser.add_argument('--window-size', type=int, default=10,
                       help='Tamaño de ventana para features estadísticas')
    parser.add_argument('--export-features', type=str,
                       help='Exportar features a CSV')

    args = parser.parse_args()

    print("═" * 60)
    print("  Análisis de Logs del Detector DDoS")
    print("═" * 60)
    print()

    # Cargar logs
    print("[*] Cargando logs...")
    extractor = FeatureExtractor(args.detection_log, args.ml_features_log)

    try:
        ml_features_df = extractor.load_ml_features()
        print(f"[+] Features ML cargadas: {len(ml_features_df)} muestras")
        print(f"    Columnas: {list(ml_features_df.columns)}")
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        return

    # Extraer firmas de ataque
    print("\n[*] Analizando firmas de ataque...")
    signatures = extractor.extract_attack_signatures(ml_features_df)
    print("[+] Scores de ataque:")
    for attack_type, score in signatures.items():
        print(f"    {attack_type}: {score:.2%}")

    # Inferencia ML
    print("\n[*] Inferencia ML...")
    inferencer = ModelInferencer(args.model_path, threshold=0.5)

    feature_cols = [col for col in ml_features_df.columns
                   if col != 'timestamp']

    results = inferencer.real_time_inference(ml_features_df, feature_cols)

    print(f"[+] Resultados:")
    print(f"    Muestras analizadas: {results['num_samples']}")
    print(f"    Ataques detectados: {results['num_attacks_detected']}")
    print(f"    Probabilidad máxima: {results['max_attack_probability']:.2%}")
    print(f"    Probabilidad media: {results['mean_attack_probability']:.2%}")
    print(f"    Tiempo de inferencia: {results['inference_time_ms']:.2f} ms")

    # Exportar features si se solicita
    if args.export_features:
        print(f"\n[*] Exportando features a {args.export_features}...")
        extractor.export_features(ml_features_df, args.export_features)

    print("\n[+] Análisis completado")


if __name__ == '__main__':
    main()
