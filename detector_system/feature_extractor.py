"""
Extractor de características para detección ML de DDoS
"""
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict
import math


class FeatureExtractor:
    """Extrae features desde logs del detector DPDK"""

    def __init__(self, detection_log: str, ml_features_log: str):
        self.detection_log = Path(detection_log)
        self.ml_features_log = Path(ml_features_log)

    def load_detection_log(self) -> pd.DataFrame:
        """Carga log de detección básico"""
        if not self.detection_log.exists():
            raise FileNotFoundError(f"Log no encontrado: {self.detection_log}")
        df = pd.read_csv(self.detection_log)
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        return df

    def load_ml_features(self) -> pd.DataFrame:
        """Carga features ML pre-calculadas"""
        if not self.ml_features_log.exists():
            raise FileNotFoundError(f"Log ML no encontrado: {self.ml_features_log}")
        df = pd.read_csv(self.ml_features_log)
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        return df

    def extract_statistical_features(self, df: pd.DataFrame,
                                    window_size: int = 10) -> pd.DataFrame:
        """Extrae features estadísticas sobre ventanas temporales"""
        features = []
        for i in range(len(df) - window_size + 1):
            window = df.iloc[i:i+window_size]
            feature_dict = {
                'timestamp': window['timestamp'].iloc[-1],
                'pps_mean': window['pps'].mean(),
                'pps_std': window['pps'].std(),
                'pps_max': window['pps'].max(),
                'gbps_mean': window['gbps'].mean(),
                'tcp_ratio_mean': window['tcp_ratio'].mean(),
                'udp_ratio_mean': window['udp_ratio'].mean(),
                'syn_ratio_mean': window['syn_ratio'].mean(),
                'frag_ratio_mean': window['frag_ratio'].mean(),
            }
            features.append(feature_dict)
        return pd.DataFrame(features)

    def extract_attack_signatures(self, df: pd.DataFrame) -> Dict[str, float]:
        """Extrae firmas características de diferentes tipos de ataques"""
        signatures = {}
        if 'syn_ratio' in df.columns:
            high_syn = (df['syn_ratio'] > 0.7).sum() / len(df)
            signatures['syn_flood_score'] = high_syn
        if 'udp_ratio' in df.columns:
            high_udp = (df['udp_ratio'] > 0.8).sum() / len(df)
            signatures['udp_flood_score'] = high_udp
        return signatures

    def prepare_ml_features(self, df: pd.DataFrame,
                           feature_cols: Optional[List[str]] = None) -> np.ndarray:
        """Prepara features para inferencia ML"""
        if feature_cols is None:
            feature_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            if 'timestamp' in feature_cols:
                feature_cols.remove('timestamp')
        X = df[feature_cols].values
        X_normalized = (X - X.mean(axis=0)) / (X.std(axis=0) + 1e-8)
        return X_normalized

    def export_features(self, df: pd.DataFrame, output_path: str):
        """Exporta features a CSV para entrenamiento"""
        output_path = Path(output_path)
        df.to_csv(output_path, index=False)
        print(f"[+] Features exportadas: {output_path}")
        print(f"    Shape: {df.shape}")
