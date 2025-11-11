"""
Inferencia de modelos ML para detección en tiempo real
"""
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional
import time


class ModelInferencer:
    """Realiza inferencia con modelos ML pre-entrenados"""

    def __init__(self, model_path: Optional[str] = None, threshold: float = 0.5):
        self.model_path = Path(model_path) if model_path else None
        self.threshold = threshold
        self.model = None
        self.feature_names = None
        if self.model_path and self.model_path.exists():
            self.load_model()

    def load_model(self):
        """Carga modelo desde disco"""
        if not self.model_path or not self.model_path.exists():
            print(f"[!] Modelo no encontrado: {self.model_path}")
            print(f"[!] Funcionando en modo rule-based")
            return
        print(f"[*] Cargando modelo: {self.model_path}")
        with open(self.model_path, 'rb') as f:
            model_data = pickle.load(f)
        if isinstance(model_data, dict):
            self.model = model_data.get('model')
            self.feature_names = model_data.get('feature_names')
        else:
            self.model = model_data
        print(f"[+] Modelo cargado: {type(self.model).__name__}")

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        """Predice probabilidades de ataque"""
        if self.model is None:
            return self._rule_based_scoring(features)
        try:
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(features)
                return proba[:, 1] if proba.shape[1] > 1 else proba.flatten()
            else:
                return self.model.predict(features)
        except Exception as e:
            print(f"[!] Error en predicción: {e}")
            return self._rule_based_scoring(features)

    def predict(self, features: np.ndarray) -> np.ndarray:
        """Predice clases binarias (0=normal, 1=ataque)"""
        proba = self.predict_proba(features)
        return (proba >= self.threshold).astype(int)

    def _rule_based_scoring(self, features: np.ndarray) -> np.ndarray:
        """Sistema de scoring basado en reglas (fallback sin modelo ML)"""
        scores = []
        for sample in features:
            score = 0.0
            if len(sample) > 0 and sample[0] > 2.0:
                score += 0.3
            if len(sample) > 1 and sample[1] > 2.0:
                score += 0.2
            if len(sample) > 7 and sample[7] > 1.5:
                score += 0.3
            if len(sample) > 5 and sample[5] > 1.5:
                score += 0.25
            scores.append(min(score, 1.0))
        return np.array(scores)

    def detect_attack_type(self, features: np.ndarray,
                          feature_names: List[str]) -> List[str]:
        """Clasifica tipo de ataque basándose en features"""
        attack_types = []
        feat_idx = {name: i for i, name in enumerate(feature_names)}
        for sample in features:
            detected = []
            if 'syn_ratio' in feat_idx and sample[feat_idx['syn_ratio']] > 0.7:
                detected.append('SYN_FLOOD')
            if 'udp_ratio' in feat_idx and sample[feat_idx['udp_ratio']] > 0.8:
                detected.append('UDP_FLOOD')
            if 'frag_ratio' in feat_idx and sample[feat_idx['frag_ratio']] > 0.3:
                detected.append('FRAGMENTATION')
            attack_types.append(detected if detected else ['NORMAL'])
        return attack_types

    def real_time_inference(self, features_df: pd.DataFrame,
                           feature_cols: List[str]) -> Dict:
        """Inferencia en tiempo real sobre ventana de datos"""
        X = features_df[feature_cols].values
        start_time = time.time()
        proba = self.predict_proba(X)
        predictions = (proba >= self.threshold).astype(int)
        inference_time = time.time() - start_time
        attack_types = self.detect_attack_type(X, feature_cols)
        results = {
            'timestamp': time.time(),
            'num_samples': len(features_df),
            'num_attacks_detected': int(predictions.sum()),
            'max_attack_probability': float(proba.max()),
            'mean_attack_probability': float(proba.mean()),
            'inference_time_ms': inference_time * 1000,
            'predictions': predictions.tolist(),
            'probabilities': proba.tolist(),
            'attack_types': attack_types,
        }
        return results
