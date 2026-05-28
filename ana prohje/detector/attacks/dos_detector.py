"""
dos_detector.py
---------------
Random Forest tabanlı DoS (Denial of Service) saldırı dedektörü.

Model `temizlik/train_cic_http.py` ile CIC-IDS2018 gerçek verisi kullanılarak
eğitilir ve `models/dos_model.pkl` olarak kaydedilir.
"""

import os
import pickle
import numpy as np

from detector.base_attack import BaseAttackDetector
from detector.attack_registry import register
from detector.feature_extractor import get_feature_vector

_MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models")
_MODEL_PATH   = os.path.join(_MODELS_DIR, "dos_model.pkl")
_SCALER_PATH  = os.path.join(_MODELS_DIR, "ml_scaler.pkl")
_ENCODER_PATH = os.path.join(_MODELS_DIR, "ml_encoder.pkl")


@register
class DosDetector(BaseAttackDetector):
    """
    CIC-IDS2018 gerçek verisiyle eğitilmiş Random Forest tabanlı DoS dedektörü.
    3 sınıflı model (Benign / BruteForce / DoS) — DoS olasılığını döndürür.
    """

    name = "dos"

    def __init__(self):
        for path in (_MODEL_PATH, _SCALER_PATH, _ENCODER_PATH):
            if not os.path.exists(os.path.normpath(path)):
                raise FileNotFoundError(
                    f"Model dosyası bulunamadı: {path}\n"
                    "Lütfen önce 'python train_cic_http.py' komutunu çalıştırın."
                )
        with open(os.path.normpath(_MODEL_PATH), 'rb') as f:
            self._model = pickle.load(f)
        with open(os.path.normpath(_SCALER_PATH), 'rb') as f:
            self._scaler = pickle.load(f)
        with open(os.path.normpath(_ENCODER_PATH), 'rb') as f:
            self._encoder = pickle.load(f)

        classes = list(self._encoder.classes_)
        self._dos_idx = classes.index('DoS') if 'DoS' in classes else 2
        self._threshold = 0.55

    def _proba(self, features: dict) -> float:
        return float(self._proba_batch([features])[0])

    def _proba_batch(self, features_list: list[dict]) -> np.ndarray:
        import pandas as pd
        vectors = [get_feature_vector(f) for f in features_list]
        df = pd.DataFrame(vectors, columns=self._scaler.feature_names_in_)
        vec_scaled = self._scaler.transform(df)
        probas = self._model.predict_proba(vec_scaled)
        return probas[:, self._dos_idx]

    def detect(self, features: dict) -> bool:
        return self._proba(features) >= self._threshold

    def detect_batch(self, features_list: list[dict]) -> list[bool]:
        return [self.detect(f) for f in features_list]

    def confidence(self, features: dict) -> float:
        return round(self._proba(features), 4)

    def score_breakdown(self, features: dict) -> dict:
        ml = round(self._proba(features), 4)
        return {"rule_conf": 0.0, "ml_conf": ml}

    def confidence_batch(self, features_list: list[dict]) -> list[float]:
        return [self.confidence(f) for f in features_list]
