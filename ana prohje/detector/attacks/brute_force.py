"""
brute_force.py
--------------
Brute Force saldırı dedektörü — kural tabanlı skor hesaplama.

Tespit sinyalleri:
  - Aynı IP'den kısa sürede çok sayıda başarısız kimlik doğrulama (401/403)
  - Hassas endpoint'lere (/login, /admin, /wp-login.php) istek
  - POST metodu kullanımı
  - Kısa User-Agent (bot davranışı)
"""

import os
import pickle

from detector.base_attack import BaseAttackDetector
from detector.attack_registry import register
from detector.feature_extractor import get_feature_vector

_MODELS_DIR   = os.path.join(os.path.dirname(__file__), "..", "..", "models")
_MODEL_PATH   = os.path.join(_MODELS_DIR, "dos_model.pkl")
_SCALER_PATH  = os.path.join(_MODELS_DIR, "ml_scaler.pkl")
_ENCODER_PATH = os.path.join(_MODELS_DIR, "ml_encoder.pkl")


_LOGIN_PATHS = [
    "/login", "/admin", "/wp-login.php", "/wp-admin",
    "/api/auth", "/api/login", "/signin", "/authenticate",
    "/user/login", "/auth/login", "/panel", "/dashboard",
]

_THRESHOLD = 0.50


@register
class BruteForceDetector(BaseAttackDetector):
    """
    CIC-IDS2018 gerçek verisiyle eğitilmiş ML + kural tabanlı BruteForce dedektörü.

    Tespit katmanları:
      1. ML modeli (3-sınıf RF): BruteForce olasılığı
      2. Kural tabanlı skor: HTTP-spesifik sinyaller (401/403, login path, vb.)
    Sonuç: max(ml_score, rule_score) >= threshold
    """

    name = "brute_force"

    def __init__(self):
        self._model = self._scaler = self._bf_idx = None
        try:
            with open(os.path.normpath(_MODEL_PATH), 'rb') as f:
                self._model = pickle.load(f)
            with open(os.path.normpath(_SCALER_PATH), 'rb') as f:
                self._scaler = pickle.load(f)
            with open(os.path.normpath(_ENCODER_PATH), 'rb') as f:
                encoder = pickle.load(f)
            classes = list(encoder.classes_)
            self._bf_idx = classes.index('BruteForce') if 'BruteForce' in classes else None
        except FileNotFoundError:
            pass  # ML yüklenemezse kural tabanlı devam eder

    def _ml_score(self, features: dict) -> float:
        if self._model is None or self._bf_idx is None:
            return 0.0
        import pandas as pd
        vec = pd.DataFrame([get_feature_vector(features)],
                           columns=self._scaler.feature_names_in_)
        vec_scaled = self._scaler.transform(vec)
        return float(self._model.predict_proba(vec_scaled)[0, self._bf_idx])

    def _rule_score(self, features: dict) -> float:
        score = 0.0
        if features.get("status_code", 200) in (401, 403):
            score += 0.30
        path = features.get("path", "/").lower().split("?")[0]
        if any(path.startswith(lp) for lp in _LOGIN_PATHS):
            score += 0.25
        rpm = features.get("requests_per_ip_last_60s", 0)
        if rpm > 20:
            score += 0.25
        elif rpm > 10:
            score += 0.10
        if features.get("method", "GET").upper() == "POST":
            score += 0.10
        if features.get("user_agent_length", 100) < 20:
            score += 0.10
        return min(score, 1.0)

    def detect(self, features: dict) -> bool:
        return self.confidence(features) >= _THRESHOLD

    def confidence(self, features: dict) -> float:
        ml   = self._ml_score(features)
        rule = self._rule_score(features)
        combined = min(ml * 0.45 + rule * 0.55, 1.0)
        return round(max(ml, rule, combined), 4)

    def score_breakdown(self, features: dict) -> dict:
        return {
            "rule_conf": round(self._rule_score(features), 4),
            "ml_conf":   round(self._ml_score(features), 4),
        }
