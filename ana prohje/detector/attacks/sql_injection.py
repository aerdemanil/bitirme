"""
sql_injection.py
----------------
SQL Injection saldırı dedektörü — kural tabanlı + ML entegreli.

Tespit katmanları:
  1. Kural tabanlı regex filtresi  : Anlık eşleşme, düşük gecikme
  2. Anomali skoru entegrasyonu    : feature_extractor'dan gelen sqli_* vektörleri
  3. ML uyumlu sinyal üretimi      : confidence() skoru ile tutarlı çıktı

Örüntüler:
  - UNION SELECT kombinasyonları
  - OR 1=1 / AND 1=1 mantıksal enjeksiyonlar
  - Stacked queries (;DROP, ;INSERT)
  - Time-based blind SQLi (SLEEP, WAITFOR)
  - Encoded karakter bypass (%27, %3D vb.)
  - Comment injection (--, /* */)
  - Subquery injection ((SELECT ...))
"""

import re
import os
import pickle
import urllib.parse
from detector.base_attack import BaseAttackDetector
from detector.attack_registry import register
from detector.feature_extractor import SQLI_THRESHOLD, compute_sqli_scores

_MODELS_DIR      = os.path.join(os.path.dirname(__file__), "..", "..", "models")
_SQLI_MODEL_PATH = os.path.join(_MODELS_DIR, "sqli_model.pkl")
_SQLI_VEC_PATH   = os.path.join(_MODELS_DIR, "sqli_vectorizer.pkl")


# ---------------------------------------------------------------------------
# Ek kural-tabanlı filtre (hızlı ön kontrol için)
# ---------------------------------------------------------------------------

# Kesin SQLi saldırı belirtisi — tek başına yeterli
_CRITICAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"union\s+(?:all\s+)?select", re.IGNORECASE),
    re.compile(r";\s*(drop|insert|update|delete|create)\s+", re.IGNORECASE),
    re.compile(r"(sleep|waitfor\s+delay)\s*\(", re.IGNORECASE),
    re.compile(r"information_schema\s*\.", re.IGNORECASE),
    re.compile(r"xp_cmdshell", re.IGNORECASE),
    re.compile(r"load_file\s*\(", re.IGNORECASE),
    re.compile(r"into\s+outfile\s+", re.IGNORECASE),
]

# Orta riskli örüntüler — birden fazlası eşleşirse alarm
_MEDIUM_PATTERNS: list[re.Pattern] = [
    re.compile(r"or\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w*[\'\"]?", re.IGNORECASE),
    re.compile(r"and\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w*[\'\"]?", re.IGNORECASE),
    re.compile(r"[\'\"][\s\w]*[\'\"]?\s+(or|and)\s+[\'\"]", re.IGNORECASE),
    re.compile(r"(/\*.*?\*/|--\s*$)", re.IGNORECASE),
    re.compile(r"0x[0-9a-fA-F]{4,}", re.IGNORECASE),
    re.compile(r"\(\s*select\s+", re.IGNORECASE),
]


def _rule_based_detect(path: str) -> tuple[bool, float]:
    """
    Saf kural tabanlı SQLi tespiti.

    Returns
    -------
    (is_sqli: bool, confidence: float)
    """
    try:
        decoded = urllib.parse.unquote_plus(path).lower()
    except Exception:
        decoded = path.lower()

    # Kritik örüntü → anında tespit
    for pattern in _CRITICAL_PATTERNS:
        if pattern.search(decoded) or pattern.search(path.lower()):
            return True, 0.95

    # Orta riskli — kaç tane eşleşiyor?
    medium_hits = sum(
        1 for p in _MEDIUM_PATTERNS
        if p.search(decoded) or p.search(path.lower())
    )
    if medium_hits >= 2:
        return True, min(0.60 + medium_hits * 0.10, 0.90)
    if medium_hits == 1:
        return False, 0.35

    return False, 0.0


# ---------------------------------------------------------------------------
# Dedektör sınıfı
# ---------------------------------------------------------------------------

@register
class SqlInjectionDetector(BaseAttackDetector):
    """
    SQL Injection saldırı dedektörü — üç katmanlı tespit.

      1. Kural tabanlı regex filtresi (hızlı ön kontrol)
      2. Anomali skoru (feature_extractor)
      3. ML modeli: sqli_model.pkl + sqli_vectorizer.pkl (metin tabanlı TF-IDF)
    """

    name = "sql_injection"

    def __init__(self):
        self._sqli_model = self._sqli_vec = None
        try:
            with open(os.path.normpath(_SQLI_MODEL_PATH), 'rb') as f:
                self._sqli_model = pickle.load(f)
            with open(os.path.normpath(_SQLI_VEC_PATH), 'rb') as f:
                self._sqli_vec = pickle.load(f)
        except FileNotFoundError:
            pass  # ML yüklenemezse diğer katmanlar devam eder

    def _ml_score(self, path: str) -> float:
        if self._sqli_model is None:
            return 0.0
        try:
            # Nginx logundan gelen path: /search?q=%27+OR+%271%27%3D%271
            # Model sadece payload metnini tanıyor, prefix'i at
            parsed = urllib.parse.urlparse(path)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if qs:
                # Tüm query param value'larını birleştir
                text = " ".join(
                    urllib.parse.unquote_plus(v)
                    for values in qs.values()
                    for v in values
                )
            else:
                # Query string yoksa path'i decode et (POST body path vb.)
                text = urllib.parse.unquote_plus(path)
        except Exception:
            text = path
        vec = self._sqli_vec.transform([text])
        return float(self._sqli_model.predict_proba(vec)[0, 1])

    def _get_path(self, features: dict) -> str:
        """features sözlüğünden ham path'i güvenli şekilde alır."""
        return features.get("path", "/")

    def detect(self, features: dict) -> bool:
        return self.confidence(features) >= SQLI_THRESHOLD

    def confidence(self, features: dict) -> float:
        """
        Üç katmanın skorunu birleştirir:
          1. Kural tabanlı regex skoru
          2. Anomali skoru (feature_extractor)
          3. ML model skoru (sqli_model.pkl)

        Her zaman tüm katmanlar hesaplanır; ML daha yüksek skor verirse
        kural sonucunu geçebilir. Anomali + ML ikisi de sub-threshold ama
        aynı yönde işaret ediyorsa ağırlıklı toplam eşiği aşabilir.
        """
        path = self._get_path(features)

        # Katman 1: Kural tabanlı
        _, rule_conf = _rule_based_detect(path)

        # Katman 2: Anomali skoru
        anomaly = features.get("sqli_anomaly_score")
        if anomaly is None:
            anomaly = compute_sqli_scores(path)["sqli_anomaly_score"]
        anomaly = float(anomaly)

        # Katman 3: ML model
        ml_conf = self._ml_score(path)

        # Anomali ve ML birbirini destekliyorsa ağırlıklı kombinasyon
        combined = min(anomaly * 0.55 + ml_conf * 0.45, 1.0)

        return round(max(rule_conf, anomaly, ml_conf, combined), 4)

    def score_breakdown(self, features: dict) -> dict:
        path = self._get_path(features)
        _, rule_conf = _rule_based_detect(path)
        return {
            "rule_conf": round(rule_conf, 4),
            "ml_conf":   round(self._ml_score(path), 4),
        }

    def explain(self, features: dict) -> dict:
        """
        Tespit kararının açıklamasını döner (debugging / dashboard için).

        Returns
        -------
        dict
            rule_hit        : bool   — Kural tabanlı eşleşme var mı
            rule_confidence : float  — Kural skoru
            anomaly_score   : float  — ML anomali skoru
            keyword_score   : float  — Anahtar kelime skoru
            pattern_score   : float  — Regex örüntü skoru
            char_score      : float  — Tehlikeli karakter skoru
            matched_count   : int    — Eşleşen toplam kural sayısı
        """
        path = self._get_path(features)
        rule_hit, rule_conf = _rule_based_detect(path)

        # feature_extractor'dan ya da hesaplanmış skorlar
        sqli_scores = {
            k: features.get(k)
            for k in ("sqli_keyword_score", "sqli_char_score",
                      "sqli_pattern_score", "sqli_anomaly_score",
                      "sqli_matched_count")
        }
        if any(v is None for v in sqli_scores.values()):
            sqli_scores = compute_sqli_scores(path)

        return {
            "rule_hit":        rule_hit,
            "rule_confidence": round(rule_conf, 4),
            "anomaly_score":   sqli_scores.get("sqli_anomaly_score", 0.0),
            "keyword_score":   sqli_scores.get("sqli_keyword_score", 0.0),
            "pattern_score":   sqli_scores.get("sqli_pattern_score", 0.0),
            "char_score":      sqli_scores.get("sqli_char_score", 0.0),
            "matched_count":   sqli_scores.get("sqli_matched_count", 0),
        }
