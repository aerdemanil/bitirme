"""
feature_extractor.py
--------------------
Nginx 'combined' log formatını parse ederek makine öğrenmesi
modellerinin anlayabileceği sayısal özellik vektörlerine dönüştürür.

Nginx combined log formatı:
  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
  "$http_referer" "$http_user_agent" $request_time

SQLi Tespit Vektörleri (v2):
  - sqli_keyword_score  : URL/path'te eşleşen SQL anahtar kelime skoru
  - sqli_char_score     : URL-encoded tehlikeli karakterler (%27 vb.)
  - sqli_pattern_score  : Regex tabanlı saldırı örüntü skoru (UNION SELECT vb.)
  - sqli_anomaly_score  : Toplam anomali skoru (0.0 – 1.0)
"""

import re
import urllib.parse
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Nginx log regex
# ---------------------------------------------------------------------------
_NGINX_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
    r'(?:\s+(?P<req_time>[\d.]+))?'
)

_HTTP_METHODS = [
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "CONNECT", "TRACE",
]

# ---------------------------------------------------------------------------
# Kayan pencere (sliding window) — IP başına istek sayacı
# ---------------------------------------------------------------------------
_WINDOW_SECONDS = 60
_ip_timestamps: dict[str, deque] = defaultdict(deque)


# ---------------------------------------------------------------------------
# SQLi Tespit Sabitleri
# ---------------------------------------------------------------------------

# Yüksek riskli SQL anahtar kelimeleri — her biri belirli bir ağırlık taşır
_SQLI_KEYWORDS: list[tuple[str, float]] = [
    # (keyword, weight)
    ("union",           0.35),
    ("select",          0.30),
    ("insert",          0.25),
    ("update",          0.25),
    ("delete",          0.25),
    ("drop",            0.40),
    ("truncate",        0.40),
    ("exec",            0.35),
    ("execute",         0.35),
    ("cast(",           0.30),
    ("convert(",        0.25),
    ("char(",           0.20),
    ("ascii(",          0.20),
    ("benchmark(",      0.35),
    ("sleep(",          0.35),
    ("waitfor",         0.35),
    ("load_file(",      0.45),
    ("outfile",         0.40),
    ("information_schema", 0.45),
    ("xp_cmdshell",     0.50),
    ("xp_",             0.30),
    ("0x",              0.15),
    ("--",              0.25),
    ("/*",              0.20),
    ("*/",              0.15),
    ("@@version",       0.40),
    ("@@datadir",       0.40),
    # Tautoloji kalıpları (OR/AND tırnak içi eşitlik)
    ("' or '",          0.45),
    ("' and '",         0.40),
    ("or 1=1",          0.50),
    ("and 1=1",         0.45),
    ("or '1'='1",       0.55),
    ("or 1 --",         0.50),
]

# URL-encoded tehlikeli karakterler
_SQLI_ENCODED_CHARS: list[tuple[str, float]] = [
    ("%27",  0.30),   # '  (tek tırnak)
    ("%22",  0.20),   # "  (çift tırnak)
    ("%3D",  0.10),   # =
    ("%3B",  0.15),   # ;
    ("%2D%2D", 0.25), # --
    ("%2F%2A", 0.20), # /*
    ("%23",  0.15),   # #
    ("%60",  0.15),   # `
    ("'",    0.25),   # ham tek tırnak
    ('"',    0.10),   # ham çift tırnak
]

# Regex tabanlı yüksek güvenilirlikli saldırı örüntüleri
_SQLI_PATTERNS: list[tuple[re.Pattern, float]] = [
    # UNION SELECT kombinasyonu
    (re.compile(r"union\s+(?:all\s+)?select", re.IGNORECASE), 0.90),
    # OR 1=1 / OR 'a'='a' / OR '1'='  — \w* son grup opsiyonel (trailing quote yakalar)
    (re.compile(r"or\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w*[\'\"]?", re.IGNORECASE), 0.70),
    # AND 1=1 / AND '1'='
    (re.compile(r"and\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w*[\'\"]?", re.IGNORECASE), 0.60),
    # Tırnak tabanlı tautoloji: ' OR ' / ' AND '
    (re.compile(r"[\'\"][\s\w]*[\'\"]?\s+(or|and)\s+[\'\"]", re.IGNORECASE), 0.75),
    # stacked queries  ;DROP / ;INSERT
    (re.compile(r";\s*(drop|insert|update|delete|create|alter)\s+", re.IGNORECASE), 0.90),
    # time-based blind: SLEEP / WAITFOR DELAY
    (re.compile(r"(sleep|waitfor\s+delay)\s*\(", re.IGNORECASE), 0.85),
    # comment injection
    (re.compile(r"(/\*.*?\*/|--\s*$)", re.IGNORECASE), 0.60),
    # hex encoding bypass
    (re.compile(r"0x[0-9a-fA-F]{4,}", re.IGNORECASE), 0.55),
    # information_schema erişimi
    (re.compile(r"information_schema\s*\.", re.IGNORECASE), 0.85),
    # subquery injection
    (re.compile(r"\(\s*select\s+", re.IGNORECASE), 0.75),
]

# SQLi anomali eşiği — bu değerin üstü saldırı olarak işaretlenir
SQLI_THRESHOLD = 0.50


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _encode_method(method: str) -> int:
    """HTTP metodunu sayısal indekse çevirir."""
    try:
        return _HTTP_METHODS.index(method.upper())
    except ValueError:
        return len(_HTTP_METHODS)  # bilinmeyen metod


def _path_depth(path: str) -> int:
    """URL path'teki segment sayısını döner."""
    return max(0, path.count("/") - 1)


def update_ip_window(ip: str, timestamp: float) -> int:
    """
    IP'nin son `_WINDOW_SECONDS` içindeki istek sayısını günceller ve döner.

    Not: Thread-safe değildir; asyncio veya tek-thread ortamı için uygundur.
    """
    ts_q = _ip_timestamps[ip]
    ts_q.append(timestamp)
    cutoff = timestamp - _WINDOW_SECONDS
    while ts_q and ts_q[0] < cutoff:
        ts_q.popleft()
    return len(ts_q)


# ---------------------------------------------------------------------------
# SQLi Skoring Motoru
# ---------------------------------------------------------------------------

def compute_sqli_scores(raw_path: str) -> dict:
    """
    Ham URL path'i çözümleyerek SQLi anomali skorlarını hesaplar.

    Parameters
    ----------
    raw_path : str
        Nginx log'undan elde edilen ham path (query string dahil).

    Returns
    -------
    dict
        sqli_keyword_score  : float  — SQL anahtar kelime eşleşme skoru
        sqli_char_score     : float  — Tehlikeli karakter skoru
        sqli_pattern_score  : float  — Regex örüntü eşleşme skoru
        sqli_anomaly_score  : float  — Toplam ağırlıklı skor (0.0 – 1.0)
        sqli_matched_count  : int    — Eşleşen toplam kural sayısı
    """
    # URL decode — encoded payload'ları açığa çıkar
    try:
        decoded = urllib.parse.unquote_plus(raw_path).lower()
    except Exception:
        decoded = raw_path.lower()

    raw_lower = raw_path.lower()

    # 1) Anahtar kelime skoru
    keyword_score = 0.0
    matched_count = 0
    for keyword, weight in _SQLI_KEYWORDS:
        if keyword in decoded or keyword in raw_lower:
            keyword_score = min(keyword_score + weight, 1.0)
            matched_count += 1

    # 2) Tehlikeli karakter skoru
    char_score = 0.0
    for char, weight in _SQLI_ENCODED_CHARS:
        if char in raw_path or char in raw_lower:
            char_score = min(char_score + weight, 1.0)
            matched_count += 1

    # 3) Regex örüntü skoru (en yüksek eşleşen)
    pattern_score = 0.0
    for pattern, weight in _SQLI_PATTERNS:
        if pattern.search(decoded) or pattern.search(raw_lower):
            pattern_score = max(pattern_score, weight)
            matched_count += 1

    # 4) Ağırlıklı toplam anomali skoru
    # Örüntü skoru en ağır (kritik), diğerleri destekleyici
    anomaly_score = min(
        pattern_score * 0.55
        + keyword_score * 0.20
        + char_score * 0.25,
        1.0,
    )

    return {
        "sqli_keyword_score": round(keyword_score, 4),
        "sqli_char_score":    round(char_score, 4),
        "sqli_pattern_score": round(pattern_score, 4),
        "sqli_anomaly_score": round(anomaly_score, 4),
        "sqli_matched_count": matched_count,
    }


# ---------------------------------------------------------------------------
# Ana log satırı ayrıştırıcı
# ---------------------------------------------------------------------------

def parse_log_line(line: str) -> Optional[dict]:
    """
    Tek bir nginx log satırını parse ederek özellik sözlüğü döner.
    Parse başarısız olursa None döner.

    Dönen sözlük anahtarları:
      Temel özellikler:
        ip                       : str
        path                     : str
        method                   : str
        requests_per_ip_last_60s : int    — kayan pencere istek sayısı
        bytes_sent               : int
        status_code              : int
        method_encoded           : int
        path_depth               : int
        user_agent_length        : int
        response_time_ms         : float  (yoksa 0.0)

      SQLi tespit vektörleri:
        sqli_keyword_score       : float
        sqli_char_score          : float
        sqli_pattern_score       : float
        sqli_anomaly_score       : float
        sqli_matched_count       : int
    """
    m = _NGINX_PATTERN.match(line.strip())
    if not m:
        return None

    ip = m.group("ip")
    status = int(m.group("status"))
    bytes_sent = int(m.group("bytes"))
    method = m.group("method")
    path = m.group("path")
    ua = m.group("ua")
    req_time_raw = m.group("req_time")

    # Zaman damgası
    try:
        dt = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
        ts = dt.timestamp()
    except ValueError:
        ts = datetime.now(timezone.utc).timestamp()

    req_count = update_ip_window(ip, ts)
    response_time_ms = float(req_time_raw) * 1000 if req_time_raw else 0.0

    # SQLi skorlarını hesapla
    sqli_scores = compute_sqli_scores(path)

    return {
        "ip":                       ip,
        "path":                     path,
        "method":                   method.upper(),
        "requests_per_ip_last_60s": req_count,
        "bytes_sent":               bytes_sent,
        "status_code":              status,
        "method_encoded":           _encode_method(method),
        "path_depth":               _path_depth(path),
        "user_agent_length":        len(ua),
        "response_time_ms":         response_time_ms,
        **sqli_scores,
    }


# ---------------------------------------------------------------------------
# ML model özellik sütunları (DoS modeli için — mevcut sıra korundu)
# ---------------------------------------------------------------------------
FEATURE_COLUMNS = [
    "requests_per_ip_last_60s",
    "bytes_sent",
    "status_code",
    "method_encoded",
    "path_depth",
    "user_agent_length",
]


def get_feature_vector(features: dict) -> list:
    """Özellik sözlüğünden DoS modeli için sıralı liste döner."""
    return [features.get(col, 0) for col in FEATURE_COLUMNS]
