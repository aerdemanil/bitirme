"""
dashboard.py
------------
Gerçek zamanlı siber güvenlik dashboard'u için Flask + SocketIO backend.

Özellikler:
  - Async nginx log stream okuma (threading tabanlı)
  - Socket.IO ile gerçek zamanlı log ve saldırı akışı
  - REST API: istatistik, log geçmişi, aktif saldırılar
  - Tüm kayıtlı dedektörler (DoS, Brute Force, SQLi) desteklenir

Kullanım:
    python dashboard.py [--container hedef-sunucu] [--port 5000]
"""

import argparse
import threading
import time
import queue
import logging
import uuid
import concurrent.futures
import urllib.request
import urllib.parse
import urllib.error
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

import docker
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

from detector.feature_extractor import parse_log_line
from detector.attack_registry import get_all_detectors

# ---------------------------------------------------------------------------
# Uygulama kurulumu
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "ads-guardian-secret-2026"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=False,
    engineio_logger=False,
)

# ---------------------------------------------------------------------------
# Paylaşılan durum (thread-safe)
# ---------------------------------------------------------------------------
_lock = threading.Lock()

_stats = {
    "total_requests":  0,
    "total_attacks":   0,
    "parse_errors":    0,
    "start_time":      datetime.now(timezone.utc).isoformat(),
    "uptime_seconds":  0,
}

# Saldırı türü → sayı
_attack_type_counts: dict[str, int] = defaultdict(int)

# Son N log satırı (ring buffer)
_recent_logs: deque = deque(maxlen=500)

# Aktif saldırı oturumları: IP → oturum bilgisi
_attack_sessions: dict[str, dict] = {}

# Son saldırı kayıtları (dashboard tablosu için)
_recent_attacks: deque = deque(maxlen=100)

# Zaman serisi: son 60 veri noktası (dakika bazlı istek sayısı)
_timeseries: deque = deque(maxlen=60)
_ts_bucket: dict = {"minute": None, "requests": 0, "attacks": 0}

# Event kuyruğu (log okuyucu → socketio yayıncı)
_event_queue: queue.Queue = queue.Queue(maxsize=2000)

# Dedektörler (lazy yükleme)
_detectors: Optional[list] = None
_detectors_lock = threading.Lock()

# Cooldown: aynı IP+saldırı türü kombinasyonu için tekrarlı alert bastırma
_alert_cooldown: dict[str, float] = {}
ALERT_COOLDOWN_SEC = 5
SESSION_TIMEOUT_SEC = 30

# Canlı test işleri
_live_jobs: dict[str, dict] = {}
_live_jobs_lock = threading.Lock()

# Canlı testlerin istek göndereceği nginx adresi (host'tan erişilen port)
_NGINX_BASE = "http://localhost:8080"

# İzlenen Docker container adı (main() tarafından güncellenir)
_container_name = "hedef-sunucu"

# Gerçekçi tarayıcı User-Agent havuzu
_REALISTIC_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "python-requests/2.31.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/8.1.2",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
]

_DEFAULT_SQLI_PAYLOADS = """\
' OR '1'='1
' OR 1=1--
1 UNION SELECT null--
1 UNION SELECT null,null--
' AND SLEEP(1)--
'; DROP TABLE users--
\" OR \"\"=\"
1' ORDER BY 1--
admin'--
' UNION SELECT user(),version()--
1 AND 1=2 UNION SELECT table_name FROM information_schema.tables--
' OR EXISTS(SELECT 1 FROM users)--
1; EXEC xp_cmdshell('whoami')--
' OR 1=1 LIMIT 1--
1' GROUP BY 1--"""


# ---------------------------------------------------------------------------
# Canlı test — iş yönetimi yardımcıları
# ---------------------------------------------------------------------------

def _job_create(job_type: str, total: int) -> str:
    job_id = uuid.uuid4().hex[:8]
    with _live_jobs_lock:
        _live_jobs[job_id] = {
            "type": job_type, "status": "running",
            "sent": 0, "errors": 0, "total": total,
        }
    return job_id


def _job_cancelled(job_id: str) -> bool:
    with _live_jobs_lock:
        return _live_jobs.get(job_id, {}).get("status") == "cancelled"


def _job_tick(job_id: str, sent: int, errors: int = 0) -> None:
    with _live_jobs_lock:
        j = _live_jobs.get(job_id)
        if j:
            j["sent"] = sent
            j["errors"] = errors


def _job_done(job_id: str) -> None:
    with _live_jobs_lock:
        j = _live_jobs.get(job_id)
        if j and j["status"] == "running":
            j["status"] = "done"


import random as _random
import json as _json


def _pick_ua(ua_config=None) -> str:
    """Konfigürasyona göre User-Agent seçer."""
    if ua_config == "random" or ua_config is None:
        return _random.choice(_REALISTIC_UAS)
    if isinstance(ua_config, list) and ua_config:
        return _random.choice(ua_config)
    if isinstance(ua_config, str) and ua_config != "random":
        return ua_config
    return _random.choice(_REALISTIC_UAS)


def _jitter_sleep(base_ms: float, jitter: float = 0.0) -> None:
    """Jitter eklenmiş gecikme uygular."""
    if base_ms <= 0:
        return
    variation = base_ms * max(0.0, min(jitter, 1.0))
    actual_ms = base_ms + _random.uniform(-variation, variation)
    time.sleep(max(0.0, actual_ms / 1000.0))


def _http_get(url: str, user_agent: str = "ADS-Guardian-LiveTest/1.0") -> int:
    """URL'ye GET isteği gönderir; HTTP durum kodunu döner (bağlantı hatasında 0)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


def _http_post(url: str, data: dict, user_agent: str = "ADS-Guardian-LiveTest/1.0") -> int:
    """URL'ye form-encoded POST isteği gönderir; HTTP durum kodunu döner."""
    try:
        payload = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={
                "User-Agent": user_agent,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Canlı test — Senaryo adım runner'ları (paths + jitter + UA destekli)
# ---------------------------------------------------------------------------

def _scenario_emit(job_id: str, step_idx: int, step_name: str, step_type: str,
                   total_steps: int, sent: int, total: int, extra: str = "") -> None:
    socketio.emit("scenario_progress", {
        "job_id": job_id,
        "step_idx": step_idx,
        "step_name": step_name,
        "step_type": step_type,
        "total_steps": total_steps,
        "sent": sent,
        "total": total,
        "extra": extra,
    })


def _run_step_normal(job_id: str, step: dict, target: str,
                     step_idx: int, total_steps: int) -> None:
    count    = max(1, int(step.get("count", 30)))
    paths    = step.get("paths", ["/", "/index.html", "/about", "/contact", "/products"])
    delay_ms = float(step.get("delay_ms", 300))
    jitter   = float(step.get("jitter", 0.4))
    ua_cfg   = step.get("user_agents", "random")
    name     = step.get("name", "Normal Trafik")

    for i in range(count):
        if _job_cancelled(job_id):
            return
        path = _random.choice(paths)
        url  = target.rstrip("/") + path
        _http_get(url, user_agent=_pick_ua(ua_cfg))
        if (i + 1) % 5 == 0 or (i + 1) == count:
            _scenario_emit(job_id, step_idx, name, "normal", total_steps,
                           i + 1, count, path)
        _jitter_sleep(delay_ms, jitter)


def _run_step_dos(job_id: str, step: dict, target: str,
                  step_idx: int, total_steps: int) -> None:
    count       = max(1, int(step.get("count", 200)))
    concurrency = max(1, min(int(step.get("concurrency", 20)), 50))
    paths       = step.get("paths", ["/"])
    delay_ms    = float(step.get("delay_ms", 0))
    jitter      = float(step.get("jitter", 0.0))
    ua_cfg      = step.get("user_agents", "random")
    name        = step.get("name", "DoS")
    stats       = {"sent": 0, "errors": 0}
    lock        = threading.Lock()

    def _req():
        path = _random.choice(paths)
        url  = target.rstrip("/") + path
        code = _http_get(url, user_agent=_pick_ua(ua_cfg))
        with lock:
            stats["sent"] += 1
            if code == 0:
                stats["errors"] += 1
            n = stats["sent"]
        if n % 25 == 0 or n == count:
            _scenario_emit(job_id, step_idx, name, "dos", total_steps,
                           n, count, f"{stats['errors']} hata")

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = []
        for _ in range(count):
            if _job_cancelled(job_id):
                break
            futures.append(pool.submit(_req))
            _jitter_sleep(delay_ms, jitter)
        concurrent.futures.wait(futures)


def _run_step_bruteforce(job_id: str, step: dict, target: str,
                         step_idx: int, total_steps: int) -> None:
    method     = step.get("method", "POST").upper()
    user_field = step.get("username_field", "username")
    pass_field = step.get("password_field", "password")
    usernames  = [u.strip() for u in step.get("usernames", ["admin", "root", "user"]) if str(u).strip()][:50]
    passwords  = [p.strip() for p in step.get("passwords", ["password", "123456", "admin"]) if str(p).strip()][:50]
    delay_ms   = float(step.get("delay_ms", 80))
    jitter     = float(step.get("jitter", 0.3))
    ua_cfg     = step.get("user_agents", "random")
    name       = step.get("name", "Brute Force")
    endpoints  = step.get("endpoints", ["/login", "/admin", "/api/auth", "/api/login", "/signin", "/panel"])
    base       = target.rstrip("/")

    combos = [(u, p) for u in usernames for p in passwords]
    _random.shuffle(combos)  # Sırayı karıştır — gerçekçi davranış
    total  = len(combos)

    for i, (username, password) in enumerate(combos):
        if _job_cancelled(job_id):
            return
        target_url = base + _random.choice(endpoints)
        data = {user_field: username, pass_field: password}
        ua   = _pick_ua(ua_cfg)
        if method == "POST":
            _http_post(target_url, data, user_agent=ua)
        else:
            _http_get(f"{target_url}?{urllib.parse.urlencode(data)}", user_agent=ua)
        if (i + 1) % 5 == 0 or (i + 1) == total:
            _scenario_emit(job_id, step_idx, name, "brute_force", total_steps,
                           i + 1, total, f"{username} / {password}")
        _jitter_sleep(delay_ms, jitter)


def _run_step_sqli(job_id: str, step: dict, target: str,
                   step_idx: int, total_steps: int) -> None:
    url        = step.get("target_url", target.rstrip("/") + "/search")
    method     = step.get("method", "GET").upper()
    param      = step.get("param_name", "q")
    raw        = step.get("payloads", _DEFAULT_SQLI_PAYLOADS.splitlines())
    payloads   = [p.strip() for p in (raw if isinstance(raw, list) else str(raw).splitlines()) if str(p).strip()][:100]
    delay_ms   = float(step.get("delay_ms", 120))
    jitter     = float(step.get("jitter", 0.2))
    ua_cfg     = step.get("user_agents", "random")
    name       = step.get("name", "SQL Injection")
    total      = len(payloads)

    for i, payload in enumerate(payloads):
        if _job_cancelled(job_id):
            return
        data = {param: payload}
        ua   = _pick_ua(ua_cfg)
        if method == "POST":
            _http_post(url, data, user_agent=ua)
        else:
            _http_get(f"{url}?{urllib.parse.urlencode(data)}", user_agent=ua)
        if (i + 1) % 3 == 0 or (i + 1) == total:
            _scenario_emit(job_id, step_idx, name, "sql_injection", total_steps,
                           i + 1, total, payload[:60])
        _jitter_sleep(delay_ms, jitter)


_STEP_RUNNERS = {
    "normal":        _run_step_normal,
    "dos":           _run_step_dos,
    "brute_force":   _run_step_bruteforce,
    "sql_injection": _run_step_sqli,
}


def _run_scenario(job_id: str, scenario: dict) -> None:
    target = scenario.get("target", _NGINX_BASE)
    steps  = scenario.get("steps", [])
    total  = len(steps)

    for idx, step in enumerate(steps):
        if _job_cancelled(job_id):
            break
        stype  = step.get("type", "normal")
        runner = _STEP_RUNNERS.get(stype)
        if runner is None:
            logger.warning("Bilinmeyen adım tipi: %s — atlanıyor", stype)
            continue
        socketio.emit("scenario_step_start", {
            "job_id": job_id, "step_idx": idx,
            "step_name": step.get("name", stype), "step_type": stype,
            "total_steps": total,
        })
        try:
            runner(job_id, step, target, idx, total)
        except Exception as exc:
            logger.error("Senaryo adımı hatası [%s]: %s", step.get("name"), exc)

    _job_done(job_id)
    socketio.emit("scenario_complete", {"job_id": job_id, "steps": total})


# ---------------------------------------------------------------------------
# Canlı test — Yüksek Hacimli Brute Force (credential stuffing)
# ---------------------------------------------------------------------------

_HV_BF_ENDPOINTS = ["/login", "/admin", "/api/auth", "/api/login",
                    "/signin", "/panel", "/wp-login.php", "/user/login"]

def _run_highvolume_bf_test(
    job_id: str, base_url: str, count: int, concurrency: int, delay: float,
    usernames: list, passwords: list,
) -> None:
    combos = [(u, p) for u in usernames for p in passwords]
    stats  = {"sent": 0, "errors": 0}
    lock   = threading.Lock()

    def _req():
        endpoint = _random.choice(_HV_BF_ENDPOINTS)
        url      = base_url.rstrip("/") + endpoint
        u, p     = _random.choice(combos)
        code     = _http_post(url, {"username": u, "password": p},
                              user_agent=_pick_ua("random"))
        with lock:
            stats["sent"] += 1
            if code == 0:
                stats["errors"] += 1
            n = stats["sent"]
        if n % 25 == 0 or n == count:
            _job_tick(job_id, n, stats["errors"])
            socketio.emit("test_progress", {
                "job_id": job_id, "type": "brute_force",
                "sent": n, "total": count, "errors": stats["errors"],
                "current": f"{u} / {p} → {endpoint}",
            })

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = []
        for _ in range(count):
            if _job_cancelled(job_id):
                break
            futures.append(pool.submit(_req))
            if delay > 0:
                time.sleep(delay)
        concurrent.futures.wait(futures)

    _job_done(job_id)
    socketio.emit("test_complete", {
        "job_id": job_id, "type": "brute_force",
        "sent": stats["sent"], "errors": stats["errors"], "total": count,
    })


# ---------------------------------------------------------------------------
# Canlı test — DoS
# ---------------------------------------------------------------------------

def _run_dos_test(job_id: str, url: str, count: int, concurrency: int, delay: float) -> None:
    stats = {"sent": 0, "errors": 0}
    lock = threading.Lock()

    def _req():
        code = _http_get(url)
        with lock:
            stats["sent"] += 1
            if code == 0:
                stats["errors"] += 1
            n = stats["sent"]
        if n % 25 == 0 or n == count:
            _job_tick(job_id, n, stats["errors"])
            socketio.emit("test_progress", {
                "job_id": job_id, "type": "dos",
                "sent": n, "total": count, "errors": stats["errors"],
            })

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = []
        for _ in range(count):
            if _job_cancelled(job_id):
                break
            futures.append(pool.submit(_req))
            if delay > 0:
                time.sleep(delay)
        concurrent.futures.wait(futures)

    _job_done(job_id)
    socketio.emit("test_complete", {
        "job_id": job_id, "type": "dos",
        "sent": stats["sent"], "errors": stats["errors"], "total": count,
    })


# ---------------------------------------------------------------------------
# Canlı test — Brute Force
# ---------------------------------------------------------------------------

def _run_bruteforce_test(
    job_id: str, url: str, method: str,
    user_field: str, pass_field: str,
    combos: list, delay: float,
    endpoints=None,
) -> None:
    sent = 0
    errors = 0
    total = len(combos)

    # Birden fazla endpoint varsa rotasyon yap
    base = url.rsplit("/", 1)[0] if endpoints else None

    for i, (username, password) in enumerate(combos):
        if _job_cancelled(job_id):
            break
        target = (base + _random.choice(endpoints)) if endpoints else url
        data = {user_field: username, pass_field: password}
        code = _http_post(target, data) if method == "POST" else _http_get(
            f"{target}?{urllib.parse.urlencode(data)}"
        )
        if code == 0:
            errors += 1
        sent += 1
        if sent % 5 == 0 or sent == total:
            _job_tick(job_id, sent, errors)
            socketio.emit("test_progress", {
                "job_id": job_id, "type": "brute_force",
                "sent": sent, "total": total, "errors": errors,
                "current": f"{username} / {password}",
            })
        if delay > 0:
            time.sleep(delay)

    _job_done(job_id)
    socketio.emit("test_complete", {
        "job_id": job_id, "type": "brute_force",
        "sent": sent, "errors": errors, "total": total,
    })


# ---------------------------------------------------------------------------
# Canlı test — SQL Injection
# ---------------------------------------------------------------------------

def _run_sqli_test(
    job_id: str, url: str, method: str,
    param_name: str, payloads: list, delay: float,
) -> None:
    sent = 0
    errors = 0
    total = len(payloads)

    for payload in payloads:
        if _job_cancelled(job_id):
            break
        data = {param_name: payload}
        code = _http_post(url, data) if method == "POST" else _http_get(
            f"{url}?{urllib.parse.urlencode(data)}"
        )
        if code == 0:
            errors += 1
        sent += 1
        if sent % 3 == 0 or sent == total:
            _job_tick(job_id, sent, errors)
            socketio.emit("test_progress", {
                "job_id": job_id, "type": "sql_injection",
                "sent": sent, "total": total, "errors": errors,
                "current": payload[:60],
            })
        if delay > 0:
            time.sleep(delay)

    _job_done(job_id)
    socketio.emit("test_complete", {
        "job_id": job_id, "type": "sql_injection",
        "sent": sent, "errors": errors, "total": total,
    })




# ---------------------------------------------------------------------------
# Dedektör yönetimi
# ---------------------------------------------------------------------------

def _get_detectors() -> list:
    """Dedektörleri lazy yükler (model dosyası büyük, tek seferlik)."""
    global _detectors
    with _detectors_lock:
        if _detectors is None:
            logger.info("Dedektörler yükleniyor...")
            try:
                _detectors = get_all_detectors()
                names = [d.name for d in _detectors]
                logger.info("Yüklendi: %s", names)
            except FileNotFoundError as exc:
                logger.error("Model yüklenemedi: %s", exc)
                _detectors = []
    return _detectors


# ---------------------------------------------------------------------------
# Zaman serisi yönetimi
# ---------------------------------------------------------------------------

def _update_timeseries(is_attack: bool) -> None:
    """Dakika bazlı zaman serisi günceller."""
    now_minute = datetime.now().strftime("%H:%M")
    with _lock:
        if _ts_bucket["minute"] != now_minute:
            if _ts_bucket["minute"] is not None:
                _timeseries.append(dict(_ts_bucket))
            _ts_bucket["minute"] = now_minute
            _ts_bucket["requests"] = 0
            _ts_bucket["attacks"] = 0
        _ts_bucket["requests"] += 1
        if is_attack:
            _ts_bucket["attacks"] += 1


# ---------------------------------------------------------------------------
# Saldırı oturumu yönetimi
# ---------------------------------------------------------------------------

def _update_attack_session(ip: str, detector_name: str, conf: float, features: dict) -> None:
    """Saldırı oturumunu günceller, gerekirse yeni oturum açar."""
    now = time.time()
    with _lock:
        if ip not in _attack_sessions:
            _attack_sessions[ip] = {
                "start_time":   now,
                "last_seen":    now,
                "total_req":    0,
                "peak_conf":    0.0,
                "peak_rpm":     0,
                "detector":     detector_name,
            }
        sess = _attack_sessions[ip]
        sess["last_seen"] = now
        sess["total_req"] += 1
        sess["peak_conf"] = max(sess["peak_conf"], conf)
        sess["peak_rpm"]  = max(
            sess["peak_rpm"],
            features.get("requests_per_ip_last_60s", 0),
        )


def _cleanup_expired_sessions() -> None:
    """Zaman aşımına uğramış oturumları temizler (arka plan thread)."""
    while True:
        time.sleep(5)
        now = time.time()
        with _lock:
            expired = [
                ip for ip, sess in _attack_sessions.items()
                if now - sess["last_seen"] > SESSION_TIMEOUT_SEC
            ]
            for ip in expired:
                _attack_sessions.pop(ip, None)


# ---------------------------------------------------------------------------
# Log işleme çekirdeği
# ---------------------------------------------------------------------------

def _process_line(line: str, detectors: list) -> None:
    """Tek bir log satırını parse edip tüm dedektörleri koşturur."""
    features = parse_log_line(line)

    with _lock:
        _stats["total_requests"] += 1

    if features is None:
        with _lock:
            _stats["parse_errors"] += 1
        return

    # Log kaydı oluştur
    log_entry = {
        "time":      datetime.now().strftime("%H:%M:%S"),
        "ip":        features["ip"],
        "method":    features["method"],
        "path":      features["path"][:80],
        "status":    features["status_code"],
        "bytes":     features["bytes_sent"],
        "type":      "normal",
        "detector":  None,
        "confidence": 0.0,
        "rule_conf": None,
        "ml_conf":   None,
    }

    any_attack = False

    for detector in detectors:
        try:
            is_attack = detector.detect(features)
            conf = detector.confidence(features)
        except Exception as exc:
            logger.warning("Dedektör hatası (%s): %s", detector.name, exc)
            continue

        if is_attack:
            any_attack = True
            ip = features["ip"]
            now = time.time()

            with _lock:
                _stats["total_attacks"] += 1
                _attack_type_counts[detector.name] += 1

            _update_attack_session(ip, detector.name, conf, features)

            try:
                breakdown = detector.score_breakdown(features)
            except Exception:
                breakdown = {"rule_conf": None, "ml_conf": None}

            log_entry["type"] = "attack"
            log_entry["detector"] = detector.name
            log_entry["confidence"] = round(conf, 3)
            log_entry["rule_conf"] = breakdown["rule_conf"]
            log_entry["ml_conf"] = breakdown["ml_conf"]

            # Alert cooldown — IP + tür kombinasyonu bazlı
            cooldown_key = f"{ip}:{detector.name}"
            last_alert = _alert_cooldown.get(cooldown_key, 0)
            if now - last_alert >= ALERT_COOLDOWN_SEC:
                _alert_cooldown[cooldown_key] = now

                with _lock:
                    sess = _attack_sessions.get(ip, {})
                    total_req = sess.get("total_req", 1)

                attack_record = {
                    "time":       datetime.now().strftime("%H:%M:%S"),
                    "ip":         ip,
                    "type":       detector.name,
                    "confidence": round(conf, 3),
                    "rule_conf":  breakdown["rule_conf"],
                    "ml_conf":    breakdown["ml_conf"],
                    "path":       features["path"][:80],
                    "method":     features["method"],
                    "status":     features["status_code"],
                    "rpm":        features.get("requests_per_ip_last_60s", 0),
                    "total_req":  total_req,
                }

                with _lock:
                    _recent_attacks.appendleft(attack_record)

                _event_queue.put_nowait(("attack", attack_record))

    _update_timeseries(any_attack)

    with _lock:
        _recent_logs.append(log_entry)

    _event_queue.put_nowait(("log", log_entry))


# ---------------------------------------------------------------------------
# Docker log okuyucu (arka plan thread)
# ---------------------------------------------------------------------------

def _nginx_logs_to_stdout(container) -> bool:
    """nginx.conf'u okuyarak access_log stdout'a mı yoksa dosyaya mı yazıyor?"""
    try:
        result = container.exec_run(
            ["grep", "-r", "access_log", "/etc/nginx/"],
            demux=False,
        )
        return b"/dev/stdout" in result.output
    except Exception:
        return False


def _iter_lines(stream):
    """Byte chunk stream'ini satır satır yield eder."""
    remainder = ""
    for chunk in stream:
        text = remainder + chunk.decode("utf-8", errors="replace")
        parts = text.split("\n")
        remainder = parts[-1]
        for ln in parts[:-1]:
            ln = ln.strip()
            if ln:
                yield ln
    if remainder.strip():
        yield remainder.strip()


def _read_log_stream(container, detectors: list) -> None:
    """
    nginx access log'larını okur.
    nginx stdout'a yazıyorsa container.logs() kullanır,
    dosyaya yazıyorsa container içinde tail -F koşturur.
    """
    if _nginx_logs_to_stdout(container):
        logger.info("nginx → stdout stream okunuyor")
        start_time = datetime.now(timezone.utc)
        stream = container.logs(
            stream=True, follow=True, since=start_time, timestamps=False
        )
        for line in _iter_lines(stream):
            try:
                _process_line(line, detectors)
            except Exception as exc:
                logger.warning("Satır işleme hatası: %s", exc)
    else:
        logger.info("nginx → dosya; exec tail -F /var/log/nginx/access.log")
        result = container.exec_run(
            ["tail", "-n", "0", "-F", "/var/log/nginx/access.log"],
            stream=True,
            demux=False,
        )
        for line in _iter_lines(result.output):
            try:
                _process_line(line, detectors)
            except Exception as exc:
                logger.warning("Satır işleme hatası: %s", exc)


def _log_reader_thread(container_name: str) -> None:
    """Docker container log'larını okuyup işleyen arka plan thread'i."""
    detectors = _get_detectors()

    while True:
        try:
            client = docker.from_env()
            container = client.containers.get(container_name)
            logger.info("Container bağlantısı kuruldu: %s", container_name)
            _read_log_stream(container, detectors)

        except docker.errors.NotFound:
            logger.error("Container bulunamadı: '%s' — 5 saniye sonra tekrar denenecek.", container_name)
            _event_queue.put_nowait(("system", {
                "level": "error",
                "message": f"Container '{container_name}' bulunamadı.",
            }))
            time.sleep(5)
        except Exception as exc:
            logger.error("Log okuma hatası: %s — 3 saniye sonra yeniden bağlanılıyor.", exc)
            time.sleep(3)


# ---------------------------------------------------------------------------
# SocketIO event yayıncısı (arka plan thread)
# ---------------------------------------------------------------------------

def _socketio_emitter_thread() -> None:
    """Kuyruktan event'leri alıp Socket.IO ile yayınlar."""
    while True:
        try:
            event_type, payload = _event_queue.get(timeout=1.0)
            socketio.emit(event_type, payload)
        except queue.Empty:
            pass
        except Exception as exc:
            logger.warning("SocketIO emit hatası: %s", exc)


# ---------------------------------------------------------------------------
# Uptime sayacı
# ---------------------------------------------------------------------------

def _uptime_thread() -> None:
    """Her saniye uptime günceller ve socketio'ya iletir."""
    start = time.time()
    while True:
        time.sleep(1)
        elapsed = int(time.time() - start)
        with _lock:
            _stats["uptime_seconds"] = elapsed
        socketio.emit("uptime", {"seconds": elapsed})


# ---------------------------------------------------------------------------
# REST API endpoint'leri
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Dashboard ana sayfası."""
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    """Genel istatistikler."""
    with _lock:
        stats = dict(_stats)
        attack_types = dict(_attack_type_counts)
        active_attacks = [
            {
                "ip":        ip,
                "duration":  round(time.time() - sess["start_time"], 1),
                "total_req": sess["total_req"],
                "peak_conf": round(sess["peak_conf"], 3),
                "peak_rpm":  sess["peak_rpm"],
                "detector":  sess["detector"],
            }
            for ip, sess in _attack_sessions.items()
        ]
        timeseries = list(_timeseries)

    return jsonify({
        "stats":          stats,
        "attack_types":   attack_types,
        "active_attacks": active_attacks,
        "timeseries":     timeseries,
    })


@app.route("/api/logs")
def api_logs():
    """Son log satırları."""
    with _lock:
        logs = list(_recent_logs)
    return jsonify({"logs": logs})


@app.route("/api/attacks")
def api_attacks():
    """Son tespit edilen saldırılar."""
    with _lock:
        attacks = list(_recent_attacks)
    return jsonify({"attacks": attacks})


def _ollama_generate(prompt: str, timeout: int = 90) -> str:
    """Ollama gemma3:4b'ye istek at, yanıtı döndür."""
    import urllib.request, json as _json
    payload = _json.dumps({
        "model": "gemma3:4b",
        "prompt": prompt,
        "stream": False
    }).encode()
    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return _json.loads(resp.read().decode()).get("response", "")


@app.route("/api/ai/analyze", methods=["POST"])
def api_ai_analyze():
    """Tek saldırı kaydını Türkçe analiz et."""
    data = request.get_json(force=True) or {}
    attack = data.get("attack", {})
    if not attack:
        return jsonify({"error": "attack verisi eksik"}), 400

    prompt = (
        f"Sen bir siber güvenlik uzmanısın. Aşağıdaki tespit edilen saldırıyı Türkçe olarak 3-4 cümleyle analiz et: "
        f"saldırı türü nedir, neden tehlikelidir ve nasıl önlem alınmalıdır.\n\n"
        f"Saldırı detayları:\n"
        f"- Tür: {attack.get('type', 'bilinmiyor')}\n"
        f"- Kaynak IP: {attack.get('ip', 'bilinmiyor')}\n"
        f"- Güven Skoru: {attack.get('confidence', 0)}\n"
        f"- Yol: {attack.get('path', '/')}\n"
        f"- Metod: {attack.get('method', 'GET')}\n"
        f"- Durum Kodu: {attack.get('status', 0)}\n"
        f"- Anlık İstek Hızı (istek/dakika): {attack.get('rpm', 0)}\n"
        f"- Oturumdaki Toplam İstek Sayısı: {attack.get('total_req', attack.get('rpm', 0))}\n"
        f"- Zaman: {attack.get('time', '')}\n\n"
        f"Yanıtın kısa ve teknik olsun. Sadece Türkçe yaz."
    )
    try:
        return jsonify({"analysis": _ollama_generate(prompt)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/chat", methods=["POST"])
def api_ai_chat():
    """Serbest soru — saldırı bağlamıyla Ollama'ya ilet."""
    data = request.get_json(force=True) or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "mesaj boş"}), 400

    with _lock:
        attacks = list(_recent_attacks)[:10]
        logs    = list(_recent_logs)[-20:]

    context_parts = []

    if attacks:
        lines = [f"  [{a['time']}] {a['type']} — IP:{a['ip']} güven:{a['confidence']} yol:{a['path']}"
                 for a in attacks]
        context_parts.append("Son tespit edilen saldırılar:\n" + "\n".join(lines))

    normal_logs = [l for l in logs if l.get("type") != "attack"]
    if normal_logs:
        lines = [f"  [{l.get('time','')}] {l.get('method','?')} {l.get('path','/')} "
                 f"→ {l.get('status_code','?')} IP:{l.get('ip','?')}"
                 for l in normal_logs[:10]]
        context_parts.append("Son normal trafik örnekleri:\n" + "\n".join(lines))

    context = ("\n\n".join(context_parts) + "\n\n") if context_parts else ""

    prompt = (
        f"Sen ADS Guardian adlı siber güvenlik sisteminin AI asistanısın. "
        f"Kullanıcının sorularını Türkçe, kısa ve teknik biçimde yanıtla. "
        f"Hem saldırı hem normal trafik verilerini analiz edebilirsin.\n\n"
        f"{context}"
        f"Kullanıcı sorusu: {message}\n\n"
        f"Yanıt:"
    )
    try:
        return jsonify({"response": _ollama_generate(prompt)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/summary", methods=["POST"])
def api_ai_summary():
    """Son 1 saatin tüm trafik özetini Ollama ile üret."""
    from datetime import datetime as _dt, timedelta
    from collections import Counter
    cutoff = _dt.now() - timedelta(hours=1)

    with _lock:
        attacks = list(_recent_attacks)
        all_logs = list(_recent_logs)

    def in_last_hour(time_str):
        try:
            t = _dt.strptime(time_str, "%H:%M:%S").replace(
                year=_dt.now().year, month=_dt.now().month, day=_dt.now().day
            )
            return t >= cutoff
        except Exception:
            return True

    recent_attacks = [a for a in attacks if in_last_hour(a.get("time", ""))]
    recent_logs    = [l for l in all_logs  if in_last_hour(l.get("time", ""))]
    normal_logs    = [l for l in recent_logs if l.get("type") != "attack"]

    total_req    = len(recent_logs)
    total_attack = len(recent_attacks)
    status_counts = Counter(str(l.get("status_code", "?")) for l in normal_logs)
    top_status   = ", ".join(f"{k}:{v}" for k, v in status_counts.most_common(4))

    attack_info = ""
    if recent_attacks:
        type_counts = Counter(a["type"] for a in recent_attacks)
        ip_counts   = Counter(a["ip"]   for a in recent_attacks)
        attack_info = (
            f"Saldırı türleri: {', '.join(f'{t}:{c}' for t,c in type_counts.items())}\n"
            f"En aktif saldırgan IP: {', '.join(f'{ip}({c})' for ip,c in ip_counts.most_common(3))}\n"
        )

    prompt = (
        f"Sen bir siber güvenlik uzmanısın. Aşağıdaki son 1 saatlik trafik verilerini Türkçe analiz et. "
        f"Genel risk seviyesini belirt, dikkat çekici anomalileri açıkla ve önerilen aksiyonları listele.\n\n"
        f"Toplam istek: {total_req}\n"
        f"Tespit edilen saldırı: {total_attack}\n"
        f"HTTP durum dağılımı: {top_status}\n"
        f"{attack_info}"
        f"\nYanıtın 5-6 cümle olsun. Sadece Türkçe yaz."
    )
    try:
        return jsonify({"summary": _ollama_generate(prompt, timeout=120)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/ip-risk", methods=["GET"])
def api_ai_ip_risk():
    """Son saldırılardaki IP'ler için risk skoru hesapla."""
    from collections import defaultdict
    with _lock:
        attacks = list(_recent_attacks)

    ip_data: dict = defaultdict(lambda: {"count": 0, "types": set(), "max_conf": 0.0})
    for a in attacks:
        ip = a["ip"]
        ip_data[ip]["count"]    += 1
        ip_data[ip]["types"].add(a["type"])
        ip_data[ip]["max_conf"] = max(ip_data[ip]["max_conf"], a.get("confidence", 0))

    result = []
    for ip, d in ip_data.items():
        type_count = len(d["types"])
        # Risk: çok saldırı + çok farklı tür + yüksek güven → Kritik
        score = min(100, int(d["count"] * 10 + type_count * 20 + d["max_conf"] * 30))
        if score >= 80:   level = "Kritik"
        elif score >= 50: level = "Yüksek"
        elif score >= 25: level = "Orta"
        else:             level = "Düşük"

        # Aynı IP'den farklı saldırı türleri varsa koordineli saldırı uyarısı
        coordinated = type_count >= 2

        result.append({
            "ip":          ip,
            "count":       d["count"],
            "types":       list(d["types"]),
            "max_conf":    round(d["max_conf"], 3),
            "score":       score,
            "level":       level,
            "coordinated": coordinated,
        })

    result.sort(key=lambda x: x["score"], reverse=True)
    return jsonify({"ip_risks": result[:20]})


@app.route("/api/detectors")
def api_detectors():
    """Yüklü dedektör listesi."""
    detectors = _get_detectors()
    return jsonify({
        "detectors": [
            {"name": d.name, "class": d.__class__.__name__}
            for d in detectors
        ]
    })


@app.route("/api/test", methods=["POST"])
def api_test():
    """Sistem testi: seçilen saldırı türü için önceden tanımlı senaryoları koşturur."""
    body      = request.get_json(silent=True) or {}
    test_type = body.get("type", "all")

    TEST_CASES = {
        "dos": [
            {
                "label": "Normal trafik",
                "expected": False,
                "features": {"requests_per_ip_last_60s": 5,     "bytes_sent": 3000,
                             "status_code": 200, "method_encoded": 0,
                             "path_depth": 2, "user_agent_length": 120,
                             "path": "/index.html", "method": "GET"},
            },
            {
                "label": "DoS Slowloris (dusuk hiz, baglanti tutan)",
                "expected": True,
                "features": {"requests_per_ip_last_60s": 60, "bytes_sent": 0,
                             "status_code": 200, "method_encoded": 0,
                             "path_depth": 0, "user_agent_length": 0,
                             "path": "/", "method": "GET"},
            },
        ],
        "brute_force": [
            {
                "label": "Normal trafik",
                "expected": False,
                "features": {"requests_per_ip_last_60s": 3,  "bytes_sent": 1500,
                             "status_code": 200, "method_encoded": 0,
                             "path_depth": 1, "user_agent_length": 100,
                             "path": "/index.html", "method": "GET"},
            },
            {
                "label": "401 + login + POST flood",
                "expected": True,
                "features": {"requests_per_ip_last_60s": 50, "bytes_sent": 200,
                             "status_code": 401, "method_encoded": 1,
                             "path_depth": 1, "user_agent_length": 10,
                             "path": "/login", "method": "POST"},
            },
            {
                "label": "Admin panele erişim denemesi",
                "expected": True,
                "features": {"requests_per_ip_last_60s": 35, "bytes_sent": 150,
                             "status_code": 403, "method_encoded": 1,
                             "path_depth": 1, "user_agent_length": 8,
                             "path": "/admin", "method": "POST"},
            },
        ],
        "sql_injection": [
            {"label": "Normal URL",           "expected": False,
             "features": {"path": "/urunler?id=42"}},
            {"label": "OR 1=1 enjeksiyonu",   "expected": True,
             "features": {"path": "/search?q=1' OR 1=1--"}},
            {"label": "UNION SELECT",          "expected": True,
             "features": {"path": "/login?user=admin' UNION SELECT * FROM users--"}},
            {"label": "DROP TABLE",            "expected": True,
             "features": {"path": "/api?x='; DROP TABLE users--"}},
            {"label": "Time-based blind",      "expected": True,
             "features": {"path": "/page?id=1 AND SLEEP(5)"}},
            {"label": "Statik sayfa",          "expected": False,
             "features": {"path": "/index.html"}},
        ],
    }

    detectors = _get_detectors()
    det_map   = {d.name: d for d in detectors}

    types_to_run = list(TEST_CASES.keys()) if test_type == "all" else [test_type]
    results = []

    for t in types_to_run:
        if t not in TEST_CASES:
            continue
        det = det_map.get(t)
        for case in TEST_CASES[t]:
            features = case["features"]
            try:
                if det:
                    detected = det.detect(features)
                    conf     = det.confidence(features)
                else:
                    detected = False
                    conf     = 0.0
            except Exception as exc:
                detected = None
                conf     = 0.0
                results.append({
                    "type": t, "label": case["label"],
                    "expected": case["expected"], "detected": None,
                    "confidence": 0.0, "pass": False,
                    "error": str(exc),
                })
                continue

            passed = detected == case["expected"]
            results.append({
                "type":       t,
                "label":      case["label"],
                "expected":   case["expected"],
                "detected":   detected,
                "confidence": round(conf, 4),
                "pass":       passed,
                "error":      None,
            })

    passed = sum(1 for r in results if r["pass"])
    return jsonify({
        "results": results,
        "summary": {"total": len(results), "passed": passed, "failed": len(results) - passed},
    })


@app.route("/api/health")
def api_health():
    """Sağlık kontrolü endpoint'i — container ve model durumunu da döner."""
    with _lock:
        total   = _stats["total_requests"]
        attacks = _stats["total_attacks"]

    # Docker container durum kontrolü
    container_status = "unknown"
    try:
        client    = docker.from_env()
        container = client.containers.get(_container_name)
        container_status = "connected" if container.status == "running" else container.status
    except Exception:
        container_status = "error"

    # Yüklü dedektör sayısı
    dets        = _get_detectors()
    model_count = len([d for d in dets if d.name in ("dos", "brute_force", "sql_injection")])

    return jsonify({
        "status":    "ok",
        "version":   "2.0.0",
        "requests":  total,
        "attacks":   attacks,
        "container": {"name": _container_name, "status": container_status},
        "models":    {"loaded": model_count, "total": 2},
    })


# ---------------------------------------------------------------------------
# Yeni test endpoint'leri (yeni arayüz)
# ---------------------------------------------------------------------------

@app.route("/api/test/offline", methods=["POST"])
def api_test_offline():
    """Offline model doğrulama — Docker'a istek gitmez, dedektörler RAM'de çalışır."""
    body      = request.get_json(silent=True) or {}
    test_type = body.get("type", "all")
    template  = body.get("template")  # mixed|auth_attack|full → type eşlemesi

    # Şablon → tür eşlemesi
    if template == "auth_attack":
        test_type = "brute_force"
    elif template in ("mixed", "full"):
        test_type = "all"

    # TEST_CASES doğrudan api_test() ile aynı yapıyı kullanır
    TEST_CASES = {
        "dos": [
            {
                "label": "Normal trafik",
                "expected": False,
                "features": {"requests_per_ip_last_60s": 5, "bytes_sent": 3000,
                             "status_code": 200, "method_encoded": 0,
                             "path_depth": 2, "user_agent_length": 120,
                             "path": "/index.html", "method": "GET"},
            },
            {
                "label": "DoS Slowloris (düşük hız, bağlantı tutan)",
                "expected": True,
                "features": {"requests_per_ip_last_60s": 60, "bytes_sent": 0,
                             "status_code": 200, "method_encoded": 0,
                             "path_depth": 0, "user_agent_length": 0,
                             "path": "/", "method": "GET"},
            },
        ],
        "brute_force": [
            {
                "label": "Normal trafik",
                "expected": False,
                "features": {"requests_per_ip_last_60s": 3, "bytes_sent": 1500,
                             "status_code": 200, "method_encoded": 0,
                             "path_depth": 1, "user_agent_length": 100,
                             "path": "/index.html", "method": "GET"},
            },
            {
                "label": "401 + login + POST flood",
                "expected": True,
                "features": {"requests_per_ip_last_60s": 50, "bytes_sent": 200,
                             "status_code": 401, "method_encoded": 1,
                             "path_depth": 1, "user_agent_length": 10,
                             "path": "/login", "method": "POST"},
            },
            {
                "label": "Admin panele erişim denemesi",
                "expected": True,
                "features": {"requests_per_ip_last_60s": 35, "bytes_sent": 150,
                             "status_code": 403, "method_encoded": 1,
                             "path_depth": 1, "user_agent_length": 8,
                             "path": "/admin", "method": "POST"},
            },
        ],
        "sql_injection": [
            {"label": "Normal URL",            "expected": False,
             "features": {"path": "/urunler?id=42"}},
            {"label": "OR 1=1 enjeksiyonu",    "expected": True,
             "features": {"path": "/search?q=1' OR 1=1--"}},
            {"label": "UNION SELECT",           "expected": True,
             "features": {"path": "/login?user=admin' UNION SELECT * FROM users--"}},
            {"label": "DROP TABLE",             "expected": True,
             "features": {"path": "/api?x='; DROP TABLE users--"}},
            {"label": "Time-based blind",       "expected": True,
             "features": {"path": "/page?id=1 AND SLEEP(5)"}},
            {"label": "Statik sayfa",           "expected": False,
             "features": {"path": "/index.html"}},
        ],
    }

    detectors  = _get_detectors()
    det_map    = {d.name: d for d in detectors}
    types_to_run = list(TEST_CASES.keys()) if test_type == "all" else [test_type]
    results    = []

    for t in types_to_run:
        if t not in TEST_CASES:
            continue
        det = det_map.get(t)
        for case in TEST_CASES[t]:
            features = case["features"]
            try:
                detected = det.detect(features)    if det else False
                conf     = det.confidence(features) if det else 0.0
            except Exception as exc:
                results.append({
                    "type": t, "label": case["label"],
                    "expected": case["expected"], "detected": None,
                    "confidence": 0.0, "pass": False, "error": str(exc),
                })
                continue
            results.append({
                "type": t, "label": case["label"],
                "expected": case["expected"], "detected": detected,
                "confidence": round(conf, 4),
                "pass": detected == case["expected"],
                "error": None,
            })

    passed = sum(1 for r in results if r["pass"])
    return jsonify({
        "results": results,
        "summary": {"total": len(results), "passed": passed, "failed": len(results) - passed},
    })


@app.route("/api/test/live", methods=["POST"])
def api_test_live():
    """Canlı saldırı başlatıcı — mevcut iş fonksiyonlarını arka planda çalıştırır."""
    body        = request.get_json(silent=True) or {}
    attack_type = body.get("type")

    if attack_type == "dos":
        count       = max(10,  min(int(body.get("count",       300)), 2000))
        concurrency = max(1,   min(int(body.get("concurrency",  20)),   50))
        delay_ms    = max(0,   min(int(body.get("delay_ms",     50)), 5000))
        target_url  = f"{_NGINX_BASE}/"
        job_id      = _job_create("dos", count)
        threading.Thread(
            target=_run_dos_test,
            args=(job_id, target_url, count, concurrency, delay_ms / 1000.0),
            daemon=True,
        ).start()

    elif attack_type == "bruteforce":
        usernames = [u.strip() for u in body.get("usernames", "admin\nroot\nuser").splitlines() if u.strip()][:50]
        passwords = [p.strip() for p in body.get("passwords", "password\n123456\nadmin").splitlines() if p.strip()][:50]
        combos    = [(u, p) for u in usernames for p in passwords]
        job_id    = _job_create("brute_force", len(combos))
        bf_endpoints = ["/login", "/admin", "/api/auth", "/api/login", "/signin", "/panel"]
        threading.Thread(
            target=_run_bruteforce_test,
            args=(job_id, f"{_NGINX_BASE}/login", "POST", "username", "password", combos, 0.08),
            kwargs={"endpoints": bf_endpoints},
            daemon=True,
        ).start()

    elif attack_type == "highvolumebrute":
        count       = max(1, min(int(body.get("count", 200)), 2000))
        concurrency = max(1, min(int(body.get("concurrency", 20)), 50))
        delay       = max(0.0, float(body.get("delay", 0.0)))
        usernames   = [u.strip() for u in body.get("usernames", "admin\nroot\nuser\nadministrator").splitlines() if u.strip()][:50]
        passwords   = [p.strip() for p in body.get("passwords", "password\n123456\nadmin\nqwerty").splitlines() if p.strip()][:50]
        job_id      = _job_create("brute_force", count)
        threading.Thread(
            target=_run_highvolume_bf_test,
            args=(job_id, _NGINX_BASE, count, concurrency, delay, usernames, passwords),
            daemon=True,
        ).start()

    elif attack_type == "sqli":
        raw = body.get("payloads", _DEFAULT_SQLI_PAYLOADS)
        payloads = [p.strip() for p in (raw if isinstance(raw, str) else "\n".join(raw)).splitlines() if p.strip()][:100]
        if not payloads:
            payloads = [p for p in _DEFAULT_SQLI_PAYLOADS.splitlines() if p.strip()]
        job_id   = _job_create("sql_injection", len(payloads))
        threading.Thread(
            target=_run_sqli_test,
            args=(job_id, f"{_NGINX_BASE}/search", "GET", "q", payloads, 0.12),
            daemon=True,
        ).start()

    else:
        return jsonify({"error": "Geçersiz saldırı türü. dos | bruteforce | sqli olmalı."}), 400

    return jsonify({"status": "started", "message": "Simülasyon arka planda başarıyla başlatıldı."})


# ---------------------------------------------------------------------------
# Canlı test REST endpoint'leri (eski — geriye dönük uyumluluk için korunuyor)
# ---------------------------------------------------------------------------

@app.route("/api/live-test/dos", methods=["POST"])
def api_live_test_dos():
    body        = request.get_json(silent=True) or {}
    count       = max(10,  min(int(body.get("count",       300)), 2000))
    concurrency = max(1,   min(int(body.get("concurrency",  20)),   50))
    delay_ms    = max(0,   min(int(body.get("delay_ms",      0)), 5000))
    target_url  = body.get("target_url", f"{_NGINX_BASE}/")

    job_id = _job_create("dos", count)
    threading.Thread(
        target=_run_dos_test,
        args=(job_id, target_url, count, concurrency, delay_ms / 1000.0),
        daemon=True,
    ).start()
    return jsonify({"job_id": job_id, "total": count})


@app.route("/api/live-test/bruteforce", methods=["POST"])
def api_live_test_bruteforce():
    body       = request.get_json(silent=True) or {}
    target_url = body.get("target_url", f"{_NGINX_BASE}/login")
    method     = body.get("method", "POST").upper()
    user_field = body.get("username_field", "username")
    pass_field = body.get("password_field", "password")
    delay_ms   = max(0, min(int(body.get("delay_ms", 80)), 5000))

    usernames = [u.strip() for u in body.get("usernames", "admin\nroot\nuser").splitlines() if u.strip()][:50]
    passwords = [p.strip() for p in body.get("passwords", "password\n123456\nadmin").splitlines() if p.strip()][:50]
    combos    = [(u, p) for u in usernames for p in passwords]

    job_id = _job_create("brute_force", len(combos))
    threading.Thread(
        target=_run_bruteforce_test,
        args=(job_id, target_url, method, user_field, pass_field, combos, delay_ms / 1000.0),
        daemon=True,
    ).start()
    return jsonify({"job_id": job_id, "total": len(combos)})


@app.route("/api/live-test/sqli", methods=["POST"])
def api_live_test_sqli():
    body       = request.get_json(silent=True) or {}
    target_url = body.get("target_url", f"{_NGINX_BASE}/search")
    method     = body.get("method", "GET").upper()
    param_name = body.get("param_name", "q")
    delay_ms   = max(0, min(int(body.get("delay_ms", 120)), 5000))

    raw = body.get("payloads", _DEFAULT_SQLI_PAYLOADS)
    payloads = [p.strip() for p in raw.splitlines() if p.strip()][:100]

    job_id = _job_create("sql_injection", len(payloads))
    threading.Thread(
        target=_run_sqli_test,
        args=(job_id, target_url, method, param_name, payloads, delay_ms / 1000.0),
        daemon=True,
    ).start()
    return jsonify({"job_id": job_id, "total": len(payloads)})


@app.route("/api/live-test/scenario", methods=["POST"])
def api_live_test_scenario():
    body = request.get_json(silent=True) or {}

    # YAML desteği (opsiyonel)
    raw_text = body.get("raw")
    if raw_text:
        try:
            import yaml as _yaml
            scenario = _yaml.safe_load(raw_text)
        except ImportError:
            try:
                scenario = _json.loads(raw_text)
            except Exception:
                return jsonify({"error": "Geçersiz JSON formatı"}), 400
        except Exception:
            return jsonify({"error": "Geçersiz YAML/JSON formatı"}), 400
    else:
        scenario = body.get("scenario", {})

    steps = scenario.get("steps", [])
    if not steps:
        return jsonify({"error": "Senaryo en az bir adım içermelidir"}), 400

    total_requests = sum(
        max(1, int(s.get("count", 30))) if s.get("type") in ("normal", "dos") else
        len([u.strip() for u in s.get("usernames", ["admin"]) if str(u).strip()]) *
        len([p.strip() for p in s.get("passwords", ["password"]) if str(p).strip()]) if s.get("type") == "brute_force" else
        len([p.strip() for p in (s.get("payloads") or _DEFAULT_SQLI_PAYLOADS).splitlines() if str(p).strip()])
        for s in steps
    )

    job_id = _job_create("scenario", total_requests)
    threading.Thread(
        target=_run_scenario,
        args=(job_id, scenario),
        daemon=True,
    ).start()
    return jsonify({"job_id": job_id, "steps": len(steps), "total_requests": total_requests})


_SCENARIO_TEMPLATES = {
    "mixed": {
        "name": "Karma Trafik Senaryosu",
        "description": "Normal trafik → DoS dalgası → SQL Injection. Gerçek karma saldırı simülasyonu.",
        "target": "http://localhost:8080",
        "steps": [
            {
                "name": "Isınma — Normal Trafik",
                "type": "normal",
                "count": 40,
                "paths": ["/", "/index.html", "/about", "/contact", "/products", "/faq"],
                "delay_ms": 250,
                "jitter": 0.5,
                "user_agents": "random"
            },
            {
                "name": "DoS Dalgası",
                "type": "dos",
                "count": 250,
                "concurrency": 25,
                "paths": ["/", "/search", "/api/data"],
                "delay_ms": 0,
                "jitter": 0.0,
                "user_agents": "random"
            },
            {
                "name": "Soğuma — Normal Trafik",
                "type": "normal",
                "count": 20,
                "paths": ["/", "/index.html"],
                "delay_ms": 400,
                "jitter": 0.6,
                "user_agents": "random"
            },
            {
                "name": "SQL Injection Taraması",
                "type": "sql_injection",
                "target_url": "http://localhost:8080/search",
                "method": "GET",
                "param_name": "q",
                "payloads": [
                    "' OR '1'='1", "1 UNION SELECT null--",
                    "'; DROP TABLE users--", "' AND SLEEP(1)--",
                    "admin'--", "' UNION SELECT user(),version()--"
                ],
                "delay_ms": 150,
                "jitter": 0.3,
                "user_agents": "random"
            }
        ]
    },
    "auth_attack": {
        "name": "Kimlik Doğrulama Saldırısı",
        "description": "Normal trafik arasına gizlenmiş brute force — gerçekçi APT simülasyonu.",
        "target": "http://localhost:8080",
        "steps": [
            {
                "name": "Normal Kullanıcı Trafiği",
                "type": "normal",
                "count": 25,
                "paths": ["/", "/login", "/register", "/about"],
                "delay_ms": 500,
                "jitter": 0.6,
                "user_agents": "random"
            },
            {
                "name": "Gizli Brute Force",
                "type": "brute_force",
                "target_url": "http://localhost:8080/login",
                "endpoints": ["/login", "/admin", "/api/auth", "/api/login", "/signin", "/panel"],
                "method": "POST",
                "username_field": "username",
                "password_field": "password",
                "usernames": ["admin", "root", "administrator", "user", "test", "guest", "webmaster"],
                "passwords": ["password", "123456", "admin", "root", "12345", "qwerty", "letmein", "admin123"],
                "delay_ms": 120,
                "jitter": 0.5,
                "user_agents": "random"
            },
            {
                "name": "Normal Trafik (Örtbas)",
                "type": "normal",
                "count": 30,
                "paths": ["/", "/products", "/contact", "/index.html"],
                "delay_ms": 350,
                "jitter": 0.4,
                "user_agents": "random"
            }
        ]
    },
    "full": {
        "name": "Tam Saldırı Seti",
        "description": "Tüm saldırı türlerini sırayla çalıştıran kapsamlı test senaryosu.",
        "target": "http://localhost:8080",
        "steps": [
            {
                "name": "Keşif — Normal Trafik",
                "type": "normal",
                "count": 30,
                "paths": ["/", "/index.html", "/robots.txt", "/sitemap.xml", "/admin", "/login"],
                "delay_ms": 400,
                "jitter": 0.5,
                "user_agents": "random"
            },
            {
                "name": "DoS Saldırısı",
                "type": "dos",
                "count": 300,
                "concurrency": 30,
                "paths": ["/", "/search", "/api"],
                "delay_ms": 0,
                "jitter": 0.0,
                "user_agents": "random"
            },
            {
                "name": "Brute Force",
                "type": "brute_force",
                "target_url": "http://localhost:8080/login",
                "endpoints": ["/login", "/admin", "/api/auth", "/api/login", "/signin", "/panel"],
                "method": "POST",
                "username_field": "username",
                "password_field": "password",
                "usernames": ["admin", "root", "user", "administrator"],
                "passwords": ["password", "123456", "admin", "root", "qwerty"],
                "delay_ms": 80,
                "jitter": 0.35,
                "user_agents": "random"
            },
            {
                "name": "SQL Injection",
                "type": "sql_injection",
                "target_url": "http://localhost:8080/search",
                "method": "GET",
                "param_name": "q",
                "payloads": [
                    "' OR '1'='1", "' OR 1=1--", "1 UNION SELECT null--",
                    "1 UNION SELECT null,null--", "' AND SLEEP(1)--",
                    "'; DROP TABLE users--", "admin'--",
                    "' UNION SELECT user(),version()--",
                    "1 AND 1=2 UNION SELECT table_name FROM information_schema.tables--"
                ],
                "delay_ms": 130,
                "jitter": 0.25,
                "user_agents": "random"
            }
        ]
    }
}


@app.route("/api/live-test/scenario/templates")
def api_scenario_templates():
    return jsonify({
        k: {"name": v["name"], "description": v["description"], "step_count": len(v["steps"])}
        for k, v in _SCENARIO_TEMPLATES.items()
    })


@app.route("/api/live-test/scenario/templates/<key>")
def api_scenario_template(key: str):
    tpl = _SCENARIO_TEMPLATES.get(key)
    if not tpl:
        return jsonify({"error": "Şablon bulunamadı"}), 404
    return jsonify(tpl)


@app.route("/api/live-test/<job_id>", methods=["DELETE"])
def api_live_test_stop(job_id: str):
    with _live_jobs_lock:
        if job_id in _live_jobs:
            _live_jobs[job_id]["status"] = "cancelled"
            return jsonify({"status": "cancelled"})
    return jsonify({"error": "not found"}), 404


@app.route("/api/live-test/status/<job_id>")
def api_live_test_status(job_id: str):
    with _live_jobs_lock:
        job = dict(_live_jobs.get(job_id, {}))
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(job)


# ---------------------------------------------------------------------------
# SocketIO bağlantı event'leri
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect():
    """İstemci bağlandığında mevcut durumu gönderir."""
    logger.debug("İstemci bağlandı")
    with _lock:
        stats = dict(_stats)
        recent = list(_recent_logs)
        attacks = list(_recent_attacks)
        attack_types = dict(_attack_type_counts)
        timeseries = list(_timeseries)

    socketio.emit("init", {
        "stats":        stats,
        "recent_logs":  recent[-50:],   # Son 50 log
        "recent_attacks": attacks[:20],
        "attack_types": attack_types,
        "timeseries":   timeseries,
    })


@socketio.on("disconnect")
def on_disconnect():
    logger.debug("İstemci bağlantısı kesildi")


# ---------------------------------------------------------------------------
# Giriş noktası
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ADS Guardian — Gerçek Zamanlı Siber Güvenlik Dashboard"
    )
    parser.add_argument(
        "--container", "-c",
        default="hedef-sunucu",
        help="Docker container adı (varsayılan: hedef-sunucu)",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=5000,
        help="Flask sunucu portu (varsayılan: 5000)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Dinleme adresi (varsayılan: 0.0.0.0)",
    )
    args = parser.parse_args()

    global _container_name
    _container_name = args.container

    logger.info("ADS Guardian Dashboard başlatılıyor...")

    # Dedektörleri önceden yükle (model soğuk start süresini gizle)
    _get_detectors()

    # Arka plan thread'lerini başlat
    threads = [
        threading.Thread(target=_log_reader_thread, args=(args.container,), daemon=True),
        threading.Thread(target=_socketio_emitter_thread, daemon=True),
        threading.Thread(target=_cleanup_expired_sessions, daemon=True),
        threading.Thread(target=_uptime_thread, daemon=True),
    ]
    for t in threads:
        t.start()

    logger.info("Dashboard: http://%s:%d", args.host, args.port)
    socketio.run(app, host=args.host, port=args.port, debug=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
