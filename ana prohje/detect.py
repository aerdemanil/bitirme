"""
detect.py
---------
Gerçek zamanlı DoS ve saldırı tespit ana döngüsü.

Docker container'ından canlı nginx loglarını okur, her satırı
parse ederek tüm kayıtlı saldırı dedektörlerini koşturur.

Kullanım:
    python detect.py [--container hedef-sunucu] [--threshold 0.55]

Gereksinimler:
    - Docker'ın makinede çalışıyor olması
    - `hedef-sunucu` container'ının ayakta olması
    - `temizlik/train_cic_http.py` ile modelin önce eğitilmiş olması
"""

import argparse
import sys
import time
import docker
import threading
from datetime import datetime, timezone
from colorama import Fore, Style, init as colorama_init

from detector.feature_extractor import parse_log_line
from detector.attack_registry import get_all_detectors, list_registered

colorama_init(autoreset=True)

# ──────────────────────────────────────────────────────────────
BANNER = r"""
  ____          ____       _            _
 |  _ \  ___  / ___| __ _| | __ _ _ __| |_
 | | | |/ _ \| |  _ / _` | |/ _` | '__| __|
 | |_| | (_) | |_| | (_| | | (_| | |  | |_
 |____/ \___/ \____|\__,_|_|\__,_|_|   \__|

  🛡️  Saldırı Tespit Sistemi — Gerçek Zamanlı Mod
"""
# ──────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


# Saldırı istatistiklerini takip etmek için
# IP -> {start_time, last_seen, total_req, peak_rpm, peak_conf}
_attack_sessions: dict[str, dict] = {}
_flagged_ips: set[str] = set()      # Şu an saldırı altında olan IP'ler
_last_alert: dict[str, float] = {}
ALERT_COOLDOWN_SECONDS = 15
SESSION_TIMEOUT_SECONDS = 20        # Bu kadar süre log gelmezse saldırı bitti sayılır


def _should_alert(ip: str) -> bool:
    """True dönerse alarm basabilirsin, False ise cooldown'da."""
    now = time.time()
    last = _last_alert.get(ip, 0)
    if now - last >= ALERT_COOLDOWN_SECONDS:
        _last_alert[ip] = now
        return True
    return False


def _print_detection(detector_name: str, ip: str, conf: float, features: dict, suppressed_count: int = 0):
    level = "🔴 KRİTİK" if conf > 0.80 else "🟡 UYARI"
    extra = f" (+{suppressed_count} tekrar baskılandı)" if suppressed_count else ""
    print(
        f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}\n"
        f"  {level}  [{_now()}]{extra}\n"
        f"  Tip      : {Fore.YELLOW}{detector_name.upper()}{Style.RESET_ALL}\n"
        f"  IP       : {Fore.CYAN}{ip}{Style.RESET_ALL}\n"
        f"  Güven    : {Fore.MAGENTA}{conf:.2%}{Style.RESET_ALL}\n"
        f"  İstek/dk : {features.get('requests_per_ip_last_60s', '?')}\n"
        f"  Durum    : {features.get('status_code', '?')}\n"
        f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n"
    )


def _print_cleared(ip: str):
    if ip in _attack_sessions:
        stats = _attack_sessions.pop(ip)
        duration = time.time() - stats["start_time"]
        print(
            f"\n{Fore.GREEN}┌──────────────────────────────────────────────────────────┐{Style.RESET_ALL}\n"
            f"{Fore.GREEN}│            🛡️  SALDIRI ÖZET RAPORU (SONLANDI)            │{Style.RESET_ALL}\n"
            f"{Fore.GREEN}├──────────────────────────────────────────────────────────┤{Style.RESET_ALL}\n"
            f"  📍 Hedef IP    : {Fore.CYAN}{ip}{Style.RESET_ALL}\n"
            f"  ⏱️  Toplam Süre  : {Fore.YELLOW}{duration:.1f} saniye{Style.RESET_ALL}\n"
            f"  📊 Toplam İstek : {Fore.WHITE}{stats['total_req']}{Style.RESET_ALL}\n"
            f"  🔥 Pik Yoğunluk : {Fore.RED}{stats['peak_rpm']} İstek/dk{Style.RESET_ALL}\n"
            f"  🎯 Maks. Güven  : {Fore.MAGENTA}{stats['peak_conf']:.2%}{Style.RESET_ALL}\n"
            f"{Fore.GREEN}└──────────────────────────────────────────────────────────┘{Style.RESET_ALL}\n"
        )
    else:
        print(
            f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n"
            f"  ✅ TEMIZ  [{_now()}]\n"
            f"  IP {Fore.CYAN}{ip}{Style.RESET_ALL} için trafik normale döndü.\n"
            f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n"
        )


def _monitor_timeouts():
    """Arka planda çalışıp sessizleşen saldırıları sonlandırır."""
    while True:
        time.sleep(5)
        now = time.time()
        to_clear = []
        for ip, stats in _attack_sessions.items():
            if now - stats["last_seen"] > SESSION_TIMEOUT_SECONDS:
                to_clear.append(ip)
        
        for ip in to_clear:
            if ip in _flagged_ips:
                _flagged_ips.discard(ip)
                _print_cleared(ip)


def run_detection(container_name: str):
    # ── Docker bağlantısı ─────────────────────────────────────
    try:
        client = docker.from_env()
        container = client.containers.get(container_name)
    except docker.errors.NotFound:
        print(f"{Fore.RED}❌ Container bulunamadı: '{container_name}'{Style.RESET_ALL}")
        print("   docker ps -a  komutuyla aktif container'ları kontrol edin.")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}❌ Docker bağlantı hatası: {e}{Style.RESET_ALL}")
        sys.exit(1)

    # ── Dedektörleri yükle ───────────────────────────────────
    print(f"{Fore.GREEN}⚙️  Kayıtlı dedektörler yükleniyor...{Style.RESET_ALL}")
    try:
        detectors = get_all_detectors()
    except FileNotFoundError as e:
        print(f"\n{Fore.RED}❌ {e}{Style.RESET_ALL}\n")
        sys.exit(1)

    # Aktif (implement edilmiş) dedektör isimleri
    _IMPLEMENTED = {"dos", "brute_force", "sql_injection"}
    active = [d for d in detectors if d.name in _IMPLEMENTED]
    passive = [d for d in detectors if d.name not in _IMPLEMENTED]

    print(f"   ✅ Aktif  : {[d.name for d in active]}")
    print(f"   ⏳ Pasif  : {[d.name for d in passive]} (henüz implement edilmedi)\n")

    # Zaman aşımı izleyiciyi başlat
    monitor_thread = threading.Thread(target=_monitor_timeouts, daemon=True)
    monitor_thread.start()

    # ── Log akışı ────────────────────────────────────────────
    print(f"{Fore.GREEN}📡 '{container_name}' container log akışı başlatılıyor...{Style.RESET_ALL}")
    print(f"   Çıkmak için  Ctrl+C  tuşlayın.\n")

    stats = {"total": 0, "attacks": 0, "parse_errors": 0}
    _suppressed_counts: dict[str, int] = {}  # IP → baskılanan alarm sayısı

    # Sadece detect.py başladıktan SONRA gelen logları al — geçmişi atla
    start_time = datetime.now(timezone.utc)
    log_stream = container.logs(stream=True, follow=True, since=start_time, timestamps=False)

    def _flush_batch(batch, detectors, stats_ref):
        """Biriken batch'i tüm dedektörlerden geçirir."""
        nonlocal attack_count
        if not batch:
            return
        for detector in detectors:
            try:
                if hasattr(detector, "detect_batch"):
                    is_attacks = detector.detect_batch(batch)
                    confs = detector.confidence_batch(batch)
                else:
                    is_attacks = [detector.detect(f) for f in batch]
                    confs = [detector.confidence(f) for f in batch]

                for is_attack, conf, f in zip(is_attacks, confs, batch):
                    ip = f.get("ip", "unknown")
                    if is_attack:
                        _flagged_ips.add(ip)
                        if ip not in _attack_sessions:
                            _attack_sessions[ip] = {
                                "start_time": time.time(),
                                "last_seen": time.time(),
                                "total_req": 0,
                                "peak_rpm": 0,
                                "peak_conf": 0,
                            }
                        sess = _attack_sessions[ip]
                        sess["last_seen"] = time.time()
                        sess["total_req"] += 1
                        sess["peak_rpm"] = max(sess["peak_rpm"], f.get("requests_per_ip_last_60s", 0))
                        sess["peak_conf"] = max(sess["peak_conf"], conf)

                        if _should_alert(ip):
                            suppressed = _suppressed_counts.pop(ip, 0)
                            attack_count += 1
                            _print_detection(detector.name, ip, conf, f, suppressed)
                        else:
                            _suppressed_counts[ip] = _suppressed_counts.get(ip, 0) + 1
                    else:
                        if ip in _flagged_ips:
                            _flagged_ips.discard(ip)
                            _last_alert.pop(ip, None)
                            _suppressed_counts.pop(ip, None)
                            _print_cleared(ip)
            except Exception as exc:
                print(f"{Fore.YELLOW}⚠️  Dedektör hatası ({detector.name}): {exc}{Style.RESET_ALL}")

    try:
        # Performans için döngü başında statları lokal değişkenlere al
        processed_count = stats["total"]
        attack_count = stats["attacks"]
        error_count = stats["parse_errors"]

        BATCH_SIZE = 20          # Daha küçük batch — dış saldırılar da hızlı işlensin
        BATCH_FLUSH_INTERVAL = 2 # Saniye — batch dolmasa bile flush et
        batch_features = []
        last_flush = time.time()

        for raw_line in log_stream:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            processed_count += 1
            features = parse_log_line(line)

            if features is None:
                error_count += 1
                continue

            batch_features.append(features)

            now = time.time()
            should_flush = (
                len(batch_features) >= BATCH_SIZE
                or (now - last_flush >= BATCH_FLUSH_INTERVAL and batch_features)
            )

            if should_flush:
                _flush_batch(batch_features, active, stats)
                batch_features = []
                last_flush = now

            # İlerleme göstergesi (her 100 satırda bir)
            if processed_count % 100 == 0:
                print(
                    f"  [{_now()}] "
                    f"İşlenen: {processed_count:,} | "
                    f"Saldırı: {Fore.RED}{attack_count}{Style.RESET_ALL} | "
                    f"Parse hatası: {error_count}"
                )
            
            # Statları periyodik olarak güncelle (Interrupt durumunda kaybolmaması için)
            stats["total"] = processed_count
            stats["attacks"] = attack_count
            stats["parse_errors"] = error_count

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⏹️  Tespit durduruldu.{Style.RESET_ALL}")
        print(f"\n{'─'*40}")
        print(f"  📈 Özet Rapor")
        print(f"{'─'*40}")
        print(f"  İşlenen log satırı : {stats['total']:,}")
        print(f"  Tespit edilen saldırı: {Fore.RED}{stats['attacks']}{Style.RESET_ALL}")
        print(f"  Parse hatası       : {stats['parse_errors']}")
        print(f"{'─'*40}\n")


def main():
    parser = argparse.ArgumentParser(
        description="DoS ve Saldırı Tespit Sistemi — Gerçek Zamanlı Nginx Log Analizi"
    )
    parser.add_argument(
        "--container", "-c",
        default="hedef-sunucu",
        help="Docker container adı (varsayılan: hedef-sunucu)"
    )
    args = parser.parse_args()

    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    run_detection(args.container)


if __name__ == "__main__":
    main()
