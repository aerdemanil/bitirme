"""
run.py
------
ADS Guardian — Tek komutla başlatıcı.

Kullanım:
    python run.py
    python run.py --container benim-nginx --port 8080
"""

import argparse
import os
import socket
import subprocess
import sys
import time


# ─── Renkli çıktı (colorama olmasa bile çalışır) ───────────
try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    def _c(text, color): return color + text + Style.RESET_ALL
except ImportError:
    def _c(text, _): return text

GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
  ╔══════════════════════════════════════════════════╗
  ║       🛡️  ADS Guardian — Saldırı Tespit Sistemi  ║
  ║                      v2.0                        ║
  ╚══════════════════════════════════════════════════╝
{RESET}"""


def get_local_ip() -> str:
    """Makinenin yerel ağ IP adresini otomatik tespit eder."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def check_model(project_dir: str) -> bool:
    """Model dosyasının var olup olmadığını kontrol eder."""
    model_path = os.path.join(project_dir, "models", "dos_model.pkl")
    return os.path.exists(model_path)


def train_model(_project_dir: str) -> None:
    """Model eksikse kullanıcıya bilgi verir."""
    print(f"\n{RED}❌ Model dosyası bulunamadı.{RESET}")
    print(f"{YELLOW}   Lütfen önce 'ml_pipeline/train_cic_http.py' scriptini çalıştırın{RESET}")
    print(f"{YELLOW}   ve üretilen ml_model.pkl dosyasını models/dos_model.pkl olarak kopyalayın.{RESET}")
    sys.exit(1)


def check_requirements(project_dir: str) -> None:
    """Eksik paketleri otomatik kurar."""
    req_file = os.path.join(project_dir, "requirements.txt")
    if not os.path.exists(req_file):
        return
    print(f"{YELLOW}📦 Gereksinimler kontrol ediliyor...{RESET}", end=" ", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", req_file, "-q"],
        capture_output=True,
    )
    if result.returncode == 0:
        print(f"{GREEN}✅{RESET}")
    else:
        print(f"{YELLOW}⚠️  Bazı paketler kurulamadı (devam ediliyor){RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="ADS Guardian — Tek komutla başlatıcı"
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
        help="Dashboard portu (varsayılan: 5000)",
    )
    parser.add_argument(
        "--skip-train",
        action="store_true",
        help="Model eğitimini atla",
    )
    args = parser.parse_args()

    project_dir = os.path.dirname(os.path.abspath(__file__))
    local_ip    = get_local_ip()

    print(BANNER)

    # 1) Gereksinimler
    check_requirements(project_dir)

    # 2) Model kontrolü
    if not args.skip_train and not check_model(project_dir):
        train_model(project_dir)
    else:
        print(f"{GREEN}✅ Model mevcut{RESET}")

    # 3) Başlatma bilgisi
    print(f"""
{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
  🐳  Container    : {CYAN}{args.container}{RESET}
  🌐  Dashboard    : {GREEN}http://localhost:{args.port}{RESET}
  🔗  Ağ Erişimi   : {GREEN}http://{local_ip}:{args.port}{RESET}
  ⏹️   Durdurmak    : Ctrl+C
{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
""")

    time.sleep(1)

    # 4) Dashboard'u başlat
    subprocess.run(
        [
            sys.executable,
            "dashboard.py",
            "--container", args.container,
            "--port",      str(args.port),
        ],
        cwd=project_dir,
    )


if __name__ == "__main__":
    main()
