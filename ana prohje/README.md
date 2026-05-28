# 🛡️ DoS Saldırı Tespit Sistemi

Docker'daki `hedef-sunucu` nginx container'ından gerçek zamanlı log okuyarak ağ saldırılarını tespit eden **Python + Random Forest** tabanlı makine öğrenmesi sistemi.

## Proje Yapısı

```
ana prohje/
├── train.py                      # Modeli eğit
├── detect.py                     # Gerçek zamanlı algılama
├── requirements.txt
└── detector/
    ├── base_attack.py            # Soyut temel sınıf
    ├── feature_extractor.py      # Nginx log → özellik vektörü
    ├── attack_registry.py        # Plugin/kayıt sistemi
    └── attacks/
        ├── dos_detector.py       # ✅ Random Forest DoS dedektörü
        ├── brute_force.py        # ⏳ Gelecekte implement edilecek
        ├── sql_injection.py      # ⏳ Gelecekte implement edilecek
        └── mitm_detector.py      # ⏳ Gelecekte implement edilecek
```

## Hızlı Başlangıç

```bash
# 1 — Bağımlılıkları yükle
pip install -r requirements.txt

# 2 — Modeli eğit (ilk seferinde zorunlu)
python train.py

# 3 — Gerçek zamanlı tespiti başlat
python detect.py

# Farklı bir container için:
python detect.py --container hedef-sunucu
```

## DoS Tespiti Nasıl Çalışır?

| Adım | Açıklama |
|------|----------|
| **Log Akışı** | Docker Python SDK ile `hedef-sunucu` container'ının nginx logları canlı okunur |
| **Parse** | Her satır `feature_extractor.py` ile ayrıştırılır |
| **Özellikler** | IP başına istek/dk, bytes_sent, status_code, yanıt süresi vb. çıkarılır |
| **Model** | Eğitilmiş Random Forest saldırı olasılığını tahmin eder |
| **Alarm** | Eşik (≥ %55) aşılırsa renkli terminal uyarısı verilir |

## Yeni Saldırı Tipi Ekleme

1. `detector/attacks/yeni_tip.py` dosyası oluştur
2. `BaseAttackDetector`'i genişlet
3. `@register` dekoratörü ekle
4. **Başka hiçbir şeye dokunma** — sistem otomatik yükler

```python
from detector.base_attack import BaseAttackDetector
from detector.attack_registry import register

@register
class YeniTipDetector(BaseAttackDetector):
    name = "yeni_tip"

    def detect(self, features: dict) -> bool:
        return features["requests_per_ip_last_60s"] > 200

    def confidence(self, features: dict) -> float:
        return min(features["requests_per_ip_last_60s"] / 500, 1.0)
```

## Planlanan Geliştirmeler

- [ ] **Brute Force**: Başarısız kimlik doğrulama tespiti (401/403 flood)
- [ ] **SQL Injection**: URL parametrelerinde şüpheli payload analizi  
- [ ] **MITM**: Anormal header ve SSL anomali tespiti
- [ ] **Web Dashboard**: Gerçek zamanlı grafik arayüz
- [ ] **Log dosyasına kayıt**: Tespit edilen saldırıların saklanması
