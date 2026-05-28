"""
SQLi modelini gerçek Tanner honeypot trafiği üzerinde test eder.
Amaç: train raporundaki %99.67 skoru gerçek dünyada da geçerli mi?
"""
import csv
import pickle
import os
from urllib.parse import unquote

KLASOR = r'c:\Users\aerde\Desktop\bitirme\temizlik'
TANNER_CSV = r'c:\Users\aerde\Desktop\bitirme\son_12_saat_tanner_detayli_tekil.csv'

with open(os.path.join(KLASOR, 'sqli_model.pkl'), 'rb') as f:
    model = pickle.load(f)
with open(os.path.join(KLASOR, 'sqli_vectorizer.pkl'), 'rb') as f:
    vec = pickle.load(f)

SQLI_KEYWORDS = ('select', 'union', 'case when', 'waitfor', 'sleep(',
                 'raise_error', 'procedure analyse', '1=1', '1%3d1',
                 '--', "'", '%27', 'extractvalue', 'updatexml', 'benchmark')

sqli_paths = []
benign_paths = []

with open(TANNER_CSV, encoding='utf-8') as f:
    for row in csv.DictReader(f):
        path = row.get('path', '') or ''
        if not path:
            continue
        decoded = unquote(path).lower()
        is_sqli_pattern = any(kw in decoded for kw in SQLI_KEYWORDS)
        if is_sqli_pattern:
            sqli_paths.append(unquote(path))
        else:
            benign_paths.append(path)

print(f'Tanner CSV ayrımı:')
print(f'  SQLi-pattern path: {len(sqli_paths):,}')
print(f'  Benign path      : {len(benign_paths):,}')

def evaluate(paths, label_name, expected):
    if not paths:
        print(f'\n[{label_name}] örnek yok, atlaniyor.')
        return
    X = vec.transform(paths)
    preds = model.predict(X)
    probs = model.predict_proba(X)[:, 1]
    sqli_count = int((preds == 1).sum())
    benign_count = int((preds == 0).sum())
    correct = sqli_count if expected == 1 else benign_count
    acc = correct / len(paths)

    print(f'\n[{label_name}] ({len(paths):,} örnek, beklenen={expected})')
    print(f'  Model SQLi dedi : {sqli_count:,}')
    print(f'  Model Benign dedi: {benign_count:,}')
    print(f'  Doğruluk        : {acc:.4f}')
    print(f'  Ortalama SQLi olasılığı: {probs.mean():.4f}')

    # Yanılgı örnekleri
    wrong_idx = [i for i, p in enumerate(preds) if p != expected]
    if wrong_idx:
        print(f'  Hatalı sınıflandırma örnekleri (ilk 5):')
        for i in wrong_idx[:5]:
            print(f'    [prob={probs[i]:.3f}] {paths[i][:120]}')

evaluate(sqli_paths,   'GERÇEK SQLi PATH',   expected=1)

# Benign örnek çok fazla — temsili 5000 al
import random
random.seed(42)
benign_sample = random.sample(benign_paths, min(5000, len(benign_paths)))
evaluate(benign_sample, 'BENIGN PATH (sample)', expected=0)

print('\n=== ÖZET ===')
print('Train raporu      : Accuracy=0.9967 (sentetik Kaggle datasetinde)')
print('Bu test (gerçek)  : Yukarıdaki "Doğruluk" satırlarına bak.')
print('Aradaki fark = sentetik vs gerçek dünya generalization gap.')
