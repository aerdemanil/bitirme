import pandas as pd
import os
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT   = os.path.join(BASE_DIR, 'cleaned_dataset.csv')
CHUNK    = 100_000
TARGET   = 50_000

# Hangi label hangi kategoriye giriyor
LABEL_MAP = {
    'DoS attacks-GoldenEye':   'DoS',
    'DoS attacks-Slowloris':   'DoS',
    'DoS attacks-Hulk':        'DoS',
    'DoS attacks-SlowHTTPTest':'DoS',
    'DDoS attacks-LOIC-HTTP':  'DoS',
    'DDOS attack-HOIC':        'DoS',
    'DDOS attack-LOIC-UDP':    'DoS',
    'FTP-BruteForce':          'BruteForce',
    'SSH-Bruteforce':          'BruteForce',
    'Brute Force -Web':        'BruteForce',
    'Brute Force -XSS':        'BruteForce',
    'Benign':                  'Benign',
}

# Her kategori için hangi dosyalar taranacak (gereksiz 4GB dosyayı atla)
FILE_PRIORITY = {
    'DoS': [
        '02-15-2018.csv',
        '02-16-2018.csv',
        '02-21-2018.csv',
    ],
    'BruteForce': [
        '02-14-2018.csv',
        '02-22-2018.csv',
        '02-23-2018.csv',
    ],
    'Benign': [
        '02-14-2018.csv',
        '02-15-2018.csv',
        '02-16-2018.csv',
    ],
}

def collect(category, target):
    parts = []
    total = 0
    for fname in FILE_PRIORITY[category]:
        if total >= target:
            break
        path = os.path.join(BASE_DIR, fname)
        print(f'  [{category}] {fname} taranıyor...', flush=True)
        for chunk in pd.read_csv(path, chunksize=CHUNK, low_memory=False,
                                  on_bad_lines='skip'):
            chunk.columns = chunk.columns.str.strip()
            mask = chunk['Label'].map(LABEL_MAP) == category
            selected = chunk[mask].copy()
            selected['Label'] = category
            parts.append(selected)
            total += len(selected)
            if total >= target:
                break

    if not parts:
        return pd.DataFrame()

    df = pd.concat(parts, ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df.head(target)

print('=== Temizleme başladı ===\n')

results = []
for category in ['DoS', 'BruteForce', 'Benign']:
    print(f'[{category}] toplanıyor...')
    df = collect(category, TARGET)
    print(f'  -> {len(df):,} satır toplandı\n')
    results.append(df)

print('Birleştiriliyor ve karıştırılıyor...')
final = pd.concat(results, ignore_index=True)
final = final.sample(frac=1, random_state=42).reset_index(drop=True)

print(f'Kaydediliyor: {OUTPUT}')
final.to_csv(OUTPUT, index=False)

print('\n=== Tamamlandı ===')
print(f'Toplam satır : {len(final):,}')
print(f'Label dağılımı:\n{final["Label"].value_counts()}')
