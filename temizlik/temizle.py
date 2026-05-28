import pandas as pd
import os
from collections import defaultdict

KLASOR = r'c:\Users\aerde\Desktop\bitirme\temizlik'
CIKTI  = os.path.join(KLASOR, 'cleaned_dataset.csv')
CHUNK  = 100_000
HEDEF  = 50_000

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
DOSYA_ONCELIK = {
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

def topla(kategori, hedef):
    parcalar = []
    toplam   = 0
    for fname in DOSYA_ONCELIK[kategori]:
        if toplam >= hedef:
            break
        yol = os.path.join(KLASOR, fname)
        print(f'  [{kategori}] {fname} taranıyor...', flush=True)
        for chunk in pd.read_csv(yol, chunksize=CHUNK, low_memory=False,
                                  on_bad_lines='skip'):
            chunk.columns = chunk.columns.str.strip()
            mask = chunk['Label'].map(LABEL_MAP) == kategori
            secilen = chunk[mask].copy()
            secilen['Label'] = kategori
            parcalar.append(secilen)
            toplam += len(secilen)
            if toplam >= hedef:
                break

    if not parcalar:
        return pd.DataFrame()

    df = pd.concat(parcalar, ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df.head(hedef)

print('=== Temizleme başladı ===\n')

sonuclar = []
for kategori in ['DoS', 'BruteForce', 'Benign']:
    print(f'[{kategori}] toplanıyor...')
    df = topla(kategori, HEDEF)
    print(f'  -> {len(df):,} satır toplandı\n')
    sonuclar.append(df)

print('Birleştiriliyor ve karıştırılıyor...')
final = pd.concat(sonuclar, ignore_index=True)
final = final.sample(frac=1, random_state=42).reset_index(drop=True)

print(f'Kaydediliyor: {CIKTI}')
final.to_csv(CIKTI, index=False)

print('\n=== Tamamlandı ===')
print(f'Toplam satır : {len(final):,}')
print(f'Label dağılımı:\n{final["Label"].value_counts()}')
