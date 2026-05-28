import pandas as pd
import os
from collections import Counter

KLASOR = r'c:\Users\aerde\Desktop\bitirme\temizlik'
CIKTI = os.path.join(KLASOR, 'label_dagilim.txt')
CHUNK = 100_000

dosyalar = sorted([f for f in os.listdir(KLASOR) if f.endswith('.csv')])

with open(CIKTI, 'w', encoding='utf-8') as out:
    for fname in dosyalar:
        yol = os.path.join(KLASOR, fname)
        print(f'Okunuyor: {fname}', flush=True)
        out.write(f'\n=== {fname} ===\n')

        sayac = Counter()
        for chunk in pd.read_csv(yol, usecols=['Label'], chunksize=CHUNK,
                                  low_memory=False, on_bad_lines='skip'):
            sayac.update(chunk['Label'].dropna().tolist())

        toplam = sum(sayac.values())
        for label, cnt in sayac.most_common():
            satir = f'  {label}: {cnt:,}'
            print(satir)
            out.write(satir + '\n')
        out.write(f'  TOPLAM: {toplam:,}\n')
        print(f'  TOPLAM: {toplam:,}\n')

print(f'\nKaydedildi: {CIKTI}')
