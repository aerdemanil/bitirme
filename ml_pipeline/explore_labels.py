import pandas as pd
import os
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(BASE_DIR, 'label_distribution.txt')
CHUNK = 100_000

files = sorted([f for f in os.listdir(BASE_DIR) if f.endswith('.csv')])

with open(OUTPUT, 'w', encoding='utf-8') as out:
    for fname in files:
        path = os.path.join(BASE_DIR, fname)
        print(f'Okunuyor: {fname}', flush=True)
        out.write(f'\n=== {fname} ===\n')

        counter = Counter()
        for chunk in pd.read_csv(path, usecols=['Label'], chunksize=CHUNK,
                                  low_memory=False, on_bad_lines='skip'):
            counter.update(chunk['Label'].dropna().tolist())

        total = sum(counter.values())
        for label, cnt in counter.most_common():
            line = f'  {label}: {cnt:,}'
            print(line)
            out.write(line + '\n')
        out.write(f'  TOPLAM: {total:,}\n')
        print(f'  TOPLAM: {total:,}\n')

print(f'\nKaydedildi: {OUTPUT}')
