import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
import os

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_curve, auc, average_precision_score, precision_recall_curve)

KLASOR = r'c:\Users\aerde\Desktop\bitirme\temizlik'
GRAFIK = os.path.join(KLASOR, 'grafikler')
os.makedirs(GRAFIK, exist_ok=True)

sns.set_theme(style='darkgrid', palette='muted')

# ── 1. VERİ YÜKLE ────────────────────────────────────────────────────────────
def yukle(fname, encoding):
    df = pd.read_csv(os.path.join(KLASOR, fname), encoding=encoding)
    df = df[['Sentence', 'Label']].copy()
    df['Label'] = df['Label'].astype(str).str.strip()
    df = df[df['Label'].isin(['0', '1'])]
    df['Label'] = df['Label'].astype(int)
    df = df.dropna(subset=['Sentence'])
    df['Sentence'] = df['Sentence'].astype(str)
    return df

print('Veriler yükleniyor...')
parcalar = []
for fname, enc in [('sqli.csv', 'utf-16'), ('sqliv2.csv', 'utf-16'), ('SQLiV3.csv', 'latin1')]:
    try:
        df = yukle(fname, enc)
    except Exception:
        df = yukle(fname, 'latin1')
    print(f'  {fname}: {len(df):,} satir | 0={( df.Label==0).sum():,} | 1={(df.Label==1).sum():,}')
    parcalar.append(df)

veri = pd.concat(parcalar, ignore_index=True).drop_duplicates(subset='Sentence')
veri = veri.sample(frac=1, random_state=42).reset_index(drop=True)
print(f'\nBirlesik: {len(veri):,} satir | Benign={( veri.Label==0).sum():,} | SQLi={(veri.Label==1).sum():,}')

X = veri['Sentence']
y = veri['Label']

# ── 2. TF-IDF (karakter n-gram) ──────────────────────────────────────────────
# SQL injection için karakter düzeyinde n-gram çok etkili:
# ' OR, --, /*, UNION gibi pattern'leri yakalar
vectorizer = TfidfVectorizer(
    analyzer='char_wb',
    ngram_range=(2, 4),
    max_features=10_000,
    sublinear_tf=True
)

X_train_raw, X_test_raw, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

X_train = vectorizer.fit_transform(X_train_raw)
X_test  = vectorizer.transform(X_test_raw)

# ── 3. MODEL ─────────────────────────────────────────────────────────────────
print('\nModel egitiliyor...')
model = LogisticRegression(max_iter=1000, random_state=42, C=1.0)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

# ── 4. RAPOR ─────────────────────────────────────────────────────────────────
rapor = classification_report(y_test, y_pred, target_names=['Benign', 'SQLi'])
print('\n=== Siniflandirma Raporu ===')
print(rapor)
with open(os.path.join(KLASOR, 'sqli_model_rapor.txt'), 'w', encoding='utf-8') as f:
    f.write(rapor)

# ── GRAFİK 1: Sınıf Dağılımı ─────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(6, 4))
counts = y.value_counts().rename({0: 'Benign', 1: 'SQLi'})
sns.barplot(x=counts.index, y=counts.values, ax=ax, palette='Set2')
ax.set_title('SQL Injection Dataset - Sınıf Dağılımı')
ax.set_ylabel('Satır Sayısı')
for i, v in enumerate(counts.values):
    ax.text(i, v + 100, f'{v:,}', ha='center', fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(GRAFIK, '1_sqli_sinif_dagilimi.png'), dpi=150)
plt.close()
print('Grafik 1 kaydedildi: sqli_sinif_dagilimi.png')

# ── GRAFİK 2: Confusion Matrix ───────────────────────────────────────────────
cm = confusion_matrix(y_test, y_pred)
fig, ax = plt.subplots(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges',
            xticklabels=['Benign', 'SQLi'],
            yticklabels=['Benign', 'SQLi'], ax=ax)
ax.set_title('SQL Injection - Confusion Matrix')
ax.set_xlabel('Tahmin')
ax.set_ylabel('Gerçek')
plt.tight_layout()
plt.savefig(os.path.join(GRAFIK, '2_sqli_confusion_matrix.png'), dpi=150)
plt.close()
print('Grafik 2 kaydedildi: sqli_confusion_matrix.png')

# ── GRAFİK 3: ROC Curve ──────────────────────────────────────────────────────
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
fig, ax = plt.subplots(figsize=(6, 5))
ax.plot(fpr, tpr, color='darkorange', lw=2, label=f'AUC = {roc_auc:.4f}')
ax.plot([0, 1], [0, 1], 'k--', lw=1)
ax.set_title('SQL Injection - ROC Curve')
ax.set_xlabel('False Positive Rate')
ax.set_ylabel('True Positive Rate')
ax.legend(loc='lower right')
plt.tight_layout()
plt.savefig(os.path.join(GRAFIK, '3_sqli_roc_curve.png'), dpi=150)
plt.close()
print('Grafik 3 kaydedildi: sqli_roc_curve.png')

# ── GRAFİK 4: En Ayırt Edici Karakterler ─────────────────────────────────────
coef = model.coef_[0]
feature_names = vectorizer.get_feature_names_out()
top_sqli   = pd.Series(coef, index=feature_names).nlargest(20)
top_benign = pd.Series(coef, index=feature_names).nsmallest(20)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))
top_sqli.sort_values().plot(kind='barh', ax=axes[0], color='tomato')
axes[0].set_title('SQLi Tarafı - En Güçlü n-gramlar')
axes[0].set_xlabel('Katsayı')

top_benign.sort_values(ascending=False).plot(kind='barh', ax=axes[1], color='steelblue')
axes[1].set_title('Benign Tarafı - En Güçlü n-gramlar')
axes[1].set_xlabel('Katsayı')

plt.suptitle('TF-IDF Karakter N-gram Katsayıları', fontsize=13)
plt.tight_layout()
plt.savefig(os.path.join(GRAFIK, '4_sqli_ngram_katsayilari.png'), dpi=150)
plt.close()
print('Grafik 4 kaydedildi: sqli_ngram_katsayilari.png')

# ── GRAFİK 5: Precision-Recall Curve ─────────────────────────────────────────
prec, rec, _ = precision_recall_curve(y_test, y_prob)
ap = average_precision_score(y_test, y_prob)
fig, ax = plt.subplots(figsize=(6, 5))
ax.plot(rec, prec, color='darkorange', lw=2, label=f'AP = {ap:.4f}')
ax.set_title('SQL Injection - Precision-Recall Curve')
ax.set_xlabel('Recall')
ax.set_ylabel('Precision')
ax.legend(loc='lower left')
plt.tight_layout()
plt.savefig(os.path.join(GRAFIK, '5_sqli_pr_curve.png'), dpi=150)
plt.close()
print('Grafik 5 kaydedildi: sqli_pr_curve.png')

# ── GRAFİK 6: Cross-Validation (5-Fold) ──────────────────────────────────────
print('5-Fold CV hesaplanıyor...')
pipe = Pipeline([
    ('tfidf', TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4),
                              max_features=10_000, sublinear_tf=True)),
    ('clf',   LogisticRegression(max_iter=1000, random_state=42, C=1.0)),
])
cv_results = cross_validate(
    pipe, X, y,
    cv=5, scoring=['accuracy', 'f1_macro', 'precision_macro', 'recall_macro'],
)
cv_metrics = {
    'Accuracy':  cv_results['test_accuracy'],
    'F1 Macro':  cv_results['test_f1_macro'],
    'Precision': cv_results['test_precision_macro'],
    'Recall':    cv_results['test_recall_macro'],
}
fig, ax = plt.subplots(figsize=(9, 5))
for j, (metric, scores) in enumerate(cv_metrics.items()):
    ax.bar(j, scores.mean(), yerr=scores.std(), capsize=5,
           color=sns.color_palette('Set2')[j], alpha=0.85)
    ax.text(j, scores.mean() + scores.std() + 0.002,
            f'{scores.mean():.4f}', ha='center', fontsize=9, fontweight='bold')
ax.set_xticks(range(len(cv_metrics)))
ax.set_xticklabels(cv_metrics.keys())
ax.set_ylim(0.90, 1.01)
ax.set_title('SQLi - 5-Fold Cross-Validation Sonuçları (Ortalama ± Std)')
ax.set_ylabel('Skor')
plt.tight_layout()
plt.savefig(os.path.join(GRAFIK, '6_sqli_cross_validation.png'), dpi=150)
plt.close()
print('Grafik 6 kaydedildi: sqli_cross_validation.png')

cv_rapor = '\n=== 5-Fold Cross-Validation ===\n'
for metric, scores in cv_metrics.items():
    cv_rapor += f'{metric}: {scores.mean():.4f} (±{scores.std():.4f})\n'
print(cv_rapor)
with open(os.path.join(KLASOR, 'sqli_model_rapor.txt'), 'a', encoding='utf-8') as f:
    f.write(cv_rapor)

# ── KAYDET ────────────────────────────────────────────────────────────────────
with open(os.path.join(KLASOR, 'sqli_model.pkl'), 'wb') as f:
    pickle.dump(model, f)
with open(os.path.join(KLASOR, 'sqli_vectorizer.pkl'), 'wb') as f:
    pickle.dump(vectorizer, f)

print('\n=== Tüm dosyalar kaydedildi ===')
print('  sqli_model.pkl')
print('  sqli_vectorizer.pkl')
print('  sqli_model_rapor.txt')
print('  grafikler/1-6 arasi PNG')
