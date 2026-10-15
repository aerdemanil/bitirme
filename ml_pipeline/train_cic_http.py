import warnings
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
import os

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_validate
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PLOTS_DIR = os.path.join(BASE_DIR, 'plots')
os.makedirs(PLOTS_DIR, exist_ok=True)

sns.set_theme(style='darkgrid', palette='muted')

# ── 1. VERİ ──────────────────────────────────────────────────────────────────
print('Veri yükleniyor...')
df = pd.read_csv(os.path.join(BASE_DIR, 'cleaned_dataset.csv'), low_memory=False)
df.columns = df.columns.str.strip()
print(f'  {len(df):,} satır yüklendi | Sınıflar: {df["Label"].value_counts().to_dict()}')

# ── 2. CIC → HTTP FEATURE MAPPING ────────────────────────────────────────────
print('\nFeature mapping uygulanıyor...')

def map_features(df):
    out = pd.DataFrame()

    # requests_per_ip_last_60s ← Flow Pkts/s × 60
    col = 'Flow Pkts/s'
    vals = pd.to_numeric(df[col], errors='coerce').fillna(0)
    vals = vals.replace([np.inf, -np.inf], 0)
    out['requests_per_ip_last_60s'] = (vals * 60).clip(0, 50000).astype(int)

    # bytes_sent ← TotLen Fwd Pkts
    col = 'TotLen Fwd Pkts'
    vals = pd.to_numeric(df[col], errors='coerce').fillna(0)
    out['bytes_sent'] = vals.clip(0, 1_000_000).astype(int)

    # status_code ← Dst Port bucket (80/443 → 200, diğer → 404)
    col = 'Dst Port'
    ports = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
    out['status_code'] = ports.apply(lambda p: 200 if p in (80, 443, 8080, 8443) else 404)

    # method_encoded ← Protocol bucket (6=TCP→0, 17=UDP→1, diğer→2)
    col = 'Protocol'
    proto = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
    out['method_encoded'] = proto.apply(lambda p: 0 if p == 6 else (1 if p == 17 else 2))

    # path_depth ← Fwd Seg Size Avg normalize → 0-5
    col = 'Fwd Seg Size Avg'
    vals = pd.to_numeric(df[col], errors='coerce').fillna(0)
    vals = vals.replace([np.inf, -np.inf], 0).clip(0, 1500)
    out['path_depth'] = (vals / 300).clip(0, 5).round().astype(int)

    # user_agent_length ← Pkt Len Mean normalize → 0-300
    col = 'Pkt Len Mean'
    vals = pd.to_numeric(df[col], errors='coerce').fillna(0)
    vals = vals.replace([np.inf, -np.inf], 0).clip(0, 1500)
    out['user_agent_length'] = (vals / 5).clip(0, 300).round().astype(int)

    return out

X = map_features(df)

y = df['Label']

# NOT: label-based status_code override kaldırıldı — target leakage'a yol açıyordu.
# status_code artık yalnızca Dst Port'tan türetiliyor (map_features içinde).

print('  Mapping sonrası feature istatistikleri:')
print(X.describe().round(2))

# ── 3. ENCODE + SCALE ────────────────────────────────────────────────────────
le = LabelEncoder()
y_enc = le.fit_transform(y)
print(f'\nSınıf sırası: {list(le.classes_)}')

X_train_df, X_test_df, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train_df)
X_test  = scaler.transform(X_test_df)

# ── 4. MODEL ─────────────────────────────────────────────────────────────────
print('\nModel eğitiliyor...')
model = RandomForestClassifier(n_estimators=100, random_state=42,
                               n_jobs=-1, class_weight='balanced')
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

# ── 5. RAPOR ─────────────────────────────────────────────────────────────────
report = classification_report(y_test, y_pred, target_names=le.classes_)
print('\n=== Sınıflandırma Raporu ===')
print(report)
with open(os.path.join(BASE_DIR, 'ml_model_report.txt'), 'w', encoding='utf-8') as f:
    f.write('CIC-IDS2018 → HTTP Feature Mapping ile eğitilmiş model\n\n')
    f.write(report)

# ── GRAFİK 7: Sınıf Dağılımı ─────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 4))
counts = y.value_counts()
sns.barplot(x=counts.index, y=counts.values, ax=ax, palette='Set2')
ax.set_title('CIC-IDS2018 — Gerçek Veri Sınıf Dağılımı')
ax.set_xlabel('Sınıf')
ax.set_ylabel('Satır Sayısı')
for i, v in enumerate(counts.values):
    ax.text(i, v + 300, f'{v:,}', ha='center', fontweight='bold')
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, '7_cic_sinif_dagilimi.png'), dpi=150)
plt.close()
print('Grafik 7 kaydedildi.')

# ── GRAFİK 8: Confusion Matrix ───────────────────────────────────────────────
cm = confusion_matrix(y_test, y_pred)
fig, ax = plt.subplots(figsize=(7, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=le.classes_, yticklabels=le.classes_, ax=ax)
ax.set_title('CIC-IDS2018 — Confusion Matrix')
ax.set_xlabel('Tahmin')
ax.set_ylabel('Gerçek')
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, '8_cic_confusion_matrix.png'), dpi=150)
plt.close()
print('Grafik 8 kaydedildi.')

# ── GRAFİK 9: Feature Importance ─────────────────────────────────────────────
feature_names = list(X.columns)
importances = pd.Series(model.feature_importances_, index=feature_names).sort_values()
fig, ax = plt.subplots(figsize=(8, 5))
importances.plot(kind='barh', ax=ax, color=sns.color_palette('Set2', len(feature_names)))
ax.set_title('CIC → HTTP Mapping — Feature Importance')
ax.set_xlabel('Önem Skoru')
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, '9_cic_feature_importance.png'), dpi=150)
plt.close()
print('Grafik 9 kaydedildi.')

# ── GRAFİK 10: ROC Curve ─────────────────────────────────────────────────────
y_prob = model.predict_proba(X_test)
fig, ax = plt.subplots(figsize=(7, 5))
for i, cls in enumerate(le.classes_):
    fpr, tpr, _ = roc_curve((y_test == i).astype(int), y_prob[:, i])
    roc_auc = auc(fpr, tpr)
    ax.plot(fpr, tpr, linewidth=2, label=f'{cls} (AUC={roc_auc:.3f})')
ax.plot([0, 1], [0, 1], 'k--', linewidth=1)
ax.set_title('CIC-IDS2018 — ROC Curve (3 Sınıf, One-vs-Rest)')
ax.set_xlabel('False Positive Rate')
ax.set_ylabel('True Positive Rate')
ax.legend(loc='lower right')
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, '10_cic_roc_curve.png'), dpi=150)
plt.close()
print('Grafik 10 kaydedildi.')

# ── GRAFİK 11: Cross-Validation (5-Fold) ─────────────────────────────────────
print('5-Fold CV hesaplanıyor...')
cv_pipe = Pipeline([
    ('scaler', StandardScaler()),
    ('clf', RandomForestClassifier(
        n_estimators=100, random_state=42,
        n_jobs=-1, class_weight='balanced'
    )),
])
cv_results = cross_validate(
    cv_pipe, X.values, y_enc,
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
ax.set_ylim(0.85, 1.01)
ax.set_title('DoS/BruteForce - 5-Fold Cross-Validation Sonuçları (Ortalama +- Std)')
ax.set_ylabel('Skor')
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, '11_cic_cross_validation.png'), dpi=150)
plt.close()
print('Grafik 11 kaydedildi.')

cv_report = '\n=== 5-Fold Cross-Validation ===\n'
for metric, scores in cv_metrics.items():
    cv_report += f'{metric}: {scores.mean():.4f} (+-{scores.std():.4f})\n'
print(cv_report)
with open(os.path.join(BASE_DIR, 'ml_model_report.txt'), 'a', encoding='utf-8') as f:
    f.write(cv_report)

# ── KAYDET ────────────────────────────────────────────────────────────────────
with open(os.path.join(BASE_DIR, 'ml_model.pkl'), 'wb') as f:
    pickle.dump(model, f)
with open(os.path.join(BASE_DIR, 'ml_scaler.pkl'), 'wb') as f:
    pickle.dump(scaler, f)
with open(os.path.join(BASE_DIR, 'ml_encoder.pkl'), 'wb') as f:
    pickle.dump(le, f)

# app/models/ — runtime tarafinin okudugu yer
MODELS_DIR = os.path.join(os.path.dirname(BASE_DIR), 'app', 'models')
os.makedirs(MODELS_DIR, exist_ok=True)
with open(os.path.join(MODELS_DIR, 'dos_model.pkl'),  'wb') as f: pickle.dump(model,  f)
with open(os.path.join(MODELS_DIR, 'ml_scaler.pkl'),  'wb') as f: pickle.dump(scaler, f)
with open(os.path.join(MODELS_DIR, 'ml_encoder.pkl'), 'wb') as f: pickle.dump(le,     f)

print('\n=== Tamamlandi ===')
print('  ml_model.pkl  |  ml_scaler.pkl  |  ml_encoder.pkl')
print('  Sinif sirasi : %s -> indeks [0, 1, 2]' % list(le.classes_))
print('  Grafikler    : plots/7-11')
