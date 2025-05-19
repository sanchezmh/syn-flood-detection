# isolation_forest_benign_only.py

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix

# === Load Dataset ===
df_raw = pd.read_csv('dummy/Syn.csv', low_memory=False)
df_raw.columns = df_raw.columns.str.strip()
print("Initial shape:", df_raw.shape)

# === Backup the Label column ===
if 'Label' in df_raw.columns:
    y_raw = df_raw['Label'].copy()
else:
    raise ValueError("No 'Label' column found in dataset.")

# === Drop identifier/non-numeric columns globally ===
drop_cols = [
    'Unnamed: 0', 'Flow ID', 'Source IP', 'Destination IP',
    'Timestamp', 'Source Port', 'Destination Port', 'Protocol', 'Label'
]

df_cleaned = df_raw.drop(columns=[col for col in drop_cols if col in df_raw.columns])
non_numeric_cols = df_cleaned.select_dtypes(exclude=[np.number]).columns.tolist()
df_cleaned = df_cleaned.drop(columns=non_numeric_cols)
df_cleaned = df_cleaned.replace([np.inf, -np.inf], np.nan).dropna()

# === Make a full copy for prediction ===
df_full = df_cleaned.copy()

# === Step 1: Extract benign flows for training ===
benign_mask = y_raw.str.upper().str.contains("BENIGN")
df_benign = df_cleaned[benign_mask].copy()

print(f"Training on {df_benign.shape[0]} benign samples...")

# === Step 2: Fit scaler & train IF on benign only ===
scaler = MinMaxScaler()
X_benign = scaler.fit_transform(df_benign)

iso = IsolationForest(contamination=0.02, max_samples=512, random_state=42)
iso.fit(X_benign)

# === Step 3: Predict on full dataset ===
X_full = scaler.transform(df_full)
raw_preds = iso.predict(X_full)
scores = iso.decision_function(X_full)
preds = np.where(raw_preds == -1, 1, 0)  # 1 = anomaly (likely SYN), 0 = normal

# === Step 4: Build ground truth labels ===
y_true = y_raw[df_full.index].apply(lambda v: 1 if 'SYN' in str(v).upper() else 0)

# === Step 5: Evaluate ===
print("\n=== Classification Report (1 = SYN, 0 = benign) ===")
print(classification_report(y_true, preds))

print("\n=== Confusion Matrix ===")
print(confusion_matrix(y_true, preds))

# === Step 6: Save Results ===
results_df = df_full.copy()
results_df['IF_score'] = scores
results_df['IF_prediction'] = preds
results_df['True_Label'] = y_true.values

results_df.to_csv('dummy/IF_benign_only_results.csv', index=False)
print("\n✅ Results saved to dummy/IF_benign_only_results.csv")

# === Save the trained Isolation Forest model ===
import joblib
joblib.dump(iso, 'dummy/if_model.pkl')
print("✅ IF model saved to dummy/if_model.pkl")
