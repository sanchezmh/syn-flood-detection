# random_forest_syn.py

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix

# === Load & clean ===
df_raw = pd.read_csv('dummy/Syn.csv', low_memory=False)
df_raw.columns = df_raw.columns.str.strip()

# === Label to binary (1 = SYN, 0 = BENIGN) ===
df_raw['Label_binary'] = df_raw['Label'].apply(lambda v: 1 if 'SYN' in str(v).upper() else 0)

# === Drop non-numeric and ID-like cols ===
drop_cols = ['Unnamed: 0', 'Flow ID', 'Source IP', 'Destination IP',
             'Timestamp', 'Source Port', 'Destination Port', 'Protocol', 'Label']
df = df_raw.drop(columns=[col for col in drop_cols if col in df_raw.columns])
df = df.drop(columns=df.select_dtypes(exclude=[np.number]).columns)
df = df.replace([np.inf, -np.inf], np.nan).dropna()

# === Features and label ===
X = df.drop(columns=['Label_binary'])
y = df['Label_binary']

# === Normalize features ===
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# === Train/test split ===
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, stratify=y, random_state=42)

# === Train RF ===
rf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
rf.fit(X_train, y_train)

# === Predict & Evaluate ===
y_pred = rf.predict(X_test)
y_proba = rf.predict_proba(X_test)[:, 1]  # Prob of being SYN

print("\n=== RF Classification Report ===")
print(classification_report(y_test, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# === Save full outputs for ANFIS input ===
X_full_scaled = scaler.transform(X)
rf_preds = rf.predict(X_full_scaled)
rf_probs = rf.predict_proba(X_full_scaled)[:, 1]

results_df = pd.DataFrame(X, columns=X.columns)
results_df['RF_prediction'] = rf_preds
results_df['RF_probability'] = rf_probs
results_df['True_Label'] = y.values

results_df.to_csv('dummy/RF_results.csv', index=False)
print("\n✅ RF results saved to dummy/RF_results.csv")

# === Save the trained Random Forest model ===
import joblib
joblib.dump(rf, 'dummy/rf_model.pkl')
print("✅ RF model saved to dummy/rf_model.pkl")
