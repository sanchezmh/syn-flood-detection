'''
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib
import torch
import torch.nn as nn
import torch.optim as optim

# ========== LOAD DATA ==========
print("📥 Loading data...")
df = pd.read_csv("dummy/zeek_combined_training.csv")

# ========== CLEAN THE DATA ==========
print("🧹 Cleaning data...")
df.replace('-', 0, inplace=True)
for col in df.columns:
    if col != 'Label':
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

# ========== SELECT USEFUL FEATURES ==========
print("🧠 Selecting important features...")
keep_cols = ['id.orig_p', 'id.resp_p', 'proto', 'service', 'duration',
             'orig_bytes', 'resp_bytes', 'missed_bytes', 'orig_pkts',
             'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'conn_state', 'Label']
df = df[keep_cols]

# ========== ENCODE CATEGORICAL COLUMNS ==========
print("🔢 Encoding categorical features...")
for col in ['proto', 'service', 'conn_state']:
    df[col] = LabelEncoder().fit_transform(df[col])

# ========== SPLIT ==========
X = df.drop(columns=['Label'])
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# ========== TRAIN RANDOM FOREST ==========
print("🌲 Training Random Forest...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)
y_pred_rf = rf_model.predict(X_test)
print("\n📊 RF Classification Report:\n", classification_report(y_test, y_pred_rf))
print("🧾 RF Confusion Matrix:\n", confusion_matrix(y_test, y_pred_rf))

# ========== TRAIN ISOLATION FOREST ==========
print("🔍 Training Isolation Forest on benign only...")
X_benign = X[df['Label'] == 0]
if_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
if_model.fit(X_benign)

# ========== PREPARE ANFIS INPUTS ==========
print("⚙️ Preparing ANFIS inputs...")
rf_scores = rf_model.predict_proba(X)[:, 1]
if_scores = -if_model.decision_function(X)  # Higher = more anomalous
anfis_input = np.vstack([rf_scores, if_scores]).T
anfis_labels = y.values.reshape(-1, 1)

# ========== DEFINE ANFIS MODEL ==========
class ANFISModel(nn.Module):
    def __init__(self):
        super(ANFISModel, self).__init__()
        self.net = nn.Sequential(
            nn.Linear(2, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )
    def forward(self, x):
        return self.net(x)

anfis = ANFISModel()
criterion = nn.BCELoss()
optimizer = optim.Adam(anfis.parameters(), lr=0.001)

X_tensor = torch.tensor(anfis_input, dtype=torch.float32)
y_tensor = torch.tensor(anfis_labels, dtype=torch.float32)

print("🧠 Training ANFIS...")
for epoch in range(50):
    optimizer.zero_grad()
    output = anfis(X_tensor)
    loss = criterion(output, y_tensor)
    loss.backward()
    optimizer.step()
    if epoch % 10 == 0:
        print(f"Epoch {epoch}: Loss = {loss.item():.4f}")

# ========== SAVE MODELS ==========
print("💾 Saving models...")
model_dir = "dummy/models"
os.makedirs(model_dir, exist_ok=True)
joblib.dump(rf_model, f"{model_dir}/rf_model.pkl")
joblib.dump(if_model, f"{model_dir}/if_model.pkl")
torch.save(anfis.state_dict(), f"{model_dir}/anfis_model.pt")

print("\n✅ All models trained and saved successfully!")







import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib
import torch
import torch.nn as nn
import torch.optim as optim

# ========== LOAD DATA ==========
print("📥 Loading data...")
df = pd.read_csv("dummy/zeek_combined_training.csv")

# ========== CLEAN THE DATA ==========
print("🧹 Cleaning data...")
df.replace('-', 0, inplace=True)
for col in df.columns:
    if col != 'Label':
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

# ========== SELECT USEFUL FEATURES ==========
print("🧠 Selecting important features...")
keep_cols = ['id.orig_p', 'id.resp_p', 'proto', 'service', 'duration',
             'orig_bytes', 'resp_bytes', 'missed_bytes', 'orig_pkts',
             'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'conn_state', 'Label']
df = df[keep_cols]

# ========== ENCODE CATEGORICAL COLUMNS ==========
print("🔢 Encoding categorical features...")
for col in ['proto', 'service', 'conn_state']:
    df[col] = LabelEncoder().fit_transform(df[col])

# ========== SPLIT ==========
X = df.drop(columns=['Label'])
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# ========== TRAIN RANDOM FOREST ==========
print("🌲 Training Random Forest...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)
y_pred_rf = rf_model.predict(X_test)
print("\n📊 RF Classification Report:\n", classification_report(y_test, y_pred_rf))
print("🧾 RF Confusion Matrix:\n", confusion_matrix(y_test, y_pred_rf))

# ========== TRAIN ISOLATION FOREST ==========
print("🔍 Training Isolation Forest on benign only...")
X_benign = X[df['Label'] == 0]
if_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
if_model.fit(X_benign)

# ========== PREPARE ANFIS INPUTS ==========
print("⚙️ Preparing ANFIS inputs...")
rf_scores = rf_model.predict_proba(X)[:, 1]
if_scores = -if_model.decision_function(X)  # Higher = more anomalous
anfis_input = np.vstack([rf_scores, if_scores]).T
anfis_labels = y.values.reshape(-1, 1)

# ========== DEFINE TRUE FUZZY ANFIS MODEL ==========
class GaussianMembership(nn.Module):
    def __init__(self):
        super(GaussianMembership, self).__init__()
        self.c = nn.Parameter(torch.randn(2))  # Center
        self.sigma = nn.Parameter(torch.randn(2).abs() + 0.1)  # Spread (positive)

    def forward(self, x):
        return torch.exp(-0.5 * ((x - self.c) ** 2) / (self.sigma ** 2))

class TrueANFIS(nn.Module):
    def __init__(self):
        super(TrueANFIS, self).__init__()
        self.mf1 = GaussianMembership()  # For RF score
        self.mf2 = GaussianMembership()  # For IF score
        self.linear = nn.Linear(2, 1)     # 2 inputs x 2 membership functions = 4 combinations

    def forward(self, x):
        x1 = x[:, 0].unsqueeze(1)  # RF
        x2 = x[:, 1].unsqueeze(1)  # IF

        mf1_out = self.mf1(x1)  # Shape: (batch_size, 2)
        mf2_out = self.mf2(x2)  # Shape: (batch_size, 2)

        rule_strengths = mf1_out * mf2_out  # Fuzzy AND
        norm_rule_strengths = rule_strengths / (rule_strengths.sum(dim=1, keepdim=True) + 1e-6)

        output = self.linear(norm_rule_strengths)
        output = torch.sigmoid(output)
        return output

anfis = TrueANFIS()
criterion = nn.BCELoss()
optimizer = optim.Adam(anfis.parameters(), lr=0.001)

X_tensor = torch.tensor(anfis_input, dtype=torch.float32)
y_tensor = torch.tensor(anfis_labels, dtype=torch.float32)

print("🧠 Training TRUE Fuzzy ANFIS...")
for epoch in range(100):  # More epochs for fuzzy convergence
    optimizer.zero_grad()
    output = anfis(X_tensor)
    loss = criterion(output, y_tensor)
    loss.backward()
    optimizer.step()
    if epoch % 10 == 0:
        print(f"Epoch {epoch}: Loss = {loss.item():.4f}")

# ========== SAVE MODELS ==========
print("💾 Saving models...")
model_dir = "dummy/models"
os.makedirs(model_dir, exist_ok=True)
joblib.dump(rf_model, f"{model_dir}/rf_model.pkl")
joblib.dump(if_model, f"{model_dir}/if_model.pkl")
torch.save(anfis.state_dict(), f"{model_dir}/anfis_model.pt")

print("\n✅ All models trained and saved successfully!")
'''

import os
import pandas as pd
import numpy as np
import joblib
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

# ========== CONFIG ==========
data_path = "dummy/zeek_combined_training.csv"
model_dir = "dummy/models"
os.makedirs(model_dir, exist_ok=True)

# ========== LOAD DATA ==========
print("📥 Loading and preparing data...")
df = pd.read_csv(data_path)

# Clean data
df.replace('-', 0, inplace=True)
for col in df.columns:
    if col != 'Label':
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

keep_cols = ['id.orig_p', 'id.resp_p', 'proto', 'service', 'duration',
             'orig_bytes', 'resp_bytes', 'missed_bytes', 'orig_pkts',
             'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'conn_state', 'Label']
df = df[keep_cols]

for col in ['proto', 'service', 'conn_state']:
    df[col] = LabelEncoder().fit_transform(df[col])

X = df.drop(columns=['Label'])
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# ========== TRAIN RANDOM FOREST ==========
print("🌲 Training Random Forest...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

y_pred_rf = rf_model.predict(X_test)
print("\n📊 RF Classification Report:\n", classification_report(y_test, y_pred_rf))
print("🧾 RF Confusion Matrix:\n", confusion_matrix(y_test, y_pred_rf))

# ========== TRAIN ISOLATION FOREST ==========
print("🔍 Training Isolation Forest on benign only...")
X_benign = X_train[y_train == 0]  # Train IF on benign traffic only
if_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
if_model.fit(X_benign)

# ========== PREPARE ANFIS INPUTS ==========
print("⚙️ Preparing ANFIS inputs (RF prob + IF score)...")

# On training set
rf_train_probs = rf_model.predict_proba(X_train)[:, 1]
if_train_scores = -if_model.decision_function(X_train)  # Higher = more anomalous

anfis_train_input = np.vstack([rf_train_probs, if_train_scores]).T
anfis_train_labels = y_train.values.reshape(-1, 1)

# On testing set (optional, for validation later)
rf_test_probs = rf_model.predict_proba(X_test)[:, 1]
if_test_scores = -if_model.decision_function(X_test)
anfis_test_input = np.vstack([rf_test_probs, if_test_scores]).T
anfis_test_labels = y_test.values.reshape(-1, 1)

# ========== DEFINE TRUE FUZZY ANFIS ==========
class GaussianMembership(nn.Module):
    def __init__(self):
        super(GaussianMembership, self).__init__()
        self.c = nn.Parameter(torch.randn(2))
        self.sigma = nn.Parameter(torch.randn(2).abs() + 0.1)

    def forward(self, x):
        return torch.exp(-0.5 * ((x - self.c) ** 2) / (self.sigma ** 2))

class TrueANFIS(nn.Module):
    def __init__(self):
        super(TrueANFIS, self).__init__()
        self.mf1 = GaussianMembership()
        self.mf2 = GaussianMembership()
        self.linear = nn.Linear(2, 1)

    def forward(self, x):
        x1 = x[:, 0].unsqueeze(1)
        x2 = x[:, 1].unsqueeze(1)

        mf1_out = self.mf1(x1)
        mf2_out = self.mf2(x2)

        rule_strengths = mf1_out * mf2_out
        norm_rule_strengths = rule_strengths / (rule_strengths.sum(dim=1, keepdim=True) + 1e-6)

        output = self.linear(norm_rule_strengths)
        output = torch.sigmoid(output)
        return output

anfis = TrueANFIS()
criterion = nn.BCELoss()
optimizer = torch.optim.Adam(anfis.parameters(), lr=0.001)

X_tensor = torch.tensor(anfis_train_input, dtype=torch.float32)
y_tensor = torch.tensor(anfis_train_labels, dtype=torch.float32)

# ========== TRAIN ANFIS ==========
print("🧠 Training TRUE Fuzzy ANFIS...")

for epoch in range(100):
    optimizer.zero_grad()
    output = anfis(X_tensor)
    loss = criterion(output, y_tensor)
    loss.backward()
    optimizer.step()
    if epoch % 10 == 0:
        print(f"Epoch {epoch}: Loss = {loss.item():.4f}")

# ========== SAVE MODELS ==========
print("💾 Saving models...")
joblib.dump(rf_model, os.path.join(model_dir, "rf_model.pkl"))
joblib.dump(if_model, os.path.join(model_dir, "if_model.pkl"))
torch.save(anfis.state_dict(), os.path.join(model_dir, "anfis_model.pt"))

print("\n✅ All models trained and saved successfully!")

