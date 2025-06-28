import os
import pandas as pd
import numpy as np
import joblib
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import (classification_report, 
                             confusion_matrix, 
                             ConfusionMatrixDisplay, 
                             roc_auc_score, 
                             roc_curve)
import matplotlib.pyplot as plt

# CONFIG
DATA_PATH = "../datasets_and_models/Cleaned_and_Processed_Dataset.csv"
MODEL_DIRECTORY = "../datasets_and_models/trainer"
RESULTS_DIR = "../Results"
os.makedirs(MODEL_DIRECTORY, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

#  Loading Cleaned and Encoded Data
df = pd.read_csv(DATA_PATH)
X = df.drop(columns=['Label'])
y = df['Label']
# === Split Data for Random Forest Evaluation
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train Random Forest
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)
y_pred_rf = rf.predict(X_test)
rf_probs = rf.predict_proba(X_test)[:, 1]
joblib.dump(rf, os.path.join(MODEL_DIRECTORY, "rf_model.joblib"))

#Evaluate Random Forest
print("\n=== Random Forest Classification Report ===")
print(classification_report(y_test, y_pred_rf))

cm_rf = confusion_matrix(y_test, y_pred_rf)
print("Random Forest Confusion Matrix:")
print(cm_rf)

disp_rf = ConfusionMatrixDisplay(confusion_matrix=cm_rf, display_labels=["Benign (0)", "Attack (1)"])
disp_rf.plot(cmap=plt.cm.Greens)
plt.title("Random Forest Confusion Matrix")
plt.savefig(os.path.join(RESULTS_DIR, "rf_confusion_matrix.png"), dpi=300, bbox_inches='tight')
print("Random Forest confusion matrix saved as 'rf_confusion_matrix.png'")

#Train Isolation Forest on Benign Samples
X_benign = X[y == 0]
iso = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
iso.fit(X_benign)
joblib.dump(iso, os.path.join(MODEL_DIRECTORY, "if_model.joblib"))

# Preparing Full Dataset for ANFI
rf_probs_all = rf.predict_proba(X)[:, 1]
iso_scores_all = -iso.decision_function(X)
anfis_input_all = np.stack([rf_probs_all, iso_scores_all], axis=1)

# Scale ANFIS Input 
scaler = MinMaxScaler()
anfis_input_scaled_all = scaler.fit_transform(anfis_input_all)
joblib.dump(scaler, os.path.join(MODEL_DIRECTORY, "anfis_input_scaler.joblib"))

# Evaluate Isolation Forest (unsupervised)
threshold = np.percentile(iso_scores_all, 90)  # Adjustable threshold
iso_preds = (iso_scores_all > threshold).astype(int)

print("\n=== Isolation Forest Evaluation ===")
print(f"Threshold (90th percentile): {threshold:.4f}")
print(classification_report(y, iso_preds, target_names=["Benign (0)", "Attack (1)"]))

cm_if = confusion_matrix(y, iso_preds)
print("Isolation Forest Confusion Matrix:")
print(cm_if)

disp_if = ConfusionMatrixDisplay(confusion_matrix=cm_if, display_labels=["Benign (0)", "Attack (1)"])
disp_if.plot(cmap=plt.cm.Oranges)
plt.title("Isolation Forest Confusion Matrix")
plt.savefig(os.path.join(RESULTS_DIR, "if_confusion_matrix.png"), dpi=300, bbox_inches='tight')
print("Isolation Forest confusion matrix saved as 'if_confusion_matrix.png'")

roc_auc_if = roc_auc_score(y, iso_scores_all)
print(f"Isolation Forest ROC AUC Score: {roc_auc_if:.4f}")

# Convert to PyTorch Tensors for ANFIS
X_tensor = torch.tensor(anfis_input_scaled_all, dtype=torch.float32)
y_tensor = torch.tensor(y.values.reshape(-1, 1), dtype=torch.float32)

# Define ANFIS Components
class GaussianMF(nn.Module):
    def __init__(self, num_inputs, num_mfs):
        super().__init__()
        self.centers = nn.Parameter(torch.rand(num_inputs, num_mfs))
        self.sigmas = nn.Parameter(torch.rand(num_inputs, num_mfs))

    def forward(self, x):
        x = x.unsqueeze(2)
        return torch.exp(-0.5 * ((x - self.centers) / self.sigmas) ** 2)

class ANFIS(nn.Module):
    def __init__(self, num_inputs=2, num_mfs=3):
        super().__init__()
        self.num_inputs = num_inputs
        self.num_mfs = num_mfs
        self.num_rules = num_mfs ** num_inputs
        self.mf_layer = GaussianMF(num_inputs, num_mfs)
        self.rule_weights = nn.Parameter(torch.rand(self.num_rules, num_inputs + 1))

    def forward(self, x):
        batch_size = x.size(0)
        mf_out = self.mf_layer(x)
        mf_out = mf_out.permute(0, 2, 1)
        rules = torch.cartesian_prod(*[torch.arange(self.num_mfs) for _ in range(self.num_inputs)])
        rule_strengths = torch.ones((batch_size, self.num_rules), device=x.device)
        for i in range(self.num_inputs):
            rule_strengths *= mf_out[:, rules[:, i], i]
        norm_strengths = rule_strengths / rule_strengths.sum(dim=1, keepdim=True)
        x_with_bias = torch.cat([x, torch.ones(batch_size, 1)], dim=1)
        rule_outputs = torch.matmul(x_with_bias, self.rule_weights.t())
        output = (norm_strengths * rule_outputs).sum(dim=1, keepdim=True)
        return torch.sigmoid(output)

# Train ANFIS
anfis_model = ANFIS(num_inputs=2, num_mfs=3)
criterion = nn.BCELoss()
optimizer = torch.optim.Adam(anfis_model.parameters(), lr=0.01)

print("\n=== Training ANFIS Model on Full Dataset ===")
for epoch in range(100):
    optimizer.zero_grad()
    outputs = anfis_model(X_tensor)
    loss = criterion(outputs, y_tensor)
    loss.backward()
    optimizer.step()
    if epoch % 10 == 0:
        print(f"Epoch {epoch}, Loss: {loss.item():.4f}")

# === Save Trained ANFIS Model ===
torch.save(anfis_model.state_dict(), os.path.join(MODEL_DIRECTORY, "anfis_model.pt"))

# === Evaluate ANFIS Model ===
with torch.no_grad():
    anfis_outputs = anfis_model(X_tensor).numpy().flatten()
    preds = (anfis_outputs > 0.5).astype(int)

    print("\n=== ANFIS Classification Report ===")
    print(classification_report(y.values, preds))

    cm_anfis = confusion_matrix(y.values, preds)
    print("ANFIS Confusion Matrix:")
    print(cm_anfis)

    disp_anfis = ConfusionMatrixDisplay(confusion_matrix=cm_anfis, display_labels=["Benign (0)", "Attack (1)"])
    disp_anfis.plot(cmap=plt.cm.Blues)
    plt.title("ANFIS Confusion Matrix")
    plt.savefig(os.path.join(RESULTS_DIR, "anfis_confusion_matrix.png"), dpi=300, bbox_inches='tight')
    print("ANFIS confusion matrix saved as 'anfis_confusion_matrix.png'")

# === Combined ROC Curve ===
print("\n=== Generating Combined ROC Curve ===")
fpr_rf, tpr_rf, _ = roc_curve(y_test, rf_probs)
fpr_if, tpr_if, _ = roc_curve(y, iso_scores_all)
fpr_anfis, tpr_anfis, _ = roc_curve(y, anfis_outputs)

plt.figure(figsize=(8, 6))
plt.plot(fpr_rf, tpr_rf, label=f"Random Forest (AUC: {roc_auc_score(y_test, rf_probs):.4f})")
plt.plot(fpr_if, tpr_if, label=f"Isolation Forest (AUC: {roc_auc_if:.4f})")
plt.plot(fpr_anfis, tpr_anfis, label=f"ANFIS (AUC: {roc_auc_score(y, anfis_outputs):.4f})")

plt.plot([0, 1], [0, 1], 'k--', label="Chance")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve Comparison")
plt.legend(loc="lower right")
plt.grid(True)
plt.savefig(os.path.join(RESULTS_DIR, "combined_roc_curve.png"), dpi=300, bbox_inches='tight')
print("Combined ROC curve saved as 'combined_roc_curve.png'")

# === Display all plots if running interactively ===
plt.show()
