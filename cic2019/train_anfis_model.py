
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
import matplotlib.pyplot as plt

# === Step 1: Load ANFIS input data ===
df = pd.read_csv('datasets_and_models/anfis_input.csv')
X = df[['RF_probability', 'IF_score']].values
y = df['True_Label'].values

X = torch.tensor(X, dtype=torch.float32)
y = torch.tensor(y, dtype=torch.float32)  # BCE loss expects float

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# === Step 2: Define the ANFIS model ===
class SimpleANFIS(nn.Module):
    def __init__(self, input_dim=2, num_rules=4):
        super().__init__()
        self.num_rules = num_rules
        self.centers = nn.Parameter(torch.randn(num_rules, input_dim))
        self.sigmas = nn.Parameter(torch.ones(num_rules, input_dim))
        self.weights = nn.Parameter(torch.randn(num_rules, input_dim))
        self.biases = nn.Parameter(torch.randn(num_rules))

    def forward(self, x):
        diff = x.unsqueeze(1) - self.centers
        gauss = torch.exp(- (diff ** 2) / (2 * self.sigmas ** 2))
        membership = gauss.prod(dim=-1)
        normalized = membership / (membership.sum(dim=1, keepdim=True) + 1e-8)
        rule_outputs = (x.unsqueeze(1) * self.weights).sum(dim=-1) + self.biases
        return (normalized * rule_outputs).sum(dim=1)

# === Step 3: Train the model ===
model = SimpleANFIS(input_dim=2, num_rules=4)
optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
loss_fn = nn.BCEWithLogitsLoss()

train_loader = DataLoader(TensorDataset(X_train, y_train), batch_size=512, shuffle=True)
losses = []

for epoch in range(20):
    model.train()
    total_loss = 0
    for xb, yb in train_loader:
        preds = model(xb)
        loss = loss_fn(preds, yb)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    losses.append(total_loss)
    print(f"Epoch {epoch+1}, Loss: {total_loss:.4f}")

# === Step 4: Save trained model ===
torch.save(model.state_dict(), 'dummy/anfis_model.pt')
print("✅ Trained ANFIS model saved to dummy/anfis_model.pt")

# === Step 5: Evaluate model ===
model.eval()
with torch.no_grad():
    preds_logits = model(X_test)
    preds_probs = torch.sigmoid(preds_logits)
    preds_binary = (preds_probs > 0.5).int()
    y_test_int = y_test.int()

# === Step 6: Compute metrics ===
accuracy = accuracy_score(y_test_int, preds_binary)
precision = precision_score(y_test_int, preds_binary)
recall = recall_score(y_test_int, preds_binary)
f1 = f1_score(y_test_int, preds_binary)
conf_mat = confusion_matrix(y_test_int, preds_binary)

print("\n=== ANFIS Evaluation Metrics ===")
print(f"Accuracy:  {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1 Score:  {f1:.4f}")
print("Confusion Matrix:")
print(conf_mat)
print("\nClassification Report:")
print(classification_report(y_test_int, preds_binary))

# === Step 7: Save metrics and predictions ===
metrics_df = pd.DataFrame([{
    'Accuracy': accuracy,
    'Precision': precision,
    'Recall': recall,
    'F1_Score': f1,
    'TN': conf_mat[0][0],
    'FP': conf_mat[0][1],
    'FN': conf_mat[1][0],
    'TP': conf_mat[1][1]
}])
metrics_df.to_csv('dummy/anfis_metrics.csv', index=False)
print("✅ Metrics saved to dummy/anfis_metrics.csv")

df_eval = pd.DataFrame({
    'RF_probability': X_test[:, 0].numpy(),
    'IF_score': X_test[:, 1].numpy(),
    'True_Label': y_test_int.numpy(),
    'ANFIS_Prediction': preds_binary.numpy(),
    'ANFIS_Probability': preds_probs.numpy(),
    'ANFIS_Logits': preds_logits.numpy()
})
df_eval.to_csv('datasets_and_models/anfis_evall_results.csv', index=False)
print("✅ Evaluation results saved to datasets_and_models/anfis_evall_results.csv")

# === Step 8: Plot training loss ===
plt.plot(losses)
plt.title("ANFIS Training Loss")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.grid(True)
plt.show()
