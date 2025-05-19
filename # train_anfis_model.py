# train_anfis_model.py

import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt

# === Step 1: Load ANFIS input data ===
df = pd.read_csv('dummy/anfis_input.csv')

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

# === Step 5: Evaluate ===
model.eval()
with torch.no_grad():
    preds_logits = model(X_test)
    preds_binary = (torch.sigmoid(preds_logits) > 0.5).int()
    y_test_int = y_test.int()

print("\n=== ANFIS Classification Report ===")
print(classification_report(y_test_int, preds_binary))
print("Confusion Matrix:")
print(confusion_matrix(y_test_int, preds_binary))

# === Step 6: Save evaluation predictions ===
df_eval = pd.DataFrame({
    'RF_probability': X_test[:, 0].numpy(),
    'IF_score': X_test[:, 1].numpy(),
    'True_Label': y_test_int.numpy(),
    'ANFIS_Prediction': preds_binary.numpy(),
    'ANFIS_Logits': preds_logits.numpy()
})
df_eval.to_csv('dummy/anfis_eval_results.csv', index=False)
print("✅ Evaluation results saved to dummy/anfis_eval_results.csv")

# === Step 7: Plot training loss ===
plt.plot(losses)
plt.title("ANFIS Training Loss")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.grid(True)
plt.show()
