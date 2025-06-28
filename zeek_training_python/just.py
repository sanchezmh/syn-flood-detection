import matplotlib.pyplot as plt

# F1 scores from your results
models = ['Random Forest', 'Isolation Forest', 'ANFIS']
f1_scores = [1.00, 0.05, 1.00]

plt.figure(figsize=(8, 6))
bars = plt.bar(models, f1_scores, color=['skyblue', 'orange', 'green'])
plt.ylim(0, 1.1)
plt.ylabel('F1-Score')
plt.title('F1-Score Comparison on Synthetic Dataset')

# Add text labels on bars
for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, yval + 0.02, round(yval, 2), ha='center', fontsize=12)

plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.show()

