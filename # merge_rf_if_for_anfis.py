# merge_rf_if_for_anfis.py

import pandas as pd

# === Load RF and IF output files ===
df_rf = pd.read_csv('dummy/RF_results.csv')
df_if = pd.read_csv('dummy/IF_benign_only_results.csv')

# === Ensure aligned indices ===
df_rf = df_rf.reset_index(drop=True)
df_if = df_if.reset_index(drop=True)

# === Sanity check (optional) ===
if len(df_rf) != len(df_if):
    raise ValueError("Mismatch in number of rows between RF and IF results!")

# === Merge features for ANFIS ===
anfis_input = pd.DataFrame({
    'RF_prediction': df_rf['RF_prediction'],
    'RF_probability': df_rf['RF_probability'],
    'IF_prediction': df_if['IF_prediction'],
    'IF_score': df_if['IF_score'],
    'True_Label': df_rf['True_Label']  # You can also use df_if['True_Label'] — same
})

# === Save to file ===
anfis_input.to_csv('dummy/anfis_input.csv', index=False)
print("✅ ANFIS input saved to dummy/anfis_input.csv")
