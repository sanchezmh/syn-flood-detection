import subprocess
import os
import sys
import pandas as pd
import joblib
import torch
import numpy as np
import time
from sklearn.preprocessing import MinMaxScaler

# -----------------------------
# CONFIGURATION
# -----------------------------
DUMMY_FOLDER = "dummy"
PCAP_FILE = os.path.join(DUMMY_FOLDER, "sample_syn.pcap")
RF_MODEL_PATH = os.path.join(DUMMY_FOLDER, "rf_model.pk1")
IF_MODEL_PATH = os.path.join(DUMMY_FOLDER, "if_model.pk1")
ANFIS_MODEL_PATH = "anfis_model.pt"
ZEOK_SCRIPT = "tools/zeek_scripts/syn_logger.zeek"
CONN_LOG_PATH = os.path.join(DUMMY_FOLDER, "conn.log")
CONN_CSV_OUTPUT = os.path.join(DUMMY_FOLDER, "zeek_runtime_input.csv")

# -----------------------------
# STEP 0: Simulate SYN packets
# -----------------------------
def simulate_syn_packets():
    print("[+] Running SYN packet simulation using send_syn.py (sudo)...")
    subprocess.run(["sudo", "python3", "send_syn.py"])

# -----------------------------
# STEP 0.5: Capture packets with tcpdump
# -----------------------------
def capture_traffic():
    print("[+] Starting tcpdump on loopback interface...")
    capture_proc = subprocess.Popen(
        ["sudo", "tcpdump", "-i", "lo", "-w", PCAP_FILE, "tcp"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(7)  # capture duration increased
    capture_proc.terminate()
    time.sleep(1)  # short buffer to flush file
    if os.path.exists(PCAP_FILE) and os.path.getsize(PCAP_FILE) > 0:
        print(f"[+] Packet capture complete. Saved to {PCAP_FILE}")
    else:
        print("[!] Failed to capture packets or empty .pcap file.")
        sys.exit(1)

# -----------------------------
# STEP 1: Run Zeek on PCAP
# -----------------------------
def run_zeek(pcap_path):
    print("[+] Running Zeek...")
    subprocess.run(["zeek", "-r", pcap_path])
    if os.path.exists("conn.log"):
        os.rename("conn.log", CONN_LOG_PATH)
        print(f"[+] conn.log moved to {CONN_LOG_PATH}")
    else:
        print("[!] conn.log not found!")
        sys.exit(1)

# -----------------------------
# STEP 2: Parse conn.log to CSV
# -----------------------------
def parse_conn_log():
    if not os.path.exists(CONN_LOG_PATH):
        print("[!] conn.log missing. Cannot continue.")
        sys.exit(1)

    records = []
    with open(CONN_LOG_PATH, 'r') as file:
        for line in file:
            if line.startswith('#'):
                continue
            parts = line.strip().split('\t')
            if len(parts) < 21:
                continue
            try:
                record = {
                    "ts": float(parts[0]),
                    "id.orig_p": int(parts[3]),
                    "id.resp_p": int(parts[5]),
                    "duration": float(parts[8]) if parts[8] != '-' else 0.0,
                    "orig_bytes": int(parts[9]) if parts[9] != '-' else 0,
                    "resp_bytes": int(parts[10]) if parts[10] != '-' else 0,
                    "missed_bytes": int(parts[14]) if parts[14] != '-' else 0,
                    "orig_pkts": int(parts[16]) if parts[16] != '-' else 0,
                    "orig_ip_bytes": int(parts[17]) if parts[17] != '-' else 0,
                    "resp_pkts": int(parts[18]) if parts[18] != '-' else 0,
                    "resp_ip_bytes": int(parts[19]) if parts[19] != '-' else 0
                }
                records.append(record)
            except Exception:
                continue
    df = pd.DataFrame(records)
    df_clean = df.drop(columns='ts', errors='ignore')
    df_clean = df_clean.dropna()
    df_clean.to_csv(CONN_CSV_OUTPUT, index=False)
    print(f"[+] Zeek features saved to {CONN_CSV_OUTPUT}")
    return CONN_CSV_OUTPUT

# -----------------------------
# STEP 3: RF and IF inference
# -----------------------------
def run_rf_if_models(csv_path):
    df = pd.read_csv(csv_path)
    X = df.copy()

    rf_model = joblib.load(RF_MODEL_PATH)
    if_model = joblib.load(IF_MODEL_PATH)

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    rf_preds = rf_model.predict(X_scaled)
    if_scores = if_model.decision_function(X_scaled)

    rf_df = pd.DataFrame(rf_preds, columns=["rf_pred"])
    if_df = pd.DataFrame(if_scores, columns=["if_score"])

    rf_df.to_csv(os.path.join(DUMMY_FOLDER, "RF_results.csv"), index=False)
    if_df.to_csv(os.path.join(DUMMY_FOLDER, "IF_benign_only_results.csv"), index=False)
    print("[+] RF and IF results saved.")
    return rf_df, if_df

# -----------------------------
# STEP 4: Merge for ANFIS
# -----------------------------
def merge_for_anfis(rf_df, if_df):
    merged = pd.concat([rf_df, if_df], axis=1)
    merged.to_csv(os.path.join(DUMMY_FOLDER, "anfis_input.csv"), index=False)
    print("[+] Merged ANFIS input saved.")
    return merged

# -----------------------------
# STEP 5: Load ANFIS and infer
# -----------------------------
def run_anfis_inference(anfis_input):
    class SimpleANFIS(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.net = torch.nn.Sequential(
                torch.nn.Linear(2, 16),
                torch.nn.ReLU(),
                torch.nn.Linear(16, 1),
                torch.nn.Sigmoid()
            )
        def forward(self, x):
            return self.net(x)

    model = SimpleANFIS()
    model.load_state_dict(torch.load(ANFIS_MODEL_PATH))
    model.eval()

    X = torch.tensor(anfis_input.values, dtype=torch.float32)
    with torch.no_grad():
        outputs = model(X).numpy()

    print("\n=== ANFIS Predictions ===")
    print(outputs)

# -----------------------------
# MAIN PIPELINE
# -----------------------------
if __name__ == "__main__":
    args = sys.argv[1:]

    if "--simulate" in args:
        simulate_syn_packets()
        capture_traffic()
        run_zeek(PCAP_FILE)
        csv_path = parse_conn_log()
    elif "--pcap" in args:
        try:
            custom_pcap = args[args.index("--pcap") + 1]
        except IndexError:
            print("[!] Please provide a pcap path after --pcap")
            sys.exit(1)
        run_zeek(custom_pcap)
        csv_path = parse_conn_log()
    else:
        print("Usage:")
        print("  python run_pipeline.py --simulate")
        print("  python run_pipeline.py --pcap dummy/sample_syn.pcap")
        sys.exit(1)

    rf_df, if_df = run_rf_if_models(csv_path)
    anfis_input = merge_for_anfis(rf_df, if_df)
    run_anfis_inference(anfis_input)
