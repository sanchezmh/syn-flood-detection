'''
import os
import time
import pandas as pd
import joblib
import torch
import torch.nn as nn
import numpy as np
from scapy.all import send, IP, TCP
import subprocess
from sklearn.preprocessing import LabelEncoder
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ========== CONFIG ==========
zeek_log_path = "conn.log"  # Path to Zeek live conn.log
model_dir = "dummy/models"
threshold = 0.5  # ANFIS detection threshold
blocked_ips = set()  # Remember already blocked IPs
sender_email = "sanchezmashokoashe@gmail.com"  # <-- CHANGE
receiver_email = "sanchezmashokoashe@gmail.com"  # <-- CHANGE
app_password = ""  # <-- CHANGE
# ============================

# ========== LOAD MODELS ==========
print("📦 Loading models...")
rf_model = joblib.load(os.path.join(model_dir, "rf_model.pkl"))
if_model = joblib.load(os.path.join(model_dir, "if_model.pkl"))

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
anfis.load_state_dict(torch.load(os.path.join(model_dir, "anfis_model.pt")))
anfis.eval()
print("✅ Models loaded!")

# ========== EMAIL ALERT FUNCTION ==========
def send_email_alert(source_ip, anfis_score):
    subject = "🚨 SYN Flood Attack Detected!"
    body = f"""
    SYN Attack Detected!

    Source IP: {source_ip}
    ANFIS Risk Score: {anfis_score:.4f}

    Please investigate immediately.
    """

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print(f"📧 Email alert sent for IP {source_ip}!")
    except Exception as e:
        print(f"❌ Failed to send email alert: {e}")

# ========== PARSE ZEEK conn.log ==========
def parse_conn_log(path):
    with open(path) as f:
        lines = f.readlines()

    field_line = next((line for line in lines if line.startswith("#fields")), None)
    if not field_line:
        raise ValueError("No #fields line found in conn.log")

    headers = field_line.strip().split("\t")[1:]
    data_lines = [line.strip().split("\t") for line in lines if not line.startswith("#")]

    clean_data = [row for row in data_lines if len(row) == len(headers)]

    if not clean_data:
        print("⚠️ Warning: No valid Zeek rows matched expected columns.")
        return pd.DataFrame()

    df = pd.DataFrame(clean_data, columns=headers)
    return df

# ========== EXTRACT FEATURES ==========
def extract_features(row):
    try:
        def safe_num(val):
            return float(val) if val not in ('-', '', None) else 0.0

        features = [
            safe_num(row.get('id.orig_p')),
            safe_num(row.get('id.resp_p')),
            LabelEncoder().fit_transform([row.get('proto', '-')])[0],
            LabelEncoder().fit_transform([row.get('service', '-')])[0],
            safe_num(row.get('duration')),
            safe_num(row.get('orig_bytes')),
            safe_num(row.get('resp_bytes')),
            safe_num(row.get('missed_bytes')),
            safe_num(row.get('orig_pkts')),
            safe_num(row.get('orig_ip_bytes')),
            safe_num(row.get('resp_pkts')),
            safe_num(row.get('resp_ip_bytes')),
            LabelEncoder().fit_transform([row.get('conn_state', '-')])[0]
        ]
        return features
    except Exception as e:
        print(f"⚠️ Feature extraction failed: {e}")
        return None

# ========== BLOCK IP (DISABLED for WSL) ==========
def block_ip(ip):
    if ip in blocked_ips:
        print(f"ℹ️ IP {ip} already marked as malicious.")
        return
    print(f"🚨 SYN attack detected from {ip} (not blocking in WSL)")
    blocked_ips.add(ip)

# ========== MAIN MONITOR LOOP ==========
print("🕵️ Starting live Zeek monitor...")
seen_conn_ids = set()

while True:
    try:
        if not os.path.exists(zeek_log_path):
            print("⌛ Waiting for Zeek conn.log to appear...")
            time.sleep(5)
            continue

        df = parse_conn_log(zeek_log_path)
        if df.empty:
            time.sleep(5)
            continue

        for idx, row in df.iterrows():
            conn_id = row.get('uid')
            if conn_id in seen_conn_ids:
                continue
            seen_conn_ids.add(conn_id)

            features = extract_features(row)
            if features is None:
                continue

            X_input = pd.DataFrame([features], columns=rf_model.feature_names_in_)

            rf_score = rf_model.predict_proba(X_input)[:, 1][0]
            if_score = -if_model.decision_function(X_input)[0]

            anfis_input = torch.tensor([[rf_score, if_score]], dtype=torch.float32)
            anfis_output = anfis(anfis_input).item()

            src_ip = row.get("id.orig_h", "0.0.0.0")
            if anfis_output > threshold:
                print(f"⚡ SYN flood detected! Source IP: {src_ip} | ANFIS score: {anfis_output:.4f}")
                block_ip(src_ip)
                send_email_alert(src_ip, anfis_output)
            else:
                print(f"✅ Benign flow detected. ANFIS score: {anfis_output:.4f}")

        time.sleep(5)

    except KeyboardInterrupt:
        print("\n🛑 Stopping monitor.")
        break
    except Exception as e:
        print(f"❌ Error in monitor loop: {e}")
        time.sleep(5)
'''



import os
import sys
import time
import pandas as pd
import joblib
import torch
import torch.nn as nn
import numpy as np
from scapy.all import send, IP, TCP
import subprocess
from sklearn.preprocessing import LabelEncoder

# ========== CONFIG ========== 
zeek_log_path = "conn.log"  # Make sure conn.log is in the working directory or adjust path
model_dir = "dummy/models"
threshold = 0.5
blocked_ips = set()

# ========== DJANGO SETUP ==========
sys.path.append('/home/sanchez/Dummy_test/defense_system/')  # <-- Adjust to YOUR project path
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'defense_system.settings')
import django
django.setup()

from attacks.models import AttackLog

# ========== LOAD MODELS ==========
print("📦 Loading models...")
rf_model = joblib.load(os.path.join(model_dir, "rf_model.pkl"))
if_model = joblib.load(os.path.join(model_dir, "if_model.pkl"))

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
anfis.load_state_dict(torch.load(os.path.join(model_dir, "anfis_model.pt")))
anfis.eval()
print("✅ Models loaded!")

# ========== PARSE ZEEK conn.log ==========
def parse_conn_log(path):
    with open(path) as f:
        lines = f.readlines()

    field_line = next((line for line in lines if line.startswith("#fields")), None)
    if not field_line:
        raise ValueError("No #fields line found in conn.log")

    headers = field_line.strip().split("\t")[1:]
    data_lines = [line.strip().split("\t") for line in lines if not line.startswith("#")]

    clean_data = [row for row in data_lines if len(row) == len(headers)]

    if not clean_data:
        print("⚠️ Warning: No valid Zeek rows matched expected columns.")
        return pd.DataFrame()

    df = pd.DataFrame(clean_data, columns=headers)
    return df

# ========== GLOBAL LABEL ENCODERS ==========
proto_encoder = LabelEncoder()
service_encoder = LabelEncoder()
conn_state_encoder = LabelEncoder()

def fit_label_encoders():
    sample = ['tcp', 'udp', 'icmp', '-']
    proto_encoder.fit(sample)

    service_sample = ['-', 'http', 'dns', 'ssl', 'ftp']
    service_encoder.fit(service_sample)

    conn_state_sample = ['S0', 'SF', 'REJ', 'RSTO', '-']
    conn_state_encoder.fit(conn_state_sample)

fit_label_encoders()

# ========== EXTRACT FEATURES ==========
def extract_features(row):
    try:
        features = [
            float(row.get('id.orig_p', 0)),
            float(row.get('id.resp_p', 0)),
            proto_encoder.transform([row.get('proto', '-')])[0],
            service_encoder.transform([row.get('service', '-')])[0],
            float(row.get('duration', 0)),
            float(row.get('orig_bytes', 0)),
            float(row.get('resp_bytes', 0)),
            float(row.get('missed_bytes', 0)),
            float(row.get('orig_pkts', 0)),
            float(row.get('orig_ip_bytes', 0)),
            float(row.get('resp_pkts', 0)),
            float(row.get('resp_ip_bytes', 0)),
            conn_state_encoder.transform([row.get('conn_state', '-')])[0]
        ]
        return features
    except Exception as e:
        print(f"⚠️ Feature extraction failed: {e}")
        return None

# ========== BLOCK IP ==========
def block_ip(ip):
    if ip in blocked_ips:
        print(f"ℹ️ IP {ip} already marked as malicious.")
        return
    print(f"🚨 SYN attack detected from {ip} (not blocking in WSL)")
    blocked_ips.add(ip)

# ========== MAIN MONITOR LOOP ==========
print("🕵️ Starting live Zeek monitor...")
seen_conn_ids = set()

while True:
    try:
        if not os.path.exists(zeek_log_path):
            print("⌛ Waiting for Zeek conn.log to appear...")
            time.sleep(5)
            continue

        df = parse_conn_log(zeek_log_path)
        if df.empty:
            time.sleep(5)
            continue

        for idx, row in df.iterrows():
            conn_id = row.get('uid')
            if conn_id in seen_conn_ids:
                continue
            seen_conn_ids.add(conn_id)

            features = extract_features(row)
            if features is None:
                continue

            X_input = pd.DataFrame([features], columns=rf_model.feature_names_in_)

            rf_score = rf_model.predict_proba(X_input)[:, 1][0]
            if_score = -if_model.decision_function(X_input)[0]

            anfis_input = torch.tensor([[rf_score, if_score]], dtype=torch.float32)
            anfis_output = anfis(anfis_input).item()

            src_ip = row.get("id.orig_h", "0.0.0.0")
            if anfis_output > threshold:
                print(f"⚡ SYN flood detected! Source IP: {src_ip} | ANFIS score: {anfis_output:.4f}")
                block_ip(src_ip)

                # 📝 Save to Django database
                try:
                    AttackLog.objects.create(
                        source_ip=src_ip,
                        score=anfis_output,
                        status="Malicious"
                    )
                    print(f"📝 Attack saved to database.")
                except Exception as e:
                    print(f"❌ Failed to save attack to DB: {e}")
            else:
                print(f"✅ Benign flow detected. ANFIS score: {anfis_output:.4f}")

        time.sleep(5)

    except KeyboardInterrupt:
        print("\n🛑 Stopping monitor.")
        break
    except Exception as e:
        print(f"❌ Error in monitor loop: {e}")
        time.sleep(5)
