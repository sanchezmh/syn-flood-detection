import os
import sys
import time
import pandas as pd
import joblib
import torch
import torch.nn as nn

# ========== CONFIG ==========
zeek_log_path = "conn.log"
model_dir = "datasets_and_models/trainer"
threshold = 0.1
blocked_ips = set()

# ========== DJANGO SETUP ==========
sys.path.append(os.path.join(os.path.dirname(__file__), 'defense_system'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'defense_system.settings')

import django
django.setup()
from attacks.models import AttackLog, AttackCounter
from django.core.mail import send_mail
from django.conf import settings

# ========== EMAIL NOTIFICATION ==========
def send_attack_email(total_count):
    send_mail(
        subject='SYN Flood Alert: New Attacks Blocked',
        message=f'A total of {total_count} SYN flood attacks have been blocked so far.',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=['mhemberesanchez@gmail.com'],
        fail_silently=False,
    )

# ========== LOAD MODELS ==========
print("🔄 Loading models...")
rf_model = joblib.load(os.path.join(model_dir, "rf_model.joblib"))
if_model = joblib.load(os.path.join(model_dir, "if_model.joblib"))
scaler = joblib.load(os.path.join(model_dir, "anfis_input_scaler.joblib"))

# === Define ANFIS classes ===
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
        mf_out = self.mf_layer(x).permute(0, 2, 1)
        rules = torch.cartesian_prod(*[torch.arange(self.num_mfs) for _ in range(self.num_inputs)])
        rule_strengths = torch.ones((batch_size, self.num_rules), device=x.device)
        for i in range(self.num_inputs):
            rule_strengths *= mf_out[:, rules[:, i], i]
        norm_strengths = rule_strengths / rule_strengths.sum(dim=1, keepdim=True)
        x_with_bias = torch.cat([x, torch.ones(batch_size, 1)], dim=1)
        rule_outputs = torch.matmul(x_with_bias, self.rule_weights.t())
        return torch.sigmoid((norm_strengths * rule_outputs).sum(dim=1, keepdim=True))

# === Load Trained ANFIS Model ===
anfis = joblib.load(os.path.join(model_dir, "anfis_model.joblib"))
anfis.eval()
print("✅ Models loaded!")

# ========== ZEEK LOG PARSING ==========
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
        print("⚠ No valid Zeek rows.")
        return pd.DataFrame()
    return pd.DataFrame(clean_data, columns=headers)

# ========== FEATURE EXTRACTION ==========
def extract_features(row):
    try:
        features = [
            float(row.get('duration', 0)),
            float(row.get('orig_bytes', 0)),
            float(row.get('resp_bytes', 0)),
            float(row.get('orig_pkts', 0)),
            float(row.get('orig_ip_bytes', 0)),
            float(row.get('resp_pkts', 0)),
            float(row.get('resp_ip_bytes', 0)),
            float(row.get('pkt_ratio', 0)),
            float(row.get('byte_ratio', 0)),
            float(row.get('ip_byte_ratio', 0))
        ]
        return features
    except Exception as e:
        print(f"⚠ Feature extraction failed: {e}")
        return None

# ========== BLOCKING IP ==========
def block_ip(ip):
    if ip in blocked_ips:
        print(f"ℹ IP {ip} already blocked.")
        return
    print(f"🚨 SYN attack detected from {ip} (not actually blocked in WSL)")
    blocked_ips.add(ip)

# ========== MONITOR LOOP ==========
print("🔍 Starting live Zeek monitor...")
seen_conn_ids = set()

while True:
    try:
        if not os.path.exists(zeek_log_path):
            print("⏳ Waiting for conn.log to appear...")
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

            try:
                X_input = pd.DataFrame([features], columns=rf_model.feature_names_in_)
            except Exception as e:
                print(f"⚠ Column mismatch: {e}")
                continue

            rf_score = rf_model.predict_proba(X_input)[:, 1][0]
            if_score = -if_model.decision_function(X_input)[0]

            scaled_input = scaler.transform([[rf_score, if_score]])
            anfis_input = torch.tensor(scaled_input, dtype=torch.float32)
            anfis_output = anfis(anfis_input).item()
            src_ip = row.get("id.orig_h", "0.0.0.0")

            if anfis_output > threshold:
                if src_ip in blocked_ips:
                    print(f"ℹ IP {src_ip} already blocked.")
                    continue

                print(f"🛑 SYN flood detected! Source IP: {src_ip} | ANFIS: {anfis_output:.4f}")
                block_ip(src_ip)

                try:
                    AttackLog.objects.create(
                        source_ip=src_ip,
                        score=anfis_output,
                        status="Malicious"
                    )
                    print("✅ Attack saved to database.")

                    counter, _ = AttackCounter.objects.get_or_create(id=1)
                    counter.count += 1
                    new_since_last = counter.count - counter.last_emailed

                    if new_since_last >= 1:
                        print(f"📧 {new_since_last} new attacks detected. Sending email...")
                        send_attack_email(counter.count)
                        counter.last_emailed = counter.count

                    counter.save()

                except Exception as e:
                    print(f"❌ Failed to save attack to DB or send email: {e}")

            else:
                print(f"✅ Benign flow. Source IP: {src_ip} | ANFIS: {anfis_output:.4f}")

        time.sleep(5)

    except KeyboardInterrupt:
        print("\n🛑 Monitor stopped.")
        break
    except Exception as e:
        print(f"❌ Error: {e}")
        time.sleep(5)
