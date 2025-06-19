
import os
import time
import subprocess
import pandas as pd
import signal
from scapy.all import IP, TCP, send

# ========== CONFIG ==========
target_ip = "10.8.0.26"  # CHANGE THIS to your actual host or router IP
target_port = 80
benign_duration = 180     # Seconds to capture benign traffic
syn_duration = 30         # Seconds for SYN flood
output_file = "datasets_and_models/zeek_combined_training.csv"
# ============================

# Directory setup
pcap_dir = "datasets_and_models/pcaps"
zeek_out_dir = "datasets_and_models/zeek_out"
data_dir = "datasets_and_models"
os.makedirs(pcap_dir, exist_ok=True)
os.makedirs(zeek_out_dir, exist_ok=True)
os.makedirs(data_dir, exist_ok=True)

# ----------------------------------
# Run Zeek on PCAP
# ----------------------------------
def run_zeek(pcap_file, output_subdir):
    output_path = os.path.join(zeek_out_dir, output_subdir)
    os.makedirs(output_path, exist_ok=True)
    full_path = os.path.abspath(pcap_file)
    subprocess.run(["/usr/local/zeek/bin/zeek", "-r", full_path], cwd=output_path, check=True)
    return os.path.join(output_path, "conn.log")

# ----------------------------------
# Parse conn.log with full features
# ----------------------------------
def parse_conn_log(path):
    with open(path) as f:
        lines = f.readlines()
    field_line = next(line for line in lines if line.startswith("#fields"))
    headers = field_line.strip().split("\t")[1:]
    data_lines = [line.strip().split("\t") for line in lines if not line.startswith("#")]
    df = pd.DataFrame(data_lines, columns=headers)
    return df

# ----------------------------------
# 1. BENIGN TRAFFIC COLLECTION
# ----------------------------------
print(" Capturing benign traffic... Please browse or let the script simulate it.")
benign_pcap = os.path.join(pcap_dir, "benign.pcap")
tcpdump_proc = subprocess.Popen(["sudo", "tcpdump", "-i", "any", "-w", benign_pcap])

# 🌐 Start curl/ping simulation in background
benign_simulator = subprocess.Popen(
    ["bash", "-c",
     "for i in {1..300}; do curl -s https://example.com > /dev/null; ping -c 1 8.8.8.8 > /dev/null; sleep 1; done"]
)

time.sleep(benign_duration)
tcpdump_proc.send_signal(signal.SIGINT)
tcpdump_proc.wait()
benign_simulator.terminate()
print(" Benign traffic capture complete.")

# ----------------------------------
# 2. SYN FLOOD SIMULATION
# ----------------------------------
print("Simulating SYN flood for 30 seconds...")
syn_pcap = os.path.join(pcap_dir, "syn.pcap")
tcpdump_proc = subprocess.Popen(["sudo", "tcpdump", "-i", "any", "-w", syn_pcap])
start = time.time()
while time.time() - start < syn_duration:
    pkt = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    send(pkt, verbose=0, inter=0.0005)
tcpdump_proc.send_signal(signal.SIGINT)
tcpdump_proc.wait()
print("SYN flood capture complete.")

# ----------------------------------
# 3. ZEEK PARSING
# ----------------------------------
print(" Running Zeek on PCAPs...")
benign_log = run_zeek(benign_pcap, "benign")
syn_log = run_zeek(syn_pcap, "syn")

df_benign = parse_conn_log(benign_log)
df_benign["Label"] = 0
df_syn = parse_conn_log(syn_log)
df_syn["Label"] = 1

# ----------------------------------
# 4. COMBINE AND SAVE
# ----------------------------------
df_final = pd.concat([df_benign, df_syn], ignore_index=True)
df_final.to_csv(output_file, index=False)
print(f" Combined training dataset saved to: {output_file} ({len(df_final)} rows)")
