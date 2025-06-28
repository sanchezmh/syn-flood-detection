import os
import time
import subprocess
import pandas as pd
import signal
from scapy.all import IP, TCP, send

# Configuration
target_ip = "10.8.0.26"  # my wsl ip address
target_port = 80
syn_duration = 800
pcap_dir = "datasets_and_models/pcaps"
zeek_out_dir = "datasets_and_models/zeek_out"
data_dir = "datasets_and_models"
output_file = os.path.join(data_dir, "zeek_combined_training.csv")

os.makedirs(pcap_dir, exist_ok=True)
os.makedirs(zeek_out_dir, exist_ok=True)

# Run Zeek
def run_zeek(pcap_file, output_subdir):
    output_path = os.path.join(zeek_out_dir, output_subdir)
    os.makedirs(output_path, exist_ok=True)
    full_path = os.path.abspath(pcap_file)
    subprocess.run(["/usr/local/zeek/bin/zeek", "-r", full_path], cwd=output_path, check=True)
    return os.path.join(output_path, "conn.log")

# Parse Zeek logs
def parse_conn_log(path):
    with open(path) as f:
        lines = f.readlines()
    field_line = next(line for line in lines if line.startswith("#fields"))
    headers = field_line.strip().split("\t")[1:]
    data_lines = [line.strip().split("\t") for line in lines if not line.startswith("#")]
    df = pd.DataFrame(data_lines, columns=headers)
    return df

# SYN Flood capture
print("Capturing SYN flood traffic for 30 seconds...")
syn_pcap = os.path.join(pcap_dir, f"syn_only_{int(time.time())}.pcap")
tcpdump_proc = subprocess.Popen(["sudo", "tcpdump", "-i", "any", "-w", syn_pcap])
start = time.time()
while time.time() - start < syn_duration:
    pkt = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    send(pkt, verbose=0, inter=0.0005)
tcpdump_proc.send_signal(signal.SIGINT)
tcpdump_proc.wait()
print("SYN capture complete.")

# Zeek processing
print("Running Zeek on SYN pcap...")
syn_log = run_zeek(syn_pcap, f"syn_only_{int(time.time())}")
df_syn = parse_conn_log(syn_log)
df_syn["Label"] = 1

# Append to CSV
if os.path.exists(output_file):
    df_existing = pd.read_csv(output_file)
    df_final = pd.concat([df_existing, df_syn], ignore_index=True)
else:
    df_final = df_syn

df_final.to_csv(output_file, index=False)
print(f"Appended SYN data to: {output_file} (total rows: {len(df_final)})")
