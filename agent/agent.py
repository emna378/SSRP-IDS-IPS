import psutil
import socket
import time
import json
from datetime import datetime
import os
import requests
import threading
from scapy.all import sniff, TCP, IP
import subprocess

# =========================
# Server
# =========================
SERVER_URL = "http://192.168.10.4:5000/agent/report"

# =========================
# Scan detection vars
# =========================
SCAN_THRESHOLD = 30
TIME_WINDOW = 5
INACTIVITY_TIMEOUT = 6

syn_packets = {}
last_seen = {}
scan_detected = False
current_attacker_ip = None

# =========================
# Scan detection
# =========================
def scan_sniffer(pkt):
    global scan_detected, current_attacker_ip

    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        src = pkt[IP].src
        now = time.time()

        syn_packets.setdefault(src, [])
        syn_packets[src].append(now)
        syn_packets[src] = [t for t in syn_packets[src] if now - t < TIME_WINDOW]
        last_seen[src] = now

        if len(syn_packets[src]) >= SCAN_THRESHOLD:
            scan_detected = True
            current_attacker_ip = src

    for src in list(last_seen.keys()):
        if time.time() - last_seen[src] > INACTIVITY_TIMEOUT:
            syn_packets[src].clear()
            scan_detected = False
            current_attacker_ip = None

def start_sniff():
    sniff(filter="tcp", prn=scan_sniffer, store=0)

threading.Thread(target=start_sniff, daemon=True).start()

# =========================
# Brute force SSH
# =========================
import subprocess
import re
from collections import Counter

def detect_ssh_bruteforce(threshold=3):
    try:
        cmd = [
            "journalctl",
            "-u", "ssh",
            "--since", "1 minute ago",
            "--no-pager"
        ]

        output = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            text=True
        )

        # Compter les échecs
        failed = output.count("Failed password")

        # Extraire les IP attaquantes
        ips = re.findall(r"from (\d+\.\d+\.\d+\.\d+)", output)

        if failed < threshold or not ips:
            return False, None

        # Trouver l’IP la plus fréquente
        counter = Counter(ips)
        bf_ip, attempts = counter.most_common(1)[0]

        return True, bf_ip

    except Exception:
        return False, None

# ===============================
# Ports ouverts (LISTEN)
# ===============================
def get_open_ports():
    ports = set()  # set pour éviter les doublons

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            ports.add(conn.laddr.port)

    return sorted(list(ports))

# ===============================
# Nombre de logs (auth.log)
# ===============================
def count_logs():
    log_file = "/var/log/auth.log"
    if os.path.exists(log_file):
        with open(log_file, "r", errors="ignore") as f:
            return sum(1 for _ in f)
    return 0


# =========================
# Firewall block
# =========================
def block_attacker(ip):
    if not ip:
        return
    print(f"[!] BLOCKING ATTACKER {ip}")
    os.system(
        f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null || "
        f"iptables -A INPUT -s {ip} -j DROP"
    )

# =========================
# Collect data
# =========================
def collect_data():
    global scan_detected, current_attacker_ip
    
    open_ports = get_open_ports()

    # --- brute force ---
    brute_force_detected, bf_ip = detect_ssh_bruteforce()

    # --- blocage automatique ---
    
    if brute_force_detected and bf_ip:
        block_attacker(bf_ip)


    if scan_detected and current_attacker_ip:
        block_attacker(current_attacker_ip)

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": socket.gethostname(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": psutil.virtual_memory().percent,
        "open_ports_count": len(open_ports),
        "scan": scan_detected,
        "attacker_ip": current_attacker_ip,
        "brute_force": brute_force_detected,
        "bruteforce_attacker_ip": bf_ip ,
        "open_ports": open_ports,
        "logs_count": count_logs(),
    }

# =========================
# Send to server
# =========================
def send_to_server(data):
    try:
        requests.post(SERVER_URL, json=data, timeout=3)
    except:
        print("[-] Server unreachable")

# =========================
# Main loop
# =========================
if __name__ == "__main__":
    print("[+] Agent IDS/IPS started\n")

    while True:
        data = collect_data()
        print(json.dumps(data, indent=4))
        send_to_server(data)
        time.sleep(1)





