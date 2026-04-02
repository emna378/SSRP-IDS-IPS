import psutil
import socket
import time
import json
from datetime import datetime
import os
import requests

# ===============================
# Paramètres serveur
# ===============================
SERVER_URL = "http://192.168.10.4:5000/agent/report"  

# ===============================
# CPU et RAM (pourcentages)
# ===============================
def get_resource_usage():
    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": psutil.virtual_memory().percent
    }

# ===============================
# Nombre de ports ouverts (LISTEN)
# ===============================
def count_open_ports():
    count = 0
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN:
            count += 1
    return count

# ===============================
# Nombre de logs (auth.log)
# ===============================
def count_logs():
    log_file = "/var/log/auth.log"
    if os.path.exists(log_file):
        with open(log_file, "r", errors="ignore") as f:
            return sum(1 for _ in f)
    return 0



# ===============================
# Ports ouverts (LISTEN)
# ===============================
def get_open_ports():
    ports = set()  # set pour éviter les doublons

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            ports.add(conn.laddr.port)

    return sorted(list(ports))


#------------------------------
#      detection de scan 
#------------------------------
import psutil
import time

previous_count = 0

def detect_scan():
    global previous_count

    current_count = 0

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_TIME_WAIT:
            current_count += 1

    # différence brutale → scan actif
    if current_count - previous_count > 15:
        previous_count = current_count
        return True

    previous_count = current_count
    return False









# ===============================
# Collecte globale
# ===============================
def collect_data():
    open_ports = get_open_ports()
    scan = detect_scan() 
    bf = detect_ssh_bruteforce() 
    data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": socket.gethostname(),
        "cpu_percent": get_resource_usage()["cpu_percent"],
        "ram_percent": get_resource_usage()["ram_percent"],
        "open_ports_count": count_open_ports(),
        "open_ports": open_ports,
        "logs_count": count_logs(),
        "brute_force": bf,
        "scan": scan 

        }
    return data





# ===============================
# Détection brute force SSH
# ===============================
import subprocess

def detect_ssh_bruteforce(threshold=3):
    try:
        cmd = [
            "journalctl",
            "-u", "ssh",
            "--since", "1 minute ago",
            "--no-pager"
        ]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()

        failed = output.count("Failed password")
        return failed >= threshold
    except:
        return False






# ===============================
# Envoi des données au serveur
# ===============================
def send_to_server(data):
    try:
        response = requests.post(SERVER_URL, json=data, timeout=5)
        if response.status_code == 200:
            print(f"[+] Données envoyées avec succès au serveur.")
        else:
            print(f"[-] Erreur serveur : {response.status_code}")
    except Exception as e:
        print(f"[-] Impossible d’envoyer les données : {e}")


# ===============================
# Lancement agent
# ===============================
if __name__ == "__main__":
    print("[+] Agent client – Collecte et envoi data to server \n")

    while True:
        data = collect_data()
        print(json.dumps(data, indent=4))
        send_to_server(data)
        time.sleep(0)

#----------------------------------
        #apply block 
#----------------------------------
def apply_blocks():
    try:
        r = requests.get("http://192.168.10.4:5000/agent/blocked", timeout=3)
        ips = r.json()
        for ip in ips:
            # ajoute la règle si elle n’existe pas encore
            os.system(f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null || iptables -A INPUT -s {ip} -j DROP")
    except Exception as e:
        print("Impossible d'appliquer les blocs:", e)


  



                   
