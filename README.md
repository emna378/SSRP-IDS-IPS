# SSRP: System Surveillance & Response Protocol
**A Distributed IDS/IPS with Real-Time SIEM Dashboard & Ansible Automation**

## 🛡️ Project Overview
SSRP is an integrated security framework designed to detect and mitigate threats in real-time across distributed Linux environments. Developed and tested within a **GNS3** virtual network, the system combines host-based monitoring with active network defense (IPS).

### 🚀 Key Features
* **Intrusion Detection (IDS):** * **Network-based:** Uses **Scapy** to detect TCP SYN Floods (Port Scanning).
    * **Host-based:** Monitors `journalctl` and `/var/log/auth.log` for SSH Brute Force attempts.
* **Active Response (IPS):** Automatically triggers `iptables` rules to drop traffic from identified attackers.
* **Centralized SIEM Dashboard:** A **Flask** web application that aggregates real-time telemetry (CPU, RAM, Open Ports) from all agents.
* **Forensic Logging:** All security incidents are archived in a **SQLite** database for historical analysis.
* **Deployment Automation:** Managed via **Ansible** and secured as a **systemd** service for persistent protection.

---

## 🏗️ Architecture & Topology
The system operates on a Client-Server model:
1.  **The Agent:** Runs as a background service on client machines (e.g., Kali Linux).
2.  **The Server:** Acts as the central SIEM, receiving data and managing the block-list.



[Image of Intrusion Detection System architecture]


---

## 🛠️ Installation & Setup

### 1. Server Configuration
```bash
cd server
pip install -r requirements.txt
python init_db.py  # Initializes the SQLite database
python server.py   # Starts the SIEM on port 5000
