from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from datetime import datetime
import os
import sqlite3
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "ssrp.db")

#-----------------------
# save attack 
#------------------------
  
def save_attack(attack_type, source_ip, target_ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO attacks (attack_type, source_ip, target_ip, detected_at)
        VALUES (?, ?, ?, ?)
    """, (attack_type, source_ip, target_ip, datetime.now()))

    conn.commit()
    conn.close()





app = Flask(__name__)
app.secret_key = "emna"

# =========================
# Auth
# =========================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"

# =========================
# Storage (simple)
# =========================
clients_data = []
alerts = []
blocked_ips = set()

# =========================
# Thresholds
# =========================
CPU_ALERT = 80
RAM_ALERT = 80
PORTS_ALERT = 3

# -------------------------
# Login
# -------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form.get("username") == ADMIN_USERNAME and
            request.form.get("password") == ADMIN_PASSWORD
        ):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        flash("Nom d'utilisateur ou mot de passe incorrect", "danger")
    return render_template("login.html")

# -------------------------
# Dashboard
# -------------------------
@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    unique_clients = {}
    for c in clients_data:
        unique_clients[c["ip"]] = c

    for c in unique_clients.values():
        c["alert"] = (
            c["cpu_percent"] > CPU_ALERT or
            c["ram_percent"] > RAM_ALERT or
            c["open_ports_count"] > PORTS_ALERT or
            c.get("brute_force") or
            c.get("scan")
        )

    return render_template("dashboard.html", clients=list(unique_clients.values()))






# -------------------------
# Client details
# -------------------------
@app.route("/client/<ip>")
def client_detail(ip):
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    history = [c for c in clients_data if c["ip"] == ip]
    latest = history[-1] if history else None

    alert = False
    if latest:
        alert = (
            latest.get("cpu_percent", 0) > CPU_ALERT or
            latest.get("ram_percent", 0) > RAM_ALERT or
            latest.get("open_ports_count", 0) > PORTS_ALERT or
            latest.get("scan") or
            latest.get("brute_force")
        )

    return render_template(
        "client_detail.html",
        ip=ip,
        history=history,
        latest=latest,
        alert=alert
    )

# -------------------------
# Endpoint agent
# -------------------------
@app.route("/agent/report", methods=["POST"])
def receive_data():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error"}), 400

    victim_ip = request.remote_addr
    data["ip"] = victim_ip
    clients_data.append(data)

    # -------------------------
    # Détection alerte
    # -------------------------
    is_alert = (
        data.get("cpu_percent", 0) > CPU_ALERT or
        data.get("ram_percent", 0) > RAM_ALERT or
        data.get("open_ports_count", 0) > PORTS_ALERT or
        data.get("scan") or
        data.get("brute_force")
    )

    if not is_alert:
        return jsonify({"status": "ok"}), 200

    # -------------------------
    # Identifier l'attaque
    # -------------------------
    attacker_ip = "UNKNOWN"
    attack_type = "resource_abuse"

    if data.get("scan") and data.get("attacker_ip"):
        attacker_ip = data["attacker_ip"]
        attack_type = "scan"

    elif data.get("brute_force") and data.get("bruteforce_attacker_ip"):
        attacker_ip = data["bruteforce_attacker_ip"]
        attack_type = "brute_force"

    # -------------------------
    # ✅ SAUVEGARDE DANS SQLITE
    # -------------------------
    save_attack(
        attack_type=attack_type,
        source_ip=attacker_ip,
        target_ip=victim_ip
    )

    alerts.append({
        "victim_ip": victim_ip,
        "attacker_ip": attacker_ip,
        "type": attack_type,
        "timestamp": datetime.now(),
        "details": data
    })

    return jsonify({"status": "alert_recorded"}), 200





# -------------------------
# Alerts page
# -------------------------
@app.route("/alerts")
def list_alerts():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("alerts.html", alerts=alerts)

# -------------------------
# Block IP (GET + POST)
# -------------------------
@app.route("/block", methods=["GET", "POST"])
def block_ip():
    if request.method == "GET":
        ip = request.args.get("ip")
    else:
        data = request.get_json()
        ip = data.get("ip") if data else None

    if not ip:
        return jsonify({"error": "IP manquante"}), 400

    if ip not in blocked_ips:
        os.system(
            f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null || "
            f"iptables -A INPUT -s {ip} -j DROP"
        )
        blocked_ips.add(ip)

    return jsonify({"status": "blocked", "ip": ip})

# -------------------------
# Agent fetch blocked IPs
# -------------------------
@app.route("/agent/blocked", methods=["GET"])
def agent_blocked():
    return jsonify(list(blocked_ips))

# -------------------------
# Kill process (simulation)
# -------------------------
@app.route("/kill/<ip>/<int:pid>")
def kill_process(ip, pid):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    flash(f"Process {pid} arrêté sur {ip}", "success")
    return redirect(url_for("list_alerts"))

# -------------------------
# Logout
# -------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))



#----------------------------
#   affichage de l'historique 
#----------------------------
@app.route("/history")
def history():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT attack_type, source_ip, target_ip, detected_at
        FROM attacks
        ORDER BY detected_at DESC
    """)
    attacks = cursor.fetchall()

    conn.close()
    return render_template("history.html", attacks=attacks)







#----------------------------
# affichage de statistique 
#--------------------------
@app.route("/stats")
def stats():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM attacks")
    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT attack_type, COUNT(*)
        FROM attacks
        GROUP BY attack_type
    """)
    by_type = cursor.fetchall()

    conn.close()

    return render_template("stats.html", total=total, by_type=by_type)





# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)






