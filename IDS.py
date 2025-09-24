from flask import Flask, request, jsonify, render_template_string
import logging
import re
from collections import defaultdict
from time import time

app = Flask(__name__)

# ----- Logging Setup -----
logging.basicConfig(filename='requests.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')
attack_logger = logging.getLogger("attacks")
attack_handler = logging.FileHandler("attacks.log")
attack_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
attack_logger.addHandler(attack_handler)
attack_logger.setLevel(logging.WARNING)

# ----- Signature Patterns -----
SQLI_PATTERN = re.compile(r"(union select|drop table|--|or 1=1|insert into)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"<script>|onerror=|alert\(|<img", re.IGNORECASE)

# ----- Rate Limiting -----
ip_requests = defaultdict(list)
BLOCKED_IPS = set()
MAX_REQUESTS_PER_MIN = 20

# ----- Recent Attacks Storage -----
recent_attacks = []

# ----- Detection Functions -----
def detect_signature_attack(data):
    if SQLI_PATTERN.search(data):
        return "SQL Injection"
    if XSS_PATTERN.search(data):
        return "XSS Attack"
    return None

def detect_bruteforce(ip):
    now = time()
    ip_requests[ip] = [t for t in ip_requests[ip] if now - t < 60]
    ip_requests[ip].append(now)
    if len(ip_requests[ip]) > MAX_REQUESTS_PER_MIN:
        BLOCKED_IPS.add(ip)
        return True
    return False

# ----- Middleware -----
@app.before_request
def monitor_request():
    ip = request.remote_addr
    url = request.url
    headers = str(request.headers)
    body = request.get_data(as_text=True) or ""
    query = request.query_string.decode() or ""

    # Blocked IP check
    if ip in BLOCKED_IPS:
        logging.warning(f"Blocked IP tried to access: {ip} - {url}")
        return jsonify({"error": "Access blocked"}), 403

    # Log every request
    logging.info(f"{ip} - {request.method} {url} - Headers: {headers} - Body: {body}")

    # Check all sources
    sources = [body, query, headers]
    for data in sources:
        attack_type = detect_signature_attack(data)
        if attack_type:
            record = {"ip": ip, "type": attack_type, "payload": data, "time": time()}
            recent_attacks.insert(0, record)  # newest first
            if len(recent_attacks) > 50:
                recent_attacks.pop()
            attack_logger.warning(f"{attack_type} detected from {ip} - Payload: {data}")
            return jsonify({"error": f"{attack_type} detected"}), 403

    # Brute-force detection
    if detect_bruteforce(ip):
        record = {"ip": ip, "type": "Brute-force", "payload": "Too many requests", "time": time()}
        recent_attacks.insert(0, record)
        if len(recent_attacks) > 50:
            recent_attacks.pop()
        attack_logger.warning(f"Brute-force detected from {ip}")
        return jsonify({"error": "Too many requests"}), 429

# ----- Example Routes -----
@app.route("/", methods=["GET", "POST"])
def home():
    return "Welcome to the secure website!"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    return f"Hello, {username}!"

# ----- Dashboard -----
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Web IDS Dashboard</title>
    <style>
        body { font-family: Arial; background: #f4f4f9; padding: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background: #444; color: white; }
        tr:nth-child(even) { background: #eee; }
        .blocked { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Web IDS Dashboard</h1>

    <h2>Blocked IPs</h2>
    <ul>
    {% for ip in blocked_ips %}
        <li class="blocked">{{ ip }}</li>
    {% else %}
        <li>No blocked IPs</li>
    {% endfor %}
    </ul>

    <h2>Recent Attacks</h2>
    <table>
        <tr>
            <th>Time</th>
            <th>IP</th>
            <th>Attack Type</th>
            <th>Payload</th>
        </tr>
        {% for attack in attacks %}
        <tr>
            <td>{{ attack.time|round(0) }}</td>
            <td>{{ attack.ip }}</td>
            <td>{{ attack.type }}</td>
            <td>{{ attack.payload }}</td>
        </tr>
        {% else %}
        <tr><td colspan="4">No attacks detected</td></tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route("/dashboard")
def dashboard():
    return render_template_string(DASHBOARD_HTML, blocked_ips=BLOCKED_IPS, attacks=recent_attacks)

# ----- Run Server -----
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
