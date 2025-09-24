from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
import re
from collections import defaultdict
from time import time
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids.db'
db = SQLAlchemy(app)

# ----- Database Models -----
class Attack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    attack_type = db.Column(db.String(50))
    payload = db.Column(db.Text)
    timestamp = db.Column(db.Float)

class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), unique=True)

with app.app_context():
    db.create_all()

# ----- Signature Patterns -----
SQLI_PATTERN = re.compile(r"(union select|drop table|--|or 1=1|insert into)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"<script>|onerror=|alert\(|<img", re.IGNORECASE)

# ----- Rate Limiting -----
ip_requests = defaultdict(list)
MAX_REQUESTS_PER_MIN = 20

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
        if not BlockedIP.query.filter_by(ip=ip).first():
            db.session.add(BlockedIP(ip=ip))
            db.session.commit()
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

    # Block IPs automatically
    if BlockedIP.query.filter_by(ip=ip).first():
        print(f"[ALERT] Blocked IP tried to access: {ip}")
        return jsonify({"error": "Access blocked"}), 403

    # Check all sources for attacks
    sources = [body, query, headers]
    for data in sources:
        attack_type = detect_signature_attack(data)
        if attack_type:
            attack = Attack(ip=ip, attack_type=attack_type, payload=data, timestamp=time())
            db.session.add(attack)
            db.session.commit()
            print(f"[ALERT] {attack_type} detected from {ip}")
            return jsonify({"error": f"{attack_type} detected"}), 403

    # Brute-force detection
    if detect_bruteforce(ip):
        attack = Attack(ip=ip, attack_type="Brute-force", payload="Too many requests", timestamp=time())
        db.session.add(attack)
        db.session.commit()
        print(f"[ALERT] Brute-force detected from {ip}")
        return jsonify({"error": "Too many requests"}), 429

# ----- Routes -----
@app.route("/", methods=["GET", "POST"])
def home():
    return "Welcome to the secure website!"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    return f"Hello, {username}!"

# ----- Dashboard -----
@app.route("/dashboard")
def dashboard():
    attacks = Attack.query.order_by(Attack.timestamp.desc()).limit(50).all()
    blocked_ips = [b.ip for b in BlockedIP.query.all()]

    # Generate attack type chart
    types = [a.attack_type for a in Attack.query.all()]
    type_counts = {t: types.count(t) for t in set(types)}
    plt.figure(figsize=(4,2))
    plt.bar(type_counts.keys(), type_counts.values(), color='tomato')
    plt.title("Attacks by Type")
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    attack_chart = base64.b64encode(buf.getvalue()).decode()
    plt.close()

    DASHBOARD_HTML = """
    <html>
    <head><title>Web IDS Dashboard</title></head>
    <body>
        <h1>Web IDS Dashboard</h1>
        <h2>Blocked IPs</h2>
        <ul>
        {% for ip in blocked_ips %}
            <li>{{ ip }}</li>
        {% else %}
            <li>No blocked IPs</li>
        {% endfor %}
        </ul>

        <h2>Recent Attacks</h2>
        <table border="1" cellpadding="5">
            <tr><th>Time</th><th>IP</th><th>Type</th><th>Payload</th></tr>
            {% for a in attacks %}
            <tr>
                <td>{{ a.timestamp|round(0) }}</td>
                <td>{{ a.ip }}</td>
                <td>{{ a.attack_type }}</td>
                <td>{{ a.payload }}</td>
            </tr>
            {% else %}
            <tr><td colspan="4">No attacks detected</td></tr>
            {% endfor %}
        </table>

        <h2>Attack Type Chart</h2>
        <img src="data:image/png;base64,{{ attack_chart }}" />
    </body>
    </html>
    """
    return render_template_string(DASHBOARD_HTML, attacks=attacks, blocked_ips=blocked_ips, attack_chart=attack_chart)

# ----- Run Server -----
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
