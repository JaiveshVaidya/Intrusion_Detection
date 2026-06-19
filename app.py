import logging
from time import time
import time as time_module
from flask import Flask, request, jsonify, render_template, render_template_string
from flask_sqlalchemy import SQLAlchemy
import psutil

# Import security and simulator logic
from security import detect_signature_attack, RateLimiter
from simulator import ThreatSimulator

# Set up logging for requests and attacks
logging.basicConfig(
    filename='requests.log', 
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
attack_logger = logging.getLogger("attacks")
attack_handler = logging.FileHandler("attacks.log")
attack_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
attack_logger.addHandler(attack_handler)
attack_logger.setLevel(logging.WARNING)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SIMULATION_MODE'] = True  # Allows X-Forwarded-For header to spoof client IP

db = SQLAlchemy(app)

# ----- Database Models -----
class TrafficLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    path = db.Column(db.String(255))
    method = db.Column(db.String(10))
    user_agent = db.Column(db.String(512))
    is_bot = db.Column(db.Boolean, default=False)
    is_attack = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.Float)

class Attack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    attack_type = db.Column(db.String(50))
    payload = db.Column(db.Text)
    timestamp = db.Column(db.Float)

class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), unique=True)
    blocked_at = db.Column(db.Float)

with app.app_context():
    db.create_all()

# Initialize Rate Limiter: 20 requests per minute
rate_limiter = RateLimiter(limit=20, period=60)

# Initialize simulator (target is local app)
simulator = ThreatSimulator(target_url="http://127.0.0.1:5000")

# Keywords to classify bots
BOT_USER_AGENTS_KEYWORDS = [
    'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python',
    'requests', 'urllib', 'httpie', 'postman', 'insomnia', 'automated',
    'headless', 'phantom', 'selenium', 'puppeteer'
]

def is_bot_ua(ua):
    if not ua:
        return True
    ua_lower = ua.lower()
    return any(keyword in ua_lower for keyword in BOT_USER_AGENTS_KEYWORDS)

def get_client_ip():
    """Extracts client IP, respecting X-Forwarded-For in simulation mode."""
    if app.config.get('SIMULATION_MODE', False) and 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr

# ----- Middleware for Security Monitoring -----
@app.before_request
def monitor_request():
    # Bypass security checks for dashboard administration and static content to avoid lockouts
    if (request.path.startswith('/dashboard') or 
        request.path.startswith('/static') or 
        request.path.startswith('/api/dashboard')):
        return None

    ip = get_client_ip()
    url = request.url
    headers_str = str(request.headers)
    user_agent = request.headers.get('User-Agent', '')
    body = request.get_data(as_text=True) or ""
    query = request.query_string.decode() or ""

    # Check if client IP is blocked
    if BlockedIP.query.filter_by(ip=ip).first():
        logging.warning(f"Blocked IP tried to access: {ip} - {url}")
        print(f"[BLOCK] Blocked IP access attempt from: {ip}")
        # Log to traffic database as blocked
        log_entry = TrafficLog(
            ip=ip, path=request.path, method=request.method,
            user_agent=user_agent, is_bot=is_bot_ua(user_agent),
            is_attack=True, timestamp=time()
        )
        db.session.add(log_entry)
        db.session.commit()
        return jsonify({"error": "Access blocked: IP is blacklisted by IDS."}), 403

    # Scan request payload for signatures
    sources = [body, query, headers_str]
    for data in sources:
        attack_type = detect_signature_attack(data)
        if attack_type:
            # 1. Log attack in DB
            attack = Attack(ip=ip, attack_type=attack_type, payload=data[:500], timestamp=time())
            db.session.add(attack)
            
            # 2. Block the IP (auto-ban signature attacks)
            if not BlockedIP.query.filter_by(ip=ip).first():
                db.session.add(BlockedIP(ip=ip, blocked_at=time()))
                
            # 3. Save to request traffic logs
            log_entry = TrafficLog(
                ip=ip, path=request.path, method=request.method,
                user_agent=user_agent, is_bot=is_bot_ua(user_agent),
                is_attack=True, timestamp=time()
            )
            db.session.add(log_entry)
            db.session.commit()

            # 4. Log to files
            attack_logger.warning(f"{attack_type} detected from {ip} - Payload: {data[:200]}")
            logging.info(f"{ip} - {request.method} {url} - BLOCKED ({attack_type})")
            
            print(f"[ALERT] {attack_type} detected from {ip}")
            return jsonify({"error": f"Security alert: {attack_type} detected and IP blocked."}), 403

    # Run rate limiter (brute-force check)
    if rate_limiter.is_rate_limited(ip):
        attack_type = "Brute-force"
        # 1. Log attack in DB
        attack = Attack(ip=ip, attack_type=attack_type, payload="Too many requests (Rate limit exceeded)", timestamp=time())
        db.session.add(attack)
        
        # 2. Block the IP
        if not BlockedIP.query.filter_by(ip=ip).first():
            db.session.add(BlockedIP(ip=ip, blocked_at=time()))
            
        # 3. Save to request traffic logs
        log_entry = TrafficLog(
            ip=ip, path=request.path, method=request.method,
            user_agent=user_agent, is_bot=is_bot_ua(user_agent),
            is_attack=True, timestamp=time()
        )
        db.session.add(log_entry)
        db.session.commit()

        # 4. Log to files
        attack_logger.warning(f"Brute-force detected from {ip}")
        logging.info(f"{ip} - {request.method} {url} - BLOCKED (Rate limit exceeded)")
        
        print(f"[ALERT] Rate-limit exceeded. IP {ip} has been blocked.")
        return jsonify({"error": "Too many requests. Your IP has been blocked."}), 429

    # Request is normal, log it
    log_entry = TrafficLog(
        ip=ip, path=request.path, method=request.method,
        user_agent=user_agent, is_bot=is_bot_ua(user_agent),
        is_attack=False, timestamp=time()
    )
    db.session.add(log_entry)
    db.session.commit()
    logging.info(f"{ip} - {request.method} {url} - Status: 200")


# ----- Normal Website Routes -----
@app.route("/")
def home():
    return jsonify({"message": "Welcome to the secure website! Protected by Antigravity IDS."})

@app.route("/about")
def about():
    return jsonify({"message": "About Us: We specialize in secure and high-performance applications."})

@app.route("/contact")
def contact():
    return jsonify({"message": "Contact us at security@example.com."})

@app.route("/products")
def products():
    return jsonify({"products": ["Firewall", "IDS", "SIEM", "WAF"]})

@app.route("/services")
def services():
    return jsonify({"services": ["Penetration Testing", "Security Auditing", "Incident Response"]})

@app.route("/help")
def help_route():
    return jsonify({"message": "If you are encountering errors, contact administrative support."})

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "Guest")
    return jsonify({"message": f"Hello, {username}! Authentication successful."})


# ----- Administrative Dashboard Routes -----
@app.route("/dashboard")
def dashboard_ui():
    # Renders the template from templates/dashboard.html
    return render_template("dashboard.html")


# ----- REST APIs for Dashboard -----
@app.route("/api/dashboard/stats")
def dashboard_stats():
    now = time()
    
    # 1. Base Metrics
    total_requests = TrafficLog.query.count()
    total_attacks = Attack.query.count()
    total_blocked = BlockedIP.query.count()
    
    # 2. Dynamic Threat Level Assessment (based on attacks in the last 60 seconds)
    recent_threat_count = Attack.query.filter(Attack.timestamp >= now - 60).count()
    if recent_threat_count == 0:
        threat_level = "Low"
    elif recent_threat_count <= 3:
        threat_level = "Medium"
    elif recent_threat_count <= 8:
        threat_level = "High"
    else:
        threat_level = "Critical"
        
    # 3. System Stats (Telemetry)
    cpu_percent = 0.0
    ram_percent = 0.0
    try:
        cpu_percent = psutil.cpu_percent()
        ram_percent = psutil.virtual_memory().percent
    except Exception:
        pass
        
    # 4. Attack Types Grouping
    attack_types = {"SQL Injection": 0, "XSS Attack": 0, "Path Traversal": 0, "Command Injection": 0, "Brute-force": 0}
    for type_name in attack_types.keys():
        attack_types[type_name] = Attack.query.filter_by(attack_type=type_name).count()
        
    # 5. Traffic Trend (last 10 blocks of 5 seconds)
    traffic_trend = []
    for i in range(9, -1, -1):
        start_t = now - (i + 1) * 5
        end_t = now - i * 5
        n_normal = TrafficLog.query.filter(
            TrafficLog.timestamp >= start_t, 
            TrafficLog.timestamp < end_t, 
            TrafficLog.is_attack == False
        ).count()
        n_attack = TrafficLog.query.filter(
            TrafficLog.timestamp >= start_t, 
            TrafficLog.timestamp < end_t, 
            TrafficLog.is_attack == True
        ).count()
        
        # Format time label
        time_label = time_module.strftime("%H:%M:%S", time_module.localtime(end_t))
        traffic_trend.append({
            "label": time_label,
            "normal": n_normal,
            "attack": n_attack
        })
        
    # 6. Detailed registers
    recent_attacks = []
    attacks_db = Attack.query.order_by(Attack.timestamp.desc()).limit(15).all()
    for att in attacks_db:
        recent_attacks.append({
            "id": att.id,
            "ip": att.ip,
            "type": att.attack_type,
            "payload": att.payload,
            "time": time_module.strftime("%Y-%m-%d %H:%M:%S", time_module.localtime(att.timestamp))
        })
        
    blocked_ips_list = []
    blocked_db = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    for b in blocked_db:
        blocked_ips_list.append({
            "ip": b.ip,
            "blocked_at": time_module.strftime("%Y-%m-%d %H:%M:%S", time_module.localtime(b.blocked_at or now))
        })
        
    return jsonify({
        "total_requests": total_requests,
        "total_attacks": total_attacks,
        "total_blocked": total_blocked,
        "threat_level": threat_level,
        "system_stats": {
            "cpu": cpu_percent,
            "ram": ram_percent
        },
        "attack_types": attack_types,
        "traffic_trend": traffic_trend,
        "recent_attacks": recent_attacks,
        "blocked_ips": blocked_ips_list,
        "simulator_active": simulator.active
    })

@app.route("/api/dashboard/simulate/start", methods=["POST"])
def start_simulation():
    simulator.start()
    return jsonify({"status": "success", "message": "Background threat simulator started."})

@app.route("/api/dashboard/simulate/stop", methods=["POST"])
def stop_simulation():
    simulator.stop()
    return jsonify({"status": "success", "message": "Threat simulator stopped."})

@app.route("/api/dashboard/block", methods=["POST"])
def manual_block():
    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "IP address is required."}), 400
        
    if not BlockedIP.query.filter_by(ip=ip).first():
        db.session.add(BlockedIP(ip=ip, blocked_at=time()))
        db.session.commit()
        print(f"[MANUAL BLOCK] IP {ip} was blocked manually.")
        return jsonify({"status": "success", "message": f"IP {ip} has been blocked."})
    return jsonify({"status": "error", "message": f"IP {ip} is already blocked."})

@app.route("/api/dashboard/unblock", methods=["POST"])
def manual_unblock():
    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "IP address is required."}), 400
        
    record = BlockedIP.query.filter_by(ip=ip).first()
    if record:
        db.session.delete(record)
        db.session.commit()
        print(f"[MANUAL UNBLOCK] IP {ip} was unblocked manually.")
        return jsonify({"status": "success", "message": f"IP {ip} has been unblocked."})
    return jsonify({"status": "error", "message": f"IP {ip} was not blocked."})

@app.route("/api/dashboard/clear-logs", methods=["POST"])
def clear_logs():
    try:
        # Delete entries
        db.session.query(TrafficLog).delete()
        db.session.query(Attack).delete()
        db.session.query(BlockedIP).delete()
        db.session.commit()
        
        # Reset security rate limiter counters
        rate_limiter.clear()
        
        # Clear log files
        with open('requests.log', 'w') as f:
            f.write('')
        with open('attacks.log', 'w') as f:
            f.write('')
            
        print("[RESET] Dashboard databases and log files have been reset.")
        return jsonify({"status": "success", "message": "Logs and blocked list cleared successfully."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/dashboard/test-attack", methods=["POST"])
def run_test_attack():
    data = request.get_json() or {}
    attack_type = data.get("type")
    if not attack_type:
        return jsonify({"status": "error", "message": "Attack type is required."}), 400
        
    triggered = simulator.trigger_single_attack(attack_type)
    if triggered:
        return jsonify({"status": "success", "message": f"Simulated {attack_type} request sent."})
    return jsonify({"status": "error", "message": "Failed to send simulated attack."}), 500


# ----- Run Flask Server -----
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
