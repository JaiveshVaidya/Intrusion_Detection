import threading
import time
import random
import requests

# Traffic simulation datasets
REAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
]

BOT_USER_AGENTS = [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/7.68.0",
    "python-requests/2.28.1",
    "Wget/1.20.3 (linux-gnu)",
    "PostmanRuntime/7.32.3",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Go-http-client/1.1"
]

SUSPICIOUS_IPS = [
    "185.220.101.32", "198.98.51.189", "45.148.10.85", "192.42.116.16",
    "23.129.64.214", "185.220.102.8", "199.87.154.255", "45.79.85.112"
]

NORMAL_ROUTES = [
    "/", "/about", "/contact", "/products", "/services", "/help"
]

ATTACK_PAYLOADS = [
    # SQL Injection payloads
    ("SQL Injection", "POST", "/login", {"username": "admin' OR 1=1--", "password": "password"}),
    ("SQL Injection", "GET", "/products?category=union select null, username, password from users", None),
    ("SQL Injection", "POST", "/submit", {"data": "'; DROP TABLE attacks; --"}),
    
    # XSS payloads
    ("XSS Attack", "GET", "/search?q=<script>alert('XSS')</script>", None),
    ("XSS Attack", "POST", "/comments", {"text": "Hello <img src=x onerror=alert(1)>"}),
    ("XSS Attack", "GET", "/profile?user=javascript:alert(document.cookie)", None),
    
    # Path Traversal payloads
    ("Path Traversal", "GET", "/download?file=../../../../etc/passwd", None),
    ("Path Traversal", "GET", "/view?path=..\\..\\windows\\win.ini", None),
    
    # Command Injection payloads
    ("Command Injection", "POST", "/ping", {"host": "127.0.0.1; whoami"}),
    ("Command Injection", "POST", "/execute", {"cmd": "dir && ping 127.0.0.1"})
]

class ThreatSimulator:
    def __init__(self, target_url="http://127.0.0.1:5000"):
        self.target_url = target_url
        self.active = False
        self.thread = None
        self._lock = threading.Lock()

    def generate_random_ip(self, suspicious=False):
        if suspicious or random.random() < 0.2:
            return random.choice(SUSPICIOUS_IPS)
        return f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def start(self):
        with self._lock:
            if not self.active:
                self.active = True
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()

    def stop(self):
        with self._lock:
            self.active = False

    def _run(self):
        while True:
            with self._lock:
                if not self.active:
                    break
            
            # 70% chance of normal request, 30% chance of attack/suspicious request
            is_attack = random.random() < 0.3
            
            try:
                if is_attack:
                    # Choose a simulated attack
                    attack_type, method, path, data = random.choice(ATTACK_PAYLOADS)
                    ip = self.generate_random_ip(suspicious=True)
                    ua = random.choice(BOT_USER_AGENTS)
                    headers = {
                        "User-Agent": ua,
                        "X-Forwarded-For": ip
                    }
                    
                    # Sometimes run a brute force attack (high rate from same IP)
                    if random.random() < 0.3:
                        brute_ip = self.generate_random_ip(suspicious=True)
                        headers["X-Forwarded-For"] = brute_ip
                        # Fire multiple rapid requests to trigger rate limiting
                        for _ in range(25):
                            requests.post(
                                f"{self.target_url}/login",
                                data={"username": "admin", "password": "wrongpassword"},
                                headers=headers,
                                timeout=1.0
                            )
                            time.sleep(0.02)
                    else:
                        # Send standard payload attack
                        if method == "GET":
                            requests.get(f"{self.target_url}{path}", headers=headers, timeout=2.0)
                        else:
                            requests.post(f"{self.target_url}{path}", data=data, headers=headers, timeout=2.0)
                else:
                    # Normal User Request
                    path = random.choice(NORMAL_ROUTES)
                    ip = self.generate_random_ip(suspicious=False)
                    ua = random.choice(REAL_USER_AGENTS)
                    headers = {
                        "User-Agent": ua,
                        "X-Forwarded-For": ip
                    }
                    
                    # Normal request can be GET or POST
                    if random.random() < 0.8:
                        requests.get(f"{self.target_url}{path}", headers=headers, timeout=2.0)
                    else:
                        requests.post(
                            f"{self.target_url}/login",
                            data={"username": f"user{random.randint(100,999)}", "password": "password123"},
                            headers=headers,
                            timeout=2.0
                        )
            except Exception as e:
                # Silent catch to prevent simulator crash if Flask server restarts
                time.sleep(1.0)
                continue
                
            # Random delay between requests to simulate human/bot timing variance
            time.sleep(random.uniform(0.5, 3.0))
            
    def trigger_single_attack(self, attack_type):
        """Sends a single attack of the specified type for testing."""
        # Find matching payload
        matches = [p for p in ATTACK_PAYLOADS if p[0] == attack_type]
        if not matches:
            return False
            
        _, method, path, data = random.choice(matches)
        ip = self.generate_random_ip(suspicious=True)
        ua = random.choice(BOT_USER_AGENTS)
        headers = {
            "User-Agent": ua,
            "X-Forwarded-For": ip
        }
        
        try:
            if method == "GET":
                requests.get(f"{self.target_url}{path}", headers=headers, timeout=2.0)
            else:
                requests.post(f"{self.target_url}{path}", data=data, headers=headers, timeout=2.0)
            return True
        except Exception:
            return False
