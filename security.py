import re
from collections import defaultdict
from time import time
import threading

# ----- Signature Patterns -----
# SQL Injection Detection
SQLI_PATTERN = re.compile(
    r"(union\s+select|drop\s+table|--|or\s+\d+=\d+|\bselect\b.*\bfrom\b|insert\s+into|delete\s+from|update\s+.*set)",
    re.IGNORECASE
)

# Cross-Site Scripting (XSS) Detection
XSS_PATTERN = re.compile(
    r"(<script>|onerror\s*=|onload\s*=|javascript\s*:|\balert\s*\(|<img\s+.*src|document\s*\.\s*cookie)",
    re.IGNORECASE
)

# Path Traversal Detection
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini)",
    re.IGNORECASE
)

# Command Injection Detection
CMD_INJECTION_PATTERN = re.compile(
    r"([;&|`]+(?:\s)*(?:cat|dir|ls|ping|whoami|id|sh|bash|cmd|powershell|wget|curl|nc))",
    re.IGNORECASE
)

def detect_signature_attack(data):
    """
    Scans the input data string for signature-based attacks.
    Returns the attack type if found, otherwise None.
    """
    if not data:
        return None
    
    if SQLI_PATTERN.search(data):
        return "SQL Injection"
    if XSS_PATTERN.search(data):
        return "XSS Attack"
    if PATH_TRAVERSAL_PATTERN.search(data):
        return "Path Traversal"
    if CMD_INJECTION_PATTERN.search(data):
        return "Command Injection"
    
    return None


class RateLimiter:
    """
    Thread-safe sliding window rate limiter for detecting brute-force attacks.
    """
    def __init__(self, limit=20, period=60):
        self.limit = limit
        self.period = period
        self.requests = defaultdict(list)
        self.lock = threading.Lock()

    def is_rate_limited(self, key):
        """
        Registers a request and checks if rate limit has been exceeded.
        Returns True if rate limited, False otherwise.
        """
        now = time()
        with self.lock:
            # Filter out requests outside the sliding window
            self.requests[key] = [t for t in self.requests[key] if now - t < self.period]
            self.requests[key].append(now)
            
            if len(self.requests[key]) > self.limit:
                return True
        return False

    def clear(self):
        """Resets the rate limiter cache."""
        with self.lock:
            self.requests.clear()
