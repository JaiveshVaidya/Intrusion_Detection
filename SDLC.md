# Software Development Life Cycle (SDLC) & Threat Model

This document outlines the software engineering lifecycle phases, security designs, threat models, and testing protocols followed during the development of the **SecurIDS** application.

---

## 1. Requirement Analysis & Planning

### 1.1 Objective
Design and implement a lightweight, performant, and self-contained Intrusion Detection (IDS) and Intrusion Prevention System (IPS) for Python-based web applications to mitigate OWASP Top 10 exploits in real-time.

### 1.2 Functional Requirements
* **Real-time Inspection**: Inspect every incoming HTTP request header, query string, and request body before hitting application routes.
* **Auto-Blocking**: Blacklist client IPs immediately upon detecting malicious signature payloads or exceeding rate limits.
* **Sliding Window Rate Limiter**: Prevent brute-force and DDoS attempts by limiting clients to 20 requests per rolling 60-second window.
* **Administrative Control Panel**: Provide visual telemetry, log analysis, interactive charts, and manual block/unblock actions.
* **Simulated Threat Injection**: Support a controlled background thread to simulate traffic models without affecting external networks.

### 1.3 Non-Functional & Security Requirements
* **lockout Prevention**: Ensure that administrative paths (dashboard, APIs) remain open, preventing administrators from accidentally locking themselves out of the system.
* **Thread Safety**: Ensure multi-threaded requests do not cause race conditions in the rate-limiter or blocklists.
* **Performant Overhead**: The security filter must execute in sub-millisecond ranges to minimize latency on clean requests.

---

## 2. System Design & Data Flow

### 2.1 Component Architecture

```text
    +-----------------------------------------------------------+
    |                     CLIENT/VISITOR                        |
    +-----------------------------+-----------------------------+
                                  |
                                  v
    +-----------------------------+-----------------------------+
    |              Flask @app.before_request Middleware         |
    |                                                           |
    |  * Extract Client IP (handling Spoofed Simulation Headers)|
    |  * Route Filter (Exclude Admin UI / Static Resources)     |
    +-----------------------------+-----------------------------+
                                  |
            +---------------------+---------------------+
            |                                           |
            v                                           v
    [Blocked IP Check]                         [IDS Inspection Engine]
            |                                           |
            +------------> [Blocked? (Yes)]             +--> [Check Signatures (SQLi/XSS/Path/Cmd)]
            |                                           |
            |                                           +--> [Check Rate Limit (Sliding Window)]
            v                                           |
    [Return 403 Forbidden] <----------------------------+ (Exploit Detected / Limit Exceeded)
            |
            v (Clean Request)
    [Forward to Target Route] --> [Save TrafficLog]
```

### 2.2 Threat Modeling & Security Controls

| Threat Vector | Description | IPS Mitigation Control |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Attackers send malicious database escape strings to read/write unauthorized tables. | Regular expression scanning of body, query strings, and headers targeting `UNION SELECT`, `DROP`, `--` comments, and boolean conditions (`OR 1=1`). |
| **Cross-Site Scripting (XSS)** | Malicious HTML or script injection to steal session cookies or hijack client sessions. | Input validation regex targeting `<script>`, JavaScript wrappers (`onerror`, `onload`, `javascript:`), and cookie capture parameters. |
| **Path Traversal / Local File Inclusion** | Attackers traverse directories to access configuration or password files on the server (e.g., `../../etc/passwd`). | Strict matching of directory backsteps (`../`, `..\\`) and matches on system target file paths. |
| **Command Injection** | Arbitrary shell execution on the host machine using special pipeline separators (`&&`, `;`, `\|`). | Regex pattern checks for pipeline characters combined with execution command keywords (`sh`, `bash`, `whoami`, `ping`, `curl`). |
| **Brute Force & DDoS** | Massive volume requests to overwhelm routes or break authentication endpoints. | Memory-mapped sliding window rate limiter that auto-blocks IPs executing >20 requests within 60 seconds. |
| **Denial of Service on Admin** | Threat actors block the administrator's IP by submitting falsified requests under the administrator's subnet. | Middleware routing exceptions guarantee dashboard access. Real-time traffic simulation is isolated using `X-Forwarded-For` spoofing, protecting local administrator sockets. |

---

## 3. Implementation & Safe Coding Standards

### 3.1 Regular Expression Optimization
All regular expressions are pre-compiled at module startup (`security.py`) to reduce execution time. Lookarounds are minimized to prevent catastrophic backtracking bugs.

### 3.2 Thread-Safe Rate Limiting
Python's `threading.Lock` protects the sliding-window state inside the `RateLimiter` class, ensuring that concurrent requests from multiple clients do not corrupt rate-limiting lists.

### 3.3 Administrative Isolation
Bypass filters are strictly evaluated based on URL path prefixes:
```python
if (request.path.startswith('/dashboard') or 
    request.path.startswith('/static') or 
    request.path.startswith('/api/dashboard')):
    return None
```
This design prevents regular expressions from matching on administrative payloads (e.g. displaying a database log entry containing a SQLi string on the dashboard must not trigger another security block!).

---

## 4. Verification & Testing Plan

### 4.1 Boundary Testing (Rate Limiting)
* **Goal**: Confirm rate limiter blocks traffic at exactly request `Limit + 1`.
* **Execution**: Trigger 20 requests from a single client in under 5 seconds. Confirm they return `HTTP 200`. Send 21st request. Confirm it immediately returns `HTTP 429` (Too Many Requests). Verify that client IP is added to `BlockedIP` registry.

### 4.2 Threat Payload Verification
* **Goal**: Validate signature detection regex.
* **Execution**: Use manual `curl` requests containing malicious payloads and verify `HTTP 403 Forbidden` response. Check that audit tables list the correct attack classification (e.g. XSS, SQLi).

### 4.3 Scale & Concurrency Testing
* **Goal**: Ensure background simulator and dashboard UI do not lock or leak memory under stress.
* **Execution**: Run continuous simulation for 1 hour generating ~5,000 requests. Verify CPU and Memory gauges on the dashboard remain stable, database file size is monitored, and Chart.js animations stay responsive.

---

## 5. Deployment & Production Hardening Guidelines

To deploy **SecurIDS** in a production environment, implement the following hardening guidelines:

1. **Production WSGI Server**: Do not run `python app.py` (which uses the development Flask server) in production. Instead, package the app using `gunicorn` (Linux) or `waitress` (Windows):
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```
2. **Reverse Proxy Configuration (Nginx/IIS)**:
   * Run the app behind a reverse proxy. Configure Nginx to forward the client's actual IP using `X-Forwarded-For`.
   * **Crucial Security Action**: Disable `app.config['SIMULATION_MODE'] = False` in production to prevent clients from spoofing their IP address using arbitrary request headers!
3. **Database Server**: Replace the SQLite database file (`ids.db`) with a robust database server like PostgreSQL or MySQL to support concurrent writes under heavy traffic volumes.
4. **TLS/HTTPS Enforcement**: Serve all routes over secure HTTPS. Force administrative dashboard paths to require strong authentication (e.g. HTTP Basic Auth or session login tokens) rather than raw open routes.
5. **Log Rotation**: Implement log rotation policies (`logrotate`) on `requests.log` and `attacks.log` to prevent server disk space exhaustion.
