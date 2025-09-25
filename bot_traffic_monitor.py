import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import defaultdict
import time
import threading
import socket
import struct
import re
import psutil
import random
import requests
from urllib.parse import urlparse

root = tk.Tk()
root.title("Bot Traffic Dashboard")
root.geometry("1000x700")

# Real traffic data
traffic_data = []  # (timestamp, ip, user_agent, bot_flag, request_size, response_time)
ip_requests = defaultdict(int)
ua_requests = defaultdict(int)
bot_over_time = []
packet_capture_active = False
capture_thread = None

# Bot detection patterns (using simple string matching instead of regex)
BOT_USER_AGENTS = [
    'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python',
    'requests', 'urllib', 'httpie', 'postman', 'insomnia', 'automated',
    'headless', 'phantom', 'selenium', 'puppeteer'
]

LEGITIMATE_BOTS = [
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
    'yandexbot', 'facebookexternalhit', 'twitterbot', 'linkedinbot'
]

def is_bot_user_agent(user_agent):
    """Detect if user agent indicates a bot"""
    if not user_agent:
        return True  # No user agent is suspicious
    
    ua_lower = user_agent.lower()
    
    # Check for legitimate bots first
    for pattern in LEGITIMATE_BOTS:
        if pattern in ua_lower:
            return False  # Legitimate bot, not malicious
    
    # Check for bot patterns
    for pattern in BOT_USER_AGENTS:
        if pattern in ua_lower:
            return True
    
    return False

def analyze_request_patterns(ip):
    """Analyze request patterns to detect bot behavior"""
    ip_traffic = [entry for entry in traffic_data if entry[1] == ip]
    
    if len(ip_traffic) < 5:
        return False
    
    # Check request frequency (more than 10 requests per minute)
    recent_requests = [entry for entry in ip_traffic if time.time() - entry[0] < 60]
    if len(recent_requests) > 10:
        return True
    
    # Check for consistent timing patterns (too regular)
    timestamps = [entry[0] for entry in ip_traffic[-10:]]
    if len(timestamps) >= 3:
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)
        # If requests are too regular (within 0.5 seconds of average), likely bot
        regular_count = sum(1 for interval in intervals if abs(interval - avg_interval) < 0.5)
        if regular_count / len(intervals) > 0.8:
            return True
    
    return False

# Real-world traffic simulation data
REAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0"
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
    "python-urllib3/1.26.12",
    "Go-http-client/1.1",
    "Apache-HttpClient/4.5.13 (Java/11.0.16)"
]

SUSPICIOUS_IPS = [
    "185.220.101.32", "198.98.51.189", "45.148.10.85", "192.42.116.16",
    "23.129.64.214", "185.220.102.8", "199.87.154.255", "45.79.85.112"
]

def generate_realistic_ip():
    """Generate realistic IP addresses"""
    # Mix of legitimate and suspicious IPs
    if random.random() < 0.1:  # 10% suspicious IPs
        return random.choice(SUSPICIOUS_IPS)
    else:
        # Generate normal-looking IPs
        return f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

def simulate_traffic_generator():
    """Generate realistic traffic patterns"""
    global traffic_data, ip_requests, ua_requests, bot_over_time
    
    while packet_capture_active:
        timestamp = time.time()
        
        # Determine if this will be bot traffic (30% chance)
        is_bot_traffic = random.random() < 0.3
        
        if is_bot_traffic:
            user_agent = random.choice(BOT_USER_AGENTS)
            # Bots often come from suspicious IPs or make many requests
            if random.random() < 0.4:
                src_ip = random.choice(SUSPICIOUS_IPS)
            else:
                src_ip = generate_realistic_ip()
        else:
            user_agent = random.choice(REAL_USER_AGENTS)
            src_ip = generate_realistic_ip()
        
        # Generate realistic request sizes
        if is_bot_traffic:
            request_size = random.randint(200, 800)  # Bots typically smaller requests
        else:
            request_size = random.randint(500, 3000)  # Human requests vary more
        
        # Detect if this is bot traffic using our algorithms
        is_bot_ua = is_bot_user_agent(user_agent)
        is_bot_pattern = analyze_request_patterns(src_ip)
        is_bot = is_bot_ua or is_bot_pattern
        
        # Store traffic data
        traffic_data.append((timestamp, src_ip, user_agent, int(is_bot), request_size, 0))
        ip_requests[src_ip] += 1
        ua_requests[user_agent] += 1
        bot_over_time.append((timestamp, int(is_bot)))
        
        # Keep only last 1000 entries to prevent memory issues
        if len(traffic_data) > 1000:
            traffic_data = traffic_data[-1000:]
            bot_over_time = bot_over_time[-1000:]
        
        # Update GUI in main thread
        root.after(0, update_display)
        
        # Realistic timing - bots are faster, humans are slower
        if is_bot_traffic:
            time.sleep(random.uniform(0.1, 2.0))  # Bots: 0.1-2 seconds
        else:
            time.sleep(random.uniform(1.0, 10.0))  # Humans: 1-10 seconds

def start_packet_capture(interface=None):
    """Start traffic monitoring simulation"""
    global packet_capture_active, capture_thread
    
    if packet_capture_active:
        return
    
    packet_capture_active = True
    print(f"Starting traffic monitoring simulation...")
    
    capture_thread = threading.Thread(target=simulate_traffic_generator, daemon=True)
    capture_thread.start()

def stop_packet_capture():
    """Stop packet capture"""
    global packet_capture_active
    packet_capture_active = False

# GUI Components
frame_top = tk.Frame(root)
frame_top.pack(side=tk.TOP, fill=tk.X, pady=5)

tk.Label(frame_top, text="Real-World Traffic Simulation", font=("Arial", 14, "bold")).pack(side=tk.LEFT, padx=5)

# Control buttons
start_btn = tk.Button(frame_top, text="Start Monitoring", command=lambda: start_packet_capture(), 
                     bg="green", fg="white", font=("Arial", 10, "bold"))
start_btn.pack(side=tk.LEFT, padx=10)

stop_btn = tk.Button(frame_top, text="Stop Monitoring", command=stop_packet_capture,
                    bg="red", fg="white", font=("Arial", 10, "bold"))
stop_btn.pack(side=tk.LEFT, padx=5)

# Status label
status_label = tk.Label(frame_top, text="Status: Stopped", fg="red", font=("Arial", 12, "bold"))
status_label.pack(side=tk.LEFT, padx=15)

# Info label
info_label = tk.Label(frame_top, text="Simulating realistic web traffic patterns", 
                     fg="gray", font=("Arial", 9))
info_label.pack(side=tk.RIGHT, padx=10)

# Table of detected bots
frame_table = tk.Frame(root)
frame_table.pack(side=tk.LEFT, fill=tk.Y, padx=5)

tk.Label(frame_table, text="Detected Bot Traffic", font=("Arial", 12, "bold")).pack(pady=5)

cols = ("IP", "User-Agent", "Requests", "Bot Score")
tree = ttk.Treeview(frame_table, columns=cols, show="headings", height=15)
for col in cols:
    tree.heading(col, text=col)
    tree.column(col, width=120)
tree.pack(fill=tk.Y, expand=True)

# Scrollbar for table
scrollbar = ttk.Scrollbar(frame_table, orient="vertical", command=tree.yview)
scrollbar.pack(side="right", fill="y")
tree.configure(yscrollcommand=scrollbar.set)

# Charts
frame_charts = tk.Frame(root)
frame_charts.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

fig, axs = plt.subplots(2,2, figsize=(8,6))
plt.subplots_adjust(hspace=0.4, wspace=0.3)

canvas = FigureCanvasTkAgg(fig, master=frame_charts)
canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def update_display():
    """Update the GUI display with current traffic data"""
    global status_label, tree, canvas, fig, axs
    
    # Update status
    if packet_capture_active:
        status_label.config(text="Status: Monitoring Active", fg="green")
    else:
        status_label.config(text="Status: Stopped", fg="red")
    
    # Clear existing tree data
    for item in tree.get_children():
        tree.delete(item)
    
    # Update table with bot traffic
    bot_ips = {}
    for entry in traffic_data:
        timestamp, ip, user_agent, is_bot, request_size, response_time = entry
        if is_bot:
            if ip not in bot_ips:
                bot_ips[ip] = {'ua': user_agent, 'count': 0, 'score': 0}
            bot_ips[ip]['count'] += 1
            # Calculate bot score based on various factors
            score = 0
            if is_bot_user_agent(user_agent):
                score += 50
            if analyze_request_patterns(ip):
                score += 30
            if ip_requests[ip] > 20:
                score += 20
            bot_ips[ip]['score'] = min(100, score)
    
    # Insert bot data into table
    for ip, data in sorted(bot_ips.items(), key=lambda x: x[1]['score'], reverse=True):
        tree.insert("", "end", values=(ip, data['ua'][:30] + "..." if len(data['ua']) > 30 else data['ua'], 
                                     data['count'], f"{data['score']}%"))
    
    # Update charts
    if traffic_data:
        # Clear all subplots
        for ax in axs.flat:
            ax.clear()
        
        # Chart 1: Top IPs by request count
        top_ips = dict(sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)[:10])
        if top_ips:
            axs[0,0].bar(range(len(top_ips)), list(top_ips.values()), color='tomato')
            axs[0,0].set_title("Top IPs by Requests")
            axs[0,0].set_xticks(range(len(top_ips)))
            axs[0,0].set_xticklabels([ip.split('.')[-1] for ip in top_ips.keys()], rotation=45)
        
        # Chart 2: Bot vs Normal Traffic
        bot_count = sum(1 for entry in traffic_data if entry[3] == 1)
        normal_count = len(traffic_data) - bot_count
        if bot_count > 0 or normal_count > 0:
            axs[0,1].pie([bot_count, normal_count], labels=["Bot","Normal"], colors=['red','green'],
                        autopct='%1.1f%%', startangle=90)
            axs[0,1].set_title("Bot vs Normal Traffic")
        
        # Chart 3: Bot activity over time (last 50 entries)
        recent_bot_data = bot_over_time[-50:] if len(bot_over_time) > 50 else bot_over_time
        if recent_bot_data:
            times = [i for i in range(len(recent_bot_data))]
            bots = [entry[1] for entry in recent_bot_data]
            axs[1,0].plot(times, bots, marker='o', linestyle='-', color='blue', markersize=3)
            axs[1,0].set_title("Bot Activity Over Time")
            axs[1,0].set_ylabel("Bot Detected")
            axs[1,0].set_xlabel("Request Sequence")
        
        # Chart 4: Request size distribution
        request_sizes = [entry[4] for entry in traffic_data if entry[4] > 0]
        if request_sizes:
            axs[1,1].hist(request_sizes, bins=20, color='skyblue', alpha=0.7)
            axs[1,1].set_title("Request Size Distribution")
            axs[1,1].set_xlabel("Request Size (bytes)")
            axs[1,1].set_ylabel("Frequency")
        
        canvas.draw()

def update_status():
    """Update status and charts periodically"""
    update_display()
    root.after(2000, update_status)  # Update every 2 seconds

# Start periodic updates
root.after(1000, update_status)

# Initial display update
update_display()

root.mainloop()

