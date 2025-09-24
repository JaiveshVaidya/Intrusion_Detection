import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import defaultdict
import random
import time

root = tk.Tk()
root.title("Bot Traffic Dashboard")
root.geometry("1000x700")

# Simulated traffic data
traffic_data = []  # (timestamp, ip, user_agent, bot_flag)
ip_requests = defaultdict(int)
ua_requests = defaultdict(int)
bot_over_time = []

# Simulate traffic
user_agents = ["Mozilla/5.0", "Googlebot/2.1", "Bingbot/2.0", "curl/7.68", "PostmanRuntime/7.28"]
ips = [f"192.168.1.{i}" for i in range(1,21)]

for _ in range(200):
    ts = time.time()
    ip = random.choice(ips)
    ua = random.choice(user_agents)
    bot = random.choice([0,1])  # 1 = bot
    traffic_data.append((ts, ip, ua, bot))
    ip_requests[ip] += 1
    ua_requests[ua] += 1
    bot_over_time.append((ts, bot))

# GUI Components
frame_top = tk.Frame(root)
frame_top.pack(side=tk.TOP, fill=tk.X, pady=5)

tk.Label(frame_top, text="Website URL:").pack(side=tk.LEFT, padx=5)
url_entry = tk.Entry(frame_top, width=50)
url_entry.pack(side=tk.LEFT, padx=5)
tk.Button(frame_top, text="Start Detection").pack(side=tk.LEFT, padx=5)

# Table of detected bots
frame_table = tk.Frame(root)
frame_table.pack(side=tk.LEFT, fill=tk.Y, padx=5)

cols = ("IP", "User-Agent", "Requests")
tree = ttk.Treeview(frame_table, columns=cols, show="headings")
for col in cols:
    tree.heading(col, text=col)
tree.pack(fill=tk.Y, expand=True)

# Insert simulated bot data into table
for ip in ip_requests:
    ua = random.choice(user_agents)
    tree.insert("", "end", values=(ip, ua, ip_requests[ip]))

# Charts
frame_charts = tk.Frame(root)
frame_charts.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

fig, axs = plt.subplots(2,2, figsize=(8,6))
plt.subplots_adjust(hspace=0.4)

# Chart 1: Requests per IP
axs[0,0].bar(ip_requests.keys(), ip_requests.values(), color='tomato')
axs[0,0].set_title("Requests per IP")
axs[0,0].tick_params(axis='x', rotation=45)

# Chart 2: Requests per User-Agent
axs[0,1].pie(ua_requests.values(), labels=ua_requests.keys(), autopct='%1.1f%%', startangle=140)
axs[0,1].set_title("Requests per User-Agent")

# Chart 3: Bot activity over time
times = [t[0] for t in bot_over_time]
bots = [t[1] for t in bot_over_time]
axs[1,0].plot(times, bots, marker='o', linestyle='-', color='blue')
axs[1,0].set_title("Bot Activity Over Time")

# Chart 4: Bot vs Normal Traffic (donut)
bot_count = sum(bots)
normal_count = len(bots)-bot_count
axs[1,1].pie([bot_count, normal_count], labels=["Bot","Normal"], colors=['red','green'],
             autopct='%1.1f%%', startangle=90, wedgeprops={'width':0.3})
axs[1,1].set_title("Bot vs Normal Traffic")

canvas = FigureCanvasTkAgg(fig, master=frame_charts)
canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
canvas.draw()

root.mainloop()
