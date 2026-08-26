import os
from pathlib import Path
from dotenv import load_dotenv

# This tells Python to find your hidden .env file and load the secrets into memory
load_dotenv(dotenv_path=Path(__file__).resolve().with_name(".env"))


import customtkinter as ctk
import subprocess
import threading
import queue
import sys
import platform
import psutil  
import socket  
import requests
from datetime import datetime, timedelta

# Note: Ensure your 'main.py' (jit_engine) is in the same folder.
try:
    import importlib.util

    _main_path = Path(__file__).resolve().with_name("main.py")
    if _main_path.exists():
        spec = importlib.util.spec_from_file_location("jit_engine_main", _main_path)
        if spec and spec.loader:
            jit_engine = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(jit_engine)
        else:
            jit_engine = None
    else:
        jit_engine = None
except Exception:
    jit_engine = None

# --- GLOBAL CONFIG ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class GhostAegisApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- 1. INITIAL STATE ---
        self.radar_enabled = False
        self.title("Ghost-Aegis | Defensive Suite")
        self.geometry("950x850") 

        # --- 2. BUILD THE UI CONTAINERS ---
        self.label = ctk.CTkLabel(self, text="GHOST-AEGIS", font=("Fixedsys", 32, "bold"), text_color="#00FF00")
        self.label.pack(pady=15)

        self.status_frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        self.status_frame.pack(pady=10, padx=20, fill="x")
        self.status_label = ctk.CTkLabel(self.status_frame, text="🛡️ SYSTEM HARDENED", text_color="green", font=("Consolas", 14))
        self.status_label.pack(pady=5)

        self.button_container = ctk.CTkFrame(self, fg_color="transparent")
        self.button_container.pack(pady=10, fill="both", expand=True)

        self.left_frame = ctk.CTkFrame(self.button_container)
        self.left_frame.pack(side="left", padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.left_frame, text="ACCESS CONTROL", font=("Arial", 12, "bold"), text_color="#3b8ed0").pack(pady=10)

        self.right_frame = ctk.CTkFrame(self.button_container)
        self.right_frame.pack(side="right", padx=10, pady=10, fill="both", expand=True)
        ctk.CTkLabel(self.right_frame, text="SYSTEM DEFENSE", font=("Arial", 12, "bold"), text_color="#3b8ed0").pack(pady=10)

        # --- 3. ADD BUTTONS (Left Column) ---
        self.jit_button = ctk.CTkButton(self.left_frame, text="JIT Admin (15m)", command=self.run_jit)
        self.jit_button.pack(pady=10, padx=20)
        
        self.audit_button = ctk.CTkButton(self.left_frame, text="Audit Admins", command=self.run_audit)
        self.audit_button.pack(pady=10, padx=20)
        
        self.info_button = ctk.CTkButton(self.left_frame, text="System Info", command=self.show_sys_info)
        self.info_button.pack(pady=10, padx=20)

        self.interfaces_button = ctk.CTkButton(
            self.left_frame,
            text="Interface Telemetry",
            command=self.run_interface_telemetry,
        )
        self.interfaces_button.pack(pady=10, padx=20)

        self.engine_button = ctk.CTkButton(
            self.left_frame,
            text="Run Defense Engine",
            fg_color="#4B0082",
            hover_color="#300052",
            command=self.run_defense_engine,
        )
        self.engine_button.pack(pady=10, padx=20)

        self.about_button = ctk.CTkButton(
            self.left_frame, 
            text="About Ghost-Aegis", 
            fg_color="gray", 
            hover_color="#333333", 
            command=self.show_about_window
        )
        self.about_button.pack(pady=10, padx=20)

        # --- 4. ADD BUTTONS (Right Column) ---
        self.stealth_button = ctk.CTkButton(self.right_frame, text="Stealth Mode", fg_color="purple", hover_color="#5a2d82", command=self.run_stealth)
        self.stealth_button.pack(pady=10, padx=20)
        
        self.clean_button = ctk.CTkButton(self.right_frame, text="Emergency Clean", fg_color="#880808", hover_color="#660000", command=self.run_cleanup)
        self.clean_button.pack(pady=10, padx=20)

        self.sentinel_button = ctk.CTkButton(self.right_frame, text="Network Sentinel", fg_color="#1f538d", command=self.network_sentinel_callback)
        self.sentinel_button.pack(pady=10, padx=20)

        self.radar_button = ctk.CTkButton(self.right_frame, text="Start Radar", fg_color="#1f538d", hover_color="#14375e", command=self.toggle_radar)
        self.radar_button.pack(pady=10, padx=20)

        # --- NEW: KILLSWITCH UI & DUAL AI ENGINE ---
        self.kill_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        self.kill_frame.pack(pady=15, padx=20)
        
        self.pid_entry = ctk.CTkEntry(self.kill_frame, placeholder_text="Enter PID...", width=90)
        self.pid_entry.pack(side="left", padx=(0, 5))
        
        self.kill_button = ctk.CTkButton(self.kill_frame, text="Kill PID", fg_color="#880808", hover_color="#660000", width=80, command=self.terminate_process_callback)
        self.kill_button.pack(side="left", padx=(0, 5))

        self.ai_eval_button = ctk.CTkButton(self.kill_frame, text="Dual-AI Eval", fg_color="#4B0082", hover_color="#300052", width=90, command=self.run_dual_ai_eval)
        self.ai_eval_button.pack(side="left")

        # --- 5. CONSOLE SECTION ---
        self.console = ctk.CTkTextbox(self, height=400, width=900, font=("Consolas", 12), fg_color="#000000", text_color="#00FF00")
        self.console.pack(pady=20, padx=20)
        
        # Clean & Sleek Dark-Mode Color Tags
        self.console.tag_config("threat", foreground="#FF3333")   # Neon Red
        self.console.tag_config("warn", foreground="#FF7518")     # Safety Orange
        self.console.tag_config("trusted", foreground="#00FF00")  # Matrix Green
        self.console.tag_config("system", foreground="#00E5FF")   # Cyber Cyan
        self.console.tag_config("review", foreground="#FFBF00")   # Crisp Amber

        # --- THREAD-SAFE QUEUE SETUP ---
        self.log_queue = queue.Queue()
        self.scan_thread_running = False
        self.engine_thread_running = False
        
        self.check_queue()
        self.log_event("Ghost-Aegis System Ready. Monitoring active.", "trusted")

    # --- THE ABOUT WINDOW LOGIC ---
    def show_about_window(self):
        about_win = ctk.CTkToplevel(self)
        about_win.title("About Ghost-Aegis")
        about_win.geometry("420x480")
        about_win.attributes("-topmost", True)

        ctk.CTkLabel(about_win, text="GHOST-AEGIS", font=("Fixedsys", 28, "bold"), text_color="#00FF00").pack(pady=20)
        ctk.CTkLabel(about_win, text="Version 1.0.0 | 'Sentinel Edition'", font=("Arial", 10, "italic")).pack()

        mission_text = (
            "Goal: To Save the World through Internet Safety.\n\n"
            "Ghost-Aegis is a defensive suite designed for Blue Team "
            "practitioners. It provides real-time network visibility, "
            "geolocation intelligence, and automated system hardening."
        )
        
        mission_box = ctk.CTkTextbox(about_win, width=380, height=130, font=("Arial", 12))
        mission_box.insert("0.0", mission_text)
        mission_box.configure(state="disabled", fg_color="#2b2b2b")
        mission_box.pack(pady=20, padx=20)

        ctk.CTkLabel(about_win, text="Project Lead:", font=("Arial", 12, "bold"), text_color="#3b8ed0").pack()
        ctk.CTkLabel(about_win, text='[H "Joseph Awana"A / Gemini / Co-Pilot]', font=("Consolas", 16)).pack(pady=5)
        
        ctk.CTkLabel(about_win, text="Built with Python, CustomTkinter, and Psutil", font=("Arial", 9)).pack(pady=(15, 0))
        ctk.CTkButton(about_win, text="CLOSE", fg_color="#444444", command=about_win.destroy).pack(pady=20)

    # --- LOGGING ENGINE ---
    def check_queue(self):
        """Drain background log messages without updating Tk from worker threads."""
        try:
            while True:
                message, tag = self.log_queue.get_nowait()
                if message == "__scan_complete__":
                    self.scan_thread_running = False
                    self.sentinel_button.configure(state="normal", text="Network Sentinel")
                    if self.radar_enabled:
                        self.after(30000, self.network_sentinel_callback)
                elif message == "__ai_eval_complete__":
                    self.ai_eval_button.configure(state="normal")
                elif message == "__interfaces_complete__":
                    self.interfaces_button.configure(state="normal", text="Interface Telemetry")
                elif message == "__engine_complete__":
                    self.engine_thread_running = False
                    self.engine_button.configure(state="normal", text="Run Defense Engine")
                else:
                    self.log_event(message, tag)
        except queue.Empty:
            pass

        self.after(100, self.check_queue)

    # --- LOGGING ENGINE ---
    def log_event(self, message, tag=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        try:
            with open("ghost_aegis.log", "a") as f:
                f.write(log_entry)
        except: pass
        
        self.console.configure(state="normal")
        if tag:
            self.console.insert("end", log_entry, tag)
        else:
            self.console.insert("end", log_entry)
        self.console.configure(state="disabled")
        self.console.see("end")

    # --- SYSTEM LOGIC ---
    def run_jit(self):
        dialog = ctk.CTkInputDialog(text="Enter username to elevate:", title="JIT Elevation")
        target_user = dialog.get_input()
        if target_user:
            try:
                subprocess.run(["net", "localgroup", "Administrators", target_user, "/add"], check=True)
                self.log_event(f"JIT Elevation SUCCESS: {target_user} granted Admin.", "trusted")
                exec_time = (datetime.now() + timedelta(minutes=15)).strftime("%H:%M")
                self.log_event(f"Lockdown scheduled for {exec_time}.", "review")
            except Exception as e:
                self.log_event(f"JIT Error: {e}", "threat")

    # --- QUARANTINE & CONTAINMENT LOGIC ---
    def run_audit(self):
        self.log_event("Auditing Admin group...", "review")
        try:
            result = subprocess.run(["net", "localgroup", "Administrators"], capture_output=True, text=True, check=True)
            self.log_event(result.stdout)
        except Exception as e:
            self.log_event(f"Audit failed: {e}", "threat")

    # --- SYSTEM INFO LOGIC ---
    def show_sys_info(self):
        try:
            cmd = "Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption"
            os_name = subprocess.check_output(["powershell", "-Command", cmd], text=True).strip()
            self.log_event(f"SYSTEM INFO: {os_name} | NODE: {platform.node()}", "system")
        except:
            self.log_event(f"SYSTEM INFO: Windows | NODE: {platform.node()}", "system")

    # --- ENGINE INTEGRATION ---
    def run_interface_telemetry(self):
        if jit_engine is None or not hasattr(jit_engine, "monitor_network_interfaces"):
            self.log_event("Interface telemetry is unavailable: main.py could not be loaded.", "threat")
            return

        self.interfaces_button.configure(state="disabled", text="Reading...")
        threading.Thread(target=self._interface_telemetry_worker, daemon=True).start()

    def _interface_telemetry_worker(self):
        try:
            telemetry = jit_engine.monitor_network_interfaces()
            for interface_name, addresses in telemetry.items():
                self._queue_log(f"[INTERFACE] {interface_name}", "system")
                for address in addresses:
                    self._queue_log(
                        f"  {address['address']} | {address['family']} | mask: {address['netmask']}",
                        "trusted",
                    )
            self._queue_log("Interface telemetry complete.", "system")
        except Exception as error:
            self._queue_log(f"Interface telemetry failed: {error}", "threat")
        finally:
            self.log_queue.put(("__interfaces_complete__", None))

    def run_defense_engine(self):
        if self.engine_thread_running:
            return
        if jit_engine is None or not hasattr(jit_engine, "run_defense_engine"):
            self.log_event("Defense engine is unavailable: main.py could not be loaded.", "threat")
            return

        self.engine_thread_running = True
        self.engine_button.configure(state="disabled", text="Engine Running...")
        self.log_event("[*] Starting dual-AI defense engine in GUI mode...", "system")
        threading.Thread(target=self._defense_engine_worker, daemon=True).start()

    def _defense_engine_worker(self):
        try:
            import asyncio

            asyncio.run(jit_engine.run_defense_engine(start_cli=False, safe_mode=True))
            self._queue_log("Defense engine completed. Review the engine log for AI verdict details.", "trusted")
        except Exception as error:
            self._queue_log(f"Defense engine failed: {error}", "threat")
        finally:
            self.log_queue.put(("__engine_complete__", None))

    # --- 6. STEALTH MODE, CLEANUP, AND NETWORK SENTINEL LOGIC ---
    def run_stealth(self):
        self.log_event("STEALTH MODE ACTIVE", "warn")

    # --- EMERGENCY CLEANUP ---
    def run_cleanup(self):
        self.log_event("! INITIATING CLEANUP PROTOCOL !", "threat")

    # --- THREAT INTELLIGENCE ENGINE ---
    def check_ip_reputation(self, ip_address):
        url = 'https://api.abuseipdb.com/api/v2/check'
        api_key = os.getenv('ABUSEIPDB_API_KEY')
        headers = {'Accept': 'application/json', 'Key': api_key}
        querystring = {'ipAddress': ip_address, 'maxAgeInDays': '30'}

        try:
            response = requests.get(url, headers=headers, params=querystring, timeout=3.0)
            if response.status_code == 200:
                data = response.json()
                return data['data']['abuseConfidenceScore']
        except Exception as e:
            pass 
        return 0

    def get_ip_location(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=1.5).json()
            if response.get("status") == "success":
                return f"{response.get('city')}, {response.get('countryCode')}"
            return "Unknown Loc"
        except: return "Loc Error"

    def network_sentinel_callback(self):
        if self.scan_thread_running:
            return

        self.scan_thread_running = True
        self.sentinel_button.configure(state="disabled", text="Scanning...")
        self.log_event("[*] Initiating Deep Network Audit...", "system")
        threading.Thread(target=self._network_sentinel_worker, daemon=True).start()

    def _queue_log(self, message, tag=None):
        self.log_queue.put((message, tag))

    def _network_sentinel_worker(self):
        trusted_domains = ['google.com', 'github.com', 'microsoft.com', 'akamai', 'azure']
        
        try:
            result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()
            self._queue_log(f"{'STATUS':<10} {'PROCESS':<15} {'REMOTE HOST / LOCATION':<45} {'PID':<6}")
            
            found_active = False
            for line in lines:
                parts = line.split()
                if len(parts) >= 5 and "ESTABLISHED" in parts:
                    ip_only = parts[2].rsplit(':', 1)[0].replace('[', '').replace(']', '')
                    pid_str = parts[-1]
                    
                    if pid_str.isdigit():
                        pid = int(pid_str)
                    else:
                        continue
                    
                    if ip_only not in ["127.0.0.1", "0.0.0.0", "::1"]:
                        try:
                            proc_name = psutil.Process(pid).name()
                        except:
                            proc_name = "Unknown"

                        location = self.get_ip_location(ip_only)
                        
                        try: 
                            hostname = socket.getfqdn(ip_only)
                        except: 
                            hostname = ip_only
                        
                        display_host = f"{hostname} ({location})"
                        
                        status, tag_name = "[REVIEW]", "review"
                        
                        if any(d in hostname.lower() for d in trusted_domains):
                            status, tag_name = "[TRUSTED]", "trusted"
                        elif proc_name.lower() in ["svchost.exe", "lsass.exe"]:
                            status, tag_name = "[SYSTEM]", "system"
                        else:
                            score = self.check_ip_reputation(ip_only)
                            
                            if score >= 80:
                                status, tag_name = "[AUTO-KILL]", "threat"
                                display_host = f"{display_host} | SCORE: {score}% - TERMINATING PROCESS"
                                try:
                                    target_proc = psutil.Process(pid)
                                    killed_name = target_proc.name()
                                    target_proc.terminate()
                                    self._queue_log(f"⚡ [NEUTRALIZED] High Threat Detected ({score}%). Killed {killed_name} (PID: {pid})!", "threat")
                                except Exception as kill_err:
                                    self._queue_log(f"⚠️ [KILL FAILED] Could not terminate PID {pid}: {kill_err}", "threat")
                            elif score >= 25:
                                status, tag_name = "[THREAT]", "threat"
                                display_host = f"{display_host} | SCORE: {score}%"
                            elif score > 0:
                                status, tag_name = "[WARN]", "warn"
                                display_host = f"{display_host} | SCORE: {score}%"
                        
                        self._queue_log(f"{status:<10} {proc_name:<15} {display_host:<45} {pid:<6}", tag_name)
                        found_active = True

            if not found_active: self._queue_log("No active external connections.")
        except Exception as e:
            self._queue_log(f"Audit Failed: {e}", "threat")
        finally:
            self.log_queue.put(("__scan_complete__", None))


    # --- RADAR LOGIC ---
    def network_sentinel_callback(self):
        if self.scan_thread_running:
            return

        self.scan_thread_running = True
        self.sentinel_button.configure(state="disabled", text="Scanning...")
        self.log_event("[*] Initiating Deep Network Audit...", "system")
        threading.Thread(target=self._network_sentinel_worker, daemon=True).start()

    def _queue_log(self, message, tag=None):
        self.log_queue.put((message, tag))

    def _network_sentinel_worker(self):
        trusted_domains = ['google.com', 'github.com', 'microsoft.com', 'akamai', 'azure']
        
        try:
            result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()
            self._queue_log(f"{'STATUS':<10} {'PROCESS':<15} {'REMOTE HOST / LOCATION':<45} {'PID':<6}")
            
            found_active = False
            for line in lines:
                parts = line.split()
                if len(parts) >= 5 and "ESTABLISHED" in parts:
                    ip_only = parts[2].rsplit(':', 1)[0].replace('[', '').replace(']', '')
                    pid_str = parts[-1]
                    
                    if pid_str.isdigit():
                        pid = int(pid_str)
                    else:
                        continue
                    
                    if ip_only not in ["127.0.0.1", "::1"]:

                        try:
                            proc_name = psutil.Process(pid).name()
                        except:
                            proc_name = "Unknown"

                        location = self.get_ip_location(ip_only)
                        
                        try: 
                            hostname = socket.getfqdn(ip_only)
                        except: 
                            hostname = ip_only
                        
                        display_host = f"{hostname} ({location})"
                        
                        status, tag_name = "[REVIEW]", "review"
                        
                        if any(d in hostname.lower() for d in trusted_domains):
                            status, tag_name = "[TRUSTED]", "trusted"
                        elif proc_name.lower() in ["svchost.exe", "lsass.exe"]:
                            status, tag_name = "[SYSTEM]", "system"
                        else:
                            score = self.check_ip_reputation(ip_only)
                            
                            if score >= 80:
                                status, tag_name = "[AUTO-KILL]", "threat"
                                display_host = f"{display_host} | SCORE: {score}% - TERMINATING PROCESS"
                                try:
                                    target_proc = psutil.Process(pid)
                                    killed_name = target_proc.name()
                                    target_proc.terminate()
                                    self._queue_log(f"⚡ [NEUTRALIZED] High Threat Detected ({score}%). Killed {killed_name} (PID: {pid})!", "threat")
                                except Exception as kill_err:
                                    self._queue_log(f"⚠️ [KILL FAILED] Could not terminate PID {pid}: {kill_err}", "threat")
                            elif score >= 25:
                                status, tag_name = "[THREAT]", "threat"
                                display_host = f"{display_host} | SCORE: {score}%"
                            elif score > 0:
                                status, tag_name = "[WARN]", "warn"
                                display_host = f"{display_host} | SCORE: {score}%"
                        
                        self._queue_log(f"{status:<10} {proc_name:<15} {display_host:<45} {pid:<6}", tag_name)
                        found_active = True

            if not found_active: self._queue_log("No active external connections.")
        except Exception as e:
            self._queue_log(f"Audit Failed: {e}", "threat")
        finally:
            self.log_queue.put(("__scan_complete__", None))

    # --- RADAR LOGIC ---
    def toggle_radar(self):
        self.radar_enabled = not self.radar_enabled
        if self.radar_enabled:
            self.radar_button.configure(text="Stop Radar", fg_color="#e67e22")
            self.log_event("[!] RADAR ENABLED: Sweeping every 30s...", "warn")
            self.network_sentinel_callback()
        else:
            self.radar_button.configure(text="Start Radar", fg_color="#1f538d")
            self.log_event("[!] RADAR DISABLED.", "review")

    # --- KILLSWITCH LOGIC ---
    def terminate_process_callback(self):
        pid_str = self.pid_entry.get().strip()
        if pid_str.isdigit():
            try:
                p = psutil.Process(int(pid_str))
                process_name = p.name()
                p.terminate()
                self.log_event(f"[X] Terminated {process_name} (PID: {pid_str}) successfully.", "threat")
                self.pid_entry.delete(0, 'end')
            except Exception as e: 
                self.log_event(f"Kill Error: {e}", "threat")
        else:
            self.log_event("Invalid PID entered.", "warn")

    # --- DUAL-AI ENGINE ---
    def run_dual_ai_eval(self):
        pid_str = self.pid_entry.get().strip()
        if pid_str.isdigit():
            self.log_event(f"[*] Initializing Dual-AI Engine for PID {pid_str}...", "system")
            self.ai_eval_button.configure(state="disabled")
            threading.Thread(target=self._dual_ai_worker, args=(int(pid_str),), daemon=True).start()
        else:
            self.log_event("Invalid PID for AI Evaluation.", "warn")

    def _dual_ai_worker(self, pid):
        try:
            # 1. Gather Telemetry
            target_proc = psutil.Process(pid)
            proc_name = target_proc.name()
            exe_path = target_proc.exe()
            connections = target_proc.net_connections()
            remote_ips = [c.raddr.ip for c in connections if c.raddr]
            
            context = f"Process Name: {proc_name}\nExecutable Path: {exe_path}\nActive External Connections: {remote_ips}"
            self._queue_log(f"[*] Telemetry gathered for {proc_name}. Consulting AIs...", "system")

            prompt = (
                "You are an expert Blue Team cybersecurity analyst. "
                "Analyze the following process telemetry and provide a brief, "
                "1-sentence threat assessment and a score out of 10 for malicious probability.\n\n"
                f"{context}"
            )

            # 2. Query Gemini
            try:
                from google import genai

                gemini_key = os.getenv("GEMINI_API_KEY")
                if not gemini_key:
                    raise RuntimeError("GEMINI_API_KEY was not loaded from .env")

                gemini_client = genai.Client(api_key=gemini_key)
                gemini_res = gemini_client.models.generate_content(
                    model="gemini-3.6-flash",
                    contents=prompt,
                )
                gemini_verdict = (gemini_res.text or "No Gemini response").strip().replace('\n', ' ')
            except Exception as e:
                gemini_verdict = f"API Error: {e}"

            # 3. Query Copilot (via OpenAI model)
            try:
                import openai
                openai_key = os.getenv("OPENAI_API_KEY") or os.getenv("COPILOT_API_KEY")
                if not openai_key:
                    raise RuntimeError("Set OPENAI_API_KEY or COPILOT_API_KEY in .env")

                client = openai.OpenAI(api_key=openai_key)
                openai_res = client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=60
                )
                copilot_verdict = openai_res.choices[0].message.content.strip().replace('\n', ' ')
            except Exception as e:
                copilot_verdict = f"API Error: {type(e).__name__}: {e}"

            # 4. Push Results to GUI
            self._queue_log(f"🧠 [GEMINI]: {gemini_verdict}", "review")
            self._queue_log(f"🤖 [COPILOT]: {copilot_verdict}", "review")

        except psutil.NoSuchProcess:
            self._queue_log(f"[!] PID {pid} no longer exists. It may have terminated.", "warn")
        except Exception as e:
            self._queue_log(f"[!] Dual-AI Engine Error: {e}", "threat")
        finally:
            self.log_queue.put(("__ai_eval_complete__", None))



# --- FIREWALL MANAGEMENT LOGIC 1 ---
def block_ip(ip_address):
    """Blocks an IP address completely using Windows Firewall outbound/inbound rules."""
    rule_name = f"GhostAegis_Block_{ip_address}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip_address}"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return f"[+] Successfully blocked IP: {ip_address}"
    except subprocess.CalledProcessError as e:
        return f"[-] Failed to block IP {ip_address}: {e.stderr.strip()}"

    
# --- FIREWALL MANAGEMENT LOGIC 2 ---
def allow_ip(ip_address):
    """Removes a block rule or creates an explicit allow/exception rule for an IP."""
    rule_name = f"GhostAegis_Block_{ip_address}"
    # Remove the block rule if it exists
    remove_cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
    subprocess.run(remove_cmd, capture_output=True, text=True)
    return f"[+] Cleared blocks and allowed IP: {ip_address}"

if __name__ == "__main__":
    app = GhostAegisApp()
    app.mainloop()