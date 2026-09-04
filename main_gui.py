import os
import sys
import ctypes
import platform
import subprocess
import threading
import queue
import socket
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timedelta
import psutil
import customtkinter as ctk
from tkinter import filedialog
from dotenv import load_dotenv
from incident_store import (
    Incident,
    append_incident,
    calculate_risk,
    build_attack_story,
    export_incident_report,
    get_authenticode_signer,
    load_incidents,
)
from persistence_audit import collect_persistence_entries
from canary_guard import CanaryGuard
from network_behavior import NetworkBehaviorStore

# Load environment secrets
load_dotenv(dotenv_path=Path(__file__).resolve().with_name(".env"))

# Dynamic import of main.py (Defense Engine)
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

# --- GLOBAL CONFIG & STYLES ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# --- BLUE TEAM TELEMETRY HELPERS ---
def get_file_sha256(filepath: str) -> str:
    """Computes SHA-256 hash of an executable binary for reputation checking."""
    if not filepath or not os.path.exists(filepath):
        return "N/A"
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return "Access Denied"


def is_suspicious_path(filepath: str) -> bool:
    """Flags binaries executing from typical malware staging paths."""
    if not filepath:
        return False
    suspicious_dirs = [
        r"\appdata\local\temp",
        r"\users\public",
        r"\programdata\temp",
        r"\windows\temp",
    ]
    path_lower = filepath.lower()
    return any(s_dir in path_lower for s_dir in suspicious_dirs)


def block_ip(ip_address: str) -> str:
    """Blocks an IP address using Windows Firewall outbound rules."""
    rule_name = f"GhostAegis_Block_{ip_address}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip_address}"
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        return f"[+] Successfully firewalled IP: {ip_address}"
    except subprocess.CalledProcessError as e:
        return f"[-] Failed to block IP {ip_address}: {e.stderr.strip()}"


def allow_ip(ip_address: str) -> str:
    """Removes an active firewall block rule for a given IP."""
    rule_name = f"GhostAegis_Block_{ip_address}"
    remove_cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
    try:
        result = subprocess.run(
            remove_cmd, capture_output=True, text=True, check=False,
        )
        if result.returncode == 0:
            return f"[+] Cleared firewall block for IP: {ip_address}"
        error = result.stderr.strip() or result.stdout.strip() or "unknown error"
        return f"[-] Failed to clear firewall block for IP {ip_address}: {error}"
    except OSError as error:
        return f"[-] Failed to clear firewall block for IP {ip_address}: {error}"


class GhostAegisApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- 1. INITIAL STATE ---
        self.radar_enabled = False
        self.host_isolated = False
        self.canary_enabled = False
        self.canary_guard = CanaryGuard()
        self.network_behavior = NetworkBehaviorStore()
        self.title("Ghost-Aegis | Defensive Suite SE")
        self.geometry("980x880")

        # --- 2. BUILD THE UI CONTAINERS ---
        self.label = ctk.CTkLabel(
            self,
            text="GHOST-AEGIS",
            font=("Fixedsys", 32, "bold"),
            text_color="#00FF00"
        )
        self.label.pack(pady=15)

        self.status_frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        self.status_frame.pack(pady=5, padx=20, fill="x")
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="🛡️ SYSTEM HARDENED & MONITORED",
            text_color="#00FF00",
            font=("Consolas", 14, "bold")
        )
        self.status_label.pack(pady=5)

        self.button_container = ctk.CTkFrame(self, fg_color="transparent")
        self.button_container.pack(pady=10, fill="both", expand=True)

        # Left Column: Access Control & System Metrics
        self.left_frame = ctk.CTkFrame(self.button_container)
        self.left_frame.pack(side="left", padx=10, pady=5, fill="both", expand=True)
        ctk.CTkLabel(
            self.left_frame,
            text="ACCESS CONTROL & ENGINES",
            font=("Arial", 12, "bold"),
            text_color="#3b8ed0"
        ).pack(pady=10)

        # Right Column: System Defense & Containment
        self.right_frame = ctk.CTkFrame(self.button_container)
        self.right_frame.pack(side="right", padx=10, pady=5, fill="both", expand=True)
        ctk.CTkLabel(
            self.right_frame,
            text="CONTAINMENT & NETWORK SENTINEL",
            font=("Arial", 12, "bold"),
            text_color="#3b8ed0"
        ).pack(pady=10)

        # --- 3. ACCESS CONTROL BUTTONS (Left Column) ---
        self._add_panel_section(self.left_frame, "IDENTITY & ACCESS")
        self.jit_button = ctk.CTkButton(
            self.left_frame, text="JIT Admin (15m Auto-Demote)",
            width=280, command=self.run_jit,
        )
        self.jit_button.pack(pady=4, padx=20)

        self.audit_button = ctk.CTkButton(
            self.left_frame, text="Audit Admins", width=280, command=self.run_audit,
        )
        self.audit_button.pack(pady=4, padx=20)

        self.info_button = ctk.CTkButton(
            self.left_frame, text="System Architecture", width=280, command=self.show_sys_info,
        )
        self.info_button.pack(pady=4, padx=20)

        self._add_panel_section(self.left_frame, "TELEMETRY & REVIEW")

        self.interfaces_button = ctk.CTkButton(
            self.left_frame,
            text="Interface Telemetry",
            width=280,
            command=self.run_interface_telemetry,
        )
        self.interfaces_button.pack(pady=4, padx=20)

        self.incidents_button = ctk.CTkButton(
            self.left_frame,
            text="View Incident Evidence",
            width=280,
            command=self.show_incidents_window,
        )
        self.incidents_button.pack(pady=4, padx=20)

        self.report_button = ctk.CTkButton(
            self.left_frame,
            text="Export Investigation Report",
            width=280,
            command=self.export_report,
        )
        self.report_button.pack(pady=4, padx=20)

        self.persistence_button = ctk.CTkButton(
            self.left_frame,
            text="Audit Persistence",
            width=280,
            command=self.run_persistence_audit,
        )
        self.persistence_button.pack(pady=4, padx=20)

        self.readiness_button = ctk.CTkButton(
            self.left_frame,
            text="System Readiness Check",
            width=280,
            command=self.run_readiness_check,
        )
        self.readiness_button.pack(pady=4, padx=20)

        self._add_panel_section(self.left_frame, "ACTIVE PROTECTION")

        self.canary_button = ctk.CTkButton(
            self.left_frame,
            text="Start Canary Shield",
            width=280,
            fg_color="#1f538d",
            hover_color="#14375e",
            command=self.toggle_canary_shield,
        )
        self.canary_button.pack(pady=4, padx=20)

        self.engine_button = ctk.CTkButton(
            self.left_frame,
            text="Launch Defense Engine",
            width=280,
            fg_color="#4B0082",
            hover_color="#300052",
            command=self.run_defense_engine,
        )
        self.engine_button.pack(pady=4, padx=20)

        self.about_button = ctk.CTkButton(
            self.left_frame,
            text="About Ghost-Aegis",
            width=280,
            fg_color="gray",
            hover_color="#333333",
            command=self.show_about_window
        )
        self.about_button.pack(pady=4, padx=20)

        # --- 4. SYSTEM DEFENSE BUTTONS (Right Column) ---
        self._add_panel_section(self.right_frame, "CONTAINMENT")
        self.stealth_button = ctk.CTkButton(
            self.right_frame,
            text="Stealth Mode (Drop ICMP)",
            width=280,
            fg_color="purple",
            hover_color="#5a2d82",
            command=self.run_stealth
        )
        self.stealth_button.pack(pady=4, padx=20)

        self.clean_button = ctk.CTkButton(
            self.right_frame,
            text="Emergency Clean (DNS/ARP)",
            width=280,
            fg_color="#880808",
            hover_color="#660000",
            command=self.run_cleanup
        )
        self.clean_button.pack(pady=4, padx=20)

        self.isolate_button = ctk.CTkButton(
            self.right_frame,
            text="Host Isolation (Air-Gap)",
            width=280,
            fg_color="#7B1113",
            hover_color="#4D0000",
            command=self.toggle_host_isolation
        )
        self.isolate_button.pack(pady=4, padx=20)

        self._add_panel_section(self.right_frame, "NETWORK MONITORING")

        self.sentinel_button = ctk.CTkButton(
            self.right_frame,
            text="Network Sentinel Audit",
            width=280,
            fg_color="#1f538d",
            command=self.network_sentinel_callback
        )
        self.sentinel_button.pack(pady=4, padx=20)

        self.radar_button = ctk.CTkButton(
            self.right_frame,
            text="Start Radar (30s Loop)",
            width=280,
            fg_color="#1f538d",
            hover_color="#14375e",
            command=self.toggle_radar
        )
        self.radar_button.pack(pady=4, padx=20)

        self.network_dashboard_button = ctk.CTkButton(
            self.right_frame,
            text="Network Trust Dashboard",
            width=280,
            command=self.show_network_dashboard,
        )
        self.network_dashboard_button.pack(pady=4, padx=20)

        # Killswitch & AI Evaluation Group
        self._add_panel_section(self.right_frame, "PROCESS RESPONSE")
        self.kill_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        self.kill_frame.pack(pady=6, padx=20)

        self.pid_entry = ctk.CTkEntry(self.kill_frame, placeholder_text="PID...", width=80)
        self.pid_entry.pack(side="left", padx=(0, 5))

        self.kill_button = ctk.CTkButton(
            self.kill_frame,
            text="Kill PID",
            fg_color="#880808",
            hover_color="#660000",
            width=75,
            command=self.terminate_process_callback
        )
        self.kill_button.pack(side="left", padx=(0, 5))

        self.ai_eval_button = ctk.CTkButton(
            self.kill_frame,
            text="Dual-AI Eval",
            fg_color="#4B0082",
            hover_color="#300052",
            width=85,
            command=self.run_dual_ai_eval
        )
        self.ai_eval_button.pack(side="left")

        # --- 5. LOGGING CONSOLE ---
        self.console = ctk.CTkTextbox(
            self,
            height=380,
            width=940,
            font=("Consolas", 12),
            fg_color="#000000",
            text_color="#00FF00"
        )
        self.console.pack(pady=15, padx=20)

        # High-visibility Dark Mode Log Tags
        self.console.tag_config("threat", foreground="#FF3333")   # Neon Red
        self.console.tag_config("warn", foreground="#FF7518")     # Orange
        self.console.tag_config("trusted", foreground="#00FF00")  # Green
        self.console.tag_config("system", foreground="#00E5FF")   # Cyan
        self.console.tag_config("review", foreground="#FFBF00")   # Amber

        # --- THREAD QUEUE SETUP ---
        self.log_queue = queue.Queue()
        self.scan_thread_running = False
        self.engine_thread_running = False

        self.check_queue()
        self.log_event("Ghost-Aegis Defensive Suite initialized. Ready.", "trusted")

    @staticmethod
    def _add_panel_section(parent, title):
        ctk.CTkLabel(
            parent,
            text=title,
            anchor="w",
            font=("Consolas", 10, "bold"),
            text_color="#7fb3d5",
        ).pack(fill="x", padx=20, pady=(10, 3))

    def destroy(self):
        self.canary_guard.stop()
        super().destroy()

    # --- ABOUT DIALOG ---
    def show_about_window(self):
        about_win = ctk.CTkToplevel(self)
        about_win.title("About Ghost-Aegis")
        about_win.geometry("440x480")
        about_win.attributes("-topmost", True)

        ctk.CTkLabel(about_win, text="GHOST-AEGIS", font=("Fixedsys", 28, "bold"), text_color="#00FF00").pack(pady=20)
        ctk.CTkLabel(about_win, text="Version 2.0.0 | 'Sentinel Blue Edition'", font=("Arial", 10, "italic")).pack()

        mission_text = (
            "Mission: Save the World through Internet Safety.\n\n"
            "Ghost-Aegis is an active defensive engineering suite designed for "
            "Blue Team operations. It integrates real-time socket inspection, "
            "automated host isolation, JIT administrative protection, and "
            "heuristic threat analysis."
        )

        mission_box = ctk.CTkTextbox(about_win, width=380, height=130, font=("Arial", 12))
        mission_box.insert("0.0", mission_text)
        mission_box.configure(state="disabled", fg_color="#2b2b2b")
        mission_box.pack(pady=15, padx=20)

        ctk.CTkLabel(about_win, text="Cyber Defense Lead:", font=("Arial", 12, "bold"), text_color="#3b8ed0").pack()
        ctk.CTkLabel(about_win, text='[Homero "Joseph Awana" Antillon / Gemini / Copilot]', font=("Consolas", 14)).pack(pady=5)
        ctk.CTkLabel(about_win, text="CustomTkinter • Psutil • Windows AdvFirewall", font=("Arial", 9)).pack(pady=(15, 0))
        ctk.CTkButton(about_win, text="CLOSE", fg_color="#444444", command=about_win.destroy).pack(pady=15)

    def show_incidents_window(self):
        incidents_win = ctk.CTkToplevel(self)
        incidents_win.title("Ghost-Aegis | Incident Evidence")
        incidents_win.geometry("900x560")
        incidents_win.attributes("-topmost", True)

        evidence_box = ctk.CTkTextbox(
            incidents_win,
            font=("Consolas", 11),
            fg_color="#000000",
            text_color="#00FF00",
        )
        evidence_box.pack(fill="both", expand=True, padx=15, pady=(15, 8))

        incidents = load_incidents()
        if not incidents:
            evidence_box.insert("end", "No incidents recorded yet. Run Network Sentinel Audit first.\n")
        else:
            for incident in reversed(incidents[-100:]):
                evidence_box.insert(
                    "end",
                    f"[{incident.get('timestamp', 'unknown')}] "
                    f"{incident.get('process', 'unknown')} (PID {incident.get('pid', '?')})\n"
                    f"  Risk: {incident.get('risk_score', 0)}/100 | "
                    f"Remote: {incident.get('remote_ip', 'none')} | "
                    f"Signer: {incident.get('signer', 'Unknown')}\n"
                    f"  Path: {incident.get('path', 'Unknown')}\n"
                    f"  Evidence: {'; '.join(incident.get('reasons', []))}\n\n",
                )
        evidence_box.configure(state="disabled")
        ctk.CTkButton(
            incidents_win, text="CLOSE", fg_color="#444444",
            command=incidents_win.destroy,
        ).pack(pady=(0, 12))
## ------------------------------
    def export_report(self):
        destination = filedialog.asksaveasfilename(
            title="Export Ghost-Aegis Investigation Report",
            defaultextension=".txt",
            filetypes=[("Text report", "*.txt"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            report_path = export_incident_report(destination)
            self.log_event(f"[+] Investigation report exported: {report_path}", "trusted")
        except OSError as error:
            self.log_event(f"Report export failed: {error}", "threat")

    def show_network_dashboard(self):
        dashboard = ctk.CTkToplevel(self)
        dashboard.title("Ghost-Aegis | Network Trust Dashboard")
        dashboard.geometry("1120x620")
        dashboard.attributes("-topmost", True)

        ctk.CTkLabel(
            dashboard,
            text="LIVE NETWORK TRUST DASHBOARD",
            font=("Consolas", 14, "bold"),
            text_color="#00E5FF",
        ).pack(pady=(15, 4))
        ctk.CTkLabel(
            dashboard,
            text="Review-only snapshot of active external connections and observed behavior",
            font=("Arial", 10),
            text_color="#9aa7b2",
        ).pack(pady=(0, 10))

        dashboard_box = ctk.CTkTextbox(
            dashboard,
            font=("Consolas", 11),
            fg_color="#000000",
            text_color="#00FF00",
        )
        dashboard_box.pack(fill="both", expand=True, padx=15, pady=5)

        controls = ctk.CTkFrame(dashboard, fg_color="transparent")
        controls.pack(fill="x", padx=15, pady=(5, 0))
        search_entry = ctk.CTkEntry(
            controls, placeholder_text="Search process, IP, port, or path...", width=300,
        )
        search_entry.pack(side="left", padx=(0, 8))
        filter_menu = ctk.CTkOptionMenu(
            controls,
            values=["All", "First seen", "Beacon-like", "Review"],
            width=125,
        )
        filter_menu.pack(side="left", padx=4)
        sort_menu = ctk.CTkOptionMenu(
            controls,
            values=["Risk", "Sightings", "Process"],
            width=110,
        )
        sort_menu.pack(side="left", padx=4)

        def refresh():
            dashboard_box.configure(state="normal")
            dashboard_box.delete("1.0", "end")
            dashboard_box.insert(
                "end",
                f"{'PROCESS':<18} {'DESTINATION':<24} {'PORT':<6} "
                f"{'SIGHTINGS':<10} {'FIRST SEEN':<11} {'BEACON':<8}\n"
                + "-" * 90 + "\n",
            )
            query = search_entry.get().strip().lower()
            selected_filter = filter_menu.get()
            selected_sort = sort_menu.get()
            rows = self._network_dashboard_rows()
            rows = [
                row for row in rows
                if not query or query in " ".join(
                    str(row[field]).lower()
                    for field in ("process", "destination", "port", "path")
                )
            ]
            if selected_filter == "First seen":
                rows = [row for row in rows if row["first_seen"]]
            elif selected_filter == "Beacon-like":
                rows = [row for row in rows if row["beacon"]]
            elif selected_filter == "Review":
                rows = [row for row in rows if row["risk"] == "REVIEW"]
            if selected_sort == "Sightings":
                rows.sort(key=lambda row: row["sightings"], reverse=True)
            elif selected_sort == "Process":
                rows.sort(key=lambda row: row["process"].lower())
            if not rows:
                dashboard_box.insert("end", "No active external connections detected.\n")
            for row in rows:
                dashboard_box.insert(
                    "end",
                    f"{row['process'][:17]:<18} {row['destination'][:23]:<24} "
                    f"{row['port']:<6} {row['sightings']:<10} "
                    f"{str(row['first_seen']):<11} {str(row['beacon']):<8}\n"
                    f"  Path: {row['path']}\n"
                    f"  Trust: {row['trust']} | Risk: {row['risk']}\n\n",
                )
            dashboard_box.configure(state="disabled")

        action_controls = ctk.CTkFrame(dashboard, fg_color="transparent")
        action_controls.pack(fill="x", padx=15, pady=(5, 12))
        ctk.CTkButton(action_controls, text="Refresh Snapshot", width=150, command=refresh).pack(side="left")
        ctk.CTkButton(
            action_controls, text="CLOSE", width=100, fg_color="#444444",
            command=dashboard.destroy,
        ).pack(side="right")
        search_entry.bind("<Return>", lambda _event: refresh())
        filter_menu.configure(command=lambda _value: refresh())
        sort_menu.configure(command=lambda _value: refresh())
        refresh()

    def _network_dashboard_rows(self):
        rows = []
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.Error:
            return rows
        for connection in connections:
            if connection.status != psutil.CONN_ESTABLISHED or not connection.raddr or not connection.pid:
                continue
            remote_ip = connection.raddr.ip
            if remote_ip in {"127.0.0.1", "0.0.0.0", "::1"}:
                continue
            try:
                process = psutil.Process(connection.pid)
                process_name = process.name()
                executable = process.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                process_name = "Unknown"
                executable = "Unavailable"
            port = str(connection.raddr.port)
            observation = self.network_behavior.get_observation(process_name, remote_ip, port)
            trust = "BEACON-LIKE" if observation["beacon"] else "FIRST-SEEN" if observation["first_seen"] else "OBSERVED"
            risk = "REVIEW" if observation["beacon"] or observation["first_seen"] else "KNOWN"
            rows.append({
                "process": process_name,
                "destination": remote_ip,
                "port": port,
                "sightings": observation["sightings"],
                "first_seen": observation["first_seen"],
                "beacon": observation["beacon"],
                "path": executable,
                "trust": trust,
                "risk": risk,
            })
        return sorted(rows, key=lambda row: (row["risk"], row["process"].lower()))

    def toggle_canary_shield(self):
        if self.canary_enabled:
            self.canary_guard.stop()
            self.canary_enabled = False
            self.canary_button.configure(text="Start Canary Shield", fg_color="#1f538d")
            self.log_event("[*] Canary Shield stopped.", "review")
            return

        started = self.canary_guard.start(self._canary_finding_callback)
        if started:
            self.canary_enabled = True
            self.canary_button.configure(text="Stop Canary Shield", fg_color="#e67e22")
            self.log_event("[+] Canary Shield active: monitoring three protected files.", "trusted")

    def _canary_finding_callback(self, finding):
        path = finding["path"]
        action = finding["action"]
        incident = Incident(
            process="Unknown",
            pid=0,
            path=path,
            risk_score=85,
            reasons=[f"canary file {action.lower()}"],
            recommended_action="suspend_and_review",
        )
        try:
            append_incident(incident)
        except OSError as error:
            self._queue_log(f"Canary incident record failed: {error}", "warn")
        self._queue_log(
            f"[CANARY ALERT] {action}: {path}. Review active processes immediately.",
            "threat",
        )

    # --- THREAD-SAFE QUEUE PROCESSING ---
    def check_queue(self):
        try:
            while True:
                message, tag = self.log_queue.get_nowait()
                if message == "__scan_complete__":
                    self.scan_thread_running = False
                    self.sentinel_button.configure(state="normal", text="Network Sentinel Audit")
                    if self.radar_enabled:
                        self.after(30000, self._run_scheduled_radar_scan)
                elif message == "__ai_eval_complete__":
                    self.ai_eval_button.configure(state="normal")
                elif message == "__interfaces_complete__":
                    self.interfaces_button.configure(state="normal", text="Interface Telemetry")
                elif message == "__persistence_complete__":
                    self.persistence_button.configure(state="normal", text="Audit Persistence")
                elif message == "__engine_complete__":
                    self.engine_thread_running = False
                    self.engine_button.configure(state="normal", text="Launch Defense Engine")
                else:
                    self.log_event(message, tag)
        except queue.Empty:
            pass

        self.after(100, self.check_queue)

    def _queue_log(self, message, tag=None):
        self.log_queue.put((message, tag))

    def _run_scheduled_radar_scan(self):
        if self.radar_enabled:
            self.network_sentinel_callback()

    def log_event(self, message, tag=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        try:
            with open("ghost_aegis.log", "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception:
            pass

        self.console.configure(state="normal")
        if tag:
            self.console.insert("end", log_entry + "\n", tag)
        else:
            self.console.insert("end", log_entry + "\n")
        self.console.configure(state="disabled")
        self.console.see("end")

    # --- ACCESS CONTROL: JIT WITH 15-MINUTE EXPIRATION ---
    def run_jit(self):
        dialog = ctk.CTkInputDialog(text="Enter username to elevate:", title="JIT Admin Elevation")
        target_user = dialog.get_input()
        if target_user:
            try:
                subprocess.run(["net", "localgroup", "Administrators", target_user, "/add"], check=True)
                self.log_event(f"JIT SUCCESS: Granted {target_user} temporary Admin privileges.", "trusted")

                def revoke_admin():
                    try:
                        subprocess.run(["net", "localgroup", "Administrators", target_user, "/delete"], check=True)
                        self._queue_log(f"⏰ [JIT EXPIRED] Auto-demotion completed: {target_user} removed from Administrators.", "warn")
                    except Exception as err:
                        self._queue_log(f"⚠️ [JIT DEMOTION FAILED] Could not demote {target_user}: {err}", "threat")

                # Actual 15-minute background timer (900 seconds)
                demote_timer = threading.Timer(900.0, revoke_admin)
                demote_timer.daemon = True
                demote_timer.start()

                exec_time = (datetime.now() + timedelta(minutes=15)).strftime("%H:%M:%S")
                self.log_event(f"Lockdown scheduled for {exec_time} (15m timer engaged).", "review")
            except Exception as e:
                self.log_event(f"JIT Error: {e}", "threat")

    def run_audit(self):
        self.log_event("Auditing local Administrators group...", "review")
        try:
            result = subprocess.run(["net", "localgroup", "Administrators"], capture_output=True, text=True, check=True)
            self.log_event(result.stdout.strip(), "system")
        except Exception as e:
            self.log_event(f"Audit failed: {e}", "threat")

    def show_sys_info(self):
        try:
            cmd = "Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption"
            os_name = subprocess.check_output(["powershell", "-Command", cmd], text=True).strip()
            self.log_event(f"SYSTEM INFO: {os_name} | HOSTNAME: {platform.node()}", "system")
        except Exception:
            self.log_event(f"SYSTEM INFO: Windows | HOSTNAME: {platform.node()}", "system")

    # --- DEFENSE ENGINE & TELEMETRY WORKERS ---
    def run_interface_telemetry(self):
        if jit_engine is None or not hasattr(jit_engine, "monitor_network_interfaces"):
            self.log_event("Interface telemetry is unavailable: main.py not loaded.", "threat")
            return

        self.interfaces_button.configure(state="disabled", text="Gathering...")
        threading.Thread(target=self._interface_telemetry_worker, daemon=True).start()

    def _interface_telemetry_worker(self):
        try:
            telemetry = jit_engine.monitor_network_interfaces()
            for interface_name, addresses in telemetry.items():
                self._queue_log(f"[IFACE] {interface_name}", "system")
                for address in addresses:
                    self._queue_log(f"   -> {address['address']} ({address['family']}) | Netmask: {address['netmask']}", "trusted")
            self._queue_log("Interface telemetry refresh complete.", "system")
        except Exception as error:
            self._queue_log(f"Interface telemetry error: {error}", "threat")
        finally:
            self.log_queue.put(("__interfaces_complete__", None))

    def run_persistence_audit(self):
        self.persistence_button.configure(state="disabled", text="Auditing...")
        self.log_event("[*] Reading common Windows persistence locations...", "system")
        threading.Thread(target=self._persistence_audit_worker, daemon=True).start()

    def _persistence_audit_worker(self):
        try:
            entries = collect_persistence_entries()
            if not entries:
                self._queue_log("No persistence entries were found or read.", "trusted")
            else:
                self._queue_log(f"Persistence audit found {len(entries)} entries:", "review")
                for entry in entries:
                    self._queue_log(
                        f"[{entry['type']}] {entry['location']}",
                        "review",
                    )
        except Exception as error:
            self._queue_log(f"Persistence audit failed: {error}", "threat")
        finally:
            self.log_queue.put(("__persistence_complete__", None))

    def run_readiness_check(self):
        """Report prerequisites without changing system state."""
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False
        self.log_event("--- Ghost-Aegis Readiness Check ---", "system")
        self.log_event(
            f"Administrator privileges: {'READY' if is_admin else 'LIMITED'}",
            "trusted" if is_admin else "warn",
        )
        firewall_status = self._firewall_readiness()
        self.log_event(
            f"Windows Firewall query: {firewall_status}",
            "trusted" if firewall_status == "READY" else "warn",
        )
        self.log_event(
            f"Optional AbuseIPDB enrichment: "
            f"{'CONFIGURED' if os.getenv('ABUSEIPDB_API_KEY') else 'NOT CONFIGURED'}",
            "trusted" if os.getenv("ABUSEIPDB_API_KEY") else "review",
        )
        self.log_event(
            f"Optional AI enrichment: "
            f"{'CONFIGURED' if os.getenv('GEMINI_API_KEY') or os.getenv('OPENAI_API_KEY') else 'NOT CONFIGURED'}",
            "trusted" if os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY") else "review",
        )
        self.log_event("Incident history: READY", "trusted")
        self.log_event("Readiness check complete. No system changes were made.", "system")

    @staticmethod
    def _firewall_readiness():
        if os.name != "nt":
            return "UNAVAILABLE"
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            return "READY" if result.returncode == 0 else "UNAVAILABLE"
        except (OSError, subprocess.SubprocessError):
            return "UNAVAILABLE"

    def run_defense_engine(self):
        if self.engine_thread_running:
            return
        if jit_engine is None or not hasattr(jit_engine, "run_defense_engine"):
            self.log_event("Defense engine is unavailable: main.py could not be loaded.", "threat")
            return

        self.engine_thread_running = True
        self.engine_button.configure(state="disabled", text="Engine Active...")
        self.log_event("[*] Spawning Dual-AI Defense Engine daemon in background...", "system")
        threading.Thread(target=self._defense_engine_worker, daemon=True).start()

    def _defense_engine_worker(self):
        try:
            import asyncio
            asyncio.run(jit_engine.run_defense_engine(start_cli=False, safe_mode=True))
            self._queue_log("Defense engine loop ended.", "trusted")
        except Exception as error:
            self._queue_log(f"Defense engine failed: {error}", "threat")
        finally:
            self.log_queue.put(("__engine_complete__", None))

    # --- DEFENSE: STEALTH, EMERGENCY CLEAN, HOST ISOLATION ---
    def run_stealth(self):
        """Drops inbound ICMP requests to hide machine from subnet sweeps."""
        self.log_event("[*] Engaging Stealth Protocol: Dropping inbound ICMP...", "warn")
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=GhostAegis_Stealth_DropPing"], capture_output=True)
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=GhostAegis_Stealth_DropPing", "dir=in", "action=block", "protocol=icmpv4"
            ], check=True, capture_output=True)
            self.log_event("🛡️ STEALTH ACTIVE: Machine is silent to ICMP ping sweeps.", "trusted")
        except Exception as e:
            self.log_event(f"Failed to activate stealth: {e}", "threat")

    def run_cleanup(self):
        """Purges ARP tables and flushes resolver caches."""
        self.log_event("! EXECUTING EMERGENCY CACHE PURGE !", "threat")
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, check=True)
            self.log_event("[+] DNS Resolver Cache successfully flushed.", "system")
        except Exception as e:
            self.log_event(f"[-] DNS Flush error: {e}", "warn")

        try:
            subprocess.run(["arp", "-d", "*"], capture_output=True)
            self.log_event("[+] ARP cache table flushed.", "system")
        except Exception as e:
            self.log_event(f"[-] ARP Purge error: {e}", "warn")

    def toggle_host_isolation(self):
        """Emergency Air-Gap toggle: drops all outbound traffic."""
        self.host_isolated = not self.host_isolated
        if self.host_isolated:
            self.isolate_button.configure(text="Restore Network", fg_color="#e67e22")
            self.log_event("🚨 [AIR-GAP ACTIVE] Emergency host containment initiated!", "threat")
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=GhostAegis_AirGap", "dir=out", "action=block"
                ], check=True, capture_output=True)
                self.log_event("[+] Outbound network traffic successfully blocked.", "warn")
            except Exception as e:
                self.log_event(f"[-] Isolation failure: {e}", "threat")
        else:
            self.isolate_button.configure(text="Host Isolation (Air-Gap)", fg_color="#7B1113")
            self.log_event("[*] Disengaging host containment...", "system")
            try:
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=GhostAegis_AirGap"], capture_output=True)
                self.log_event("[+] Outbound network traffic restored.", "trusted")
            except Exception as e:
                self.log_event(f"[-] Reconnect error: {e}", "threat")

    # --- THREAT INTELLIGENCE & GEOLOCATION ---
    def check_ip_reputation(self, ip_address):
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return 0
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": api_key}
        querystring = {"ipAddress": ip_address, "maxAgeInDays": "30"}
        try:
            response = requests.get(url, headers=headers, params=querystring, timeout=2.5)
            if response.status_code == 200:
                data = response.json()
                return data["data"]["abuseConfidenceScore"]
        except Exception:
            pass
        return 0

    def get_ip_location(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=1.5).json()
            if response.get("status") == "success":
                return f"{response.get('city')}, {response.get('countryCode')}"
            return "Unknown Loc"
        except Exception:
            return "Loc Error"

    # --- NETWORK SENTINEL & RADAR ---
    def toggle_radar(self):
        self.radar_enabled = not self.radar_enabled
        if self.radar_enabled:
            self.radar_button.configure(text="Stop Radar", fg_color="#e67e22")
            self.log_event("[!] RADAR ENGAGED: Continuous audit sweep every 30s.", "warn")
            self.network_sentinel_callback()
        else:
            self.radar_button.configure(text="Start Radar (30s Loop)", fg_color="#1f538d")
            self.log_event("[!] RADAR DISENGAGED.", "review")

    def network_sentinel_callback(self):
        if self.scan_thread_running:
            return

        self.scan_thread_running = True
        self.sentinel_button.configure(state="disabled", text="Scanning Sockets...")
        self.log_event("[*] Network Sentinel starting deep socket audit...", "system")
        threading.Thread(target=self._network_sentinel_worker, daemon=True).start()

    def _network_sentinel_worker(self):
        trusted_domains = ["google.com", "github.com", "microsoft.com", "akamai", "azure", "cloudflare"]

        try:
            result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()
            self._queue_log(f"{'STATUS':<12} {'PROCESS':<16} {'REMOTE HOST / LOCATION':<42} {'PID':<6}")

            found_active = False
            for line in lines:
                parts = line.split()
                if len(parts) >= 5 and "ESTABLISHED" in parts:
                    ip_only = parts[2].rsplit(":", 1)[0].replace("[", "").replace("]", "")
                    pid_str = parts[-1]

                    if not pid_str.isdigit():
                        continue
                    pid = int(pid_str)

                    if ip_only in ["127.0.0.1", "0.0.0.0", "::1"]:
                        continue

                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                        exe_path = proc.exe()
                    except Exception:
                        proc_name = "Unknown"
                        exe_path = ""

                    location = self.get_ip_location(ip_only)
                    try:
                        hostname = socket.getfqdn(ip_only)
                    except Exception:
                        hostname = ip_only

                    display_host = f"{hostname} ({location})"
                    status, tag_name = "[REVIEW]", "review"
                    remote_port = parts[2].rsplit(":", 1)[-1]
                    try:
                        behavior = self.network_behavior.observe(
                            proc_name, ip_only, remote_port,
                        )
                    except OSError as history_error:
                        behavior = {"first_seen": False, "beacon": False}
                        self._queue_log(
                            f"Network history unavailable: {history_error}", "warn"
                        )
                    if behavior["first_seen"]:
                        self._queue_log(
                            f"[NEW DESTINATION] {proc_name} -> {ip_only}:{remote_port}",
                            "review",
                        )
                    if behavior["beacon"]:
                        self._queue_log(
                            f"[BEACON PATTERN] {proc_name} repeatedly contacts "
                            f"{ip_only}:{remote_port} at regular intervals.",
                            "warn",
                        )
                    signer = get_authenticode_signer(exe_path)
                    reputation = 0
                    trusted_process = False

                    # Heuristic 1: Staged execution path
                    # Heuristic 2: Known trusted domains / system binaries
                    if any(d in hostname.lower() for d in trusted_domains):
                        status, tag_name = "[TRUSTED]", "trusted"
                        trusted_process = True
                    elif proc_name.lower() in ["svchost.exe", "lsass.exe"]:
                        status, tag_name = "[SYSTEM]", "system"
                        trusted_process = True
                    else:
                        reputation = self.check_ip_reputation(ip_only)

                    risk_score, reasons = calculate_risk(
                        suspicious_path=is_suspicious_path(exe_path),
                        unsigned=signer == "Unsigned",
                        reputation=reputation,
                        trusted_process=trusted_process,
                    )
                    if risk_score >= 70:
                        status, tag_name = "[THREAT]", "threat"
                    elif risk_score >= 40:
                        status, tag_name = "[WARN]", "warn"
                    display_host = f"{display_host} | RISK: {risk_score}/100"

                    incident = Incident(
                        process=proc_name,
                        pid=pid,
                        path=exe_path,
                        remote_ip=ip_only,
                        reputation=reputation,
                        signer=signer,
                        risk_score=risk_score,
                        reasons=reasons,
                        recommended_action=(
                            "block_and_review" if risk_score >= 70 else "review"
                        ),
                    )
                    try:
                        append_incident(incident)
                    except OSError as log_error:
                        self._queue_log(f"Incident record failed: {log_error}", "warn")

                    self._queue_log(f"{status:<12} {proc_name:<16} {display_host:<42} {pid:<6}", tag_name)
                    self._queue_log(
                        f"   Evidence: {'; '.join(reasons)} | Signer: {signer}",
                        tag_name,
                    )
                    found_active = True

            if not found_active:
                self._queue_log("No active external sockets detected.")
        except Exception as e:
            self._queue_log(f"Audit Exception: {e}", "threat")
        finally:
            self.log_queue.put(("__scan_complete__", None))

    # --- PROCESS TERMINATION & DUAL-AI ANALYSIS ---
    def terminate_process_callback(self):
        pid_str = self.pid_entry.get().strip()
        if pid_str.isdigit():
            try:
                p = psutil.Process(int(pid_str))
                process_name = p.name()
                p.terminate()
                self.log_event(f"[X] Terminated process {process_name} (PID: {pid_str}).", "threat")
                self.pid_entry.delete(0, "end")
            except Exception as e:
                self.log_event(f"Process kill error: {e}", "threat")
        else:
            self.log_event("Invalid PID format entered.", "warn")

    def run_dual_ai_eval(self):
        pid_str = self.pid_entry.get().strip()
        if pid_str.isdigit():
            self.log_event(f"[*] Extracting telemetry and invoking Dual-AI for PID {pid_str}...", "system")
            self.ai_eval_button.configure(state="disabled")
            threading.Thread(target=self._dual_ai_worker, args=(int(pid_str),), daemon=True).start()
        else:
            self.log_event("Invalid PID entered for AI evaluation.", "warn")

    def _dual_ai_worker(self, pid):
        try:
            target_proc = psutil.Process(pid)
            proc_name = target_proc.name()
            try:
                exe_path = target_proc.exe()
            except Exception:
                exe_path = "Unavailable"
            try:
                parent_name = target_proc.parent().name() if target_proc.parent() else "None"
            except Exception:
                parent_name = "Unknown"

            file_hash = get_file_sha256(exe_path)
            connections = target_proc.net_connections()
            remote_ips = [c.raddr.ip for c in connections if c.raddr]

            context = (
                f"Process Name: {proc_name} (PID: {pid})\n"
                f"Parent Process: {parent_name}\n"
                f"Executable Path: {exe_path} (Staged Dir: {is_suspicious_path(exe_path)})\n"
                f"SHA256 Hash: {file_hash}\n"
                f"Active Outbound IP Connections: {remote_ips}"
            )
            self._queue_log(f"[*] Telemetry gathered for {proc_name}. Querying AI models...", "system")

            prompt = (
                "You are an expert Blue Team cybersecurity analyst. "
                "Analyze the following process telemetry and provide a 1-sentence assessment "
                "along with a threat probability score (0-10):\n\n"
                f"{context}"
            )

            # 1. Gemini Engine Query
            try:
                from google import genai
                gemini_key = os.getenv("GEMINI_API_KEY")
                if not gemini_key:
                    raise RuntimeError("Missing GEMINI_API_KEY in .env")

                gemini_client = genai.Client(api_key=gemini_key)
                gemini_res = gemini_client.models.generate_content(
                    model="gemini-3.8-flash",
                    contents=prompt,
                )
                gemini_verdict = (gemini_res.text or "No response").strip().replace("\n", " ")
            except Exception as e:
                gemini_verdict = f"Gemini Error: {e}"

            # 2. Copilot / Secondary Model Query
            try:
                import openai
                openai_key = os.getenv("OPENAI_API_KEY") or os.getenv("COPILOT_API_KEY")
                if not openai_key:
                    raise RuntimeError("Missing OPENAI_API_KEY / COPILOT_API_KEY in .env")

                client = openai.OpenAI(api_key=openai_key)
                openai_res = client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=60
                )
                copilot_verdict = openai_res.choices[0].message.content.strip().replace("\n", " ")
            except Exception as e:
                copilot_verdict = f"Copilot Error: {e}"

            # 3. Present Verdicts to Console
            self._queue_log(f"🧠 [GEMINI]: {gemini_verdict}", "review")
            self._queue_log(f"🤖 [COPILOT]: {copilot_verdict}", "review")

        except psutil.NoSuchProcess:
            self._queue_log(f"[!] PID {pid} is no longer running.", "warn")
        except Exception as e:
            self._queue_log(f"[!] Dual-AI Worker error: {e}", "threat")
        finally:
            self.log_queue.put(("__ai_eval_complete__", None))


if __name__ == "__main__":
    app = GhostAegisApp()
    app.mainloop()