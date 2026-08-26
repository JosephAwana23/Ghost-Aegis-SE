import os
import json
import asyncio
import threading
import psutil
from dotenv import load_dotenv

load_dotenv()

NETWORK_POLICY_PATH = os.path.join(os.path.dirname(__file__), "network_policy.json")


def load_network_policy():
    default_policy = {"whitelist": [], "blacklist": []}
    try:
        with open(NETWORK_POLICY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return default_policy
        return {
            "whitelist": set(str(item).lower() for item in data.get("whitelist", [])),
            "blacklist": set(str(item).lower() for item in data.get("blacklist", []))
        }
    except (FileNotFoundError, json.JSONDecodeError):
        return default_policy


def refresh_network_policy():
    policy = load_network_policy()
    globals()["KNOWN_NETWORK_WHITELIST"] = policy["whitelist"]
    globals()["KNOWN_NETWORK_BLACKLIST"] = policy["blacklist"]
    return policy


refresh_network_policy()


def normalize_host(value):
    if value is None:
        return ""
    host = str(value).strip().lower().replace("http://", "").replace("https://", "")
    return host.split("/")[0].split(":")[0]


class TelemetryEvent:
    """Fallback class for standalone testing if telemetry module isn't imported."""
    def __init__(self, process_name, details):
        self.process_name = process_name
        self.details = details
        self.risk_score = details.get("risk_score", 0.0)

class CopilotIntelligenceEngine:
    """The Local AI Brain: Offline heuristic and behavioral analysis pipelines."""
    def __init__(self):
        self.suspicious_extensions = [".tmp", ".ps1", ".bat", ".vbs", "updater.exe"]
        self.critical_paths = ["appdata", "temp", "programdata"]
        
    def analyze_process_lineage(self, process_name, parent_process):
        """Analyzes parent-child execution chains for malicious masquerading."""
        score, notes = 0.0, []
        office_apps = ["winword.exe", "excel.exe", "powerpnt.exe"]
        shells = ["cmd.exe", "powershell.exe", "bash.exe"]
        if parent_process.lower() in office_apps and process_name.lower() in shells:
            score += 0.8
            notes.append(f"Suspicious Lineage: {parent_process} spawned {process_name}")
        return score, notes

    def evaluate_network_guard(self, connections):
        """Evaluates network telemetry for anomalous outbound connections."""
        refresh_network_policy()
        score, notes = 0.0, []

        for conn in connections:
            ip = str(conn.get("ip") or "").strip()
            host = normalize_host(conn.get("host") or conn.get("domain") or conn.get("hostname") or conn.get("url") or ip)
            destination = host or ip

            if destination in KNOWN_NETWORK_WHITELIST or ip in KNOWN_NETWORK_WHITELIST:
                continue

            if destination in KNOWN_NETWORK_BLACKLIST or ip in KNOWN_NETWORK_BLACKLIST:
                score += 0.9
                notes.append(f"Connection to a known blacklisted destination: {destination}")
                continue

            if conn.get("port") in [4444, 666, 1337, 31337]:
                score += 0.6
                notes.append(f"Suspicious outbound port detected: {conn.get('port')}")
            if ip == "92.223.96.6":
                score += 0.9
                notes.append(f"Connection to known malicious external IP: {ip}")

        return score, notes

    def heuristic_risk_scorer(self, event):
        """Risk scoring pipeline evaluating file paths and internal behavioral flags."""
        score, notes = 0.0, []
        path = event.process_name.lower()
        if any(ext in path for ext in self.suspicious_extensions):
            score += 0.3
            notes.append("Process matches suspicious extension pattern.")
        if any(c_path in path for c_path in self.critical_paths):
            score += 0.2
            notes.append("Process executing from easily writable temp directory.")
        if event.details.get("is_critical"):
            score += 0.5
            notes.append("Telemetry event natively flagged as critical.")
        if event.details.get("high_entropy", False):
            score += 0.4
            notes.append("High file entropy detected (potential packing/encryption).")
        return score, notes

class GhostAegisCopilot:
    def __init__(self):
        self.version = "2.1.0-SE"
        self.codename = "CyberBuddy Sentinel"
        self.audit_log_path = "logs/aegis_audit.log"
        self.engine = CopilotIntelligenceEngine()
        self.safe_mode = False
        self._ensure_audit_log_dir()

    def _ensure_audit_log_dir(self):
        """Make sure the audit log directory exists before writing or reading logs."""
        log_dir = os.path.dirname(self.audit_log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    def toggle_safe_mode(self):
        """Flip the live enforcement mode for testing and safe monitoring."""
        self.safe_mode = not self.safe_mode
        state = "ENABLED" if self.safe_mode else "DISABLED"
        print(f"\n[SAFE MODE] Live quarantine enforcement is now {state}.\n")
        return self.safe_mode

    def show_policy_help(self):
        """Displays a concise policy help menu."""
        print("\n[POLICY HELP]")
        print("  policy        - Open policy management menu")
        print("  show-policy   - Display active allowlist/denylist")
        print("  reload-policy - Reload policy JSON from disk")
        print("  add-white     - Add domain/IP to allowlist")
        print("  add-black     - Add domain/IP to denylist")
        print("  remove-white  - Remove domain/IP from allowlist")
        print("  remove-black  - Remove domain/IP from denylist")
        print("  safe-mode     - Toggle quarantine enforcement ON/OFF")
        print()

    async def analyze_threat(self, event) -> dict:
        """Unified dual-AI schema executed by main.py and CLI 'analyze' command."""
        await asyncio.sleep(0.1)
        parent_proc = event.details.get("parent_process", "explorer.exe")
        network_conns = event.details.get("network_connections", [])
        
        lineage_score, lineage_notes = self.engine.analyze_process_lineage(event.process_name, parent_proc)
        net_score, net_notes = self.engine.evaluate_network_guard(network_conns)
        heuristic_score, heuristic_notes = self.engine.heuristic_risk_scorer(event)
        
        total_risk = min(lineage_score + net_score + heuristic_score + event.risk_score, 1.0)
        all_notes = lineage_notes + net_notes + heuristic_notes
        
        if total_risk >= 0.75:
            verdict = "MALICIOUS"
            action = "quarantine_process"
            summary_prefix = "CRITICAL THREAT IDENTIFIED."
        elif total_risk >= 0.4:
            verdict = "SUSPICIOUS"
            action = "monitor_and_restrict"
            summary_prefix = "ANOMALY DETECTED."
        else:
            verdict = "BENIGN"
            action = "log_only"
            summary_prefix = "Normal activity validated."

        summary = f"{summary_prefix} Findings: {' | '.join(all_notes) if all_notes else 'No anomalies.'}"

        return {
            "source": "Copilot Local Intelligence",
            "verdict": verdict,
            "confidence": round(total_risk, 2),
            "summary": summary,
            "recommended_action": action
        }

    def display_banner(self):
        safe_state = "ON" if self.safe_mode else "OFF"
        print("\n" + "="*60)
        print(f"  🤖 Ghost Aegis Copilot [{self.codename}] v{self.version}")
        print("  Local Intelligence Matrix & Incident Responder (OFFLINE)")
        print(f"  Network Trust Guard: allowlist/denylist enabled | Safe Mode: {safe_state}")
        print("="*60)
        if self.safe_mode:
            print("  [SAFE MODE ACTIVE] Monitoring only — no live quarantine actions will execute.")
        print("  Type 'help' for commands, 'policy' for policy management, or 'scan' to run live process audit.\n")

    def show_system_status(self):
        """Displays real-time hardware telemetry and defensive status."""
        cpu_usage = psutil.cpu_percent(interval=0.1)
        ram_usage = psutil.virtual_memory().percent
        safe_state = "ENABLED" if self.safe_mode else "DISABLED"
        print("\n[SYSTEM STATUS]")
        print(f"  - Defensive Engine   : ONLINE (Air-Gapped Local Matrix)")
        print(f"  - Safe Mode          : {safe_state}")
        print(f"  - Active Memory Usage: {ram_usage}%")
        print(f"  - Processor Load     : {cpu_usage}%")
        print(f"  - Audit Log File     : {self.audit_log_path} ({'ACTIVE' if os.path.exists(self.audit_log_path) else 'NO LOGS'})")
        print(f"  - Active PIDs Monitored: {len(psutil.pids())}\n")

    def show_network_policy(self):
        """Display the currently loaded network allowlist and denylist."""
        policy = refresh_network_policy()
        print("\n[NETWORK POLICY]")
        print(f"  - Allowlist ({len(policy['whitelist'])}): {', '.join(sorted(policy['whitelist'])) if policy['whitelist'] else 'none'}")
        print(f"  - Denylist ({len(policy['blacklist'])}): {', '.join(sorted(policy['blacklist'])) if policy['blacklist'] else 'none'}")
        print()

    def reload_network_policy(self):
        """Reload policy data from the JSON file on disk."""
        policy = refresh_network_policy()
        print(f"\n[POLICY] Network policy refreshed from {NETWORK_POLICY_PATH}")
        print(f"  - Allowlist entries: {len(policy['whitelist'])}")
        print(f"  - Denylist entries: {len(policy['blacklist'])}")
        print()

    def add_policy_entry(self, list_type, value):
        """Persist a domain/IP to the allowlist or denylist."""
        normalized = normalize_host(value)
        if not normalized:
            print("\n[POLICY] Empty value provided. No entry added.\n")
            return

        try:
            with open(NETWORK_POLICY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {"whitelist": [], "blacklist": []}

        if not isinstance(data, dict):
            data = {"whitelist": [], "blacklist": []}

        container = data.setdefault(list_type, [])
        item = normalized.lower()

        if item not in container:
            container.append(item)
            with open(NETWORK_POLICY_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            refresh_network_policy()
            self._ensure_audit_log_dir()
            with open(self.audit_log_path, "a", encoding="utf-8") as log_file:
                log_file.write(f"{__import__('datetime').datetime.now().isoformat()} | POLICY | Added '{item}' to {list_type}\n")
            print(f"\n[POLICY] Added '{item}' to the {list_type} list.\n")
        else:
            print(f"\n[POLICY] '{item}' is already present in the {list_type} list.\n")

    def remove_policy_entry(self, list_type, value):
        """Remove a domain/IP from the allowlist or denylist."""
        normalized = normalize_host(value)
        if not normalized:
            print("\n[POLICY] Empty value provided. No entry removed.\n")
            return

        try:
            with open(NETWORK_POLICY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {"whitelist": [], "blacklist": []}

        if not isinstance(data, dict):
            data = {"whitelist": [], "blacklist": []}

        container = data.setdefault(list_type, [])
        item = normalized.lower()

        if item in container:
            container.remove(item)
            with open(NETWORK_POLICY_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            refresh_network_policy()
            self._ensure_audit_log_dir()
            with open(self.audit_log_path, "a", encoding="utf-8") as log_file:
                log_file.write(f"{__import__('datetime').datetime.now().isoformat()} | POLICY | Removed '{item}' from {list_type}\n")
            print(f"\n[POLICY] Removed '{item}' from the {list_type} list.\n")
        else:
            print(f"\n[POLICY] '{item}' was not found in the {list_type} list.\n")

    def read_audit_logs(self, lines: int = 10):
        """Reads and formats live containment entries from aegis_audit.log."""
        self._ensure_audit_log_dir()
        print("\n[LOGS] Recent Audit History:")
        if not os.path.exists(self.audit_log_path):
            print("  [!] No audit logs found yet. Run an enforcement task first!\n")
            return
        try:
            with open(self.audit_log_path, "r", encoding="utf-8") as f:
                log_lines = f.readlines()[-lines:]
                if not log_lines:
                    print("  - Audit log is currently empty.")
                for line in log_lines:
                    print(f"  {line.strip()}")
            print()
        except Exception as e:
            print(f"  [!] Failed to read log file: {e}\n")

    def read_policy_audit_logs(self, lines: int = 20):
        """Reads only POLICY entries from the audit log (filtered view)."""
        self._ensure_audit_log_dir()
        print("\n[POLICY AUDIT] Recent Policy Changes:")
        if not os.path.exists(self.audit_log_path):
            print("  [!] No audit logs found yet.\n")
            return
        try:
            with open(self.audit_log_path, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
                policy_lines = [l for l in all_lines if "| POLICY |" in l]
                recent_policy = policy_lines[-lines:]
                if not recent_policy:
                    print("  - No policy changes recorded yet.")
                for line in recent_policy:
                    print(f"  {line.strip()}")
            print()
        except Exception as e:
            print(f"  [!] Failed to read log file: {e}\n")

    def _run_coroutine_safely(self, coro):
        """Run an async coroutine even when called from an active event loop."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        result = {}
        def runner():
            result["value"] = asyncio.run(coro)

        thread = threading.Thread(target=runner)
        thread.start()
        thread.join()
        return result["value"]

    def run_cli(self):
        self.display_banner()
        while True:
            try:
                command = input("ghost-copilot> ").strip().lower()
                if not command: continue

                if command == "exit":
                    print("\n[!] Disengaging Ghost Copilot. Stay safe out there, Blue Teamer!")
                    break
                elif command == "help":
                    print("\n[Available Copilot Commands]")
                    print("  status        - Display live system resource load & engine state")
                    print("  scan          - Execute live process scanner across system PIDs")
                    print("  analyze       - Run a simulated threat through the Local Brain")
                    print("  logs          - Stream recent entries from aegis_audit.log")
                    print("  policy-audit  - Show only policy change entries from the audit log")
                    print("  show-policy   - Display the active allowlist/denylist")
                    print("  reload-policy - Reload the JSON network policy from disk")
                    print("  add-white     - Add a host/IP to the allowlist")
                    print("  add-black     - Add a host/IP to the denylist")
                    print("  remove-white  - Remove a host/IP from the allowlist")
                    print("  remove-black  - Remove a host/IP from the denylist")
                    print("  policy        - Open the network trust policy management menu")
                    print("  safe-mode     - Toggle live quarantine enforcement")
                    print("  exit          - Exit the copilot session\n")
                    print("[Policy Notes]")
                    print("  - Trusted domains are allowed by default when matched in the policy file.")
                    print("  - Blocked destinations trigger immediate suspicion.")
                    print("  - Use 'policy' to manage your allowlist/denylist from the CLI.")
                    print("  - Use 'safe-mode' to disable live quarantine actions during testing.\n")
                elif command == "status":
                    self.show_system_status()
                elif command == "show-policy":
                    self.show_network_policy()
                elif command == "reload-policy":
                    self.reload_network_policy()
                elif command == "safe-mode":
                    self.toggle_safe_mode()
                elif command == "policy-help":
                    self.show_policy_help()
                elif command in {"add-white", "add-black"}:
                    list_type = "whitelist" if command == "add-white" else "blacklist"
                    value = input("  Enter destination to add: ").strip()
                    self.add_policy_entry(list_type, value)
                elif command in {"remove-white", "remove-black"}:
                    list_type = "whitelist" if command == "remove-white" else "blacklist"
                    value = input("  Enter destination to remove: ").strip()
                    self.remove_policy_entry(list_type, value)
                elif command == "policy":
                    print("\n[POLICY MENU]")
                    print("  1) Show policy")
                    print("  2) Reload policy")
                    print("  3) Add to allowlist")
                    print("  4) Add to denylist")
                    print("  5) Remove from allowlist")
                    print("  6) Remove from denylist")
                    print("  7) Toggle safe mode")
                    print("  8) Back")
                    while True:
                        choice = input("ghost-copilot:policy> ").strip().lower()
                        if choice in {"8", "back", "exit"}:
                            break
                        elif choice in {"1", "show", "show-policy"}:
                            self.show_network_policy()
                        elif choice in {"2", "reload", "reload-policy"}:
                            self.reload_network_policy()
                        elif choice in {"3", "allow", "add-white"}:
                            value = input("  Enter destination to allow: ").strip()
                            self.add_policy_entry("whitelist", value)
                        elif choice in {"4", "deny", "add-black"}:
                            value = input("  Enter destination to block: ").strip()
                            self.add_policy_entry("blacklist", value)
                        elif choice in {"5", "remove-allow", "remove-white"}:
                            value = input("  Enter destination to remove from allowlist: ").strip()
                            self.remove_policy_entry("whitelist", value)
                        elif choice in {"6", "remove-deny", "remove-black"}:
                            value = input("  Enter destination to remove from denylist: ").strip()
                            self.remove_policy_entry("blacklist", value)
                        elif choice in {"7", "safe", "safe-mode"}:
                            self.toggle_safe_mode()
                        else:
                            print("  [!] Invalid policy menu choice.\n")
                elif command == "logs":
                    self.read_audit_logs(lines=8)
                elif command == "policy-audit":
                    self.read_policy_audit_logs(lines=15)
                elif command == "scan":
                    print("\n[+] Initiating live process sweep...")
                    try:
                        from process_scanner import scan_live_processes
                        events = scan_live_processes(risk_threshold=0.3)
                        print(f"[+] Scan Complete: Flagged {len(events)} elevated-risk events.")
                        for ev in events:
                            print(f"  -> PID {ev.details['pid']} | {ev.process_name} | Risk Score: {ev.risk_score}")
                        print()
                    except ImportError:
                        print("  [!] process_scanner.py not found in directory.\n")
                elif command == "analyze":
                    print("\n[+] Injecting simulated malicious telemetry...")
                    sim_event = TelemetryEvent(
                        "powershell.exe", 
                        {
                            "parent_process": "winword.exe",
                            "is_critical": True,
                            "network_connections": [{"port": 4444, "ip": "92.223.96.6"}],
                            "high_entropy": True
                        }
                    )
                    result = self._run_coroutine_safely(self.analyze_threat(sim_event))
                    print(f"\n[COPILOT VERDICT] {result['verdict']} (Confidence: {result['confidence']})")
                    print(f"[ACTION] {result['recommended_action']}")
                    print(f"[SUMMARY] {result['summary']}\n")
                else:
                    print("\n[Ghost Aegis Analyst] Command not recognized.\n")
            except (KeyboardInterrupt, EOFError):
                print("\n[!] Session interrupted. Exiting Copilot.")
                break

if __name__ == "__main__":
    copilot = GhostAegisCopilot()
    copilot.run_cli()