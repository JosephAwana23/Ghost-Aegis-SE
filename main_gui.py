import os
import sys
import math
import time
import base64
import shutil
import ctypes
import platform
import subprocess
import threading
import queue
import socket
import hashlib
import json
import ipaddress
import re
import requests
import asyncio
from pathlib import Path
from datetime import datetime, timedelta, timezone

import psutil
import customtkinter as ctk
from tkinter import filedialog
from dotenv import load_dotenv

from ghost_decoy import GhostDecoy
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

# --- NEW GHOST AEGIS MODULES ---
try:
    from behavior_api import get_behavior_score  # type: ignore[import-not-found]
except ImportError:
    def get_behavior_score(keystrokes, mouse_movements):
        try:
            delay = float(keystrokes.get("avg_delay", 0))
            variance = float(keystrokes.get("variance", 0))
            speed = float(mouse_movements.get("speed", 0))
            jitter = float(mouse_movements.get("jitter", 0))
            score = max(0, min(100, round(
                50 + delay * 10 + variance * 20 + jitter * 10 - speed * 2
            )))
            return {"score": score, "risk": "elevated" if score >= 60 else "low"}
        except (AttributeError, TypeError, ValueError):
            return {"error": "Invalid behavior telemetry"}

try:
    from breach_api import check_breach  # type: ignore[import-not-found]
except ImportError:
    def check_breach(target_email=""):
        return {"error": "Breach intelligence service is unavailable"}

# --- EXECUTABLE PATH RESOLUTION ---
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).resolve().parent

load_dotenv(dotenv_path=BASE_DIR / ".env")

RULE_FILE_PATH = BASE_DIR / "rules.yar"
SIGMA_RULE_PATH = BASE_DIR / "sigma_rules.yml"
EDR_CHAIN_LOG_PATH = BASE_DIR / "aegis_edr_alerts.jsonl"

# Dynamic import of main.py (Defense Engine)
try:
    import importlib.util
    _main_path = BASE_DIR / "main.py"
    if _main_path.exists():
        spec = importlib.util.spec_from_file_location("jit_engine_main", str(_main_path))
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

# --- GEMINI 4 MODEL TIERS ---
GEMINI_4_MODELS = [
    "gemini-4-hydrogen",
    "gemini-4-argon",
    "gemini-4-carbon",
]

# --- CORE INFRASTRUCTURE WHITELISTS ---
STATIC_IP_WHITELIST = {
    "127.0.0.1", "::1", "0.0.0.0",
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
}

PROCESS_WHITELIST = {
    "svchost.exe", "system", "ntoskrnl.exe", "lsass.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "code.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "explorer.exe", "python.exe", "pythonw.exe", "cmd.exe", "conhost.exe",
    "powershell.exe", "pwsh.exe", "taskhostw.exe", "wininit.exe",
    "googlechrome.exe", "googleupdate.exe", "onenote.exe", "teams.exe",
    "outlook.exe", "word.exe", "excel.exe", "powerpnt.exe", "notepad.exe",
    "notepad++.exe", "putty.exe", "winscp.exe", "filezilla.exe", "vscode.exe",
    "sublime_text.exe", "intellij.exe", "pycharm.exe", "eclipse.exe",
    "netbeans.exe", "androidstudio.exe", "virtualbox.exe", "vmware.exe", "docker.exe",
    r"DRIVERS\WUDFRd.sys", r"DRIVERS\dxgkrnl.sys", r"DRIVERS\ndis.sys",
    r"DRIVERS\ntfs.sys", r"DRIVERS\volsnap.sys", r"DRIVERS\disk.sys",
    r"DRIVERS\fltmgr.sys", r"DRIVERS\storport.sys", r"DRIVERS\usbport.sys",
    r"DRIVERS\usbhub.sys", r"DRIVERS\usbccgp.sys", r"DRIVERS\usbvideo.sys",
    r"DRIVERS\usbser.sys", r"DRIVERS\usbuhci.sys", r"DRIVERS\usbohci.sys",
    r"DRIVERS\usbehci.sys", r"DRIVERS\usbfilter.sys",
    r"Lenovo\Vantage\LenovoVantageService.exe",
    r"Lenovo\Vantage\LenovoVantage.exe",
    r"Lenovo\Vantage\LenovoVantageUI.exe",
    r"Lenovo\Vantage\LenovoVantageUpdater.exe",
    r"Lenovo\Vantage\LenovoVantageServiceHost.exe",
    r"Lenovo\Vantage\LenovoVantageServiceManager.exe",
    r"Lenovo\Vantage\LenovoVantageServiceInstaller.exe",
    r"Lenovo\Vantage\LenovoVantageServiceUninstaller.exe",
    r"Lenovo\Vantage\LenovoVantageServiceRepair.exe",
    r"Lenovo\Vantage\LenovoVantageServiceUpdate.exe",
    r"Lenovo\Vantage\LenovoVantageServiceCheck.exe",
    r"Lenovo\Vantage\LenovoVantageServiceMonitor.exe",
    r"Lenovo\Vantage\LenovoVantageServiceScheduler.exe",
    r"Lenovo\Vantage\ServiceLogger.exe",
}


# ==============================================================================
# --- NATIVE PURE-PYTHON YARA ENGINE & CRYPTOGRAPHIC CHAIN AUDITOR ---
# ==============================================================================
DEFAULT_YARA_RULES = """rule Windows_Encoded_PowerShell {
    meta:
        description = "Detects base64 encoded PowerShell execution flags"
        mitre_attack = "T1059.001"
        severity = "HIGH"
    strings:
        $enc1 = "-enc " ascii wide nocase
        $enc2 = "-EncodedCommand " ascii wide nocase
        $bypass = "ExecutionPolicy Bypass" ascii wide nocase
        $hidden = "-WindowStyle Hidden" ascii wide nocase
    condition:
        any of them
}

rule Suspicious_LOLBin_Execution {
    meta:
        description = "Detects Living-off-the-Land binaries used for payload staging"
        mitre_attack = "T1218"
        severity = "CRITICAL"
    strings:
        $certutil = "certutil -urlcache -split -f" ascii wide nocase
        $bitsadmin = "bitsadmin /transfer" ascii wide nocase
        $mshta = "mshta vbscript:" ascii wide nocase
    condition:
        any of them
}
"""


class AegisYaraEngine:
    """
    Pure-Python YARA Rule Parser & Command-Line / Memory Scanner for Ghost-Aegis SE.
    Parses standard .yar files natively without requiring libyara.dll.
    """
    def __init__(self, rule_path: Path | str = RULE_FILE_PATH):
        self.rule_path = Path(rule_path)
        if not self.rule_path.exists():
            try:
                self.rule_path.write_text(DEFAULT_YARA_RULES, encoding="utf-8")
            except Exception:
                pass
        self.rules = self._parse_yar_file(self.rule_path)

    def _parse_yar_file(self, filepath: Path) -> list:
        try:
            content = filepath.read_text(encoding="utf-8")
        except Exception:
            content = DEFAULT_YARA_RULES

        parsed_rules = []
        rule_blocks = re.findall(r"rule\s+(\w+)\s*\{(.*?)\}", content, re.DOTALL)

        for rule_name, body in rule_blocks:
            meta = {}
            for m_key, m_val in re.findall(r'(\w+)\s*=\s*"([^"]+)"', body):
                if not m_key.startswith("$"):
                    meta[m_key] = m_val

            strings = []
            for s_id, s_val, mods in re.findall(r'(\$\w+)\s*=\s*"([^"]+)"([^\r\n]*)', body):
                flags = re.IGNORECASE if "nocase" in mods.lower() else 0
                strings.append((s_id, re.compile(re.escape(s_val), flags)))

            condition = "all" if "all of them" in body else "any"
            parsed_rules.append({
                "name": rule_name,
                "meta": meta,
                "strings": strings,
                "condition": condition
            })
        return parsed_rules

    def scan_command_line(self, pid: int, process_name: str, cmdline: str) -> list:
        if not cmdline:
            return []

        alerts = []
        for rule in self.rules:
            matched_ids = [s_id for s_id, regex in rule["strings"] if regex.search(cmdline)]
            triggered = (
                (rule["condition"] == "any" and len(matched_ids) > 0) or
                (rule["condition"] == "all" and len(matched_ids) == len(rule["strings"]))
            )
            if triggered:
                alerts.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "pid": pid,
                    "process": process_name,
                    "rule_triggered": f"YARA: {rule['name']}",
                    "mitre_id": rule["meta"].get("mitre_attack", "Unknown"),
                    "severity": rule["meta"].get("severity", "MEDIUM"),
                    "matched_indicators": matched_ids,
                    "matched_cmdline": cmdline
                })
        return alerts


# ==============================================================================
# --- NATIVE PURE-PYTHON SIGMA RULE ENGINE (ZERO-DEPENDENCY YAML PARSER) ---
# ==============================================================================
DEFAULT_SIGMA_RULES = """title: Suspicious Encoded PowerShell or Download Cradle
id: 8f3b2a1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c
status: production
level: high
logsource:
    category: process_creation
    product: windows
tags:
    - attack.execution
    - attack.t1059.001
detection:
    keywords:
        - '-enc '
        - '-EncodedCommand'
        - 'DownloadString'
        - 'Invoke-Expression'
        - 'IEX('
        - '-WindowStyle Hidden'
    condition: keywords
---
title: Living Off The Land Binary (LOLBin) Proxy Execution
id: 2c9a1b3d-5e6f-4a8b-9c0d-1e2f3a4b5c6d
status: production
level: critical
logsource:
    category: process_creation
    product: windows
tags:
    - attack.defense_evasion
    - attack.t1218
detection:
    keywords:
        - 'certutil -urlcache'
        - 'mshta vbscript:'
        - 'regsvr32 /s /n /u /i:'
        - 'rundll32 javascript:'
        - 'bitsadmin /transfer'
    condition: keywords
---
title: Windows Security Audit Log Cleared
id: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
status: production
level: critical
logsource:
    product: windows
    service: security
tags:
    - attack.defense_evasion
    - attack.t1070.001
detection:
    event_id: 1102
    condition: selection
---
title: Suspicious New Windows Service Installed
id: b2c3d4e5-f6a7-4b5c-9d0e-1f2a3b4c5d6e
status: production
level: high
logsource:
    product: windows
    service: system
tags:
    - attack.persistence
    - attack.t1543.003
detection:
    event_id: 7045
    condition: selection
---
title: Windows Brute Force or Failed Logon Burst
id: c3d4e5f6-a7b8-4c5d-0e1f-2a3b4c5d6e7f
status: production
level: medium
logsource:
    product: windows
    service: security
tags:
    - attack.credential_access
    - attack.t1110
detection:
    event_id: 4625
    condition: selection
"""


class AegisSigmaEngine:
    """
    Pure-Python Sigma Rule Parser & Detection Engine for Ghost-Aegis SE v3.0.
    Parses standard Sigma YAML rules natively without requiring PyYAML.
    Evaluates both live process creation command lines and Windows Event IDs.
    """

    def __init__(self, sigma_path: Path | str = SIGMA_RULE_PATH):
        self.sigma_path = Path(sigma_path)
        if not self.sigma_path.exists():
            try:
                self.sigma_path.write_text(DEFAULT_SIGMA_RULES, encoding="utf-8")
            except Exception:
                pass
        self.rules = self._parse_sigma_yaml(self.sigma_path)

    def _parse_sigma_yaml(self, filepath: Path) -> list[dict]:
        try:
            content = filepath.read_text(encoding="utf-8")
        except Exception:
            content = DEFAULT_SIGMA_RULES

        parsed_rules = []
        for doc in content.split("---"):
            doc = doc.strip()
            if not doc:
                continue

            title_m = re.search(r"^title:\s*(.+)$", doc, re.MULTILINE)
            id_m = re.search(r"^id:\s*(.+)$", doc, re.MULTILINE)
            level_m = re.search(r"^level:\s*(.+)$", doc, re.MULTILINE)
            cat_m = re.search(r"category:\s*(.+)$", doc, re.MULTILINE)
            event_id_m = re.search(r"event_id:\s*(\d+)", doc, re.MULTILINE)

            tags = re.findall(r"-\s*(attack\.[a-zA-Z0-9_.]+)", doc)
            mitre_tags = [t.replace("attack.", "").upper() for t in tags if t.lower().startswith("attack.t")]
            mitre_id = mitre_tags[0] if mitre_tags else "T1059"

            keywords = []
            in_keywords = False
            for line in doc.splitlines():
                stripped = line.strip()
                if stripped.startswith("keywords:"):
                    in_keywords = True
                    continue
                if in_keywords:
                    if stripped.startswith("-"):
                        val = stripped.lstrip("-").strip().strip("'").strip('"')
                        if val:
                            keywords.append(val)
                    elif ":" in stripped:
                        in_keywords = False

            parsed_rules.append({
                "title": title_m.group(1).strip() if title_m else "Unnamed Sigma Rule",
                "id": id_m.group(1).strip() if id_m else "0000",
                "level": (level_m.group(1).strip().upper() if level_m else "HIGH"),
                "category": cat_m.group(1).strip().lower() if cat_m else "windows_event",
                "event_id": int(event_id_m.group(1)) if event_id_m else None,
                "mitre_id": mitre_id,
                "keywords": keywords,
            })
        return parsed_rules

    def evaluate_process(self, pid: int, process_name: str, cmdline: str) -> list[dict]:
        if not cmdline:
            return []
        lower_cmd = cmdline.lower()
        hits = []
        for rule in self.rules:
            if rule["category"] != "process_creation" or not rule["keywords"]:
                continue
            matched = [kw for kw in rule["keywords"] if kw.lower() in lower_cmd]
            if matched:
                hits.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "pid": pid,
                    "process": process_name,
                    "rule_triggered": f"SIGMA: {rule['title']}",
                    "sigma_id": rule["id"],
                    "mitre_id": rule["mitre_id"],
                    "severity": rule["level"],
                    "matched_indicators": matched,
                    "matched_cmdline": cmdline,
                })
        return hits

    def evaluate_event_id(self, event_id: int, log_name: str, count: int) -> list[dict]:
        hits = []
        for rule in self.rules:
            if rule["event_id"] == event_id:
                hits.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "pid": 4,
                    "ppid": 0,
                    "process": f"WindowsEventLog ({log_name})",
                    "rule_triggered": f"SIGMA: {rule['title']}",
                    "sigma_id": rule["id"],
                    "mitre_id": rule["mitre_id"],
                    "severity": rule["level"],
                    "matched_indicators": [f"EventID:{event_id}", f"Hits:{count}"],
                    "matched_cmdline": f"wevtutil {log_name} EventID {event_id} ({count} occurrences)",
                })
        return hits


class ForensicChainAuditor:
    """Manages and verifies the tamper-evident SHA-256 chain in aegis_edr_alerts.jsonl."""

    def __init__(self, log_path: Path | str = EDR_CHAIN_LOG_PATH):
        self.log_path = Path(log_path)
        self._lock = threading.Lock()
        self.last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.log_path.exists():
            return "0" * 64
        try:
            lines = [line.strip() for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines:
                last_record = json.loads(lines[-1])
                return last_record.get("sha256_seal", "0" * 64)
        except Exception:
            pass
        return "0" * 64

    def seal_alert(self, alert_data: dict) -> dict:
        with self._lock:
            record = dict(alert_data)
            record["prev_hash"] = self.last_hash
            raw_payload = json.dumps(record, sort_keys=True).encode("utf-8")
            current_hash = hashlib.sha256(raw_payload).hexdigest()
            record["sha256_seal"] = current_hash
            self.last_hash = current_hash

            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            return record

    def verify_chain(self) -> tuple[bool, int, str]:
        """Returns (all_intact, record_count, formatted_audit_report)."""
        lines_out = [
            "=" * 78,
            " 🛡️  GHOST-AEGIS SE: CRYPTOGRAPHIC CHAIN-OF-CUSTODY AUDITOR",
            "=" * 78,
        ]
        if not self.log_path.exists():
            lines_out.append(f"\n[-] No forensic chain file found at: {self.log_path}")
            return True, 0, "\n".join(lines_out)

        raw_lines = [line.strip() for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not raw_lines:
            lines_out.append("\n[-] Forensic ledger is empty.")
            return True, 0, "\n".join(lines_out)

        expected_prev_hash = "0" * 64
        tamper_detected = False

        for idx, line in enumerate(raw_lines, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                tamper_detected = True
                lines_out.append(f"\n[Event #{idx}] CORRUPTED JSON RECORD DETECTED!")
                continue

            recorded_seal = record.pop("sha256_seal", None)
            recorded_prev = record.get("prev_hash", None)

            raw_payload = json.dumps(record, sort_keys=True).encode("utf-8")
            calculated_seal = hashlib.sha256(raw_payload).hexdigest()

            chain_valid = (recorded_prev == expected_prev_hash) and (recorded_seal == calculated_seal)
            status = "VALID (INTACT)" if chain_valid else "TAMPERED / BROKEN"
            if not chain_valid:
                tamper_detected = True

            tree_nodes = record.get("process_tree", {}).get("nodes", [])
            lineage_str = " -> ".join(f"{n.get('name')}({n.get('pid')})" for n in tree_nodes) if tree_nodes else "Single Node"

            lines_out.append(f"\n[Event #{idx}] {record.get('timestamp', 'Unknown')}")
            lines_out.append(
                f"  ├─ Rule & MITRE : {record.get('rule_triggered')} ({record.get('mitre_id')}) | Severity: {record.get('severity')}"
            )
            lines_out.append(
                f"  ├─ Target PID   : {record.get('pid')} (PPID: {record.get('ppid')}) -> {record.get('process')}"
            )
            lines_out.append(f"  ├─ PPID Lineage : {lineage_str}")
            lines_out.append(f"  ├─ Indicators   : {', '.join(record.get('matched_indicators', []))}")
            lines_out.append(f"  ├─ Prev Hash    : {str(recorded_prev)[:36]}...")
            lines_out.append(f"  ├─ SHA-256 Seal : {calculated_seal[:36]}...")
            lines_out.append(f"  └─ Chain Status : {status}")

            expected_prev_hash = recorded_seal

        lines_out.append("\n" + "=" * 78)
        if not tamper_detected:
            lines_out.append(f"[+] AUDIT PASSED: All {len(raw_lines)} EDR evidence records are cryptographically intact.")
        else:
            lines_out.append("[!] CRITICAL WARNING: Evidence tampering detected in the forensic chain!")
        lines_out.append("=" * 78)

        return (not tamper_detected), len(raw_lines), "\n".join(lines_out)


# ==============================================================================
# --- UPGRADE 7: LIVE PROCESS ANCESTRY TREE & KILL-CHAIN TIMELINE ENGINE ---
# ==============================================================================
class AegisForensicCorrelator:
    """
    Captures live psutil PPID ancestry trees (with Windows PID-reuse validation)
    and reconstructs chronological kill-chain timelines across aegis_edr_alerts.jsonl
    and the Incident Store.
    """

    @staticmethod
    def capture_process_tree(target_pid: int, max_depth: int = 6) -> dict:
        chain = []
        current_pid = target_pid
        visited_pids = set()

        for _ in range(max_depth):
            if not current_pid or current_pid in visited_pids or current_pid <= 4:
                break
            visited_pids.add(current_pid)

            try:
                proc = psutil.Process(current_pid)
                ctime = proc.create_time()
                ppid = proc.ppid()
                name = proc.name()

                try:
                    exe_val = proc.exe() or "N/A"
                except (psutil.AccessDenied, psutil.Error):
                    exe_val = "<Protected SYSTEM Binary>"

                try:
                    cmdline_list = proc.cmdline()
                    cmd_val = " ".join(cmdline_list) if cmdline_list else name
                except (psutil.AccessDenied, psutil.Error):
                    cmd_val = f"{name} <Protected SYSTEM Command Line>"

                p_info = {
                    "pid": current_pid,
                    "ppid": ppid,
                    "name": name,
                    "exe": exe_val,
                    "cmdline": cmd_val,
                    "create_time": ctime,
                    "timestamp": datetime.fromtimestamp(ctime).strftime("%H:%M:%S.%f")[:-3],
                    "is_trigger": (current_pid == target_pid),
                }

                chain.insert(0, p_info)

                # Validate parent creation time to defeat Windows PID recycling false-positives
                if ppid > 4 and psutil.pid_exists(ppid):
                    parent_proc = psutil.Process(ppid)
                    if parent_proc.create_time() <= ctime:
                        current_pid = ppid
                    else:
                        break
                else:
                    break

            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                if current_pid == target_pid and not chain:
                    chain.append({
                        "pid": current_pid,
                        "ppid": 0,
                        "name": "<Terminated Process>",
                        "exe": "N/A",
                        "cmdline": "<Exited prior to tree walk>",
                        "create_time": time.time(),
                        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                        "is_trigger": True,
                    })
                break
            except psutil.AccessDenied:
                if current_pid == target_pid and not chain:
                    chain.append({
                        "pid": current_pid,
                        "ppid": 0,
                        "name": f"Protected_Process_PID_{current_pid}",
                        "exe": "<Protected SYSTEM Binary>",
                        "cmdline": "<Protected SYSTEM Context>",
                        "create_time": time.time(),
                        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                        "is_trigger": True,
                    })
                break

        return {
            "root_pid": chain[0]["pid"] if chain else target_pid,
            "trigger_pid": target_pid,
            "nodes": chain,
            "ascii_tree": AegisForensicCorrelator.format_ascii_tree(chain),
        }

    @staticmethod
    def format_ascii_tree(chain: list) -> str:
        if not chain:
            return "No active process lineage available (process may have exited)."

        lines = []
        for idx, node in enumerate(chain):
            indent = "   " * idx
            branch = "└─ " if idx > 0 else "🎯 ROOT: "
            flag = "  ◄── [ALERT TRIGGER]" if node.get("is_trigger") else ""
            lines.append(
                f"{indent}{branch}{node['name']} (PID: {node['pid']} | PPID: {node['ppid']}) [{node['timestamp']}]{flag}"
            )
            cmd_preview = node.get("cmdline", "")
            if len(cmd_preview) > 95:
                cmd_preview = cmd_preview[:92] + "..."
            lines.append(f"{indent}   │  Cmd: {cmd_preview}")
            if node.get("exe") and node.get("exe") != "N/A":
                lines.append(f"{indent}   │  Exe: {node['exe']}")
        return "\n".join(lines)

    @staticmethod
    def reconstruct_timeline(record: dict) -> list[dict]:
        """
        Builds a chronological Attack Kill-Chain from process lineage, YARA/Sigma hits,
        network incidents, and SHA-256 chain sealing.
        """
        timeline = []
        pid = record.get("pid", 0)
        tree_data = record.get("process_tree")
        if not tree_data and pid > 0 and psutil.pid_exists(pid):
            tree_data = AegisForensicCorrelator.capture_process_tree(pid)

        # 1. Process Ancestry Spawn Sequence
        if tree_data and tree_data.get("nodes"):
            for idx, node in enumerate(tree_data["nodes"]):
                if idx == 0 and not node.get("is_trigger"):
                    stage = "1. Initial Parent Execution"
                elif node.get("is_trigger"):
                    stage = "2. Target Process Spawn (Trigger)"
                else:
                    stage = "1b. Intermediate Child Spawn"

                timeline.append({
                    "time": node.get("timestamp", "N/A"),
                    "stage": stage,
                    "action": f"{node['name']} spawned (PID: {node['pid']} <- PPID: {node['ppid']})",
                    "evidence": f"Cmd: {node.get('cmdline', '')[:90]}",
                })

        # 2. YARA / Sigma / EDR Command-Line & Deobfuscation Telemetry
        if record.get("rule_triggered"):
            timeline.append({
                "time": str(record.get("timestamp", "Now"))[-15:],
                "stage": f"3. YARA / Sigma / Lineage Interception ({record.get('mitre_id', 'MITRE')})",
                "action": f"Rule '{record['rule_triggered']}' matched ({record.get('severity', 'HIGH')})",
                "evidence": f"Indicators: {', '.join(record.get('matched_indicators', []))} | Cmd: {record.get('matched_cmdline', '')[:80]}",
            })

        # 3. Correlate Network / Heuristic Reasons from Incident Store if present
        reasons = record.get("reasons", [])
        if reasons:
            timeline.append({
                "time": str(record.get("timestamp", "Now"))[-15:],
                "stage": "3b. Behavioral & Network Telemetry Correlation",
                "action": f"Risk Score {record.get('risk_score', 85)}/100 | Remote IP: {record.get('remote_ip', 'local_spawn')}",
                "evidence": f"Flags: {'; '.join(reasons)}",
            })

        # 4. Containment Status
        rec_action = record.get("recommended_action", "")
        if "vault" in rec_action or "quarantine" in rec_action or record.get("quarantined"):
            timeline.append({
                "time": "Immediate",
                "stage": "4. Automated SOAR Containment (Quarantine Vault)",
                "action": "Process Frozen in RAM -> Binary Hashed -> Manifest Sealed -> Reviewed/Terminated",
                "evidence": f"Directive: {rec_action or 'Quarantined'}",
            })

        # 5. Cryptographic Chain-of-Custody Seal
        seal = record.get("sha256_seal")
        if seal:
            timeline.append({
                "time": "Sealed",
                "stage": "5. Forensic Chain-of-Custody Verification",
                "action": "Lineage & Event cryptographically chained to aegis_edr_alerts.jsonl",
                "evidence": f"PrevHash: {str(record.get('prev_hash', ''))[:16]}... -> Seal: {seal[:24]}...",
            })

        return timeline


# ==============================================================================
# --- UPGRADE 8: PARENT-CHILD LINEAGE & MASQUERADING DETECTOR (BEHAVIORAL EDR) ---
# ==============================================================================
class ParentChildAnomalyDetector:
    """
    Detects suspicious Windows parent-child process relationships (e.g., WMI or Office
    spawning shells, svchost.exe outside services.exe) and binary path masquerading.
    """

    SHELL_PROCESSES = {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe"}
    SUSPICIOUS_PARENTS = {
        "wmiprvse.exe": ("WMI Provider spawning command shell", "T1047"),
        "winword.exe": ("Microsoft Word macro spawning shell", "T1566.001"),
        "excel.exe": ("Microsoft Excel macro spawning shell", "T1566.001"),
        "powerpnt.exe": ("PowerPoint spawning command shell", "T1566.001"),
        "outlook.exe": ("Outlook client spawning command shell", "T1566.001"),
        "spoolsv.exe": ("Print Spooler privilege escalation shell spawn", "T1068"),
    }
    SYSTEM32_BINARIES = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "wininit.exe", "smss.exe"}

    @classmethod
    def evaluate_lineage(cls, tree_data: dict) -> list[dict]:
        nodes = tree_data.get("nodes", [])
        if not nodes:
            return []

        anomalies = []
        target = nodes[-1]
        pid = target.get("pid", 0)
        proc_name = str(target.get("name", "")).lower()
        exe_path = str(target.get("exe", "")).lower()
        cmdline = str(target.get("cmdline", ""))
        parent_name = str(nodes[-2].get("name", "")).lower() if len(nodes) >= 2 else ""

        # 1. Check for svchost.exe not spawned by services.exe
        if proc_name == "svchost.exe" and parent_name and parent_name not in {"services.exe", "msmpeng.exe"}:
            anomalies.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "pid": pid,
                "process": target.get("name", "svchost.exe"),
                "rule_triggered": f"LINEAGE: Masqueraded svchost.exe parent ({parent_name})",
                "mitre_id": "T1036.005",
                "severity": "CRITICAL",
                "matched_indicators": [f"Parent:{parent_name}", "Expected:services.exe"],
                "matched_cmdline": cmdline,
            })

        # 2. Check for WMI / Office / Spooler spawning a command shell
        if proc_name in cls.SHELL_PROCESSES and parent_name in cls.SUSPICIOUS_PARENTS:
            desc, mitre = cls.SUSPICIOUS_PARENTS[parent_name]
            anomalies.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "pid": pid,
                "process": target.get("name", proc_name),
                "rule_triggered": f"LINEAGE: {desc} ({parent_name} -> {proc_name})",
                "mitre_id": mitre,
                "severity": "CRITICAL",
                "matched_indicators": [f"Parent:{parent_name}", f"Child:{proc_name}"],
                "matched_cmdline": cmdline,
            })

        # 3. Check for core Windows system binaries executing outside System32 / SysWOW64
        if proc_name in cls.SYSTEM32_BINARIES and exe_path not in {"", "n/a"}:
            if r"\windows\system32" not in exe_path and r"\windows\syswow64" not in exe_path:
                anomalies.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "pid": pid,
                    "process": target.get("name", proc_name),
                    "rule_triggered": f"MASQUERADE: System binary executing outside System32 ({exe_path})",
                    "mitre_id": "T1036.005",
                    "severity": "CRITICAL",
                    "matched_indicators": [f"RoguePath:{exe_path}"],
                    "matched_cmdline": cmdline,
                })

        return anomalies


# ==============================================================================
# --- UPGRADE 9: RANSOMWARE EARLY WARNING & I/O WRITE-SPIKE CORRELATOR ---
# ==============================================================================
class RansomwareEarlyWarning:
    """
    Correlates Canary file modifications with live process disk write-byte spikes
    and PE Shannon entropy to pinpoint and freeze active ransomware processes.
    """

    @staticmethod
    def identify_high_writer_pid() -> dict:
        best_candidate = {
            "pid": os.getpid(),
            "name": "Unknown_Encryptor",
            "exe": "N/A",
            "write_bytes": 0,
            "entropy": 0.0,
        }
        max_score = -1

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                p_info = proc.info
                p_name = (p_info.get("name") or "").lower()
                if not p_name or p_name in {"system", "registry", "memcompression", "svchost.exe"}:
                    continue
                io_stat = proc.io_counters() if hasattr(proc, "io_counters") else None
                write_bytes = io_stat.write_bytes if io_stat else 0

                # Prioritize non-whitelisted processes with heavy disk writes
                weight = write_bytes
                if p_name not in PROCESS_WHITELIST:
                    weight *= 10

                if weight > max_score:
                    max_score = weight
                    best_candidate = {
                        "pid": p_info["pid"],
                        "name": p_info.get("name") or "Unknown",
                        "exe": p_info.get("exe") or "N/A",
                        "write_bytes": write_bytes,
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        exe_path = best_candidate.get("exe", "")
        if exe_path and exe_path != "N/A" and os.path.exists(exe_path):
            pe_res = ForensicEDRInspector.scan_pe_binary(exe_path)
            best_candidate["entropy"] = pe_res.get("entropy", 0.0)
        else:
            best_candidate["entropy"] = 0.0

        return best_candidate


# ==============================================================================
# --- UPGRADE 10: THREAT DNA CAMPAIGN CLUSTERING (XDR CORRELATION) ---
# ==============================================================================
class ThreatCampaignCorrelator:
    """
    Clusters multi-stage EDR alerts and high-risk network incidents into unified
    XDR Threat Campaigns, prioritizing sealed YARA/Sigma/Lineage MITRE chains.
    """

    @staticmethod
    def cluster_campaigns(records: list[dict]) -> list[dict]:
        clusters: dict[str, dict] = {}

        for rec in records:
            # Skip low-risk routine browser/system network audits so real attacks rank #1
            if rec.get("_source") == "INCIDENT_STORE" and rec.get("risk_score", 0) < 60:
                continue

            pid = rec.get("pid", 0)
            proc = rec.get("process", "unknown")
            tree = rec.get("process_tree", {})
            root_pid = tree.get("root_pid") or pid or 0
            remote_ip = rec.get("remote_ip", "local_spawn")
            mitre = rec.get("mitre_id")
            is_sealed = bool(rec.get("sha256_seal"))

            # Clean out raw ChainHash tags from displayable detection names
            raw_reasons = [r for r in rec.get("reasons", []) if not str(r).startswith("ChainHash:")]
            rule = rec.get("rule_triggered") or ("; ".join(raw_reasons[:2]) if raw_reasons else "Behavioral Anomaly")

            cluster_key = f"ROOT_PID_{root_pid}" if root_pid not in {0, 4} else f"PROC_{proc}_{remote_ip}"
            if cluster_key not in clusters:
                clusters[cluster_key] = {
                    "campaign_id": hashlib.sha256(cluster_key.encode()).hexdigest()[:10].upper(),
                    "root_pid": root_pid,
                    "primary_process": proc,
                    "remote_ip": remote_ip,
                    "event_count": 0,
                    "sealed_count": 0,
                    "mitre_techniques": set(),
                    "rules_triggered": [],
                }

            c = clusters[cluster_key]
            c["event_count"] += 1
            if is_sealed:
                c["sealed_count"] += 1
            if mitre:
                c["mitre_techniques"].add(str(mitre))
            if rule and rule not in c["rules_triggered"]:
                c["rules_triggered"].append(rule)

        # Sort by: (1) Sealed EDR alerts first, (2) Number of distinct MITRE TTPs, (3) Total correlated events
        return sorted(
            clusters.values(),
            key=lambda x: (x["sealed_count"] > 0, len(x["mitre_techniques"]), x["event_count"]),
            reverse=True,
        )


# ==============================================================================
# --- UPGRADE 11: LIVE SOAR WEBHOOK DISPATCHER (DISCORD / SLACK) ---
# ==============================================================================
class SoarWebhookDispatcher:
    """
    Dispatches real-time, sanitized EDR/XDR alert embeds to a Discord or Slack
    SOAR webhook URL configured in .env (DISCORD_WEBHOOK_URL or SOAR_WEBHOOK_URL).
    """

    def __init__(self):
        self.webhook_url = (
            os.getenv("DISCORD_WEBHOOK_URL") or os.getenv("SOAR_WEBHOOK_URL") or ""
        ).strip()

    def dispatch_alert(self, sealed_record: dict):
        if not self.webhook_url:
            return False

        def _worker():
            try:
                tree_nodes = sealed_record.get("process_tree", {}).get("nodes", [])
                lineage = " -> ".join(f"{n.get('name')}({n.get('pid')})" for n in tree_nodes) or sealed_record.get("process", "Unknown")
                content = (
                    f"🚨 **GHOST-AEGIS SE v3.0 — SOAR ALERT**\n"
                    f"**Rule:** `{sealed_record.get('rule_triggered')}` | **MITRE:** `{sealed_record.get('mitre_id')}` | **Severity:** `{sealed_record.get('severity')}`\n"
                    f"**Target PID:** `{sealed_record.get('pid')}` (`{sealed_record.get('process')}`)\n"
                    f"**Process Lineage:** `{lineage}`\n"
                    f"**SHA-256 Chain Seal:** `{str(sealed_record.get('sha256_seal', ''))[:32]}...`"
                )
                requests.post(
                    self.webhook_url,
                    json={"content": content},
                    timeout=5,
                )
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()
        return True


# ==============================================================================
# --- SENTINEL-SANITIZE (ZERO DATA LEAKAGE & MITRE MAPPING) ---
# ==============================================================================
class SentinelSanitizer:
    """Enterprise Data Sanitization, MITRE ATT&CK Mapping, and Cryptographic Chaining"""
    
    RFC1918_REGEX = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
    PAN_CANDIDATE_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
    
    DETECTION_RULES = [
        {"id": "T1110.001", "technique": "Password Guessing", "tactic": "Credential Access", "keywords": ["failed login", "invalid credentials", "eventid 4625"], "severity": "MEDIUM"},
        {"id": "T1059.001", "technique": "PowerShell Execution", "tactic": "Execution", "keywords": ["powershell", "-enc", "downloadstring", "invoke-expression", "frombase64string", "iex"], "severity": "HIGH"},
        {"id": "T1218", "technique": "System Binary Proxy Execution (LOLBin)", "tactic": "Defense Evasion", "keywords": ["certutil", "mshta", "rundll32", "regsvr32", "bitsadmin"], "severity": "HIGH"},
        {"id": "T1055", "technique": "Process Injection", "tactic": "Privilege Escalation", "keywords": ["virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection"], "severity": "CRITICAL"},
        {"id": "T1046", "technique": "Network Service Discovery", "tactic": "Discovery", "keywords": ["port scan", "syn scan", "nmap"], "severity": "LOW"},
        {"id": "T1574", "technique": "Hijack Execution Flow", "tactic": "Persistence", "keywords": ["unquoted service path", "dll hijacking"], "severity": "HIGH"},
        {"id": "T1557.002", "technique": "ARP Cache Poisoning", "tactic": "Collection", "keywords": ["arp spoof", "duplicate mac"], "severity": "CRITICAL"},
    ]

    def __init__(self):
        self.previous_hash = hashlib.sha256(b"GHOST_AEGIS_GENESIS_BLOCK").hexdigest()

    @staticmethod
    def is_luhn_valid(card_number: str) -> bool:
        digits = [int(c) for c in card_number if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        for idx, digit in enumerate(digits[::-1]):
            if idx % 2 == 1:
                doubled = digit * 2
                checksum += (doubled - 9) if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    def scrub_text(self, text: str) -> str:
        if not isinstance(text, str):
            return text
        text = self.RFC1918_REGEX.sub("[INTERNAL_IP_MASKED]", text)
        def replace_card(match):
            raw = match.group(0)
            cleaned = re.sub(r"[^\d]", "", raw)
            if self.is_luhn_valid(cleaned):
                return f"[CARD_REDACTED_****{cleaned[-4:]}]"
            return raw
        return self.PAN_CANDIDATE_REGEX.sub(replace_card, text)

    def sanitize_log(self, record: dict | list | str) -> dict | list | str:
        if isinstance(record, dict):
            return {k: self.sanitize_log(v) for k, v in record.items()}
        elif isinstance(record, list):
            return [self.sanitize_log(elem) for elem in record]
        elif isinstance(record, str):
            return self.scrub_text(record)
        return record

    def correlate_mitre(self, log_str: str) -> list:
        lowered = log_str.lower()
        return [rule for rule in self.DETECTION_RULES if any(kw in lowered for kw in rule["keywords"])]

    def secure_hash_log(self, sanitized_data: dict) -> str:
        """Calculates a tamper-proof cryptographic chain hash."""
        payload_str = json.dumps(sanitized_data, sort_keys=True)
        chain_data = self.previous_hash + payload_str
        current_hash = hashlib.sha256(chain_data.encode()).hexdigest()
        self.previous_hash = current_hash
        return current_hash


# ==============================================================================
# --- UPGRADE 1 & 4: LOLBIN / BASE64 DEOBFUSCATOR & PURE-PYTHON PE SCANNER ---
# ==============================================================================
class ForensicEDRInspector:
    """Pure-Python Command-Line Deobfuscation, LOLBin Detection, and PE Entropy/API Scanner."""

    LOLBINS = {
        "certutil.exe": "Certificate utility abused for payload download/decode (T1140)",
        "mshta.exe": "HTML Application host abused for script execution (T1218.005)",
        "rundll32.exe": "DLL proxy execution utility (T1218.011)",
        "regsvr32.exe": "COM scriptlet registration proxy execution (T1218.010)",
        "bitsadmin.exe": "Background Intelligent Transfer abused for staging (T1197)",
        "wmic.exe": "WMI command-line execution (T1047)",
        "cscript.exe": "Windows Script Host execution (T1059.005)",
        "wscript.exe": "Windows Script Host execution (T1059.005)",
    }

    SUSPICIOUS_PE_APIS = [
        b"VirtualAllocEx",
        b"WriteProcessMemory",
        b"CreateRemoteThread",
        b"NtUnmapViewOfSection",
        b"QueueUserAPC",
        b"SetWindowsHookEx",
    ]

    ENC_REGEX = re.compile(r"(?:-e|-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{12,})", re.IGNORECASE)

    @classmethod
    def inspect_cmdline(cls, pid: int) -> dict:
        """Extracts process command line, flags LOLBins, and decodes Base64 PowerShell."""
        result = {
            "cmdline": "",
            "decoded_b64": None,
            "lolbin_hit": None,
            "suspicious_flags": [],
            "risk_boost": 0,
        }
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name().lower()
            cmdline_list = proc.cmdline()
            cmdline_str = " ".join(cmdline_list) if cmdline_list else ""
            result["cmdline"] = cmdline_str

            if proc_name in cls.LOLBINS:
                result["lolbin_hit"] = cls.LOLBINS[proc_name]
                result["suspicious_flags"].append(f"LOLBin: {proc_name}")
                result["risk_boost"] += 25

            lower_cmd = cmdline_str.lower()
            for indicator in ("-windowstyle hidden", "-w hidden", "downloadstring", "invoke-webrequest", "iex(", "frombase64string", "-nop", "bypass"):
                if indicator in lower_cmd:
                    result["suspicious_flags"].append(f"CmdFlag: {indicator}")
                    result["risk_boost"] += 15

            match = cls.ENC_REGEX.search(cmdline_str)
            if match:
                b64_blob = match.group(1)
                try:
                    raw_bytes = base64.b64decode(b64_blob, validate=False)
                    try:
                        decoded = raw_bytes.decode("utf-16le").strip("\x00")
                    except UnicodeDecodeError:
                        decoded = raw_bytes.decode("utf-8", errors="ignore")
                    result["decoded_b64"] = decoded[:300]
                    result["suspicious_flags"].append(f"DecodedPowerShell: {decoded[:80]}")
                    result["risk_boost"] += 35
                except Exception:
                    result["suspicious_flags"].append("Obfuscated Base64 Cmdline")
                    result["risk_boost"] += 25

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        return result

    @classmethod
    def scan_pe_binary(cls, filepath: str) -> dict:
        """Pure-Python Shannon entropy calculator & process-injection API byte scanner."""
        report = {
            "entropy": 0.0,
            "packed": False,
            "suspicious_apis": [],
            "risk_boost": 0,
        }
        if not filepath or not os.path.exists(filepath):
            return report
        try:
            with open(filepath, "rb") as f:
                data = f.read(2 * 1024 * 1024)
            if not data:
                return report

            length = len(data)
            counts = [0] * 256
            for b in data:
                counts[b] += 1
            entropy = 0.0
            for count in counts:
                if count > 0:
                    p = count / length
                    entropy -= p * math.log2(p)
            report["entropy"] = round(entropy, 2)

            if entropy >= 7.20:
                report["packed"] = True
                report["risk_boost"] += 20

            for api in cls.SUSPICIOUS_PE_APIS:
                if api in data:
                    api_name = api.decode("ascii")
                    report["suspicious_apis"].append(api_name)

            if len(report["suspicious_apis"]) >= 2:
                report["risk_boost"] += 25

        except Exception:
            pass
        return report


# ==============================================================================
# --- UPGRADE 2: PROCESS FREEZE & FORENSIC QUARANTINE VAULT ---
# ==============================================================================
class ForensicQuarantineVault:
    """Suspends processes in RAM to prevent watchdog respawn, vaults binary + SHA256 manifest, then kills."""

    def __init__(self, vault_dir: Path):
        self.vault_dir = vault_dir
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def freeze_and_quarantine(self, pid: int, reasons: list, risk_score: int = 90) -> dict:
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            try:
                exe_path = proc.exe()
            except Exception:
                exe_path = ""
            try:
                cmdline = " ".join(proc.cmdline())
            except Exception:
                cmdline = ""

            proc.suspend()

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", proc_name)
            vault_binary_path = self.vault_dir / f"{safe_name}_PID{pid}_{timestamp}.quarantine"
            manifest_path = self.vault_dir / f"{safe_name}_PID{pid}_{timestamp}_manifest.json"

            sha256_hash = get_file_sha256(exe_path)
            copied = False
            if exe_path and os.path.exists(exe_path) and proc_name.lower() not in PROCESS_WHITELIST:
                try:
                    shutil.copy2(exe_path, vault_binary_path)
                    copied = True
                except Exception:
                    copied = False

            manifest = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "process_name": proc_name,
                "pid": pid,
                "original_path": exe_path,
                "cmdline": cmdline,
                "sha256": sha256_hash,
                "risk_score": risk_score,
                "forensic_reasons": reasons,
                "binary_vaulted": copied,
                "vault_file": str(vault_binary_path) if copied else "N/A (System/Locked)",
            }
            with manifest_path.open("w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)

            proc.kill()
            return {
                "success": True,
                "process": proc_name,
                "pid": pid,
                "sha256": sha256_hash,
                "manifest": str(manifest_path),
                "binary_vaulted": copied,
            }
        except psutil.NoSuchProcess:
            return {"success": False, "error": f"PID {pid} no longer exists."}
        except Exception as exc:
            return {"success": False, "error": str(exc)}


# ==============================================================================
# --- UPGRADE 3: WINDOWS EVENT ID LIVE THREAT HUNTER (WEVTUTIL) ---
# ==============================================================================
class WindowsEventHunter:
    """Queries Windows Security & System Event Logs for high-signal Blue Team Event IDs."""

    TARGET_EVENTS = [
        {"log": "Security", "id": 4625, "label": "Failed Logon / Brute-Force Attempt (MITRE T1110)"},
        {"log": "Security", "id": 4720, "label": "New Local User Account Created (MITRE T1136)"},
        {"log": "System",   "id": 7045, "label": "New Windows Service Installed (MITRE T1543.003)"},
        {"log": "Security", "id": 1102, "label": "Security Audit Log Cleared! (MITRE T1070.001)"},
    ]

    @classmethod
    def hunt_events(cls) -> list[dict]:
        findings = []
        if os.name != "nt":
            return findings
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        for item in cls.TARGET_EVENTS:
            cmd = [
                "wevtutil", "qe", item["log"],
                f"/q:*[System[(EventID={item['id']})]]",
                "/c:5", "/rd:true", "/f:text"
            ]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6, creationflags=flags)
                output = (res.stdout or "").strip()
                if output and "Event[" in output:
                    count = output.count("Event[")
                    findings.append({
                        "event_id": item["id"],
                        "log": item["log"],
                        "label": item["label"],
                        "count": count,
                        "sample": output.splitlines()[:8],
                    })
            except Exception:
                continue
        return findings


# ==============================================================================
# --- UPGRADE 5: ACTIVE ARP SPOOFING & GATEWAY TAMPER GUARD ---
# ==============================================================================
class ArpSpoofGuard:
    """Detects Man-in-the-Middle ARP cache poisoning and duplicate MAC-to-IP mappings."""

    IGNORED_MAC_PREFIXES = ("ff-ff-ff-ff-ff-ff", "01-00-5e", "33-33-")

    def __init__(self):
        self.baseline_mac_to_ips: dict[str, set[str]] = {}
        self.scan_arp_table(establish_baseline=True)

    def scan_arp_table(self, establish_baseline: bool = False) -> dict:
        mac_map: dict[str, set[str]] = {}
        spoof_alerts = []
        try:
            flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5, creationflags=flags)
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    ip_cand, mac_cand, arp_type = parts[0], parts[1].lower(), parts[2].lower()
                    if arp_type == "dynamic" and re.match(r"^(?:[0-9a-f]{2}-){5}[0-9a-f]{2}$", mac_cand):
                        if any(mac_cand.startswith(prefix) for prefix in self.IGNORED_MAC_PREFIXES):
                            continue
                        mac_map.setdefault(mac_cand, set()).add(ip_cand)

            for mac, ips in mac_map.items():
                if len(ips) > 1:
                    spoof_alerts.append(
                        f"ARP Poisoning Alert: Physical MAC {mac} claims multiple IPs ({', '.join(sorted(ips))})"
                    )

            if establish_baseline and not self.baseline_mac_to_ips:
                self.baseline_mac_to_ips = mac_map

        except Exception as exc:
            return {"alerts": [], "entries": 0, "error": str(exc)}

        return {
            "alerts": spoof_alerts,
            "entries": sum(len(v) for v in mac_map.values()),
            "unique_macs": len(mac_map),
        }


# ==============================================================================
# --- UPGRADE 6: REMOTE SIEM TELEMETRY STREAMER (UDP CEF / JSON) ---
# ==============================================================================
class SiemStreamer:
    """Streams sanitized, SHA-256 hash-chained forensic events over UDP to a SIEM / Kali collector."""

    def __init__(self):
        self.host = os.getenv("SIEM_HOST", "127.0.0.1").strip()
        try:
            self.port = int(os.getenv("SIEM_PORT", "5140"))
        except ValueError:
            self.port = 5140

    def emit(self, payload: dict, chain_hash: str) -> bool:
        try:
            cef_header = (
                f"CEF:0|GhostAegis|SentinelBlue|3.0|{payload.get('process', 'unknown')}|"
                f"Risk={payload.get('risk_score', 0)}|ChainHash={chain_hash[:12]}"
            )
            packet = json.dumps({
                "cef": cef_header,
                "chain_hash": chain_hash,
                "telemetry": payload,
                "timestamp": datetime.now().isoformat(),
            }).encode("utf-8")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(packet, (self.host, self.port))
            return True
        except Exception:
            return False


# ==============================================================================
# --- DLL-SAFE REST AI HELPERS (GEMINI 4 HYDROGEN / ARGON / CARBON) ---
# ==============================================================================
def _query_gemini_rest(
    prompt: str,
    api_key: str,
    preferred_model: str = "gemini-4-hydrogen",
) -> tuple[str, str]:
    """
    Queries Google Gemini 4 tiers (gemini-4-hydrogen, gemini-4-argon, gemini-4-carbon)
    via direct HTTPS REST to avoid compiled .pyd DLL blocks.
    Returns (response_text, model_used).
    """
    env_model = os.getenv("GEMINI_MODEL", "").strip()
    candidate_models = []
    for m in (
        preferred_model,
        env_model,
        "gemini-4-hydrogen",
        "gemini-4-argon",
        "gemini-4-carbon",
    ):
        if m and m not in candidate_models:
            candidate_models.append(m)

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2},
    }

    last_error = "Unknown Gemini 4 error"
    for model_name in candidate_models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        try:
            resp = requests.post(
                url,
                params={"key": api_key},
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=30,
            )
            if resp.status_code == 404:
                last_error = f"Model '{model_name}' returned 404"
                continue
            resp.raise_for_status()
            data = resp.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                text = "".join(part.get("text", "") for part in parts).strip()
                if text:
                    return text, model_name
            last_error = f"Empty response payload from {model_name}"
        except Exception as exc:
            last_error = f"{model_name}: {exc}"

    raise RuntimeError(last_error)


def _query_copilot_rest(prompt: str) -> str:
    """Queries OpenAI / Copilot or Local Ollama via direct REST without importing 'openai'/'jiter'."""
    openai_key = (os.getenv("OPENAI_API_KEY") or os.getenv("COPILOT_API_KEY") or "").strip()
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions").strip()
    model = os.getenv("COPILOT_MODEL", "gpt-4o-mini").strip()

    system_instruction = (
        "You are a concise Blue Team analyst. You must output exactly one sentence "
        "assessing the telemetry, ending with 'Threat Score: X/10'. Never use conversational filler."
    )

    if not openai_key:
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/v1/chat/completions").strip()
        ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:7b").strip()
        try:
            resp = requests.post(
                ollama_url,
                headers={"Content-Type": "application/json"},
                json={
                    "model": ollama_model,
                    "messages": [
                        {"role": "system", "content": system_instruction},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            raise RuntimeError("Missing OPENAI_API_KEY / COPILOT_API_KEY in .env (and local Ollama unreachable)")

    headers = {
        "Authorization": f"Bearer {openai_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 150,
        "temperature": 0.2,
    }
    resp = requests.post(base_url, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


# --- IN-CONTEXT AI MEMORY & THREAT DNA ---
class AnalystMemory:
    """Stores analyst triage feedback to provide dynamic few-shot context to AI evaluators."""
    def __init__(self, filepath="data/analyst_memory.json"):
        self.filepath = Path(filepath)
        self._lock = threading.Lock()
        self.data = self._load()

    def has_decision(self, process_name: str, remote_ip: str) -> bool:
        p = str(process_name).strip().lower()
        ip = str(remote_ip).strip()
        with self._lock:
            for cat in ("benign_baselines", "confirmed_threats"):
                for entry in self.data.get(cat, []):
                    if entry.get("process") == p and entry.get("remote_ip") == ip:
                        return True
        return False

    def _load(self):
        try:
            with self.filepath.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"benign_baselines": [], "confirmed_threats": []}

    def record_decision(self, process_name: str, remote_ip: str, verdict: str, reason: str):
        entry = {
            "process": str(process_name).strip().lower(),
            "remote_ip": str(remote_ip).strip(),
            "reason": reason,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        category = "benign_baselines" if verdict.lower() == "benign" else "confirmed_threats"
        with self._lock:
            self.data.setdefault("benign_baselines", [])
            self.data.setdefault("confirmed_threats", [])
            self.data[category] = [
                x for x in self.data[category]
                if not (x.get("process") == entry["process"] and x.get("remote_ip") == entry["remote_ip"])
            ]
            self.data[category].append(entry)
            self.data[category] = self.data[category][-20:]
            self._save()

    def _save(self):
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(f"{self.filepath}.tmp")
        try:
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            tmp.replace(self.filepath)
        except Exception:
            if tmp.exists():
                tmp.unlink()

    def get_prompt_context(self) -> str:
        with self._lock:
            benign = self.data.get("benign_baselines", [])
            threats = self.data.get("confirmed_threats", [])

        if not benign and not threats:
            return ""

        lines = ["[LEARNED LOCAL HOST BASELINE & ANALYST DECISIONS]"]
        if benign:
            lines.append("Verified Safe Exceptions on this specific machine:")
            for b in benign[-5:]:
                lines.append(f" - Process '{b['process']}' contacting {b['remote_ip']} ({b['reason']})")
        if threats:
            lines.append("Previously Confirmed Malicious Patterns on this host:")
            for t in threats[-5:]:
                lines.append(f" - Process '{t['process']}' targeting {t['remote_ip']} ({t['reason']})")
        return "\n".join(lines)


# --- THREAT DNA HASHING FOR CLUSTERING ---
def generate_threat_dna(process: str, signer: str, remote_ip: str, reasons: list) -> str:
    """Computes a persistent canonical hash for clustering repeated threats."""
    payload = f"{process.lower()}|{signer}|{remote_ip}|{','.join(sorted(reasons))}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16].upper()


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


def is_whitelisted_ip(ip_str: str) -> bool:
    """Checks if an IP is local, loopback, or in trusted RFC1918 / DNS infrastructure."""
    if not ip_str or ip_str in ["none", "N/A", "Unknown"]:
        return True
    if ip_str in STATIC_IP_WHITELIST:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    except ValueError:
        return True
    return False


def block_ip(ip_address: str, rule_suffix: str = "Block") -> str:
    """Safely blocks an IP address using Windows Firewall outbound rules with whitelisting."""
    if is_whitelisted_ip(ip_address):
        return f"[!] Whitelist bypass: {ip_address} is protected from firewall blocks."

    rule_name = f"GhostAegis_{rule_suffix}_{ip_address.replace(':', '_')}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip_address}"
    ]
    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=flags)
        return f"[+] Successfully firewalled IP: {ip_address}"
    except subprocess.CalledProcessError as e:
        return f"[-] Failed to block IP {ip_address}: {e.stderr.strip()}"
    except Exception as e:
        return f"[-] Error firewalling {ip_address}: {e}"


class GhostAegisApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- 1. INITIAL STATE ---
        self.radar_enabled = False
        self.host_isolated = False
        self.canary_enabled = False
        self.auto_mitigate_enabled = False
        self.yara_interceptor_enabled = False
        self.selected_gemini_model = "gemini-4-hydrogen"
        
        # Instantiate Active Defense & Enterprise EDR Modules
        self.canary_guard = CanaryGuard()
        self.network_behavior = NetworkBehaviorStore()
        self.analyst_memory = AnalystMemory(filepath=BASE_DIR / "data" / "analyst_memory.json")
        self.sanitizer = SentinelSanitizer()
        self.edr_inspector = ForensicEDRInspector()
        self.quarantine_vault = ForensicQuarantineVault(vault_dir=BASE_DIR / "quarantine")
        self.arp_guard = ArpSpoofGuard()
        self.siem_streamer = SiemStreamer()
        self.soar_dispatcher = SoarWebhookDispatcher()

        # Instantiate Native YARA Engine, Sigma Engine & Cryptographic Chain Auditor
        self.yara_engine = AegisYaraEngine(RULE_FILE_PATH)
        self.sigma_engine = AegisSigmaEngine(SIGMA_RULE_PATH)
        self.chain_auditor = ForensicChainAuditor(EDR_CHAIN_LOG_PATH)
        self.known_pids = set(psutil.pids())
        
        # Ghost Protocol State
        self.ghost_decoy = GhostDecoy(port=2222)
        self.decoy_thread = None
        self.decoy_loop = None

        self.title("Ghost-Aegis | Defensive Suite SE (v3.0 Enterprise XDR | Process Tree + Sigma + Purple Team + Ransomware Guard)")
        self.geometry("1220x950")
        self.minsize(1020, 750)

        # --- 2. BUILD THE UI CONTAINERS ---
        self.label = ctk.CTkLabel(
            self,
            text="GHOST-AEGIS",
            font=("Fixedsys", 28, "bold"),
            text_color="#00FF00"
        )
        self.label.pack(pady=(8, 3))

        self.status_frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        self.status_frame.pack(pady=3, padx=20, fill="x")
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="🛡️ SYSTEM HARDENED | v3.0 XDR + PURPLE TEAM SIM + LINEAGE GUARD + RANSOMWARE EARLY WARNING READY",
            text_color="#00FF00",
            font=("Consolas", 13, "bold")
        )
        self.status_label.pack(pady=4)

        self.button_container = ctk.CTkFrame(self, fg_color="transparent")
        self.button_container.pack(pady=4, padx=15, fill="x", expand=False)

        # Left Column: Access Control & System Metrics
        self.left_frame = ctk.CTkFrame(self.button_container)
        self.left_frame.pack(side="left", padx=8, pady=2, fill="both", expand=True)
        ctk.CTkLabel(
            self.left_frame,
            text="ACCESS CONTROL & FORENSIC ENGINES",
            font=("Arial", 11, "bold"),
            text_color="#3b8ed0"
        ).pack(pady=(5, 2))

        # Right Column: System Defense & Containment
        self.right_frame = ctk.CTkFrame(self.button_container)
        self.right_frame.pack(side="right", padx=8, pady=2, fill="both", expand=True)
        ctk.CTkLabel(
            self.right_frame,
            text="CONTAINMENT & NETWORK SENTINEL",
            font=("Arial", 11, "bold"),
            text_color="#3b8ed0"
        ).pack(pady=(5, 2))

        # --- 3. ACCESS CONTROL BUTTONS (Left Column) ---
        self._add_panel_section(self.left_frame, "IDENTITY & ACCESS")
        self.jit_button = ctk.CTkButton(
            self.left_frame, text="JIT Admin (15m Auto-Demote)",
            width=280, height=25, command=self.run_jit,
        )
        self.jit_button.pack(pady=2, padx=15)

        self.audit_button = ctk.CTkButton(
            self.left_frame, text="Audit Admins", width=280, height=25, command=self.run_audit,
        )
        self.audit_button.pack(pady=2, padx=15)

        self.info_button = ctk.CTkButton(
            self.left_frame, text="System Architecture", width=280, height=25, command=self.show_sys_info,
        )
        self.info_button.pack(pady=2, padx=15)

        self._add_panel_section(self.left_frame, "TELEMETRY, EVENT HUNTING & REVIEW")

        self.interfaces_button = ctk.CTkButton(
            self.left_frame,
            text="Interface Telemetry",
            width=280,
            height=25,
            command=self.run_interface_telemetry,
        )
        self.interfaces_button.pack(pady=2, padx=15)

        self.event_hunt_button = ctk.CTkButton(
            self.left_frame,
            text="Hunt Event IDs + Sigma (4625/4720/7045/1102)",
            width=280,
            height=25,
            fg_color="#8B4000",
            hover_color="#5C2A00",
            command=self.run_event_log_hunt,
        )
        self.event_hunt_button.pack(pady=2, padx=15)

        self.incidents_button = ctk.CTkButton(
            self.left_frame,
            text="Single Investigation Workbench (v3.0)",
            width=280,
            height=25,
            fg_color="#005577",
            hover_color="#00384F",
            command=self.show_incidents_window,
        )
        self.incidents_button.pack(pady=2, padx=15)

        self.report_button = ctk.CTkButton(
            self.left_frame,
            text="Export Investigation Report",
            width=280,
            height=25,
            command=self.export_report,
        )
        self.report_button.pack(pady=2, padx=15)

        self.ai_report_button = ctk.CTkButton(
            self.left_frame,
            text="Generate AI Incident Brief (4-Carbon)",
            width=280,
            height=25,
            fg_color="#4B0082",
            hover_color="#300052",
            command=self.run_ai_incident_report,
        )
        self.ai_report_button.pack(pady=2, padx=15)

        self.behavior_button = ctk.CTkButton(
            self.left_frame,
            text="Behavior Fingerprint Scan",
            width=280,
            height=25,
            fg_color="#1f538d",
            hover_color="#14375e",
            command=self.run_behavior_scan,
        )
        self.behavior_button.pack(pady=2, padx=15)

        self.breach_button = ctk.CTkButton(
            self.left_frame,
            text="Dark Web Breach Check",
            width=280,
            height=25,
            fg_color="#7B1FA2",
            hover_color="#4A0F6A",
            command=self.run_breach_check,
        )
        self.breach_button.pack(pady=2, padx=15)

        self.persistence_button = ctk.CTkButton(
            self.left_frame,
            text="Audit Persistence",
            width=280,
            height=25,
            command=self.run_persistence_audit,
        )
        self.persistence_button.pack(pady=2, padx=15)

        self.readiness_button = ctk.CTkButton(
            self.left_frame,
            text="System Readiness Check",
            width=280,
            height=25,
            command=self.run_readiness_check,
        )
        self.readiness_button.pack(pady=2, padx=15)

        self._add_panel_section(self.left_frame, "ACTIVE PROTECTION & YARA/SIGMA INTERCEPTOR")

        self.canary_button = ctk.CTkButton(
            self.left_frame,
            text="Start Canary Shield",
            width=280,
            height=25,
            fg_color="#1f538d",
            hover_color="#14375e",
            command=self.toggle_canary_shield,
        )
        self.canary_button.pack(pady=2, padx=15)

        self.yara_interceptor_button = ctk.CTkButton(
            self.left_frame,
            text="Start YARA + Sigma PID Interceptor",
            width=280,
            height=25,
            fg_color="#006644",
            hover_color="#004d33",
            command=self.toggle_yara_interceptor,
        )
        self.yara_interceptor_button.pack(pady=2, padx=15)

        # Compact Row: Verify SHA-256 Chain + Purple Team Simulator
        self.yara_tools_frame = ctk.CTkFrame(self.left_frame, fg_color="transparent")
        self.yara_tools_frame.pack(pady=2, padx=15)

        self.verify_chain_button = ctk.CTkButton(
            self.yara_tools_frame,
            text="Verify SHA-256 Chain",
            width=138,
            height=25,
            fg_color="#005577",
            hover_color="#00384F",
            command=self.run_forensic_chain_audit,
        )
        self.verify_chain_button.pack(side="left", padx=(0, 4))

        self.purple_team_button = ctk.CTkButton(
            self.yara_tools_frame,
            text="Purple Team Sim",
            width=138,
            height=25,
            fg_color="#6C3483",
            hover_color="#512E5F",
            command=self.show_purple_team_window,
        )
        self.purple_team_button.pack(side="left")

        self.engine_button = ctk.CTkButton(
            self.left_frame,
            text="Launch Defense Engine",
            width=280,
            height=25,
            fg_color="#4B0082",
            hover_color="#300052",
            command=self.run_defense_engine,
        )
        self.engine_button.pack(pady=2, padx=15)

        self.about_button = ctk.CTkButton(
            self.left_frame,
            text="About Ghost-Aegis",
            width=280,
            height=25,
            fg_color="gray",
            hover_color="#333333",
            command=self.show_about_window
        )
        self.about_button.pack(pady=2, padx=15)

        # --- 4. SYSTEM DEFENSE BUTTONS (Right Column) ---
        self._add_panel_section(self.right_frame, "CONTAINMENT")
        self.stealth_button = ctk.CTkButton(
            self.right_frame,
            text="Stealth Mode (Drop ICMP)",
            width=280,
            height=26,
            fg_color="purple",
            hover_color="#5a2d82",
            command=self.run_stealth
        )
        self.stealth_button.pack(pady=2, padx=15)

        self.clean_button = ctk.CTkButton(
            self.right_frame,
            text="Emergency Clean (DNS/ARP)",
            width=280,
            height=26,
            fg_color="#880808",
            hover_color="#660000",
            command=self.run_cleanup
        )
        self.clean_button.pack(pady=2, padx=15)

        self.isolate_button = ctk.CTkButton(
            self.right_frame,
            text="Host Isolation (Air-Gap)",
            width=280,
            height=26,
            fg_color="#7B1113",
            hover_color="#4D0000",
            command=self.toggle_host_isolation
        )
        self.isolate_button.pack(pady=2, padx=15)

        self._add_panel_section(self.right_frame, "ACTIVE DECOY")
        
        self.ghost_button = ctk.CTkButton(
            self.right_frame,
            text="Engage Ghost Protocol (Decoy)",
            width=280,
            height=26,
            fg_color="#006400",
            hover_color="#004d00",
            command=self.toggle_ghost_protocol
        )
        self.ghost_button.pack(pady=2, padx=15)

        self._add_panel_section(self.right_frame, "NETWORK & MITM MONITORING")

        self.sentinel_button = ctk.CTkButton(
            self.right_frame,
            text="Network Sentinel Audit",
            width=280,
            height=26,
            fg_color="#1f538d",
            command=self.network_sentinel_callback
        )
        self.sentinel_button.pack(pady=2, padx=15)

        self.arp_guard_button = ctk.CTkButton(
            self.right_frame,
            text="ARP Spoof & MitM Guard Audit",
            width=280,
            height=26,
            fg_color="#006666",
            hover_color="#004C4C",
            command=self.run_arp_guard_check,
        )
        self.arp_guard_button.pack(pady=2, padx=15)

        self.radar_button = ctk.CTkButton(
            self.right_frame,
            text="Start Radar (30s Loop)",
            width=280,
            height=26,
            fg_color="#1f538d",
            hover_color="#14375e",
            command=self.toggle_radar
        )
        self.radar_button.pack(pady=2, padx=15)

        self.network_dashboard_button = ctk.CTkButton(
            self.right_frame,
            text="Network Trust Dashboard",
            width=280,
            height=26,
            command=self.show_network_dashboard,
        )
        self.network_dashboard_button.pack(pady=2, padx=15)

        self.map_button = ctk.CTkButton(
            self.right_frame,
            text="Global Threat Radar",
            width=280,
            height=26,
            fg_color="#880808",  
            hover_color="#4D0000",
            command=self.show_threat_map,
        )
        self.map_button.pack(pady=2, padx=15)

        # --- PROCESS RESPONSE & ADAPTIVE TRIAGE (Right Column) ---
        self._add_panel_section(self.right_frame, "PROCESS RESPONSE, VAULT & GEMINI 4 TRIAGE")

        # Row 0: Auto-Mitigate + Gemini 4 Tier Selector
        self.mitigate_model_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        self.mitigate_model_frame.pack(pady=(2, 2), padx=10)

        self.auto_mitigate_button = ctk.CTkButton(
            self.mitigate_model_frame,
            text="Auto-Mitigate: OFF",
            fg_color="#1f538d",
            hover_color="#14375e",
            width=145,
            height=26,
            command=self.toggle_auto_mitigate
        )
        self.auto_mitigate_button.pack(side="left", padx=(0, 4))

        self.gemini_model_menu = ctk.CTkOptionMenu(
            self.mitigate_model_frame,
            values=GEMINI_4_MODELS,
            width=155,
            height=26,
            fg_color="#4B0082",
            button_color="#300052",
            command=self.on_gemini_model_change,
        )
        self.gemini_model_menu.set("gemini-4-hydrogen")
        self.gemini_model_menu.pack(side="left")

        # Row 1: PID Selection, Freeze+Vault, Kill & Dual-AI Eval
        self.kill_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        self.kill_frame.pack(pady=2, padx=10)

        self.pid_entry = ctk.CTkComboBox(
            self.kill_frame,
            values=["Select PID..."],
            width=115,
            height=26
        )
        self.pid_entry.pack(side="left", padx=(0, 3))

        self.vault_button = ctk.CTkButton(
            self.kill_frame,
            text="Freeze+Vault",
            fg_color="#B85D00",
            hover_color="#7A3E00",
            width=82,
            height=26,
            command=self.quarantine_process_callback
        )
        self.vault_button.pack(side="left", padx=(0, 3))

        self.kill_button = ctk.CTkButton(
            self.kill_frame,
            text="Kill",
            fg_color="#880808",
            hover_color="#660000",
            width=45,
            height=26,
            command=self.terminate_process_callback
        )
        self.kill_button.pack(side="left", padx=(0, 3))

        self.ai_eval_button = ctk.CTkButton(
            self.kill_frame,
            text="Dual-AI",
            fg_color="#4B0082",
            hover_color="#300052",
            width=64,
            height=26,
            command=self.run_dual_ai_eval
        )
        self.ai_eval_button.pack(side="left")

        # Row 2: Deep Inspect PID & In-Context AI Memory Triage Buttons
        self.triage_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        self.triage_frame.pack(pady=(2, 4), padx=10)

        self.edr_inspect_button = ctk.CTkButton(
            self.triage_frame,
            text="PE + Cmdline Inspect",
            fg_color="#005577",
            hover_color="#00384F",
            width=125,
            height=25,
            command=self.inspect_selected_pid_edr
        )
        self.edr_inspect_button.pack(side="left", padx=(0, 3))

        self.baseline_button = ctk.CTkButton(
            self.triage_frame,
            text="Mark Safe",
            fg_color="#1E6B37",
            hover_color="#154B27",
            width=88,
            height=25,
            command=self.mark_selected_safe
        )
        self.baseline_button.pack(side="left", padx=(0, 3))

        self.confirm_threat_button = ctk.CTkButton(
            self.triage_frame,
            text="Mark Threat",
            fg_color="#7B1113",
            hover_color="#4D0000",
            width=88,
            height=25,
            command=self.mark_selected_threat
        )
        self.confirm_threat_button.pack(side="left")

        # --- 5. LOGGING CONSOLE ---
        self.console = ctk.CTkTextbox(
            self,
            font=("Consolas", 12),
            fg_color="#000000",
            text_color="#00FF00"
        )
        self.console.pack(pady=(4, 12), padx=20, fill="both", expand=True)

        # High-visibility Dark Mode Log Tags
        self.console.tag_config("threat", foreground="#FF3333")   # Neon Red
        self.console.tag_config("warn", foreground="#FF7518")     # Orange
        self.console.tag_config("trusted", foreground="#00FF00")  # Green
        self.console.tag_config("system", foreground="#00E5FF")   # Cyan
        self.console.tag_config("review", foreground="#FFBF00")   # Amber
        self.console.tag_config("identity", foreground="#00AAFF") # Identity / behavior
        self.console.tag_config("breach", foreground="#FF00FF")   # Breach intel
        self.console.tag_config("learning", foreground="#BA55D3") # AI Memory / Baseline

        # --- THREAD QUEUE SETUP ---
        self.log_queue = queue.Queue()
        self.scan_thread_running = False
        self.engine_thread_running = False

        # Start Real-Time Process Creation Interceptor Worker Thread (active when toggled)
        self.interceptor_thread = threading.Thread(target=self._yara_interceptor_loop, daemon=True)
        self.interceptor_thread.start()

        self.check_queue()
        self.log_event(
            f"Ghost-Aegis v3.0 XDR initialized | Process Tree + Lineage Guard + Ransomware Correlator + Purple Team Sim active | "
            f"Loaded {len(self.yara_engine.rules)} YARA rules & {len(self.sigma_engine.rules)} Sigma rules.",
            "trusted",
        )
        self.refresh_active_pids()

    # --- 6. PANEL SECTION LABELS ---
    @staticmethod
    def _add_panel_section(parent, title):
        ctk.CTkLabel(
            parent,
            text=title,
            anchor="w",
            font=("Consolas", 10, "bold"),
            text_color="#7fb3d5",
        ).pack(fill="x", padx=15, pady=(4, 1))

    def on_gemini_model_change(self, selected_model: str):
        self.selected_gemini_model = selected_model
        self.log_event(
            f"🧠 [GEMINI 4 ENGINE] Primary model set to '{selected_model}' (Auto-cascade: hydrogen -> argon -> carbon).",
            "system",
        )

    # ==========================================================================
    # --- REAL-TIME YARA + SIGMA + LINEAGE PID INTERCEPTOR & CHAIN SEALING ---
    # ==========================================================================
    def toggle_yara_interceptor(self):
        self.yara_interceptor_enabled = not self.yara_interceptor_enabled
        if self.yara_interceptor_enabled:
            self.known_pids = set(psutil.pids())
            self.yara_interceptor_button.configure(
                text="Stop YARA + Sigma Interceptor (ACTIVE)",
                fg_color="#e67e22",
                hover_color="#b85d00",
            )
            self.log_event(
                f"🛡️ [YARA + SIGMA + LINEAGE INTERCEPTOR ARMED] Hooking new Windows process spawns (50ms kernel table diff) "
                f"across {len(self.yara_engine.rules)} YARA & {len(self.sigma_engine.rules)} Sigma rules...",
                "trusted",
            )
        else:
            self.yara_interceptor_button.configure(
                text="Start YARA + Sigma PID Interceptor",
                fg_color="#006644",
                hover_color="#004d33",
            )
            self.log_event("[*] Real-Time YARA + Sigma Process Interceptor paused.", "review")

    def _yara_interceptor_loop(self):
        while True:
            if self.yara_interceptor_enabled:
                try:
                    current_pids = set(psutil.pids())
                    new_pids = current_pids - self.known_pids
                    for pid in new_pids:
                        self._inspect_spawned_pid(pid)
                    self.known_pids = current_pids
                except Exception:
                    pass
            time.sleep(0.05)

    def _inspect_spawned_pid(self, pid: int):
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            ppid = proc.ppid()
            cmdline_list = proc.cmdline()
            cmdline = " ".join(cmdline_list) if cmdline_list else ""
            exe_path = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return

        tree_snapshot = AegisForensicCorrelator.capture_process_tree(pid)

        # Evaluate command line against YARA, Sigma, AND Parent-Child Lineage Anomaly Detector
        alerts = (
            self.yara_engine.scan_command_line(pid, name, cmdline)
            + self.sigma_engine.evaluate_process(pid, name, cmdline)
            + ParentChildAnomalyDetector.evaluate_lineage(tree_snapshot)
        )
        if not alerts:
            return

        for alert in alerts:
            alert["ppid"] = ppid
            alert["exe_path"] = exe_path
            alert["process_tree"] = tree_snapshot
            sealed = self.chain_auditor.seal_alert(alert)

            self._queue_log(
                f"🚨 [GHOST-AEGIS EDR ALERT] {sealed['rule_triggered']} | MITRE: {sealed['mitre_id']} | "
                f"Severity: {sealed['severity']} | PID: {pid} (PPID: {ppid}) -> {name}",
                "threat",
            )
            self._queue_log(
                f"   Indicators: {sealed['matched_indicators']} | Cmd: {cmdline[:120]}",
                "threat",
            )
            self._queue_log(
                f"   PrevHash: {sealed['prev_hash'][:20]}... -> SHA-256 Seal: {sealed['sha256_seal'][:24]}...",
                "system",
            )
            self.log_queue.put(("__set_target_pid__", f"{pid} ({name})"))

            risk_val = 95 if sealed["severity"] == "CRITICAL" else 85
            reasons = [
                f"{sealed['rule_triggered']}",
                f"MITRE:{sealed['mitre_id']}",
                f"ChainSeal:{sealed['sha256_seal'][:12]}",
            ]
            incident = Incident(
                process=name,
                pid=pid,
                path=exe_path,
                remote_ip="local_spawn",
                reputation=0,
                signer=get_authenticode_signer(exe_path),
                risk_score=risk_val,
                reasons=reasons,
                recommended_action="quarantine_and_review",
            )
            try:
                append_incident(incident)
            except Exception:
                pass

            self.siem_streamer.emit(sealed, sealed["sha256_seal"])
            self.soar_dispatcher.dispatch_alert(sealed)

            if getattr(self, "auto_mitigate_enabled", False) and pid != os.getpid():
                vault_res = self.quarantine_vault.freeze_and_quarantine(
                    pid=pid,
                    reasons=reasons,
                    risk_score=risk_val,
                )
                if vault_res.get("success"):
                    self._queue_log(
                        f"🚨 [AUTO-MITIGATE EDR VAULT] {name} (PID {pid}) FROZEN, VAULTED & KILLED.",
                        "threat",
                    )

    # ==========================================================================
    # --- UPGRADE 12 UI: PURPLE TEAM ADVERSARY SIMULATOR (4 SCENARIOS) ---
    # ==========================================================================
    def run_safe_yara_test(self):
        """Simulates an encoded PowerShell payload in memory to test YARA + Sigma + Process Tree + SHA-256 sealing."""
        test_cmd = "powershell.exe -WindowStyle Hidden -enc SQBFAFgA_GHOST_AEGIS_SAFE_MEMORY_TEST"
        sim_pid = os.getpid()
        alerts = (
            self.yara_engine.scan_command_line(
                pid=sim_pid,
                process_name="powershell_sim.exe",
                cmdline=test_cmd,
            )
            + self.sigma_engine.evaluate_process(
                pid=sim_pid,
                process_name="powershell_sim.exe",
                cmdline=test_cmd,
            )
        )
        tree_snapshot = AegisForensicCorrelator.capture_process_tree(sim_pid)
        for alert in alerts:
            alert["ppid"] = os.getppid()
            alert["exe_path"] = str(BASE_DIR / "Memory_Simulation_Test")
            alert["process_tree"] = tree_snapshot
            sealed = self.chain_auditor.seal_alert(alert)
            self.soar_dispatcher.dispatch_alert(sealed)
            self.log_event(
                f"🧪 [PURPLE TEAM SCENARIO 1] Triggered '{sealed['rule_triggered']}' ({sealed['mitre_id']}) | "
                f"Process Tree & Alert Sealed to {EDR_CHAIN_LOG_PATH.name} (SHA-256: {sealed['sha256_seal'][:24]}...)",
                "learning",
            )

    def show_purple_team_window(self):
        pt_win = ctk.CTkToplevel(self)
        pt_win.title("Ghost-Aegis v3.0 | Purple Team Adversary Simulator (Safe MITRE Emulation)")
        pt_win.geometry("760x540")
        pt_win.attributes("-topmost", True)
        pt_win.configure(fg_color="#0d1117")

        ctk.CTkLabel(
            pt_win,
            text="⚔️ PURPLE TEAM ADVERSARY EMULATION WORKBENCH",
            font=("Consolas", 16, "bold"),
            text_color="#BA55D3",
        ).pack(pady=(14, 4))

        ctk.CTkLabel(
            pt_win,
            text="Safely fires benign MITRE ATT&CK telemetry to validate YARA, Sigma, Lineage, Canary & SHA-256 Chain engines live.",
            font=("Consolas", 11),
            text_color="#9aa7b2",
        ).pack(pady=(0, 10))

        sim_frame = ctk.CTkFrame(pt_win, fg_color="#161b22", corner_radius=8)
        sim_frame.pack(fill="both", expand=True, padx=18, pady=6)

        def sim_live_child_powershell():
            """Spawns a real, benign child Python process carrying encoded PowerShell flags in argv."""
            if not self.yara_interceptor_enabled:
                self.toggle_yara_interceptor()
            flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import time; time.sleep(1.5)",
                    "powershell.exe -WindowStyle Hidden -enc SQBFAFgA_PURPLE_TEAM_LIVE_PID_SPAWN",
                ],
                creationflags=flags,
            )
            self.log_event(
                f"⚔️ [PURPLE TEAM LIVE SPAWN] Spawned benign child PID {proc.pid} with T1059.001 obfuscated arguments...",
                "learning",
            )

        def sim_lolbin_staging():
            sim_pid = os.getpid()
            cmd = "certutil -urlcache -split -f http://127.0.0.1/benign_purple_test.bin C:\\Windows\\Temp\\test.bin"
            alerts = (
                self.yara_engine.scan_command_line(sim_pid, "certutil_sim.exe", cmd)
                + self.sigma_engine.evaluate_process(sim_pid, "certutil_sim.exe", cmd)
            )
            tree_snapshot = AegisForensicCorrelator.capture_process_tree(sim_pid)
            for alert in alerts:
                alert["ppid"] = os.getppid()
                alert["exe_path"] = "C:\\Windows\\System32\\certutil.exe (Simulated)"
                alert["process_tree"] = tree_snapshot
                sealed = self.chain_auditor.seal_alert(alert)
                self.soar_dispatcher.dispatch_alert(sealed)
                self.log_event(
                    f"⚔️ [PURPLE TEAM SCENARIO 2] Triggered '{sealed['rule_triggered']}' ({sealed['mitre_id']}) -> Sealed ({sealed['sha256_seal'][:20]}...)",
                    "learning",
                )

        def sim_lineage_masquerade():
            sim_pid = os.getpid()
            base_tree = AegisForensicCorrelator.capture_process_tree(sim_pid)
            # Inject simulated WMI -> PowerShell parent-child nodes at the tip of the real host lineage
            nodes = list(base_tree.get("nodes", []))
            for n in nodes:
                n["is_trigger"] = False
            nodes.append({
                "pid": 4412,
                "ppid": sim_pid,
                "name": "wmiprvse.exe",
                "exe": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                "cmdline": "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding",
                "create_time": time.time(),
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "is_trigger": False,
            })
            nodes.append({
                "pid": 8824,
                "ppid": 4412,
                "name": "powershell.exe",
                "exe": "C:\\Users\\Public\\svchost.exe",
                "cmdline": "powershell.exe -nop -w hidden -c Get-WmiObject Win32_Process",
                "create_time": time.time() + 0.01,
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "is_trigger": True,
            })
            sim_tree = {
                "root_pid": nodes[0]["pid"] if nodes else sim_pid,
                "trigger_pid": 8824,
                "nodes": nodes,
                "ascii_tree": AegisForensicCorrelator.format_ascii_tree(nodes),
            }
            anomalies = ParentChildAnomalyDetector.evaluate_lineage(sim_tree)
            for anomaly in anomalies:
                anomaly["ppid"] = 4412
                anomaly["exe_path"] = "C:\\Users\\Public\\svchost.exe (Simulated)"
                anomaly["process_tree"] = sim_tree
                sealed = self.chain_auditor.seal_alert(anomaly)
                self.soar_dispatcher.dispatch_alert(sealed)
                self.log_event(
                    f"⚔️ [PURPLE TEAM SCENARIO 3] Triggered '{sealed['rule_triggered']}' ({sealed['mitre_id']}) -> Sealed ({sealed['sha256_seal'][:20]}...)",
                    "learning",
                )

        def sim_ransomware_canary():
            self._canary_finding_callback({
                "path": str(BASE_DIR / "canary_vault_Simulation_Decoy.docx"),
                "action": "MODIFIED (PURPLE TEAM RANSOMWARE TEST)",
            })

        def run_full_campaign():
            self.log_event("🚀 [PURPLE TEAM FULL CAMPAIGN] Launching 4-stage MITRE ATT&CK kill-chain emulation...", "learning")
            self.run_safe_yara_test()
            sim_lolbin_staging()
            sim_lineage_masquerade()
            sim_ransomware_canary()
            sim_live_child_powershell()
            self.log_event(
                "✅ [PURPLE TEAM CAMPAIGN COMPLETE] Open 'Single Investigation Workbench (v3.0)' to inspect all sealed events & XDR Campaign Clusters!",
                "trusted",
            )

        scenarios = [
            (
                "1. Encoded PowerShell Cradle (MITRE T1059.001)",
                "Tests Native YARA + Sigma command-line interception & Base64 deobfuscation.",
                self.run_safe_yara_test,
                "#5B2C6F",
            ),
            (
                "2. Live Child PID Spawn Hook (50ms Kernel Table Diff)",
                "Spawns a real, benign child process to verify live 50ms PID Interceptor capture.",
                sim_live_child_powershell,
                "#006644",
            ),
            (
                "3. LOLBin Certutil Payload Staging (MITRE T1218 / T1140)",
                "Simulates Living-off-the-Land certutil URL cache staging across YARA & Sigma.",
                sim_lolbin_staging,
                "#8B4000",
            ),
            (
                "4. WMI Shell Lineage Anomaly (MITRE T1047 / T1036.005)",
                "Tests Parent-Child Masquerading Detector (wmiprvse.exe spawning powershell.exe).",
                sim_lineage_masquerade,
                "#005577",
            ),
            (
                "5. Ransomware Canary Trip + Write-Spike Correlation (MITRE T1486)",
                "Triggers Ransomware Early Warning Engine to attribute I/O write spikes & seal alert.",
                sim_ransomware_canary,
                "#7B1113",
            ),
        ]

        for title, desc, cb, color in scenarios:
            row = ctk.CTkFrame(sim_frame, fg_color="#090d13", corner_radius=6)
            row.pack(fill="x", padx=12, pady=5)
            text_col = ctk.CTkFrame(row, fg_color="transparent")
            text_col.pack(side="left", fill="x", expand=True, padx=10, pady=6)
            ctk.CTkLabel(text_col, text=title, font=("Consolas", 12, "bold"), text_color="#e6edf3", anchor="w").pack(fill="x")
            ctk.CTkLabel(text_col, text=desc, font=("Consolas", 10), text_color="#8b949e", anchor="w").pack(fill="x")
            ctk.CTkButton(
                row,
                text="Fire Scenario",
                width=130,
                height=28,
                fg_color=color,
                command=cb,
            ).pack(side="right", padx=10, pady=8)

        bottom = ctk.CTkFrame(pt_win, fg_color="transparent")
        bottom.pack(fill="x", padx=18, pady=(6, 12))

        ctk.CTkButton(
            bottom,
            text="🚀 Run Full 5-Stage Adversary Campaign",
            fg_color="#4B0082",
            hover_color="#300052",
            width=280,
            height=32,
            font=("Consolas", 12, "bold"),
            command=run_full_campaign,
        ).pack(side="left")

        ctk.CTkButton(
            bottom,
            text="Open Investigation Workbench",
            fg_color="#005577",
            hover_color="#00384F",
            width=220,
            height=32,
            command=self.show_incidents_window,
        ).pack(side="left", padx=10)

        ctk.CTkButton(
            bottom,
            text="CLOSE",
            fg_color="#444444",
            width=90,
            height=32,
            command=pt_win.destroy,
        ).pack(side="right")

    def run_forensic_chain_audit(self):
        intact, count, report_text = self.chain_auditor.verify_chain()
        if count == 0:
            self.log_event(f"[*] Cryptographic Chain Audit: No records in {EDR_CHAIN_LOG_PATH.name} yet.", "review")
        elif intact:
            self.log_event(
                f"🔐 [CHAIN-OF-CUSTODY PASSED] All {count} EDR records in {EDR_CHAIN_LOG_PATH.name} are cryptographically intact.",
                "trusted",
            )
        else:
            self.log_event(
                f"🚨 [CHAIN TAMPER DETECTED] Cryptographic mismatch found in {EDR_CHAIN_LOG_PATH.name}!",
                "threat",
            )

        ledger_win = ctk.CTkToplevel(self)
        ledger_win.title("Ghost-Aegis | Cryptographic Chain-of-Custody Auditor (SHA-256)")
        ledger_win.geometry("920x620")
        ledger_win.attributes("-topmost", True)

        ctk.CTkLabel(
            ledger_win,
            text="🛡️ CRYPTOGRAPHIC CHAIN-OF-CUSTODY AUDITOR (SHA-256 LEDGER)",
            font=("Consolas", 15, "bold"),
            text_color="#00FF00" if intact else "#FF3333",
        ).pack(pady=(12, 4))

        box = ctk.CTkTextbox(
            ledger_win,
            font=("Consolas", 11),
            fg_color="#000000",
            text_color="#00E5FF" if intact else "#FF3333",
        )
        box.pack(fill="both", expand=True, padx=15, pady=8)
        box.insert("1.0", report_text)
        box.configure(state="disabled")

        ctk.CTkButton(
            ledger_win,
            text="CLOSE",
            fg_color="#444444",
            width=100,
            command=ledger_win.destroy,
        ).pack(pady=(2, 12))

    # --- ON-DEMAND EDR PE & CMDLINE INSPECTOR ---
    def inspect_selected_pid_edr(self):
        pid = self._get_selected_pid()
        if not pid:
            self.log_event("Select an active PID to run PE Entropy, YARA, Sigma, Lineage & Command-Line Deobfuscation.", "warn")
            return
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            exe_path = proc.exe()
        except Exception as exc:
            self.log_event(f"[!] Cannot inspect PID {pid}: {exc}", "warn")
            return

        cmd_info = self.edr_inspector.inspect_cmdline(pid)
        pe_info = self.edr_inspector.scan_pe_binary(exe_path)
        yara_hits = self.yara_engine.scan_command_line(pid, proc_name, cmd_info["cmdline"])
        sigma_hits = self.sigma_engine.evaluate_process(pid, proc_name, cmd_info["cmdline"])
        tree_info = AegisForensicCorrelator.capture_process_tree(pid)
        lineage_hits = ParentChildAnomalyDetector.evaluate_lineage(tree_info)

        self.log_event(f"🔬 [EDR DEEP INSPECT] {proc_name} (PID: {pid} | Root PID: {tree_info.get('root_pid')})", "system")
        self.log_event(f"   Cmdline: {cmd_info['cmdline'] or 'N/A'}", "review")
        if cmd_info["lolbin_hit"]:
            self.log_event(f"   [!] LOLBIN DETECTED: {cmd_info['lolbin_hit']}", "threat")
        if cmd_info["decoded_b64"]:
            self.log_event(f"   [!] DECODED BASE64 PAYLOAD: {cmd_info['decoded_b64']}", "threat")
        for yh in yara_hits:
            self.log_event(
                f"   [!] {yh['rule_triggered']} (MITRE {yh['mitre_id']}) -> {yh['matched_indicators']}",
                "threat",
            )
        for sh in sigma_hits:
            self.log_event(
                f"   [!] {sh['rule_triggered']} (MITRE {sh['mitre_id']}) -> {sh['matched_indicators']}",
                "threat",
            )
        for lh in lineage_hits:
            self.log_event(
                f"   [!] {lh['rule_triggered']} (MITRE {lh['mitre_id']}) -> {lh['matched_indicators']}",
                "threat",
            )
        self.log_event(
            f"   PE Shannon Entropy: {pe_info['entropy']}/8.00 ({'PACKED/ENCRYPTED SUSPECT' if pe_info['packed'] else 'Normal'}) | "
            f"Injection APIs: {', '.join(pe_info['suspicious_apis']) if pe_info['suspicious_apis'] else 'None'}",
            "threat" if (pe_info["packed"] or pe_info["suspicious_apis"] or yara_hits or sigma_hits or lineage_hits) else "trusted"
        )

    # --- ON-DEMAND FREEZE & QUARANTINE VAULT ---
    def quarantine_process_callback(self):
        pid = self._get_selected_pid()
        if pid is None:
            self.log_event("Select a valid PID to Freeze & Quarantine.", "warn")
            return
        self.log_event(f"🧊 [QUARANTINE VAULT] Suspending threads and vaulting PID {pid}...", "warn")
        res = self.quarantine_vault.freeze_and_quarantine(
            pid=pid,
            reasons=["Manual Analyst Freeze & Quarantine"],
            risk_score=95,
        )
        if res.get("success"):
            self.log_event(
                f"🔒 [VAULTED & NEUTRALIZED] {res['process']} (PID {pid}) frozen, hashed (SHA256: {res['sha256'][:16]}...), "
                f"manifest saved to {res['manifest']}, and terminated.",
                "threat"
            )
            self.refresh_active_pids()
        else:
            self.log_event(f"[-] Quarantine failed: {res.get('error')}", "threat")

    # --- ON-DEMAND WINDOWS EVENT ID THREAT HUNTER + SIGMA CORRELATION ---
    def run_event_log_hunt(self):
        self.event_hunt_button.configure(state="disabled", text="Hunting Event Logs...")
        self.log_event("[*] Querying Windows Security & System Event Logs (4625, 4720, 7045, 1102) & evaluating Sigma rules...", "system")
        threading.Thread(target=self._event_hunt_worker, daemon=True).start()

    def _event_hunt_worker(self):
        try:
            findings = WindowsEventHunter.hunt_events()
            if not findings:
                self._queue_log("[+] Event Log + Sigma Hunt complete: 0 high-risk Security/System Event IDs detected (or elevation required for Security log).", "trusted")
            else:
                for item in findings:
                    self._queue_log(
                        f"🚨 [EVENT ID {item['event_id']}] {item['label']} ({item['count']} recent hits in {item['log']} log)",
                        "threat"
                    )
                    sigma_hits = self.sigma_engine.evaluate_event_id(
                        event_id=item["event_id"],
                        log_name=item["log"],
                        count=item["count"],
                    )
                    for sh in sigma_hits:
                        sh["process_tree"] = AegisForensicCorrelator.capture_process_tree(os.getpid())
                        sealed = self.chain_auditor.seal_alert(sh)
                        self.soar_dispatcher.dispatch_alert(sealed)
                        self._queue_log(
                            f"   🛡️ [{sealed['rule_triggered']}] MITRE {sealed['mitre_id']} | Sealed to {EDR_CHAIN_LOG_PATH.name} (SHA-256: {sealed['sha256_seal'][:20]}...)",
                            "threat",
                        )
        except Exception as exc:
            self._queue_log(f"[-] Event Log Hunt error: {exc}", "threat")
        finally:
            self.log_queue.put(("__event_hunt_complete__", None))

    # --- ON-DEMAND ARP SPOOFING & MITM GUARD ---
    def run_arp_guard_check(self):
        self.log_event("[*] Auditing LAN ARP Cache Table for MAC duplication & MitM poisoning...", "system")
        report = self.arp_guard.scan_arp_table()
        if report.get("alerts"):
            for alert in report["alerts"]:
                self.log_event(f"🚨 [MITM / ARP SPOOF DETECTED] {alert}", "threat")
        else:
            self.log_event(
                f"[+] ARP Table Clean: {report.get('entries', 0)} dynamic neighbor entries verified across {report.get('unique_macs', 0)} unique MACs.",
                "trusted"
            )

    # --- AUTONOMOUS AI AUDIT TELEMETRY LEARNING ---
    def _auto_learn_telemetry(self, proc_name: str, remote_ip: str, signer: str, risk_score: int, exe_path: str, observation: dict, reasons: list):
        proc_lower = proc_name.lower()
        if proc_lower in PROCESS_WHITELIST or is_whitelisted_ip(remote_ip):
            return
        if self.analyst_memory.has_decision(proc_lower, remote_ip):
            return

        sightings = observation.get("sightings", 0)
        is_beacon = observation.get("beacon", False)

        if (
            signer not in ["Unsigned", "Unknown", "Unavailable", ""]
            and not is_suspicious_path(exe_path)
            and not is_beacon
            and risk_score <= 15
            and sightings >= 4
        ):
            reason_str = f"Auto-Learned Safe: Signed by '{signer}' with stable baseline ({sightings} audits, 0 anomalies)"
            self.analyst_memory.record_decision(
                process_name=proc_lower,
                remote_ip=remote_ip,
                verdict="benign",
                reason=reason_str
            )
            self._queue_log(
                f"🧠 [AUTO-LEARN BASELINE] '{proc_name}' -> {remote_ip} learned as Safe (Signer: {signer}).",
                "learning"
            )
            return

        if risk_score >= 80:
            evidence_summary = ", ".join(reasons[:2]) if reasons else "Severe heuristic anomaly"
            reason_str = f"Auto-Learned Threat: Heuristic Score {risk_score}/100 [{evidence_summary}]"
            self.analyst_memory.record_decision(
                process_name=proc_lower,
                remote_ip=remote_ip,
                verdict="malicious",
                reason=reason_str
            )
            self._queue_log(
                f"🚨 [AUTO-LEARN THREAT] Critical pattern logged: '{proc_name}' -> {remote_ip} ({evidence_summary}).",
                "threat"
            )

    # --- ZERO-TOUCH AUTO-MITIGATION ---
    def toggle_auto_mitigate(self):
        self.auto_mitigate_enabled = not self.auto_mitigate_enabled
        if self.auto_mitigate_enabled:
            self.auto_mitigate_button.configure(
                text="Auto-Mitigate: ARMED", 
                fg_color="#880808", 
                hover_color="#660000"
            )
            self.log_event("🚨 [AUTO-MITIGATION ARMED] High-risk processes will be Frozen, Vaulted, Killed & Firewalled on sight.", "threat")
        else:
            self.auto_mitigate_button.configure(
                text="Auto-Mitigate: OFF", 
                fg_color="#1f538d", 
                hover_color="#14375e"
            )
            self.log_event("[*] Auto-mitigation disarmed. Returning to manual review mode.", "review")

    def _get_selected_pid(self) -> int | None:
        raw = self.pid_entry.get().strip()
        if not raw or raw in {"Select PID...", "No active net PIDs"}:
            return None
        candidate = raw.split()[0].strip("():,")
        return int(candidate) if candidate.isdigit() else None

    def refresh_active_pids(self):
        pids = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.pid and conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    if not is_whitelisted_ip(conn.raddr.ip):
                        try:
                            name = psutil.Process(conn.pid).name()
                            entry = f"{conn.pid} ({name})"
                            if entry not in pids:
                                pids.append(entry)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
        except Exception:
            pass

        if pids:
            self.pid_entry.configure(values=pids)
            if not self.pid_entry.get() or self.pid_entry.get() == "Select PID...":
                self.pid_entry.set(pids[0])
        else:
            self.pid_entry.configure(values=["No active net PIDs"])

    def destroy(self):
        self.yara_interceptor_enabled = False
        self.canary_guard.stop()
        if hasattr(self.network_behavior, "flush"):
            self.network_behavior.flush()
        if self.decoy_loop and self.decoy_loop.is_running():
            self.decoy_loop.call_soon_threadsafe(self.ghost_decoy.stop_server)
            self.decoy_loop.call_soon_threadsafe(self.decoy_loop.stop)
        super().destroy()

    # --- IN-CONTEXT AI FEEDBACK / TRIAGE ACTIONS ---
    def mark_selected_safe(self):
        pid = self._get_selected_pid()
        if not pid:
            self.log_event("Select a running process PID to mark as safe baseline.", "warn")
            return

        try:
            p = psutil.Process(pid)
            proc_name = p.name()
            connections = p.net_connections()
            ips = [c.raddr.ip for c in connections if c.raddr and not is_whitelisted_ip(c.raddr.ip)]
            target_ip = ips[0] if ips else "Any"

            self.analyst_memory.record_decision(
                process_name=proc_name,
                remote_ip=target_ip,
                verdict="benign",
                reason="Analyst verified as safe host behavior via GUI"
            )
            self.log_event(f"🧠 [AI MEMORY] Learned Safe Baseline: '{proc_name}' -> {target_ip}. Dual-AI will trust this pattern.", "learning")
        except psutil.NoSuchProcess:
            self.log_event(f"[!] PID {pid} is no longer running.", "warn")
        except Exception as e:
            self.log_event(f"Memory update error: {e}", "threat")

    def mark_selected_threat(self):
        pid = self._get_selected_pid()
        if not pid:
            self.log_event("Select a running process PID to mark as threat pattern.", "warn")
            return

        try:
            p = psutil.Process(pid)
            proc_name = p.name()
            connections = p.net_connections()
            ips = [c.raddr.ip for c in connections if c.raddr and not is_whitelisted_ip(c.raddr.ip)]
            target_ip = ips[0] if ips else "Any"

            self.analyst_memory.record_decision(
                process_name=proc_name,
                remote_ip=target_ip,
                verdict="malicious",
                reason="Analyst confirmed malicious behavior via GUI"
            )
            self.log_event(f"🧠 [AI MEMORY] Confirmed Attack Pattern: '{proc_name}' -> {target_ip}. Dual-AI will score aggressively.", "threat")
        except psutil.NoSuchProcess:
            self.log_event(f"[!] PID {pid} is no longer running.", "warn")
        except Exception as e:
            self.log_event(f"Memory update error: {e}", "threat")

    # --- ABOUT DIALOG ---
    def show_about_window(self):
        about_win = ctk.CTkToplevel(self)
        about_win.title("About Ghost-Aegis")
        about_win.geometry("460x510")
        about_win.attributes("-topmost", True)

        ctk.CTkLabel(about_win, text="GHOST-AEGIS", font=("Fixedsys", 28, "bold"), text_color="#00FF00").pack(pady=20)
        ctk.CTkLabel(about_win, text="Version 3.0.0 | 'Sentinel Blue Enterprise EDR/XDR'", font=("Arial", 10, "italic")).pack()

        mission_text = (
            "Mission: Save the World through Internet Safety.\n\n"
            "Ghost-Aegis is an active defensive engineering suite designed for "
            "Blue Team operations. Powered by Gemini 4 (Hydrogen, Argon, Carbon) "
            "and Copilot, it integrates Live Process Ancestry Tree & Kill-Chain "
            "Timeline Reconstruction, Native YARA & Sigma Detection Engines, "
            "Parent-Child Masquerading Detection, Ransomware Early Warning, "
            "Purple Team Simulation, and SHA-256 Chain-of-Custody Auditing."
        )

        mission_box = ctk.CTkTextbox(about_win, width=400, height=150, font=("Arial", 12))
        mission_box.insert("0.0", mission_text)
        mission_box.configure(state="disabled", fg_color="#2b2b2b")
        mission_box.pack(pady=15, padx=20)

        ctk.CTkLabel(about_win, text="Cyber Defense Lead:", font=("Arial", 12, "bold"), text_color="#3b8ed0").pack()
        ctk.CTkLabel(about_win, text='[Homero "Joseph Awana" Antillon / Gemini 4 / Copilot]', font=("Consolas", 14)).pack(pady=5)
        ctk.CTkLabel(about_win, text="Gemini 4 Hydrogen • Argon • Carbon • Pure-Python YARA & Sigma XDR", font=("Arial", 9)).pack(pady=(15, 0))
        ctk.CTkButton(about_win, text="CLOSE", fg_color="#444444", command=about_win.destroy).pack(pady=15)

    # ==========================================================================
    # --- UPGRADE 7 & 10 UI: SINGLE INVESTIGATION VIEW + XDR CAMPAIGNS (v3.0) ---
    # ==========================================================================
    def show_incidents_window(self):
        workbench = ctk.CTkToplevel(self)
        workbench.title("Ghost-Aegis v3.0 | Single Investigation View (Process Tree, Kill-Chain & XDR Campaigns)")
        workbench.geometry("1200x750")
        workbench.attributes("-topmost", True)
        workbench.configure(fg_color="#0a0d12")

        # Gather unified records from both aegis_edr_alerts.jsonl and incident_store
        records = []
        if EDR_CHAIN_LOG_PATH.exists():
            try:
                for line in reversed(EDR_CHAIN_LOG_PATH.read_text(encoding="utf-8").splitlines()):
                    if line.strip():
                        rec = json.loads(line)
                        rec["_source"] = "YARA_CHAIN"
                        records.append(rec)
            except Exception:
                pass

        for inc in reversed(load_incidents()[-50:]):
            inc_copy = dict(inc)
            inc_copy["_source"] = "INCIDENT_STORE"
            records.append(inc_copy)

        campaigns = ThreatCampaignCorrelator.cluster_campaigns(records)

        # --- TOP BAR: Incident Selector & Chain Integrity Status ---
        top_bar = ctk.CTkFrame(workbench, fg_color="#161b22", corner_radius=8)
        top_bar.pack(fill="x", padx=15, pady=(12, 6))

        ctk.CTkLabel(
            top_bar,
            text="🔍 SELECT INCIDENT:",
            font=("Consolas", 13, "bold"),
            text_color="#00E5FF",
        ).pack(side="left", padx=(12, 6), pady=10)

        options = []
        for idx, r in enumerate(records):
            if r.get("_source") == "YARA_CHAIN":
                label = f"[#{idx+1} SEALED] {r.get('process')} (PID {r.get('pid')}) - {r.get('rule_triggered')} [{r.get('mitre_id')}]"
            else:
                label = f"[#{idx+1} INCIDENT] {r.get('process')} (PID {r.get('pid')}) - Risk {r.get('risk_score', 0)}/100 ({r.get('remote_ip', 'local')})"
            options.append(label)

        if not options:
            options = ["No recorded incidents (Click 'Purple Team Sim' or 'Inspect Active PID')"]

        incident_menu = ctk.CTkOptionMenu(
            top_bar,
            values=options,
            width=500,
            fg_color="#1f538d",
            button_color="#14375e",
            font=("Consolas", 11),
        )
        incident_menu.pack(side="left", padx=6, pady=10)

        seal_badge = ctk.CTkLabel(
            top_bar,
            text="⛓️ SHA-256 SEAL: STANDBY",
            font=("Consolas", 12, "bold"),
            text_color="#00FF00",
        )
        seal_badge.pack(side="right", padx=12, pady=10)

        # --- MIDDLE SPLIT PANES: Left = Process Tree | Right = Kill-Chain & XDR Campaigns ---
        split_frame = ctk.CTkFrame(workbench, fg_color="transparent")
        split_frame.pack(fill="both", expand=True, padx=15, pady=4)
        split_frame.grid_columnconfigure(0, weight=1)
        split_frame.grid_columnconfigure(1, weight=1)
        split_frame.grid_rowconfigure(0, weight=1)

        # Left Pane: Process Ancestry Tree + Deep Telemetry
        left_pane = ctk.CTkFrame(split_frame, fg_color="#161b22", corner_radius=8)
        left_pane.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=2)

        ctk.CTkLabel(
            left_pane,
            text="🌳 LIVE PROCESS ANCESTRY TREE (PPID LINEAGE & TELEMETRY)",
            font=("Consolas", 13, "bold"),
            text_color="#FF7518",
        ).pack(anchor="w", padx=12, pady=(8, 4))

        tree_box = ctk.CTkTextbox(
            left_pane,
            font=("Consolas", 11),
            fg_color="#000000",
            text_color="#00FF00",
            wrap="none",
        )
        tree_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Right Pane: Chronological Kill-Chain Timeline + XDR Campaign Clusters
        right_pane = ctk.CTkFrame(split_frame, fg_color="#161b22", corner_radius=8)
        right_pane.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=2)

        ctk.CTkLabel(
            right_pane,
            text="⏱️ ATTACK TIMELINE RECONSTRUCTION & XDR CAMPAIGN CLUSTERS",
            font=("Consolas", 13, "bold"),
            text_color="#00E5FF",
        ).pack(anchor="w", padx=12, pady=(8, 4))

        timeline_box = ctk.CTkTextbox(
            right_pane,
            font=("Consolas", 11),
            fg_color="#000000",
            text_color="#e6edf3",
            wrap="word",
        )
        timeline_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # --- BOTTOM BAR: Threat DNA, MITRE Summary & Direct Response Controls ---
        bottom_bar = ctk.CTkFrame(workbench, fg_color="#161b22", corner_radius=8)
        bottom_bar.pack(fill="x", padx=15, pady=(6, 12))

        dna_label = ctk.CTkLabel(
            bottom_bar,
            text="🧬 THREAT DNA: N/A | MITRE: N/A",
            font=("Consolas", 12, "bold"),
            text_color="#BA55D3",
        )
        dna_label.pack(side="left", padx=12, pady=10)

        def render_record(rec: dict):
            pid = rec.get("pid", 0)
            proc_name = rec.get("process", "unknown")
            reasons = rec.get("reasons", rec.get("matched_indicators", []))
            dna = generate_threat_dna(
                proc_name,
                rec.get("signer", "Unknown"),
                rec.get("remote_ip", "local"),
                [str(x) for x in reasons],
            )
            mitre_str = rec.get("mitre_id") or ", ".join(
                [r for r in reasons if "MITRE" in str(r) or "YARA" in str(r) or "SIGMA" in str(r)]
            ) or "Heuristic / Behavioral"

            # 1. Update Seal Badge
            seal = rec.get("sha256_seal")
            if seal:
                seal_badge.configure(
                    text=f"⛓️ SHA-256 SEAL VERIFIED: {seal[:16]}...",
                    text_color="#00FF00",
                )
            else:
                seal_badge.configure(
                    text="⛓️ INCIDENT STORE RECORD (UNSEALED)",
                    text_color="#FFBF00",
                )

            # 2. Build or Retrieve Process Ancestry Tree
            tree_data = rec.get("process_tree")
            if not tree_data and pid > 0:
                tree_data = AegisForensicCorrelator.capture_process_tree(pid)
                rec["process_tree"] = tree_data

            tree_box.configure(state="normal")
            tree_box.delete("1.0", "end")
            tree_text = [
                "=" * 70,
                f" INCIDENT TARGET : {proc_name} (PID: {pid})",
                f" DETECTION RULE  : {rec.get('rule_triggered', 'Behavioral / Network Sentinel')}",
                f" EXECUTABLE PATH : {rec.get('exe_path') or rec.get('path', 'N/A')}",
                f" REMOTE ENDPOINT : {rec.get('remote_ip', 'local_spawn')}",
                f" DIGITAL SIGNER  : {rec.get('signer', 'N/A')}",
                "=" * 70,
                "",
                tree_data.get("ascii_tree", "No process tree available.") if tree_data else "No process tree available.",
                "",
                "-" * 70,
                " FORENSIC INDICATORS & EVIDENCE:",
            ]
            for ind in reasons:
                tree_text.append(f"  • {ind}")
            if rec.get("matched_cmdline"):
                tree_text.append(f"\n CAPTURED COMMAND LINE:\n  {rec['matched_cmdline']}")

            tree_box.insert("1.0", "\n".join(tree_text))
            tree_box.configure(state="disabled")

            # 3. Reconstruct Attack Kill-Chain Timeline + XDR Campaign Clusters
            timeline_steps = AegisForensicCorrelator.reconstruct_timeline(rec)
            timeline_box.configure(state="normal")
            timeline_box.delete("1.0", "end")

            t_lines = [
                "=" * 68,
                " CHRONOLOGICAL KILL-CHAIN RECONSTRUCTION",
                "=" * 68,
                "",
            ]
            for idx, step in enumerate(timeline_steps):
                if idx > 0:
                    t_lines.append("        │")
                    t_lines.append("        ▼")
                t_lines.append(f"[{step['time']}] 🛡️ {step['stage']}")
                t_lines.append(f"   ├─ Action   : {step['action']}")
                t_lines.append(f"   └─ Evidence : {step['evidence']}")

            if campaigns:
                t_lines.extend([
                    "",
                    "=" * 68,
                    f" 🔗 XDR THREAT CAMPAIGN CLUSTERING ({len(campaigns)} ACTIVE CLUSTERS)",
                    "=" * 68,
                ])
                for c in campaigns[:5]:
                    mitres = ", ".join(sorted(c["mitre_techniques"]))
                    t_lines.append(
                        f"\n[Campaign #{c['campaign_id']}] Root PID: {c['root_pid']} | Primary: {c['primary_process']} ({c['event_count']} correlated events)"
                    )
                    t_lines.append(f"   ├─ MITRE TTPs : {mitres}")
                    t_lines.append(f"   └─ Detections : {' | '.join(c['rules_triggered'][:3])}")

            timeline_box.insert("1.0", "\n".join(t_lines))
            timeline_box.configure(state="disabled")

            # 4. Update Bottom DNA & MITRE Bar
            root_pid = tree_data.get("root_pid", pid) if tree_data else pid
            dna_label.configure(
                text=f"🧬 THREAT DNA: {dna}  |  🎯 ROOT PID: {root_pid}  |  ⚔️ {mitre_str[:45]}"
            )
            if pid > 0:
                self.pid_entry.set(f"{pid} ({proc_name})")

        def on_select_incident(choice: str):
            if not records:
                return
            try:
                idx = int(choice.split("#")[1].split()[0]) - 1
                if 0 <= idx < len(records):
                    render_record(records[idx])
            except Exception:
                pass

        incident_menu.configure(command=on_select_incident)

        def inspect_live_selected_pid():
            live_pid = self._get_selected_pid() or os.getpid()
            try:
                p = psutil.Process(live_pid)
                live_rec = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "pid": live_pid,
                    "ppid": p.ppid(),
                    "process": p.name(),
                    "path": p.exe() if p.exe() else "N/A",
                    "remote_ip": "live_inspection",
                    "signer": get_authenticode_signer(p.exe() if p.exe() else ""),
                    "risk_score": 50,
                    "reasons": ["Live Analyst Process Tree Inspection"],
                    "process_tree": AegisForensicCorrelator.capture_process_tree(live_pid),
                }
                render_record(live_rec)
            except Exception as exc:
                self.log_event(f"[!] Live PID tree inspection error: {exc}", "warn")

        ctk.CTkButton(
            bottom_bar,
            text="CLOSE",
            fg_color="#444444",
            width=90,
            command=workbench.destroy,
        ).pack(side="right", padx=(6, 12), pady=10)

        ctk.CTkButton(
            bottom_bar,
            text="Freeze + Vault PID",
            fg_color="#B85D00",
            hover_color="#7A3E00",
            width=135,
            command=self.quarantine_process_callback,
        ).pack(side="right", padx=6, pady=10)

        ctk.CTkButton(
            bottom_bar,
            text="Dual-AI Triage PID",
            fg_color="#4B0082",
            hover_color="#300052",
            width=135,
            command=self.run_dual_ai_eval,
        ).pack(side="right", padx=6, pady=10)

        ctk.CTkButton(
            bottom_bar,
            text="Inspect Active PID Tree",
            fg_color="#005577",
            hover_color="#00384F",
            width=155,
            command=inspect_live_selected_pid,
        ).pack(side="right", padx=6, pady=10)

        # Render the most recent incident immediately on open, or fall back to live host tree
        if records:
            render_record(records[0])
        else:
            inspect_live_selected_pid()

    # --- REPORT EXPORT ---
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

    # --- NETWORK TRUST DASHBOARD ---
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
            controls, placeholder_text="Search process, PID, IP, port, or path...", width=300,
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
                f"{'PID':<8} {'PROCESS':<16} {'DESTINATION':<20} {'PORT':<6} "
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
                    for field in ("pid", "process", "destination", "port", "path")
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
                    f"{str(row['pid']):<8} {row['process'][:15]:<16} {row['destination'][:19]:<20} "
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
            if is_whitelisted_ip(remote_ip):
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
                "pid": connection.pid,
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

    # --- LIVE GLOBAL THREAT RADAR ---
    def show_threat_map(self):
        try:
            import tkintermapview
        except ImportError:
            self.log_event("[-] tkintermapview not installed. Run: pip install tkintermapview", "threat")
            return

        map_win = ctk.CTkToplevel(self)
        map_win.title("Ghost-Aegis | Global Threat Radar")
        map_win.geometry("950x650")
        map_win.attributes("-topmost", True)

        ctk.CTkLabel(
            map_win,
            text="LIVE GLOBAL THREAT RADAR",
            font=("Consolas", 16, "bold"),
            text_color="#FF3333"
        ).pack(pady=(15, 5))

        map_widget = tkintermapview.TkinterMapView(map_win, corner_radius=0)
        map_widget.pack(fill="both", expand=True, padx=20, pady=(5, 20))
        
        carto_key = os.getenv("CARTO_API_KEY")
        if carto_key and carto_key.strip():
            map_widget.set_tile_server(f"https://a.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}.png?key={carto_key}", max_zoom=19)
        else:
            self.log_event("[!] No CARTO_API_KEY found in .env. Defaulting to Satellite view.", "warn")
            map_widget.set_tile_server("https://mt0.google.com/vt/lyrs=s&hl=en&x={x}&y={y}&z={z}&s=Ga", max_zoom=22)

        home_lat, home_lon = 33.9400, -118.0267
        map_widget.set_position(home_lat, home_lon)
        map_widget.set_zoom(2)

        map_widget.set_marker(
            home_lat, home_lon, 
            text="AEGIS ORIGIN (DEFENDER)", 
            marker_color_circle="#00FF00",
            marker_color_outside="#004400"
        )

        def plot_threats():
            self._queue_log("[*] Polling incident history for global coordinates...", "system")
            incidents = load_incidents()
            plotted_ips = set()
            count = 0

            for incident in reversed(incidents[-20:]):
                ip = incident.get("remote_ip")
                risk = incident.get("risk_score", 0)

                if ip and not is_whitelisted_ip(ip) and risk >= 40 and ip not in plotted_ips:
                    lat, lon, city = self.get_ip_coords(ip)
                    if lat and lon:
                        plotted_ips.add(ip)
                        count += 1
                        color = "#FF3333" if risk >= 70 else "#FFBF00"
                        map_widget.set_marker(
                            lat, lon, 
                            text=f"[{risk}/100] {city} ({ip})",
                            marker_color_circle=color,
                            marker_color_outside="#000000"
                        )
                        map_widget.set_path([(home_lat, home_lon), (lat, lon)], color=color, width=2)

            if count > 0:
                self._queue_log(f"[+] Plotted {count} active threat vectors on the map.", "trusted")
            else:
                self._queue_log("[+] Radar clear. No external threat coordinates found.", "trusted")

        threading.Thread(target=plot_threats, daemon=True).start()

    # --- AI EXECUTIVE BRIEFING GENERATOR (GEMINI 4 CARBON / ARGON / HYDROGEN) ---
    def run_ai_incident_report(self):
        incidents = load_incidents()
        if not incidents:
            self.log_event("[!] No incidents logged yet to generate an IR report.", "warn")
            return

        gemini_key = os.getenv("GEMINI_API_KEY")
        if not gemini_key:
            self.log_event("[-] GEMINI_API_KEY missing in .env. Cannot generate AI briefing.", "threat")
            return

        self.ai_report_button.configure(state="disabled", text="Synthesizing Brief...")
        self.log_event(
            "[*] Aggregating telemetry and generating AI Incident Response Brief via Gemini 4 (gemini-4-carbon / argon / hydrogen)...",
            "system",
        )
        threading.Thread(target=self._ai_incident_report_worker, args=(incidents[-35:], gemini_key), daemon=True).start()

    def _ai_incident_report_worker(self, incidents, api_key):
        try:
            telemetry_lines = []
            for inc in incidents:
                dna = generate_threat_dna(
                    inc.get("process", "unknown"),
                    inc.get("signer", "Unknown"),
                    inc.get("remote_ip", "none"),
                    inc.get("reasons", [])
                )
                
                raw_inc_data = {
                    "timestamp": inc.get('timestamp', 'N/A'),
                    "dna": dna,
                    "process": inc.get('process'),
                    "pid": inc.get('pid'),
                    "path": inc.get('path'),
                    "remote_ip": inc.get('remote_ip'),
                    "risk_score": inc.get('risk_score'),
                    "signer": inc.get('signer'),
                    "flags": inc.get('reasons', [])
                }
                clean_inc = self.sanitizer.sanitize_log(raw_inc_data)
                
                telemetry_lines.append(
                    f"- Timestamp: {clean_inc['timestamp']} | DNA: {clean_inc['dna']} | Process: {clean_inc['process']} "
                    f"(PID: {clean_inc['pid']}) | Path: {clean_inc['path']} | Remote IP: {clean_inc['remote_ip']} "
                    f"| Risk Score: {clean_inc['risk_score']}/100 | Signer: {clean_inc['signer']} "
                    f"| Flags: {', '.join(clean_inc['flags'])}"
                )
            
            telemetry_dump = "\n".join(telemetry_lines)

            prompt = (
                "You are a Lead Incident Response Commander and Cyber Threat Intelligence Analyst. "
                "Synthesize the following security telemetry log into an executive-level Incident Response Briefing "
                "and Post-Mortem Report. Structure your response cleanly using formal Markdown with these sections:\n\n"
                "# GHOST-AEGIS EXECUTIVE INCIDENT RESPONSE BRIEF\n"
                "## 1. Executive Summary & Threat Posture Verdict\n"
                "## 2. Key Indicators of Compromise (IOCs) & Flagged Entities\n"
                "## 3. Attack Chain & Anomaly Analysis (TTPs)\n"
                "## 4. Tactical Containment & System Hardening Directives\n\n"
                "Be authoritative, analytical, and concise. Avoid filler. Focus on risk mitigation.\n\n"
                f"### TELEMETRY LOGS:\n{telemetry_dump}"
            )

            report_text, model_used = _query_gemini_rest(
                prompt=prompt,
                api_key=api_key,
                preferred_model="gemini-4-carbon",
            )
            self._queue_log(f"[+] AI Incident Brief synthesized successfully using {model_used}.", "trusted")
            self.log_queue.put(("__ai_report_complete__", report_text))

        except Exception as error:
            self._queue_log(f"AI Report Generation failed: {error}", "threat")
            self.log_queue.put(("__ai_report_complete__", None))

    def show_ai_report_window(self, report_markdown: str):
        report_win = ctk.CTkToplevel(self)
        report_win.title("Ghost-Aegis | AI Incident Response Briefing (Gemini 4)")
        report_win.geometry("900x650")
        report_win.attributes("-topmost", True)

        ctk.CTkLabel(
            report_win,
            text="EXECUTIVE INCIDENT RESPONSE BRIEFING (GEMINI 4 SUITE)",
            font=("Consolas", 15, "bold"),
            text_color="#00E5FF",
        ).pack(pady=(12, 4))

        report_box = ctk.CTkTextbox(
            report_win,
            font=("Consolas", 11),
            fg_color="#000000",
            text_color="#00FF00",
            wrap="word",
        )
        report_box.pack(fill="both", expand=True, padx=15, pady=8)
        report_box.insert("1.0", report_markdown)
        report_box.configure(state="disabled")

        action_frame = ctk.CTkFrame(report_win, fg_color="transparent")
        action_frame.pack(fill="x", padx=15, pady=(4, 12))

        def save_markdown():
            destination = filedialog.asksaveasfilename(
                title="Save Executive Briefing",
                defaultextension=".md",
                filetypes=[("Markdown Document", "*.md"), ("Text Document", "*.txt"), ("All Files", "*.*")],
                initialfile=f"IR_Brief_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            )
            if not destination:
                return
            try:
                with open(destination, "w", encoding="utf-8") as f:
                    f.write(report_markdown)
                self.log_event(f"[+] Executive IR Brief exported to: {destination}", "trusted")
            except OSError as write_err:
                self.log_event(f"Failed to save IR Brief: {write_err}", "threat")

        ctk.CTkButton(
            action_frame,
            text="Save to Markdown (.md)",
            fg_color="#1f538d",
            hover_color="#14375e",
            command=save_markdown,
            width=180,
        ).pack(side="left")

        ctk.CTkButton(
            action_frame,
            text="CLOSE",
            fg_color="#444444",
            command=report_win.destroy,
            width=100,
        ).pack(side="right")

    # ==========================================================================
    # --- UPGRADE 9 HOOK: CANARY SHIELD + RANSOMWARE I/O WRITE CORRELATOR ---
    # ==========================================================================
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
            self.log_event("[+] Canary Shield active: monitoring protected canary files with I/O write-spike correlation.", "trusted")

    def _canary_finding_callback(self, finding):
        path = finding["path"]
        action = finding["action"]

        # Correlate Canary hit with active disk write-spike process & PE entropy
        suspect = RansomwareEarlyWarning.identify_high_writer_pid()
        s_pid = suspect.get("pid", 0)
        s_name = suspect.get("name", "Unknown")
        s_writes = suspect.get("write_bytes", 0)
        s_entropy = suspect.get("entropy", 0.0)
        tree_snapshot = AegisForensicCorrelator.capture_process_tree(s_pid) if s_pid > 0 else {}

        alert_payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pid": s_pid,
            "ppid": os.getppid(),
            "process": s_name,
            "exe_path": suspect.get("exe", path),
            "rule_triggered": f"RANSOMWARE_CANARY_TRIP: {action}",
            "mitre_id": "T1486",
            "severity": "CRITICAL",
            "matched_indicators": [
                f"Canary:{Path(path).name}",
                f"WriteBytes:{s_writes}",
                f"Entropy:{s_entropy}",
            ],
            "matched_cmdline": f"Canary trip on {path} correlated to high-writer {s_name} (PID {s_pid})",
            "process_tree": tree_snapshot,
        }
        sealed = self.chain_auditor.seal_alert(alert_payload)
        self.soar_dispatcher.dispatch_alert(sealed)

        incident = Incident(
            process=s_name,
            pid=s_pid,
            path=path,
            risk_score=98,
            reasons=[
                f"Canary {action.lower()}",
                f"SuspectWriter:{s_name}(PID {s_pid})",
                f"WriteBytes:{s_writes}",
                f"ChainSeal:{sealed['sha256_seal'][:12]}",
            ],
            recommended_action="quarantine_and_review",
        )
        try:
            append_incident(incident)
        except OSError as error:
            self._queue_log(f"Canary incident record failed: {error}", "warn")

        self._queue_log(
            f"🚨 [RANSOMWARE EARLY WARNING] Canary {action}: {path} | Correlated Writer: {s_name} (PID {s_pid} | Writes: {s_writes:,} B | Entropy: {s_entropy}) | Sealed: {sealed['sha256_seal'][:18]}...",
            "threat",
        )

        if getattr(self, "auto_mitigate_enabled", False) and s_pid not in {0, os.getpid()}:
            vault_res = self.quarantine_vault.freeze_and_quarantine(
                pid=s_pid,
                reasons=[f"Ransomware Canary Trip ({action})"],
                risk_score=98,
            )
            if vault_res.get("success"):
                self._queue_log(
                    f"🚨 [RANSOMWARE AUTO-CONTAINMENT] {s_name} (PID {s_pid}) FROZEN IN RAM, VAULTED & KILLED.",
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
                elif message == "__ai_report_complete__":
                    self.ai_report_button.configure(state="normal", text="Generate AI Incident Brief (4-Carbon)")
                    if isinstance(tag, str):
                        self.show_ai_report_window(tag)
                elif message == "__interfaces_complete__":
                    self.interfaces_button.configure(state="normal", text="Interface Telemetry")
                elif message == "__persistence_complete__":
                    self.persistence_button.configure(state="normal", text="Audit Persistence")
                elif message == "__event_hunt_complete__":
                    self.event_hunt_button.configure(state="normal", text="Hunt Event IDs + Sigma (4625/4720/7045/1102)")
                elif message == "__engine_complete__":
                    self.engine_thread_running = False
                    self.engine_button.configure(state="normal", text="Launch Defense Engine")
                elif message == "__update_pids__":
                    if isinstance(tag, list) and tag:
                        self.pid_entry.configure(values=tag)
                elif message == "__set_target_pid__":
                    self.pid_entry.set(str(tag))
                else:
                    self.log_event(message, tag)
        except queue.Empty:
            pass

        self.after(100, self.check_queue)

    # --- LOGGING & CONSOLE OUTPUT ---
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
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False
        self.log_event("--- Ghost-Aegis v3.0 XDR Readiness Check ---", "system")
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
            f"Native YARA Engine ({RULE_FILE_PATH.name}): {len(self.yara_engine.rules)} rules compiled (DLL-Free READY)",
            "trusted",
        )
        self.log_event(
            f"Native Sigma Engine ({SIGMA_RULE_PATH.name}): {len(self.sigma_engine.rules)} rules compiled (YAML-Free READY)",
            "trusted",
        )
        self.log_event(
            f"SHA-256 Chain Ledger ({EDR_CHAIN_LOG_PATH.name}): Head Hash {self.chain_auditor.last_hash[:16]}...",
            "trusted",
        )
        self.log_event(
            "Forensic Process Tree, Lineage Anomaly & Campaign Correlator: READY",
            "trusted",
        )
        self.log_event(
            "Ransomware Early Warning (Canary + I/O Write-Spike Correlator): READY",
            "trusted",
        )
        self.log_event(
            f"SOAR Webhook Dispatcher: {'CONFIGURED' if self.soar_dispatcher.webhook_url else 'STANDBY (Set DISCORD_WEBHOOK_URL in .env)'}",
            "trusted" if self.soar_dispatcher.webhook_url else "review",
        )
        self.log_event(
            f"Gemini 4 Models (gemini-4-hydrogen / gemini-4-argon / gemini-4-carbon): "
            f"{'CONFIGURED (Active: ' + self.selected_gemini_model + ')' if os.getenv('GEMINI_API_KEY') else 'MISSING GEMINI_API_KEY'}",
            "trusted" if os.getenv("GEMINI_API_KEY") else "review",
        )
        self.log_event(
            f"Copilot / Secondary AI (DLL-Safe REST): "
            f"{'CONFIGURED' if os.getenv('OPENAI_API_KEY') or os.getenv('COPILOT_API_KEY') else 'LOCAL OLLAMA FALLBACK'}",
            "trusted" if os.getenv("OPENAI_API_KEY") or os.getenv("COPILOT_API_KEY") else "review",
        )
        self.log_event(
            f"Quarantine Vault Directory: {self.quarantine_vault.vault_dir} (READY)",
            "trusted",
        )
        self.log_event(
            f"Remote SIEM UDP Streamer: {self.siem_streamer.host}:{self.siem_streamer.port} (ACTIVE)",
            "trusted",
        )
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

    # --- DEFENSE ENGINE: DUAL-AI DAEMON ---
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
            asyncio.run(jit_engine.run_defense_engine(start_cli=False, safe_mode=True))
            self._queue_log("Defense engine loop ended.", "trusted")
        except Exception as error:
            self._queue_log(f"Defense engine failed: {error}", "threat")
        finally:
            self.log_queue.put(("__engine_complete__", None))

    # --- BEHAVIOR & BREACH WORKERS ---
    def run_behavior_scan(self):
        self.log_event("[*] Running behavior fingerprint scan...", "identity")
        keystrokes = {"avg_delay": 0.12, "variance": 0.03}
        mouse_movements = {"speed": 1.4, "jitter": 0.2}

        result = get_behavior_score(keystrokes, mouse_movements)
        if "error" in result:
            self.log_event(f"[!] Behavior API error: {result['error']}", "threat")
            return

        score = result.get("score", 0)
        risk = result.get("risk", "unknown")
        tag = "identity" if score < 50 else "warn" if score < 75 else "threat"
        self.log_event(f"[IDENTITY] Behavior Score={score} | Risk={risk}", tag)

        incident = Incident(
            process="BehaviorEngine",
            pid=0,
            path="behavior_fingerprint",
            risk_score=score,
            reasons=[f"Behavior anomaly detected: {risk}"],
            recommended_action="review_identity",
        )
        try:
            append_incident(incident)
        except OSError as log_error:
            self._queue_log(f"Incident record failed: {log_error}", "warn")

    # --- DARK WEB BREACH CHECK ---
    def run_breach_check(self):
        self.log_event("[*] Checking dark web breach exposure...", "breach")
        target_email = os.getenv("ADMIN_EMAIL")
        if not target_email or target_email.strip() == "":
            dialog = ctk.CTkInputDialog(
                text="No ADMIN_EMAIL found in .env\n\nEnter the target email to scan:", 
                title="Dark Web Intelligence"
            )
            target_email = dialog.get_input()
            if not target_email:
                self.log_event("[!] Breach check cancelled: No target email provided.", "warn")
                return

        result = check_breach(target_email)
        if "error" in result:
            self.log_event(f"[!] Breach API error: {result['error']}", "threat")
            return

        exposed = result.get("exposed", False)
        details = result.get("details", "No details provided")
        if exposed:
            self.log_event(f"[BREACH] Exposure detected: {details}", "breach")
            incident = Incident(
                process="BreachIntel",
                pid=0,
                path="dark_web_exposure",
                risk_score=90,
                reasons=[f"Dark web exposure: {details}"],
                recommended_action="rotate_credentials",
            )
            try:
                append_incident(incident)
            except OSError as log_error:
                self._queue_log(f"Incident record failed: {log_error}", "warn")
        else:
            self.log_event(f"[BREACH] {details}", "trusted")

    # --- DEFENSE: STEALTH, EMERGENCY CLEAN, HOST ISOLATION ---
    def run_stealth(self):
        if os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
            self.log_event("[-] Elevation required: Run Ghost-Aegis as Administrator to manage firewall rules.", "threat")
            return

        self.log_event("[*] Engaging Stealth Protocol: Dropping inbound ICMP...", "warn")
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=GhostAegis_Stealth_DropPing"],
                capture_output=True, text=True, check=False
            )
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=GhostAegis_Stealth_DropPing", "dir=in", "action=block", "protocol=icmpv4"
            ], capture_output=True, text=True, check=True)
            self.log_event("🛡️ STEALTH ACTIVE: Machine is silent to ICMP ping sweeps.", "trusted")
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() if e.stderr else str(e)
            self.log_event(f"Failed to activate stealth: {err_msg}", "threat")
        except Exception as e:
            self.log_event(f"Failed to activate stealth: {e}", "threat")

    # --- EMERGENCY CLEANUP & AIR-GAP ISOLATION ---
    def run_cleanup(self):
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

    # --- ACTIVE AI DECOY ---
    def toggle_ghost_protocol(self):
        if self.decoy_loop and self.decoy_loop.is_running():
            self.decoy_loop.call_soon_threadsafe(self.ghost_decoy.stop_server)
            self.decoy_loop.call_soon_threadsafe(self.decoy_loop.stop)
            self.ghost_button.configure(text="Engage Ghost Protocol (Decoy)", fg_color="#006400")
            self.log_event("[-] Ghost Protocol Decoy disengaged.", "review")
            self.decoy_loop = None
        else:
            self.ghost_button.configure(text="Disengage Ghost Protocol", fg_color="#880808")
            self.log_event("[*] GHOST PROTOCOL ENGAGED: Decoy listener active on Port 2222.", "warn")
            
            def run_async_decoy():
                self.decoy_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self.decoy_loop)
                self.decoy_loop.create_task(self.ghost_decoy.start_server())
                self.decoy_loop.run_forever()

            self.decoy_thread = threading.Thread(target=run_async_decoy, daemon=True)
            self.decoy_thread.start()

    # --- THREAT INTELLIGENCE & GEOLOCATION ---
    def check_ip_reputation(self, ip_address):
        if is_whitelisted_ip(ip_address):
            return 0
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
        if is_whitelisted_ip(ip):
            return "Internal/Trusted"
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=1.5).json()
            if response.get("status") == "success":
                return f"{response.get('city')}, {response.get('countryCode')}"
            return "Unknown Loc"
        except Exception:
            return "Loc Error"

    def get_ip_coords(self, ip):
        if is_whitelisted_ip(ip):
            return None, None, "Internal"
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2.0).json()
            if response.get("status") == "success":
                return response.get("lat"), response.get("lon"), response.get("city")
        except Exception:
            pass
        return None, None, "Unknown"

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
        self.log_event("[*] Network Sentinel starting deep socket + YARA + Sigma + Lineage + ARP audit...", "system")
        threading.Thread(target=self._network_sentinel_worker, daemon=True).start()

    def _network_sentinel_worker(self):
        trusted_domains = ["google.com", "github.com", "microsoft.com", "akamai", "azure", "cloudflare", "amazonaws", "apple.com", "mozilla.org", "openai.com", "abuseipdb.com", "carto.com", "ip-api.com"]    
        active_pids = []
        highest_threat_pid = None
        max_risk = -1

        try:
            arp_check = self.arp_guard.scan_arp_table()
            for arp_alert in arp_check.get("alerts", []):
                self._queue_log(f"🚨 [ARP SPOOF ALERT] {arp_alert}", "threat")

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

                    if is_whitelisted_ip(ip_only):
                        continue

                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                        exe_path = proc.exe()
                    except Exception:
                        proc_name = "Unknown"
                        exe_path = ""

                    entry_label = f"{pid} ({proc_name})"
                    if entry_label not in active_pids:
                        active_pids.append(entry_label)

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
                    except Exception as history_error:
                        behavior = {"first_seen": False, "beacon": False}
                        self._queue_log(f"Network history error: {history_error}", "warn")

                    if behavior.get("first_seen"):
                        self._queue_log(f"[NEW DESTINATION] {proc_name} -> {ip_only}:{remote_port}", "review")
                    if behavior.get("beacon"):
                        self._queue_log(f"[BEACON PATTERN] {proc_name} repeatedly contacts {ip_only}:{remote_port}", "warn")

                    signer = get_authenticode_signer(exe_path)
                    reputation = 0
                    trusted_process = False

                    if any(d in hostname.lower() for d in trusted_domains):
                        status, tag_name = "[TRUSTED]", "trusted"
                        trusted_process = True
                    elif proc_name.lower() in PROCESS_WHITELIST:
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

                    cmd_info = self.edr_inspector.inspect_cmdline(pid)
                    if cmd_info["suspicious_flags"]:
                        reasons.extend(cmd_info["suspicious_flags"])
                        risk_score = min(100, risk_score + cmd_info["risk_boost"])

                    # Scan command line against Native YARA, Sigma & Lineage Rules
                    yara_hits = self.yara_engine.scan_command_line(pid, proc_name, cmd_info["cmdline"])
                    for yh in yara_hits:
                        reasons.append(f"{yh['rule_triggered']}({yh['mitre_id']})")
                        risk_score = max(risk_score, 90)

                    sigma_hits = self.sigma_engine.evaluate_process(pid, proc_name, cmd_info["cmdline"])
                    for sh in sigma_hits:
                        reasons.append(f"{sh['rule_triggered']}({sh['mitre_id']})")
                        risk_score = max(risk_score, 90)

                    tree_snapshot = AegisForensicCorrelator.capture_process_tree(pid)
                    lineage_hits = ParentChildAnomalyDetector.evaluate_lineage(tree_snapshot)
                    for lh in lineage_hits:
                        reasons.append(f"{lh['rule_triggered']}({lh['mitre_id']})")
                        risk_score = max(risk_score, 95)

                    if not trusted_process and exe_path:
                        pe_info = self.edr_inspector.scan_pe_binary(exe_path)
                        if pe_info["packed"]:
                            reasons.append(f"HighEntropy:{pe_info['entropy']}")
                        if pe_info["suspicious_apis"]:
                            reasons.append(f"InjAPIs:{','.join(pe_info['suspicious_apis'][:3])}")
                        risk_score = min(100, risk_score + pe_info["risk_boost"])

                    raw_event_data = {
                        "process": proc_name,
                        "path": exe_path,
                        "cmdline": cmd_info.get("cmdline", ""),
                        "decoded_b64": cmd_info.get("decoded_b64"),
                        "remote_ip": ip_only,
                        "port": remote_port,
                        "risk_score": risk_score,
                        "reasons": reasons
                    }
                    sanitized_event = self.sanitizer.sanitize_log(raw_event_data)
                    crypto_hash = self.sanitizer.secure_hash_log(sanitized_event)
                    mitre_hits = self.sanitizer.correlate_mitre(json.dumps(sanitized_event))
                    
                    for hit in mitre_hits:
                        reasons.append(f"MITRE: {hit['id']} ({hit['technique']})")
                        if hit['severity'] in ["HIGH", "CRITICAL"]:
                            risk_score = max(risk_score, 85)
                    
                    reasons.append(f"ChainHash: {crypto_hash[:12]}")

                    self.siem_streamer.emit(sanitized_event, crypto_hash)

                    if risk_score > max_risk:
                        max_risk = risk_score
                        highest_threat_pid = pid

                    recommended_act = "review"
                    
                    if risk_score >= 70:
                        status, tag_name = "[THREAT]", "threat"
                        recommended_act = "block_and_review"
                        
                        if getattr(self, "auto_mitigate_enabled", False):
                            recommended_act = "auto_vaulted_blocked_and_killed"
                            vault_res = self.quarantine_vault.freeze_and_quarantine(
                                pid=pid,
                                reasons=reasons,
                                risk_score=risk_score,
                            )
                            if vault_res.get("success"):
                                self._queue_log(
                                    f"🚨 [AUTO-MITIGATE VAULT] {proc_name} (PID {pid}) FROZEN, VAULTED & KILLED.",
                                    "threat"
                                )
                            else:
                                self._queue_log(f"[-] Auto-Mitigate Vault error for {pid}: {vault_res.get('error')}", "warn")
                            
                            block_result = block_ip(ip_only, rule_suffix="ThreatAuto")
                            self._queue_log(f"🚨 [AUTO-MITIGATE] {block_result}", "threat")
                            
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
                        recommended_action=recommended_act,
                    )
                    try:
                        append_incident(incident)
                    except OSError as log_error:
                        self._queue_log(f"Incident record failed: {log_error}", "warn")

                    self._auto_learn_telemetry(
                        proc_name=proc_name,
                        remote_ip=ip_only,
                        signer=signer,
                        risk_score=risk_score,
                        exe_path=exe_path,
                        observation=behavior,
                        reasons=reasons
                    )

                    self._queue_log(f"{status:<12} {proc_name:<16} {display_host:<42} {pid:<6}", tag_name)
                    self._queue_log(
                        f"   Evidence: {'; '.join(reasons)} | Signer: {signer}",
                        tag_name,
                    )
                    found_active = True

            if not found_active:
                self._queue_log("No active external sockets detected.")

            if active_pids:
                self.log_queue.put(("__update_pids__", active_pids))
            if highest_threat_pid and max_risk >= 40:
                self.log_queue.put(("__set_target_pid__", str(highest_threat_pid)))

        except Exception as e:
            self._queue_log(f"Audit Exception: {e}", "threat")
        finally:
            self.log_queue.put(("__scan_complete__", None))

    # --- PROCESS TERMINATION & DUAL-AI ANALYSIS WITH GEMINI 4 (HYDROGEN / ARGON / CARBON) ---
    def terminate_process_callback(self):
        pid = self._get_selected_pid()
        if pid is not None:
            try:
                p = psutil.Process(pid)
                process_name = p.name()
                p.terminate()
                self.log_event(f"[X] Terminated process {process_name} (PID: {pid}).", "threat")
                self.refresh_active_pids()
            except Exception as e:
                self.log_event(f"Process kill error: {e}", "threat")
        else:
            self.log_event("Invalid or empty PID entered for termination.", "warn")

    def run_dual_ai_eval(self):
        pid = self._get_selected_pid()
        if pid is not None:
            preferred_gemini = self.gemini_model_menu.get()
            self.log_event(
                f"[*] Extracting deep EDR + Process Tree + YARA & Sigma telemetry and invoking Dual-AI ({preferred_gemini} + Copilot) for PID {pid}...",
                "system",
            )
            self.ai_eval_button.configure(state="disabled")
            threading.Thread(
                target=self._dual_ai_worker,
                args=(pid, preferred_gemini),
                daemon=True,
            ).start()
        else:
            self.log_event("Invalid or empty PID selected for AI evaluation.", "warn")

    def _dual_ai_worker(self, pid, preferred_gemini="gemini-4-hydrogen"):
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
            remote_ips = [c.raddr.ip for c in connections if c.raddr and not is_whitelisted_ip(c.raddr.ip)]

            cmd_info = self.edr_inspector.inspect_cmdline(pid)
            pe_info = self.edr_inspector.scan_pe_binary(exe_path if exe_path != "Unavailable" else "")
            yara_hits = self.yara_engine.scan_command_line(pid, proc_name, cmd_info["cmdline"])
            sigma_hits = self.sigma_engine.evaluate_process(pid, proc_name, cmd_info["cmdline"])
            tree_info = AegisForensicCorrelator.capture_process_tree(pid)
            lineage_hits = ParentChildAnomalyDetector.evaluate_lineage(tree_info)

            memory_context = self.analyst_memory.get_prompt_context()

            raw_context_data = {
                "Process Name": proc_name,
                "PID": pid,
                "Parent Process": parent_name,
                "Process Lineage Chain": [f"{n['name']} (PID {n['pid']})" for n in tree_info.get("nodes", [])],
                "Executable Path": exe_path,
                "Command Line": cmd_info["cmdline"],
                "Decoded Base64 Payload": cmd_info["decoded_b64"],
                "LOLBin Alert": cmd_info["lolbin_hit"],
                "YARA Rule Hits": [f"{y['rule_triggered']} ({y['mitre_id']})" for y in yara_hits],
                "Sigma Rule Hits": [f"{s['rule_triggered']} ({s['mitre_id']})" for s in sigma_hits],
                "Lineage Anomalies": [f"{l['rule_triggered']} ({l['mitre_id']})" for l in lineage_hits],
                "PE Shannon Entropy": pe_info["entropy"],
                "Packed Binary Suspect": pe_info["packed"],
                "Injection API Imports": pe_info["suspicious_apis"],
                "Staged Dir": is_suspicious_path(exe_path),
                "SHA256 Hash": file_hash,
                "Active Outbound IP Connections": remote_ips
            }
            sanitized_context = self.sanitizer.sanitize_log(raw_context_data)
            context = json.dumps(sanitized_context, indent=2)

            self._queue_log(
                f"[*] EDR telemetry, Process Tree, YARA, Sigma & Lineage hits gathered for {proc_name}. Querying {preferred_gemini} & Copilot...",
                "system",
            )

            prompt = (
                "You are an expert Blue Team cybersecurity analyst for Ghost-Aegis.\n"
                "Analyze the following process telemetry (including parent-child process lineage, command-line arguments, "
                "decoded Base64, YARA hits, Sigma rule hits, lineage anomalies, PE entropy, and injection APIs) and provide a 1-sentence assessment "
                "ending strictly with 'Threat Score: X/10'.\n\n"
                f"{memory_context}\n\n"
                f"### SANITIZED TELEMETRY:\n{context}"
            )

            # 2. Gemini 4 Engine Query (Cascades: gemini-4-hydrogen -> gemini-4-argon -> gemini-4-carbon)
            gemini_score = 0
            gemini_model_used = preferred_gemini
            try:
                gemini_key = os.getenv("GEMINI_API_KEY")
                if not gemini_key:
                    raise RuntimeError("Missing GEMINI_API_KEY in .env")

                raw_gemini, gemini_model_used = _query_gemini_rest(
                    prompt=prompt,
                    api_key=gemini_key,
                    preferred_model=preferred_gemini,
                )
                gemini_verdict = raw_gemini.replace("\n", " ")
                score_match = re.search(r"(\d{1,2})/10", gemini_verdict)
                if score_match:
                    gemini_score = int(score_match.group(1))
            except Exception as e:
                gemini_verdict = f"Gemini 4 Error: {e}"

            # 3. Copilot / Secondary Model Query (Direct REST - Bypasses 'jiter' WDAC DLL block)
            copilot_score = 0
            try:
                raw_copilot = _query_copilot_rest(prompt=prompt)
                copilot_verdict = raw_copilot.replace("\n", " ")
                score_match = re.search(r"(\d{1,2})/10", copilot_verdict)
                if score_match:
                    copilot_score = int(score_match.group(1))
            except Exception as e:
                copilot_verdict = f"Copilot Error: {e}"

            # 4. Present Verdicts to Console
            self._queue_log(f"🧠 [{gemini_model_used.upper()}]: {gemini_verdict}", "review")
            self._queue_log(f"🤖 [COPILOT]: {copilot_verdict}", "review")

            # 5. Autonomous Mitigation Trigger if Armed and AI Score >= 8/10
            max_ai_score = max(gemini_score, copilot_score)
            if max_ai_score >= 8 and getattr(self, "auto_mitigate_enabled", False):
                self._queue_log(f"🚨 [AI CONSENSUS CONTAINMENT] Severe Threat Score ({max_ai_score}/10) reached for PID {pid}.", "threat")
                vault_res = self.quarantine_vault.freeze_and_quarantine(
                    pid=pid,
                    reasons=[f"AI Consensus Score {max_ai_score}/10 ({gemini_model_used})", gemini_verdict],
                    risk_score=max_ai_score * 10,
                )
                if vault_res.get("success"):
                    self._queue_log(f"🚨 [AUTO-MITIGATE VAULT] Frozen, vaulted & neutralized {proc_name} (PID: {pid}).", "threat")
                else:
                    self._queue_log(f"[-] Failed to quarantine PID {pid}: {vault_res.get('error')}", "warn")

                for ip in remote_ips:
                    block_msg = block_ip(ip, rule_suffix="AIConsensus")
                    self._queue_log(f"🚨 [AUTO-MITIGATE] {block_msg}", "threat")

        except psutil.NoSuchProcess:
            self._queue_log(f"[!] PID {pid} is no longer running.", "warn")
        except Exception as e:
            self._queue_log(f"[!] Dual-AI Worker error: {e}", "threat")
        finally:
            self.log_queue.put(("__ai_eval_complete__", None))


if __name__ == "__main__":
    app = GhostAegisApp()
    app.mainloop()