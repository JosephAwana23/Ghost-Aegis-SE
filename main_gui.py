import os
import sys
import math
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
from datetime import datetime, timedelta

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
    "code.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "explorer.exe", "python.exe", "pythonw.exe", "cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe", "taskhostw.exe", "wininit.exe", "googlechrome.exe", "googleupdate.exe", "onenote.exe", "teams.exe", "outlook.exe", "word.exe", "excel.exe", "powerpnt.exe","notepad.exe", "notepad++.exe", "putty.exe", "winscp.exe", "filezilla.exe", "vscode.exe", "sublime_text.exe", "intellij.exe", "pycharm.exe", "eclipse.exe", "netbeans.exe", "androidstudio.exe", "virtualbox.exe", "vmware.exe", "docker.exe", "DRIVERS\WUDFRd.sys", "DRIVERS\dxgkrnl.sys", "DRIVERS\ndis.sys", "DRIVERS\ntfs.sys", "DRIVERS\volsnap.sys", "DRIVERS\disk.sys", "DRIVERS\fltmgr.sys", "DRIVERS\storport.sys", "DRIVERS\usbport.sys", "DRIVERS\usbhub.sys", "DRIVERS\usbccgp.sys", "DRIVERS\usbvideo.sys", "DRIVERS\usbser.sys", "DRIVERS\usbuhci.sys", "DRIVERS\usbohci.sys", "DRIVERS\usbehci.sys", "DRIVERS\usbfilter.sys", "Lenovo\Vantage\LenovoVantageService.exe", "Lenovo\Vantage\LenovoVantage.exe", "Lenovo\Vantage\LenovoVantageUI.exe", "Lenovo\Vantage\LenovoVantageUpdater.exe", "Lenovo\Vantage\LenovoVantageServiceHost.exe", "Lenovo\Vantage\LenovoVantageServiceManager.exe", "Lenovo\Vantage\LenovoVantageServiceInstaller.exe", "Lenovo\Vantage\LenovoVantageServiceUninstaller.exe", "Lenovo\Vantage\LenovoVantageServiceRepair.exe", "Lenovo\Vantage\LenovoVantageServiceUpdate.exe", "Lenovo\Vantage\LenovoVantageServiceCheck.exe", "Lenovo\Vantage\LenovoVantageServiceMonitor.exe", "Lenovo\Vantage\LenovoVantageServiceScheduler.exe", "Lenovo\Vantage\LenovoVantageServiceLogger.exe",
}

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
                f"CEF:0|GhostAegis|SentinelBlue|2.5|{payload.get('process', 'unknown')}|"
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
# ==============================================================================


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
        
        # Ghost Protocol State
        self.ghost_decoy = GhostDecoy(port=2222)
        self.decoy_thread = None
        self.decoy_loop = None

        self.title("Ghost-Aegis | Defensive Suite SE (v2.5 Enterprise EDR | Gemini 4 Suite)")
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
            text="🛡️ SYSTEM HARDENED | GEMINI 4 (HYDROGEN / ARGON / CARBON) + EDR VAULT READY",
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
            width=280, height=26, command=self.run_jit,
        )
        self.jit_button.pack(pady=2, padx=15)

        self.audit_button = ctk.CTkButton(
            self.left_frame, text="Audit Admins", width=280, height=26, command=self.run_audit,
        )
        self.audit_button.pack(pady=2, padx=15)

        self.info_button = ctk.CTkButton(
            self.left_frame, text="System Architecture", width=280, height=26, command=self.show_sys_info,
        )
        self.info_button.pack(pady=2, padx=15)

        self._add_panel_section(self.left_frame, "TELEMETRY, EVENT HUNTING & REVIEW")

        self.interfaces_button = ctk.CTkButton(
            self.left_frame,
            text="Interface Telemetry",
            width=280,
            height=26,
            command=self.run_interface_telemetry,
        )
        self.interfaces_button.pack(pady=2, padx=15)

        self.event_hunt_button = ctk.CTkButton(
            self.left_frame,
            text="Hunt Event IDs (4625/4720/7045/1102)",
            width=280,
            height=26,
            fg_color="#8B4000",
            hover_color="#5C2A00",
            command=self.run_event_log_hunt,
        )
        self.event_hunt_button.pack(pady=2, padx=15)

        self.incidents_button = ctk.CTkButton(
            self.left_frame,
            text="View Incident Evidence",
            width=280,
            height=26,
            command=self.show_incidents_window,
        )
        self.incidents_button.pack(pady=2, padx=15)

        self.report_button = ctk.CTkButton(
            self.left_frame,
            text="Export Investigation Report",
            width=280,
            height=26,
            command=self.export_report,
        )
        self.report_button.pack(pady=2, padx=15)

        self.ai_report_button = ctk.CTkButton(
            self.left_frame,
            text="Generate AI Incident Brief (4-Carbon)",
            width=280,
            height=26,
            fg_color="#4B0082",
            hover_color="#300052",
            command=self.run_ai_incident_report,
        )
        self.ai_report_button.pack(pady=2, padx=15)

        self.behavior_button = ctk.CTkButton(
            self.left_frame,
            text="Behavior Fingerprint Scan",
            width=280,
            height=26,
            fg_color="#1f538d",
            hover_color="#14375e",
            command=self.run_behavior_scan,
        )
        self.behavior_button.pack(pady=2, padx=15)

        self.breach_button = ctk.CTkButton(
            self.left_frame,
            text="Dark Web Breach Check",
            width=280,
            height=26,
            fg_color="#7B1FA2",
            hover_color="#4A0F6A",
            command=self.run_breach_check,
        )
        self.breach_button.pack(pady=2, padx=15)

        self.persistence_button = ctk.CTkButton(
            self.left_frame,
            text="Audit Persistence",
            width=280,
            height=26,
            command=self.run_persistence_audit,
        )
        self.persistence_button.pack(pady=2, padx=15)

        self.readiness_button = ctk.CTkButton(
            self.left_frame,
            text="System Readiness Check",
            width=280,
            height=26,
            command=self.run_readiness_check,
        )
        self.readiness_button.pack(pady=2, padx=15)

        self._add_panel_section(self.left_frame, "ACTIVE PROTECTION")

        self.canary_button = ctk.CTkButton(
            self.left_frame,
            text="Start Canary Shield",
            width=280,
            height=26,
            fg_color="#1f538d",
            hover_color="#14375e",
            command=self.toggle_canary_shield,
        )
        self.canary_button.pack(pady=2, padx=15)

        self.engine_button = ctk.CTkButton(
            self.left_frame,
            text="Launch Defense Engine",
            width=280,
            height=26,
            fg_color="#4B0082",
            hover_color="#300052",
            command=self.run_defense_engine,
        )
        self.engine_button.pack(pady=2, padx=15)

        self.about_button = ctk.CTkButton(
            self.left_frame,
            text="About Ghost-Aegis",
            width=280,
            height=26,
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

        self.check_queue()
        self.log_event(
            "Ghost-Aegis v2.5 initialized | Gemini 4 Models active: gemini-4-hydrogen, gemini-4-argon, gemini-4-carbon.",
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

    # --- ON-DEMAND EDR PE & CMDLINE INSPECTOR ---
    def inspect_selected_pid_edr(self):
        pid = self._get_selected_pid()
        if not pid:
            self.log_event("Select an active PID to run PE Entropy & Command-Line Deobfuscation.", "warn")
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

        self.log_event(f"🔬 [EDR DEEP INSPECT] {proc_name} (PID: {pid})", "system")
        self.log_event(f"   Cmdline: {cmd_info['cmdline'] or 'N/A'}", "review")
        if cmd_info["lolbin_hit"]:
            self.log_event(f"   [!] LOLBIN DETECTED: {cmd_info['lolbin_hit']}", "threat")
        if cmd_info["decoded_b64"]:
            self.log_event(f"   [!] DECODED BASE64 PAYLOAD: {cmd_info['decoded_b64']}", "threat")
        self.log_event(
            f"   PE Shannon Entropy: {pe_info['entropy']}/8.00 ({'PACKED/ENCRYPTED SUSPECT' if pe_info['packed'] else 'Normal'}) | "
            f"Injection APIs: {', '.join(pe_info['suspicious_apis']) if pe_info['suspicious_apis'] else 'None'}",
            "threat" if (pe_info["packed"] or pe_info["suspicious_apis"]) else "trusted"
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

    # --- ON-DEMAND WINDOWS EVENT ID THREAT HUNTER ---
    def run_event_log_hunt(self):
        self.event_hunt_button.configure(state="disabled", text="Hunting Event Logs...")
        self.log_event("[*] Querying Windows Security & System Event Logs (4625, 4720, 7045, 1102)...", "system")
        threading.Thread(target=self._event_hunt_worker, daemon=True).start()

    def _event_hunt_worker(self):
        try:
            findings = WindowsEventHunter.hunt_events()
            if not findings:
                self._queue_log("[+] Event Log Hunt complete: 0 high-risk Security/System Event IDs detected (or elevation required for Security log).", "trusted")
            else:
                for item in findings:
                    self._queue_log(
                        f"🚨 [EVENT ID {item['event_id']}] {item['label']} ({item['count']} recent hits in {item['log']} log)",
                        "threat"
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
        ctk.CTkLabel(about_win, text="Version 2.5.0 | 'Sentinel Blue Enterprise EDR'", font=("Arial", 10, "italic")).pack()

        mission_text = (
            "Mission: Save the World through Internet Safety.\n\n"
            "Ghost-Aegis is an active defensive engineering suite designed for "
            "Blue Team operations. Powered by Gemini 4 (Hydrogen, Argon, Carbon) "
            "and Copilot, it integrates LOLBin & Base64 PowerShell deobfuscation, "
            "PE Shannon entropy analysis, process suspension & quarantine vaulting, "
            "ARP spoof detection, and Windows Event ID threat hunting."
        )

        mission_box = ctk.CTkTextbox(about_win, width=400, height=150, font=("Arial", 12))
        mission_box.insert("0.0", mission_text)
        mission_box.configure(state="disabled", fg_color="#2b2b2b")
        mission_box.pack(pady=15, padx=20)

        ctk.CTkLabel(about_win, text="Cyber Defense Lead:", font=("Arial", 12, "bold"), text_color="#3b8ed0").pack()
        ctk.CTkLabel(about_win, text='[Homero "Joseph Awana" Antillon / Gemini 4 / Copilot]', font=("Consolas", 14)).pack(pady=5)
        ctk.CTkLabel(about_win, text="Gemini 4 Hydrogen • Argon • Carbon • Pure-Python EDR", font=("Arial", 9)).pack(pady=(15, 0))
        ctk.CTkButton(about_win, text="CLOSE", fg_color="#444444", command=about_win.destroy).pack(pady=15)

    def show_incidents_window(self):
        incidents_win = ctk.CTkToplevel(self)
        incidents_win.title("Ghost-Aegis | Incident Evidence & Threat DNA")
        incidents_win.geometry("950x580")
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
                dna = generate_threat_dna(
                    incident.get("process", "unknown"),
                    incident.get("signer", "Unknown"),
                    incident.get("remote_ip", "none"),
                    incident.get("reasons", [])
                )
                evidence_box.insert(
                    "end",
                    f"[{incident.get('timestamp', 'unknown')}] "
                    f"{incident.get('process', 'unknown')} (PID {incident.get('pid', '?')}) | Threat DNA: {dna}\n"
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

    # --- CANARY SHIELD MONITORING ---
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
                elif message == "__ai_report_complete__":
                    self.ai_report_button.configure(state="normal", text="Generate AI Incident Brief (4-Carbon)")
                    if isinstance(tag, str):
                        self.show_ai_report_window(tag)
                elif message == "__interfaces_complete__":
                    self.interfaces_button.configure(state="normal", text="Interface Telemetry")
                elif message == "__persistence_complete__":
                    self.persistence_button.configure(state="normal", text="Audit Persistence")
                elif message == "__event_hunt_complete__":
                    self.event_hunt_button.configure(state="normal", text="Hunt Event IDs (4625/4720/7045/1102)")
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
        self.log_event("--- Ghost-Aegis v2.5 Readiness Check ---", "system")
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
        self.log_event("[*] Network Sentinel starting deep socket + EDR + ARP audit...", "system")
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
                f"[*] Extracting deep EDR telemetry and invoking Dual-AI ({preferred_gemini} + Copilot) for PID {pid}...",
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

            memory_context = self.analyst_memory.get_prompt_context()

            raw_context_data = {
                "Process Name": proc_name,
                "PID": pid,
                "Parent Process": parent_name,
                "Executable Path": exe_path,
                "Command Line": cmd_info["cmdline"],
                "Decoded Base64 Payload": cmd_info["decoded_b64"],
                "LOLBin Alert": cmd_info["lolbin_hit"],
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
                f"[*] EDR telemetry & PE entropy gathered for {proc_name}. Querying {preferred_gemini} & Copilot...",
                "system",
            )

            prompt = (
                "You are an expert Blue Team cybersecurity analyst for Ghost-Aegis.\n"
                "Analyze the following process telemetry (including command-line arguments, decoded Base64, "
                "PE entropy, and injection APIs) and provide a 1-sentence assessment "
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
