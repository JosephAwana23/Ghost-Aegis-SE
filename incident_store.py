import json
import os
import subprocess
from datetime import datetime
from functools import lru_cache

INCIDENT_LOG_FILE = "ghost_incidents.json"

class Incident(dict):
    """A dictionary subclass that standardizes how Ghost-Aegis records threats."""
    def __init__(self, process, pid, path, risk_score, reasons, recommended_action, remote_ip="none", reputation=0, signer="Unknown"):
        super().__init__(
            timestamp=datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            process=process,
            pid=pid,
            path=path,
            risk_score=risk_score,
            reasons=reasons,
            recommended_action=recommended_action,
            remote_ip=remote_ip,
            reputation=reputation,
            signer=signer
        )

def load_incidents():
    if not os.path.exists(INCIDENT_LOG_FILE):
        return []
    try:
        with open(INCIDENT_LOG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def append_incident(incident: dict):
    incidents = load_incidents()
    incidents.append(incident)
    with open(INCIDENT_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=4)

@lru_cache(maxsize=512)
def get_authenticode_signer(filepath: str) -> str:
    """
    Inspects the Authenticode digital signature of an executable.
    Uses @lru_cache to prevent repetitive process spawns during sentinel audits.
    """
    if not filepath or not os.path.exists(filepath):
        return "Unknown"

    # Escape single quotes and use -LiteralPath to prevent breakage from spaces
    safe_path = filepath.replace("'", "''")

    ps_command = (
        f"$sig = Get-AuthenticodeSignature -LiteralPath '{safe_path}'; "
        "if ($sig.Status -eq 'Valid') { "
        "    $subject = $sig.SignerCertificate.Subject; "
        "    if ($subject -match 'CN=([^,]+)') { $matches[1] } else { $subject } "
        "} elseif ($sig.Status -eq 'NotSigned') { "
        "    'Unsigned' "
        "} else { "
        "    $sig.Status.ToString() "
        "}"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True, text=True, timeout=15, check=False
        )
        output = result.stdout.strip()
        return output if output and result.returncode == 0 else "Unknown"
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception:
        return "Unknown"

def calculate_risk(suspicious_path=False, unsigned=False, reputation=0, trusted_process=False, signer="Unknown"):
    score = 0
    reasons = []

    # Verified corporate signers receive a trust credit
    known_trusted_signers = ["Microsoft Corporation", "Google LLC", "GitHub, Inc.", "Brave Software, Inc."]
    is_verified_vendor = any(vendor.lower() in signer.lower() for vendor in known_trusted_signers)

    if trusted_process or is_verified_vendor:
        score = max(0, score - 20)

    if suspicious_path:
        if is_verified_vendor:
            # AppData staging for verified binaries is flagged as informational only
            reasons.append("per-user installation path (verified signer)")
            score += 5
        else:
            reasons.append("staged in untrusted directory")
            score += 35

    if unsigned:
        reasons.append("unsigned binary")
        score += 30

    if reputation > 0:
        reasons.append(f"AbuseIPDB reputation score: {reputation}%")
        score += int(reputation * 0.6)

    return min(100, score), reasons

def export_incident_report(destination: str):
    incidents = load_incidents()
    with open(destination, "w", encoding="utf-8") as f:
        f.write("GHOST-AEGIS INCIDENT REPORT\n")
        f.write("="*50 + "\n\n")
        for inc in incidents:
            f.write(f"[{inc.get('timestamp')}] Process: {inc.get('process')} (PID {inc.get('pid')})\n")
            f.write(f"  Risk Score: {inc.get('risk_score')}/100\n")
            f.write(f"  Remote IP: {inc.get('remote_ip')}\n")
            f.write(f"  Signer: {inc.get('signer')}\n")
            f.write(f"  Path: {inc.get('path')}\n")
            f.write(f"  Reasons: {', '.join(inc.get('reasons', []))}\n")
            f.write("-" * 50 + "\n\n")
    return destination

def build_attack_story(incident: dict):
    """Constructs a simple narrative string for an incident."""
    return f"Process {incident.get('process')} executed from {incident.get('path')} connecting to {incident.get('remote_ip')}."