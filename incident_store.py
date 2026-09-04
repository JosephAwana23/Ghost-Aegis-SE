import json
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Incident:
    process: str
    pid: int
    path: str = ""
    sha256: str = ""
    parent: str = ""
    remote_ip: str = ""
    reputation: int = 0
    signer: str = "Unknown"
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    recommended_action: str = "review"
    action: str = "logged"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def calculate_risk(*, suspicious_path=False, unsigned=False,
                   lineage_suspicious=False, reputation=0,
                   trusted_process=False):
    """Return a bounded score and the evidence that produced it."""
    score = 0
    reasons = []
    if suspicious_path:
        score += 20
        reasons.append("executable in a temporary or user-writable path")
    if unsigned:
        score += 25
        reasons.append("executable is unsigned or has an invalid signature")
    if lineage_suspicious:
        score += 30
        reasons.append("suspicious parent-child process relationship")
    if reputation >= 80:
        score += 25
        reasons.append(f"remote IP reputation is high ({reputation}%)")
    elif reputation >= 25:
        score += 10
        reasons.append(f"remote IP reputation needs review ({reputation}%)")
    if trusted_process:
        score = max(0, score - 15)
        reasons.append("known system process reduced the score")
    return min(score, 100), reasons or ["no high-confidence evidence"]


def get_authenticode_signer(file_path: str) -> str:
    """Read the Windows Authenticode signer without failing a scan."""
    if not file_path:
        return "Unknown"
    escaped_path = file_path.replace("'", "''")
    command = (
        "(Get-AuthenticodeSignature -LiteralPath "
        f"'{escaped_path}').SignerCertificate.Subject"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=3, check=False,
        )
        return result.stdout.strip() or "Unsigned"
    except (OSError, subprocess.SubprocessError):
        return "Unknown"


def append_incident(incident: Incident, filepath="logs/incidents.jsonl"):
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(asdict(incident), ensure_ascii=True) + "\n")


def load_incidents(filepath="logs/incidents.jsonl") -> list[dict[str, Any]]:
    path = Path(filepath)
    if not path.exists():
        return []
    incidents = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            try:
                incidents.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return incidents


def build_attack_story(incidents: list[dict[str, Any]]) -> list[str]:
    """Convert raw records into a concise chronological investigation story."""
    story = []
    for incident in sorted(incidents, key=lambda item: item.get("timestamp", "")):
        process = incident.get("process", "unknown")
        pid = incident.get("pid", "?")
        remote_ip = incident.get("remote_ip") or "no remote address"
        risk = incident.get("risk_score", 0)
        reasons = "; ".join(incident.get("reasons", []))
        story.append(
            f"{incident.get('timestamp', 'unknown')}: {process} (PID {pid}) "
            f"connected to {remote_ip}; risk {risk}/100. Evidence: {reasons}"
        )
    return story


def export_incident_report(filepath="logs/ghost_aegis_report.txt", incidents=None):
    """Write a portable human-readable report for incident review."""
    incidents = load_incidents() if incidents is None else incidents
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        stream.write("GHOST-AEGIS INCIDENT REPORT\n")
        stream.write("=" * 30 + "\n\n")
        stream.write(f"Incidents recorded: {len(incidents)}\n\n")
        stream.write("ATTACK STORY\n------------\n")
        for item in build_attack_story(incidents):
            stream.write(f"- {item}\n")
        stream.write("\nRAW EVIDENCE\n------------\n")
        for incident in incidents:
            stream.write(json.dumps(incident, ensure_ascii=True) + "\n")
    return str(path)