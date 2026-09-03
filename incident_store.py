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