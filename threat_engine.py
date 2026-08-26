import os
import json
from dataclasses import dataclass
from fnmatch import fnmatch

from telemetry import TelemetryEvent


@dataclass
class ThreatEvent:
    filename: str
    file_path: str
    action_type: str
    hash_val: str
    timestamp: str
    user: str


@dataclass
class ThreatRule:
    rule_id: str
    rule_name: str
    severity: str
    pattern: str
    action: str


class ThreatEngine:
    def __init__(self, rules=None, escalation_threshold: float = 0.7):
        self.rules = rules or []
        self.escalation_threshold = escalation_threshold
        self.suspicious_paths = (
            "\\temp\\",
            "\\appdata\\local\\temp\\",
            "unknown",
            "updater",
            "dropper",
            "payload",
            "install",
        )

    def quarantine_file(self, file_path: str):
        if not file_path:
            return False

        try:
            quarantine_dir = os.path.join(os.path.dirname(file_path) or ".", "ghost_aegis_quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)

            original_name = os.path.basename(file_path)
            destination = os.path.join(quarantine_dir, original_name)
            counter = 1

            while os.path.exists(destination):
                name, ext = os.path.splitext(original_name)
                destination = os.path.join(quarantine_dir, f"{name}_{counter}{ext}")
                counter += 1

            os.replace(file_path, destination)
            return True
        except Exception:
            return False

    def _calculate_telemetry_risk(self, event):
        """Produces a 0.0-1.0 risk score for runtime telemetry events."""
        score = 0.0
        details = event.details or {}
        process_name = (event.process_name or "").lower()

        if event.event_type == "process_creation":
            score += 0.15
            if "temp" in process_name or "appdata" in process_name:
                score += 0.25
            if any(x in process_name for x in ("unknown", "updater", "dropper", "payload", "install")):
                score += 0.2
            if details.get("command_line") and any(
                x in str(details.get("command_line")).lower()
                for x in ("powershell", "cmd", "rundll32", "regsvr32")
            ):
                score += 0.25

        if event.event_type == "network_socket":
            score += 0.2
            remote_ip = details.get("remote_ip")
            if remote_ip:
                score += 0.35
            if details.get("is_critical"):
                score += 0.25
            if any(x in process_name for x in ("temp", "unknown", "updater", "dropper")):
                score += 0.15

        if details.get("is_critical"):
            score += 0.1
        if details.get("remote_ip") and not details.get("is_internal"):
            score += 0.1

        if score > 1.0:
            score = 1.0
        return round(score, 2)

    def evaluate_event(self, event):
        """Supports both file-based rule evaluation and telemetry event scoring."""
        if isinstance(event, TelemetryEvent):
            event.risk_score = self._calculate_telemetry_risk(event)
            return event

        for rule in self.rules:
            if not rule.pattern:
                continue

            if fnmatch(event.filename.lower(), rule.pattern.lower()):
                if rule.severity.upper() in {"HIGH", "CRITICAL"} and rule.action.upper() == "QUARANTINE":
                    self.quarantine_file(event.file_path)
                    return True

        return False

    def should_escalate_to_ai(self, event) -> bool:
        """Escalate telemetry events with a risk score above the configured threshold."""
        if hasattr(event, "risk_score"):
            return float(event.risk_score) >= self.escalation_threshold
        if hasattr(event, "event_type") and hasattr(event, "details"):
            return self._calculate_telemetry_risk(event) >= self.escalation_threshold
        return False


def load_rules_from_json(json_path: str) -> list[ThreatRule]:
    """Parse a JSON file containing threat rules into ThreatRule objects.
    
    Args:
        json_path: Path to the JSON file containing threat rules.
        
    Returns:
        A list of ThreatRule objects parsed from the JSON file.
        
    Raises:
        FileNotFoundError: If the JSON file does not exist.
        json.JSONDecodeError: If the JSON is invalid.
        KeyError: If required fields are missing from a rule.
    """
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Rules file not found: {json_path}")
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in {json_path}: {e.msg}", e.doc, e.pos)
    
    rules = []
    for rule_data in data:
        try:
            rule = ThreatRule(
                rule_id=rule_data["rule_id"],
                rule_name=rule_data["rule_name"],
                severity=rule_data["severity"],
                pattern=rule_data["pattern"],
                action=rule_data["action"]
            )
            rules.append(rule)
        except KeyError as e:
            raise KeyError(f"Missing required field {e} in rule: {rule_data}")
    
    return rules
