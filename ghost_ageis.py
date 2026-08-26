import os
import time
import datetime
# Import our new threat engine components
try:
    from threat_engine import ThreatEngine, ThreatEvent, ThreatRule
except ImportError as e:
    print(f"Warning: threat_engine module not found. Please ensure it is installed. Error: {e}")
    ThreatEngine = ThreatEvent = ThreatRule = None

# Define baseline Blue Team threat rules
DEFAULT_RULES = [
    ThreatRule(
        rule_id="R001",
        rule_name="Ransomware / Suspicious Executable Dropped",
        severity="CRITICAL",
        pattern="*.exe",
        action="QUARANTINE"
    ),
    ThreatRule(
        rule_id="R002",
        rule_name="Script Payload Detection",
        severity="HIGH",
        pattern="*.sh",
        action="QUARANTINE"
    ),
    ThreatRule(
        rule_id="R003",
        rule_name="Sensitive File Access / Extension",
        severity="MEDIUM",
        pattern="*.pem",
        action="ALERT"
    )
]

# Initialize Threat Engine instance
threat_engine = ThreatEngine(rules=DEFAULT_RULES)