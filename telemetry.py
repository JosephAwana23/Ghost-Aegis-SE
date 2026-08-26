from dataclasses import dataclass, field
import os
import time

@dataclass
class TelemetryEvent:
    process_name: str
    pid: int | None = 0
    details: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    risk_score: float = field(init=False)
    classification: str = field(init=False)

    def __post_init__(self):
        if isinstance(self.pid, dict):
            self.details = self.pid
            self.pid = 0

        try:
            self.pid = int(self.pid)
        except (TypeError, ValueError):
            self.pid = 0

        self.details = self.details or {}
        self.classification = self.classify_process()
        self.risk_score = self.calculate_risk()

    # ---------------------------------------------------------
    # NEW: Process Classification Layer
    # ---------------------------------------------------------
    def classify_process(self) -> str:
        """
        Classifies process into categories for better AI analysis.
        """
        name = self.process_name.lower()

        if "chrome" in name or "firefox" in name or "edge" in name:
            return "browser"
        if "svchost" in name or "system32" in name:
            return "system_core"
        if "temp" in name or "unknown" in name or "updater" in name:
            return "untrusted"
        if name.endswith(".exe"):
            return "generic_binary"
        return "other"

    # ---------------------------------------------------------
    # NEW: Multi‑Factor Risk Scoring Engine
    # ---------------------------------------------------------
    def calculate_risk(self) -> float:
        """
        Calculates a multi-factor heuristic risk score.
        Factors:
        - Path reputation
        - Process classification
        - Critical flag
        - Suspicious keywords
        - PID anomalies
        """
        path_lower = self.process_name.lower()
        score = 0.0

        # Critical flag from details
        if self.details.get("is_critical"):
            score += 0.40

        # Suspicious path indicators
        suspicious_keywords = ["temp", "unknown", "updater", ".tmp", "appdata"]
        if any(k in path_lower for k in suspicious_keywords):
            score += 0.40

        # Classification-based scoring
        if self.classification == "untrusted":
            score += 0.35
        elif self.classification == "generic_binary":
            score += 0.15
        elif self.classification == "system_core":
            score += 0.05
        elif self.classification == "browser":
            score += 0.10

        # PID anomaly (0 or negative PID)
        if self.pid <= 0:
            score += 0.10

        # Clamp score between 0 and 1
        return min(score, 1.0)

    # ---------------------------------------------------------
    # NEW: Cloud Enrichment Stub (Future Use)
    # ---------------------------------------------------------
    async def enrich_with_cloud(self):
        """
        Placeholder for future cloud enrichment (hash lookup, reputation, etc.)
        """
        return {
            "cloud_reputation": "unknown",
            "confidence": 0.0
        }
