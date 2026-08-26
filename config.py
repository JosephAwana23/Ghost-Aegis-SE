from dotenv import load_dotenv
load_dotenv()
import os
from dataclasses import dataclass, field

@dataclass
class AegisConfig:
    """
    Central configuration hub for Ghost Aegis.
    All modules read from this file.
    """

    # ---------------------------------------------------------
    # AI Engine Settings
    # ---------------------------------------------------------
    risk_threshold: float = 0.70          # Minimum risk score to trigger dual-AI analysis
    gemini_confidence_weight: float = 1.0 # Weight multiplier for Gemini verdicts
    copilot_confidence_weight: float = 1.0 # Weight multiplier for Copilot verdicts

    # ---------------------------------------------------------
    # Telemetry Settings
    # ---------------------------------------------------------
    enable_cloud_enrichment: bool = False
    enable_pid_anomaly_detection: bool = True
    enable_process_classification: bool = True

    # ---------------------------------------------------------
    # Logging & Output
    # ---------------------------------------------------------
    verbose_logging: bool = True
    audit_log_path: str = "logs/aegis_audit.log"

    # ---------------------------------------------------------
    # API Keys (Loaded from environment)
    # ---------------------------------------------------------
    gemini_api_key: str = field(default_factory=lambda: os.environ.get("GEMINI_API_KEY"))
    copilot_api_key: str = field(default_factory=lambda: os.environ.get("COPILOT_API_KEY"))

    # ---------------------------------------------------------
    # Feature Flags (Future Expansion)
    # ---------------------------------------------------------
    enable_ghost_mode: bool = False
    enable_cloud_sentinel: bool = False
    enable_fleet_manager: bool = False

    # ---------------------------------------------------------
    # Utility Methods
    # ---------------------------------------------------------
    def show(self):
        """Prints current configuration values."""
        print("\n--- Ghost Aegis Configuration ---")
        for field_name, value in self.__dict__.items():
            print(f"{field_name}: {value}")
        print("---------------------------------\n")

# Global config instance
CONFIG = AegisConfig()
