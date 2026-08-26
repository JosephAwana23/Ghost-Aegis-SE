import asyncio
import logging
from typing import List

from telemetry import TelemetryEvent
from ai_sentinel import GeminiSentinel
from copilot import GhostAegisCopilot
from config import CONFIG

# ---------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO if CONFIG.verbose_logging else logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

class GhostAegisEngine:
    """
    Unified Defense Engine for Ghost Aegis.
    Handles telemetry ingestion, dual-AI analysis,
    config-driven thresholds, and module orchestration.
    """

    def __init__(self):
        logging.info("Initializing Ghost Aegis Engine...")

        self.gemini = GeminiSentinel()
        self.copilot = GhostAegisCopilot()

        self.risk_threshold = CONFIG.risk_threshold

        logging.info(f"Risk threshold set to {self.risk_threshold}")
        logging.info("Dual-AI modules loaded successfully.")

    # ---------------------------------------------------------
    # Telemetry Ingestion
    # ---------------------------------------------------------
    def ingest_telemetry(self, raw_events: List[dict]) -> List[TelemetryEvent]:
        """
        Converts raw telemetry dictionaries into TelemetryEvent objects.
        """
        events = []
        for evt in raw_events:
            event = TelemetryEvent(
                process_name=evt.get("process_name"),
                pid=evt.get("pid", 0),
                details=evt.get("details", {})
            )
            events.append(event)
            logging.info(f"[INGESTED] {event.process_name} | Risk: {event.risk_score}")
        return events

    # ---------------------------------------------------------
    # Dual-AI Analysis Pipeline
    # ---------------------------------------------------------
    async def analyze_event(self, event: TelemetryEvent):
        """
        Runs Gemini + Copilot analysis in parallel and merges results.
        """
        logging.info(f"[PIPELINE] Processing event: {event.process_name}")

        if event.risk_score < self.risk_threshold:
            logging.info("[PIPELINE] Risk below threshold. Logged locally.")
            return {
                "source": "Local",
                "verdict": "BENIGN",
                "confidence": 0.50,
                "summary": "Event did not meet escalation threshold.",
                "recommended_action": "log_only"
            }

        logging.warning("[PIPELINE] High-risk event detected. Escalating to Dual-AI...")

        gem_task = self.gemini.analyze_threat(event)
        cop_task = self.copilot.analyze_threat(event)

        gem_result, cop_result = await asyncio.gather(gem_task, cop_task)

        # Apply config-based weighting
        gem_result["confidence"] *= CONFIG.gemini_confidence_weight
        cop_result["confidence"] *= CONFIG.copilot_confidence_weight

        final = max([gem_result, cop_result], key=lambda r: r["confidence"])

        logging.info(f"[FINAL VERDICT] {final['source']} -> {final['verdict']}")
        logging.info(f"[SUMMARY] {final['summary']}")

        return final

    # ---------------------------------------------------------
    # Engine Runner
    # ---------------------------------------------------------
    async def run(self, raw_events: List[dict]):
        """
        Main execution pipeline for Ghost Aegis.
        """
        logging.info("--- Ghost Aegis Engine Online ---")

        events = self.ingest_telemetry(raw_events)

        tasks = [self.analyze_event(event) for event in events]
        results = await asyncio.gather(*tasks)

        logging.info("--- Analysis Complete ---")
        return results

    # ---------------------------------------------------------
    # Copilot Interface Bridge
    # ---------------------------------------------------------
    def launch_copilot(self):
        """
        Launches the Copilot CLI after engine processing.
        """
        logging.info("Launching Copilot Interface...")
        self.copilot.run_cli()


# ---------------------------------------------------------
# Standalone Execution
# ---------------------------------------------------------
if __name__ == "__main__":
    engine = GhostAegisEngine()

    sample_events = [
        {"process_name": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "pid": 1337, "details": {"is_critical": False}},
        {"process_name": "C:\\Users\\AppData\\Local\\Temp\\unknown_updater.exe", "pid": 0, "details": {"is_critical": True}}
    ]

    asyncio.run(engine.run(sample_events))
    engine.launch_copilot()
