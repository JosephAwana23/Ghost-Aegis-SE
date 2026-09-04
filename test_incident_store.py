import tempfile
import unittest
from pathlib import Path

from incident_store import (
    Incident,
    append_incident,
    build_attack_story,
    calculate_risk,
    export_incident_report,
    load_incidents,
)


class IncidentStoreTests(unittest.TestCase):
    def test_risk_score_explains_multiple_evidence_factors(self):
        score, reasons = calculate_risk(
            suspicious_path=True, unsigned=True,
            lineage_suspicious=True, reputation=90,
        )
        self.assertEqual(score, 100)
        self.assertEqual(len(reasons), 4)

    def test_incidents_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "incidents.jsonl")
            append_incident(Incident(process="demo.exe", pid=7), path)
            incidents = load_incidents(path)
            self.assertEqual(incidents[0]["process"], "demo.exe")
            self.assertEqual(incidents[0]["pid"], 7)

    def test_report_contains_attack_story_and_raw_evidence(self):
        incident = {"timestamp": "2026-01-01T00:00:00Z", "process": "demo.exe",
                    "pid": 7, "remote_ip": "203.0.113.10", "risk_score": 80,
                    "reasons": ["unsigned"]}
        self.assertIn("demo.exe", build_attack_story([incident])[0])
        with tempfile.TemporaryDirectory() as directory:
            report = export_incident_report(str(Path(directory) / "report.txt"), [incident])
            contents = Path(report).read_text(encoding="utf-8")
            self.assertIn("ATTACK STORY", contents)
            self.assertIn('"remote_ip": "203.0.113.10"', contents)


if __name__ == "__main__":
    unittest.main()