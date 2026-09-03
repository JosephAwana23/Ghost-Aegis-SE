import tempfile
import unittest
from pathlib import Path

from incident_store import Incident, append_incident, calculate_risk, load_incidents


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


if __name__ == "__main__":
    unittest.main()