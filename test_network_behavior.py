import tempfile
import unittest
from pathlib import Path

from network_behavior import NetworkBehaviorStore


class NetworkBehaviorTests(unittest.TestCase):
    def test_first_seen_and_regular_beacon_are_detected(self):
        current_time = [100.0]
        with tempfile.TemporaryDirectory() as directory:
            store = NetworkBehaviorStore(
                Path(directory) / "history.json", clock=lambda: current_time[0]
            )
            first = store.observe("demo.exe", "203.0.113.10", 443)
            self.assertTrue(first["first_seen"])
            for current_time[0] in (110.0, 120.0, 130.0):
                result = store.observe("demo.exe", "203.0.113.10", 443)
            self.assertTrue(result["beacon"])

    def test_lookup_does_not_change_history(self):
        with tempfile.TemporaryDirectory() as directory:
            store = NetworkBehaviorStore(Path(directory) / "history.json", clock=lambda: 100)
            before = store.get_observation("demo.exe", "203.0.113.10", "443")
            store.observe("demo.exe", "203.0.113.10", "443")
            after = store.get_observation("demo.exe", "203.0.113.10", "443")
            self.assertEqual(before["sightings"], 0)
            self.assertEqual(after["sightings"], 1)


if __name__ == "__main__":
    unittest.main()