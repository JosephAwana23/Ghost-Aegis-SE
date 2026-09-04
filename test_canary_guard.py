import tempfile
import unittest
from pathlib import Path

from canary_guard import CanaryGuard


class CanaryGuardTests(unittest.TestCase):
    def test_detects_modified_and_deleted_canaries(self):
        with tempfile.TemporaryDirectory() as directory:
            guard = CanaryGuard(directory)
            self.assertEqual(guard.create_baseline(), 3)
            canaries = sorted(Path(directory).glob("aegis_canary_*.txt"))
            canaries[0].write_text("changed", encoding="utf-8")
            canaries[1].unlink()
            findings = guard.check_once()
            self.assertEqual({item["action"] for item in findings}, {"MODIFIED", "DELETED"})


if __name__ == "__main__":
    unittest.main()