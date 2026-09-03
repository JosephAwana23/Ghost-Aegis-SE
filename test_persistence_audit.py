import unittest
from unittest.mock import patch

from persistence_audit import collect_persistence_entries


class PersistenceAuditTests(unittest.TestCase):
    @patch("persistence_audit._powershell_entries", return_value=[])
    @patch("persistence_audit._startup_entries", return_value=[])
    def test_audit_is_read_only_and_returns_entries(self, startup, powershell):
        self.assertEqual(collect_persistence_entries(), [])
        startup.assert_called_once_with()
        self.assertEqual(powershell.call_count, 3)


if __name__ == "__main__":
    unittest.main()