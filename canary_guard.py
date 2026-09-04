import hashlib
import threading
from pathlib import Path
from typing import Callable


class CanaryGuard:
    """Monitor harmless files for unexpected modification or deletion."""

    def __init__(self, directory="logs/canaries", interval=5):
        self.directory = Path(directory)
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread = None
        self._baseline = {}
        self._lock = threading.Lock()

    @staticmethod
    def _hash(path):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def create_baseline(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        for index in range(1, 4):
            path = self.directory / f"aegis_canary_{index}.txt"
            if not path.exists():
                path.write_text(
                    "Ghost-Aegis canary file. Do not modify.\n",
                    encoding="utf-8",
                )
        with self._lock:
            self._baseline = {
                path: self._hash(path)
                for path in self.directory.glob("aegis_canary_*.txt")
            }
        return len(self._baseline)

    def check_once(self):
        """Return evidence records for canaries that changed or disappeared."""
        with self._lock:
            baseline = dict(self._baseline)
        findings = []
        for path, expected_hash in baseline.items():
            if not path.exists():
                findings.append({"action": "DELETED", "path": str(path)})
                continue
            try:
                actual_hash = self._hash(path)
            except OSError:
                findings.append({"action": "UNREADABLE", "path": str(path)})
                continue
            if actual_hash != expected_hash:
                findings.append({"action": "MODIFIED", "path": str(path)})
        return findings

    def start(self, on_finding: Callable[[dict], None]):
        if self._thread and self._thread.is_alive():
            return False
        self.create_baseline()
        self._stop_event.clear()

        def monitor():
            while not self._stop_event.wait(self.interval):
                for finding in self.check_once():
                    on_finding(finding)

        self._thread = threading.Thread(target=monitor, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(self.interval + 1, 2))
        self._thread = None
