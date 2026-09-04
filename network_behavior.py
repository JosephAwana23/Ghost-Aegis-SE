import json
import statistics
import time
from pathlib import Path


class NetworkBehaviorStore:
    """Persist connection sightings and identify regular repeated contacts."""

    def __init__(self, filepath="logs/network_history.json", clock=None):
        self.filepath = Path(filepath)
        self.clock = clock or time.time
        self.history = self._load()

    def _load(self):
        try:
            with self.filepath.open("r", encoding="utf-8") as stream:
                return json.load(stream)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save(self):
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = Path(f"{self.filepath}.tmp")
        with temporary_path.open("w", encoding="utf-8") as stream:
            json.dump(self.history, stream, indent=2)
        temporary_path.replace(self.filepath)

    def observe(self, process, remote_ip, port):
        key = f"{process}|{remote_ip}|{port}"
        now = float(self.clock())
        record = self.history.setdefault(
            key,
            {"process": process, "remote_ip": remote_ip, "port": port,
             "first_seen": now, "last_seen": now, "sightings": []},
        )
        previous_sightings = record["sightings"]
        record["last_seen"] = now
        previous_sightings.append(now)
        record["sightings"] = previous_sightings[-20:]
        self._save()

        intervals = [
            later - earlier
            for earlier, later in zip(record["sightings"], record["sightings"][1:])
            if later > earlier
        ]
        beacon = False
        if len(intervals) >= 3:
            average = statistics.mean(intervals)
            deviation = statistics.pstdev(intervals)
            beacon = average >= 5 and deviation / average <= 0.25
        return {
            "first_seen": len(previous_sightings) == 1,
            "beacon": beacon,
            "sightings": len(previous_sightings),
            "intervals": intervals,
        }

    def get_observation(self, process, remote_ip, port):
        """Return saved behavior details without recording a new sighting."""
        key = f"{process}|{remote_ip}|{port}"
        record = self.history.get(key)
        if not record:
            return {"sightings": 0, "first_seen": True, "beacon": False}
        sightings = record.get("sightings", [])
        intervals = [
            later - earlier
            for earlier, later in zip(sightings, sightings[1:])
            if later > earlier
        ]
        beacon = False
        if len(intervals) >= 3:
            average = statistics.mean(intervals)
            beacon = average >= 5 and statistics.pstdev(intervals) / average <= 0.25
        return {
            "sightings": len(sightings),
            "first_seen": len(sightings) == 0,
            "beacon": beacon,
        }