import json
from pathlib import Path
import threading

class AnalystMemory:
    """Stores analyst triage feedback to provide dynamic few-shot context to AI evaluators."""
    
    def __init__(self, filepath="data/analyst_memory.json"):
        self.filepath = Path(filepath)
        self._lock = threading.Lock()
        self.data = self._load()

    def _load(self):
        try:
            with self.filepath.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"benign_baselines": [], "confirmed_threats": []}

    def record_decision(self, process_name: str, remote_ip: str, verdict: str, reason: str):
        """Records whether a flagged connection was confirmed malicious or marked benign."""
        entry = {
            "process": process_name.lower(),
            "remote_ip": remote_ip,
            "reason": reason
        }
        category = "benign_baselines" if verdict.lower() == "benign" else "confirmed_threats"
        
        with self._lock:
            # Prevent duplicate entries for the exact same process and IP
            if not any(x["process"] == entry["process"] and x["remote_ip"] == entry["remote_ip"] for x in self.data[category]):
                self.data[category].append(entry)
                # Keep the last 15 historical decisions per category to manage prompt token budgets
                self.data[category] = self.data[category][-15:]
                self._save()

    def _save(self):
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(f"{self.filepath}.tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        tmp.replace(self.filepath)

    def get_prompt_context(self) -> str:
        """Formats learned host behaviors into a system injection block."""
        with self._lock:
            benign = self.data.get("benign_baselines", [])
            threats = self.data.get("confirmed_threats", [])

        if not benign and not threats:
            return ""

        context_lines = ["[LEARNED LOCAL HOST BASELINE]"]
        if benign:
            context_lines.append("Verified Safe Exceptions on this specific machine:")
            for b in benign[-5:]:
                context_lines.append(f" - {b['process']} talking to {b['remote_ip']} ({b['reason']})")
        if threats:
            context_lines.append("Previously Confirmed Attack Patterns on this host:")
            for t in threats[-5:]:
                context_lines.append(f" - {t['process']} targeting {t['remote_ip']} ({t['reason']})")

        return "\n".join(context_lines)