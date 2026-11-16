import yara
import json
from datetime import datetime, timezone

class AegisYaraEngine:
    def __init__(self, rule_path="rules.yar"):
        self.rules = yara.compile(filepath=rule_path)
        print(f"[+] YARA Engine initialized with rules from: {rule_path}")

    def scan_command_line(self, pid: int, process_name: str, cmdline: str) -> list:
        """Scans raw command-line strings in memory against loaded YARA rules."""
        if not cmdline:
            return []
        
        matches = self.rules.match(data=cmdline)
        alerts = []
        for match in matches:
            alerts.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "pid": pid,
                "process": process_name,
                "rule_triggered": match.rule,
                "mitre_id": match.meta.get("mitre_attack", "Unknown"),
                "severity": match.meta.get("severity", "MEDIUM"),
                "matched_cmdline": cmdline
            })
        return alerts

    def scan_process_memory(self, pid: int) -> list:
        """Scans live process memory space (Requires Admin privileges)."""
        try:
            matches = self.rules.match(pid=pid)
            return [m.rule for m in matches]
        except yara.Error as e:
            return [f"Memory scan skipped/denied: {str(e)}"]

if __name__ == "__main__":
    engine = AegisYaraEngine("rules.yar")
    
    # Quick self-test with a simulated malicious command string
    test_cmd = "powershell.exe -WindowStyle Hidden -enc SQBFAFgA"
    results = engine.scan_command_line(pid=9999, process_name="powershell.exe", cmdline=test_cmd)
    
    print("\n[*] Self-Test Telemetry Output:")
    print(json.dumps(results, indent=2))