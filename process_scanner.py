import psutil
import logging
from typing import Dict, List, Any

# Telemetry data model fallback
class TelemetryEvent:
    def __init__(self, process_name: str, details: Dict[str, Any]):
        self.process_name = process_name
        self.details = details
        self.risk_score = details.get("risk_score", 0.0)

# Critical heuristic patterns
SUSPICIOUS_PATHS = ["temp", "appdata\\local\\temp", "public", "downloads"]
SUSPICIOUS_KEYWORDS = ["updater", "hack", "inject", "payload", "nc", "mimikatz"]

# Allowlist to suppress false positives on signed/legitimate software in AppData/Program Files
TRUSTED_PATH_PATTERNS = [
    r"microsoft vs code",
    r"windowsapps",
    r"driverstore",
    r"grammarly\desktopintegrations",
    r"nvidia corporation",
    r"microsoft\edgewebview",
    r"google\chrome\application",
    r"windows-powershell",
    r"system32"
]

def build_socket_map() -> Dict[int, List[Dict[str, Any]]]:
    """
    Sweeps active TCP/UDP sockets and maps ESTABLISHED remote IP connections by PID.
    """
    socket_map = {}
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.pid and conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                if conn.pid not in socket_map:
                    socket_map[conn.pid] = []
                    
                socket_map[conn.pid].append({
                    "ip": remote_ip,
                    "port": remote_port,
                    "status": conn.status
                })
    except (psutil.AccessDenied, PermissionError):
        # Graceful degradation if running without full Administrator privileges
        pass
    return socket_map

def is_trusted_application(exe_path: str) -> bool:
    """Checks if the executable matches known trusted path patterns."""
    path_lower = exe_path.lower()
    return any(pattern in path_lower for pattern in TRUSTED_PATH_PATTERNS)

def scan_live_processes(risk_threshold: float = 0.3) -> List[TelemetryEvent]:
    """
    Sweeps live OS processes, correlates network sockets, applies whitelisting,
    and returns prioritized TelemetryEvent objects.
    """
    telemetry_events = []
    sockets_map = build_socket_map()
    attrs = ['pid', 'name', 'exe', 'ppid', 'cmdline']
    
    for proc in psutil.process_iter(attrs=attrs):
        try:
            pinfo = proc.info
            pid = pinfo['pid']
            name = pinfo['name'] or "unknown"
            exe_path = pinfo['exe'] or name
            ppid = pinfo['ppid'] or 0
            cmdline = " ".join(pinfo['cmdline']) if pinfo['cmdline'] else ""

            # Fetch parent process name safely
            try:
                parent_proc = psutil.Process(ppid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                parent_proc = "unknown.exe"

            details = {
                "pid": pid,
                "parent_process": parent_proc,
                "cmdline": cmdline,
                "is_critical": False,
                "network_connections": sockets_map.get(pid, [])
            }

            path_lower = exe_path.lower()
            calc_risk = 0.0

            # 1. Evaluate Path Risk (Skip if whitelisted)
            if not is_trusted_application(exe_path):
                if any(p in path_lower for p in SUSPICIOUS_PATHS):
                    calc_risk += 0.35

            # 2. Evaluate Keyword Risk
            if any(k in path_lower or k in cmdline.lower() for k in SUSPICIOUS_KEYWORDS):
                calc_risk += 0.45
                details["is_critical"] = True

            # 3. Evaluate Active Network Connections
            for conn in details["network_connections"]:
                if conn["port"] in [4444, 666, 1337, 31337] or conn["ip"] == "92.223.96.6":
                    calc_risk += 0.50
                    details["is_critical"] = True

            # Yield event if it exceeds minimum risk threshold
            if calc_risk >= risk_threshold:
                event = TelemetryEvent(exe_path, details)
                event.risk_score = min(calc_risk, 1.0)
                telemetry_events.append(event)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return telemetry_events