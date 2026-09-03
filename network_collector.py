import psutil
import json
import os
from telemetry import TelemetryEvent

def load_network_policy(filepath="network_policy.json"):
    """Loads the active allowlist/denylist from the Copilot policy file."""
    if not os.path.exists(filepath):
        return {"allowlist": [], "denylist": []}
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception:
        return {"allowlist": [], "denylist": []}

def collect_network_telemetry() -> list[TelemetryEvent]:
    """
    Scans active network sockets, wraps them into TelemetryEvents, 
    and cross-references them with the local network policy.
    """
    events = []
    policy = load_network_policy()
    denylist = policy.get("denylist", [])

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            try:
                proc = psutil.Process(conn.pid)
                remote_ip = conn.raddr.ip
                
                is_external = not (
                    remote_ip.startswith("127.") or 
                    remote_ip.startswith("192.168.") or 
                    remote_ip.startswith("10.") or
                    remote_ip.startswith("172.16.")
                )

                # Check if the IP is actively blocked in your Copilot policy
                is_blacklisted = remote_ip in denylist

                details = {
                    "remote_address": f"{remote_ip}:{conn.raddr.port}",
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "status": conn.status,
                    "exe_path": proc.exe(),
                    "cmdline": " ".join(proc.cmdline()),
                    "parent_pid": proc.ppid(),
                    "is_external": is_external,
                    "is_blacklisted": is_blacklisted
                }

                event = TelemetryEvent(
                    process_name=proc.name(),
                    pid=conn.pid,
                    details=details
                )
                events.append(event)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    return events