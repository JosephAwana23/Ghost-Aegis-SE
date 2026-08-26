import asyncio
import logging
import os
from telemetry import TelemetryEvent
from ai_sentinel import GeminiSentinel
from copilot import GhostAegisCopilot
import psutil
from datetime import datetime
from quarantine import quarantine_process_by_pid
from quarantine_manager import QuarantineManager

qm = QuarantineManager()

import socket
# ------------------------------------
# Utility Functions
#-------------------------------------
def format_family(family_int):
    if family_int == -1:
        return "MAC Address"
    elif family_int == socket.AF_INET:
        return "IPv4"
    elif family_int == socket.AF_INET6:
        return "IPv6"
    return f"Unknown ({family_int})"

def is_trusted_process(event) -> bool:
    """Avoid over-escalation against common system and browser processes."""
    process_name = os.path.basename(event.process_name).lower()
    trusted_names = {
        "chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe",
        "svchost.exe", "services.exe", "lsass.exe", "wininit.exe",
        "runtimebroker.exe", "dllhost.exe", "searchindexer.exe"
    }
    if process_name in trusted_names:
        return True
    return event.classification in {"browser", "system_core"}

# ---------------------------
# Logging Configuration
# ---------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

async def analyze_event_dual_ai(event, gemini, copilot):
    """
    Runs Gemini + Copilot analysis in parallel and merges results.
    """
    logging.info(f"[EVALUATED] {event.process_name} | Local Risk Score: {event.risk_score}")

    if event.risk_score <= 0.7:
        logging.info("[PASSED] Normal behavior. Logged locally.")
        return

    logging.warning("[ESCALATING] High risk detected! Triggering Dual-AI Analysis...")

    gem_task = gemini.analyze_threat(event)
    cop_task = copilot.analyze_threat(event)

    gem_result, cop_result = await asyncio.gather(gem_task, cop_task)

    final = max([gem_result, cop_result], key=lambda r: r["confidence"])

    logging.info(f"[AI VERDICT] {final['source']} -> {final['verdict']} | Action: {final['recommended_action']}")
    logging.info(f"[AI SUMMARY] {final['summary']}")

    if final['recommended_action'] == "quarantine_process":
        if getattr(copilot, "safe_mode", False):
            logging.warning("[SAFE MODE] Quarantine enforcement disabled. Monitoring only.")
            return

        if is_trusted_process(event) and final.get("confidence", 0.0) < 0.9:
            logging.info(f"[SKIP] Trusted process {event.process_name} classified as {event.classification}; containment deferred.")
            return

        pid = event.details.get("pid") or getattr(event, "pid", 0)
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            pid = 0

        candidate_paths = []
        if event.details.get("file_path"):
            candidate_paths.append(event.details.get("file_path"))
        if event.process_name:
            candidate_paths.append(event.process_name)

        if pid > 0:
            quarantine_process_by_pid(pid, event.process_name, final['summary'])

        for candidate in candidate_paths:
            if candidate and os.path.exists(candidate):
                qm.isolate_file(candidate)
                break

        if pid > 0 and not any(os.path.exists(path) for path in candidate_paths if path):
            qm.terminate_process(pid)

async def run_defense_engine(start_cli=True, safe_mode=False):
    logging.info("--- Ghost Aegis Dual-AI Engine Initialized ---")

    gemini = GeminiSentinel()
    copilot = GhostAegisCopilot()
    copilot.safe_mode = safe_mode

    events = [
        TelemetryEvent("C:\\Program Files\\Google\\Chrome\\chrome.exe", {"is_critical": False}),
        TelemetryEvent("C:\\Users\\AppData\\Local\\Temp\\unknown_updater.exe", {"is_critical": True})
    ]

    tasks = [analyze_event_dual_ai(event, gemini, copilot) for event in events]
    await asyncio.gather(*tasks)

    if start_cli:
        logging.info("--- Transitioning to Copilot Interface ---")
        copilot.run_cli()

def monitor_network_interfaces():
    """Logs active network interfaces and their current IP configurations."""
    print(f"[*] Running network telemetry scan at {datetime.now()}")
    addrs = psutil.net_if_addrs()
    
    interface_telemetry = {}
    for interface_name, interface_addresses in addrs.items():
        addresses = []
        for address in interface_addresses:
            addresses.append({
                "family": str(address.family),
                "address": address.address,
                "netmask": address.netmask
            })
        interface_telemetry[interface_name] = addresses
        
    return interface_telemetry

if __name__ == "__main__":
    asyncio.run(run_defense_engine())
    
    telemetry = monitor_network_interfaces()
    for iface, addrs in telemetry.items():
        print(f"Interface: {iface}")
        for a in addrs:
            print(f"  -> IP: {a['address']} (Family: {a['family']})")
