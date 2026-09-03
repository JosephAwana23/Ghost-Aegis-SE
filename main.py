import asyncio
import logging
import os
import socket
from datetime import datetime
import psutil

from telemetry import TelemetryEvent
from network_collector import collect_network_telemetry
from ai_sentinel import GeminiSentinel
from copilot import GhostAegisCopilot
from quarantine import quarantine_process_by_pid
from quarantine_manager import QuarantineManager

qm = QuarantineManager()

# ------------------------------------
# Utility Functions
# ------------------------------------
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

async def analyze_event_dual_ai(event: TelemetryEvent, gemini: GeminiSentinel, copilot: GhostAegisCopilot):
    """
    Runs Gemini + Copilot analysis in parallel and executes remediation if needed.
    """
    logging.info(f"[EVALUATED] {event.process_name} (PID: {event.pid}) | Risk: {event.risk_score:.2f} | Class: {event.classification}")

    # Pass low-risk/routine events
    if event.risk_score <= 0.7:
        return

    logging.warning(f"[ESCALATING] High risk ({event.risk_score:.2f}) on {event.process_name}! Triggering Dual-AI Analysis...")

    gem_task = gemini.analyze_threat(event)
    cop_task = copilot.analyze_threat(event)

    gem_result, cop_result = await asyncio.gather(gem_task, cop_task)

    final = max([gem_result, cop_result], key=lambda r: r.get("confidence", 0.0))

    logging.info(f"[AI VERDICT] {final['source']} -> {final['verdict']} | Action: {final['recommended_action']}")
    logging.info(f"[AI SUMMARY] {final['summary']}")

    if final.get("recommended_action") == "quarantine_process":
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

async def telemetry_daemon(gemini: GeminiSentinel, copilot: GhostAegisCopilot, interval_seconds: int = 5):
    """
    Continuous asynchronous monitoring loop scanning sockets at regular intervals.
    """
    logging.info(f"[*] Telemetry daemon started. Polling every {interval_seconds}s...")
    try:
        while True:
            live_events = collect_network_telemetry()
            
            # Focus evaluation on outbound connections or non-zero risk
            actionable_events = [
                ev for ev in live_events 
                if ev.details.get("is_external") or ev.risk_score > 0.3
            ]

            if actionable_events:
                logging.info(f"[*] Telemetry sweep found {len(actionable_events)} active outbound socket(s).")
                tasks = [analyze_event_dual_ai(ev, gemini, copilot) for ev in actionable_events]
                await asyncio.gather(*tasks)

            await asyncio.sleep(interval_seconds)

    except asyncio.CancelledError:
        logging.info("[*] Telemetry daemon received shutdown signal.")
        raise

async def run_defense_engine(start_cli: bool = True, safe_mode: bool = True, poll_interval: int = 5):
    logging.info("--- Ghost Aegis Dual-AI Engine Initialized ---")

    gemini = GeminiSentinel()
    copilot = GhostAegisCopilot()
    copilot.safe_mode = safe_mode

    # Launch daemon loop as a background task
    daemon_task = asyncio.create_task(
        telemetry_daemon(gemini, copilot, interval_seconds=poll_interval)
    )

    try:
        if start_cli:
            logging.info("--- Transitioning to Copilot Interface ---")
            # Run blocking CLI inside executor to prevent event loop freeze
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, copilot.run_cli)
        else:
            # Keep daemon running until interrupted if CLI is false
            await daemon_task

    except (KeyboardInterrupt, asyncio.CancelledError):
        logging.info("\n[*] Halting Ghost-Aegis engine...")
    finally:
        daemon_task.cancel()
        try:
            await daemon_task
        except asyncio.CancelledError:
            pass
        logging.info("[*] Ghost-Aegis engine shutdown complete.")

def monitor_network_interfaces():
    """Logs active network interfaces and their current IP configurations."""
    print(f"\n[*] Network Interface Telemetry ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
    addrs = psutil.net_if_addrs()
    
    interface_telemetry = {}
    for interface_name, interface_addresses in addrs.items():
        addresses = []
        for address in interface_addresses:
            addresses.append({
                "family": format_family(address.family),
                "address": address.address,
                "netmask": address.netmask
            })
        interface_telemetry[interface_name] = addresses
        
    return interface_telemetry

if __name__ == "__main__":
    # 1. Route background logs to a file so they don't interrupt your CLI typing
    file_handler = logging.FileHandler("ghost_aegis_telemetry.log")
    file_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logging.getLogger().addHandler(file_handler)
    logging.getLogger().setLevel(logging.INFO)

    # 2. Print initial network interface diagnostics to terminal
    telemetry = monitor_network_interfaces()
    for iface, addrs in telemetry.items():
        print(f"Interface: {iface}")
        for a in addrs:
            print(f"  -> IP: {a['address']} ({a['family']})")

    # 3. Start live async monitoring and interactive CLI simultaneously
    try:
        asyncio.run(run_defense_engine(start_cli=True, safe_mode=True, poll_interval=5))
    except KeyboardInterrupt:
        print("\n[*] Exited cleanly.")