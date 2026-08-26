import os
import psutil
import logging
from config import CONFIG

# Ensure logs directory exists
os.makedirs(os.path.dirname(CONFIG.audit_log_path), exist_ok=True)

# Configure audit logger
audit_logger = logging.getLogger("AegisAudit")
audit_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(CONFIG.audit_log_path)
file_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
audit_logger.addHandler(file_handler)

def quarantine_process_by_pid(pid: int, process_name: str, verdict_summary: str) -> bool:
    """
    Suspends and terminates a malicious process tree, then logs the audit event.
    """
    try:
        proc = psutil.Process(pid)
        
        # 1. Suspend first to freeze execution/exfiltration
        proc.suspend()
        audit_logger.info(f"[SUSPENDED] PID {pid} ({process_name}) placed in memory isolation.")
        
        # 2. Terminate parent and child process tree
        for child in proc.children(recursive=True):
            child.kill()
        proc.kill()
        
        audit_logger.warning(f"[TERMINATED] PID {pid} ({process_name}) killed successfully. Reason: {verdict_summary}")
        print(f"\n[🛡️ ENFORCER] Process {process_name} (PID: {pid}) successfully quarantined and killed.")
        return True

    except psutil.NoSuchProcess:
        audit_logger.info(f"[SKIP] PID {pid} ({process_name}) already exited.")
        return False
    except psutil.AccessDenied:
        audit_logger.error(f"[ACCESS DENIED] Insufficient privileges to kill PID {pid} ({process_name}).")
        print(f"\n[⚠️ ENFORCER] Access Denied for PID {pid}. Run PowerShell as Administrator!")
        return False
    except Exception as e:
        audit_logger.error(f"[ERROR] Failed to quarantine PID {pid}: {e}")
        return False