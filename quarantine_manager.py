import os
import shutil
import logging
import psutil
from datetime import datetime

# Configure containment log
os.makedirs("logs", exist_ok=True)
os.makedirs("quarantine_vault", exist_ok=True)

class QuarantineManager:
    """Native Windows Process Containment & File Isolation Engine."""

    def __init__(self, vault_dir: str = "quarantine_vault"):
        self.vault_dir = vault_dir
        os.makedirs(self.vault_dir, exist_ok=True)

    def terminate_process(self, pid: int) -> bool:
        """Terminates a running high-risk process by PID."""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.kill()  # Forceful termination
            self._log_audit(f"PROCESS TERMINATED: PID {pid} ({proc_name})")
            return True
        except psutil.NoSuchProcess:
            self._log_audit(f"TERMINATION FAILED: PID {pid} no longer exists.")
        except psutil.AccessDenied:
            self._log_audit(f"TERMINATION FAILED: Access denied for PID {pid}. (Run as Administrator)")
        return False

    def isolate_file(self, file_path: str) -> bool:
        """
        Moves a malicious executable to the safe quarantine vault 
        and disables execution by renaming its extension to .locked.
        """
        if not os.path.exists(file_path):
            self._log_audit(f"ISOLATION FAILED: File {file_path} not found.")
            return False

        try:
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            vaulted_filename = f"{timestamp}_{filename}.locked"
            destination = os.path.join(self.vault_dir, vaulted_filename)

            # Move and lock file
            shutil.move(file_path, destination)
            self._log_audit(f"FILE ISOLATED: '{file_path}' -> '{destination}'")
            return True
        except Exception as e:
            self._log_audit(f"ISOLATION FAILED for '{file_path}': {e}")
            return False

    def _log_audit(self, message: str):
        """Appends containment actions directly to aegis_audit.log."""
        log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | [QUARANTINE] | {message}\n"
        print(f"  [🛡️ CONTAINER] {message}")
        with open("logs/aegis_audit.log", "a") as f:
            f.write(log_entry)