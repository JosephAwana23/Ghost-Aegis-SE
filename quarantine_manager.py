import os
import shutil
import logging
import hashlib
import json
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
        self.manifest_path = os.path.join(self.vault_dir, "manifest.json")

    def _load_manifest(self):
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as stream:
                return json.load(stream)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save_manifest(self, entries):
        temporary_path = f"{self.manifest_path}.tmp"
        with open(temporary_path, "w", encoding="utf-8") as stream:
            json.dump(entries, stream, indent=2)
        os.replace(temporary_path, self.manifest_path)

    @staticmethod
    def _sha256(file_path):
        digest = hashlib.sha256()
        with open(file_path, "rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

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
            manifest = self._load_manifest()
            manifest.append({
                "vault_path": os.path.abspath(destination),
                "original_path": os.path.abspath(file_path),
                "sha256": self._sha256(destination),
                "quarantined_at": datetime.now().isoformat(),
            })
            self._save_manifest(manifest)
            self._log_audit(f"FILE ISOLATED: '{file_path}' -> '{destination}'")
            return True
        except Exception as e:
            self._log_audit(f"ISOLATION FAILED for '{file_path}': {e}")
            return False

    def restore_file(self, vault_path: str) -> bool:
        """Restore a quarantined file only when its recorded hash still matches."""
        manifest = self._load_manifest()
        entry = next((item for item in manifest if item["vault_path"] == os.path.abspath(vault_path)), None)
        if not entry or not os.path.exists(vault_path):
            self._log_audit(f"RESTORE FAILED: vault entry not found for '{vault_path}'.")
            return False
        try:
            if self._sha256(vault_path) != entry["sha256"]:
                self._log_audit(f"RESTORE FAILED: hash mismatch for '{vault_path}'.")
                return False
            destination = entry["original_path"]
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            if os.path.exists(destination):
                self._log_audit(f"RESTORE FAILED: destination already exists '{destination}'.")
                return False
            shutil.move(vault_path, destination)
            self._save_manifest([item for item in manifest if item is not entry])
            self._log_audit(f"FILE RESTORED: '{vault_path}' -> '{destination}'")
            return True
        except (OSError, KeyError) as error:
            self._log_audit(f"RESTORE FAILED for '{vault_path}': {error}")
            return False

    def _log_audit(self, message: str):
        """Appends containment actions directly to aegis_audit.log."""
        log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | [QUARANTINE] | {message}\n"
        print(f"  [🛡️ CONTAINER] {message}")
        with open("logs/aegis_audit.log", "a") as f:
            f.write(log_entry)