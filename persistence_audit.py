import os
import subprocess
from pathlib import Path


def _startup_entries():
    locations = [
        Path(os.getenv("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.getenv("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
    ]
    entries = []
    for location in locations:
        if location.exists():
            entries.extend({"type": "Startup folder", "location": str(path)} for path in location.iterdir())
    return entries


def _powershell_entries(command, entry_type):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=8, check=False,
        )
        return [
            {"type": entry_type, "location": line.strip()}
            for line in result.stdout.splitlines() if line.strip()
        ]
    except (OSError, subprocess.SubprocessError):
        return []


def collect_persistence_entries():
    """Read common Windows persistence locations without changing the host."""
    entries = _startup_entries()
    entries += _powershell_entries(
        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', "
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' | "
        "ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | "
        "ForEach-Object { \"$($_.Name)=$($_.Value)\" } }",
        "Registry Run key",
    )
    entries += _powershell_entries(
        "Get-ScheduledTask | ForEach-Object { $_.TaskPath + $_.TaskName }",
        "Scheduled task",
    )
    entries += _powershell_entries(
        "Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } | "
        "ForEach-Object { \"$($_.Name) -> $($_.PathName)\" }",
        "Auto-start service",
    )
    return entries