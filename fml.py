import datetime
import hashlib
import os
from threat_engine import ThreatEngine, ThreatEvent, load_rules_from_json


import os
import time
import datetime
# Import our new threat engine components
try:
    from threat_engine import ThreatEngine, ThreatEvent, ThreatRule
except ImportError as e:
    print(f"Warning: threat_engine module not found. Please ensure it is installed. Error: {e}")
    ThreatEngine = ThreatEvent = ThreatRule = None

# Define baseline Blue Team threat rules
DEFAULT_RULES = [
    ThreatRule(
        rule_id="R001",
        rule_name="Ransomware / Suspicious Executable Dropped",
        severity="CRITICAL",
        pattern="*.exe",
        action="QUARANTINE"
    ),
    ThreatRule(
        rule_id="R002",
        rule_name="Script Payload Detection",
        severity="HIGH",
        pattern="*.sh",
        action="QUARANTINE"
    ),
    ThreatRule(
        rule_id="R003",
        rule_name="Sensitive File Access / Extension",
        severity="MEDIUM",
        pattern="*.pem",
        action="ALERT"
    )
]

# Initialize Threat Engine instance
threat_engine = ThreatEngine(rules=DEFAULT_RULES)

# Load threat rules from JSON file
rules = load_rules_from_json("sample_rules.json")
threat_engine = ThreatEngine(rules)



def process_file_event(file_path: str, action_type: str, hash_val: str = "N/A", user: str = "SYSTEM"):
    """
    Called whenever the FIM detects a file CREATED, MODIFIED, or DELETED.
    """
    filename = os.path.basename(file_path)
    
    # 1. Instantiate the telemetry event
    event = ThreatEvent(
        filename=filename,
        file_path=file_path,
        action_type=action_type,
        hash_val=hash_val,
        timestamp=datetime.datetime.now().isoformat(),
        user=user
    )

    # 2. Pass event into Threat Engine evaluation pipeline
    alerts = threat_engine.evaluate_event(event)

    # 3. Handle Telemetry & Alert Dispatch
    if alerts:
        for alert in alerts:
            print(f"\n[!] GHOST-AEGIS ALERT [{alert['severity']}]: {alert['rule_name']}")
            print(f"    Target: {event.file_path}")
            print(f"    Action Executed: {alert['action_taken']}")
            print(f"    Hash: {event.hash_val}\n")
    else:
        # Standard clean log
        print(f"[*] Ghost-Aegis Telemetry: {action_type} -> {filename} (Clean)")

def calculate_file_hash(filepath):
    """Calculates the SHA-256 hash of a single file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None 

def scan_directory(directory_path, is_baseline=True):
    """Scans a directory and returns a dictionary of file hashes."""
    if is_baseline:

        print(f"\nStarting Blue Team Baseline Sweep of: {directory_path}\n" + "-"*40)
    
    ledger = {} 
    
    for root_folder, subfolders, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root_folder, file)
            file_hash = calculate_file_hash(full_path)
            
            if file_hash:
                ledger[full_path] = file_hash
                if is_baseline:
                    print(f"[SECURED] {file} -> {file_hash[:10]}...") 
                
    return ledger

def run_integrity_check(baseline_ledger, directory_path):
    """Compares the current live folder to the saved baseline."""
    print("\nInitiating Active Defense Sweep...\n" + "-"*40)
    
    # Take a live snapshot of the folder right now
    live_ledger = scan_directory(directory_path, is_baseline=False)
    
    print("\n--- Integrity Report ---")
    alerts = 0
    
    # 1. Check for Modified or Deleted files
    for filepath, baseline_hash in baseline_ledger.items():
        filename = os.path.basename(filepath)
        
        # If the baseline file isn't in the live snapshot, it was deleted
        if filepath not in live_ledger:
            print(f"[ALERT - DELETED] Critical file missing: {filename}")
            alerts += 1
            
        # If the file is there, but the hashes don't match, it was modified
        elif live_ledger[filepath] != baseline_hash:
            print(f"[ALERT - MODIFIED] Tampering detected in: {filename}")
            alerts += 1
            
    # 2. Check for newly Added files (rogue files)
    for filepath in live_ledger:
        if filepath not in baseline_ledger:
            filename = os.path.basename(filepath)
            print(f"[ALERT - ADDED] Unauthorized rogue file detected: {filename}")
            alerts += 1
            
    # Final Verdict
    if alerts == 0:
        print("[SAFE] All files intact. No anomalies detected.")
    else:
        print(f"\n[WARNING] {alerts} security alerts generated! Check the system immediately.")


# --- Deployment Area ---
target_folder = r"C:\Users\Gem\BlueTeam_Test_Folder"

if not os.path.exists(target_folder):
    os.makedirs(target_folder)
    print(f"Created new secure test folder at: {target_folder}")
else:
    # 1. Generate our secure baseline
    master_baseline = scan_directory(target_folder, is_baseline=True)
    
    # 2. To test the alarm, we are going to pause the script here and wait for you
    # to tamper with the folder before pressing Enter to run the integrity check.
    input("\n[PAUSED] Go tamper with the folder now! Press ENTER when ready to run the check...")
    
    # 3. Run the integrity check!
    run_integrity_check(master_baseline, target_folder)