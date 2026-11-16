# 🛡️ Ghost-Aegis: Defensive Suite (Sentinel Blue Enterprise EDR v2.5)

*"Securing endpoints, automating threat intelligence, and defending the digital perimeter."*

**Ghost-Aegis SE (v2.5)** is a modular, pure-Python Endpoint Detection & Response (EDR) and Blue Team active-defense command center built with `CustomTkinter`. Engineered for resilience on hardened Windows environments, Ghost-Aegis combines real-time kernel PID table interception, DLL-free native YARA signature scanning, SHA-256 cryptographic chain-of-custody auditing, multi-tier **Gemini 4** (`gemini-4-hydrogen`, `gemini-4-argon`, `gemini-4-carbon`) + Copilot/Ollama Dual-AI triage, and automated process quarantine vaulting.

---

## 🔥 What's New in v2.5 (Enterprise EDR Upgrade)

* **🧬 Native Pure-Python YARA Engine & Real-Time PID Interceptor (`rules.yar`):** Hooks new Windows process spawns via a `50ms` differential kernel PID table loop and scans command-line arguments in memory against external `.yar` files (`T1059.001` Encoded PowerShell, `T1218` LOLBins, `T1490` Shadow Copy Deletion, `T1003.001` LSASS Dumping, and `T1543.003` Service Persistence)—100% immune to Windows Defender Application Control (WDAC) / Smart App Control `.dll` blocks.
* **🔐 Cryptographic SHA-256 Chain-of-Custody Auditor (`aegis_edr_alerts.jsonl`):** Every YARA and EDR alert is cryptographically sealed (`prev_hash` + `sha256_seal`). Includes a built-in GUI Chain Auditor that recalculates every hash link from the genesis block to detect indicator removal or log tampering (`MITRE T1070`).
* **🧠 Multi-Tier Gemini 4 Suite (`Hydrogen` / `Argon` / `Carbon`) & Dual-AI Consensus:** Uses DLL-safe HTTPS REST transport to query **Gemini 4** tiers alongside **Copilot / Local Ollama (`qwen2.5:7b`)**, featuring automatic model cascading and one-click **Executive Incident Response Briefing (`.md`)** generation.
* **🧊 Forensic Quarantine Vault & PE Shannon Entropy Scanner:** Suspends malicious threads in RAM (`proc.suspend()`) to prevent watchdog respawns, calculates PE Shannon entropy (`>= 7.20` packed binary detection), scans for process-injection APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`), and vaults the binary with a SHA-256 JSON manifest before termination.
* **⚡ Live Windows Event ID Hunter & ARP Spoof MitM Guard:** Hunts high-signal Windows Event IDs (`4625` Failed Logon, `4720` New Account, `7045` Service Installed, `1102` Audit Log Cleared) via `wevtutil` and audits LAN ARP tables for duplicate MAC-to-IP Man-in-the-Middle poisoning (`T1557.002`).
* **🛡️ Sentinel-Sanitize & SIEM UDP Streamer:** Masks RFC1918 internal IPs and Luhn-validated PCI card numbers before AI transmission and streams CEF/JSON telemetry over UDP (`Port 5140`) to remote Kali Linux / SIEM collectors.

---

## 🚀 Core Active-Defense Capabilities

* **The Ghost Protocol (Active AI Decoy):** An asynchronous honeypot (`Port 2222`) that intercepts unauthorized network scans and traps attackers in a dynamically simulated terminal while logging their payloads and source IPs.
* **In-Context Analyst Memory & Threat DNA:** Learns verified host baselines (`Mark Safe` / `Mark Threat`) stored in `data/analyst_memory.json` and computes canonical 16-byte Threat DNA hashes to cluster recurring anomalies.
* **Behavioral Fingerprinting:** Monitors keystroke timing variance and mouse jitter to detect bot-like execution or unauthorized operator sessions.
* **Dark Web Breach Intelligence:** Integrates credential exposure lookups to scan organizational email addresses for dark web leaks.
* **Real-Time Network Sentinel & Global Threat Radar:** Sweeps active `ESTABLISHED` TCP sockets, resolves FQDNs and geolocation coordinates, detects C2 beaconing intervals, and plots threat vectors on an interactive world map.
* **JIT (Just-In-Time) Administration:** Grants temporary local Administrator elevation with automated 15-minute revocation timers.

---

## ⚙️ Network Policy & Safe Mode

Ghost-Aegis includes a dynamic allowlist/denylist system stored in `network_policy.json` that is reloaded on the fly by the defense engine.

### Available CLI Commands:
* `help` — Display all Copilot commands
* `policy` — Open the policy management menu
* `show-policy` — Show the active allowlist and denylist
* `reload-policy` — Reload the JSON policy file from disk
* `add-white` / `remove-white` — Manage allowlisted hostnames or IPs
* `add-black` / `remove-black` — Manage denylisted hostnames or IPs
* `safe-mode` — Toggle live quarantine enforcement on/off

---

## 🛠️ Tech Stack & Architecture

* **Language:** Python 3.11+ / 3.13 (100% Pure-Python DLL-Safe Architecture)
* **GUI Command Center:** `CustomTkinter`, `tkintermapview`
* **Endpoint & Kernel Telemetry:** `psutil`, `wevtutil`, `netsh`, Native YARA Parser (`rules.yar`), PE Byte/Entropy Scanner
* **AI Engines:** Google Gemini 4 (`gemini-4-hydrogen`, `gemini-4-argon`, `gemini-4-carbon`), OpenAI / Copilot, Local Ollama (`qwen2.5:7b`)
* **Forensic Integrity:** SHA-256 Cryptographic Hash Chaining (`aegis_edr_alerts.jsonl`) & Quarantine Manifest Vaulting

---

## 🚀 Quick Start

```powershell
# 1. Clone the repository
git clone [https://github.com/JosephAwana23/Ghost-Aegis-SE.git](https://github.com/JosephAwana23/Ghost-Aegis-SE.git)
cd Ghost-Aegis-SE

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment variables (.env)
Copy-Item .env.example .env

# 4. Launch the Enterprise EDR Command Center
python main_gui.py
```
