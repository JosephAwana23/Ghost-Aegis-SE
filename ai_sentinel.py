import asyncio
import json
import os
import re
from telemetry import TelemetryEvent

# Optional import: google-genai SDK
try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


def construct_evaluation_prompt(target_telemetry: dict, memory_context: str = "") -> str:
    """Formats telemetry and local host baseline into a zero-shot/few-shot prompt."""
    return f"""
You are the primary threat triaging AI for Ghost Aegis SE.
Analyze the following process and network connection telemetry.
Assign a Threat Score from 0 to 100, determine a Verdict (BENIGN, SUSPICIOUS, or MALICIOUS), and justify your verdict.

{memory_context}

[TARGET TELEMETRY]
Process Name: {target_telemetry.get('process')}
PID: {target_telemetry.get('pid')}
Signer: {target_telemetry.get('signer', 'Unsigned / Unknown')}
Remote IP: {target_telemetry.get('remote_ip')}:{target_telemetry.get('port')}
Behavior Flags: {target_telemetry.get('flags', 'None')}

Respond in valid JSON format only:
{{
  "verdict": "BENIGN" | "SUSPICIOUS" | "MALICIOUS",
  "threat_score": <int 0-100>,
  "confidence": <float 0.0-1.0>,
  "summary": "<one sentence justification>",
  "recommended_action": "log_only" | "alert" | "terminate_process" | "isolate_network"
}}
""".strip()


class GeminiSentinel:
    def __init__(self, model_name: str = "gemini-3.8-flash"):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        self.model_name = model_name
        self.client = None

        if self.api_key and GENAI_AVAILABLE:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception:
                self.client = None

    async def analyze_threat(self, event: TelemetryEvent, memory_context: str = "") -> dict:
        """
        Evaluates a telemetry event using Gemini API when available,
        falling back to local behavioral heuristics if offline.
        """
        # 1. Normalize TelemetryEvent into dictionary payload
        target_telemetry = {
            "process": event.process_name,
            "pid": getattr(event, "pid", "N/A"),
            "signer": getattr(event, "signer", "Unknown"),
            "remote_ip": getattr(event, "remote_ip", event.details.get("remote_ip", "0.0.0.0")),
            "port": getattr(event, "port", event.details.get("port", "0")),
            "flags": event.details.get("flags", [])
        }

        # 2. Attempt Cloud Inference if client is ready
        if self.client:
            prompt = construct_evaluation_prompt(target_telemetry, memory_context)
            cloud_result = await self._query_gemini(prompt)
            if cloud_result:
                cloud_result["source"] = "Gemini-Cloud"
                return cloud_result

        # 3. Deterministic Local Fallback (Heuristic Engine)
        return self._local_heuristic_analysis(event, target_telemetry)

    async def _query_gemini(self, prompt: str) -> dict | None:
        """Runs the API query inside an executor thread to avoid blocking asyncio."""
        loop = asyncio.get_running_loop()

        def _call_api():
            try:
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt
                )
                text = response.text.strip()
                # Extract JSON block if enclosed in markdown backticks
                if "```json" in text:
                    text = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL).group(1)
                elif "```" in text:
                    text = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL).group(1)
                return json.loads(text)
            except Exception:
                return None

        return await loop.run_in_executor(None, _call_api)

    def _local_heuristic_analysis(self, event: TelemetryEvent, telemetry: dict) -> dict:
        """Fast offline heuristic classifier."""
        path = event.process_name.lower()
        details = event.details
        flags = telemetry["flags"]

        is_suspicious_path = ("temp" in path) or ("appdata" in path) or ("downloads" in path)
        is_beacon = "BEACON" in flags or details.get("beacon", False)
        is_critical = details.get("is_critical", False)

        if is_suspicious_path and (is_beacon or is_critical):
            return {
                "source": "Gemini-LocalHeuristic",
                "verdict": "MALICIOUS",
                "threat_score": 90,
                "confidence": 0.88,
                "summary": f"Unsigned binary in temporary path exhibiting active anomalies: {event.process_name}",
                "recommended_action": "terminate_process"
            }
        elif is_suspicious_path or is_beacon:
            return {
                "source": "Gemini-LocalHeuristic",
                "verdict": "SUSPICIOUS",
                "threat_score": 65,
                "confidence": 0.72,
                "summary": f"Behavioral anomaly detected on {event.process_name}",
                "recommended_action": "alert"
            }
        else:
            return {
                "source": "Gemini-LocalHeuristic",
                "verdict": "BENIGN",
                "threat_score": 15,
                "confidence": 0.85,
                "summary": f"Standard operational profile for {event.process_name}",
                "recommended_action": "log_only"
            }