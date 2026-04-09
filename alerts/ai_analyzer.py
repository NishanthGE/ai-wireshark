"""
alerts/ai_analyzer.py
Supports Anthropic, OpenAI, Gemini, and Groq
"""

import json
import asyncio
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import ANTHROPIC_API_KEY, AI_PROVIDER, AI_MODEL

try:
    from config import GROQ_API_KEY
except (ImportError, AttributeError):
    GROQ_API_KEY = ""

try:
    from config import GEMINI_API_KEY
except (ImportError, AttributeError):
    GEMINI_API_KEY = ""

SYSTEM_PROMPT = """You are an expert network security analyst inside a real-time 
packet analysis tool. Analyze suspicious network events.

Always respond in this exact JSON format:
{
  "confirmed": true,
  "threat_name": "concise threat name",
  "explanation": "2-3 sentence plain English explanation",
  "risk_score": 0-100,
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "remediation": ["step 1", "step 2"],
  "false_positive_reason": ""
}
Be concise. No fluff."""


def _build_prompt(threat: dict, recent_packets: list) -> str:
    packet_summary = []
    for p in recent_packets[-5:]:
        if p.get("src_ip"):
            summary = f"  {p.get('src_ip')}:{p.get('src_port','?')} -> {p.get('dst_ip')}:{p.get('dst_port','?')} [{p.get('protocol','?')}]"
            packet_summary.append(summary)

    return f"""THREAT ALERT:
Rule: {threat.get('type')}
Source: {threat.get('src_ip')}
Destination: {threat.get('dst_ip')}:{threat.get('dst_port')}
Severity: {threat.get('severity')}
Risk: {threat.get('risk_score')}/100
Description: {threat.get('description')}

Recent packets:
{chr(10).join(packet_summary) if packet_summary else "  None"}

Respond in JSON format only."""


class AIAnalyzer:

    def __init__(self):
        self.provider = AI_PROVIDER
        self._client = None
        self._initialized = False

    def _init_client(self):
        if self._initialized:
            return

        if self.provider == "groq":
            try:
                from groq import Groq
                self._client = Groq(api_key=GROQ_API_KEY)
                self._initialized = True
                print("[+] Groq AI connected")
            except Exception as e:
                print(f"[!] Groq init failed: {e}")

        elif self.provider == "anthropic":
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
                self._initialized = True
                print("[+] Claude connected")
            except Exception as e:
                print(f"[!] Anthropic init failed: {e}")

        elif self.provider == "gemini":
            try:
                from google import genai
                self._client = genai.Client(api_key=GEMINI_API_KEY)
                self._initialized = True
                print("[+] Gemini AI connected")
            except Exception as e:
                print(f"[!] Gemini init failed: {e}")

    async def analyze(self, threat: dict, recent_packets: list) -> dict:
        # Only call the AI for HIGH and CRITICAL threats to avoid rate limits
        severity = threat.get("severity", "LOW")
        if severity not in ("HIGH", "CRITICAL"):
            return {**threat, "ai_analyzed": False}

        self._init_client()

        if not self._client:
            return {**threat, "ai_analyzed": False}

        prompt = _build_prompt(threat, recent_packets)

        try:
            loop = asyncio.get_event_loop()
            response_text = await loop.run_in_executor(
                None, self._call_api, prompt
            )

            clean = response_text.strip()
            if "```" in clean:
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]

            ai_result = json.loads(clean)

            # Validate field types — AI occasionally returns wrong types
            remediation = ai_result.get("remediation", [])
            if not isinstance(remediation, list):
                remediation = [str(remediation)] if remediation else []

            risk_score = ai_result.get("risk_score", threat.get("risk_score", 0))
            if not isinstance(risk_score, (int, float)):
                risk_score = threat.get("risk_score", 0)
            risk_score = max(0, min(100, int(risk_score)))

            severity = ai_result.get("severity", threat.get("severity", "LOW"))
            if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                severity = threat.get("severity", "LOW")

            return {
                **threat,
                "ai_analyzed":       True,
                "ai_confirmed":      bool(ai_result.get("confirmed", True)),
                "ai_threat_name":    str(ai_result.get("threat_name", threat.get("type", ""))),
                "ai_explanation":    str(ai_result.get("explanation", "")),
                "ai_risk_score":     risk_score,
                "ai_severity":       severity,
                "ai_remediation":    remediation,
                "ai_false_positive": str(ai_result.get("false_positive_reason", "")),
            }

        except json.JSONDecodeError:
            # AI returned non-JSON — don't mark as analyzed, keep original threat
            print(f"[!] AI returned invalid JSON — skipping AI enrichment")
            return {**threat, "ai_analyzed": False}
        except Exception as e:
            print(f"[!] AI analysis failed: {e}")
            return {**threat, "ai_analyzed": False}

    def _call_api(self, prompt: str) -> str:
        if self.provider == "groq":
            response = self._client.chat.completions.create(
                model=AI_MODEL,
                max_tokens=500,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content

        elif self.provider == "anthropic":
            response = self._client.messages.create(
                model=AI_MODEL,
                max_tokens=500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text

        elif self.provider == "gemini":
            full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"
            response = self._client.models.generate_content(
                model=AI_MODEL,
                contents=full_prompt
            )
            return response.text

        return "{}"
