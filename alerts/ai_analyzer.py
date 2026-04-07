"""
alerts/ai_analyzer.py
Sends threat context to Claude / OpenAI and returns
a structured AI-powered security analysis.
"""

import json
import asyncio
from typing import Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import (
    ANTHROPIC_API_KEY, OPENAI_API_KEY,
    AI_PROVIDER, AI_MODEL
)


SYSTEM_PROMPT = """You are an expert network security analyst inside a real-time 
packet analysis tool. You will receive details about a suspicious network event 
that was flagged by automated rules.

Your job is to:
1. Confirm or refine the threat classification
2. Explain clearly what is happening in simple terms
3. Assess the actual risk (not just rule-triggered)
4. Give 1-2 specific, actionable remediation commands

Always respond in this exact JSON format:
{
  "confirmed": true/false,
  "threat_name": "concise threat name",
  "explanation": "2-3 sentence plain English explanation of what is happening",
  "risk_score": 0-100,
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "remediation": ["command or step 1", "command or step 2"],
  "false_positive_reason": "if confirmed=false, explain why"
}

Be concise. Security analysts are busy. No fluff."""


def _build_prompt(threat: dict, recent_packets: list) -> str:
    """Build the prompt from threat data + surrounding packet context."""
    packet_summary = []
    for p in recent_packets[-5:]:
        if p.get("src_ip"):
            summary = f"  {p.get('src_ip')}:{p.get('src_port','?')} → {p.get('dst_ip')}:{p.get('dst_port','?')} [{p.get('protocol','?')}] {p.get('length',0)}b"
            if p.get("syn"):
                summary += " SYN"
            if p.get("dns_query"):
                summary += f" DNS:{p['dns_query']}"
            packet_summary.append(summary)

    return f"""THREAT ALERT — Analyze this security event:

Rule triggered: {threat.get('type')}
Source IP: {threat.get('src_ip')}
Destination: {threat.get('dst_ip')}:{threat.get('dst_port')}
Initial severity: {threat.get('severity')}
Initial risk score: {threat.get('risk_score')}/100
Rule description: {threat.get('description')}

Recent packets from this source:
{chr(10).join(packet_summary) if packet_summary else "  No recent packet history"}

Provide your expert analysis in the required JSON format."""


class AIAnalyzer:
    """Handles AI API calls for threat analysis."""

    def __init__(self):
        self.provider = AI_PROVIDER
        self._client = None
        self._initialized = False

    def _init_client(self):
        """Lazy-initialize the AI client."""
        if self._initialized:
            return

        if self.provider == "anthropic":
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
                self._initialized = True
                print("[✓] Anthropic Claude connected")
            except ImportError:
                print("[!] anthropic package not installed. Run: pip install anthropic")
            except Exception as e:
                print(f"[!] Anthropic init failed: {e}")

        elif self.provider == "openai":
            try:
                import openai
                self._client = openai.OpenAI(api_key=OPENAI_API_KEY)
                self._initialized = True
                print("[✓] OpenAI connected")
            except ImportError:
                print("[!] openai package not installed. Run: pip install openai")
            except Exception as e:
                print(f"[!] OpenAI init failed: {e}")

    async def analyze(self, threat: dict, recent_packets: list) -> dict:
        """
        Send threat to AI for analysis.
        Returns enriched threat dict with AI fields added.
        Falls back to rule-based result if API fails.
        """
        self._init_client()

        if not self._client:
            # No AI client — return rule-based result unchanged
            return {**threat, "ai_analyzed": False}

        prompt = _build_prompt(threat, recent_packets)

        try:
            # Run in thread pool to avoid blocking async loop
            loop = asyncio.get_event_loop()
            response_text = await loop.run_in_executor(
                None, self._call_api, prompt
            )

            # Parse JSON response
            ai_result = json.loads(response_text)

            return {
                **threat,
                "ai_analyzed":       True,
                "ai_confirmed":      ai_result.get("confirmed", True),
                "ai_threat_name":    ai_result.get("threat_name", threat["type"]),
                "ai_explanation":    ai_result.get("explanation", ""),
                "ai_risk_score":     ai_result.get("risk_score", threat["risk_score"]),
                "ai_severity":       ai_result.get("severity", threat["severity"]),
                "ai_remediation":    ai_result.get("remediation", []),
                "ai_false_positive": ai_result.get("false_positive_reason", ""),
            }

        except json.JSONDecodeError:
            # API returned non-JSON — store raw text
            return {
                **threat,
                "ai_analyzed":    True,
                "ai_explanation": response_text[:500],
                "ai_confirmed":   True,
            }
        except Exception as e:
            print(f"[!] AI analysis failed: {e}")
            return {**threat, "ai_analyzed": False}

    def _call_api(self, prompt: str) -> str:
        """Synchronous API call (runs in thread pool)."""
        if self.provider == "anthropic":
            response = self._client.messages.create(
                model=AI_MODEL,
                max_tokens=500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text

        elif self.provider == "openai":
            response = self._client.chat.completions.create(
                model="gpt-4o",
                max_tokens=500,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt}
                ]
            )
            return response.choices[0].message.content

        return "{}"
