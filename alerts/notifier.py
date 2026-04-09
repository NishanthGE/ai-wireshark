"""
alerts/notifier.py
Sends alerts to terminal, Slack, and email.
"""

import smtplib
import requests
from email.mime.text import MIMEText
from datetime import datetime
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import (
    ALERT_SLACK, SLACK_WEBHOOK_URL,
    ALERT_EMAIL, EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT,
    EMAIL_FROM, EMAIL_PASSWORD, EMAIL_TO,
    MIN_ALERT_SEVERITY
)

SEVERITY_COLORS = {
    "LOW":      "\033[94m",   # blue
    "MEDIUM":   "\033[93m",   # yellow
    "HIGH":     "\033[91m",   # red
    "CRITICAL": "\033[95m",   # magenta
}
RESET = "\033[0m"
BOLD  = "\033[1m"

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _should_alert(severity: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(MIN_ALERT_SEVERITY, 2)


def notify(threat: dict, skip_terminal: bool = False):
    """Send alert through all configured channels.

    Args:
        threat: threat dict from classifier / AI analyzer
        skip_terminal: pass True when dashboard is active so we don't
                       double-print to stdout (the dashboard shows it)
    """
    severity = threat.get("ai_severity") or threat.get("severity", "LOW")
    if not _should_alert(severity):
        return

    if not skip_terminal:
        _notify_terminal(threat)

    if ALERT_SLACK and SLACK_WEBHOOK_URL:
        _notify_slack(threat)

    if ALERT_EMAIL and EMAIL_TO:
        _notify_email(threat)


def _notify_terminal(threat: dict):
    """Print formatted threat alert to terminal."""
    severity  = threat.get("ai_severity")   or threat.get("severity", "UNKNOWN")
    name      = threat.get("ai_threat_name") or threat.get("type", "Unknown Threat")
    src       = threat.get("src_ip", "?")
    dst       = threat.get("dst_ip", "?")
    dst_port  = threat.get("dst_port", "?")
    score     = threat.get("ai_risk_score")  or threat.get("risk_score", 0)
    explain   = threat.get("ai_explanation") or threat.get("description", "")
    remediate = threat.get("ai_remediation", [])
    ts        = datetime.now().strftime("%H:%M:%S")
    color     = SEVERITY_COLORS.get(severity, "")

    print(f"\n{color}{BOLD}{'─'*60}{RESET}")
    print(f"{color}{BOLD}[{severity}] {name}{RESET}  {ts}")
    print(f"{color}{'─'*60}{RESET}")
    print(f"  Source      : {BOLD}{src}{RESET}")
    print(f"  Destination : {dst}:{dst_port}")
    print(f"  Risk Score  : {BOLD}{score}/100{RESET}")
    if explain:
        print(f"\n  Analysis    : {explain}")
    if remediate:
        print(f"\n  Remediation :")
        for step in remediate:
            print(f"    → {step}")
    if threat.get("ai_analyzed"):
        print(f"\n  {BOLD}[AI]{RESET} Claude-verified threat")
    print()


def _notify_slack(threat: dict):
    """Send alert to Slack webhook."""
    severity = threat.get("ai_severity") or threat.get("severity", "LOW")
    name     = threat.get("ai_threat_name") or threat.get("type", "Threat")
    score    = threat.get("ai_risk_score") or threat.get("risk_score", 0)
    explain  = threat.get("ai_explanation") or threat.get("description", "")
    remediate = threat.get("ai_remediation", [])

    emoji = {"LOW": "🔵", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨"}.get(severity, "⚠️")

    remediation_text = "\n".join(f"• `{r}`" for r in remediate) if remediate else "No specific steps"

    payload = {
        "text": f"{emoji} *{severity} — {name}*",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *[{severity}] {name}*\n*Source:* `{threat.get('src_ip')}` → `{threat.get('dst_ip')}:{threat.get('dst_port')}`\n*Risk Score:* {score}/100"
                }
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Analysis:*\n{explain}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Remediation:*\n{remediation_text}"}
            }
        ]
    }

    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        print("[!] Slack notification failed — check webhook URL in .env")


def _notify_email(threat: dict):
    """Send alert via email (SMTP)."""
    severity = threat.get("ai_severity") or threat.get("severity", "LOW")
    name     = threat.get("ai_threat_name") or threat.get("type", "Threat")
    explain  = threat.get("ai_explanation") or threat.get("description", "")

    subject = f"[AI Wireshark] {severity} Alert: {name}"
    body = f"""
AI Wireshark Security Alert
============================
Threat     : {name}
Severity   : {severity}
Source     : {threat.get('src_ip')} → {threat.get('dst_ip')}:{threat.get('dst_port')}
Risk Score : {threat.get('ai_risk_score') or threat.get('risk_score', 0)}/100
Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Analysis:
{explain}

Remediation Steps:
{chr(10).join(f'- {r}' for r in threat.get('ai_remediation', []))}
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = EMAIL_FROM
    msg["To"]      = EMAIL_TO

    try:
        with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"[!] Email notification failed: {e}")
