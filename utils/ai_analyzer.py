"""
AI Threat Analysis Engine using Groq LLM (Llama-3.3-70b-versatile).
Features robust fallback to SOC threat intelligence when GROQ_API_KEY is unset or unavailable.
Never crashes on missing API key or network failures.
"""

import os
import json
from dotenv import load_dotenv
from utils.constants import THREAT_INTELLIGENCE, RISK_LEVELS

load_dotenv()


def is_groq_configured():
    """Check if a valid, non-placeholder GROQ_API_KEY is configured."""
    key = os.getenv("GROQ_API_KEY", "").strip()
    if not key or key in ["your_key_here", "YOUR_GROQ_API_KEY", "your_groq_api_key_here"]:
        return False
    return True


def get_groq_client():
    """Lazily initialize Groq client only when valid key exists."""
    if not is_groq_configured():
        return None
    try:
        from groq import Groq
        return Groq(api_key=os.getenv("GROQ_API_KEY").strip())
    except Exception as e:
        print(f"[AI Analyzer] Warning: Could not initialize Groq client: {e}")
        return None


def get_fallback_explanation(threat_type, risk_level, confidence, protocol="TCP", service="HTTP"):
    """Deterministic SOC intelligence explanation when LLM is unavailable."""
    intel = THREAT_INTELLIGENCE.get(threat_type, THREAT_INTELLIGENCE["Normal"])

    return {
        "source": "SOC Threat Intelligence Engine (Deterministic)",
        "threat_type": threat_type,
        "risk_level": risk_level,
        "confidence": confidence,
        "explanation": intel["description"],
        "detection_rationale": f"Identified characteristic {threat_type} flow signatures over {protocol}/{service} with {confidence}% model confidence.",
        "potential_impact": intel["impact"],
        "recommended_actions": [
            intel["action"],
            "Inspect edge firewall logs and verify IDS alerting thresholds.",
            "Cross-reference source IP against active threat intelligence feeds.",
            "Verify endpoint system integrity and session authentication logs."
        ],
        "notice": "AI analysis unavailable. Configure GROQ_API_KEY in .env to enable dynamic LLM-generated analysis." if not is_groq_configured() else ""
    }


def analyze_single_threat(threat_type, risk_level, confidence, protocol="TCP", service="HTTP", key_features=None):
    """
    Generate SOC cybersecurity analysis for an individual detected threat.
    Uses Groq LLM if available; gracefully falls back to deterministic SOC intel.
    """
    client = get_groq_client()
    fallback = get_fallback_explanation(threat_type, risk_level, confidence, protocol, service)

    if not client:
        return fallback

    prompt = f"""
You are a senior Tier-3 Cybersecurity SOC Analyst. Analyze this detected network anomaly:
- Attack Classification: {threat_type}
- Assessed Risk Level: {risk_level}
- Model Confidence: {confidence}%
- Protocol / Service: {protocol} / {service}
- Key Flow Signatures: {key_features if key_features else 'Standard signature metrics'}

Provide an objective, defensive-only security analysis in strictly valid JSON format with keys:
- "explanation": (A 2-3 sentence overview of the threat behavior)
- "detection_rationale": (Why the machine learning flow features triggered this alert)
- "potential_impact": (The potential security consequence to enterprise assets)
- "recommended_actions": (An array of exactly 4 defensive remediation steps)
"""

    try:
        completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a defensive cybersecurity SOC analyst. Output strictly valid JSON. Do not generate offensive exploitation or payload material."
                },
                {"role": "user", "content": prompt}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.3,
            max_tokens=500,
            response_format={"type": "json_object"}
        )

        res_json = json.loads(completion.choices[0].message.content)
        return {
            "source": "Groq Llama-3.3-70B AI",
            "threat_type": threat_type,
            "risk_level": risk_level,
            "confidence": confidence,
            "explanation": res_json.get("explanation", fallback["explanation"]),
            "detection_rationale": res_json.get("detection_rationale", fallback["detection_rationale"]),
            "potential_impact": res_json.get("potential_impact", fallback["potential_impact"]),
            "recommended_actions": res_json.get("recommended_actions", fallback["recommended_actions"]),
            "notice": ""
        }

    except Exception as e:
        print(f"[AI Analyzer] Groq API call failed, using fallback: {e}")
        fallback["notice"] = f"Groq API unavailable ({str(e)[:60]}...). Using SOC rule-based analysis."
        return fallback


def analyze_threat(total, safe, threat, threat_rate, threat_counts=None):
    """
    Batch dataset analysis summary for uploaded traffic files.
    Preserves backwards compatibility with legacy routes while adding rich structured reporting.
    """
    client = get_groq_client()

    fallback_level = "LOW"
    fallback_attack = "Normal Network Traffic"
    fallback_recs = [
        "Maintain standard network telemetry monitoring",
        "Perform routine firewall policy audit",
        "Verify intrusion detection system signature updates",
        "Ensure endpoint EDR agents are reporting healthy status"
    ]

    if threat_rate > 50:
        fallback_level = "CRITICAL"
        fallback_attack = "High-Density Distributed Denial of Service (DoS) or Multi-Vector Assault"
        fallback_recs = [
            "Activate edge DDoS mitigation and IP rate-limiting rules",
            "Isolate compromised network subnets and apply ACL blocks",
            "Inspect edge ingress router logs for spoofed SYN/UDP floods",
            "Escalate immediately to Incident Response and Tier-3 SOC team"
        ]
    elif threat_rate > 25:
        fallback_level = "HIGH"
        fallback_attack = "Substantial Reconnaissance & Denial of Service Activity"
        fallback_recs = [
            "Drop connection requests from identified scanning CIDR blocks",
            "Inspect web application firewall and reverse proxy metrics",
            "Enforce strict rate limits on authentication endpoints",
            "Enable heightened alerting for privileged account activity"
        ]
    elif threat_rate > 5:
        fallback_level = "MEDIUM"
        fallback_attack = "Anomalous Probe Scanning / Unauthorized Access Inquiries"
        fallback_recs = [
            "Monitor scanning IPs for escalation to exploitation phase",
            "Audit public-facing services for exposed non-essential ports",
            "Review authentication failure thresholds across remote services",
            "Cross-reference source IPs with known threat intelligence feeds"
        ]

    ai_source = "SOC Threat Intelligence Engine"
    notice = ""

    if client:
        prompt = f"""
You are a Lead SOC Analyst reviewing a batch network traffic assessment:
- Total Records Analyzed: {total}
- Legitimate Safe Traffic: {safe}
- Malicious Traffic: {threat}
- Threat Detection Rate: {threat_rate}%
- Threat Category Breakdown: {threat_counts if threat_counts else 'Aggregated NSL-KDD samples'}

Return strictly valid JSON with keys:
- "level": ("CRITICAL", "HIGH", "MEDIUM", or "LOW")
- "attack": (Concise descriptive title of observed traffic patterns)
- "analysis": (2-3 sentences explaining the assessment)
- "recommendations": (Array of exactly 4 actionable defensive remediation points)
"""
        try:
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity SOC analyst returning structured JSON. Only provide defensive security guidance."
                    },
                    {"role": "user", "content": prompt}
                ],
                model="llama-3.3-70b-versatile",
                temperature=0.3,
                max_tokens=600,
                response_format={"type": "json_object"}
            )
            ai_data = json.loads(chat_completion.choices[0].message.content)
            level = ai_data.get("level", fallback_level)
            attack = ai_data.get("attack", fallback_attack)
            recs = ai_data.get("recommendations", fallback_recs)
            analysis_text = ai_data.get("analysis", "")
            ai_source = "Groq Llama-3.3-70B AI"
        except Exception as e:
            print(f"[AI Analyzer] Groq batch analysis failed: {e}")
            level = fallback_level
            attack = fallback_attack
            recs = fallback_recs
            analysis_text = "Rule-based analysis applied based on threat density metrics."
            notice = f"AI analysis note: Groq API unavailable ({str(e)[:50]}...)."
    else:
        level = fallback_level
        attack = fallback_attack
        recs = fallback_recs
        analysis_text = "Standard defensive assessment derived from NSL-KDD anomaly rate thresholds."
        notice = "AI analysis note: Configure GROQ_API_KEY in .env to enable Groq AI-generated reports."

    formatted_str = f"""Threat Level: {level}
Possible Attack: {attack}
Risk Score: {threat_rate}%
Analysis Engine: {ai_source}
{f'Notice: {notice}' if notice else ''}

Analysis Summary:
{analysis_text}

Recommendations:
""" + "\n".join([f"- {r}" for r in recs])

    return formatted_str