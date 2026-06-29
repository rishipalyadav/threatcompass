"""
narrative/generator.py

LLM #2 in the pipeline.

Takes each fired threat (with deterministic evidence from evaluators)
and generates a structured 4-section narrative specific to the user's system.

Output format per threat:
  Threat Narrative
  How It Can Be Exploited
  Safeguards
  Dev Team Checklist
"""

import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

NARRATIVE_PROMPT = """
You are a senior application security consultant writing a threat model report.
You are analyzing a specific threat for a client's AI-powered system.

System: {project_name}
Industry: {domain}
Summary: {summary}

Threat: {threat_id} — {threat_name}
Severity: {severity}

Evidence identified in this specific system:
{evidence}

Write a structured threat analysis with EXACTLY these four sections.
Be specific to THIS system — not generic. Reference their actual components.
Do not show any thinking or reasoning. Output only the four sections below.

**Threat Narrative**
2-3 sentences explaining what this threat is in the context of their specific system.
Reference their actual architecture — not a generic description of the threat.

**How It Can Be Exploited**
A concrete, realistic attack scenario against their system.
Walk through what an attacker would actually do, step by step.
Make it specific enough that a developer reading this immediately understands the risk.

**Safeguards**
3-5 specific technical or process controls that address this threat.
Each control should be actionable — not "implement security" but "validate all LLM outputs 
against an allowlist before passing to the payments API".

**Dev Team Checklist**
4-6 checklist items the development team should verify before shipping.
Format as short, verifiable statements starting with a verb.
Example: "Validate that user input is stripped of instruction-like patterns before reaching the LLM"
"""


def generate_narrative(threat, report) -> str:
    """
    Generates a 4-section narrative for a single fired threat.
    Returns the formatted string ready for display.
    """
    evidence_text = "\n".join(f"- {e}" for e in threat.evidence)

    prompt = NARRATIVE_PROMPT.format(
        project_name=report.system.project_name,
        domain=report.system.domain,
        summary=report.system.summary,
        threat_id=threat.threat_id,
        threat_name=threat.threat_name,
        severity=threat.severity,
        evidence=evidence_text,
    )

    client = OpenAI(
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )
    response = client.chat.completions.create(
        model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        max_tokens=700,
        temperature=0.3,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a security consultant writing threat model reports. "
                    "Output only the four sections requested. "
                    "No preamble, no meta-commentary, no thinking out loud."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
    )

    return response.choices[0].message.content.strip()


def enrich_report_with_narratives(report):
    """
    Adds narratives to all fired threats in the report.
    Modifies threats in place, returns report.
    """
    for threat in report.threats:
        threat.narrative = generate_narrative(threat, report)
    return report
