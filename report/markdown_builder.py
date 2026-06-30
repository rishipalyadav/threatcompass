"""
report/markdown_builder.py

Generates a clean Markdown export of the threat report —
suitable for pasting into GitHub wikis, Confluence, or Notion.
"""

from datetime import datetime


def generate_markdown(report) -> str:
    s = report.system
    lines = []

    lines.append(f"# ThreatLens Report — {s.project_name}")
    lines.append("")
    lines.append(f"**Industry:** {s.domain.upper()}  ")
    lines.append(f"**Overall Risk:** {report.risk_rating}  ")
    lines.append(f"**User Type:** {s.user_type}  ")
    lines.append(f"**Generated:** {datetime.now().strftime('%d %b %Y, %H:%M')}  ")
    lines.append(f"**Framework:** OWASP LLM Top 10 (2025)")
    lines.append("")
    lines.append(f"> {s.summary}")
    lines.append("")

    lines.append("## Risk Summary")
    lines.append("")
    lines.append("| Total | Critical | High | Medium | Low |")
    lines.append("|---|---|---|---|---|")
    lines.append(
        f"| {report.total_threats} | {report.critical_count} | "
        f"{report.high_count} | {report.medium_count} | {report.low_count} |"
    )
    lines.append("")

    if s.assumptions:
        lines.append("## ⚠ Assumptions Made")
        lines.append("")
        for a in s.assumptions:
            lines.append(f"- {a}")
        lines.append("")

    lines.append("## Identified Threats")
    lines.append("")

    for threat in report.threats:
        lines.append(f"### {threat.threat_id}: {threat.threat_name} — `{threat.severity}`")
        lines.append("")
        lines.append(
            f"*{threat.signals_detected} of {threat.signals_total} signals detected* · "
            f"[OWASP Reference]({threat.owasp_reference})"
        )
        lines.append("")

        if threat.narrative:
            lines.append(threat.narrative)
        else:
            lines.append("**Evidence:**")
            for e in threat.evidence:
                lines.append(f"- {e}")
            lines.append("")
            lines.append("**Mitigations:**")
            for m in threat.mitigations:
                lines.append(f"- {m}")

        lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("## GRC & Governance Checklist")
    lines.append("")
    grc_items = [
        "Document AI system in the risk register with this threat model as evidence",
        "Add LLM provider to Third-Party Risk Management register",
        "Define and approve an AI Acceptable Use Policy",
        "Establish audit logging requirements for all AI-driven actions",
        "Schedule threat model review when architecture changes significantly",
        "Define escalation path for AI-related security incidents",
    ]
    if s.is_bfsi:
        grc_items += [
            "Review against RBI guidelines on AI in financial services",
            "Verify LLM provider data residency meets RBI outsourcing requirements",
        ]
    for item in grc_items:
        lines.append(f"- [ ] {item}")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "*This is a project-generated work. Kindly verify with your expertise before "
        "acting on any recommendations. This report is suggestive in nature.*"
    )
    lines.append("")
    lines.append("*Made by NotYourCISO with ❤️ · ThreatCompass*")

    return "\n".join(lines)