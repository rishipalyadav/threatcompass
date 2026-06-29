"""
report/pdf_builder.py

Generates a PDF threat model report from a ThreatReport object.
Uses reportlab — no external dependencies beyond pip install reportlab.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#cc0000"),
    "HIGH":     colors.HexColor("#cc6600"),
    "MEDIUM":   colors.HexColor("#ccaa00"),
    "LOW":      colors.HexColor("#336600"),
}

SEVERITY_BG = {
    "CRITICAL": colors.HexColor("#fff0f0"),
    "HIGH":     colors.HexColor("#fff5ee"),
    "MEDIUM":   colors.HexColor("#fffef0"),
    "LOW":      colors.HexColor("#f0fff0"),
}


def _styles():
    base = getSampleStyleSheet()
    custom = {}

    custom["title"] = ParagraphStyle(
        "title", fontSize=22, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1a1a2e"), spaceAfter=4,
    )
    custom["subtitle"] = ParagraphStyle(
        "subtitle", fontSize=11, fontName="Helvetica",
        textColor=colors.HexColor("#555555"), spaceAfter=16,
    )
    custom["section_header"] = ParagraphStyle(
        "section_header", fontSize=14, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1a1a2e"), spaceBefore=16, spaceAfter=6,
    )
    custom["threat_title"] = ParagraphStyle(
        "threat_title", fontSize=12, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1a1a2e"), spaceBefore=12, spaceAfter=4,
    )
    custom["subsection"] = ParagraphStyle(
        "subsection", fontSize=10, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#333333"), spaceBefore=8, spaceAfter=3,
    )
    custom["body"] = ParagraphStyle(
        "body", fontSize=9, fontName="Helvetica",
        textColor=colors.HexColor("#333333"), spaceAfter=4, leading=14,
    )
    custom["bullet"] = ParagraphStyle(
        "bullet", fontSize=9, fontName="Helvetica",
        textColor=colors.HexColor("#333333"), spaceAfter=2,
        leftIndent=12, leading=13,
    )
    custom["assumption"] = ParagraphStyle(
        "assumption", fontSize=9, fontName="Helvetica-Oblique",
        textColor=colors.HexColor("#8B6914"), spaceAfter=2,
        leftIndent=12, leading=13,
    )
    custom["footer"] = ParagraphStyle(
        "footer", fontSize=8, fontName="Helvetica",
        textColor=colors.HexColor("#999999"), alignment=TA_CENTER,
    )
    custom["label"] = ParagraphStyle(
        "label", fontSize=8, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#666666"),
    )

    return custom

def _draw_watermark(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 40)
    canvas.setFillColorRGB(0.85, 0.85, 0.85, alpha=0.3)
    canvas.translate(A4[0]/2, A4[1]/2)
    canvas.rotate(45)
    canvas.drawCentredString(0, 0, "ThreatCompass by NotYourCISO")
    canvas.restoreState()


def generate_pdf(report) -> bytes:
    """
    Takes a ThreatReport, returns PDF as bytes.
    Call with: pdf_bytes = generate_pdf(report)
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2.5*cm,
        title=f"ThreatCompass Report — {report.system.project_name}",
    )

    st = _styles()
    story = []
    s = report.system

    # ── Cover ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("🔍 ThreatCompass for AI Products", st["title"]))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("Threat Model Report", st["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2,
                            color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 0.4*cm))

    meta = [
        ["System", s.project_name],
        ["Industry", s.domain.upper()],
        ["Overall Risk", report.risk_rating],
        ["Generated", datetime.now().strftime("%d %b %Y, %H:%M")],
        ["Framework", "OWASP LLM Top 10 (2025)"],
    ]
    meta_table = Table(meta, colWidths=[4*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",    (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",   (0, 0), (0, -1), colors.HexColor("#666666")),
        ("TEXTCOLOR",   (1, 0), (1, -1), colors.HexColor("#1a1a2e")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#f8f8f8"), colors.white]),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5*cm))

    # Summary line
    story.append(Paragraph(s.summary, st["body"]))
    story.append(Spacer(1, 0.3*cm))

    # ── Risk summary table ────────────────────────────────────────────────
    story.append(Paragraph("Risk Summary", st["section_header"]))

    risk_color = SEVERITY_COLORS.get(report.risk_rating, colors.grey)
    summary_data = [
        ["Total Threats", "Critical", "High", "Medium", "Low"],
        [
            str(report.total_threats),
            str(report.critical_count),
            str(report.high_count),
            str(report.medium_count),
            str(report.low_count),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[3.4*cm]*5)
    summary_table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",      (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("TEXTCOLOR",     (1, 1), (1, 1), SEVERITY_COLORS["CRITICAL"]),
        ("TEXTCOLOR",     (2, 1), (2, 1), SEVERITY_COLORS["HIGH"]),
        ("TEXTCOLOR",     (3, 1), (3, 1), SEVERITY_COLORS["MEDIUM"]),
        ("TEXTCOLOR",     (4, 1), (4, 1), SEVERITY_COLORS["LOW"]),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
    ]))
    story.append(summary_table)

    # ── Assumptions ───────────────────────────────────────────────────────
    if s.assumptions:
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("⚠ Assumptions Made", st["section_header"]))
        story.append(Paragraph(
            "The following assumptions were made where information was unclear. "
            "Review these as they affect which threats were identified.",
            st["body"]
        ))
        for a in s.assumptions:
            story.append(Paragraph(f"• {a}", st["assumption"]))

    # ── Threats ───────────────────────────────────────────────────────────
    story.append(Paragraph("Identified Threats", st["section_header"]))
    story.append(HRFlowable(width="100%", thickness=0.5,
                            color=colors.HexColor("#cccccc")))

    for threat in report.threats:
        sev_color = SEVERITY_COLORS.get(threat.severity, colors.grey)
        sev_bg = SEVERITY_BG.get(threat.severity, colors.white)

        block = []

        # Threat header row
        header_data = [[
            Paragraph(
                f"<b>{threat.threat_id}: {threat.threat_name}</b>",
                ParagraphStyle("th", fontSize=11, fontName="Helvetica-Bold",
                               textColor=colors.white)
            ),
            Paragraph(
                threat.severity,
                ParagraphStyle("sev", fontSize=10, fontName="Helvetica-Bold",
                               textColor=colors.white, alignment=TA_RIGHT)
            ),
        ]]
        header_table = Table(header_data, colWidths=[13*cm, 4*cm])
        header_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), sev_color),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        block.append(header_table)

        # Parse narrative sections
        if threat.narrative:
            sections = _parse_narrative(threat.narrative)

            section_map = [
                ("Threat Narrative",         "📖 Threat Narrative"),
                ("How It Can Be Exploited",  "⚔ How It Can Be Exploited"),
                ("Safeguards",               "🛡 Safeguards"),
                ("Dev Team Checklist",       "✅ Dev Team Checklist"),
            ]

            for key, label in section_map:
                content = sections.get(key, "").strip()
                if not content:
                    continue
                block.append(Paragraph(label, st["subsection"]))
                for line in content.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    # Checklist and bullet items
                    if line.startswith(("-", "*", "•", "[")):
                        clean = line.lstrip("-*•[ ]").strip()
                        if clean:
                            block.append(Paragraph(f"• {clean}", st["bullet"]))
                    else:
                        block.append(Paragraph(line, st["body"]))

        else:
            # Fallback to raw evidence
            block.append(Paragraph("Evidence", st["subsection"]))
            for e in threat.evidence:
                block.append(Paragraph(f"• {e}", st["bullet"]))

        block.append(Spacer(1, 0.3*cm))
        block.append(HRFlowable(width="100%", thickness=0.3,
                                color=colors.HexColor("#eeeeee")))

        story.append(KeepTogether(block[:4]))  # Keep header + first section together
        story.extend(block[4:])

    # ── GRC Checklist ─────────────────────────────────────────────────────
    story.append(Paragraph("GRC & Governance Checklist", st["section_header"]))
    grc_items = [
        "Document AI system in the risk register with this threat model as evidence",
        "Add LLM provider to Third-Party Risk Management register",
        "Define and approve an AI Acceptable Use Policy",
        "Establish audit logging requirements for all AI-driven actions",
        "Schedule threat model review when architecture changes",
        "Define escalation path for AI-related security incidents",
    ]
    if s.is_bfsi:
        grc_items += [
            "Review against RBI guidelines on AI in financial services",
            "Verify LLM provider data residency meets RBI outsourcing requirements",
        ]
    if s.has_agentic_actions:
        grc_items += [
            "Define maximum impact boundaries for AI-triggered actions",
            "Test human-in-the-loop controls as part of UAT",
        ]
    for item in grc_items:
        story.append(Paragraph(f"☐  {item}", st["bullet"]))

    # ── Footer ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        "⚠ Disclaimer",
        ParagraphStyle("disc_head", fontSize=9, fontName="Helvetica-Bold",
                       textColor=colors.HexColor("#cc6600"))
    ))
    story.append(Paragraph(
        "This is a project-generated work. Kindly verify with your expertise before "
        "acting on any recommendations. This report is suggestive in nature and should "
        "not be treated as a substitute for professional security assessment.",
        ParagraphStyle("disc_body", fontSize=8, fontName="Helvetica-Oblique",
                       textColor=colors.HexColor("#666666"), leading=12)
    ))
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=0.5,
                            color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Made by NotYourCISO with love  ·  ThreatCompass for AI Products  ·  "
        f"Generated {datetime.now().strftime('%d %b %Y')}  ·  "
        "OWASP LLM Top 10 (2025)",
        st["footer"]
    ))

    doc.build(story, onFirstPage=_draw_watermark, onLaterPages=_draw_watermark)
    return buffer.getvalue()


def _parse_narrative(narrative: str) -> dict:
    """Parse the 4-section narrative into a dict keyed by section name."""
    sections = {
        "Threat Narrative": "",
        "How It Can Be Exploited": "",
        "Safeguards": "",
        "Dev Team Checklist": "",
    }
    current = None
    buffer = []

    for line in narrative.split("\n"):
        clean = line.strip().lstrip("#").strip().strip("*").strip()
        if clean in sections:
            if current and buffer:
                sections[current] = "\n".join(buffer).strip()
            current = clean
            buffer = []
        else:
            if current:
                buffer.append(line)

    if current and buffer:
        sections[current] = "\n".join(buffer).strip()

    return sections
