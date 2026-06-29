"""
ui/app.py — ThreatLens for AI Products

Flow:
  Step 1 — User describes system
           → AI detection: if no AI components, confirm with user
  Step 2 — Clarifying questions (single round)
  Step 3 — Threat report with PDF export

Features:
  - AI component detection gate
  - Single-round clarification
  - 4-section structured narratives
  - PDF export
  - Error handling throughout
  - Made by NotYourCISO with love
"""

import streamlit as st
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="ThreatLens for AI Products",
    page_icon="🔍",
    layout="wide",
)

from engine.clarifier import (
    check_ai_components,
    get_clarifying_questions,
    build_enriched_description,
)
from engine.runner import run
from narrative.generator import enrich_report_with_narratives
from report.pdf_builder import generate_pdf

# ── Helpers ───────────────────────────────────────────────────────────────────
def _parse_narrative_sections(narrative: str) -> dict:
    """Parse 4-section narrative into a dict keyed by section name."""
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


# ── Constants ─────────────────────────────────────────────────────────────────
SEVERITY_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ccaa00",
    "LOW":      "#44bb44",
}
SEVERITY_BG = {
    "CRITICAL": "#2d0000",
    "HIGH":     "#2d1400",
    "MEDIUM":   "#2d2600",
    "LOW":      "#002d00",
}
SAMPLES = {
    "Bank Customer Support Chatbot": open(
        os.path.join(os.path.dirname(__file__),
                     "../tests/test_descriptions/01_bank_chatbot.txt")
    ).read().strip(),
    "Loan Underwriting Assistant": open(
        os.path.join(os.path.dirname(__file__),
                     "../tests/test_descriptions/02_loan_underwriting.txt")
    ).read().strip(),
    "AI KYC Verification System": open(
        os.path.join(os.path.dirname(__file__),
                     "../tests/test_descriptions/03_kyc_verification.txt")
    ).read().strip(),
    "Fraud Investigation Copilot": open(
        os.path.join(os.path.dirname(__file__),
                     "../tests/test_descriptions/04_fraud_copilot.txt")
    ).read().strip(),
}

# ── Session state ─────────────────────────────────────────────────────────────
defaults = {
    "step": 1,
    "description": "",
    "questions": [],
    "report": None,
    "no_ai_detected": False,
    "ai_reasoning": "",
    "error": None,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


def reset():
    for k, v in defaults.items():
        st.session_state[k] = v


def set_error(msg: str):
    st.session_state.error = msg


# ── Header ────────────────────────────────────────────────────────────────────
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🔍 ThreatLens for AI Products")
    st.caption(
        "Threat modeling specific to AI-enabled products — "
        "powered by OWASP LLM Top 10 (2025)"
    )
with col_reset:
    if st.session_state.step > 1 or st.session_state.no_ai_detected:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("↩ Start Over"):
            reset()
            st.rerun()

st.divider()

# ── Global error banner ───────────────────────────────────────────────────────
if st.session_state.error:
    st.error(
        f"**Something went wrong:** {st.session_state.error}\n\n"
        "Please try again. If the issue persists, check your GROQ_API_KEY in `.env`."
    )
    if st.button("Clear error and retry"):
        st.session_state.error = None
        st.rerun()
    st.stop()

# ── Step indicator ────────────────────────────────────────────────────────────
if not st.session_state.no_ai_detected:
    steps = ["Describe System", "Clarify Details", "Threat Report"]
    cols = st.columns(3)
    for i, (col, label) in enumerate(zip(cols, steps), 1):
        with col:
            active = st.session_state.step == i
            done = st.session_state.step > i
            color = "#4CAF50" if done else ("#1f77b4" if active else "#555")
            prefix = "✅" if done else ("▶" if active else "○")
            st.markdown(
                f"<div style='text-align:center; color:{color}; "
                f"font-weight:{'bold' if active else 'normal'}'>"
                f"{prefix} Step {i}: {label}</div>",
                unsafe_allow_html=True,
            )
    st.markdown("<br>", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# NO AI COMPONENTS DETECTED — confirmation gate
# ════════════════════════════════════════════════════════════════════════════
if st.session_state.no_ai_detected:
    st.warning(
        "### ⚠️ No AI Components Detected\n\n"
        f"{st.session_state.ai_reasoning}\n\n"
        "ThreatLens is designed specifically for threat modeling of **AI-enabled products**. "
        "It evaluates risks from the OWASP LLM Top 10 framework, which applies only to systems "
        "that use AI/ML models, LLM APIs, or AI-powered components.\n\n"
        "**Does your system actually contain AI components that weren't mentioned in your description?**"
    )

    col_yes, col_no = st.columns(2)
    with col_yes:
        if st.button("✅ Yes — let me update my description", type="primary",
                     use_container_width=True):
            st.session_state.no_ai_detected = False
            st.session_state.step = 1
            st.rerun()
    with col_no:
        if st.button("❌ No — my system has no AI components",
                     use_container_width=True):
            st.session_state.no_ai_detected = False
            st.info(
                "**ThreatLens is for AI-enabled products only.**\n\n"
                "For threat modeling of traditional software systems, consider tools like "
                "OWASP Threat Dragon, Microsoft Threat Modeling Tool, or IriusRisk.\n\n"
                "If you add AI components to your system in the future, come back — "
                "we'll be here. 👋"
            )
            st.stop()

    st.stop()


# ════════════════════════════════════════════════════════════════════════════
# STEP 1 — Description
# ════════════════════════════════════════════════════════════════════════════
elif st.session_state.step == 1:
    st.markdown("### Describe your AI-powered system")
    st.markdown(
        "Tell us what you're building — what it does, what AI model or API it uses, "
        "what data it handles, and what actions it can take. "
        "The more detail you provide, the fewer follow-up questions we'll need."
    )

    with st.expander("💡 Load a sample description"):
        for name, text in SAMPLES.items():
            if st.button(name, key=f"sample_{name}"):
                st.session_state.description = text
                st.rerun()

    description = st.text_area(
        "System description",
        value=st.session_state.description,
        height=220,
        placeholder=(
            "Example: We're building a customer support chatbot for our bank using GPT-4o "
            "on Azure OpenAI. Customers log in before chatting. The bot retrieves account "
            "balances via our internal API and can initiate refunds up to ₹5,000 after "
            "customer confirmation. Chat history is stored for QA monitoring..."
        ),
        label_visibility="collapsed",
    )

    if st.button("Continue →", type="primary", disabled=not description.strip()):
        st.session_state.description = description.strip()

        # ── Step A: Check for AI components ──────────────────────────────
        with st.spinner("Analyzing your description..."):
            try:
                has_ai, reasoning = check_ai_components(st.session_state.description)
                if not has_ai:
                    st.session_state.no_ai_detected = True
                    st.session_state.ai_reasoning = reasoning
                    st.rerun()
            except Exception as e:
                # If AI detection fails, show error — don't silently proceed
                set_error(
                    f"Could not analyze your description. "
                    f"Check your GROQ_API_KEY and try again. Details: {e}"
                )
                st.rerun()

        # ── Step B: Get clarifying questions ─────────────────────────────
        with st.spinner("Identifying what information we still need..."):
            try:
                questions = get_clarifying_questions(st.session_state.description)
                st.session_state.questions = questions
            except Exception as e:
                # Show error — user needs to know clarification failed
                set_error(
                    f"Could not generate clarifying questions. "
                    f"Check your GROQ_API_KEY and try again. Details: {e}"
                )
                st.rerun()

        # ── Step C: Route based on questions ─────────────────────────────
        if not st.session_state.questions:
            # Description is comprehensive — skip clarification, go straight to report
            with st.spinner("Your description is detailed — building threat model..."):
                try:
                    report = run(st.session_state.description)
                    report = enrich_report_with_narratives(report)
                    st.session_state.report = report
                    st.session_state.step = 3
                except Exception as e:
                    set_error(f"Failed to generate threat model: {e}")
                    st.rerun()
        else:
            # Questions ready — go to Step 2
            st.session_state.step = 2

        st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# STEP 2 — Clarifying questions
# ════════════════════════════════════════════════════════════════════════════
elif st.session_state.step == 2:
    st.markdown("### A few quick questions")
    st.markdown(
        "We need a bit more information for an accurate threat model. "
        "If you're unsure about something, just say **'not sure'** — "
        "we'll make a reasonable assumption and flag it in the report."
    )

    with st.form("clarification_form"):
        answers = {}
        for q in st.session_state.questions:
            st.markdown(f"**{q['question']}**")
            st.caption(f"*Why we're asking: {q['why_asking']}*")
            answer = st.text_input(
                "Answer",
                key=q["id"],
                placeholder="Your answer, or 'not sure'",
                label_visibility="collapsed",
            )
            answers[q["question"]] = answer
            st.markdown("")

        submitted = st.form_submit_button(
            "Generate Threat Model →", type="primary"
        )

    if submitted:
        filled = {q: a for q, a in answers.items() if a.strip()}
        enriched = build_enriched_description(st.session_state.description, filled)

        with st.spinner("Building your threat model — this takes about 30 seconds..."):
            try:
                report = run(enriched)
                report = enrich_report_with_narratives(report)
                st.session_state.report = report
                st.session_state.step = 3
                st.rerun()
            except Exception as e:
                set_error(f"Failed to generate threat model: {e}")
                st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# STEP 3 — Threat Report
# ════════════════════════════════════════════════════════════════════════════
elif st.session_state.step == 3 and st.session_state.report:
    report = st.session_state.report
    s = report.system

    # ── PDF Export ────────────────────────────────────────────────────────
    col_head, col_pdf = st.columns([4, 1])
    with col_pdf:
        try:
            pdf_bytes = generate_pdf(report)
            st.download_button(
                label="⬇ Download PDF",
                data=pdf_bytes,
                file_name=f"threatlens_{s.project_name.replace(' ', '_').lower()}.pdf",
                mime="application/pdf",
                type="primary",
                use_container_width=True,
            )
        except Exception as e:
            st.warning(f"PDF export unavailable: {e}")

    # ── Assumptions banner ────────────────────────────────────────────────
    if s.assumptions:
        with st.expander(
            f"⚠️ {len(s.assumptions)} assumption(s) made — review these",
            expanded=True
        ):
            st.markdown(
                "The following assumptions were made where information was unclear. "
                "Review these — they affect which threats were identified."
            )
            for a in s.assumptions:
                st.markdown(f"- _{a}_")

    # ── Risk banner ───────────────────────────────────────────────────────
    risk_color = SEVERITY_COLOR.get(report.risk_rating, "#888")
    risk_bg = SEVERITY_BG.get(report.risk_rating, "#111")
    st.markdown(f"""
    <div style="background:{risk_bg}; border-left:5px solid {risk_color};
                padding:16px 20px; border-radius:6px; margin-bottom:20px;">
        <h2 style="color:{risk_color}; margin:0 0 4px 0;">
            Overall Risk: {report.risk_rating}
        </h2>
        <p style="color:#ddd; margin:0; font-size:0.95em;">
            <strong>{s.project_name}</strong> &nbsp;·&nbsp;
            {s.domain.upper()} &nbsp;·&nbsp; {s.summary}
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ── Metrics ───────────────────────────────────────────────────────────
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Threats Found", report.total_threats)
    m2.metric("🔴 Critical", report.critical_count)
    m3.metric("🟠 High", report.high_count)
    m4.metric("🟡 Medium", report.medium_count)
    m5.metric("🟢 Low", report.low_count)

    st.divider()

    # ── System profile ────────────────────────────────────────────────────
    with st.expander("📋 System Profile", expanded=False):
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("**AI Model**")
            st.write(f"Model: `{s.llm_model}`")
            st.write(f"Provider: `{s.llm_provider}`")
            st.write(f"Hosting: `{s.llm_hosting}`")
            st.write(f"Fine-tuned: `{s.fine_tuned}`")
            st.write(f"RAG: `{s.has_rag}`")
        with c2:
            st.markdown("**Data Handled**")
            st.write(f"PII: `{s.handles_pii}`")
            st.write(f"Financial: `{s.handles_financial_data}`")
            st.write(f"KYC: `{s.handles_kyc_data}`")
            st.write(f"Aadhaar/PAN: `{s.handles_aadhaar_or_pan}`")
            st.write(f"Conversation stored: `{s.conversation_history_stored}`")
        with c3:
            st.markdown("**Agentic Actions**")
            st.write(f"Transactions: `{s.can_initiate_transactions}`")
            st.write(f"Freeze accounts: `{s.can_freeze_accounts}`")
            st.write(f"Approve decisions: `{s.can_approve_decisions}`")
            st.write(f"Human-in-loop: `{s.human_in_the_loop}`")
            st.write(f"Confirmation required: `{s.human_confirmation_required}`")

    # ── Threat cards ──────────────────────────────────────────────────────
    st.markdown("### 🚨 Identified Threats")

    for threat in report.threats:
        color = SEVERITY_COLOR.get(threat.severity, "#888")
        with st.expander(
            f"[{threat.severity}]  {threat.threat_id}: {threat.threat_name}",
            expanded=threat.severity in ("CRITICAL", "HIGH"),
        ):
            st.markdown(
                f'<span style="background:{color}22; color:{color}; '
                f'padding:3px 10px; border-radius:4px; font-weight:bold; font-size:0.85em;">'
                f'{threat.severity}</span> &nbsp; '
                f'<a href="{threat.owasp_reference}" target="_blank" '
                f'style="color:#888; font-size:0.82em;">OWASP Reference ↗</a>',
                unsafe_allow_html=True,
            )
            st.markdown("")

            if threat.narrative:
                sections = _parse_narrative_sections(threat.narrative)
                section_map = [
                    ("Threat Narrative",        "📖 Threat Narrative"),
                    ("How It Can Be Exploited", "⚔️ How It Can Be Exploited"),
                    ("Safeguards",              "🛡️ Safeguards"),
                    ("Dev Team Checklist",      "✅ Dev Team Checklist"),
                ]
                for key, label in section_map:
                    content = sections.get(key, "").strip()
                    if not content:
                        continue
                    st.markdown(f"#### {label}")
                    if key == "Dev Team Checklist":
                        for line in content.split("\n"):
                            item = line.strip().lstrip("-*•[ ]").strip()
                            if item:
                                st.checkbox(
                                    item, value=False,
                                    key=f"{threat.threat_id}_{item[:40]}"
                                )
                    else:
                        st.markdown(content)
            else:
                st.markdown("**Evidence:**")
                for e in threat.evidence:
                    st.markdown(f"- {e}")
                st.markdown("**Mitigations:**")
                for m in threat.mitigations:
                    st.markdown(f"- {m}")

    # ── Not applicable ────────────────────────────────────────────────────
    if report.not_applicable:
        with st.expander(
            f"✅ {len(report.not_applicable)} threats not applicable to this system"
        ):
            for t in report.not_applicable:
                st.markdown(f"- **{t.threat_id}** — {t.threat_name}")

    # ── GRC Checklist ─────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 📋 GRC & Governance Checklist")
    st.markdown("Actions for your security and compliance team:")

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
            "Confirm incident response runbook covers AI-specific failure modes",
        ]
    if s.has_agentic_actions:
        grc_items += [
            "Define maximum impact boundaries for all AI-triggered actions",
            "Test human-in-the-loop controls as part of UAT",
        ]
    for item in grc_items:
        st.checkbox(item, value=False, key=f"grc_{item[:50]}")


# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
st.markdown(
    "<div style='text-align:center; color:#888; font-size:0.82em; padding:8px;'>"
    "Made by <strong>NotYourCISO</strong> with ❤️ &nbsp;·&nbsp; "
    "ThreatLens for AI Products &nbsp;·&nbsp; OWASP LLM Top 10 (2025)"
    "</div>",
    unsafe_allow_html=True,
)


