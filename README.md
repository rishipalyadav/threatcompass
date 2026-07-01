# ThreatCompass 🔍

**Threat modeling built specifically for AI-enabled products — mapped to OWASP LLM Top 10**

Describe your AI-powered application in plain English. Answer a few clarifying questions. Get a structured threat model — with confidence-scored findings, system-specific narratives, and exportable checklists for developers and GRC teams.

---

## Why This Exists

Most threat modeling tools were built for traditional software. They have no concept of prompt injection, excessive agency, or training data poisoning. ThreatCompass was built specifically for products that use AI — whether AI is the entire product or just one component of it.

It also solves a problem most AI security advice ignores: **most teams call an external AI API, they don't train their own model.** Generic advice like "secure your training pipeline" is useless if you're calling GPT-4 or Llama via an API. ThreatCompass detects whether you're a **model operator** (you call external AI APIs) or a **model builder** (you train/fine-tune your own models) and tailors every recommendation accordingly.

---

## What It Does

- **Detects if your system actually has AI components** — gracefully declines to analyze non-AI systems
- **Asks targeted clarifying questions** — only for what's missing from your description, max 5, single round
- **Evaluates all 10 OWASP LLM threats** deterministically against your specific architecture
- **Shows confidence per threat** — "4 of 5 signals detected" instead of a black-box severity label
- **Exposes the evidence behind every threat** — see exactly why each threat fired
- **Tailors advice to operator vs builder** — API guardrails vs model-level controls
- **Generates structured 4-part narratives** — Threat Narrative, How It Can Be Exploited, Safeguards, Dev Checklist
- **Lets you override severity** — your judgment matters; overrides require a documented reason
- **Exports to PDF and Markdown** — ready for a client deliverable or a GitHub wiki page
- **Flags BFSI-specific risk** — RBI guidance, data residency, agentic financial actions

---

## How It Works

```
User describes their AI system (plain text)
                ↓
   AI Component Detection (LLM)
   — confirms the system actually uses AI before proceeding
                ↓
   Clarifying Questions (LLM, single round)
   — identifies what's missing: data types, hosting, agentic actions, etc.
   — "I don't know" answers become flagged assumptions
                ↓
   Structured Extraction (LLM)
   — combines description + answers into a typed system profile
                ↓
   OWASP Rule Engine (deterministic Python — no LLM)
   — 10 evaluators, each checking specific architectural signals
   — confidence score = signals detected / signals possible
                ↓
   Risk Scoring (deterministic)
   — severity with BFSI and agentic-action context modifiers
                ↓
   Narrative Generation (LLM, one call per fired threat)
   — operator vs builder aware
   — structured into 4 sections, grounded in deterministic evidence
                ↓
   Report
   — Streamlit UI, PDF export, Markdown export
   — severity overrides, GRC checklist, dev checklist
```

**Three LLM calls for detection/clarification/extraction, plus one LLM call per fired threat for narrative generation. Everything else — the actual threat evaluation logic — is deterministic Python you can read, test, and trust.**

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/yourusername/threatcompass
cd threatcompass
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Set your API key

This project uses [Groq](https://console.groq.com) — free tier, fast inference.

```bash
cp .env.example .env
```

Edit `.env`:
```
LLM_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=your model (I used qwen)
```
Sometimes, when genAI does not generate proper response in the requested format, the tool throws an error. There is nothing wrong. This is non-determinstic nature of GenAI. Just try again. 

### 3. Run the app

```bash
streamlit run ui/app.py
```

### 4. Or run from command line (skips clarification step)

```bash
python engine/runner.py tests/test_descriptions/01_bank_chatbot.txt
```

---

## Test Scenarios

BFSI-focused scenarios included in `tests/test_descriptions/`:

1. `01_bank_chatbot.txt` — Customer support chatbot with refund capability
2. `02_loan_underwriting.txt` — AI loan assistant with RAG over lending policies
3. `03_kyc_verification.txt` — GPT-4 Vision KYC with third-party face matching
4. `04_fraud_copilot.txt` — Fraud analyst copilot with account freeze capability
5. `05_autonomous_trading_agent.txt` — Autonomous Trading Agent for trading 
6. `06_internal_banking_knowledge_assistant.txt` — Internal Tool for browsing company documents

*(Add your own under `tests/test_descriptions/` and register them in `SAMPLES` in `ui/app.py` to show up as one-click samples in the UI.)*

---

## OWASP LLM Top 10 Coverage

| ID | Threat | Operator-aware advice | Builder-aware advice |
|---|---|---|---|
| LLM01 | Prompt Injection | ✅ | ✅ |
| LLM02 | Insecure Output Handling | ✅ | ✅ |
| LLM03 | Training Data Poisoning | ✅ Monitor provider | ✅ Pipeline integrity |
| LLM04 | Model Denial of Service | ✅ Rate limit your API | ✅ Model-level controls |
| LLM05 | Supply Chain Vulnerabilities | ✅ TPRM + API hardening | ✅ Dependency auditing |
| LLM06 | Sensitive Information Disclosure | ✅ | ✅ |
| LLM07 | Insecure Plugin Design | ✅ | ✅ |
| LLM08 | Excessive Agency | ✅ | ✅ |
| LLM09 | Overreliance | ✅ | ✅ |
| LLM10 | Model Theft | ✅ Protect your prompts/IP | ✅ Protect model weights |

---

## Disclaimer

ThreatCompass is an experimental tool intended to support, not replace, professional threat modeling and security assessment practices. Outputs are generated using large language models and deterministic heuristics, and should be independently reviewed and validated by qualified security or compliance professionals before being used to inform risk decisions, remediation efforts, or audit evidence.

---

## Stack

- Python 3.11
- Groq API via OpenAI-compatible SDK
- Streamlit
- ReportLab (PDF generation)
- python-dotenv

---

## Author

Made by **NotYourCISO** with ❤️

Rishipal Yadav | CISSP | [@NotYourCISO](https://notyourciso.medium.com) | [linkedin.com/in/rishipalyadav](https://linkedin.com/in/rishipalyadav)
