# ThreatCompass AI 🔍

**AI threat modeling for AI systems — mapped to OWASP LLM Top 10**

Describe any AI-powered application in plain English. Get a structured threat model identifying which OWASP LLM Top 10 risks apply to your specific architecture — with evidence, mitigations, and actionable checklists for developers and GRC teams.

---

## What It Does

- **Understands your system** from a plain-text description
- **Evaluates all 10 OWASP LLM threats** deterministically against your architecture
- **Generates system-specific narratives** — not generic descriptions
- **Produces dev and GRC checklists** tailored to your risk profile
- **Flags BFSI-specific risks** — RBI, data residency, agentic financial actions

## Why It's Different

Most threat modeling tools were built for traditional software. They have no concept of prompt injection, excessive agency, training data poisoning, or supply chain risks specific to LLM systems. ThreatCompass AI was built specifically for systems that use AI as a component or as the core product.

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/rishipalyadav/threatcompass
cd threatcompass
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Set your API key

```bash
cp .env.example .env
# Edit .env and add your LLM Provider API key
```

### 3. Run the UI

```bash
streamlit run ui/app.py
```

### 4. Or run from command line

```bash
python engine/runner.py tests/test_descriptions/01_bank_chatbot.txt
```

---

## Architecture

```
Description (plain text)
        ↓
LLM Extraction          — Structured system profile (one LLM call)
        ↓
OWASP Rule Engine       — 10 deterministic evaluators (deterministic code)
        ↓
Risk Scoring            — Severity with BFSI context modifiers
        ↓
Narrative Generator     — System-specific explanations (one LLM call per threat)
        ↓
Report + Checklists     — Dev actions + GRC actions
```

**Two LLM calls total per analysis.** Everything in between is deterministic Python.

---

## Test Descriptions

Four BFSI scenarios included in `tests/test_descriptions/`:

1. `01_bank_chatbot.txt` — Customer support chatbot with refund capability
2. `02_loan_underwriting.txt` — AI loan assistant with RAG over lending policies
3. `03_kyc_verification.txt` — GPT-4 Vision KYC with third-party face matching
4. `04_fraud_copilot.txt` — Fraud analyst copilot with account freeze capability

---

## OWASP LLM Top 10 Coverage

| ID | Threat | Implemented |
|---|---|---|
| LLM01 | Prompt Injection | ✅ |
| LLM02 | Insecure Output Handling | ✅ |
| LLM03 | Training Data Poisoning | ✅ |
| LLM04 | Model Denial of Service | ✅ |
| LLM05 | Supply Chain Vulnerabilities | ✅ |
| LLM06 | Sensitive Information Disclosure | ✅ |
| LLM07 | Insecure Plugin Design | ✅ |
| LLM08 | Excessive Agency | ✅ |
| LLM09 | Overreliance | ✅ |
| LLM10 | Model Theft | ✅ |

---

## Stack

- Python 3.11
- OpenAI SDK 
- Streamlit
- python-dotenv

---

## Author

Rishipal Yadav | CISSP | [@NotYourCISO](https://notyourciso.medium.com) | [linkedin.com/in/rishipalyadav](https://linkedin.com/in/rishipalyadav)
