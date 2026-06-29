"""
engine/extractor.py

Takes the enriched description (original + clarification answers) and
extracts a structured ExtractedSystem object.

When user answered "I don't know" or "not sure", the LLM makes reasonable
assumptions and flags them in the assumptions list.
"""

import json
import os
from dataclasses import dataclass, field
from typing import List
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

EXTRACTION_PROMPT = """
You are a security architect extracting structured information from an AI system description.
Some answers may say "I don't know" or "not sure" — for those, use your judgment to make 
the most reasonable assumption given the context, and add it to the assumptions list.

Return ONLY valid JSON matching this exact schema. No markdown, no explanation.

{
  "project_name": "short descriptive name (3-5 words)",
  "summary": "one sentence describing what this system does",
  "domain": "one of: banking | fintech | insurance | healthcare | ecommerce | hr | legal | general",

  "assumptions": [
    "List any assumptions made where user said they did not know. Format: 'Assumed X because Y'"
  ],

  "llm_details": {
    "model": "model name if mentioned, else 'unspecified'",
    "provider": "one of: openai | azure_openai | google | anthropic | aws_bedrock | huggingface | self_hosted | unspecified",
    "hosting": "one of: cloud_external | cloud_internal | self_hosted | unspecified",
    "fine_tuned": true or false,
    "trains_on_user_data": true or false
  },

  "data_handled": {
    "pii": true or false,
    "financial_data": true or false,
    "kyc_data": true or false,
    "aadhaar_or_pan": true or false,
    "credit_data": true or false,
    "transaction_data": true or false,
    "health_data": true or false,
    "conversation_history_stored": true or false,
    "data_sent_to_external_provider": true or false
  },

  "architecture": {
    "accepts_user_input": true or false,
    "customer_facing": true or false,
    "employee_facing": true or false,
    "has_rag": true or false,
    "rag_data_sources": [],
    "calls_internal_apis": true or false,
    "internal_apis": [],
    "uses_third_party_apis": true or false,
    "third_party_apis": [],
    "has_plugins_or_tools": true or false,
    "multi_tenant": true or false
  },

  "agentic_capabilities": {
    "can_initiate_transactions": true or false,
    "can_modify_records": true or false,
    "can_freeze_or_block_accounts": true or false,
    "can_approve_or_reject_decisions": true or false,
    "can_send_communications": true or false,
    "other_actions": [],
    "human_confirmation_required": true or false,
    "human_in_the_loop": true or false,
    "actions_are_reversible": true or false
  },

  "users": {
    "end_customers": true or false,
    "internal_employees": true or false,
    "admins_or_analysts": true or false,
    "authentication_mentioned": true or false
  },

  "user_type": "one of: model_operator | model_builder | hybrid",
  "user_type_reasoning": "one sentence explaining why",
  "compliance_hints": []
}

Classification guidance:
- model_operator: uses external AI APIs (OpenAI, Groq, Gemini, Anthropic, Azure OpenAI etc.) 
  and does NOT train or fine-tune their own model
- model_builder: trains, fine-tunes, or hosts their own model
- hybrid: uses external APIs but also fine-tunes or trains custom models on top

When in doubt, default to model_operator — it is the more common case.

System description:
{description}
"""


@dataclass
class ExtractedSystem:
    project_name: str
    summary: str
    domain: str
    assumptions: List[str] = field(default_factory=list)

    # LLM details
    llm_model: str = "unspecified"
    llm_provider: str = "unspecified"
    llm_hosting: str = "unspecified"
    fine_tuned: bool = False
    trains_on_user_data: bool = False

    # Data
    handles_pii: bool = False
    handles_financial_data: bool = False
    handles_kyc_data: bool = False
    handles_aadhaar_or_pan: bool = False
    handles_credit_data: bool = False
    handles_transaction_data: bool = False
    conversation_history_stored: bool = False
    data_sent_to_external_provider: bool = False

    # Architecture
    accepts_user_input: bool = False
    customer_facing: bool = False
    employee_facing: bool = False
    has_rag: bool = False
    rag_data_sources: List[str] = field(default_factory=list)
    calls_internal_apis: bool = False
    internal_apis: List[str] = field(default_factory=list)
    uses_third_party_apis: bool = False
    third_party_apis: List[str] = field(default_factory=list)
    has_plugins_or_tools: bool = False
    multi_tenant: bool = False

    # Agentic
    can_initiate_transactions: bool = False
    can_modify_records: bool = False
    can_freeze_accounts: bool = False
    can_approve_decisions: bool = False
    can_send_communications: bool = False
    other_actions: List[str] = field(default_factory=list)
    human_confirmation_required: bool = False
    human_in_the_loop: bool = False
    actions_are_reversible: bool = False

    # Users
    end_customers: bool = False
    internal_employees: bool = False
    admins_or_analysts: bool = False
    authentication_mentioned: bool = False
    user_type: str = "model_operator"  # model_operator | model_builder | hybrid
    user_type_reasoning: str = ""
    compliance_hints: List[str] = field(default_factory=list)

    @property
    def is_bfsi(self) -> bool:
        return self.domain in ("banking", "fintech", "insurance")

    @property
    def has_agentic_actions(self) -> bool:
        return any([
            self.can_initiate_transactions,
            self.can_modify_records,
            self.can_freeze_accounts,
            self.can_approve_decisions,
            self.can_send_communications,
            bool(self.other_actions),
        ])

    @property
    def handles_sensitive_data(self) -> bool:
        return any([
            self.handles_pii,
            self.handles_financial_data,
            self.handles_kyc_data,
            self.handles_aadhaar_or_pan,
            self.handles_credit_data,
            self.handles_transaction_data,
        ])


def _clean_json(raw: str) -> str:
    """Robustly strip markdown fences and leading preamble."""
    raw = raw.strip()
    if "```" in raw:
        parts = raw.split("```")
        raw = parts[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    if not raw.startswith("{"):
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1:
            raw = raw[start:end+1]
    return raw.strip()


def extract_system(enriched_description: str) -> ExtractedSystem:
    """
    Takes the enriched description (original + clarification answers).
    Returns a structured ExtractedSystem.
    """
    prompt = EXTRACTION_PROMPT.replace("{description}", enriched_description.strip())

    client = OpenAI(
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )
    response = client.chat.completions.create(
        model=os.getenv("GROQ_MODEL") or "qwen/qwen3-32b",
        max_tokens=1500,
        temperature=0,
        messages=[
            {
                "role": "system",
                "content": "You are a JSON extraction API. Return only valid JSON. No markdown, no preamble."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
    )

    raw = _clean_json(response.choices[0].message.content)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Extraction failed — invalid JSON:\n{e}\n\nRaw output:\n{raw}")

    llm = data.get("llm_details", {})
    dat = data.get("data_handled", {})
    arc = data.get("architecture", {})
    age = data.get("agentic_capabilities", {})
    usr = data.get("users", {})

    return ExtractedSystem(
        project_name=data.get("project_name", "Unnamed System"),
        summary=data.get("summary", ""),
        domain=data.get("domain", "general"),
        assumptions=data.get("assumptions", []),

        llm_model=llm.get("model", "unspecified"),
        llm_provider=llm.get("provider", "unspecified"),
        llm_hosting=llm.get("hosting", "unspecified"),
        fine_tuned=llm.get("fine_tuned", False),
        trains_on_user_data=llm.get("trains_on_user_data", False),

        handles_pii=dat.get("pii", False),
        handles_financial_data=dat.get("financial_data", False),
        handles_kyc_data=dat.get("kyc_data", False),
        handles_aadhaar_or_pan=dat.get("aadhaar_or_pan", False),
        handles_credit_data=dat.get("credit_data", False),
        handles_transaction_data=dat.get("transaction_data", False),
        conversation_history_stored=dat.get("conversation_history_stored", False),
        data_sent_to_external_provider=dat.get("data_sent_to_external_provider", False),

        accepts_user_input=arc.get("accepts_user_input", False),
        customer_facing=arc.get("customer_facing", False),
        employee_facing=arc.get("employee_facing", False),
        has_rag=arc.get("has_rag", False),
        rag_data_sources=arc.get("rag_data_sources", []),
        calls_internal_apis=arc.get("calls_internal_apis", False),
        internal_apis=arc.get("internal_apis", []),
        uses_third_party_apis=arc.get("uses_third_party_apis", False),
        third_party_apis=arc.get("third_party_apis", []),
        has_plugins_or_tools=arc.get("has_plugins_or_tools", False),
        multi_tenant=arc.get("multi_tenant", False),

        can_initiate_transactions=age.get("can_initiate_transactions", False),
        can_modify_records=age.get("can_modify_records", False),
        can_freeze_accounts=age.get("can_freeze_or_block_accounts", False),
        can_approve_decisions=age.get("can_approve_or_reject_decisions", False),
        can_send_communications=age.get("can_send_communications", False),
        other_actions=age.get("other_actions", []),
        human_confirmation_required=age.get("human_confirmation_required", False),
        human_in_the_loop=age.get("human_in_the_loop", False),
        actions_are_reversible=age.get("actions_are_reversible", False),

        end_customers=usr.get("end_customers", False),
        internal_employees=usr.get("internal_employees", False),
        admins_or_analysts=usr.get("admins_or_analysts", False),
        authentication_mentioned=usr.get("authentication_mentioned", False),

        compliance_hints=data.get("compliance_hints", []),
        user_type=data.get("user_type", "model_operator"),
        user_type_reasoning=data.get("user_type_reasoning", ""),
    )
