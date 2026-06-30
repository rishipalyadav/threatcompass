"""
LLM06: Sensitive Information Disclosure

In BFSI systems, LLMs handling customer PII, financial data, KYC documents,
or credit information can inadvertently expose this data through:
- Responses that include more data than requested
- Cross-user data leakage in multi-tenant systems
- System prompt extraction revealing internal policies
- Conversation history leakage
- Training data memorization
"""

from .base import BaseEvaluator
from typing import List


class LLM06_SensitiveDisclosure(BaseEvaluator):
    threat_id = "LLM06"
    threat_name = "Sensitive Information Disclosure"
    owasp_reference = "https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/"

    def fires(self, system) -> bool:
        return system.handles_sensitive_data or system.conversation_history_stored

    def get_severity(self, system) -> str:
        if system.handles_aadhaar_or_pan:
            return "CRITICAL"
        if system.handles_financial_data and system.customer_facing:
            return "CRITICAL"
        if system.handles_credit_data:
            return "HIGH"
        if system.handles_kyc_data:
            return "HIGH"
        if system.conversation_history_stored:
            return "HIGH"
        return "MEDIUM"

    def get_evidence(self, system) -> List[str]:
        evidence = []

        if system.handles_aadhaar_or_pan:
            evidence.append(
                "System processes Aadhaar and/or PAN data — "
                "these are regulated identifiers under UIDAI and Income Tax Act. "
                "Any inadvertent disclosure in LLM responses triggers legal liability."
            )

        if system.handles_financial_data and system.customer_facing:
            evidence.append(
                "LLM has access to customer financial data and is customer-facing — "
                "risk of LLM surfacing other customers' data or revealing more "
                "account detail than the request warrants."
            )

        if system.handles_credit_data:
            evidence.append(
                "Credit bureau data is in LLM context — "
                "credit scores and bureau reports are sensitive financial data "
                "with strict handling requirements under RBI guidelines."
            )

        if system.conversation_history_stored:
            evidence.append(
                "Conversation history is stored — "
                "chat logs containing financial queries, account details, or "
                "personal information become a high-value breach target. "
                "Cross-session leakage is possible if history is injected into context."
            )

        if system.data_sent_to_external_provider:
            evidence.append(
                "Sensitive data is transmitted to an external LLM provider — "
                "data leaves your control boundary. Provider's data retention, "
                "training practices, and breach notification obligations must be assessed."
            )

        if system.multi_tenant:
            evidence.append(
                "Multi-tenant system — risk of cross-tenant data leakage "
                "if customer context is not strictly isolated between sessions."
            )

        if system.has_rag and system.handles_sensitive_data:
            evidence.append(
                "RAG retrieves sensitive customer data into LLM context — "
                "LLM may include retrieved data verbatim in responses, "
                "potentially exposing data beyond what the query requires."
            )

        return evidence

    def get_signal_count(self) -> int:
        return 7  # aadhaar/pan, financial+customer, credit, conv history, external provider, multi-tenant, rag+sensitive

    def get_mitigations(self, system) -> List[str]:
        mitigations = []

        mitigations.append(
            "Implement output filtering — scan LLM responses for sensitive patterns "
            "(PAN format, Aadhaar format, account numbers) before returning to user. "
            "Mask or redact automatically."
        )

        if system.has_rag:
            mitigations.append(
                "Apply need-to-know filtering in RAG retrieval — "
                "only retrieve records the authenticated user is authorized to see. "
                "Do not retrieve full customer profiles when a specific field is queried."
            )

        if system.conversation_history_stored:
            mitigations.append(
                "Encrypt conversation history at rest with customer-specific keys. "
                "Define and enforce retention limits — do not retain beyond operational need. "
                "Ensure conversation history is never injected into other customers' contexts."
            )

        if system.data_sent_to_external_provider:
            provider = system.llm_provider if system.llm_provider != "unspecified" else "LLM provider"
            mitigations.append(
                f"Conduct third-party risk assessment for {provider} — "
                f"review data processing agreement, confirm no training on customer data, "
                f"verify data residency meets RBI requirements for Indian customer data."
            )

        if system.handles_aadhaar_or_pan:
            mitigations.append(
                "Tokenize or mask Aadhaar and PAN before passing to LLM — "
                "pass only what is necessary for the task. "
                "Raw Aadhaar numbers should never appear in LLM prompts or responses."
            )

        mitigations.append(
            "Implement system prompt confidentiality — "
            "test that the LLM cannot be manipulated into revealing its system prompt, "
            "which may contain internal policies, API schemas, or business logic."
        )

        return mitigations
