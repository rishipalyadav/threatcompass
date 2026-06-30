"""
LLM01: Prompt Injection

The most critical threat for any system that accepts user input and passes
it to an LLM. In BFSI systems with agentic capabilities, this is almost
always CRITICAL — a successful injection can trigger real financial actions.

Two attack vectors:
  Direct:   User types malicious instructions directly
  Indirect: Malicious content retrieved into context via RAG or APIs
"""

from .base import BaseEvaluator
from typing import List


class LLM01_PromptInjection(BaseEvaluator):
    threat_id = "LLM01"
    threat_name = "Prompt Injection"
    owasp_reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"

    def fires(self, system) -> bool:
        # Fires if system accepts any user-controlled input OR
        # retrieves external content into LLM context (indirect injection)
        return system.accepts_user_input or system.has_rag or system.calls_internal_apis

    def get_severity(self, system) -> str:
        # Agentic + user input = worst case scenario
        if system.has_agentic_actions and system.accepts_user_input:
            return "CRITICAL"
        # BFSI domain with user input = CRITICAL
        if system.is_bfsi and system.accepts_user_input:
            return "CRITICAL"
        # RAG creates indirect injection surface
        if system.has_rag:
            return "HIGH"
        return "HIGH"

    def get_evidence(self, system) -> List[str]:
        evidence = []

        if system.accepts_user_input and system.customer_facing:
            evidence.append(
                f"System accepts free-form input from end customers — "
                f"malicious instructions can be embedded in chat messages"
            )

        if system.accepts_user_input and system.employee_facing:
            evidence.append(
                "Internal employees provide natural language queries — "
                "insider threat vector for prompt injection"
            )

        if system.has_rag:
            sources = ", ".join(system.rag_data_sources) if system.rag_data_sources else "unspecified data sources"
            evidence.append(
                f"RAG pipeline retrieves content from {sources} into LLM context — "
                f"indirect prompt injection possible if retrieved content is attacker-controlled"
            )

        if system.calls_internal_apis:
            apis = ", ".join(system.internal_apis) if system.internal_apis else "internal systems"
            evidence.append(
                f"LLM retrieves data from {apis} — API responses injected into context "
                f"could carry malicious instructions"
            )

        if system.has_agentic_actions:
            actions = []
            if system.can_initiate_transactions:
                actions.append("initiate financial transactions")
            if system.can_freeze_accounts:
                actions.append("freeze customer accounts")
            if system.can_approve_decisions:
                actions.append("approve/reject decisions")
            if system.can_modify_records:
                actions.append("modify records")
            if actions:
                evidence.append(
                    f"Successful injection could trigger real-world actions: "
                    f"{', '.join(actions)} — making this a CRITICAL business risk"
                )

        return evidence

    def get_signal_count(self) -> int:
        return 5  # customer input, employee input, RAG, internal APIs, agentic actions

    def get_mitigations(self, system) -> List[str]:
        mitigations = []

        mitigations.append(
            "Implement strict input validation — reject or sanitize inputs "
            "containing instruction-like patterns before passing to LLM"
        )
        mitigations.append(
            "Separate system prompt from user input using structural boundaries "
            "(e.g. XML tags, distinct message roles) — never concatenate them as plain strings"
        )

        if system.has_rag:
            mitigations.append(
                "Treat all RAG-retrieved content as untrusted — "
                "apply content filtering before injecting into LLM context"
            )

        if system.has_agentic_actions:
            mitigations.append(
                "Implement a separate, non-LLM authorization layer for all actions — "
                "never rely on the LLM itself to enforce action restrictions"
            )
            if not system.human_confirmation_required:
                mitigations.append(
                    "CRITICAL: Add human-in-the-loop confirmation before any "
                    "irreversible action (transactions, account changes, approvals)"
                )

        if system.is_bfsi:
            mitigations.append(
                "Log all LLM inputs and outputs with customer ID and session context "
                "for forensic investigation — required for RBI incident response"
            )

        return mitigations
