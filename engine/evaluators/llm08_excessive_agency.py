"""
LLM08: Excessive Agency

The most dangerous threat in BFSI AI systems.
When an LLM can take real-world actions — transactions, account changes,
approvals — without adequate human oversight, a single manipulation or
hallucination can have direct financial and regulatory consequences.

This is the evaluator that makes your tool genuinely valuable in BFSI context.
"""

from .base import BaseEvaluator
from typing import List


class LLM08_ExcessiveAgency(BaseEvaluator):
    threat_id = "LLM08"
    threat_name = "Excessive Agency"
    owasp_reference = "https://genai.owasp.org/llmrisk/llm08-excessive-agency/"

    def fires(self, system) -> bool:
        return system.has_agentic_actions or system.calls_internal_apis

    def get_severity(self, system) -> str:
        # Financial transactions without human confirmation = always CRITICAL
        if system.can_initiate_transactions and not system.human_confirmation_required:
            return "CRITICAL"
        # Account freezing = CRITICAL (irreversible customer impact)
        if system.can_freeze_accounts and not system.human_in_the_loop:
            return "CRITICAL"
        # Approval decisions at scale without oversight
        if system.can_approve_decisions and not system.human_in_the_loop:
            return "CRITICAL"
        # Has actions but with human controls
        if system.has_agentic_actions and system.human_in_the_loop:
            return "HIGH"
        # Calls internal APIs even without explicit actions
        if system.calls_internal_apis:
            return "MEDIUM"
        return "MEDIUM"

    def get_evidence(self, system) -> List[str]:
        evidence = []

        if system.can_initiate_transactions:
            conf = "with customer confirmation mentioned" if system.human_confirmation_required else "WITHOUT explicit confirmation gate mentioned"
            evidence.append(
                f"System can initiate financial transactions — {conf}. "
                f"LLM-triggered transactions without a non-LLM authorization check "
                f"are a direct financial fraud risk."
            )

        if system.can_freeze_accounts:
            hitl = "human analyst makes final decision" if system.human_in_the_loop else "no human-in-the-loop mentioned"
            evidence.append(
                f"System can freeze or block customer accounts — {hitl}. "
                f"Incorrectly frozen accounts create immediate customer harm "
                f"and potential regulatory complaints."
            )

        if system.can_approve_decisions:
            evidence.append(
                "System can approve or reject decisions (loans, KYC, onboarding) — "
                "AI-driven approvals at scale without oversight risk systematic errors "
                "affecting large customer cohorts."
            )

        if system.can_modify_records:
            evidence.append(
                "System can modify customer or transaction records — "
                "unauthorized modification is a data integrity risk with "
                "audit trail and regulatory implications."
            )

        if system.calls_internal_apis:
            apis = ", ".join(system.internal_apis) if system.internal_apis else "internal systems"
            evidence.append(
                f"LLM has direct access to internal APIs ({apis}) — "
                f"scope of API access granted to LLM may exceed what is needed "
                f"for any single user interaction."
            )

        if not system.actions_are_reversible and system.has_agentic_actions:
            evidence.append(
                "No mention of reversibility controls — "
                "AI-triggered actions that cannot be undone compound the risk "
                "of any manipulation or hallucination."
            )

        return evidence

    def get_mitigations(self, system) -> List[str]:
        mitigations = []

        mitigations.append(
            "Apply principle of least privilege to all LLM tool/API access — "
            "LLM should only have access to exactly what it needs for the current task, "
            "not a broad set of capabilities"
        )

        if system.can_initiate_transactions:
            mitigations.append(
                "Implement a non-LLM transaction authorization layer — "
                "the decision to execute a transaction must be validated by deterministic "
                "code with explicit user consent, never delegated to LLM judgment alone"
            )

        if system.can_freeze_accounts:
            mitigations.append(
                "Account freeze actions must require human analyst confirmation — "
                "LLM recommendation only, human executes. "
                "Log all freeze recommendations with reasoning for audit trail."
            )

        if system.can_approve_decisions:
            mitigations.append(
                "AI approval recommendations must be reviewed by a qualified human "
                "before execution, especially for credit, KYC, or onboarding decisions "
                "that have regulatory implications"
            )

        mitigations.append(
            "Implement audit logging for every action the LLM triggers or recommends — "
            "capture: user, session, LLM input, LLM output, action taken, timestamp. "
            "Required for RBI incident response and forensic investigation."
        )

        mitigations.append(
            "Define and enforce maximum impact boundaries — "
            "e.g. refund limit per session, freeze only flagged accounts, "
            "approve only within defined risk parameters"
        )

        if not system.actions_are_reversible:
            mitigations.append(
                "Design all AI-triggered actions to be reversible where possible — "
                "soft deletes, staging queues, approval workflows before permanent changes"
            )

        return mitigations
