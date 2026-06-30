"""
Evaluators for LLM02, LLM03, LLM04, LLM05, LLM07, LLM09, LLM10

Each follows the same BaseEvaluator contract.
These can be split into individual files as they grow.
"""

from .base import BaseEvaluator
from typing import List


class LLM02_InsecureOutput(BaseEvaluator):
    threat_id = "LLM02"
    threat_name = "Insecure Output Handling"
    owasp_reference = "https://genai.owasp.org/llmrisk/llm02-insecure-output-handling/"

    def fires(self, system) -> bool:
        return system.has_agentic_actions or system.calls_internal_apis

    def get_severity(self, system) -> str:
        if system.can_initiate_transactions or system.can_modify_records:
            return "HIGH"
        if system.is_bfsi:
            return "HIGH"
        return "MEDIUM"

    def get_evidence(self, system) -> List[str]:
        evidence = []
        if system.has_agentic_actions:
            evidence.append(
                "LLM output is used to trigger real-world actions — "
                "malformed or manipulated output could cause incorrect actions "
                "to be executed on downstream banking systems."
            )
        if system.calls_internal_apis:
            apis = ", ".join(system.internal_apis) if system.internal_apis else "internal APIs"
            evidence.append(
                f"LLM-generated parameters are passed to {apis} — "
                f"without output validation, injection attacks via LLM output are possible."
            )
        return evidence

    def get_signal_count(self) -> int:
        return 2  # transactions, freeze, approve, modify, internal apis

    def get_mitigations(self, system) -> List[str]:
        return [
            "Validate and sanitize all LLM outputs before passing to downstream systems — "
            "treat LLM output as untrusted input to your application layer.",
            "Use structured output formats (JSON schema validation) for any LLM output "
            "that triggers actions — never parse free-text output to drive business logic.",
            "Implement allowlists for valid action parameters — "
            "reject any LLM output that falls outside expected value ranges.",
        ]


class LLM03_TrainingDataPoisoning(BaseEvaluator):
    threat_id = "LLM03"
    threat_name = "Training Data Poisoning"
    owasp_reference = "https://genai.owasp.org/llmrisk/llm03-training-data-poisoning/"

    def fires(self, system) -> bool:
        return system.fine_tuned or system.trains_on_user_data

    def get_severity(self, system) -> str:
        if system.is_bfsi and system.fine_tuned:
            return "HIGH"
        if system.trains_on_user_data:
            return "HIGH"
        return "MEDIUM"

    def get_evidence(self, system) -> List[str]:
        evidence = []
        if system.fine_tuned:
            evidence.append(
                "Model is fine-tuned — integrity of fine-tuning dataset directly "
                "determines model behavior. Poisoned training data can introduce "
                "systematic biases or backdoors."
            )
        if system.trains_on_user_data:
            evidence.append(
                "Model trains on user-generated data — "
                "users can intentionally craft inputs to influence future model behavior."
            )
        return evidence

    def get_signal_count(self) -> int:
        return 2  # transactions, freeze, approve, modify, internal apis

    # def get_mitigations(self, system) -> List[str]:
    #     return [
    #         "Maintain provenance records for all training and fine-tuning data — "
    #         "know exactly where every training example came from.",
    #         "Implement anomaly detection on training datasets — "
    #         "flag outliers and unusual patterns before training runs.",
    #         "Conduct adversarial testing after every fine-tuning cycle — "
    #         "verify model behavior has not changed in unexpected ways.",
    #         "If using user-generated data for training, implement human review "
    #         "and filtering pipeline before data enters training sets.",
    #     ]
    def get_mitigations(self, system) -> List[str]:
        if self.is_operator(system):
            return [
                "Subscribe to your model provider's security advisories and release notes — "
                "treat model version changes like dependency upgrades requiring review.",
                "Review model cards and safety evaluations before upgrading to a new model version — "
                "check for known biases, failure modes, or behavior changes.",
                "Establish an internal policy requiring security review before deploying "
                "a new model version to production — don't auto-upgrade.",
                "Test model behavior against your critical use cases after every provider "
                "model update — regression test for safety, not just functionality.",
                "Document which model version is running in production and maintain "
                "a change log — required for incident investigation.",
            ]
        else:
            return [
                "Maintain provenance records for all training and fine-tuning data — "
                "know exactly where every training example came from.",
                "Implement anomaly detection on training datasets — "
                "flag outliers and unusual patterns before training runs.",
                "Conduct adversarial testing after every fine-tuning cycle — "
                "verify model behavior has not changed in unexpected ways.",
                "Implement human review and filtering pipeline before user-generated "
                "data enters training sets.",
                "Maintain a reproducible training pipeline with version-controlled datasets "
                "so poisoning incidents can be identified and rolled back.",
            ]


class LLM04_ModelDoS(BaseEvaluator):
    threat_id = "LLM04"
    threat_name = "Model Denial of Service"
    owasp_reference = "https://genai.owasp.org/llmrisk/llm04-model-denial-of-service/"

    def fires(self, system) -> bool:
        return system.accepts_user_input and system.customer_facing

    def get_severity(self, system) -> str:
        if system.is_bfsi and system.customer_facing:
            return "HIGH"
        return "MEDIUM"

    def get_evidence(self, system) -> List[str]:
        return [
            "System accepts free-form customer input with no mention of input length limits — "
            "adversarial inputs designed to maximize token consumption can inflate "
            "API costs and degrade response times for all users.",
            "Customer-facing banking system — availability degradation during peak periods "
            "(salary credits, payment deadlines) has direct customer and regulatory impact."
        ]

    def get_signal_count(self) -> int:
        return 2  # transactions, freeze, approve, modify, internal apis

    def get_mitigations(self, system) -> List[str]:
        return [
            "Enforce input length limits at the application layer — "
            "reject or truncate inputs exceeding a defined token threshold before LLM call.",
            "Implement per-user and per-session rate limiting on LLM API calls.",
            "Set max_tokens limits on all LLM API calls to bound cost and response time.",
            "Monitor token consumption per session — alert on anomalous usage patterns.",
        ]


class LLM05_SupplyChain(BaseEvaluator):
    threat_id = "LLM05"
    threat_name = "Supply Chain Vulnerabilities"
    owasp_reference = "https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/"

    def fires(self, system) -> bool:
        return (
            system.llm_provider not in ("self_hosted", "unspecified")
            or system.uses_third_party_apis
        )

    def get_severity(self, system) -> str:
        if system.data_sent_to_external_provider and system.is_bfsi:
            return "HIGH"
        if system.uses_third_party_apis and system.handles_sensitive_data:
            return "HIGH"
        return "MEDIUM"

    def get_evidence(self, system) -> List[str]:
        evidence = []
        if system.llm_provider not in ("self_hosted", "unspecified"):
            evidence.append(
                f"LLM hosted externally via {system.llm_provider} — "
                f"customer data in prompts leaves your organization's control boundary. "
                f"Provider outage, policy change, or security incident directly impacts your service."
            )
        if system.uses_third_party_apis:
            third_party = ", ".join(system.third_party_apis) if system.third_party_apis else "third-party services"
            evidence.append(
                f"Third-party APIs in use: {third_party} — "
                f"security posture, data handling practices, and availability of these "
                f"providers directly affect your system's security."
            )
        return evidence

    def get_signal_count(self) -> int:
        return 2  # transactions, freeze, approve, modify, internal apis

    # # def get_mitigations(self, system) -> List[str]:
    #     mitigations = [
    #         "Add LLM provider to your Third-Party Risk Management program — "
    #         "conduct security assessment, review DPA, confirm breach notification terms.",
    #         "Implement fallback handling for LLM provider outages — "
    #         "define graceful degradation behavior rather than hard failures.",
    #     ]
    #     if system.is_bfsi:
    #         mitigations.append(
    #             "Verify data residency compliance with RBI outsourcing guidelines — "
    #             "confirm customer financial data is not stored or processed outside "
    #             "permitted jurisdictions by the LLM provider."
    #         )
    #     # return mitigations
    def get_mitigations(self, system) -> List[str]:
        if self.is_operator(system):
            return [
                "Add your LLM provider to your Third-Party Risk Management program — "
                "assess their security posture, certifications, and breach history.",
                "Review the provider's data processing agreement — confirm they are not "
                "training on your prompts and responses, and understand their retention policy.",
                "Monitor provider status pages and security advisories — "
                "set up alerts for incidents that could affect your service.",
                "Review model changelogs before version upgrades — "
                "behavior changes in new model versions can introduce new risks.",
                "Implement fallback handling for provider outages — "
                "define what your system does when the AI API is unavailable.",
                "Strengthen your own API layer around the LLM — "
                "input validation, output filtering, rate limiting, and audit logging "
                "are entirely within your control regardless of provider.",
            ]
        else:
            return [
                "Audit all dependencies in your model training and serving stack — "
                "treat ML libraries (transformers, pytorch, etc.) like any software dependency.",
                "Use reproducible builds for model training pipelines — "
                "pin dependency versions and verify checksums.",
                "Verify integrity of pre-trained model weights before fine-tuning — "
                "download from official sources, verify hashes.",
                "Implement security scanning on any third-party model components "
                "integrated into your serving infrastructure.",
            ]


class LLM07_InsecurePlugin(BaseEvaluator):
    threat_id = "LLM07"
    threat_name = "Insecure Plugin Design"
    owasp_reference = "https://genai.owasp.org/llmrisk/llm07-insecure-plugin-design/"

    def fires(self, system) -> bool:
        return system.has_plugins_or_tools or system.calls_internal_apis

    def get_severity(self, system) -> str:
        if system.calls_internal_apis and system.is_bfsi:
            return "HIGH"
        if system.has_plugins_or_tools:
            return "HIGH"
        return "MEDIUM"

    def get_evidence(self, system) -> List[str]:
        evidence = []
        if system.calls_internal_apis:
            apis = ", ".join(system.internal_apis) if system.internal_apis else "internal banking APIs"
            evidence.append(
                f"LLM can call internal APIs ({apis}) — "
                f"if these APIs do not re-validate authorization at the API layer, "
                f"a prompt injection attack can use them to access unauthorized data."
            )
        if system.has_plugins_or_tools:
            evidence.append(
                "LLM has access to plugins or tools — "
                "each plugin is an attack surface. Insufficient input validation "
                "in plugins allows LLM-driven exploitation."
            )
        return evidence

    def get_signal_count(self) -> int:
        return 2  # transactions, freeze, approve, modify, internal apis

    def get_mitigations(self, system) -> List[str]:
        return [
            "Ensure every internal API validates authorization independently — "
            "do not rely on the LLM orchestration layer to enforce access control.",
            "Implement parameter validation in every plugin/tool — "
            "treat LLM-generated parameters as untrusted input.",
            "Scope API tokens used by LLM to minimum required permissions — "
            "separate service account with read-only access where possible.",
            "Log all plugin/tool invocations with full parameters for audit trail.",
        ]


class LLM09_Overreliance(BaseEvaluator):
    threat_id = "LLM09"
    threat_name = "Overreliance"
    owasp_reference = "https://genai.owasp.org/llmrisk/llm09-overreliance/"

    def fires(self, system) -> bool:
        return system.can_approve_decisions or (
            system.has_agentic_actions and not system.human_in_the_loop
        )

    def get_severity(self, system) -> str:
        if system.can_approve_decisions and not system.human_in_the_loop:
            return "HIGH"
        if system.is_bfsi and not system.human_in_the_loop:
            return "HIGH"
        return "MEDIUM"

    def get_evidence(self, system) -> List[str]:
        evidence = []
        if system.can_approve_decisions:
            hitl = "human reviews final decision" if system.human_in_the_loop else "no human review step mentioned"
            evidence.append(
                f"AI makes approval/rejection recommendations — {hitl}. "
                f"LLMs hallucinate and can make systematically wrong recommendations "
                f"that affect large numbers of customers if not reviewed."
            )
        if not system.human_in_the_loop and system.has_agentic_actions:
            evidence.append(
                "Agentic actions without human oversight mean LLM errors "
                "translate directly into real-world consequences at scale."
            )
        return evidence

    def get_signal_count(self) -> int:
        return 2  # transactions, freeze, approve, modify, internal apis

    def get_mitigations(self, system) -> List[str]:
        return [
            "Frame AI outputs explicitly as recommendations, not decisions — "
            "UI and workflow design should make human review the default path.",
            "Implement confidence scoring — flag low-confidence outputs for mandatory human review.",
            "Conduct regular audits of AI recommendations vs actual outcomes — "
            "monitor for systematic errors or drift in recommendation quality.",
            "Define clear escalation criteria — specify which cases must always "
            "go to human review regardless of AI confidence.",
        ]


class LLM10_ModelTheft(BaseEvaluator):
    threat_id = "LLM10"
    threat_name = "Model Theft"
    owasp_reference = "https://genai.owasp.org/llmrisk/llm10-model-theft/"

    def fires(self, system) -> bool:
        return system.fine_tuned or (
            system.customer_facing and system.llm_provider != "self_hosted"
        )

    def get_severity(self, system) -> str:
        if system.fine_tuned and system.trains_on_user_data:
            return "HIGH"
        if system.fine_tuned:
            return "MEDIUM"
        return "LOW"

    def get_evidence(self, system) -> List[str]:
        evidence = []
        if system.fine_tuned:
            evidence.append(
                "System uses a fine-tuned model — "
                "fine-tuned models encode proprietary knowledge, internal policies, "
                "and potentially customer data patterns. Model extraction attacks "
                "can replicate this IP through systematic querying."
            )
        if system.customer_facing:
            evidence.append(
                "Customer-facing system exposed to public — "
                "high query volume from the public makes systematic model probing feasible."
            )
        return evidence

    def get_signal_count(self) -> int:
        return 2  # transactions, freeze, approve, modify, internal apis

    # def get_mitigations(self, system) -> List[str]:
    #     return [
    #         "Implement rate limiting per user and API key to make "
    #         "systematic model extraction economically infeasible.",
    #         "Monitor for unusual query patterns — "
    #         "high volume, systematically varied inputs may indicate extraction attempts.",
    #         "Add output perturbation for fine-tuned models — "
    #         "slight randomness in responses makes exact model replication harder.",
    #     ]

    def get_mitigations(self, system) -> List[str]:
        if self.is_operator(system):
            return [
                "You don't own the base model — but you own your prompt engineering, "
                "system prompts, and application logic. Treat these as IP and protect them.",
                "Implement rate limiting and anomaly detection on query patterns — "
                "systematic probing of your application can extract your prompt design.",
                "Do not expose your system prompt directly — test that users cannot "
                "extract it through prompt injection or repeated probing.",
                "If you use fine-tuned models via the provider's fine-tuning API, "
                "review the provider's terms on model ownership and data usage.",
            ]
        else:
            return [
                "Implement rate limiting per user and API key to make systematic "
                "model extraction economically infeasible.",
                "Monitor for unusual query patterns — high volume, systematically "
                "varied inputs may indicate extraction attempts.",
                "Add output perturbation for sensitive fine-tuned models — "
                "slight randomness in responses makes exact replication harder.",
                "Restrict direct model access — serve through an API layer, "
                "never expose model weights or architecture directly.",
                "Register proprietary model architecture and training methodology "
                "as trade secrets with appropriate legal protections.",
            ]