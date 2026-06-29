"""
base.py

Base class for all OWASP LLM Top 10 evaluators.
Every evaluator follows the same contract:
  - fires()     → should this threat be raised for this system?
  - severity()  → CRITICAL | HIGH | MEDIUM | LOW
  - evidence()  → specific reasons from THIS system that make it real
  - result()    → complete EvaluationResult

This pattern means every threat is deterministic, testable, and explainable.
The LLM never makes these decisions — your code does.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from abc import ABC, abstractmethod


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class EvaluationResult:
    """
    The output of a single evaluator for a single system.
    This is what gets passed to the narrative generator and report builder.
    """
    threat_id: str                    # e.g. "LLM01"
    threat_name: str                  # e.g. "Prompt Injection"
    fired: bool                       # Did this threat apply to this system?
    severity: Optional[str]           # CRITICAL | HIGH | MEDIUM | LOW | None if not fired
    evidence: List[str]               # Specific reasons from THIS system
    mitigations: List[str]            # Concrete actions to address this threat
    owasp_reference: str              # Link to OWASP documentation
    narrative: Optional[str] = None  # Filled in later by narrative generator

    @property
    def severity_score(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


class BaseEvaluator(ABC):
    """
    All 10 OWASP LLM evaluators inherit from this.
    Subclasses implement fires(), get_severity(), get_evidence(), get_mitigations().
    """
    threat_id: str = ""
    threat_name: str = ""
    owasp_reference: str = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"

    @abstractmethod
    def fires(self, system) -> bool:
        """Return True if this threat is relevant to this system."""
        pass

    @abstractmethod
    def get_severity(self, system) -> str:
        """Return severity: CRITICAL | HIGH | MEDIUM | LOW"""
        pass

    @abstractmethod
    def get_evidence(self, system) -> List[str]:
        """Return list of specific, system-grounded reasons this threat applies."""
        pass

    @abstractmethod
    def get_mitigations(self, system) -> List[str]:
        """Return list of concrete mitigations for this system."""
        pass

    def evaluate(self, system) -> EvaluationResult:
        """Run the full evaluation. Called by the runner."""
        fired = self.fires(system)
        return EvaluationResult(
            threat_id=self.threat_id,
            threat_name=self.threat_name,
            fired=fired,
            severity=self.get_severity(system) if fired else None,
            evidence=self.get_evidence(system) if fired else [],
            mitigations=self.get_mitigations(system) if fired else [],
            owasp_reference=self.owasp_reference,
        )
