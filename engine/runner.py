"""
runner.py

Orchestrates the full pipeline:
  1. Extract structured system profile from description
  2. Run all 10 OWASP LLM evaluators
  3. Score and prioritize threats
  4. Return a ThreatReport ready for narrative generation and output
"""

from dataclasses import dataclass, field
from typing import List
from .extractor import extract_system, ExtractedSystem
from .evaluators import ALL_EVALUATORS
from .evaluators.base import EvaluationResult, SEVERITY_ORDER


@dataclass
class ThreatReport:
    system: ExtractedSystem
    threats: List[EvaluationResult]        # Only fired threats, sorted by severity
    not_applicable: List[EvaluationResult] # Threats that did not fire
    total_threats: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    def __post_init__(self):
        self.total_threats = len(self.threats)
        self.critical_count = sum(1 for t in self.threats if t.severity == "CRITICAL")
        self.high_count = sum(1 for t in self.threats if t.severity == "HIGH")
        self.medium_count = sum(1 for t in self.threats if t.severity == "MEDIUM")
        self.low_count = sum(1 for t in self.threats if t.severity == "LOW")

    @property
    def risk_rating(self) -> str:
        if self.critical_count >= 2:
            return "CRITICAL"
        if self.critical_count == 1 or self.high_count >= 3:
            return "HIGH"
        if self.high_count >= 1 or self.medium_count >= 3:
            return "MEDIUM"
        return "LOW"


def run(description: str) -> ThreatReport:
    """
    Main entry point.
    Takes a free-form project description.
    Returns a complete ThreatReport.
    """
    # Step 1: Extract structured system profile
    system = extract_system(description)

    # Step 2: Run all evaluators
    fired = []
    not_applicable = []

    for evaluator in ALL_EVALUATORS:
        result = evaluator.evaluate(system)
        if result.fired:
            fired.append(result)
        else:
            not_applicable.append(result)

    # Step 3: Sort fired threats by severity
    fired.sort(key=lambda r: SEVERITY_ORDER.get(r.severity, 99))

    return ThreatReport(
        system=system,
        threats=fired,
        not_applicable=not_applicable,
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        desc = open(sys.argv[1]).read()
    else:
        desc = """
        We are building a customer support chatbot for our bank using GPT-4o 
        hosted on Azure OpenAI. Customers authenticate before chatting. The chatbot 
        can retrieve account balances, recent transactions, card status, and loan 
        information through internal banking APIs. It can also initiate refunds for 
        eligible transactions after customer confirmation. Chat history is stored for 
        quality monitoring. Human agents can take over conversations if required.
        """

    print("\n🔍 Running ThreatLens AI...\n")
    report = run(desc)

    print(f"Project:      {report.system.project_name}")
    print(f"Domain:       {report.system.domain}")
    print(f"Risk Rating:  {report.risk_rating}")
    print(f"Threats:      {report.total_threats} fired | "
          f"{report.critical_count} CRITICAL | "
          f"{report.high_count} HIGH | "
          f"{report.medium_count} MEDIUM\n")

    print("=" * 60)
    for threat in report.threats:
        print(f"\n[{threat.severity}] {threat.threat_id}: {threat.threat_name}")
        for e in threat.evidence:
            print(f"  • {e}")
