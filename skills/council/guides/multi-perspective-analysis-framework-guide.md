# Multi-Perspective Analysis Framework Guide

> Structured methodology for conducting security analysis from attacker, defender, and auditor viewpoints with automated consensus building.

## 1. Perspective Definitions

Each security finding must be evaluated from three distinct viewpoints:

- **Attacker**: Exploitability, attack surface, chain potential
- **Defender**: Detection capability, response time, mitigation cost
- **Auditor**: Compliance impact, evidence quality, risk acceptance criteria

```python
from dataclasses import dataclass
from enum import Enum

class Perspective(Enum):
    ATTACKER = "attacker"
    DEFENDER = "defender"
    AUDITOR = "auditor"

@dataclass(frozen=True)
class PerspectiveScore:
    perspective: Perspective
    severity: float  # 0.0 - 10.0
    confidence: float  # 0.0 - 1.0
    rationale: str
```

## 2. Scoring Each Perspective

Assign severity and confidence from each viewpoint independently before combining.

```python
def score_finding(finding: dict) -> list[PerspectiveScore]:
    scores = []
    # Attacker perspective: how easy to exploit?
    attacker_severity = (
        finding["attack_complexity_inverse"] * 0.4
        + finding["privilege_required_inverse"] * 0.3
        + finding["chain_potential"] * 0.3
    )
    scores.append(PerspectiveScore(
        perspective=Perspective.ATTACKER,
        severity=min(attacker_severity * 10, 10.0),
        confidence=finding.get("exploit_evidence", 0.5),
        rationale=f"Complexity:{finding['attack_complexity_inverse']:.1f}"
    ))
    # Defender perspective: how hard to detect/mitigate?
    defender_severity = (
        (1 - finding["detection_rate"]) * 0.5
        + finding["response_time_hours"] / 72 * 0.3
        + finding["mitigation_cost_normalized"] * 0.2
    )
    scores.append(PerspectiveScore(
        perspective=Perspective.DEFENDER,
        severity=min(defender_severity * 10, 10.0),
        confidence=finding.get("detection_confidence", 0.7),
        rationale=f"DetectionGap:{1 - finding['detection_rate']:.1f}"
    ))
    # Auditor perspective: compliance and business risk
    auditor_severity = (
        finding["compliance_frameworks_affected"] / 5 * 0.4
        + finding["data_sensitivity"] * 0.4
        + finding["regulatory_penalty_risk"] * 0.2
    )
    scores.append(PerspectiveScore(
        perspective=Perspective.AUDITOR,
        severity=min(auditor_severity * 10, 10.0),
        confidence=finding.get("evidence_quality", 0.6),
        rationale=f"Compliance:{finding['compliance_frameworks_affected']}"
    ))
    return scores
```

## 3. Weighted Consensus Calculation

Combine perspectives using configurable weights based on engagement type.

```python
ENGAGEMENT_WEIGHTS = {
    "pentest": {Perspective.ATTACKER: 0.5, Perspective.DEFENDER: 0.3, Perspective.AUDITOR: 0.2},
    "blue_team": {Perspective.ATTACKER: 0.2, Perspective.DEFENDER: 0.5, Perspective.AUDITOR: 0.3},
    "compliance": {Perspective.ATTACKER: 0.2, Perspective.DEFENDER: 0.2, Perspective.AUDITOR: 0.6},
}

def compute_consensus(scores: list[PerspectiveScore], engagement: str) -> float:
    weights = ENGAGEMENT_WEIGHTS[engagement]
    weighted_sum = sum(
        s.severity * s.confidence * weights[s.perspective] for s in scores
    )
    total_weight = sum(
        s.confidence * weights[s.perspective] for s in scores
    )
    return weighted_sum / total_weight if total_weight > 0 else 0.0
```

## 4. Disagreement Detection and Resolution

Flag findings where perspectives diverge significantly for manual review.

```python
def detect_disagreement(scores: list[PerspectiveScore], threshold: float = 3.0) -> dict:
    severities = [s.severity for s in scores]
    spread = max(severities) - min(severities)
    if spread >= threshold:
        high = max(scores, key=lambda s: s.severity)
        low = min(scores, key=lambda s: s.severity)
        return {
            "disagreement": True,
            "spread": spread,
            "highest": f"{high.perspective.value} ({high.severity:.1f}): {high.rationale}",
            "lowest": f"{low.perspective.value} ({low.severity:.1f}): {low.rationale}",
            "recommendation": "Escalate to council review"
        }
    return {"disagreement": False, "spread": spread}
```

## 5. Running the Framework via CLI

```bash
# Export findings from scanner and run multi-perspective analysis
cat findings.json | python3 council_scorer.py --engagement pentest --threshold 3.0

# Generate disagreement report
python3 council_scorer.py --input findings.json --report disagreements --format markdown

# Compare perspectives across multiple assessors
python3 council_scorer.py --input assessor_*.json --mode inter-rater --output consensus.json
```

## 6. Integration with Security Tooling

Pipe tool output directly into the framework for real-time scoring.

```bash
# Score nmap findings through the framework
nmap -sV --script vuln target | python3 parse_nmap.py | python3 council_scorer.py --engagement pentest

# Combine nuclei and nikto results for multi-source consensus
nuclei -t cves/ -target url -json | jq -s '.' > nuclei_findings.json
nikto -h url -Format json -output nikto_findings.json
python3 council_scorer.py --input nuclei_findings.json nikto_findings.json --merge --output final_scores.json
```

## 7. Best Practices

- Score perspectives independently before viewing others to avoid anchoring bias
- Use confidence values honestly — low confidence on a high severity still warrants investigation
- Disagreements above threshold 3.0 require documented resolution rationale
- Re-score after new evidence (exploit PoC, detection rule, compliance update)
- Archive all perspective scores for trend analysis across engagements
