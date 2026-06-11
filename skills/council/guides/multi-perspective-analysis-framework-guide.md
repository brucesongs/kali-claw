# Multi-Perspective Analysis Framework Guide

> Structured methodology for conducting security analysis from attacker, defender, and auditor viewpoints with automated consensus building.

## Introduction

Multi-perspective analysis is the core methodology that transforms single-viewpoint security assessments into robust, stress-tested evaluations. Every security finding carries different implications depending on the lens through which it is viewed: an SQL injection that appears Critical to an attacker may be adequately mitigated from a defender's perspective, while a compliance gap rated Low by an attacker may carry severe financial penalties from an auditor's view.

This guide provides the complete framework for implementing structured multi-perspective analysis, including perspective definitions, scoring algorithms, consensus computation, disagreement detection, and integration with security tooling. It is designed for both manual implementation and automated pipeline integration.

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

### Perspective Scope Rules

Each perspective has explicit boundaries. Crossing these boundaries during the scoring phase contaminates the analysis and reduces the value of cross-validation.

| Perspective | In-Scope | Out-of-Scope | Forbidden |
|------------|----------|-------------|-----------|
| Attacker | Exploit paths, bypass techniques, chaining, impact | Control costs, compliance requirements, evidence docs | "The defender would catch this" |
| Defender | Control effectiveness, detection coverage, hardening priorities | Compliance mapping, evidence gathering for auditors | "This violates PCI-DSS" |
| Auditor | Compliance mapping, evidence sufficiency, gap analysis | Specific exploit techniques, control implementation details | "An attacker could exploit this via SQLi" |

### Sub-Perspectives for Specialized Analysis

For complex engagements, each primary perspective can spawn specialized sub-perspectives:

| Primary | Sub-Perspective | Focus Area |
|---------|----------------|------------|
| Attacker | Network Attacker | Network-level exploits, lateral movement |
| Attacker | Web Attacker | Application-level exploits, injection, auth bypass |
| Attacker | Physical Attacker | Social engineering, physical access exploitation |
| Defender | SOC Analyst | Detection rule effectiveness, alert quality |
| Defender | Incident Responder | Containment procedures, evidence preservation |
| Defender | Security Architect | Design-level mitigations, defense in depth |
| Auditor | Compliance Analyst | Regulatory mapping, evidence collection |
| Auditor | Risk Analyst | Business impact, risk quantification |
| Auditor | Privacy Officer | Data handling, consent management |

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

### Attacker Scoring Factors in Detail

The attacker perspective evaluates three primary factors:

| Factor | Weight | Source Data | Scale |
|--------|--------|-------------|-------|
| Attack Complexity (inverse) | 0.4 | CVSS Attack Complexity, inverted so easier = higher score | 0.0-1.0 |
| Privileges Required (inverse) | 0.3 | CVSS Privileges Required, inverted so none required = higher score | 0.0-1.0 |
| Chain Potential | 0.3 | Assessor judgment on exploit chaining possibilities | 0.0-1.0 |

### Defender Scoring Factors in Detail

The defender perspective evaluates detection and response capabilities:

| Factor | Weight | Source Data | Scale |
|--------|--------|-------------|-------|
| Detection Gap | 0.5 | (1 - detection_rate): lower detection = higher severity | 0.0-1.0 |
| Response Time | 0.3 | Hours to respond, normalized against 72-hour baseline | 0.0-1.0 |
| Mitigation Cost | 0.2 | Cost of remediation normalized against engagement budget | 0.0-1.0 |

### Auditor Scoring Factors in Detail

The auditor perspective evaluates compliance and regulatory impact:

| Factor | Weight | Source Data | Scale |
|--------|--------|-------------|-------|
| Compliance Frameworks Affected | 0.4 | Number of frameworks (PCI, HIPAA, GDPR, SOX, NIST) | 0-5, normalized |
| Data Sensitivity | 0.4 | Classification of affected data (PII, PHI, financial) | 0.0-1.0 |
| Regulatory Penalty Risk | 0.2 | Likelihood and magnitude of fines or legal action | 0.0-1.0 |

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

### Engagement Weight Rationale

| Engagement Type | Dominant Perspective | Rationale |
|----------------|---------------------|-----------|
| Pentest (Red Team) | Attacker (0.5) | Primary goal is exploit validation; attacker feasibility is paramount |
| Blue Team Assessment | Defender (0.5) | Primary goal is detection and response improvement |
| Compliance Audit | Auditor (0.6) | Primary goal is regulatory alignment and evidence sufficiency |
| Purple Team | Balanced (0.33 each) | Equal weight ensures attack and defense inform each other |
| Incident Response | Attacker + Defender (0.4 each) | Both adversary prediction and containment are critical |

### Custom Weight Profiles

For specialized engagements, define custom weight profiles:

```python
CUSTOM_WEIGHTS = {
    "purple_team": {Perspective.ATTACKER: 0.33, Perspective.DEFENDER: 0.34, Perspective.AUDITOR: 0.33},
    "incident_response": {Perspective.ATTACKER: 0.4, Perspective.DEFENDER: 0.4, Perspective.AUDITOR: 0.2},
    "risk_assessment": {Perspective.ATTACKER: 0.3, Perspective.DEFENDER: 0.3, Perspective.AUDITOR: 0.4},
    "maturity_assessment": {Perspective.ATTACKER: 0.15, Perspective.DEFENDER: 0.45, Perspective.AUDITOR: 0.4},
}
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

### Disagreement Classification

Not all disagreements are equal. Classify them to determine the appropriate response:

| Spread | Classification | Response |
|--------|---------------|----------|
| 0.0 - 1.0 | Agreement | Accept consensus score, no action needed |
| 1.1 - 2.0 | Minor divergence | Document, accept consensus with note |
| 2.1 - 3.0 | Moderate disagreement | Require documented rationale from each perspective |
| 3.1 - 5.0 | Significant disagreement | Mandatory council review, add expert assessor |
| 5.1+ | Fundamental disagreement | Block decision, require new evidence or investigation |

### Resolution Strategies

When disagreement exceeds threshold, apply these resolution strategies in order:

1. **Evidence gathering**: Request additional evidence from the perspective that disagrees. Often, disagreement stems from incomplete information.
2. **Expert tie-breaker**: Bring in a domain expert not involved in the initial scoring to provide an independent opinion.
3. **Scenario analysis**: Ask each perspective to describe the specific scenario where their severity rating is correct. Compare plausibility.
4. **Worst-case adoption**: If the finding affects safety-critical systems, adopt the higher severity until proven otherwise.
5. **Split reporting**: If disagreement persists after all resolution attempts, report both scores with full rationale for each.

## 5. Running the Framework via CLI

```bash
# Export findings from scanner and run multi-perspective analysis
cat findings.json | python3 council_scorer.py --engagement pentest --threshold 3.0

# Generate disagreement report
python3 council_scorer.py --input findings.json --report disagreements --format markdown

# Compare perspectives across multiple assessors
python3 council_scorer.py --input assessor_*.json --mode inter-rater --output consensus.json

# Run with custom engagement weights
python3 council_scorer.py --input findings.json --engagement purple_team --output purple_scores.json

# Export per-perspective breakdown for detailed review
python3 council_scorer.py --input findings.json --report breakdown --format json --output perspective_breakdown.json
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

# Integrate with Burp Suite via XML export
python3 parse_burp.py burp_report.xml | python3 council_scorer.py --engagement pentest --output burp_scores.json

# Score OWASP ZAP results
python3 parse_zap.py zap_report.json | python3 council_scorer.py --engagement pentest --threshold 2.5
```

### Tool Output Parser Requirements

To integrate a new tool, implement a parser that converts tool output to the standard finding format:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | Yes | Unique finding identifier |
| title | string | Yes | Human-readable finding title |
| cvss | float | Yes | Base CVSS score (0.0-10.0) |
| attack_complexity_inverse | float | Yes | 1.0 = trivial, 0.0 = requires expert skills |
| privilege_required_inverse | float | Yes | 1.0 = none required, 0.0 = admin required |
| chain_potential | float | Yes | How likely this finding chains with others |
| detection_rate | float | Yes | Estimated detection probability (0.0-1.0) |
| response_time_hours | float | Yes | Estimated hours to respond |
| compliance_frameworks_affected | int | Yes | Number of compliance frameworks impacted |

## Hands-on Exercises

### Exercise 1: Single-Finding Three-Perspective Analysis

Select a real vulnerability (e.g., CVE-2024-3094 XZ Utils backdoor). Score it independently from all three perspectives without looking at the other perspectives' scores. Then compute consensus and identify disagreements.

Expected outcome: The attacker perspective will rate exploitability based on supply chain trust, the defender will focus on detection difficulty (legitimate-appearing code), and the auditor will emphasize compliance process gaps (vendor vetting).

### Exercise 2: Engagement Weight Comparison

Take a set of 10 findings and score them using all five engagement weight profiles (pentest, blue_team, compliance, purple_team, incident_response). Compare how the same findings are prioritized differently based on engagement type.

Expected outcome: The same finding (e.g., missing HSTS header) may score Low in a pentest weight profile but High in a compliance weight profile due to PCI-DSS requirements.

### Exercise 3: Disagreement Resolution Workshop

Create a set of 5 findings where perspectives systematically disagree. Practice the resolution strategies (evidence gathering, expert tie-breaker, scenario analysis, worst-case adoption) for each.

## References

- [NIST SP 800-30 Rev. 1: Guide for Conducting Risk Assessments](https://csrc.nist.gov/publications/detail/sp/800-30/vol-1/final)
- [OWASP Risk Assessment Methodology](https://owasp.org/www-community/OWASP_Risk_Assessment_Methodology)
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversary behavior modeling for attacker perspective
- [CIS Controls v8](https://www.cisecurity.org/controls) - Defender perspective baseline
- [ISO 27001:2022](https://www.iso.org/standard/27001) - Auditor perspective compliance framework
- [CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document) - Vulnerability scoring standard
