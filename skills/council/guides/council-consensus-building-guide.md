# Council Consensus Building Guide

> Consensus algorithms for multi-agent security decisions, voting mechanisms, conflict resolution, and weighted expertise scoring.

## Introduction

Consensus building is the final and most critical phase of the council methodology. After independent perspectives have been generated and cross-validated, the team must converge on a unified recommendation. Poor consensus processes lead to either false unanimity (groupthink) or perpetual disagreement (analysis paralysis). Effective consensus building produces decisions that are stronger than any individual perspective could produce alone, while preserving dissent for audit and future reference.

This guide covers the complete consensus building toolkit: voting mechanisms for aggregating opinions, conflict resolution protocols for handling disagreements, weighted expertise scoring for calibrating influence, and practical algorithms for computing consensus in both synchronous and asynchronous assessment environments.

## 1. Consensus Models

### Unanimous Consensus

All perspectives fully agree on the finding severity and recommended action.

- **When it works**: Simple findings with clear evidence, low ambiguity
- **When it fails**: Complex findings requiring nuanced judgment; pressure to agree artificially
- **Risk**: Groupthink -- perspectives converge too quickly because agreement feels easier than disagreement
- **Usage guideline**: Accept unanimous consensus only after verifying that each perspective was genuinely generated independently

### Majority Consensus

The majority (2 of 3 perspectives, or more than 50% in larger groups) agree, with documented minority dissent.

- **When it works**: Time-constrained decisions, findings with moderate ambiguity
- **When it fails**: The majority holds a systematically biased view that the minority correctly identifies
- **Risk**: Majority tyranny -- the dissenting perspective is correct but outvoted
- **Usage guideline**: Majority consensus must always include a documented dissent section with the minority position

### Supermajority Consensus

Requires a higher threshold (e.g., 67% or 75%) for agreement, protecting minority positions.

- **When it works**: Critical decisions with irreversible consequences, findings affecting safety-critical systems
- **When it fails**: Can block necessary action when the minority position is based on incomplete evidence
- **Risk**: Decision paralysis -- no finding can meet the higher threshold
- **Usage guideline**: Use for P0-CRITICAL findings and decisions that cannot be easily reversed

### Consensus Model Selection Matrix

| Engagement Type | Recommended Model | Threshold | Rationale |
|----------------|-------------------|-----------|-----------|
| Standard pentest | Majority | 2 of 3 perspectives | Balance speed with rigor |
| Purple team exercise | Supermajority | 67% | Both red and blue must agree |
| Incident response | Majority + authority | 2 of 3 + IC override | Speed is paramount |
| Compliance audit | Supermajority | 75% | Regulatory consequences require strong agreement |
| Threat modeling | Unanimous | 100% | Design decisions should have full team buy-in |

## 2. Voting Mechanisms

### Simple Scoring Vote

Each perspective assigns a severity score (0.0-10.0) and the scores are combined.

```python
from dataclasses import dataclass
from enum import Enum

class Perspective(Enum):
    ATTACKER = "attacker"
    DEFENDER = "defender"
    AUDITOR = "auditor"

@dataclass(frozen=True)
class Vote:
    perspective: Perspective
    severity: float
    confidence: float
    rationale: str

def simple_vote_aggregation(votes: list[Vote]) -> dict:
    """Aggregate votes using simple mean, median, and range."""
    severities = [v.severity for v in votes]
    mean = sum(severities) / len(severities)
    sorted_scores = sorted(severities)
    n = len(sorted_scores)
    median = sorted_scores[n // 2] if n % 2 == 1 else (sorted_scores[n // 2 - 1] + sorted_scores[n // 2]) / 2
    return {
        "mean": round(mean, 2),
        "median": round(median, 2),
        "range": (min(severities), max(severities)),
        "spread": round(max(severities) - min(severities), 2),
        "recommended_score": round(median, 2),  # Median is more robust to outliers
    }
```

### Confidence-Weighted Vote

Votes are weighted by each perspective's confidence level, reducing the influence of uncertain opinions.

```python
def confidence_weighted_vote(votes: list[Vote]) -> dict:
    """Weight votes by confidence to reduce influence of uncertain opinions."""
    total_confidence = sum(v.confidence for v in votes)
    if total_confidence == 0:
        return {"weighted_score": 0.0, "effective_votes": 0}

    weighted_score = sum(v.severity * v.confidence for v in votes) / total_confidence
    effective_votes = sum(1 for v in votes if v.confidence > 0.5)

    return {
        "weighted_score": round(weighted_score, 2),
        "effective_votes": effective_votes,
        "confidence_range": (min(v.confidence for v in votes), max(v.confidence for v in votes)),
        "low_confidence_voters": [v.perspective.value for v in votes if v.confidence < 0.5],
    }
```

### Ranked Choice Vote

For remediation prioritization where ordinal ranking matters more than absolute scores.

```python
def ranked_choice_voting(perspective_rankings: dict[Perspective, list[str]]) -> str:
    """Select the top-priority finding using ranked choice voting."""
    finding_counts = {}
    eliminated = set()

    while True:
        # Count first-preference votes (excluding eliminated)
        for perspective, rankings in perspective_rankings.items():
            for finding_id in rankings:
                if finding_id not in eliminated:
                    finding_counts[finding_id] = finding_counts.get(finding_id, 0) + 1
                    break

        total = sum(finding_counts.values())
        if total == 0:
            return "NO CONSENSUS"

        # Check for majority
        for finding_id, count in finding_counts.items():
            if count > total / 2:
                return finding_id

        # Eliminate lowest-ranked
        min_count = min(finding_counts.values())
        for finding_id, count in finding_counts.items():
            if count == min_count:
                eliminated.add(finding_id)

        finding_counts = {}
```

### Approval Voting

Each perspective approves or rejects each finding at a given severity level. Useful for binary decisions (fix / don't fix).

```python
def approval_vote(votes: list[Vote], threshold: float = 7.0) -> dict:
    """Binary approval voting: each perspective approves findings above threshold."""
    approvals = [v for v in votes if v.severity >= threshold]
    rejections = [v for v in votes if v.severity < threshold]
    return {
        "approved": len(approvals) >= len(votes) / 2,  # Majority approval
        "approval_count": len(approvals),
        "rejection_count": len(rejections),
        "approving_perspectives": [v.perspective.value for v in approvals],
        "rejecting_perspectives": [v.perspective.value for v in rejections],
        "threshold_used": threshold,
    }
```

## 3. Conflict Resolution Protocols

### Resolution Hierarchy

When perspectives disagree, follow this resolution hierarchy from least to most intervention:

| Level | Method | When to Use | Time Required |
|-------|--------|-------------|---------------|
| 1 | Evidence review | Disagreement stems from incomplete evidence | 30 minutes |
| 2 | Scenario analysis | Different interpretations of the same evidence | 1 hour |
| 3 | Expert consultation | Requires specialized knowledge outside the team | 2-4 hours |
| 4 | Structured debate | Fundamental disagreement on risk assessment | 1-2 hours |
| 5 | Authority decision | Time-constrained decision with unresolvable disagreement | 15 minutes |
| 6 | Dual reporting | Report both positions independently | 1 hour |

### Evidence Review Protocol

The most common and effective resolution method. When perspectives disagree:

```python
def evidence_review_protocol(disagreement: dict) -> dict:
    """Structured protocol for resolving disagreements through evidence review."""
    return {
        "step_1_identify_gap": "Each perspective states what evidence they need to change their position",
        "step_2_evidence_search": "Search for the identified evidence using available tools and data",
        "step_3_present_findings": "Each perspective presents evidence to the group",
        "step_4_re_score": "All perspectives re-score independently based on new evidence",
        "step_5_check_convergence": "If scores converge (spread < 2.0), accept consensus. If not, escalate.",
        "step_6_document": "Record the evidence reviewed, positions changed, and final scores",
    }
```

### Structured Debate Format

For fundamental disagreements that cannot be resolved through evidence alone:

**Phase 1: Position Statements (10 minutes)**
- Each perspective states their position in 3 minutes, uninterrupted
- No questions or challenges during this phase

**Phase 2: Clarifying Questions (5 minutes)**
- Each perspective asks factual questions about the others' positions
- No arguments or rebuttals -- only information-seeking questions

**Phase 3: Challenge Round (10 minutes)**
- Each perspective identifies the weakest point in the others' reasoning
- The challenged perspective must respond directly to each challenge

**Phase 4: Position Revision (5 minutes)**
- Each perspective may revise their position based on the debate
- Revision is optional; maintaining the original position is valid

**Phase 5: Final Vote (5 minutes)**
- Re-vote using the appropriate consensus model
- Document all positions, challenges, and the final outcome

## 4. Weighted Expertise Scoring

### Expertise Calibration Framework

Not all perspectives should have equal influence on every finding. Domain expertise scoring adjusts influence based on the finding type.

```python
@dataclass(frozen=True)
class ExpertiseProfile:
    perspective: Perspective
    web_security: float    # 0.0 - 1.0
    network_security: float
    cloud_security: float
    compliance: float
    cryptography: float
    application_security: float

EXPERTISE_PROFILES = {
    Perspective.ATTACKER: ExpertiseProfile(
        perspective=Perspective.ATTACKER,
        web_security=0.9,
        network_security=0.8,
        cloud_security=0.7,
        compliance=0.3,
        cryptography=0.6,
        application_security=0.8,
    ),
    Perspective.DEFENDER: ExpertiseProfile(
        perspective=Perspective.DEFENDER,
        web_security=0.7,
        network_security=0.8,
        cloud_security=0.8,
        compliance=0.5,
        cryptography=0.7,
        application_security=0.6,
    ),
    Perspective.AUDITOR: ExpertiseProfile(
        perspective=Perspective.AUDITOR,
        web_security=0.4,
        network_security=0.4,
        cloud_security=0.5,
        compliance=1.0,
        cryptography=0.3,
        application_security=0.5,
    ),
}

def domain_weighted_score(
    votes: list[Vote],
    finding_domain: str,
    profiles: dict[Perspective, ExpertiseProfile],
) -> dict:
    """Weight votes by each perspective's expertise in the finding's domain."""
    weighted_scores = []
    for vote in votes:
        profile = profiles[vote.perspective]
        domain_weight = getattr(profile, finding_domain, 0.5)
        effective_weight = vote.confidence * domain_weight
        weighted_scores.append(vote.severity * effective_weight)

    total_weight = sum(
        vote.confidence * getattr(profiles[vote.perspective], finding_domain, 0.5)
        for vote in votes
    )

    final_score = sum(weighted_scores) / total_weight if total_weight > 0 else 0.0

    return {
        "domain_weighted_score": round(final_score, 2),
        "finding_domain": finding_domain,
        "perspective_weights": {
            vote.perspective.value: round(
                vote.confidence * getattr(profiles[vote.perspective], finding_domain, 0.5), 2
            )
            for vote in votes
        },
    }
```

### Expertise Scoring by Finding Domain

| Finding Domain | Dominant Perspective | Weight Distribution |
|---------------|---------------------|-------------------|
| Web vulnerability | Attacker (0.9) | A:0.9, D:0.7, U:0.4 |
| Network misconfiguration | Defender (0.8) | A:0.8, D:0.8, U:0.4 |
| Cloud IAM issue | Defender (0.8) | A:0.7, D:0.8, U:0.5 |
| Compliance gap | Auditor (1.0) | A:0.3, D:0.5, U:1.0 |
| Cryptographic weakness | Mixed | A:0.6, D:0.7, U:0.3 |
| Application logic flaw | Attacker (0.8) | A:0.8, D:0.6, U:0.5 |

## 5. Asynchronous Consensus

### When Synchronous Consensus Is Not Possible

In distributed teams or time-zone-separated engagements, synchronous consensus sessions may not be feasible. Use asynchronous consensus with these adaptations:

| Synchronous Element | Asynchronous Replacement |
|--------------------|-------------------------|
| Live debate | Written position papers (max 500 words each) |
| Real-time voting | Time-boxed voting window (24-48 hours) |
| Immediate feedback | Annotated document review |
| Quick clarification | FAQ document with structured questions |
| Rapid convergence | Extended Delphi rounds (3-5 instead of 2-3) |

### Asynchronous Consensus Protocol

```python
def run_async_consensus(
    finding: dict,
    perspectives: list[Perspective],
    deadline_hours: int = 48,
) -> dict:
    """Run consensus building asynchronously with a deadline."""
    return {
        "phase_1_position_papers": {
            "duration_hours": deadline_hours * 0.4,
            "action": "Each perspective submits a written analysis (max 500 words)",
        },
        "phase_2_review_and_annotate": {
            "duration_hours": deadline_hours * 0.2,
            "action": "Each perspective reviews and annotates others' papers",
        },
        "phase_3_revision": {
            "duration_hours": deadline_hours * 0.2,
            "action": "Perspectives may revise their positions based on annotations",
        },
        "phase_4_final_vote": {
            "duration_hours": deadline_hours * 0.2,
            "action": "Final scoring vote with confidence levels",
        },
    }
```

## 6. Consensus Quality Metrics

### Measuring Consensus Effectiveness

Track these metrics across engagements to improve the consensus process:

| Metric | Calculation | Target |
|--------|-------------|--------|
| Convergence rate | Percentage of findings that reach consensus within allotted rounds | > 85% |
| Average rounds to consensus | Mean number of Delphi rounds across all findings | < 2.5 |
| Dissent preservation rate | Percentage of dissenting views that are fully documented | 100% |
| Decision reversal rate | Percentage of decisions reversed within 30 days | < 10% |
| Inter-rater reliability | Correlation between assessor scores (Krippendorff's alpha) | > 0.7 |
| Escalation rate | Percentage of findings escalated past the initial consensus group | < 15% |

### Calibration Dashboard

```python
def generate_consensus_dashboard(engagement_results: dict) -> dict:
    """Generate metrics for the consensus process quality."""
    findings = engagement_results.get("findings", [])
    total = len(findings)

    converged = sum(1 for f in findings if f.get("converged", False))
    with_dissent = sum(1 for f in findings if f.get("dissent_documented", False))
    reversed_decisions = sum(1 for f in findings if f.get("reversed", False))

    return {
        "total_findings": total,
        "convergence_rate": round(converged / total * 100, 1) if total > 0 else 0,
        "dissent_preservation_rate": round(with_dissent / total * 100, 1) if total > 0 else 0,
        "decision_reversal_rate": round(reversed_decisions / total * 100, 1) if total > 0 else 0,
        "avg_rounds_to_consensus": round(
            sum(f.get("rounds", 3) for f in findings) / total, 2
        ) if total > 0 else 0,
        "avg_spread_at_convergence": round(
            sum(f.get("final_spread", 0) for f in findings) / total, 2
        ) if total > 0 else 0,
    }
```

## Practical Steps

1. **Select the consensus model** based on the engagement type using the selection matrix above
2. **Choose the voting mechanism** based on the decision type: confidence-weighted for severity scoring, ranked choice for prioritization, approval for binary fix/don't-fix decisions
3. **Define expertise profiles** for each perspective before the engagement begins. Calibrate based on team members' actual experience
4. **Set up the conflict resolution protocol** with clear escalation paths. Ensure every team member knows the hierarchy
5. **Track consensus quality metrics** from day one. Review the dashboard at each sync meeting and adjust the process as needed
6. **Preserve all dissent** -- even resolved disagreements must be documented for future reference and audit

## Hands-on Exercises

### Exercise 1: Voting Mechanism Comparison

Take a set of 10 findings with known "ground truth" severities (established by an expert panel). Apply each voting mechanism (simple, confidence-weighted, ranked choice, approval) and compare accuracy. Which mechanism produces scores closest to the ground truth?

### Exercise 2: Conflict Resolution Role-Play

Simulate a disagreement where the attacker perspective rates a finding as Critical (9.5) but the defender rates it as Medium (5.0) because compensating controls exist. Practice the full conflict resolution hierarchy from evidence review through structured debate. Document the outcome.

### Exercise 3: Asynchronous Consensus Simulation

Run a consensus round asynchronously over 48 hours. Each team member writes a position paper (max 500 words) for a complex finding, reviews and annotates others' papers, revises their position, and submits a final vote. Compare the asynchronous result with a synchronous consensus on the same finding.

## References

- [The Delphi Method: Techniques and Applications](https://www.rand.org/topics/delphi-method.html) - Original Rand Corporation methodology
- [Arrow's Impossibility Theorem](https://en.wikipedia.org/wiki/Arrow%27s_impossibility_theorem) - Mathematical foundations of voting systems
- [NIST SP 800-30: Risk Assessment](https://csrc.nist.gov/publications/detail/sp/800-30/vol-1/final) - Risk assessment consensus requirements
- [FAIR Quantitative Risk Analysis](https://www.fairinstitute.org/) - Quantitative approaches to risk consensus
- [Krippendorff's Alpha](https://en.wikipedia.org/wiki/Krippendorff%27s_alpha) - Inter-rater reliability measurement
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) - Security-specific consensus scoring
