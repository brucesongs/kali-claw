# Automated Consensus Scoring Guide

> Automating consensus across multiple security assessments using weighted voting, confidence intervals, and adapted Delphi method.

## Introduction

Automated consensus scoring replaces ad-hoc "gut feeling" severity assessments with a rigorous, reproducible process that combines multiple expert opinions into statistically sound final scores. This guide covers the complete pipeline from individual assessor voting through multi-round convergence to final output integration with vulnerability management systems.

The methodology draws from three established frameworks: weighted voting (combining opinions proportionally to expertise), confidence intervals (quantifying uncertainty in group judgments), and the Delphi method (iterative convergence through anonymized feedback). Together, these produce severity scores that are more accurate than any single assessor while maintaining full auditability.

When to use this guide: multi-assessor penetration tests, red team exercises with independent operators, purple team assessments requiring cross-validation, and any engagement where multiple analysts evaluate overlapping findings.

## 1. Weighted Voting System

Assign assessor weights based on expertise, track record, and domain relevance.

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class AssessorVote:
    assessor_id: str
    finding_id: str
    severity: float  # 0.0 - 10.0
    confidence: float  # 0.0 - 1.0
    domain_expertise: float  # 0.0 - 1.0

def weighted_vote(votes: list[AssessorVote]) -> float:
    total_weight = sum(v.confidence * v.domain_expertise for v in votes)
    if total_weight == 0:
        return 0.0
    return sum(
        v.severity * v.confidence * v.domain_expertise for v in votes
    ) / total_weight
```

### Weight Calibration Table

The `domain_expertise` weight should be calibrated based on assessor background and verified track record, not self-reported skill. Use the following rubric:

| Expertise Level | Weight | Criteria |
|----------------|--------|----------|
| Domain Expert | 1.0 | 5+ years in the specific finding domain (e.g., web app, network, cloud), published research or CVEs, OSCP/OSCE or equivalent |
| Experienced | 0.8 | 3-5 years in security, performed 10+ assessments in this domain, holds relevant certifications |
| Generalist | 0.6 | 1-3 years security experience, cross-domain knowledge, limited specialization in this finding type |
| Junior | 0.4 | Less than 1 year, supervised assessments only, developing domain knowledge |
| External Reviewer | 0.3 | Not part of the core team, providing independent verification with limited context |

### Dynamic Weight Adjustment

Expertise weights should not be static. Implement calibration scoring to adjust weights based on historical accuracy:

```python
def calibrate_weights(assessor_history: dict, reference_scores: dict) -> dict:
    """Adjust expertise weights based on historical accuracy vs. reference scores."""
    calibrated = {}
    for assessor_id, past_votes in assessor_history.items():
        errors = []
        for finding_id, vote in past_votes.items():
            if finding_id in reference_scores:
                errors.append(abs(vote - reference_scores[finding_id]))
        if errors:
            mean_error = sum(errors) / len(errors)
            # Lower error = higher weight (0.3-1.0 range)
            calibrated[assessor_id] = max(0.3, min(1.0, 1.0 - (mean_error / 10.0)))
        else:
            calibrated[assessor_id] = 0.5  # Default for no history
    return calibrated
```

## 2. Confidence Interval Calculation

Compute confidence intervals to quantify uncertainty in consensus scores.

```python
import math

def confidence_interval(votes: list[AssessorVote], z: float = 1.96) -> tuple[float, float, float]:
    """Returns (mean, lower_bound, upper_bound) at 95% confidence."""
    n = len(votes)
    if n < 2:
        mean = votes[0].severity if votes else 0.0
        return (mean, mean, mean)
    severities = [v.severity for v in votes]
    mean = sum(severities) / n
    variance = sum((s - mean) ** 2 for s in severities) / (n - 1)
    std_err = math.sqrt(variance / n)
    margin = z * std_err
    return (mean, max(0.0, mean - margin), min(10.0, mean + margin))
```

### Understanding Confidence Levels

The z-score parameter controls the confidence level of the interval. Select based on the engagement context:

| z-Score | Confidence Level | When to Use |
|---------|-----------------|-------------|
| 1.645 | 90% | Rapid triage, time-constrained assessments |
| 1.960 | 95% | Standard engagements, most common default |
| 2.576 | 99% | Critical infrastructure, regulatory-mandated assessments |
| 3.291 | 99.9% | Safety-critical systems, medical/SCADA environments |

### Interpreting Narrow vs. Wide Intervals

A narrow confidence interval (spread < 1.0) indicates strong assessor agreement and high confidence in the score. A wide interval (spread > 3.0) indicates significant disagreement, which may stem from genuinely ambiguous findings or insufficient evidence. Wide intervals should trigger additional investigation rather than simply averaging.

## 3. Delphi Method Adaptation

Iterative rounds where assessors revise scores after seeing anonymized group statistics.

```python
def delphi_round(votes: list[AssessorVote], round_num: int, max_rounds: int = 3) -> dict:
    mean, lower, upper = confidence_interval(votes)
    spread = upper - lower
    outliers = [v for v in votes if v.severity < lower or v.severity > upper]
    converged = spread < 1.5 or round_num >= max_rounds
    return {
        "round": round_num,
        "mean": round(mean, 2),
        "ci_lower": round(lower, 2),
        "ci_upper": round(upper, 2),
        "spread": round(spread, 2),
        "outlier_count": len(outliers),
        "converged": converged,
        "feedback": (
            f"Group mean: {mean:.1f} (CI: {lower:.1f}-{upper:.1f}). "
            f"{len(outliers)} outlier(s). "
            + ("Consensus reached." if converged else "Please revise scores.")
        ),
    }
```

### Delphi Round Protocol

Each Delphi round follows a strict protocol to prevent bias contamination:

1. **Anonymization**: Assessor identities are removed from feedback. Each assessor sees only the group statistics (mean, CI, outlier count), not which specific assessor gave which score.
2. **Justification requirement**: When an assessor's score is an outlier, they must provide a written justification before revising. This captures domain-specific insights that the majority may have missed.
3. **Convergence criterion**: A round is considered converged when the CI spread drops below 1.5 OR after the maximum number of rounds (default 3). Forced convergence after max rounds prevents endless iteration.
4. **Documentation**: Every round's statistics are archived for audit trail. If a finding is later disputed, the full convergence history is available for review.

### When Delphi Convergence Fails

Not all findings will converge within 3 rounds. Common reasons and responses:

| Failure Mode | Cause | Response |
|-------------|-------|----------|
| Persistent bimodal split | Two legitimate interpretations of evidence | Document both positions, escalate to senior analyst for tie-breaking |
| Anchoring to initial round | Assessors unwilling to shift from first vote | Add a "blind re-score" round where all assessors score without seeing any prior data |
| New evidence introduced | Assessor discovered additional context mid-process | Reset the Delphi process with the new evidence shared with all assessors |
| Strategic voting | Assessor inflating/deflating to skew outcome | Compare against calibrated weight history; anomalous patterns flag for review |

## 4. Full Consensus Pipeline

Orchestrate multiple rounds and produce final scored output.

```python
def run_consensus_pipeline(
    all_votes: dict[str, list[AssessorVote]], max_rounds: int = 3
) -> list[dict]:
    results = []
    for finding_id, votes in all_votes.items():
        for round_num in range(1, max_rounds + 1):
            outcome = delphi_round(votes, round_num, max_rounds)
            if outcome["converged"]:
                break
        final_score = weighted_vote(votes)
        mean, lower, upper = confidence_interval(votes)
        results.append({
            "finding_id": finding_id,
            "final_score": round(final_score, 2),
            "consensus_mean": round(mean, 2),
            "ci_95": (round(lower, 2), round(upper, 2)),
            "rounds_needed": outcome["round"],
            "assessor_count": len(votes),
        })
    return sorted(results, key=lambda r: r["final_score"], reverse=True)
```

### Pipeline Output Format

Each finding in the pipeline output includes metadata for downstream consumption:

```json
{
  "finding_id": "WEB-0042",
  "final_score": 8.7,
  "consensus_mean": 8.5,
  "ci_95": [7.9, 9.1],
  "rounds_needed": 2,
  "assessor_count": 4,
  "convergence_quality": "strong",
  "tier": "P0-CRITICAL"
}
```

The `convergence_quality` field provides a human-readable summary:
- **strong**: CI spread < 1.0, converged in 1-2 rounds
- **moderate**: CI spread 1.0-2.5, converged in 2-3 rounds
- **weak**: CI spread > 2.5, or forced convergence at max rounds
- **failed**: Did not converge, requires manual adjudication

## 5. CLI Execution

```bash
# Collect assessor votes from JSON files
python3 consensus_scorer.py --votes assessor_*.json --rounds 3 --output consensus.json

# Generate confidence interval report
python3 consensus_scorer.py --votes assessor_*.json --report ci --format markdown > ci_report.md

# Run single Delphi round and distribute feedback
python3 consensus_scorer.py --votes round1_*.json --delphi-feedback --notify slack

# Run with custom confidence level (99%)
python3 consensus_scorer.py --votes assessor_*.json --z-score 2.576 --output high_confidence.json

# Generate full audit trail
python3 consensus_scorer.py --votes assessor_*.json --audit-trail --output audit/
```

### Vote File Format

Each assessor provides a JSON file with their votes:

```json
{
  "assessor_id": "analyst-001",
  "engagement_id": "ENG-2026-042",
  "timestamp": "2026-06-10T14:30:00Z",
  "votes": [
    {
      "finding_id": "WEB-0042",
      "severity": 9.0,
      "confidence": 0.85,
      "domain_expertise": 0.9,
      "rationale": "Unauthenticated RCE with publicly available exploit code"
    },
    {
      "finding_id": "NET-0015",
      "severity": 6.5,
      "confidence": 0.7,
      "domain_expertise": 0.6,
      "rationale": "Internal network segmentation gap, limited blast radius"
    }
  ]
}
```

## 6. Interpreting Results

| CI Spread | Interpretation | Action |
|-----------|---------------|--------|
| < 1.0 | Strong consensus | Accept score, proceed to remediation planning |
| 1.0 - 2.5 | Moderate agreement | Review outlier rationale, consider one more Delphi round |
| 2.5 - 4.0 | Weak consensus | Mandatory additional Delphi round, add assessor if possible |
| > 4.0 | No consensus | Escalate to senior council, add domain expert assessor |

### Decision Matrix for Consensus Quality

When the pipeline produces mixed quality results across findings, use this matrix to prioritize adjudication effort:

| Final Score | Convergence Quality | Action |
|------------|-------------------|--------|
| 8.0+ | Strong | Accept and escalate immediately |
| 8.0+ | Moderate/Weak | Adjudicate urgently -- high severity demands high confidence |
| 5.0-7.9 | Strong | Accept and schedule remediation |
| 5.0-7.9 | Moderate | Review outliers, accept if rationale is documented |
| 5.0-7.9 | Weak | Adjudicate before scheduling remediation |
| < 5.0 | Any | Accept with documentation, add to backlog |

## 7. Integration with Vulnerability Management

```bash
# Import consensus scores into DefectDojo
python3 consensus_scorer.py --votes *.json --output consensus.json
curl -X POST "https://defectdojo.internal/api/v2/import-scan/" \
  -H "Authorization: Token $DOJO_TOKEN" \
  -F "file=@consensus.json" \
  -F "scan_type=Generic Findings Import"

# Update Jira tickets with consensus severity
python3 consensus_scorer.py --votes *.json --sync-jira --project VULN --field priority

# Export to SARIF for GitHub Advanced Security
python3 consensus_scorer.py --votes *.json --format sarif --output results.sarif

# Generate executive summary with risk dashboard
python3 consensus_scorer.py --votes *.json --report executive --format html --output dashboard.html
```

### DefectDojo Integration Detail

When importing consensus scores into DefectDojo, map the pipeline output fields to DefectDojo's finding model:

| Consensus Field | DefectDojo Field | Notes |
|----------------|------------------|-------|
| finding_id | unique_id_from_tool | Enables deduplication across runs |
| final_score | severity | Map 8.0+ to Critical, 6.0-7.9 to High, etc. |
| ci_95 | (custom field) | Store as finding metadata for confidence tracking |
| convergence_quality | (custom field) | Enables filtering by consensus strength |
| assessor_count | (custom field) | Flag findings with fewer than 3 assessors |

## Hands-on Exercises

### Exercise 1: Three-Assessor Consensus

Simulate a three-assessor vote on five findings. One assessor should have high domain expertise (1.0), one moderate (0.7), and one general (0.5). Run the weighted vote and observe how expertise weighting shifts the final score compared to a simple average.

Steps:
1. Create three JSON vote files with different severity opinions for the same findings
2. Run the consensus pipeline with 3 Delphi rounds
3. Compare weighted vs. unweighted results
4. Identify which findings had the largest shift and explain why

### Exercise 2: Delphi Convergence

Set up a scenario where two assessors fundamentally disagree on a finding's severity (e.g., one rates 9.0, another rates 4.0). Run multiple Delphi rounds and observe:
- How the CI spread changes across rounds
- Whether convergence is achieved within 3 rounds
- What justification each assessor provides for maintaining or changing their score
- How the final weighted score compares to a simple average

### Exercise 3: Pipeline-to-DefectDojo Integration

Run a full consensus pipeline with sample data and import the results into a DefectDojo instance. Verify that:
- Severity mappings are correct (Critical/High/Medium/Low)
- Finding deduplication works across re-imports
- CI spread and convergence quality are preserved as metadata
- The executive dashboard accurately reflects consensus results

## References

- [NIST SP 800-30: Guide for Conducting Risk Assessments](https://csrc.nist.gov/publications/detail/sp/800-30/vol-1/final) - Risk assessment methodology
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) - Severity scoring framework
- [The Delphi Method: Techniques and Applications](https://www.rand.org/topics/delphi-method.html) - Original Rand Corporation Delphi methodology
- [FAIR Risk Framework](https://www.fairinstitute.org/) - Quantitative risk analysis standards
- [DefectDojo API Documentation](https://defectdojo.github.io/django-DefectDojo/integrations/api-v2-docs/) - Vulnerability management integration
- [CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document) - Vulnerability scoring standard
