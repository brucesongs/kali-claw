# Automated Consensus Scoring Guide

> Automating consensus across multiple security assessments using weighted voting, confidence intervals, and adapted Delphi method.

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

## 5. CLI Execution

```bash
# Collect assessor votes from JSON files
python3 consensus_scorer.py --votes assessor_*.json --rounds 3 --output consensus.json

# Generate confidence interval report
python3 consensus_scorer.py --votes assessor_*.json --report ci --format markdown > ci_report.md

# Run single Delphi round and distribute feedback
python3 consensus_scorer.py --votes round1_*.json --delphi-feedback --notify slack
```

## 6. Interpreting Results

| CI Spread | Interpretation | Action |
|-----------|---------------|--------|
| < 1.0 | Strong consensus | Accept score |
| 1.0 - 2.5 | Moderate agreement | Review outlier rationale |
| 2.5 - 4.0 | Weak consensus | Additional Delphi round |
| > 4.0 | No consensus | Escalate to senior council |

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
```

## 8. Best Practices

- Minimum 3 assessors per finding for statistical validity
- Anonymize feedback between rounds to prevent authority bias
- Weight domain expertise higher than general seniority
- Archive all rounds for audit trail and calibration analysis
- Re-run consensus when new exploit intelligence emerges
