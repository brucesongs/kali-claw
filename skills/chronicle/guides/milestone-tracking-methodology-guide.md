# Milestone Tracking Methodology Guide

> Systematic approach to tracking skill progression, achievement criteria, and regression detection. Covers quantitative metrics, progress visualization, and automated milestone verification for continuous learning systems.

---

## 1. Milestone Definition Framework

Define milestones with measurable criteria that can be automatically verified. Each milestone has clear entry conditions, success metrics, and evidence requirements.

```python
# Python — Milestone definition and tracking system
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

class MilestoneStatus(Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    ACHIEVED = "achieved"
    REGRESSED = "regressed"

@dataclass(frozen=True)
class MilestoneCriteria:
    metric_name: str
    threshold: float
    comparison: str  # 'gte', 'lte', 'eq'
    evidence_required: bool = True

@dataclass(frozen=True)
class Milestone:
    id: str
    name: str
    domain: str
    criteria: tuple[MilestoneCriteria, ...]
    achieved_date: Optional[datetime] = None
    status: MilestoneStatus = MilestoneStatus.NOT_STARTED
    evidence: tuple[str, ...] = field(default_factory=tuple)

def evaluate_milestone(milestone: Milestone, current_metrics: dict) -> MilestoneStatus:
    """Check if all criteria for a milestone are currently met."""
    all_met = True
    for criterion in milestone.criteria:
        value = current_metrics.get(criterion.metric_name, 0)
        if criterion.comparison == 'gte' and value < criterion.threshold:
            all_met = False
        elif criterion.comparison == 'lte' and value > criterion.threshold:
            all_met = False
        elif criterion.comparison == 'eq' and value != criterion.threshold:
            all_met = False

    if all_met and milestone.status == MilestoneStatus.ACHIEVED:
        return MilestoneStatus.ACHIEVED
    elif all_met:
        return MilestoneStatus.ACHIEVED
    elif milestone.status == MilestoneStatus.ACHIEVED:
        return MilestoneStatus.REGRESSED
    else:
        return MilestoneStatus.IN_PROGRESS
```

## 2. Progress Metrics Collection

```python
# Python — Automated metrics collection from session logs
import re
from pathlib import Path
from collections import defaultdict

def collect_skill_metrics(memory_dir: Path, skill_domain: str) -> dict:
    """Aggregate metrics for a skill domain from session history."""
    metrics = defaultdict(list)

    for log_file in sorted(memory_dir.glob("*.md")):
        content = log_file.read_text()

        # Extract tool usage counts
        tool_mentions = re.findall(
            rf'\b({skill_domain})\b.*?tools?:\s*(\w+)',
            content, re.IGNORECASE
        )
        if tool_mentions:
            metrics['tools_used'].extend([t[1] for t in tool_mentions])

        # Extract success/failure indicators
        successes = len(re.findall(r'(?:success|completed|achieved|found)', content, re.I))
        failures = len(re.findall(r'(?:failed|error|blocked|timeout)', content, re.I))
        if successes + failures > 0:
            metrics['success_rate'].append(successes / (successes + failures))

        # Extract time-to-completion patterns
        time_matches = re.findall(r'completed in (\d+)\s*(min|sec|hour)', content, re.I)
        for value, unit in time_matches:
            seconds = int(value) * {'sec': 1, 'min': 60, 'hour': 3600}[unit.lower()]
            metrics['completion_times'].append(seconds)

    return {
        'unique_tools': len(set(metrics.get('tools_used', []))),
        'avg_success_rate': sum(metrics.get('success_rate', [0])) / max(len(metrics.get('success_rate', [])), 1),
        'sessions_count': len(list(memory_dir.glob("*.md"))),
        'avg_completion_time': sum(metrics.get('completion_times', [0])) / max(len(metrics.get('completion_times', [])), 1),
    }
```

## 3. Regression Detection

```bash
# Bash — Detect skill regression by comparing recent vs historical performance
#!/bin/bash
# Compare last 7 days metrics against 30-day baseline

MEMORY_DIR="memory"
SKILL="$1"

echo "=== Regression Check: $SKILL ==="

# Count successful operations in last 7 days
RECENT=$(find "$MEMORY_DIR" -name "*.md" -mtime -7 -exec \
  grep -li "$SKILL" {} \; | wc -l)

# Count in previous 23 days (day 8-30)
BASELINE=$(find "$MEMORY_DIR" -name "*.md" -mtime +7 -mtime -30 -exec \
  grep -li "$SKILL" {} \; | wc -l)

# Normalize to per-week rate
BASELINE_WEEKLY=$(echo "scale=1; $BASELINE / 3.3" | bc)

echo "Recent (7d):    $RECENT sessions"
echo "Baseline (weekly avg): $BASELINE_WEEKLY sessions"

# Alert if recent activity dropped by more than 50%
if [ "$(echo "$RECENT < $BASELINE_WEEKLY * 0.5" | bc)" -eq 1 ]; then
  echo "WARNING: Possible regression — activity dropped significantly"
fi
```

```python
# Python — Statistical regression detection
from statistics import mean, stdev

def detect_regression(
    historical_scores: list[float],
    recent_scores: list[float],
    threshold_sigma: float = 1.5
) -> dict:
    """Detect if recent performance has regressed from historical baseline."""
    if len(historical_scores) < 5 or len(recent_scores) < 3:
        return {'status': 'insufficient_data', 'regressed': False}

    hist_mean = mean(historical_scores)
    hist_std = stdev(historical_scores)
    recent_mean = mean(recent_scores)

    deviation = (hist_mean - recent_mean) / max(hist_std, 0.01)

    return {
        'status': 'regressed' if deviation > threshold_sigma else 'stable',
        'regressed': deviation > threshold_sigma,
        'historical_mean': hist_mean,
        'recent_mean': recent_mean,
        'deviation_sigma': deviation,
        'recommendation': 'Review recent sessions for degradation cause' if deviation > threshold_sigma else None
    }
```

## 4. Achievement Criteria Templates

```yaml
# YAML — Milestone templates for security skill domains
milestones:
  - id: "web-recon-basic"
    name: "Web Reconnaissance Fundamentals"
    domain: "web-pentest"
    criteria:
      - metric: "tools_mastered"
        threshold: 5
        comparison: "gte"
        tools: ["nmap", "gobuster", "nikto", "whatweb", "wappalyzer"]
      - metric: "successful_enumerations"
        threshold: 10
        comparison: "gte"
      - metric: "avg_time_to_enumerate"
        threshold: 1800  # 30 minutes
        comparison: "lte"

  - id: "web-recon-advanced"
    name: "Advanced Web Reconnaissance"
    domain: "web-pentest"
    depends_on: "web-recon-basic"
    criteria:
      - metric: "tools_mastered"
        threshold: 12
        comparison: "gte"
      - metric: "custom_wordlists_created"
        threshold: 3
        comparison: "gte"
      - metric: "hidden_endpoints_discovered"
        threshold: 20
        comparison: "gte"
```

## 5. Progress Visualization

```python
# Python — Generate text-based progress dashboard
def render_progress_dashboard(milestones: list[Milestone]) -> str:
    """Generate a text progress dashboard for milestone tracking."""
    lines = ["# Skill Progress Dashboard", ""]

    by_domain = {}
    for m in milestones:
        by_domain.setdefault(m.domain, []).append(m)

    for domain, domain_milestones in sorted(by_domain.items()):
        achieved = sum(1 for m in domain_milestones if m.status == MilestoneStatus.ACHIEVED)
        total = len(domain_milestones)
        pct = int(achieved / total * 100) if total > 0 else 0
        bar = '█' * (pct // 5) + '░' * (20 - pct // 5)

        lines.append(f"## {domain}")
        lines.append(f"  [{bar}] {pct}% ({achieved}/{total})")

        for m in domain_milestones:
            icon = {'achieved': '✓', 'regressed': '!', 'in_progress': '→', 'not_started': '○'}
            lines.append(f"    {icon[m.status.value]} {m.name}")

        lines.append("")

    return "\n".join(lines)
```

## 6. Tracking Best Practices

| Practice | Description | Frequency |
|----------|-------------|-----------|
| Metric collection | Gather raw performance data | Every session |
| Milestone evaluation | Check criteria against metrics | Weekly |
| Regression check | Compare recent vs baseline | Weekly |
| Milestone review | Update criteria, add new milestones | Monthly |
| Full audit | Verify all evidence, prune stale milestones | Quarterly |

Milestones should be challenging but achievable. If a milestone has been "in progress" for more than 4 weeks without advancement, either the criteria are too aggressive or the learning approach needs adjustment. Revisit and recalibrate.
