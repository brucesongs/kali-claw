# Adaptive Learning Strategies Guide

> Optimize knowledge acquisition and retention through spaced repetition, difficulty scaling, and mastery metrics. Build a self-improving learning system that adapts to performance patterns.

## 1. Spaced Repetition Algorithm

Implement an SM-2 variant tuned for security skill retention:

```python
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass(frozen=True)
class ReviewItem:
    topic: str
    easiness: float  # 1.3 to 2.5
    interval_days: int
    repetitions: int
    next_review: datetime
    last_score: int  # 0-5

def calculate_next_review(item: ReviewItem, score: int) -> ReviewItem:
    """SM-2 algorithm adapted for security knowledge."""
    if score < 3:
        # Failed recall — reset interval
        return ReviewItem(
            topic=item.topic,
            easiness=max(1.3, item.easiness - 0.2),
            interval_days=1,
            repetitions=0,
            next_review=datetime.now() + timedelta(days=1),
            last_score=score
        )
    
    # Successful recall — extend interval
    new_easiness = item.easiness + (0.1 - (5 - score) * (0.08 + (5 - score) * 0.02))
    new_easiness = max(1.3, new_easiness)
    
    if item.repetitions == 0:
        new_interval = 1
    elif item.repetitions == 1:
        new_interval = 6
    else:
        new_interval = int(item.interval_days * new_easiness)
    
    return ReviewItem(
        topic=item.topic,
        easiness=new_easiness,
        interval_days=new_interval,
        repetitions=item.repetitions + 1,
        next_review=datetime.now() + timedelta(days=new_interval),
        last_score=score
    )
```

## 2. Difficulty Scaling Framework

Adjust challenge level based on demonstrated competence:

```yaml
# difficulty-levels.yaml
skill_progression:
  network_scanning:
    beginner:
      tasks: ["basic nmap scan", "identify open ports", "service detection"]
      success_threshold: 0.8
      promotion_criteria: "3 consecutive successes"
    
    intermediate:
      tasks: ["NSE script usage", "firewall evasion", "timing optimization"]
      success_threshold: 0.7
      promotion_criteria: "5 successes in last 7 attempts"
    
    advanced:
      tasks: ["custom NSE development", "IDS evasion chains", "protocol manipulation"]
      success_threshold: 0.6
      promotion_criteria: "3 successes with novel approaches"
    
    expert:
      tasks: ["zero-day discovery", "protocol fuzzing", "tool development"]
      success_threshold: 0.5
      promotion_criteria: "consistent novel contributions"
```

## 3. Mastery Metrics Calculation

Track multi-dimensional competence across security domains:

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class MasteryMetrics:
    accuracy: float      # Correct application rate (0-1)
    speed: float         # Time efficiency vs baseline (0-1)
    retention: float     # Long-term recall rate (0-1)
    transfer: float      # Cross-domain application (0-1)
    creativity: float    # Novel approach generation (0-1)

def calculate_mastery_level(metrics: MasteryMetrics) -> str:
    """Determine overall mastery level from component metrics."""
    weighted_score = (
        metrics.accuracy * 0.30 +
        metrics.speed * 0.15 +
        metrics.retention * 0.25 +
        metrics.transfer * 0.20 +
        metrics.creativity * 0.10
    )
    
    if weighted_score >= 0.9:
        return "expert"
    elif weighted_score >= 0.7:
        return "advanced"
    elif weighted_score >= 0.5:
        return "intermediate"
    else:
        return "beginner"

def identify_weak_dimensions(metrics: MasteryMetrics) -> list:
    """Find dimensions below threshold for targeted practice."""
    threshold = 0.6
    weak = []
    for field, value in [
        ("accuracy", metrics.accuracy),
        ("speed", metrics.speed),
        ("retention", metrics.retention),
        ("transfer", metrics.transfer),
        ("creativity", metrics.creativity),
    ]:
        if value < threshold:
            weak.append((field, value))
    return sorted(weak, key=lambda x: x[1])
```

## 4. Practice Session Generator

Create targeted practice based on current mastery state:

```bash
#!/bin/bash
# generate-practice-session.sh — Select topics needing review
KNOWLEDGE_DB="$HOME/.learning/mastery.json"

echo "[*] Generating practice session for $(date +%Y-%m-%d)"

# Find items due for review (spaced repetition schedule)
python3 << 'EOF'
import json
from datetime import datetime

with open("$HOME/.learning/mastery.json") as f:
    items = json.load(f)

due_items = [
    item for item in items
    if datetime.fromisoformat(item["next_review"]) <= datetime.now()
]

# Sort by priority: low mastery + overdue = highest priority
due_items.sort(key=lambda x: x["mastery_score"] - x["days_overdue"] * 0.1)

print(f"\n=== Practice Session ({len(due_items)} items due) ===\n")
for item in due_items[:10]:
    print(f"  [{item['difficulty']}] {item['topic']}")
    print(f"      Last score: {item['last_score']}/5 | Mastery: {item['mastery_score']:.0%}")
    print()
EOF
```

## 5. Interleaving Strategy

Mix topics from different domains to strengthen connections:

```python
import random
from typing import Sequence

def create_interleaved_session(
    due_items: Sequence,
    session_size: int = 10,
    domain_mix_ratio: float = 0.3
) -> list:
    """Create a practice session that interleaves domains."""
    # Group by domain
    domains = {}
    for item in due_items:
        domain = item.get("domain", "general")
        domains.setdefault(domain, []).append(item)
    
    session = []
    # Ensure primary focus items (highest priority)
    primary = sorted(due_items, key=lambda x: x["priority"])[:int(session_size * 0.7)]
    session.extend(primary)
    
    # Add cross-domain items for interleaving
    other_domains = [d for d in domains if d != primary[0].get("domain")]
    for domain in other_domains:
        if len(session) >= session_size:
            break
        candidates = domains[domain]
        session.append(random.choice(candidates))
    
    # Shuffle to prevent domain clustering
    random.shuffle(session)
    return session[:session_size]
```

## 6. Performance Tracking Dashboard

Monitor learning velocity and identify plateaus:

```bash
#!/bin/bash
# learning-dashboard.sh — Weekly performance summary
echo "=== Learning Performance Dashboard ==="
echo "Week of $(date -d 'last monday' +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)"
echo ""

# Metrics from practice logs
SESSIONS=$(find ~/.learning/logs -name "*.json" -mtime -7 | wc -l)
AVG_SCORE=$(find ~/.learning/logs -name "*.json" -mtime -7 -exec cat {} \; | \
  python3 -c "import sys,json; scores=[json.loads(l)['score'] for l in sys.stdin]; print(f'{sum(scores)/len(scores):.1f}/5' if scores else 'N/A')")

echo "Sessions completed: $SESSIONS"
echo "Average score: $AVG_SCORE"
echo ""
echo "Domain breakdown:"
find ~/.learning/logs -name "*.json" -mtime -7 -exec cat {} \; | \
  python3 -c "
import sys, json
from collections import Counter
domains = Counter()
for line in sys.stdin:
    data = json.loads(line)
    domains[data['domain']] += 1
for domain, count in domains.most_common():
    print(f'  {domain}: {count} reviews')
"
```

## 7. Plateau Detection and Breakthrough

Identify when learning stalls and trigger strategy changes:

```python
def detect_plateau(scores: list, window: int = 10, threshold: float = 0.05) -> bool:
    """Detect if recent scores show no improvement."""
    if len(scores) < window * 2:
        return False
    
    recent = scores[-window:]
    previous = scores[-window*2:-window]
    
    recent_avg = sum(recent) / len(recent)
    previous_avg = sum(previous) / len(previous)
    
    improvement = recent_avg - previous_avg
    return abs(improvement) < threshold

def suggest_breakthrough_strategy(domain: str, current_level: str) -> list:
    """Suggest strategies to break through a learning plateau."""
    strategies = [
        "Teach the concept to another (Feynman technique)",
        "Attempt problems one difficulty level above current",
        "Study from a different source or perspective",
        "Focus on the weakest sub-skill within this domain",
        "Take a 2-day break then return with fresh approach",
        "Combine with a related domain for cross-pollination",
    ]
    return strategies
```

## 8. Integration Points

Connect adaptive learning to the broader knowledge system:

- Decay detection feeds items into the spaced repetition queue
- Mastery metrics inform which skills to prioritize in practice
- Cross-domain transfer scores identify synergies between skill areas
- Plateau detection triggers strategy rotation automatically
- Performance data drives difficulty scaling decisions
- Weekly reports highlight areas needing focused attention
