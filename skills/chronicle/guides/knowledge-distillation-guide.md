# Knowledge Distillation Guide

> Methods for extracting actionable insights from raw session logs and operational data. Covers progressive summarization, signal-to-noise filtering, pattern recognition, and building a searchable knowledge base from daily operations.

---

## 1. Progressive Summarization Pipeline

Raw logs contain noise. Distillation extracts signal through multiple passes, each reducing volume while increasing density.

```python
# Python — Three-pass distillation pipeline
from dataclasses import dataclass
from datetime import datetime

@dataclass(frozen=True)
class RawEntry:
    timestamp: datetime
    content: str
    source: str
    tags: tuple[str, ...]

@dataclass(frozen=True)
class DistilledInsight:
    summary: str
    evidence: tuple[str, ...]
    confidence: float
    category: str
    actionable: bool

def pass_one_filter(entries: list[RawEntry]) -> list[RawEntry]:
    """Pass 1: Remove noise — routine events, duplicates, heartbeats."""
    noise_patterns = [
        'health check passed',
        'scheduled task completed normally',
        'connection pool refreshed',
        'cache hit ratio:',
    ]
    return [
        entry for entry in entries
        if not any(pattern in entry.content.lower() for pattern in noise_patterns)
    ]

def pass_two_cluster(entries: list[RawEntry]) -> dict[str, list[RawEntry]]:
    """Pass 2: Group related entries by topic/incident."""
    clusters = {}
    for entry in entries:
        # Use first tag as primary cluster key
        key = entry.tags[0] if entry.tags else 'uncategorized'
        clusters.setdefault(key, []).append(entry)
    return clusters

def pass_three_distill(cluster: list[RawEntry]) -> DistilledInsight:
    """Pass 3: Extract the key insight from a cluster of related entries."""
    # Identify the most significant entry (longest, most tags, or error-level)
    significant = max(cluster, key=lambda e: len(e.content))
    return DistilledInsight(
        summary=significant.content[:200],
        evidence=tuple(e.content[:100] for e in cluster[:5]),
        confidence=min(1.0, len(cluster) / 10),
        category=cluster[0].tags[0] if cluster[0].tags else 'general',
        actionable=any('action' in e.content.lower() or 'fix' in e.content.lower() for e in cluster)
    )
```

## 2. Signal-to-Noise Classification

```python
# Python — Classify log entries by information value
from enum import IntEnum

class SignalLevel(IntEnum):
    NOISE = 0       # Routine, expected, no action needed
    CONTEXT = 1     # Useful background, supports other entries
    SIGNAL = 2      # Notable event, worth recording
    INSIGHT = 3     # Key learning, changes understanding
    CRITICAL = 4    # Must-remember, affects future decisions

SIGNAL_INDICATORS = {
    SignalLevel.CRITICAL: ['vulnerability found', 'breach detected', 'data loss', 'zero-day'],
    SignalLevel.INSIGHT: ['root cause:', 'lesson learned:', 'pattern identified:', 'workaround:'],
    SignalLevel.SIGNAL: ['error', 'warning', 'failed', 'timeout', 'unexpected'],
    SignalLevel.CONTEXT: ['started', 'completed', 'configured', 'deployed'],
}

def classify_signal(content: str) -> SignalLevel:
    """Classify an entry's information value for distillation priority."""
    content_lower = content.lower()
    for level in sorted(SIGNAL_INDICATORS.keys(), reverse=True):
        if any(indicator in content_lower for indicator in SIGNAL_INDICATORS[level]):
            return level
    return SignalLevel.NOISE
```

## 3. Daily-to-Memory Distillation Workflow

```bash
# Bash — Automated daily log distillation script
#!/bin/bash
# Run at end of day to distill session logs into MEMORY.md candidates

DAILY_LOG="memory/$(date +%Y-%m-%d).md"
MEMORY_FILE="MEMORY.md"

# Extract lines marked with decision/insight/learning tags
grep -E "^(##|###|\*\*)" "$DAILY_LOG" | \
  grep -iE "(decision|insight|learned|important|critical|pattern)" \
  > /tmp/distill_candidates.txt

# Count entries by category
echo "=== Distillation Summary ==="
echo "Decisions: $(grep -ci 'decision' /tmp/distill_candidates.txt)"
echo "Insights:  $(grep -ci 'insight\|learned' /tmp/distill_candidates.txt)"
echo "Critical:  $(grep -ci 'critical\|important' /tmp/distill_candidates.txt)"
echo ""
echo "=== Candidates for MEMORY.md ==="
cat /tmp/distill_candidates.txt
```

## 4. Pattern Recognition Across Sessions

```python
# Python — Detect recurring patterns across multiple daily logs
from collections import Counter
from pathlib import Path
import re

def find_recurring_patterns(
    memory_dir: Path,
    min_occurrences: int = 3,
    lookback_days: int = 30
) -> list[dict]:
    """Identify patterns that repeat across multiple sessions."""
    # Extract key phrases from daily logs
    phrase_occurrences = Counter()
    phrase_dates = {}

    for log_file in sorted(memory_dir.glob("*.md"))[-lookback_days:]:
        content = log_file.read_text()
        date = log_file.stem  # YYYY-MM-DD

        # Extract notable phrases (headers, bold text, tagged items)
        phrases = re.findall(r'(?:##\s+|^\*\*)(.*?)(?:\*\*|$)', content, re.MULTILINE)

        for phrase in phrases:
            normalized = phrase.strip().lower()
            if len(normalized) > 10:  # Skip trivial phrases
                phrase_occurrences[normalized] += 1
                phrase_dates.setdefault(normalized, []).append(date)

    # Return patterns that recur above threshold
    recurring = []
    for phrase, count in phrase_occurrences.most_common():
        if count >= min_occurrences:
            recurring.append({
                'pattern': phrase,
                'occurrences': count,
                'dates': phrase_dates[phrase],
                'first_seen': phrase_dates[phrase][0],
                'last_seen': phrase_dates[phrase][-1],
            })

    return recurring
```

## 5. Knowledge Base Structure

```yaml
# YAML — Knowledge base entry schema for distilled insights
---
id: "insight-2025-001"
date_distilled: "2025-03-15"
source_sessions:
  - "2025-03-10"
  - "2025-03-12"
  - "2025-03-14"
category: "attack-patterns"
confidence: 0.9
summary: |
  WAF bypass via chunked transfer encoding is effective against
  ModSecurity CRS v3.x when rule 920420 is not enabled.
evidence:
  - "Tested against 3 different ModSecurity deployments"
  - "Confirmed bypass on CRS 3.3.2 and 3.3.4"
  - "Blocked by CRS 4.0+ with default ruleset"
actionable_next_steps:
  - "Add chunked encoding test to standard WAF bypass checklist"
  - "Document CRS version detection methodology"
tags: ["waf-bypass", "modsecurity", "chunked-encoding"]
supersedes: null  # ID of older insight this replaces
---
```

## 6. Distillation Quality Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| Compression ratio | Raw entries / distilled insights | 10:1 to 50:1 |
| Actionability rate | % of insights with clear next steps | >60% |
| Recall accuracy | Can you reconstruct context from insight? | Yes for all CRITICAL |
| Staleness | Days since last review/update | <30 days |
| Cross-reference density | Links to related insights | >1 per insight |

The goal of distillation is not to summarize everything — it is to preserve only what changes future behavior. If an insight does not affect how you approach the next engagement, it belongs in the daily log archive, not in long-term memory.
