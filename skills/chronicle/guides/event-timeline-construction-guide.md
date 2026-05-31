# Event Timeline Construction Guide

> Techniques for building chronological event timelines from disparate log sources. Covers timestamp normalization, event correlation, gap analysis, and visualization of attack sequences across multiple systems.

---

## 1. Timestamp Normalization

Logs from different systems use different time formats and zones. Normalize everything to UTC with nanosecond precision before correlation.

```python
# Python — Multi-format timestamp normalizer
from datetime import datetime, timezone
import re

TIMESTAMP_FORMATS = [
    ('%Y-%m-%dT%H:%M:%S.%fZ', 'ISO 8601 UTC'),
    ('%Y-%m-%dT%H:%M:%S%z', 'ISO 8601 with offset'),
    ('%b %d %H:%M:%S', 'Syslog (no year)'),
    ('%d/%b/%Y:%H:%M:%S %z', 'Apache/nginx combined'),
    ('%Y-%m-%d %H:%M:%S,%f', 'Python logging default'),
    ('%a %b %d %H:%M:%S %Y', 'ctime format'),
]

def normalize_timestamp(raw: str, source_timezone: str = 'UTC') -> datetime:
    """Parse any common log timestamp to UTC datetime."""
    for fmt, name in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(raw.strip(), fmt)
            if dt.tzinfo is None:
                # Assume source timezone if not specified
                from zoneinfo import ZoneInfo
                dt = dt.replace(tzinfo=ZoneInfo(source_timezone))
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse timestamp: {raw}")

# Unix epoch handling
def epoch_to_utc(epoch: float) -> datetime:
    """Convert Unix epoch (seconds or milliseconds) to UTC."""
    if epoch > 1e12:  # milliseconds
        epoch = epoch / 1000
    return datetime.fromtimestamp(epoch, tz=timezone.utc)
```

## 2. Event Correlation Across Sources

```python
# Python — Correlate events from multiple log sources by time proximity
from dataclasses import dataclass, field
from typing import Optional

@dataclass(frozen=True)
class TimelineEvent:
    timestamp: datetime
    source: str
    event_type: str
    description: str
    raw_data: str
    correlation_ids: tuple = field(default_factory=tuple)

def correlate_events(
    events: list[TimelineEvent],
    window_seconds: float = 2.0
) -> list[list[TimelineEvent]]:
    """Group events that occur within a time window into correlated clusters."""
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    clusters = []
    current_cluster = [sorted_events[0]] if sorted_events else []

    for event in sorted_events[1:]:
        time_diff = (event.timestamp - current_cluster[-1].timestamp).total_seconds()
        if time_diff <= window_seconds:
            current_cluster.append(event)
        else:
            clusters.append(current_cluster)
            current_cluster = [event]

    if current_cluster:
        clusters.append(current_cluster)

    return clusters
```

## 3. Gap Analysis and Missing Event Detection

```bash
# Bash — Detect gaps in log continuity
# Find time gaps larger than expected interval in syslog

awk '
BEGIN { prev_epoch = 0; gap_threshold = 300 }
{
    # Parse syslog timestamp (assumes current year)
    cmd = "date -d \"" $1 " " $2 " " $3 "\" +%s 2>/dev/null"
    cmd | getline epoch
    close(cmd)

    if (prev_epoch > 0 && (epoch - prev_epoch) > gap_threshold) {
        printf "GAP DETECTED: %d seconds between %s and line %d\n", \
            (epoch - prev_epoch), prev_time, NR
    }
    prev_epoch = epoch
    prev_time = $1 " " $2 " " $3
}
' /var/log/syslog
```

```python
# Python — Structured gap analysis with expected event cadence
from datetime import timedelta

def find_timeline_gaps(
    events: list[TimelineEvent],
    expected_interval: timedelta,
    tolerance: float = 2.0
) -> list[dict]:
    """Identify gaps where expected events are missing."""
    gaps = []
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    for i in range(1, len(sorted_events)):
        actual_gap = sorted_events[i].timestamp - sorted_events[i-1].timestamp
        if actual_gap > expected_interval * tolerance:
            gaps.append({
                'start': sorted_events[i-1].timestamp,
                'end': sorted_events[i].timestamp,
                'duration': actual_gap,
                'expected': expected_interval,
                'preceding_event': sorted_events[i-1],
                'following_event': sorted_events[i],
                'missing_count': int(actual_gap / expected_interval) - 1
            })

    return gaps
```

## 4. Multi-Source Timeline Assembly

```bash
# Bash — Merge and sort logs from multiple sources into unified timeline
# Normalize different log formats into a common sortable format

# Step 1: Convert each source to unified format (epoch | source | message)
paste <(
  awk '{cmd="date -d \""$1" "$2" "$3"\" +%s"; cmd|getline ts; close(cmd); print ts}' /var/log/auth.log
) <(
  awk '{$1=$2=$3=""; print "auth |" $0}' /var/log/auth.log
) > /tmp/timeline_auth.txt

paste <(
  awk -F'[][]' '{print $2}' /var/log/nginx/access.log
) <(
  awk '{print "nginx | " $0}' /var/log/nginx/access.log
) > /tmp/timeline_nginx.txt

# Step 2: Merge and sort by epoch
cat /tmp/timeline_auth.txt /tmp/timeline_nginx.txt | \
  sort -n -t'|' -k1 | \
  awk -F'|' '{printf "[%s] %s | %s\n", strftime("%Y-%m-%d %H:%M:%S", $1), $2, $3}'
```

## 5. Attack Sequence Visualization

```python
# Python — Generate Mermaid timeline diagram from events
def generate_mermaid_timeline(clusters: list[list[TimelineEvent]]) -> str:
    """Create a Mermaid sequence diagram from correlated event clusters."""
    lines = ["sequenceDiagram"]
    participants = set()

    for cluster in clusters:
        for event in cluster:
            participants.add(event.source)

    for p in sorted(participants):
        lines.append(f"    participant {p}")

    lines.append("")

    for cluster in clusters:
        if len(cluster) > 1:
            lines.append(f"    Note over {cluster[0].source}: {cluster[0].timestamp.strftime('%H:%M:%S')}")
        for event in cluster:
            lines.append(f"    {event.source}->>+{event.source}: {event.event_type}: {event.description[:40]}")

    return "\n".join(lines)
```

## 6. Timeline Quality Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| Coverage | % of time window with events | >95% |
| Source diversity | Number of log sources included | All relevant systems |
| Correlation rate | % of events linked to clusters | >70% |
| Gap count | Unexplained gaps in timeline | 0 critical gaps |
| Timestamp confidence | Events with verified timestamps | 100% |

A complete timeline should have no unexplained gaps during the incident window. Every gap must be investigated — it may indicate log tampering, system downtime, or collection failure.
