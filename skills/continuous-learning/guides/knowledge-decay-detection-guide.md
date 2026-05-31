# Knowledge Decay Detection Guide

> Identify when stored knowledge becomes stale, outdated, or inaccurate. Implement automated staleness detection, refresh triggers, and version tracking to maintain a reliable knowledge base.

## 1. Staleness Detection Framework

Define decay indicators and thresholds for knowledge items:

```yaml
# knowledge-decay-config.yaml
decay_rules:
  tool_knowledge:
    max_age_days: 90
    refresh_trigger: "version_change"
    staleness_indicators:
      - deprecated_flag_usage
      - removed_feature_reference
      - outdated_version_number
  
  vulnerability_data:
    max_age_days: 30
    refresh_trigger: "cve_update"
    staleness_indicators:
      - patched_vulnerability_reference
      - outdated_exploit_technique
  
  methodology:
    max_age_days: 180
    refresh_trigger: "framework_update"
    staleness_indicators:
      - superseded_technique
      - deprecated_protocol
```

## 2. Automated Version Tracking

Monitor tool versions and flag knowledge that references outdated versions:

```bash
#!/bin/bash
# version-tracker.sh — Compare installed vs. documented tool versions
KNOWLEDGE_DIR="$HOME/knowledge-base/tools"
REPORT="/tmp/version-drift-report.txt"

echo "=== Version Drift Report $(date +%Y-%m-%d) ===" > "$REPORT"

# Check each documented tool against installed version
while IFS='|' read -r tool expected_version; do
  actual=$(dpkg -s "$tool" 2>/dev/null | grep "^Version:" | awk '{print $2}')
  if [ -z "$actual" ]; then
    echo "[MISSING] $tool — not installed" >> "$REPORT"
  elif [ "$actual" != "$expected_version" ]; then
    echo "[DRIFT] $tool — documented: $expected_version, actual: $actual" >> "$REPORT"
  fi
done < "$KNOWLEDGE_DIR/version-manifest.txt"

# Count drift items
DRIFT_COUNT=$(grep -c "\[DRIFT\]" "$REPORT")
echo "[*] Found $DRIFT_COUNT version drifts"
cat "$REPORT"
```

## 3. Content Freshness Scoring

Assign decay scores to knowledge items based on multiple signals:

```python
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass(frozen=True)
class KnowledgeItem:
    topic: str
    last_verified: datetime
    source_version: str
    access_count: int
    confidence: float

def calculate_decay_score(item: KnowledgeItem, current_date: datetime) -> float:
    """Score from 0.0 (fresh) to 1.0 (fully decayed)."""
    age_days = (current_date - item.last_verified).days
    
    # Time-based decay (exponential)
    time_decay = min(1.0, age_days / 180.0)
    
    # Access-based signal (unused knowledge decays faster)
    access_factor = 1.0 if item.access_count == 0 else max(0.3, 1.0 - (item.access_count / 50))
    
    # Confidence degradation
    confidence_factor = 1.0 - item.confidence
    
    # Weighted combination
    score = (time_decay * 0.5) + (access_factor * 0.3) + (confidence_factor * 0.2)
    return round(min(1.0, score), 3)

def get_refresh_candidates(items: list, threshold: float = 0.6) -> list:
    """Return items that need refreshing."""
    now = datetime.now()
    scored = [(item, calculate_decay_score(item, now)) for item in items]
    return [(item, score) for item, score in scored if score >= threshold]
```

## 4. CVE and Exploit Freshness Monitoring

Track whether referenced vulnerabilities have been patched:

```bash
#!/bin/bash
# cve-freshness-check.sh — Verify referenced CVEs are still relevant
KNOWLEDGE_FILES=$(find ~/knowledge-base -name "*.md" -type f)

echo "[*] Scanning knowledge base for CVE references..."

grep -roh "CVE-[0-9]\{4\}-[0-9]\{4,\}" $KNOWLEDGE_FILES | sort -u | while read -r cve; do
  # Query NVD for patch status
  STATUS=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); \
    vulns=d.get('vulnerabilities',[]); \
    print(vulns[0]['cve']['metrics'].get('cvssMetricV31',[{}])[0].get('exploitabilityScore','unknown') if vulns else 'not_found')" 2>/dev/null)
  
  echo "$cve: exploitability=$STATUS"
done
```

## 5. Refresh Trigger System

Automate knowledge refresh based on external events:

```python
from dataclasses import dataclass
from typing import Callable

@dataclass(frozen=True)
class RefreshTrigger:
    name: str
    condition: str
    action: str
    priority: int

TRIGGERS = [
    RefreshTrigger(
        name="tool_major_version",
        condition="major_version_increment",
        action="full_rescan",
        priority=1
    ),
    RefreshTrigger(
        name="cve_published",
        condition="new_cve_in_domain",
        action="update_vulnerability_notes",
        priority=2
    ),
    RefreshTrigger(
        name="technique_deprecated",
        condition="mitre_attack_retirement",
        action="flag_and_replace",
        priority=1
    ),
    RefreshTrigger(
        name="periodic_review",
        condition="age_exceeds_threshold",
        action="schedule_verification",
        priority=3
    ),
]

def evaluate_triggers(knowledge_item, events: list) -> list:
    """Determine which refresh actions are needed."""
    actions = []
    for trigger in TRIGGERS:
        for event in events:
            if event.matches(trigger.condition):
                actions.append((trigger.priority, trigger.action, knowledge_item))
    return sorted(actions, key=lambda x: x[0])
```

## 6. Knowledge Dependency Graph

Track which knowledge items depend on others for cascading invalidation:

```yaml
# dependency-graph.yaml
dependencies:
  nmap_scanning:
    depends_on: [nmap_version, nse_scripts_catalog]
    invalidated_by: [nmap_major_release]
  
  metasploit_exploitation:
    depends_on: [msf_version, exploit_db_sync]
    invalidated_by: [msf_major_release, ruby_version_change]
  
  web_testing_methodology:
    depends_on: [owasp_top10_version, burp_version]
    invalidated_by: [owasp_revision, new_attack_class]
```

## 7. Decay Report Generation

Produce actionable reports for knowledge maintenance:

```bash
#!/bin/bash
# generate-decay-report.sh
KNOWLEDGE_DIR="$1"
THRESHOLD_DAYS="${2:-90}"

echo "# Knowledge Decay Report"
echo "Generated: $(date -Iseconds)"
echo "Threshold: ${THRESHOLD_DAYS} days"
echo ""
echo "## Stale Items (last modified > ${THRESHOLD_DAYS} days ago)"
echo ""

find "$KNOWLEDGE_DIR" -name "*.md" -type f -mtime "+${THRESHOLD_DAYS}" | \
  while read -r file; do
    AGE=$(( ($(date +%s) - $(stat -f%m "$file")) / 86400 ))
    echo "- **$(basename "$file")** — ${AGE} days old"
  done

echo ""
echo "## Recently Updated (last 7 days)"
find "$KNOWLEDGE_DIR" -name "*.md" -type f -mtime -7 | \
  while read -r file; do
    echo "- $(basename "$file")"
  done
```

## 8. Integration with Learning Workflow

Connect decay detection to the adaptive learning system:

- Items with decay score > 0.7 are queued for immediate review
- Items accessed frequently but never verified get priority refresh
- Cascading invalidation propagates through the dependency graph
- Monthly decay reports drive the knowledge maintenance schedule
- Version drift triggers automatic re-testing of documented procedures
- Confidence scores decrease automatically with age unless re-verified
