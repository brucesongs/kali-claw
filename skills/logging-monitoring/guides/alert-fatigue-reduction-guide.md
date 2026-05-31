# Alert Fatigue Reduction Guide

> Companion to `skills/logging-monitoring/SKILL.md`. This guide covers alert tuning, correlation rules, noise reduction strategies, and threshold optimization to maintain effective security monitoring without overwhelming analysts.

---

## 1. Measuring Alert Fatigue

Before optimizing, quantify the current state of alert fatigue in your environment:

```bash
# Calculate alert-to-incident ratio (target: < 10:1)
# Query SIEM for total alerts vs confirmed incidents in past 30 days
curl -s "http://siem:9200/alerts-*/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"range":{"@timestamp":{"gte":"now-30d"}}}}' | \
  jq '.count' # Total alerts

curl -s "http://siem:9200/incidents-*/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"range":{"@timestamp":{"gte":"now-30d"}}}}' | \
  jq '.count' # Confirmed incidents

# Calculate false positive rate by alert rule
curl -s "http://siem:9200/alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {"range": {"@timestamp": {"gte": "now-30d"}}},
    "aggs": {
      "by_rule": {
        "terms": {"field": "rule.name.keyword", "size": 50},
        "aggs": {
          "false_positives": {
            "filter": {"term": {"disposition": "false_positive"}}
          }
        }
      }
    }
  }' | jq '.aggregations.by_rule.buckets[] | 
  {rule: .key, total: .doc_count, fp: .false_positives.doc_count, 
   fp_rate: (.false_positives.doc_count / .doc_count * 100)}'
```

---

## 2. Alert Threshold Optimization

Static thresholds generate noise. Use statistical baselines for dynamic thresholds:

```python
#!/usr/bin/env python3
"""Calculate dynamic alert thresholds based on historical baselines."""

from dataclasses import dataclass
import statistics

@dataclass(frozen=True)
class ThresholdConfig:
    metric_name: str
    baseline_mean: float
    baseline_stddev: float
    warning_multiplier: float  # typically 2.0
    critical_multiplier: float  # typically 3.0

def calculate_dynamic_threshold(
    historical_values: list[float],
    warning_sigma: float = 2.0,
    critical_sigma: float = 3.0
) -> ThresholdConfig:
    """Calculate thresholds using standard deviation from baseline."""
    mean = statistics.mean(historical_values)
    stddev = statistics.stdev(historical_values)
    return ThresholdConfig(
        metric_name="",
        baseline_mean=mean,
        baseline_stddev=stddev,
        warning_multiplier=warning_sigma,
        critical_multiplier=critical_sigma
    )

# Example: failed login threshold
# Instead of static "alert on > 5 failures"
# Use: "alert when failures exceed 3 standard deviations from normal"
hourly_failures_last_30d = [2, 3, 1, 4, 2, 3, 5, 2, 1, 3, 2, 4, 3, 2, 1,
                            3, 2, 4, 2, 3, 1, 2, 3, 4, 2, 3, 2, 1, 3, 2]
threshold = calculate_dynamic_threshold(hourly_failures_last_30d)
warning_level = threshold.baseline_mean + (threshold.warning_multiplier * threshold.baseline_stddev)
critical_level = threshold.baseline_mean + (threshold.critical_multiplier * threshold.baseline_stddev)
print(f"Baseline: {threshold.baseline_mean:.1f} failures/hour")
print(f"Warning threshold: {warning_level:.1f}")
print(f"Critical threshold: {critical_level:.1f}")
```

---

## 3. Alert Correlation Rules

Reduce volume by correlating related alerts into single incidents:

```yaml
# Sigma-style correlation rules
# Instead of 50 individual "failed login" alerts, generate 1 "brute force" alert

title: Brute Force Attack Correlation
id: bf-correlation-001
description: Correlate multiple failed logins into single brute force alert
correlation:
  type: event_count
  rules:
    - failed_login_rule
  group-by:
    - source.ip
    - destination.host
  timespan: 5m
  condition:
    gte: 10
level: high
---
# Lateral movement correlation
title: Lateral Movement Detection
id: lateral-001
description: Correlate authentication events across multiple hosts
correlation:
  type: temporal
  rules:
    - successful_login_rule
  group-by:
    - source.user
  timespan: 15m
  condition:
    unique_values:
      field: destination.host
      gte: 3
level: critical
---
# Suppress duplicate alerts for same source within time window
title: Alert Deduplication
id: dedup-001
suppression:
  group-by:
    - rule.id
    - source.ip
    - destination.host
  timespan: 1h
  keep: first
```

---

## 4. Allowlisting and Suppression Strategies

Systematically reduce known-good noise without losing visibility:

```bash
# Build context-aware allowlists
# Step 1: Identify top noise generators
curl -s "http://siem:9200/alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {
      "bool": {
        "must": [
          {"range": {"@timestamp": {"gte": "now-7d"}}},
          {"term": {"disposition": "false_positive"}}
        ]
      }
    },
    "aggs": {
      "noise_sources": {
        "composite": {
          "sources": [
            {"rule": {"terms": {"field": "rule.name.keyword"}}},
            {"source": {"terms": {"field": "source.ip"}}}
          ]
        }
      }
    }
  }' | jq '.aggregations.noise_sources.buckets[:10]'

# Step 2: Create targeted suppression rules (not blanket exclusions)
cat > suppression_rules.yaml << 'EOF'
suppressions:
  - name: "Vulnerability scanner noise"
    condition:
      source.ip: ["10.0.1.50", "10.0.1.51"]  # Scanner IPs
      rule.category: "web-attack"
    action: suppress
    reason: "Authorized vulnerability scanner — ticket SEC-1234"
    review_date: "2026-07-01"

  - name: "Backup system file access"
    condition:
      source.user: "backup-svc"
      rule.name: "Sensitive file access"
      destination.path: "/data/backups/*"
    action: reduce_severity
    new_severity: "low"
    reason: "Expected backup operations — ticket OPS-567"
    review_date: "2026-07-01"

  - name: "Health check noise"
    condition:
      source.ip: ["10.0.0.1"]  # Load balancer
      http.path: ["/health", "/status", "/ping"]
    action: suppress
    reason: "Load balancer health checks"
    review_date: "2026-09-01"
EOF
```

---

## 5. Alert Priority Scoring

Replace binary alert/no-alert with risk-scored prioritization:

```python
#!/usr/bin/env python3
"""Risk-based alert scoring to prioritize analyst attention."""

from dataclasses import dataclass

@dataclass(frozen=True)
class AlertContext:
    source_ip: str
    destination_host: str
    user: str
    rule_severity: str
    asset_criticality: str
    time_of_day: str
    is_known_attacker: bool
    previous_alerts_24h: int

def calculate_priority_score(alert: AlertContext) -> float:
    """Score alert 0-100 based on contextual risk factors."""
    score = 0.0

    # Base severity score
    severity_scores = {"critical": 40, "high": 30, "medium": 20, "low": 10}
    score += severity_scores.get(alert.rule_severity, 10)

    # Asset criticality multiplier
    criticality_multipliers = {"crown_jewel": 2.0, "high": 1.5, "medium": 1.0, "low": 0.5}
    score *= criticality_multipliers.get(alert.asset_criticality, 1.0)

    # Threat intelligence enrichment
    if alert.is_known_attacker:
        score += 20

    # Behavioral anomaly (alerts outside business hours)
    if alert.time_of_day in ("night", "weekend"):
        score += 10

    # Alert velocity (many alerts from same source = campaign)
    if alert.previous_alerts_24h > 10:
        score += 15
    elif alert.previous_alerts_24h > 5:
        score += 10

    return min(score, 100.0)

# Only page on-call for score > 80
# Queue for next-business-day review: 40-80
# Auto-close with logging: < 40
```

---

## 6. SIEM Rule Tuning Workflow

Systematic process for reducing false positives without losing true positives:

```bash
# Step 1: Identify rules with highest false positive rates
# Export last 30 days of alert dispositions
curl -s "http://siem:9200/alerts-*/_search?scroll=1m" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1000,
    "query": {"range": {"@timestamp": {"gte": "now-30d"}}},
    "_source": ["rule.name", "disposition", "source.ip", "destination.host"]
  }' > alert_export.json

# Step 2: Calculate per-rule metrics
cat alert_export.json | jq -r '.hits.hits[]._source | 
  [.["rule.name"], .disposition] | @csv' | \
  sort | uniq -c | sort -rn | head -20

# Step 3: For each noisy rule, analyze the false positives
# What do they have in common? Source IP? Time? User?
cat alert_export.json | jq '.hits.hits[]._source | 
  select(.["rule.name"] == "Suspicious PowerShell") |
  select(.disposition == "false_positive")' | \
  jq -s 'group_by(.["source.ip"]) | 
  map({ip: .[0]["source.ip"], count: length}) | 
  sort_by(-.count)'

# Step 4: Add targeted exception (not disable the rule)
# "Suspicious PowerShell from SCCM server" → suppress
# "Suspicious PowerShell from user workstation" → keep alerting
```

---

## 7. Alert Routing and Escalation Tiers

Not every alert needs human review. Build automated tiers:

```yaml
# alert-routing.yaml — defines handling per severity/confidence
routing_rules:
  - name: "Tier 0 — Auto-remediate"
    conditions:
      confidence: high
      severity: [low, medium]
      playbook_available: true
    action:
      type: auto_remediate
      playbook: "block_ip"
      notify: slack_channel_security_auto
      review: weekly_batch

  - name: "Tier 1 — SOC analyst queue"
    conditions:
      confidence: [medium, high]
      severity: [medium, high]
    action:
      type: queue
      team: soc_l1
      sla: 4h
      notify: pagerduty_low

  - name: "Tier 2 — Immediate escalation"
    conditions:
      severity: critical
      OR:
        - asset_criticality: crown_jewel
        - is_known_apt: true
        - alert_score_gt: 80
    action:
      type: page
      team: soc_l2
      sla: 15m
      notify: pagerduty_high
      create_incident: true

  - name: "Tier 3 — Suppress and log"
    conditions:
      confidence: low
      severity: low
      in_allowlist: true
    action:
      type: suppress
      log: true
      review: monthly
```

---

## 8. Measuring Improvement

Track alert fatigue metrics over time to validate tuning effectiveness:

```bash
# Weekly alert fatigue dashboard metrics
cat > fatigue_metrics_query.json << 'EOF'
{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-7d"}}},
  "aggs": {
    "total_alerts": {"value_count": {"field": "alert.id"}},
    "true_positives": {
      "filter": {"term": {"disposition": "true_positive"}}
    },
    "false_positives": {
      "filter": {"term": {"disposition": "false_positive"}}
    },
    "mean_time_to_triage": {
      "avg": {"field": "triage_duration_minutes"}
    },
    "alerts_per_analyst_per_shift": {
      "avg": {"field": "analyst_alert_count"}
    },
    "rules_with_zero_tp": {
      "filter": {
        "bool": {
          "must": [{"range": {"alert_count": {"gte": 10}}}],
          "must_not": [{"exists": {"field": "true_positive_count"}}]
        }
      }
    }
  }
}
EOF

# Target metrics for healthy alert environment:
# - Alert-to-incident ratio: < 10:1
# - False positive rate: < 20%
# - Mean time to triage: < 15 minutes
# - Alerts per analyst per shift: < 50
# - Rules with 0% true positive rate: candidates for removal
curl -s "http://siem:9200/alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d @fatigue_metrics_query.json | \
  jq '{
    total: .aggregations.total_alerts.value,
    true_pos: .aggregations.true_positives.doc_count,
    false_pos: .aggregations.false_positives.doc_count,
    avg_triage_min: .aggregations.mean_time_to_triage.value,
    fp_rate_pct: (.aggregations.false_positives.doc_count / .aggregations.total_alerts.value * 100)
  }'
```

Effective alert fatigue reduction is iterative. Start by eliminating the top 5 noisiest rules (which typically account for 60-80% of false positives), then refine thresholds monthly based on analyst feedback and disposition data.
