# Risk Prioritization Matrix Guide

> Building risk prioritization matrices that contextualize CVSS scores with business impact, exploitability evidence, and remediation ordering.

## Introduction

Raw vulnerability scores tell only part of the story. A CVSS 9.8 on an internal development server with no sensitive data and strong network segmentation is less urgent than a CVSS 7.5 on an internet-facing payment processing system. Risk prioritization matrices bridge the gap between technical vulnerability scores and business-driven remediation decisions by incorporating exploitability evidence, business impact, exposure factors, and compensating controls into a single actionable priority queue.

This guide covers the complete risk prioritization pipeline: CVSS contextualization, business impact mapping, exploitability scoring, priority matrix generation, and remediation ordering with SLA enforcement.

## 1. CVSS Contextualization

Raw CVSS scores lack organizational context. Adjust with environmental and threat metrics.

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class ContextualizedRisk:
    finding_id: str
    cvss_base: float
    exploitability_modifier: float  # 0.5 - 2.0
    business_criticality: float  # 0.0 - 1.0
    exposure_factor: float  # 0.0 - 1.0 (internet-facing = 1.0)
    compensating_controls: float  # 0.0 - 1.0 (reduces score)

    @property
    def contextualized_score(self) -> float:
        adjusted = (
            self.cvss_base
            * self.exploitability_modifier
            * (0.4 + 0.6 * self.business_criticality)
            * (0.3 + 0.7 * self.exposure_factor)
            * (1.0 - 0.5 * self.compensating_controls)
        )
        return min(round(adjusted, 2), 10.0)
```

### Contextualization Factor Weights Explained

Each factor in the contextualization formula adjusts the raw CVSS score based on real-world conditions:

| Factor | Formula Weight | Range | Effect |
|--------|---------------|-------|--------|
| Exploitability Modifier | Direct multiplier | 0.5 - 2.0 | Halves theoretical findings, doubles actively exploited ones |
| Business Criticality | 0.4 + 0.6 * value | 0.4 - 1.0 | Uncritical assets score at 40%, critical assets at 100% |
| Exposure Factor | 0.3 + 0.7 * value | 0.3 - 1.0 | Internal-only at 30%, internet-facing at 100% |
| Compensating Controls | 1.0 - 0.5 * value | 0.5 - 1.0 | Full controls reduce score by 50%, no controls leave unchanged |

### Contextualization Examples

| Finding | Raw CVSS | Exploit Mod | Business | Exposure | Controls | Context Score |
|---------|----------|-------------|----------|----------|----------|---------------|
| RCE on payment API | 9.8 | 1.7 (weaponized) | 1.0 | 1.0 | 0.0 | 9.8 |
| SQLi on internal tool | 8.1 | 1.3 (public PoC) | 0.3 | 0.2 | 0.2 | 3.1 |
| XSS on marketing site | 6.1 | 1.0 (public) | 0.5 | 1.0 | 0.1 | 3.8 |
| Priv Esc on dev server | 7.8 | 0.5 (theoretical) | 0.2 | 0.1 | 0.5 | 1.1 |

## 2. Business Impact Mapping

Map technical findings to business impact categories for executive communication.

```python
IMPACT_CATEGORIES = {
    "revenue": {"weight": 0.3, "examples": ["payment processing", "e-commerce", "SaaS platform"]},
    "reputation": {"weight": 0.25, "examples": ["customer data", "public-facing", "brand trust"]},
    "compliance": {"weight": 0.25, "examples": ["PCI-DSS", "HIPAA", "GDPR", "SOX"]},
    "operations": {"weight": 0.2, "examples": ["CI/CD", "internal tools", "infrastructure"]},
}

def compute_business_impact(finding: dict, asset_context: dict) -> float:
    total = 0.0
    for category, meta in IMPACT_CATEGORIES.items():
        category_score = asset_context.get(f"{category}_exposure", 0.0)
        total += category_score * meta["weight"]
    return min(total, 1.0)
```

### Business Impact Assessment Template

For each finding, assess business impact by answering these questions for each category:

| Category | Assessment Questions | Scoring Guide |
|----------|---------------------|---------------|
| Revenue | Would exploit directly impact payment collection or sales? | 1.0 = payment system, 0.7 = e-commerce catalog, 0.3 = indirect revenue impact, 0.0 = no revenue link |
| Reputation | Would exploit become public and damage customer trust? | 1.0 = customer data breach, 0.7 = service outage visible to users, 0.3 = internal only but media-worthy, 0.0 = no reputational risk |
| Compliance | Does exploit violate regulatory requirements? | 1.0 = PCI/HIPAA/GDPR violation, 0.7 = SOX/ISO control gap, 0.3 = best practice deviation, 0.0 = no compliance impact |
| Operations | Would exploit disrupt business operations? | 1.0 = CI/CD or infrastructure down, 0.7 = degraded performance, 0.3 = limited internal tool impact, 0.0 = no operational impact |

### Industry-Specific Impact Adjustments

Adjust category weights based on the target industry:

```python
INDUSTRY_WEIGHTS = {
    "fintech": {"revenue": 0.35, "reputation": 0.25, "compliance": 0.3, "operations": 0.1},
    "healthcare": {"revenue": 0.15, "reputation": 0.25, "compliance": 0.45, "operations": 0.15},
    "saas": {"revenue": 0.35, "reputation": 0.3, "compliance": 0.15, "operations": 0.2},
    "manufacturing": {"revenue": 0.2, "reputation": 0.15, "compliance": 0.15, "operations": 0.5},
    "government": {"revenue": 0.1, "reputation": 0.3, "compliance": 0.4, "operations": 0.2},
}
```

## 3. Exploitability Scoring

Factor in real-world exploit availability and attack feasibility.

```python
def exploitability_modifier(finding: dict) -> float:
    """Returns modifier between 0.5 (theoretical) and 2.0 (actively exploited)."""
    base = 1.0
    if finding.get("exploit_public"):
        base += 0.3
    if finding.get("exploit_weaponized"):
        base += 0.4
    if finding.get("in_the_wild"):
        base += 0.3
    if finding.get("requires_auth") and not finding.get("default_creds"):
        base -= 0.3
    if finding.get("requires_local_access"):
        base -= 0.2
    return max(0.5, min(base, 2.0))
```

### Exploitability Evidence Sources

| Source | What It Indicates | Modifier Impact |
|--------|------------------|-----------------|
| Exploit-DB entry | Public proof-of-concept exists | +0.3 (exploit_public) |
| Metasploit module | Weaponized, reliable exploit | +0.4 (exploit_weaponized) |
| CISA KEV catalog | Known to be exploited in the wild | +0.3 (in_the_wild) |
| Authentication required | Raises the bar for exploitation | -0.3 |
| Local access required | Significantly limits attack surface | -0.2 |
| Default credentials available | Lowers exploitation barrier | No penalty even with auth required |

### EPSS Integration

The Exploit Prediction Scoring System (EPSS) provides probability estimates for future exploitation:

```python
def enrich_with_epss(finding: dict, epss_percentile: float) -> dict:
    """Enrich finding with EPSS data for enhanced exploitability scoring."""
    if epss_percentile >= 0.95:
        finding["epss_tier"] = "CRITICAL"  # Top 5% - likely to be exploited
        finding["exploitability_modifier"] = min(
            finding.get("exploitability_modifier", 1.0) * 1.3, 2.0
        )
    elif epss_percentile >= 0.8:
        finding["epss_tier"] = "HIGH"
    elif epss_percentile >= 0.5:
        finding["epss_tier"] = "MODERATE"
    else:
        finding["epss_tier"] = "LOW"
    return finding
```

## 4. Priority Matrix Generation

Combine all factors into a ranked remediation queue.

```python
def build_priority_matrix(findings: list[dict], assets: dict) -> list[dict]:
    matrix = []
    for f in findings:
        biz_impact = compute_business_impact(f, assets.get(f["asset_id"], {}))
        exploit_mod = exploitability_modifier(f)
        risk = ContextualizedRisk(
            finding_id=f["id"],
            cvss_base=f["cvss"],
            exploitability_modifier=exploit_mod,
            business_criticality=biz_impact,
            exposure_factor=f.get("exposure", 0.5),
            compensating_controls=f.get("controls", 0.0),
        )
        matrix.append({
            "finding_id": f["id"],
            "title": f["title"],
            "raw_cvss": f["cvss"],
            "contextualized_score": risk.contextualized_score,
            "exploit_modifier": exploit_mod,
            "business_impact": round(biz_impact, 2),
            "priority_tier": _assign_tier(risk.contextualized_score),
        })
    return sorted(matrix, key=lambda r: r["contextualized_score"], reverse=True)

def _assign_tier(score: float) -> str:
    if score >= 8.0:
        return "P0-CRITICAL"
    if score >= 6.0:
        return "P1-HIGH"
    if score >= 4.0:
        return "P2-MEDIUM"
    return "P3-LOW"
```

### Matrix Output Example

```json
[
  {
    "finding_id": "WEB-001",
    "title": "Unauthenticated RCE in web application",
    "raw_cvss": 9.8,
    "contextualized_score": 9.8,
    "exploit_modifier": 1.7,
    "business_impact": 0.92,
    "priority_tier": "P0-CRITICAL"
  },
  {
    "finding_id": "WEB-007",
    "title": "Reflected XSS in search parameter",
    "raw_cvss": 6.1,
    "contextualized_score": 3.8,
    "exploit_modifier": 1.0,
    "business_impact": 0.5,
    "priority_tier": "P3-LOW"
  }
]
```

## 5. CLI and Tooling Integration

```bash
# Generate priority matrix from scanner output
python3 risk_matrix.py --findings scan_results.json --assets asset_inventory.json --output matrix.json

# Filter for critical items requiring immediate action
python3 risk_matrix.py --findings scan_results.json --assets assets.json --tier P0-CRITICAL --format table

# Enrich with EPSS (Exploit Prediction Scoring System) data
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-1234" | \
  jq '.data[0].epss' | xargs -I{} python3 risk_matrix.py --enrich-epss {}

# Export to CSV for stakeholder reporting
python3 risk_matrix.py --findings scan_results.json --assets assets.json --format csv > priority_report.csv

# Compare before/after contextualization
python3 risk_matrix.py --findings scan_results.json --assets assets.json --diff --format markdown
```

### CI/CD Pipeline Integration

```yaml
# Example GitLab CI integration
container_scan:
  stage: test
  script:
    - trivy image --format json --output trivy-results.json $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - python3 risk_matrix.py --findings trivy-results.json --assets asset_inventory.json --output matrix.json
    - python3 risk_matrix.py --findings trivy-results.json --tier P0-CRITICAL --count
    - exit $(python3 risk_matrix.py --findings trivy-results.json --fail-on P0-CRITICAL)
  artifacts:
    paths:
      - matrix.json
```

## 6. Remediation Ordering Logic

```python
def remediation_order(matrix: list[dict], capacity: int = 10) -> list[dict]:
    """Select top findings considering effort and dependencies."""
    ordered = []
    for item in matrix:
        if len(ordered) >= capacity:
            break
        # Skip if blocked by dependency
        if item.get("blocked_by") and item["blocked_by"] not in [o["finding_id"] for o in ordered]:
            continue
        ordered.append(item)
    return ordered
```

### Dependency-Aware Scheduling

Remediation ordering must account for dependencies between findings. Common dependency patterns:

| Dependency Pattern | Example | Resolution |
|-------------------|---------|------------|
| Prerequisite fix | Fix input validation before XSS can be fully resolved | Order prerequisite first |
| Shared root cause | Multiple findings from same misconfigured library | Fix root cause, all findings resolve together |
| Conflict | One fix blocks another (e.g., strict CSP breaks inline scripts) | Schedule as a combined task |
| Environment constraint | Fix requires maintenance window or downtime | Batch with other window-dependent fixes |

### Capacity Planning with Velocity Tracking

```python
def estimate_remediation_capacity(historical_velocity: dict, sprint_length_days: int = 14) -> dict:
    """Estimate how many findings can be remediated based on historical velocity."""
    avg_per_sprint = sum(historical_velocity.values()) / len(historical_velocity)
    return {
        "estimated_capacity": round(avg_per_sprint),
        "p0_capacity": round(avg_per_sprint * 0.3),  # 30% allocated to critical
        "p1_capacity": round(avg_per_sprint * 0.4),  # 40% allocated to high
        "p2_capacity": round(avg_per_sprint * 0.2),  # 20% allocated to medium
        "p3_capacity": round(avg_per_sprint * 0.1),  # 10% allocated to low
    }
```

## 7. Priority Tier SLA Mapping

| Tier | Contextualized Score | Remediation SLA | Escalation | Notification |
|------|---------------------|-----------------|------------|-------------|
| P0-CRITICAL | 8.0 - 10.0 | 24 hours | CISO immediately | PagerDuty + Email + Slack |
| P1-HIGH | 6.0 - 7.9 | 7 days | Security lead | Email + Slack |
| P2-MEDIUM | 4.0 - 5.9 | 30 days | Sprint planning | Ticket auto-creation |
| P3-LOW | 0.0 - 3.9 | 90 days | Backlog | Quarterly review |

### SLA Breach Handling

When remediation SLAs are breached, automatic escalation procedures activate:

```python
def check_sla_breaches(matrix: list[dict], finding_dates: dict) -> list[dict]:
    """Check for SLA breaches and generate escalation actions."""
    sla_limits = {"P0-CRITICAL": 1, "P1-HIGH": 7, "P2-MEDIUM": 30, "P3-LOW": 90}
    breaches = []
    for item in matrix:
        days_open = (datetime.now() - finding_dates[item["finding_id"]]).days
        limit = sla_limits.get(item["priority_tier"], 90)
        if days_open > limit:
            breaches.append({
                "finding_id": item["finding_id"],
                "tier": item["priority_tier"],
                "days_open": days_open,
                "sla_limit": limit,
                "overdue_by": days_open - limit,
                "escalation": "ciso" if item["priority_tier"] == "P0-CRITICAL" else "security_lead",
            })
    return sorted(breaches, key=lambda b: b["overdue_by"], reverse=True)
```

## Hands-on Exercises

### Exercise 1: Full Matrix Build

Given a set of 15 findings from a web application penetration test and an asset inventory, build the complete priority matrix. Contextualize each finding, compute business impact, apply exploitability modifiers, and generate the ranked output.

Steps:
1. Parse the findings JSON and asset inventory
2. Compute contextualized scores for all findings
3. Generate the priority tier assignments
4. Compare the ranked output against raw CVSS ordering -- observe how contextualization changes priorities

### Exercise 2: SLA Enforcement Simulation

Simulate a 90-day remediation cycle. Assign discovery dates to findings and track SLA compliance. Identify which findings breach their SLA and generate escalation reports.

Steps:
1. Assign realistic discovery dates (spread over the past 90 days)
2. Run SLA breach detection weekly
3. Track remediation velocity and adjust capacity estimates
4. Generate a dashboard showing open findings by tier, SLA compliance rate, and overdue escalations

### Exercise 3: Before/After Contextualization Analysis

Take a raw scanner output (50+ findings) and compare the priority ordering before and after contextualization. Produce a report showing:
- Which findings moved up in priority (and why)
- Which findings moved down in priority (and why)
- Executive summary with the top 10 findings by contextualized score

## References

- [NVD CVSS Calculator v4.0](https://www.first.org/cvss/calculator/4.0) - Official CVSS scoring tool
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - In-the-wild exploit tracking
- [EPSS (Exploit Prediction Scoring System)](https://www.first.org/epss/) - Probabilistic exploit prediction
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) - Risk assessment framework
- [FAIR (Factor Analysis of Information Risk)](https://www.fairinstitute.org/) - Quantitative risk quantification
- [CIS Controls v8](https://www.cisecurity.org/controls) - Security control prioritization
