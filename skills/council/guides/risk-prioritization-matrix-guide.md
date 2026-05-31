# Risk Prioritization Matrix Guide

> Building risk prioritization matrices that contextualize CVSS scores with business impact, exploitability evidence, and remediation ordering.

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

## 7. Priority Tier SLA Mapping

| Tier | Contextualized Score | Remediation SLA | Escalation |
|------|---------------------|-----------------|------------|
| P0-CRITICAL | 8.0 - 10.0 | 24 hours | CISO immediately |
| P1-HIGH | 6.0 - 7.9 | 7 days | Security lead |
| P2-MEDIUM | 4.0 - 5.9 | 30 days | Sprint planning |
| P3-LOW | 0.0 - 3.9 | 90 days | Backlog |

## 8. Best Practices

- Never rely on raw CVSS alone — always contextualize with business and threat data
- Update exploitability modifiers weekly from threat intelligence feeds
- Review asset criticality mappings quarterly with business owners
- Track remediation velocity per tier to calibrate capacity planning
- Use EPSS percentile alongside CVSS for exploit likelihood grounding
