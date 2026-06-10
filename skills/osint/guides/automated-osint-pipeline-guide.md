# Automated OSINT Pipeline Guide

> End-to-end methodology for building automated, repeatable OSINT collection pipelines that scale across multiple targets.

## Introduction

Automating OSINT collection transforms ad-hoc manual lookups into a repeatable, auditable, and scalable process. This guide walks through the full lifecycle of an OSINT pipeline: from defining targets and scope, through collection and normalization, to reporting and continuous monitoring. Each section provides working code that you can adapt to your own engagements.

A well-designed pipeline offers several advantages over manual collection: consistency across engagements, reduced operator fatigue, faster turnaround on large target sets, built-in scope enforcement, and automatic change detection for long-running assessments. The trade-off is upfront investment in pipeline infrastructure, which this guide aims to minimize with ready-to-use modules.

### Pipeline Design Principles

| Principle | Description |
|-----------|-------------|
| Idempotent runs | Re-running the same pipeline produces consistent, deduplicated results |
| Rate-limit aware | Respects API quotas and target infrastructure to avoid detection |
| Modular stages | Each collection phase is independently testable and replaceable |
| Persistent state | Pipeline can resume from the last checkpoint on failure |
| Scope enforcement | Every finding is validated against engagement scope rules |
| Auditable logging | All collection activities are timestamped and attributable |

---

## 1. Pipeline Architecture

### Core Components

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────┐
│ Input Layer │───▶│ Collection   │───▶│ Processing  │───▶│ Output   │
│ (targets)   │    │ (tools/APIs) │    │ (normalize) │    │ (report) │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────┘
```

### Design Principles

- **Idempotent runs**: re-running produces consistent results without duplication
- **Rate-limit aware**: respect API quotas and target infrastructure
- **Modular stages**: each phase independently testable and replaceable
- **Persistent state**: resume from last checkpoint on failure

---

## 2. Input Management

### Target Specification Format

```yaml
# targets.yml
targets:
  - type: domain
    value: example.com
    scope:
      include_subdomains: true
      exclude_patterns:
        - "*.dev.example.com"
        - "staging.*"
  - type: organization
    value: "Example Corp"
    identifiers:
      asn: [AS12345]
      ip_ranges: ["192.0.2.0/24", "198.51.100.0/24"]
  - type: person
    value: "John Smith"
    context:
      employer: "Example Corp"
      role: "CTO"
```

### Scope Validation

```bash
#!/bin/bash
validate_scope() {
    local target="$1"
    local scope_file="$2"
    
    # Check target against inclusion/exclusion rules
    if grep -qF "$target" "$scope_file.exclude"; then
        echo "OUT_OF_SCOPE: $target"
        return 1
    fi
    
    # Verify domain belongs to target org
    whois "$target" 2>/dev/null | grep -qi "$(grep 'organization' "$scope_file" | cut -d: -f2)"
}
```

---

## 3. Collection Modules

### Module: Subdomain Discovery

```bash
#!/bin/bash
collect_subdomains() {
    local domain="$1"
    local output_dir="$2"
    
    mkdir -p "$output_dir/subdomains"
    
    # Passive sources (parallel)
    subfinder -d "$domain" -silent > "$output_dir/subdomains/subfinder.txt" &
    amass enum -passive -d "$domain" -o "$output_dir/subdomains/amass.txt" &
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sort -u > "$output_dir/subdomains/crtsh.txt" &
    wait
    
    # Merge and deduplicate
    sort -u "$output_dir/subdomains/"*.txt > "$output_dir/subdomains/all_unique.txt"
    
    # Resolve live hosts
    dnsx -l "$output_dir/subdomains/all_unique.txt" -silent -a > "$output_dir/subdomains/resolved.txt"
    
    echo "[+] Found $(wc -l < "$output_dir/subdomains/all_unique.txt") unique subdomains"
    echo "[+] $(wc -l < "$output_dir/subdomains/resolved.txt") resolve to IP addresses"
}
```

### Module: Technology Fingerprinting

```bash
collect_technologies() {
    local hosts_file="$1"
    local output_dir="$2"
    
    httpx -l "$hosts_file" -silent \
        -status-code -title -tech-detect -server \
        -content-length -follow-redirects \
        -json -o "$output_dir/technologies.json"
    
    # Extract unique technology stack
    jq -r '.tech[]?' "$output_dir/technologies.json" | sort | uniq -c | sort -rn > "$output_dir/tech_summary.txt"
}
```

### Module: Email & Personnel Discovery

```bash
collect_emails() {
    local domain="$1"
    local output_dir="$2"

    mkdir -p "$output_dir/emails"

    # theHarvester multi-source
    theHarvester -d "$domain" -b all -f "$output_dir/emails/harvester_report" 2>/dev/null

    # Hunter.io API (if key available)
    if [ -n "$HUNTER_API_KEY" ]; then
        curl -s "https://api.hunter.io/v2/domain-search?domain=$domain&api_key=$HUNTER_API_KEY" \
            | jq -r '.data.emails[].value' > "$output_dir/emails/hunter.txt"
    fi

    # Extract pattern
    curl -s "https://api.hunter.io/v2/domain-search?domain=$domain&api_key=$HUNTER_API_KEY" \
        | jq -r '.data.pattern' > "$output_dir/emails/pattern.txt"
}
```

### Module: Credential Leak Monitoring

```bash
collect_credential_intel() {
    local domain="$1"
    local output_dir="$2"

    mkdir -p "$output_dir/credentials"

    # Check Have I Been Pwned via theHarvester integration
    theHarvester -d "$domain" -b haveibeenpwned -f "$output_dir/credentials/hibp.json" 2>/dev/null || true

    # Search GitHub for potential credential leaks
    for query in "\"$domain\" password" "\"$domain\" api_key" "\"$domain\" secret" "\"$domain\" token"; do
        curl -s "https://api.github.com/search/code?q=$(echo "$query" | tr ' ' '+')" \
            -H "Accept: application/vnd.github.v3+json" \
            | jq -r '.items[] | "\(.repository.full_name) \(.path) \(.html_url)"' \
            >> "$output_dir/credentials/github_leaks.txt" 2>/dev/null || true
    done

    sort -u "$output_dir/credentials/github_leaks.txt" > "$output_dir/credentials/github_leaks_unique.txt" 2>/dev/null || true
    echo "[+] Credential leak check complete for $domain"
}
```

### Module: Social Media and Personnel Correlation

```python
"""Personnel intelligence collection module."""
from dataclasses import dataclass
from typing import Optional
import json

@dataclass(frozen=True)
class PersonIntel:
    name: str
    role: str
    employer: str
    social_profiles: dict
    email_addresses: list[str]
    confidence: float
    source: str

def collect_personnel_intel(organization: str, output_path: str) -> list[PersonIntel]:
    """Collect personnel intelligence from multiple public sources."""
    personnel = []

    # GitHub organization members
    gh_members = query_github_org_members(organization)
    for member in gh_members:
        personnel.append(PersonIntel(
            name=member.get("name", member.get("login", "")),
            role=member.get("bio", "Unknown"),
            employer=organization,
            social_profiles={"github": member.get("html_url", "")},
            email_addresses=[member.get("email")] if member.get("email") else [],
            confidence=0.7,
            source="github_org",
        ))

    # Cross-reference with LinkedIn public data
    for person in personnel:
        linkedin_data = search_linkedin_public(person.name, organization)
        if linkedin_data:
            updated_profiles = {**person.social_profiles, "linkedin": linkedin_data.get("url", "")}
            personnel.append(PersonIntel(
                name=person.name,
                role=linkedin_data.get("headline", person.role),
                employer=organization,
                social_profiles=updated_profiles,
                email_addresses=person.email_addresses,
                confidence=0.9,
                source="github_linkedin_correlation",
            ))

    # Save results
    with open(output_path, "w") as f:
        json.dump([vars(p) for p in personnel], f, indent=2)

    return personnel

def query_github_org_members(org: str) -> list[dict]:
    """Query GitHub API for organization members."""
    import urllib.request
    url = f"https://api.github.com/orgs/{org}/members?per_page=100"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github.v3+json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return []

def search_linkedin_public(name: str, company: str) -> Optional[dict]:
    """Placeholder for LinkedIn public profile search (implement with care for ToS)."""
    # In practice, use a search engine API to find public LinkedIn profiles
    return None
```

---

## 4. Processing & Normalization

### Unified Data Model

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass(frozen=True)
class OSINTFinding:
    source: str
    category: str  # subdomain, email, technology, credential, infrastructure
    value: str
    confidence: float  # 0.0 - 1.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: dict = field(default_factory=dict)
    related_to: Optional[str] = None

def normalize_findings(raw_results: list[dict]) -> list[OSINTFinding]:
    """Convert tool-specific output to unified format."""
    findings = []
    for item in raw_results:
        findings.append(OSINTFinding(
            source=item["tool"],
            category=item["type"],
            value=item["data"].strip().lower(),
            confidence=item.get("confidence", 0.8),
            metadata=item.get("extra", {}),
        ))
    return deduplicate(findings)

def deduplicate(findings: list[OSINTFinding]) -> list[OSINTFinding]:
    """Remove duplicates, keeping highest confidence."""
    seen = {}
    for f in findings:
        key = (f.category, f.value)
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return list(seen.values())
```

### Correlation Engine

```python
def correlate_findings(findings: list[OSINTFinding]) -> dict:
    """Cross-reference findings to build entity relationships."""
    graph = {"nodes": [], "edges": []}

    # Group by category
    by_category = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    # Link subdomains to IPs
    for sub in by_category.get("subdomain", []):
        for infra in by_category.get("infrastructure", []):
            if sub.metadata.get("ip") == infra.value:
                graph["edges"].append({
                    "from": sub.value,
                    "to": infra.value,
                    "relation": "resolves_to"
                })

    # Link emails to domains
    for email in by_category.get("email", []):
        domain = email.value.split("@")[1]
        graph["edges"].append({
            "from": email.value,
            "to": domain,
            "relation": "belongs_to"
        })

    return graph
```

### Confidence Scoring System

```python
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

@dataclass(frozen=True)
class ConfidenceScore:
    """Multi-factor confidence scoring for OSINT findings."""
    value: float  # 0.0 - 1.0
    factors: dict  # Individual factor scores
    explanation: str

def calculate_confidence(
    finding: OSINTFinding,
    cross_references: int = 0,
    age_days: int = 0,
    source_reliability: float = 0.8,
) -> ConfidenceScore:
    """Calculate a composite confidence score based on multiple factors."""
    factors = {
        "source_reliability": source_reliability,
        "cross_reference_count": min(cross_references / 3.0, 1.0),  # 3+ refs = max
        "data_freshness": max(0.0, 1.0 - (age_days / 365.0)),       # Decay over 1 year
        "original_confidence": finding.confidence,
    }

    # Weighted average
    weights = {
        "source_reliability": 0.3,
        "cross_reference_count": 0.3,
        "data_freshness": 0.2,
        "original_confidence": 0.2,
    }

    composite = sum(
        factors[k] * weights[k] for k in factors
    )

    explanation = (
        f"Source reliability: {factors['source_reliability']:.2f}, "
        f"Cross-references: {cross_references}, "
        f"Age: {age_days} days, "
        f"Original: {finding.confidence:.2f}"
    )

    return ConfidenceScore(
        value=round(composite, 3),
        factors=factors,
        explanation=explanation,
    )
```

### Finding Enrichment Pipeline

```python
def enrich_findings(findings: list[OSINTFinding]) -> list[dict]:
    """Add context and risk scoring to raw findings."""
    enriched = []

    for finding in findings:
        enrichment = {
            "original": finding,
            "risk_level": classify_risk(finding),
            "tags": generate_tags(finding),
            "related_findings": find_related(finding, findings),
        }

        if finding.category == "subdomain":
            enrichment["dns_records"] = resolve_dns(finding.value)
            enrichment["whois"] = query_whois(finding.value)
            enrichment["technologies"] = fingerprint_tech(finding.value)

        elif finding.category == "email":
            enrichment["breach_count"] = check_breach_count(finding.value)
            enrichment["social_profiles"] = find_profiles(finding.value)

        enriched.append(enrichment)

    return enriched

def classify_risk(finding: OSINTFinding) -> str:
    """Classify a finding into risk levels for prioritization."""
    high_risk_keywords = ["admin", "internal", "vpn", "dev", "staging", "test"]
    value_lower = finding.value.lower()

    if any(kw in value_lower for kw in high_risk_keywords):
        return "high"
    elif finding.confidence > 0.8:
        return "medium"
    else:
        return "low"
```

---

## 5. Rate Limiting & Stealth

### Adaptive Rate Controller

```python
import time
import random

class RateLimiter:
    def __init__(self, requests_per_minute=30, jitter=True):
        self.interval = 60.0 / requests_per_minute
        self.jitter = jitter
        self.last_request = 0
    
    def wait(self):
        elapsed = time.time() - self.last_request
        delay = self.interval - elapsed
        if self.jitter:
            delay += random.uniform(0, self.interval * 0.3)
        if delay > 0:
            time.sleep(delay)
        self.last_request = time.time()
```

### Source Rotation

```bash
# Rotate DNS resolvers to avoid rate limits
RESOLVERS=("8.8.8.8" "1.1.1.1" "9.9.9.9" "208.67.222.222")

resolve_with_rotation() {
    local domain="$1"
    local resolver="${RESOLVERS[$((RANDOM % ${#RESOLVERS[@]}))]}"
    dig +short "$domain" "@$resolver"
}
```

### API Key Management

```python
"""Centralized API key management with rotation support."""
import os
import time
from dataclasses import dataclass

@dataclass(frozen=True)
class APIKeyConfig:
    service: str
    keys: list[str]
    requests_per_minute: int
    current_index: int = 0

class KeyRotator:
    """Rotate through multiple API keys to stay within rate limits."""

    def __init__(self):
        self._configs: dict[str, APIKeyConfig] = {}
        self._last_used: dict[str, float] = {}

    def register(self, service: str, env_var: str, rpm: int = 30):
        """Register a service with API keys from environment variables."""
        keys_str = os.environ.get(env_var, "")
        keys = [k.strip() for k in keys_str.split(",") if k.strip()]
        if keys:
            self._configs[service] = APIKeyConfig(
                service=service,
                keys=keys,
                requests_per_minute=rpm,
            )

    def get_key(self, service: str) -> str | None:
        """Get the next available API key, respecting rate limits."""
        config = self._configs.get(service)
        if not config or not config.keys:
            return None

        # Simple round-robin rotation
        index = int(time.time() / 60) % len(config.keys)
        return config.keys[index]

    def get_rpm(self, service: str) -> int:
        """Get the configured requests-per-minute limit."""
        config = self._configs.get(service)
        return config.requests_per_minute if config else 30
```

---

## 6. Output & Reporting

### Structured JSON Report

```bash
generate_report() {
    local output_dir="$1"
    local target="$2"
    
    jq -n \
        --arg target "$target" \
        --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --slurpfile subs "$output_dir/subdomains/all_unique.txt" \
        --slurpfile tech "$output_dir/technologies.json" \
        '{
            target: $target,
            scan_date: $date,
            summary: {
                subdomains_found: ($subs | length),
                technologies_detected: ($tech | map(.tech // []) | flatten | unique | length)
            },
            findings: {
                subdomains: $subs,
                technologies: $tech
            }
        }' > "$output_dir/final_report.json"
}
```

### Executive Summary Generator

```python
def generate_executive_summary(findings: list, target: str) -> str:
    """Produce a human-readable summary for non-technical stakeholders."""
    categories = {}
    for f in findings:
        categories.setdefault(f["category"], []).append(f)

    lines = [
        f"# OSINT Assessment: {target}",
        f"**Date**: {datetime.utcnow().strftime('%Y-%m-%d')}",
        f"**Total Findings**: {len(findings)}",
        "",
        "## Key Statistics",
        f"- Subdomains discovered: {len(categories.get('subdomain', []))}",
        f"- Email addresses found: {len(categories.get('email', []))}",
        f"- Technologies identified: {len(categories.get('technology', []))}",
        f"- Exposed services: {len(categories.get('infrastructure', []))}",
        "",
        "## Critical Findings",
    ]

    critical = [f for f in findings if f.get("confidence", 0) > 0.9]
    for item in critical[:10]:
        lines.append(f"- [{item['category']}] {item['value']}")

    return "\n".join(lines)
```

### HTML Report with Risk Heatmap

```python
def generate_html_report(findings: list[dict], target: str) -> str:
    """Generate an HTML report with visual risk indicators."""
    risk_colors = {"high": "#dc3545", "medium": "#ffc107", "low": "#28a745"}

    rows = []
    for f in findings:
        risk = f.get("risk_level", "low")
        color = risk_colors.get(risk, "#6c757d")
        rows.append(
            f'<tr><td>{f["category"]}</td>'
            f'<td>{f["value"]}</td>'
            f'<td style="color:{color};font-weight:bold">{risk.upper()}</td>'
            f'<td>{f.get("source", "unknown")}</td></tr>'
        )

    return f"""<!DOCTYPE html>
<html><head><title>OSINT Report: {target}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #333; color: white; }}
</style></head><body>
<h1>OSINT Assessment Report</h1>
<p><strong>Target:</strong> {target}</p>
<p><strong>Total Findings:</strong> {len(findings)}</p>
<table><tr><th>Category</th><th>Value</th><th>Risk</th><th>Source</th></tr>
{''.join(rows)}
</table></body></html>"""
```

---

## 7. Scheduling & Continuous Monitoring

### Cron-Based Recurring Scans

```bash
# /etc/cron.d/osint-monitor
# Run weekly subdomain check
0 3 * * 1 /opt/osint/pipeline.sh --target example.com --module subdomains --diff-only
# Run daily certificate transparency monitor
0 */6 * * * /opt/osint/ct_monitor.sh example.com
```

### Change Detection

```bash
detect_changes() {
    local current="$1"
    local previous="$2"
    local output="$3"
    
    # New subdomains
    comm -23 <(sort "$current") <(sort "$previous") > "$output/new_findings.txt"
    
    # Removed entries
    comm -13 <(sort "$current") <(sort "$previous") > "$output/removed.txt"
    
    if [ -s "$output/new_findings.txt" ]; then
        echo "[ALERT] $(wc -l < "$output/new_findings.txt") new findings detected"
        # Send notification
        cat "$output/new_findings.txt" | mail -s "OSINT Alert: New findings" analyst@team.local
    fi
}
```

---

## 8. Error Handling & Resilience

### Checkpoint System

```python
import json
from pathlib import Path

class PipelineCheckpoint:
    def __init__(self, checkpoint_file: str):
        self.file = Path(checkpoint_file)
        self.state = self._load()
    
    def _load(self) -> dict:
        if self.file.exists():
            return json.loads(self.file.read_text())
        return {"completed_stages": [], "last_target_index": 0}
    
    def save(self):
        self.file.write_text(json.dumps(self.state, indent=2))
    
    def mark_complete(self, stage: str):
        self.state["completed_stages"].append(stage)
        self.save()
    
    def should_skip(self, stage: str) -> bool:
        return stage in self.state["completed_stages"]
```

### Retry with Backoff

```bash
retry_with_backoff() {
    local max_attempts=3
    local delay=5
    local cmd="$@"
    
    for ((i=1; i<=max_attempts; i++)); do
        if eval "$cmd"; then
            return 0
        fi
        echo "[WARN] Attempt $i failed, retrying in ${delay}s..."
        sleep "$delay"
        delay=$((delay * 2))
    done
    echo "[ERROR] All $max_attempts attempts failed: $cmd"
    return 1
}
```

## 9. Full Pipeline Orchestration Script

```bash
#!/bin/bash
# osint_pipeline.sh - Master orchestration script
set -euo pipefail

TARGET="$1"
OUTPUT_DIR="${2:-osint_output_$(date +%Y%m%d)}"
PHASE="${3:-all}"

mkdir -p "$OUTPUT_DIR"/{raw,processed,reports}

echo "[*] OSINT Pipeline starting for: $TARGET"
echo "[*] Output directory: $OUTPUT_DIR"
echo "[*] Phase filter: $PHASE"

# Load configuration
source "${OSINT_CONFIG:-/etc/osint/pipeline.conf}"

run_phase() {
    local phase_name="$1"
    local phase_func="$2"

    if [[ "$PHASE" == "all" || "$PHASE" == "$phase_name" ]]; then
        echo "[*] Running phase: $phase_name"
        "$phase_func" "$TARGET" "$OUTPUT_DIR"
        echo "[+] Phase $phase_name complete"
    fi
}

run_phase "subdomains"    "collect_subdomains"
run_phase "technologies"  "collect_technologies"
run_phase "emails"        "collect_emails"
run_phase "credentials"   "collect_credential_intel"

# Generate reports
generate_report "$OUTPUT_DIR" "$TARGET"
generate_html_report_from_json "$OUTPUT_DIR/final_report.json" > "$OUTPUT_DIR/reports/report.html"

echo "[+] Pipeline complete. Reports in $OUTPUT_DIR/reports/"
```

## Hands-on Exercises

Practice the techniques described in this guide against authorized targets or lab environments. Document your findings and methodology for each exercise.
## References

- OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- PTES Technical Guidelines — http://www.pentest-standard.org/
