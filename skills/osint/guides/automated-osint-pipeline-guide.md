# Automated OSINT Pipeline Guide

> End-to-end methodology for building automated, repeatable OSINT collection pipelines that scale across multiple targets.

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
