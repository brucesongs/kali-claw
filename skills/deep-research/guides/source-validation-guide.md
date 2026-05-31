# Deep Research Source Validation Guide

> Methodology for validating source credibility, detecting misinformation, and ensuring research findings are reliable and actionable.

---

## 1. Source Credibility Framework

### Authority Assessment Matrix

| Factor | High (0.9+) | Medium (0.6-0.8) | Low (<0.5) |
|--------|-------------|-------------------|------------|
| Publisher | NIST, MITRE, vendor advisory | Security firms, conferences | Personal blogs, forums |
| Peer review | Published CVE, academic paper | Conference talk, reviewed blog | Unreviewed post |
| Reproducibility | PoC provided, lab-verified | Steps described, not verified | Claims without evidence |
| Timeliness | Within 30 days of disclosure | Within 6 months | Over 1 year old |

### Automated Credibility Scoring

```python
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass(frozen=True)
class Source:
    url: str
    domain: str
    published: datetime
    has_poc: bool
    has_cve: bool
    citation_count: int

AUTHORITY_DOMAINS = {
    "nvd.nist.gov": 1.0,
    "cve.mitre.org": 1.0,
    "github.com/advisories": 0.95,
    "hackerone.com": 0.9,
    "exploit-db.com": 0.85,
    "portswigger.net": 0.85,
    "owasp.org": 0.8,
}

def score_credibility(source: Source) -> float:
    score = AUTHORITY_DOMAINS.get(source.domain, 0.4)
    
    # Recency bonus
    age_days = (datetime.now() - source.published).days
    if age_days < 30:
        score += 0.1
    elif age_days > 365:
        score -= 0.1
    
    # Evidence bonus
    if source.has_poc:
        score += 0.15
    if source.has_cve:
        score += 0.1
    
    # Citation authority
    score += min(source.citation_count * 0.02, 0.1)
    
    return min(score, 1.0)
```

---

## 2. Cross-Validation Techniques

### Multi-Source Verification

```bash
#!/bin/bash
# verify-finding.sh — Cross-validate a vulnerability claim
CVE_ID="$1"

echo "=== Verifying: $CVE_ID ==="

# Check NVD (authoritative)
echo "[NVD]"
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CVE_ID" \
  | jq '.vulnerabilities[0].cve | {id, published: .published, severity: .metrics.cvssMetricV31[0].cvssData.baseScore, description: .descriptions[0].value[:100]}'

# Check GitHub Advisory
echo "[GitHub]"
gh api graphql -f query="
{
  securityAdvisory(ghsaId: \"$CVE_ID\") {
    summary severity publishedAt
  }
}" 2>/dev/null | jq '.data.securityAdvisory'

# Check ExploitDB for PoC
echo "[ExploitDB]"
searchsploit "$CVE_ID" 2>/dev/null | grep -v "^$\|Shellcodes\|Papers"

# Check Nuclei templates
echo "[Nuclei]"
find ~/nuclei-templates -name "*.yaml" -exec grep -l "$CVE_ID" {} \; 2>/dev/null

echo ""
echo "[*] Verified in $(echo "NVD GitHub ExploitDB Nuclei" | wc -w) sources"
```

### Contradiction Detection

```python
def detect_contradictions(findings: list[dict]) -> list[dict]:
    """Identify conflicting claims across sources."""
    contradictions = []
    
    # Check severity disagreements
    severities = {}
    for f in findings:
        key = f.get("cve_id") or f.get("title")
        severities.setdefault(key, []).append(f.get("severity"))
    
    for key, scores in severities.items():
        scores = [s for s in scores if s is not None]
        if scores and (max(scores) - min(scores)) > 2.0:
            contradictions.append({
                "finding": key,
                "issue": "severity_disagreement",
                "range": f"{min(scores)} - {max(scores)}",
                "action": "verify with vendor advisory"
            })
    
    return contradictions
```

---

## 3. Misinformation Detection Patterns

### Red Flags in Security Research

```python
RED_FLAGS = [
    "no CVE assigned but claims critical severity",
    "PoC requires disabling security features",
    "affects all versions with no version specificity",
    "no responsible disclosure timeline mentioned",
    "links to suspicious download for 'tool'",
    "newly created account with single post",
    "copied content from known advisory without attribution",
]

def check_red_flags(content: str, metadata: dict) -> list[str]:
    """Screen research content for misinformation indicators."""
    flags = []
    
    content_lower = content.lower()
    
    if "all versions" in content_lower and "cve" not in content_lower:
        flags.append("Claims all versions affected without CVE")
    
    if metadata.get("account_age_days", 365) < 30:
        flags.append("Author account less than 30 days old")
    
    if "download" in content_lower and "github.com" not in content_lower:
        flags.append("Links to non-GitHub download")
    
    if metadata.get("citation_count", 0) == 0 and metadata.get("claims_critical", False):
        flags.append("Claims critical severity with zero citations")
    
    return flags
```

---

## 4. Research Provenance Tracking

### Citation Chain Verification

```bash
# Track a finding back to its original source
trace_provenance() {
    local url="$1"
    echo "=== Provenance trace: $url ==="
    
    # Extract references from the page
    curl -s "$url" | grep -oP 'href="(https?://[^"]+)"' | grep -iE "cve|advisory|security" | sort -u
    
    # Check if this is original research or aggregation
    curl -s "$url" | grep -ciE "originally reported|credit|discovered by"
}
```

### Research Log Template

```markdown
## Finding: [Title]
- **First seen**: [date] at [source URL]
- **Original researcher**: [name/handle]
- **Corroborated by**: [list of independent sources]
- **Credibility score**: [0.0-1.0]
- **Red flags**: [none / list]
- **Status**: [Confirmed / Unverified / Disputed / Debunked]
- **Action**: [Patch / Monitor / Investigate / Ignore]
```

---

## 5. Automated Validation Pipeline

```python
def validate_research_finding(finding: dict) -> dict:
    """End-to-end validation of a research finding."""
    result = {
        "finding": finding,
        "credibility": 0.0,
        "sources_checked": 0,
        "corroborations": 0,
        "contradictions": 0,
        "red_flags": [],
        "verdict": "unverified",
    }
    
    # Step 1: Source credibility
    result["credibility"] = score_credibility(finding["source"])
    
    # Step 2: Cross-reference
    for source in ["nvd", "github", "exploitdb"]:
        result["sources_checked"] += 1
        match = query_source(source, finding["identifier"])
        if match:
            result["corroborations"] += 1
    
    # Step 3: Red flag scan
    result["red_flags"] = check_red_flags(finding["content"], finding["metadata"])
    
    # Step 4: Verdict
    if result["corroborations"] >= 2 and not result["red_flags"]:
        result["verdict"] = "confirmed"
    elif result["red_flags"]:
        result["verdict"] = "suspicious"
    elif result["corroborations"] >= 1:
        result["verdict"] = "likely_valid"
    
    return result
```
