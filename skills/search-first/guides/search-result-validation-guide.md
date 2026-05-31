# Search Result Validation Guide

> Techniques for verifying that search results (exploits, tools, techniques) are genuine, safe, and applicable before use in engagements.

---

## 1. Exploit Verification Checklist

### Pre-Use Validation

```bash
# Step 1: Check exploit metadata
searchsploit -x <EDB-ID> | head -30
# Look for: Author, Date, Tested versions, Platform

# Step 2: Cross-reference with NVD
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE-ID>" \
  | jq '.vulnerabilities[0].cve | {published, lastModified, descriptions: .descriptions[0].value[:150]}'

# Step 3: Check if exploit is weaponized (malicious)
# Review the code for unexpected behavior:
grep -nE "curl.*\|.*bash|wget.*\|.*sh|rm -rf|/dev/tcp|base64.*-d" exploit.py
grep -nE "reverse.*shell|bind.*shell|callback" exploit.py
```

### Version Compatibility Check

```bash
# Verify target matches exploit requirements
check_version_match() {
    local target_version="$1"
    local exploit_versions="$2"  # comma-separated
    
    for v in $(echo "$exploit_versions" | tr ',' '\n'); do
        if [ "$target_version" = "$v" ]; then
            echo "[+] Exact match: $target_version"
            return 0
        fi
    done
    echo "[-] No exact match. Target: $target_version, Exploit supports: $exploit_versions"
    return 1
}
```

---

## 2. Tool Authenticity Verification

### GitHub Repository Trust Assessment

```bash
assess_repo_trust() {
    local repo="$1"
    
    echo "=== Trust Assessment: $repo ==="
    
    # Basic metrics
    gh repo view "$repo" --json stargazersCount,forkCount,createdAt,updatedAt,licenseInfo \
      | jq '{stars: .stargazersCount, forks: .forkCount, created: .createdAt, updated: .updatedAt, license: .licenseInfo.name}'
    
    # Contributor count
    echo "Contributors: $(gh api "repos/$repo/contributors?per_page=1" -i 2>/dev/null | grep -oP 'page=\K[0-9]+' | tail -1)"
    
    # Recent activity
    echo "Recent commits (30d): $(gh api "repos/$repo/commits?since=$(date -d '30 days ago' +%Y-%m-%dT00:00:00Z)&per_page=1" -i 2>/dev/null | grep -oP 'page=\K[0-9]+' | tail -1)"
    
    # Check for security policy
    gh api "repos/$repo/contents/SECURITY.md" --jq '.name' 2>/dev/null && echo "Has SECURITY.md" || echo "No SECURITY.md"
}
```

### Binary Verification

```bash
# Verify downloaded tool integrity
verify_binary() {
    local file="$1"
    local expected_hash="$2"
    
    actual_hash=$(sha256sum "$file" | cut -d' ' -f1)
    if [ "$actual_hash" = "$expected_hash" ]; then
        echo "[+] Hash verified: $file"
    else
        echo "[!] HASH MISMATCH: $file"
        echo "    Expected: $expected_hash"
        echo "    Got:      $actual_hash"
        return 1
    fi
}

# Check for known malware signatures
clamscan "$file" 2>/dev/null
```

---

## 3. Search Result Freshness Validation

### Staleness Detection

```python
from datetime import datetime, timedelta

STALENESS_THRESHOLDS = {
    "exploit": timedelta(days=365),
    "tool": timedelta(days=180),
    "technique": timedelta(days=730),
    "advisory": timedelta(days=90),
}

def is_stale(result: dict, result_type: str) -> bool:
    """Determine if a search result is too old to be reliable."""
    threshold = STALENESS_THRESHOLDS.get(result_type, timedelta(days=365))
    published = datetime.fromisoformat(result.get("date", "2000-01-01"))
    return (datetime.now() - published) > threshold

def freshness_score(result: dict) -> float:
    """Score from 0 (ancient) to 1 (just published)."""
    published = datetime.fromisoformat(result.get("date", "2000-01-01"))
    age_days = (datetime.now() - published).days
    return max(0, 1.0 - (age_days / 730))
```

### Patch Status Check

```bash
# Check if vulnerability has been patched
check_patch_status() {
    local cve_id="$1"
    
    # Check NVD for patch references
    curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve_id" \
      | jq '.vulnerabilities[0].cve.references[] | select(.tags[] == "Patch") | .url'
    
    # Check if vendor has issued advisory
    curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve_id" \
      | jq '.vulnerabilities[0].cve.references[] | select(.tags[] == "Vendor Advisory") | .url'
}
```

---

## 4. False Positive Filtering

### Common False Positive Patterns

```python
FALSE_POSITIVE_INDICATORS = [
    "theoretical",
    "requires physical access",
    "requires root/admin already",
    "only affects debug mode",
    "not reproducible",
    "disputed",
    "rejected",
]

def filter_false_positives(results: list[dict]) -> list[dict]:
    """Remove likely false positives from search results."""
    filtered = []
    for r in results:
        text = (r.get("description", "") + r.get("title", "")).lower()
        if not any(fp in text for fp in FALSE_POSITIVE_INDICATORS):
            filtered.append(r)
    return filtered
```

### Exploit Reliability Tiers

```bash
# Classify exploit reliability before use
classify_reliability() {
    local edb_id="$1"
    local exploit_text=$(searchsploit -x "$edb_id" 2>/dev/null)
    
    # Tier 1: Verified + multiple sources
    if echo "$exploit_text" | grep -qi "verified\|tested on"; then
        echo "TIER-1: Verified exploit"
    # Tier 2: Has PoC but unverified
    elif echo "$exploit_text" | grep -qi "proof of concept\|PoC"; then
        echo "TIER-2: Unverified PoC"
    # Tier 3: Theoretical/advisory only
    else
        echo "TIER-3: Theoretical/unverified"
    fi
}
```

---

## 5. Operational Security for Search

### Safe Research Practices

```bash
# Use isolated environment for exploit analysis
analyze_in_sandbox() {
    local file="$1"
    
    # Run in disposable container
    docker run --rm --network none \
        -v "$(pwd)/$file:/exploit:ro" \
        kalilinux/kali-rolling \
        bash -c "cat /exploit | head -50; echo '---'; grep -c 'def\|function\|class' /exploit"
}

# Search without revealing intent (use generic terms)
# BAD:  "exploit target.com apache 2.4.49"
# GOOD: "apache 2.4.49 CVE path traversal"
```

### Search Audit Trail

```bash
# Maintain research log for engagement documentation
log_research() {
    local log="$HOME/.research_audit/$(date +%Y-%m-%d).log"
    mkdir -p "$(dirname "$log")"
    echo "[$(date +%H:%M:%S)] QUERY: $1 | SOURCE: $2 | RELEVANT: $3" >> "$log"
}
```
