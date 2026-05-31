# Multi-Source Intelligence Correlation Guide

> Methodology for correlating search results across multiple sources to build comprehensive intelligence pictures.

---

## 1. Source Taxonomy

### Primary Sources (High Authority)

| Source | Type | Best For |
|--------|------|----------|
| NVD/CVE | Vulnerability DB | Known CVEs, CVSS scores |
| GitHub Security Advisories | Advisory | OSS vulnerabilities |
| Vendor advisories | Official | Product-specific patches |
| Exploit-DB | Exploit archive | Working exploits, PoCs |

### Secondary Sources (Context)

| Source | Type | Best For |
|--------|------|----------|
| Blog posts | Research | Technique details, walkthroughs |
| Conference talks | Presentation | Novel attacks, tooling |
| HackerOne disclosures | Bug bounty | Real-world impact |
| GitHub repos | Code | Tools, PoCs, scanners |

---

## 2. Cross-Reference Pipeline

```python
from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class IntelItem:
    source: str
    identifier: str  # CVE-ID, GHSA-ID, EDB-ID
    title: str
    severity: Optional[float] = None
    published: Optional[str] = None
    references: tuple = ()

def correlate_findings(items: list[IntelItem]) -> dict:
    """Group findings by vulnerability identity."""
    clusters = {}
    
    for item in items:
        # Use CVE as primary key if available
        key = next(
            (r for r in item.references if r.startswith("CVE-")),
            item.identifier
        )
        clusters.setdefault(key, []).append(item)
    
    # Enrich clusters with cross-source data
    enriched = {}
    for key, group in clusters.items():
        enriched[key] = {
            "sources": [i.source for i in group],
            "max_severity": max((i.severity for i in group if i.severity), default=None),
            "titles": list(set(i.title for i in group)),
            "source_count": len(group),
        }
    
    return enriched
```

---

## 3. Automated Multi-Source Search

```bash
#!/bin/bash
# multi-source-search.sh — Query multiple sources and correlate
TARGET="$1"

echo "=== Searching: $TARGET ==="
mkdir -p "/tmp/intel_$TARGET"

# Source 1: NVD
echo "[NVD] Searching..."
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$TARGET&resultsPerPage=10" \
  | jq '[.vulnerabilities[].cve | {source: "NVD", id: .id, title: .descriptions[0].value, severity: (.metrics.cvssMetricV31[0].cvssData.baseScore // null)}]' \
  > "/tmp/intel_$TARGET/nvd.json"

# Source 2: ExploitDB
echo "[ExploitDB] Searching..."
searchsploit "$TARGET" --json 2>/dev/null \
  | jq '[.RESULTS_EXPLOIT[:10][] | {source: "ExploitDB", id: .EDB_ID, title: .Title, severity: null}]' \
  > "/tmp/intel_$TARGET/edb.json" 2>/dev/null

# Source 3: GitHub Advisories
echo "[GitHub] Searching..."
gh api graphql -f query="
{
  securityAdvisories(first: 10, query: \"$TARGET\") {
    nodes { ghsaId summary severity publishedAt }
  }
}" 2>/dev/null | jq '[.data.securityAdvisories.nodes[] | {source: "GitHub", id: .ghsaId, title: .summary, severity: .severity}]' \
  > "/tmp/intel_$TARGET/github.json" 2>/dev/null

# Merge results
echo "[*] Correlating..."
jq -s 'flatten | group_by(.title | ascii_downcase | split(" ")[:3] | join(" ")) | map({cluster_size: length, items: .})' \
  /tmp/intel_$TARGET/*.json

echo "[+] Results saved to /tmp/intel_$TARGET/"
```

---

## 4. Confidence Scoring

```python
def calculate_confidence(cluster: dict) -> float:
    """Score confidence based on multi-source corroboration."""
    base = 0.3
    
    # More sources = higher confidence
    source_bonus = min(cluster["source_count"] * 0.2, 0.4)
    
    # Official sources increase confidence
    official = {"NVD", "GitHub", "Vendor"}
    official_count = sum(1 for s in cluster["sources"] if s in official)
    authority_bonus = min(official_count * 0.15, 0.3)
    
    return min(base + source_bonus + authority_bonus, 1.0)
```

---

## 5. Temporal Correlation

```python
from datetime import datetime, timedelta

def detect_coordinated_disclosure(items: list, window_days=7) -> list:
    """Find items published within a time window (likely same vuln)."""
    sorted_items = sorted(items, key=lambda x: x.published or "")
    clusters = []
    current_cluster = [sorted_items[0]] if sorted_items else []
    
    for i in range(1, len(sorted_items)):
        if not sorted_items[i].published or not sorted_items[i-1].published:
            continue
        d1 = datetime.fromisoformat(sorted_items[i-1].published)
        d2 = datetime.fromisoformat(sorted_items[i].published)
        if (d2 - d1) <= timedelta(days=window_days):
            current_cluster.append(sorted_items[i])
        else:
            if len(current_cluster) > 1:
                clusters.append(current_cluster)
            current_cluster = [sorted_items[i]]
    
    if len(current_cluster) > 1:
        clusters.append(current_cluster)
    return clusters
```

---

## 6. Reporting Correlated Intelligence

```bash
# Generate markdown report from correlated data
generate_intel_report() {
    local target="$1"
    local data_dir="/tmp/intel_$target"
    
    echo "# Intelligence Report: $target"
    echo "**Generated**: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "## Sources Queried"
    echo "- NVD: $(jq length "$data_dir/nvd.json") results"
    echo "- ExploitDB: $(jq length "$data_dir/edb.json" 2>/dev/null || echo 0) results"
    echo "- GitHub: $(jq length "$data_dir/github.json" 2>/dev/null || echo 0) results"
    echo ""
    echo "## Critical Findings"
    jq -r '.[] | select(.severity != null and (.severity | tonumber) >= 9.0) | "- [\(.id)] \(.title) (CVSS: \(.severity))"' "$data_dir/nvd.json"
}
```
