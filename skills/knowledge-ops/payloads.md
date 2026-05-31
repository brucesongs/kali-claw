# Knowledge Operations Payloads

Commands and templates for building, querying, and maintaining the knowledge graph.

---

## Session Startup: Load Context

Run at the start of every session when working on a known target:

```bash
# Find all knowledge files for a target
ls memory/ | grep -i "[target-name]"
grep -rn "target: [target-name]" memory/ | awk -F: '{print $1}' | sort -u

# Find high-confidence findings
grep -rn "confidence: [7-9][0-9]\|confidence: 100" memory/ | head -20

# Find open hypotheses
grep -rn "type: hypothesis" memory/ -l
grep -rn "type: hypothesis" memory/ -A5 | grep -B1 "confidence: [2-5]"

# Find expired intelligence
TODAY=$(date +%Y-%m-%d)
grep -rn "expires:" memory/ | grep -v "null" | while read line; do
  file=$(echo $line | cut -d: -f1)
  expires=$(echo $line | grep -oP '\d{4}-\d{2}-\d{2}')
  if [[ "$expires" < "$TODAY" ]]; then
    echo "EXPIRED: $file (expires: $expires)"
  fi
done
```

---

## Capture: Create New Knowledge Units

### Entity Capture

```markdown
---
id: KU-2026-05-001
type: entity
target: target-org
confidence: 90
created: 2026-05-11
updated: 2026-05-11
tags: [domain, infrastructure, target]
linked: []
source: osint/recon
expires: null
---

## Summary

target.com resolves to 203.0.113.42, hosted on AWS us-east-1.

## Detail

- Primary domain: target.com
- IP: 203.0.113.42
- ASN: AS16509 (Amazon AWS)
- Region: us-east-1 (inferred from response headers: x-amz-cf-id)
- CDN: CloudFront detected (via CNAME to cloudfront.net)
- Nameservers: ns1.target.com, ns2.target.com (custom)

## Connections

- Leads to: subdomain enumeration, CloudFront config bypass research
```

### Finding Capture

```markdown
---
id: KU-2026-05-002
type: finding
target: target-org
confidence: 85
created: 2026-05-11
updated: 2026-05-11
tags: [sql-injection, search, high-risk]
linked: [KU-2026-05-001]
source: codebase-onboarding
expires: null
---

## Summary

SQL injection in search endpoint at search.php:34 via GET parameter `q`.

## Detail

File: `search.php:34`
Code: `$query = "SELECT * FROM products WHERE name LIKE '%" . $_GET['q'] . "%'"`
Type: Classic string concatenation SQL injection
Parameter: GET `q`
Tested: Static analysis only (not confirmed via active testing)
Database: MySQL (from db.php:5 connection string)

## Connections

- Confirms: target uses legacy PHP without parameterized queries
- Leads to: manual verification via sqlmap, data extraction via UNION injection
- Linked entity: KU-2026-05-001 (same target)

## Confidence History

| Date | Score | Reason |
|------|-------|--------|
| 2026-05-11 | 85 | Static code analysis — high probability, not exploited yet |
```

### Relationship Capture

```markdown
---
id: KU-2026-05-003
type: relationship
target: target-org
confidence: 70
created: 2026-05-11
updated: 2026-05-11
tags: [admin, user, access]
linked: [KU-2026-05-001]
source: social-intelligence
expires: 2026-08-11
---

## Summary

John Smith (john@target.com) is the IT administrator, identified via LinkedIn.

## Detail

- Name: John Smith
- Email: john@target.com (format: firstname@domain)
- Role: IT Administrator (LinkedIn profile, 3 years at target.com)
- LinkedIn: linkedin.com/in/johnsmith-target
- GitHub: github.com/jsmith-target (found via email search)
- Notable: Repository named "internal-admin-tool" visible on GitHub (public)

## Connections

- Leads to: Check github.com/jsmith-target for credential exposure
- Leads to: Spear phishing template targeting IT admin role
```

### Pattern Capture

```markdown
---
id: KU-2026-05-004
type: pattern
target: [org-wide pattern]
confidence: 75
created: 2026-05-11
updated: 2026-05-11
tags: [jwt, hs256, pattern, multi-target]
linked: []
source: codebase-onboarding
expires: null
---

## Summary

Organizations using Express.js starter templates frequently use HS256 with a weak or default JWT secret.

## Detail

Observed in: 3 separate targets (target-a, target-b, target-c)
Pattern: `jwt.sign(payload, process.env.JWT_SECRET || 'secret', ...)` — fallback to 'secret' if env not set
Risk: If JWT_SECRET env var is not set in production, all tokens are signed with 'secret'
Frequency: High — Express.js JWT tutorials often use this pattern

## Connections

- Leads to: Check JWT_SECRET in .env for all Express targets
- Leads to: jwt_tool for token forgery attempts if weak secret suspected
```

---

## Knowledge Graph Queries

### Find Attack Chains

```bash
# Find all findings for a target, ordered by confidence
grep -rn "target: target-org" memory/ -l | \
  xargs grep -l "type: finding" | \
  xargs grep -h "confidence:" | \
  sort -t: -k2 -rn | head -10

# Find links between findings (potential attack chains)
grep -rn "linked:" memory/ | grep -v "\[\]" | head -20

# Find hypotheses that could elevate to findings
grep -rn "type: hypothesis" memory/ -A3 | grep -B1 "confidence: [4-6]" | head -10
```

### Cross-Target Pattern Search

```bash
# Find patterns observed across multiple targets
grep -rn "type: pattern" memory/ -l

# Find recurring vulnerability types
grep -rn "tags:.*sql-injection" memory/ | wc -l
grep -rn "tags:.*jwt" memory/ | wc -l
grep -rn "tags:.*xss" memory/ | wc -l

# Most referenced knowledge units (high connectivity = high importance)
grep -rn "linked:" memory/ | grep -oP 'KU-\d{4}-\d{2}-\d{3}' | \
  sort | uniq -c | sort -rn | head -10
```

### Confidence Tracking

```bash
# All high-confidence findings (>= 80)
grep -rn "confidence: [89][0-9]\|confidence: 100" memory/ \
  | grep -v "history\|Reason" | head -20

# All unvalidated findings (confidence 26-50)
grep -rn "confidence: [23456][05]" memory/ | head -20

# Findings that haven't been updated in 30+ days (possibly stale)
find memory/ -name "*.md" -mtime +30 | head -10
```

---

## Knowledge Maintenance

### Update Confidence After Exploitation

```bash
# When a finding is confirmed via exploitation, update confidence
# Edit the memory file:
# 1. Change confidence: 85 → 95
# 2. Add to confidence history table
# 3. Update linked units

# Find the file to update
grep -rn "KU-2026-05-002" memory/
# Edit it:
# confidence: 85 → 95
# Add history row: | 2026-05-11 | 95 | Confirmed via sqlmap, dumped users table |
```

### Archive Disproven Hypotheses

```markdown
# Add to a hypothesis that was disproven:
---
# Change type: hypothesis → type: archived
type: archived
confidence: 0
# Add note:
---

## Archived

Disproven on 2026-05-11. The admin portal does NOT accept VPN bypass — requires client certificate authentication.
```

### Session Capture Template (End of Session)

```bash
# Quick capture script — fill in findings, entities, and relationships
cat > memory/$(date +%Y-%m-%d)-[session-topic].md << 'EOF'
# Session Knowledge Capture — [Topic]

Date: $(date +%Y-%m-%d)
Target: [target]
Session type: [recon / codebase-onboarding / exploitation / research]

## New Entities

[List new domains, IPs, people, systems discovered]

## New Findings

[List vulnerabilities, misconfigurations, sensitive data found]

## Updated Confidence

[List any existing KU IDs with updated confidence scores and reasons]

## Open Hypotheses

[List unconfirmed leads that need follow-up]

## Next Session Priorities

1. [Highest priority follow-up]
2. [Second priority]
3. [Third priority]

## Knowledge Units Created

- KU-YYYY-MM-NNN: [brief description]
- KU-YYYY-MM-NNN: [brief description]
EOF
```

---

## Knowledge-Ops Index File

Maintain an index of all knowledge bases (update monthly):

```markdown
# Knowledge Base Index

## Active Engagements

| Target | KB Files | Findings | Last Updated |
|--------|----------|----------|--------------|
| target-org | 12 | 8 | 2026-05-11 |
| client-b | 5 | 3 | 2026-04-20 |

## Patterns Library

| Pattern ID | Description | Targets Observed |
|-----------|-------------|-----------------|
| KU-2026-05-004 | HS256 JWT with fallback secret | 3 |
| KU-2026-03-021 | Admin endpoints without @PreAuthorize | 2 |

## High-Value Intelligence

| KU ID | Summary | Confidence |
|-------|---------|-----------|
| KU-2026-05-002 | SQL injection in target-org search | 95 |
| KU-2026-04-015 | Exposed admin credentials in GitHub | 90 |
```

---

## Automated Knowledge Extraction

### NLP Entity Extraction from Reports

```bash
# Extract named entities (IPs, domains, emails, hashes) from pentest reports
grep -oP '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' report.md | sort -u > entities_ips.txt
grep -oP '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' report.md | sort -u > entities_emails.txt
grep -oP '\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b' report.md | sort -u > entities_hashes.txt
grep -oP '\b([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b' report.md | sort -u > entities_domains.txt
grep -oP 'CVE-\d{4}-\d{4,7}' report.md | sort -u > entities_cves.txt
```

### Relationship Mining from Session Logs

```python
#!/usr/bin/env python3
"""Extract relationships between knowledge units from session logs."""
import re
import json
from pathlib import Path

MEMORY_DIR = Path("memory/")
LINK_PATTERN = re.compile(r'KU-\d{4}-\d{2}-\d{3}')
TAG_PATTERN = re.compile(r'tags:\s*\[([^\]]+)\]')

def build_relationship_graph():
    graph = {"nodes": [], "edges": []}
    for md_file in MEMORY_DIR.glob("*.md"):
        content = md_file.read_text()
        ku_ids = LINK_PATTERN.findall(content)
        tags_match = TAG_PATTERN.search(content)
        tags = [t.strip() for t in tags_match.group(1).split(",")] if tags_match else []
        if ku_ids:
            primary = ku_ids[0]
            graph["nodes"].append({"id": primary, "tags": tags, "file": str(md_file)})
            for linked in ku_ids[1:]:
                graph["edges"].append({"source": primary, "target": linked})
    return graph

if __name__ == "__main__":
    result = build_relationship_graph()
    print(json.dumps(result, indent=2))
    print(f"Nodes: {len(result['nodes'])}, Edges: {len(result['edges'])}")
```

### Automated Tagging via Keyword Extraction

```bash
# TF-IDF style keyword extraction from knowledge units
find memory/ -name "*.md" -exec sh -c '
  file="$1"
  echo "=== $file ==="
  # Extract top keywords (excluding common stopwords)
  grep -oP "\b[a-z]{4,}\b" "$file" | \
    sort | uniq -c | sort -rn | \
    grep -vE "^\s+[0-9]+ (this|that|with|from|have|been|will|they|their|what|when|where)" | \
    head -10
' _ {} \;
```

### CVE-to-Knowledge Unit Correlation

```bash
# Cross-reference CVEs found in scans with existing knowledge units
CVE_LIST="cve_scan_results.txt"
for cve in $(cat "$CVE_LIST"); do
  matches=$(grep -rln "$cve" memory/)
  if [ -n "$matches" ]; then
    echo "[LINKED] $cve -> $matches"
  else
    echo "[NEW] $cve -> No existing KU, create new entry"
  fi
done
```

### Technology Stack Fingerprinting from Findings

```bash
# Auto-detect technology stack from accumulated findings
echo "=== Technology Stack Summary ==="
echo "Languages:"
grep -rh "tags:" memory/ | grep -oP '(python|javascript|php|java|ruby|golang|rust|csharp)' | sort | uniq -c | sort -rn
echo "Frameworks:"
grep -rh "tags:" memory/ | grep -oP '(express|django|flask|spring|rails|laravel|nextjs|react)' | sort | uniq -c | sort -rn
echo "Infrastructure:"
grep -rh "tags:" memory/ | grep -oP '(aws|azure|gcp|docker|kubernetes|nginx|apache)' | sort | uniq -c | sort -rn
```

---

## Knowledge Base Querying

### SPARQL Queries for Security Ontology

```bash
# Query a local security knowledge graph (Apache Jena/Fuseki)
# Find all vulnerabilities linked to a specific host
curl -s "http://localhost:3030/security/query" \
  --data-urlencode "query=
    PREFIX sec: <http://security.ontology/ns#>
    SELECT ?vuln ?severity ?description WHERE {
      ?vuln sec:affectsHost <http://security.ontology/host/target-org> .
      ?vuln sec:severity ?severity .
      ?vuln sec:description ?description .
    } ORDER BY DESC(?severity)
  " -H "Accept: application/json" | jq '.results.bindings[]'
```

### Cypher Queries for Attack Graph (Neo4j)

```bash
# Query attack paths in Neo4j knowledge graph
cypher-shell -u neo4j -p password "
  // Find all attack paths from external to internal assets
  MATCH path = (entry:Asset {type: 'external'})-[:EXPLOITS*1..5]->(target:Asset {type: 'internal'})
  WHERE target.criticality = 'high'
  RETURN path, length(path) as hops
  ORDER BY hops ASC
  LIMIT 10
"

# Find most connected vulnerability nodes (high-impact targets)
cypher-shell -u neo4j -p password "
  MATCH (v:Vulnerability)-[r]-()
  RETURN v.cve_id, v.severity, count(r) as connections
  ORDER BY connections DESC
  LIMIT 20
"
```

### Semantic Search Across Knowledge Units

```python
#!/usr/bin/env python3
"""Semantic search over knowledge units using embeddings."""
import json
from pathlib import Path

def search_knowledge(query, memory_dir="memory/", top_k=5):
    """Search knowledge units by keyword relevance scoring."""
    query_terms = set(query.lower().split())
    results = []
    for md_file in Path(memory_dir).glob("*.md"):
        content = md_file.read_text().lower()
        score = sum(content.count(term) for term in query_terms)
        if score > 0:
            results.append({"file": str(md_file), "score": score})
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:top_k]

if __name__ == "__main__":
    import sys
    query = sys.argv[1] if len(sys.argv) > 1 else "sql injection authentication"
    hits = search_knowledge(query)
    for hit in hits:
        print(f"  Score: {hit['score']:3d} | {hit['file']}")
```

### Temporal Queries (Time-Based Knowledge Retrieval)

```bash
# Find all knowledge created in the last 7 days
find memory/ -name "*.md" -mtime -7 -exec grep -l "type:" {} \;

# Find knowledge updated but not created recently (active investigations)
find memory/ -name "*.md" -mtime -3 | while read f; do
  created=$(grep "^created:" "$f" | grep -oP '\d{4}-\d{2}-\d{2}')
  updated=$(grep "^updated:" "$f" | grep -oP '\d{4}-\d{2}-\d{2}')
  if [ "$created" != "$updated" ]; then
    echo "[ACTIVE] $f (created: $created, updated: $updated)"
  fi
done
```

### Tag-Based Faceted Search

```bash
# Multi-tag intersection search (AND logic)
TAG1="sql-injection"
TAG2="high-risk"
grep -rln "tags:.*$TAG1" memory/ | while read f; do
  grep -q "tags:.*$TAG2" "$f" && echo "$f"
done

# Tag frequency analysis (find knowledge gaps)
grep -rh "tags:" memory/ | grep -oP '\b[a-z][-a-z]+\b' | \
  sort | uniq -c | sort -rn | head -20
echo "---"
echo "Low-frequency tags (potential knowledge gaps):"
grep -rh "tags:" memory/ | grep -oP '\b[a-z][-a-z]+\b' | \
  sort | uniq -c | sort -n | head -10
```

---

## Knowledge Conflict Resolution

### Version Comparison Between Knowledge Units

```bash
# Detect conflicting confidence scores for the same target+type
grep -rn "target:" memory/ | while read line; do
  file=$(echo "$line" | cut -d: -f1)
  target=$(echo "$line" | grep -oP 'target:\s*\K.*')
  type=$(grep "^type:" "$file" | head -1 | grep -oP 'type:\s*\K.*')
  confidence=$(grep "^confidence:" "$file" | head -1 | grep -oP 'confidence:\s*\K\d+')
  echo "$target|$type|$confidence|$file"
done | sort -t'|' -k1,2 | awk -F'|' '
  prev_key == $1"|"$2 && prev_conf != $3 {
    print "[CONFLICT] " $1 " / " $2 ": " prev_conf " (" prev_file ") vs " $3 " (" $4 ")"
  }
  { prev_key=$1"|"$2; prev_conf=$3; prev_file=$4 }
'
```

### Merge Strategy for Duplicate Findings

```python
#!/usr/bin/env python3
"""Detect and merge duplicate knowledge units."""
import re
from pathlib import Path
from difflib import SequenceMatcher

def find_duplicates(memory_dir="memory/", threshold=0.75):
    """Find KU pairs with high content similarity."""
    files = list(Path(memory_dir).glob("*.md"))
    duplicates = []
    for i, f1 in enumerate(files):
        content1 = f1.read_text()
        summary1 = re.search(r'## Summary\n\n(.+)', content1)
        if not summary1:
            continue
        for f2 in files[i+1:]:
            content2 = f2.read_text()
            summary2 = re.search(r'## Summary\n\n(.+)', content2)
            if not summary2:
                continue
            ratio = SequenceMatcher(None, summary1.group(1), summary2.group(1)).ratio()
            if ratio >= threshold:
                duplicates.append({
                    "file1": str(f1), "file2": str(f2),
                    "similarity": round(ratio, 3)
                })
    return duplicates

if __name__ == "__main__":
    dupes = find_duplicates()
    for d in dupes:
        print(f"[DUP {d['similarity']}] {d['file1']} <-> {d['file2']}")
```

### Conflict Resolution via Confidence Precedence

```bash
# When two KUs conflict, keep the one with higher confidence
# and archive the lower-confidence version
resolve_conflict() {
  local file1="$1" file2="$2"
  conf1=$(grep "^confidence:" "$file1" | grep -oP '\d+')
  conf2=$(grep "^confidence:" "$file2" | grep -oP '\d+')
  if [ "$conf1" -ge "$conf2" ]; then
    echo "[KEEP] $file1 (confidence: $conf1)"
    echo "[ARCHIVE] $file2 (confidence: $conf2)"
    sed -i 's/^type:.*/type: archived/' "$file2"
  else
    echo "[KEEP] $file2 (confidence: $conf2)"
    echo "[ARCHIVE] $file1 (confidence: $conf1)"
    sed -i 's/^type:.*/type: archived/' "$file1"
  fi
}
# Usage: resolve_conflict memory/ku-001.md memory/ku-002.md
```

### Source Authority Ranking

```bash
# Rank knowledge by source reliability
# exploitation > active-scan > static-analysis > osint > hypothesis
declare -A SOURCE_RANK=(
  ["exploitation"]=5
  ["active-scan"]=4
  ["static-analysis"]=3
  ["codebase-onboarding"]=3
  ["osint"]=2
  ["social-intelligence"]=2
  ["hypothesis"]=1
)

grep -rn "^source:" memory/ | while IFS=: read file _ source; do
  source=$(echo "$source" | xargs)
  rank=${SOURCE_RANK[$source]:-0}
  ku_id=$(grep "^id:" "$file" | head -1 | awk '{print $2}')
  echo "$rank|$ku_id|$source|$file"
done | sort -t'|' -k1 -rn
```

---

## Knowledge Decay Detection

### Staleness Scoring Algorithm

```bash
# Calculate staleness score for each knowledge unit
# Score = days_since_update * (1 / confidence) * type_weight
TODAY=$(date +%s)
TYPE_WEIGHT_FINDING=3
TYPE_WEIGHT_ENTITY=2
TYPE_WEIGHT_PATTERN=1

find memory/ -name "*.md" | while read file; do
  updated=$(grep "^updated:" "$file" | grep -oP '\d{4}-\d{2}-\d{2}')
  [ -z "$updated" ] && continue
  updated_epoch=$(date -d "$updated" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "$updated" +%s 2>/dev/null)
  days_old=$(( (TODAY - updated_epoch) / 86400 ))
  confidence=$(grep "^confidence:" "$file" | grep -oP '\d+')
  type=$(grep "^type:" "$file" | awk '{print $2}')
  case "$type" in
    finding) weight=$TYPE_WEIGHT_FINDING ;;
    entity) weight=$TYPE_WEIGHT_ENTITY ;;
    *) weight=$TYPE_WEIGHT_PATTERN ;;
  esac
  staleness=$(echo "scale=2; $days_old * $weight / ($confidence + 1)" | bc)
  echo "Staleness: $staleness | Days: $days_old | $file"
done | sort -t: -k2 -rn | head -20
```

### Refresh Trigger Detection

```bash
# Identify knowledge units that need refresh based on expiry and staleness
TODAY=$(date +%Y-%m-%d)

echo "=== EXPIRED KNOWLEDGE ==="
grep -rn "^expires:" memory/ | grep -v "null" | while IFS=: read file _ expires; do
  expires=$(echo "$expires" | xargs)
  if [[ "$expires" < "$TODAY" ]]; then
    ku_id=$(grep "^id:" "$file" | awk '{print $2}')
    echo "[EXPIRED] $ku_id in $file (expired: $expires)"
  fi
done

echo ""
echo "=== STALE KNOWLEDGE (>30 days without update) ==="
find memory/ -name "*.md" -mtime +30 -exec grep -l "type: finding\|type: entity" {} \; | \
  while read file; do
    ku_id=$(grep "^id:" "$file" | awk '{print $2}')
    updated=$(grep "^updated:" "$file" | grep -oP '\d{4}-\d{2}-\d{2}')
    echo "[STALE] $ku_id | Last updated: $updated | $file"
  done
```

### Confidence Decay Over Time

```python
#!/usr/bin/env python3
"""Apply time-based confidence decay to knowledge units."""
import re
from pathlib import Path
from datetime import datetime, timedelta

DECAY_RATE = 0.02  # 2% per week
MIN_CONFIDENCE = 10

def calculate_decayed_confidence(memory_dir="memory/"):
    today = datetime.now()
    results = []
    for md_file in Path(memory_dir).glob("*.md"):
        content = md_file.read_text()
        conf_match = re.search(r'^confidence:\s*(\d+)', content, re.MULTILINE)
        updated_match = re.search(r'^updated:\s*(\d{4}-\d{2}-\d{2})', content, re.MULTILINE)
        if not conf_match or not updated_match:
            continue
        original_conf = int(conf_match.group(1))
        updated = datetime.strptime(updated_match.group(1), "%Y-%m-%d")
        weeks_elapsed = (today - updated).days / 7
        decayed_conf = max(MIN_CONFIDENCE, int(original_conf * (1 - DECAY_RATE) ** weeks_elapsed))
        if decayed_conf < original_conf:
            results.append({
                "file": str(md_file),
                "original": original_conf,
                "decayed": decayed_conf,
                "weeks_old": round(weeks_elapsed, 1)
            })
    results.sort(key=lambda x: x["original"] - x["decayed"], reverse=True)
    return results

if __name__ == "__main__":
    for r in calculate_decayed_confidence():
        delta = r["original"] - r["decayed"]
        print(f"  {r['original']} -> {r['decayed']} (-{delta}) | {r['weeks_old']}w | {r['file']}")
```

### External Intelligence Feed Comparison

```bash
# Compare local CVE knowledge against NVD feed for updates
NVD_API="https://services.nvd.nist.gov/rest/json/cves/2.0"
LOCAL_CVES=$(grep -rhoP 'CVE-\d{4}-\d{4,7}' memory/ | sort -u)

for cve in $LOCAL_CVES; do
  response=$(curl -s "$NVD_API?cveId=$cve" -H "apiKey: ${NVD_API_KEY}")
  last_modified=$(echo "$response" | jq -r '.vulnerabilities[0].cve.lastModified // empty')
  local_updated=$(grep -rn "$cve" memory/ -l | head -1 | xargs grep "^updated:" | grep -oP '\d{4}-\d{2}-\d{2}')
  if [ -n "$last_modified" ] && [ -n "$local_updated" ]; then
    nvd_date=$(echo "$last_modified" | cut -dT -f1)
    if [[ "$nvd_date" > "$local_updated" ]]; then
      echo "[UPDATE AVAILABLE] $cve: NVD=$nvd_date, Local=$local_updated"
    fi
  fi
done
```

---

## Cross-Domain Knowledge Linking

### Ontology Mapping Between Skill Domains

```bash
# Map knowledge units across skill domains by shared tags
echo "=== Cross-Domain Links ==="
DOMAINS="api-security web-auth-bypass network-pentest cloud-security supply-chain-security"

for tag in $(grep -rh "tags:" memory/ | grep -oP '\b[a-z][-a-z]+\b' | sort | uniq -c | sort -rn | head -20 | awk '{print $2}'); do
  files=$(grep -rln "tags:.*$tag" memory/)
  count=$(echo "$files" | wc -l)
  if [ "$count" -gt 1 ]; then
    domains=$(echo "$files" | grep -oP 'skills/[^/]+' | sort -u | tr '\n' ', ')
    echo "Tag: $tag (${count} KUs) -> Domains: $domains"
  fi
done
```

### Concept Bridging Between Attack Techniques

```python
#!/usr/bin/env python3
"""Build cross-domain concept bridges from MITRE ATT&CK mappings."""
import re
import json
from pathlib import Path
from collections import defaultdict

TECHNIQUE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?')

def build_technique_map(skills_dir="skills/"):
    """Map ATT&CK techniques to skill domains."""
    technique_domains = defaultdict(set)
    for skill_dir in Path(skills_dir).iterdir():
        if not skill_dir.is_dir():
            continue
        domain = skill_dir.name
        for md_file in skill_dir.glob("**/*.md"):
            content = md_file.read_text()
            techniques = TECHNIQUE_PATTERN.findall(content)
            for tech in techniques:
                technique_domains[tech].add(domain)
    # Find techniques spanning multiple domains (bridge concepts)
    bridges = {t: list(d) for t, d in technique_domains.items() if len(d) > 1}
    return bridges

if __name__ == "__main__":
    bridges = build_technique_map()
    print(f"Found {len(bridges)} cross-domain technique bridges:")
    for tech, domains in sorted(bridges.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {tech}: {', '.join(domains)}")
```

### Kill Chain Phase Correlation

```bash
# Link knowledge units by kill chain phase progression
# Recon -> Weaponize -> Deliver -> Exploit -> Install -> C2 -> Actions
PHASES=("recon" "weaponize" "deliver" "exploit" "install" "c2" "exfiltrate")

echo "=== Kill Chain Coverage ==="
for phase in "${PHASES[@]}"; do
  count=$(grep -rln "tags:.*$phase\|phase:.*$phase" memory/ | wc -l)
  printf "  %-12s: %d KUs\n" "$phase" "$count"
done

echo ""
echo "=== Phase Transition Links ==="
for i in $(seq 0 $((${#PHASES[@]}-2))); do
  current="${PHASES[$i]}"
  next="${PHASES[$((i+1))]}"
  links=$(grep -rln "tags:.*$current" memory/ | while read f; do
    grep -q "Leads to:.*$next\|linked:.*$next" "$f" && echo "$f"
  done | wc -l)
  echo "  $current -> $next: $links transitions"
done
```

### Automated Cross-Reference Injection

```bash
# Scan all KUs and suggest missing cross-references
find memory/ -name "*.md" | while read file; do
  ku_id=$(grep "^id:" "$file" | awk '{print $2}')
  target=$(grep "^target:" "$file" | awk '{print $2}')
  [ -z "$ku_id" ] || [ -z "$target" ] && continue

  # Find other KUs with same target but not already linked
  related=$(grep -rln "target: $target" memory/ | grep -v "$file")
  current_links=$(grep "^linked:" "$file" | grep -oP 'KU-\d{4}-\d{2}-\d{3}')

  for rel in $related; do
    rel_id=$(grep "^id:" "$rel" | awk '{print $2}')
    if ! echo "$current_links" | grep -q "$rel_id"; then
      echo "[SUGGEST] $ku_id -> link to $rel_id ($rel)"
    fi
  done
done
```

---

## Knowledge Export and Reporting

### Structured JSON Export

```bash
# Export entire knowledge base as structured JSON
python3 -c "
import re, json
from pathlib import Path

knowledge_base = []
for md_file in sorted(Path('memory/').glob('*.md')):
    content = md_file.read_text()
    frontmatter = re.search(r'^---\n(.*?)\n---', content, re.DOTALL)
    if not frontmatter:
        continue
    entry = {'file': str(md_file)}
    for line in frontmatter.group(1).split('\n'):
        if ':' in line:
            key, val = line.split(':', 1)
            entry[key.strip()] = val.strip()
    summary = re.search(r'## Summary\n\n(.+)', content)
    if summary:
        entry['summary'] = summary.group(1)
    knowledge_base.append(entry)

print(json.dumps(knowledge_base, indent=2))
" > knowledge_export.json
echo "Exported $(jq length knowledge_export.json) knowledge units"
```

### Executive Summary Report Generation

```bash
# Generate executive summary from knowledge base
cat << 'SCRIPT' > /tmp/gen_report.sh
#!/bin/bash
echo "# Security Assessment Knowledge Summary"
echo "Generated: $(date +%Y-%m-%d)"
echo ""
echo "## Statistics"
echo "- Total Knowledge Units: $(find memory/ -name '*.md' | wc -l)"
echo "- Findings: $(grep -rln 'type: finding' memory/ | wc -l)"
echo "- Entities: $(grep -rln 'type: entity' memory/ | wc -l)"
echo "- Patterns: $(grep -rln 'type: pattern' memory/ | wc -l)"
echo "- Archived: $(grep -rln 'type: archived' memory/ | wc -l)"
echo ""
echo "## Critical Findings (Confidence >= 80)"
grep -rn "confidence: [89][0-9]\|confidence: 100" memory/ -l | while read f; do
  summary=$(grep -A1 "## Summary" "$f" | tail -1)
  conf=$(grep "^confidence:" "$f" | awk '{print $2}')
  echo "- [$conf%] $summary"
done
echo ""
echo "## Coverage by Domain"
for domain in api web network cloud mobile; do
  count=$(grep -rln "tags:.*$domain" memory/ | wc -l)
  echo "- $domain: $count KUs"
done
SCRIPT
bash /tmp/gen_report.sh > assessment_summary.md
```

### MITRE ATT&CK Mapping Export

```bash
# Export knowledge mapped to MITRE ATT&CK framework
echo "| Technique ID | Name | KU Count | Confidence (avg) |"
echo "|---|---|---|---|"
grep -rhoP 'T\d{4}(\.\d{3})?' memory/ | sort | uniq -c | sort -rn | while read count tech; do
  # Look up technique name from local mapping
  files=$(grep -rln "$tech" memory/)
  avg_conf=$(echo "$files" | xargs grep "^confidence:" | grep -oP '\d+' | \
    awk '{sum+=$1; n++} END {if(n>0) printf "%.0f", sum/n; else print "N/A"}')
  printf "| %s | - | %d | %s |\n" "$tech" "$count" "$avg_conf"
done
```

### Visualization Data Export (Graph Format)

```python
#!/usr/bin/env python3
"""Export knowledge graph in D3.js-compatible format for visualization."""
import re
import json
from pathlib import Path

def export_graph_data(memory_dir="memory/"):
    nodes = []
    links = []
    node_ids = set()

    for md_file in sorted(Path(memory_dir).glob("*.md")):
        content = md_file.read_text()
        id_match = re.search(r'^id:\s*(KU-[\d-]+)', content, re.MULTILINE)
        type_match = re.search(r'^type:\s*(\w+)', content, re.MULTILINE)
        conf_match = re.search(r'^confidence:\s*(\d+)', content, re.MULTILINE)
        target_match = re.search(r'^target:\s*(.+)', content, re.MULTILINE)
        linked_match = re.search(r'^linked:\s*\[([^\]]*)\]', content, re.MULTILINE)

        if not id_match:
            continue
        ku_id = id_match.group(1)
        node_ids.add(ku_id)
        nodes.append({
            "id": ku_id,
            "type": type_match.group(1) if type_match else "unknown",
            "confidence": int(conf_match.group(1)) if conf_match else 0,
            "target": target_match.group(1).strip() if target_match else "",
            "file": str(md_file)
        })
        if linked_match and linked_match.group(1).strip():
            for linked_id in re.findall(r'KU-[\d-]+', linked_match.group(1)):
                links.append({"source": ku_id, "target": linked_id})

    # Filter links to only include existing nodes
    links = [l for l in links if l["source"] in node_ids and l["target"] in node_ids]
    graph = {"nodes": nodes, "links": links}
    return graph

if __name__ == "__main__":
    graph = export_graph_data()
    with open("knowledge_graph.json", "w") as f:
        json.dump(graph, f, indent=2)
    print(f"Exported: {len(graph['nodes'])} nodes, {len(graph['links'])} links")
```

### Markdown Report with Findings Table

```bash
# Generate a findings table sorted by severity for client reporting
echo "| # | KU ID | Target | Summary | Confidence | Type | Last Updated |"
echo "|---|---|---|---|---|---|---|"
counter=1
grep -rln "type: finding" memory/ | while read file; do
  ku_id=$(grep "^id:" "$file" | awk '{print $2}')
  target=$(grep "^target:" "$file" | sed 's/target: //')
  confidence=$(grep "^confidence:" "$file" | awk '{print $2}')
  updated=$(grep "^updated:" "$file" | awk '{print $2}')
  summary=$(grep -A1 "## Summary" "$file" | tail -1 | cut -c1-60)
  echo "| $counter | $ku_id | $target | $summary | $confidence | finding | $updated |"
  counter=$((counter + 1))
done | sort -t'|' -k5 -rn
```

### Knowledge Base Health Dashboard

```bash
# Generate a health status overview of the knowledge base
echo "=== Knowledge Base Health Report ==="
echo "Date: $(date +%Y-%m-%d)"
echo ""
echo "--- Completeness ---"
total=$(find memory/ -name "*.md" | wc -l)
with_summary=$(grep -rln "## Summary" memory/ | wc -l)
with_links=$(grep -rln "linked:.*KU-" memory/ | wc -l)
echo "  Total KUs: $total"
echo "  With summary: $with_summary ($(( with_summary * 100 / total ))%)"
echo "  With links: $with_links ($(( with_links * 100 / total ))%)"
echo ""
echo "--- Freshness ---"
fresh=$(find memory/ -name "*.md" -mtime -7 | wc -l)
stale=$(find memory/ -name "*.md" -mtime +30 | wc -l)
ancient=$(find memory/ -name "*.md" -mtime +90 | wc -l)
echo "  Fresh (<7 days): $fresh"
echo "  Stale (>30 days): $stale"
echo "  Ancient (>90 days): $ancient"
echo ""
echo "--- Quality ---"
high_conf=$(grep -rn "confidence: [89][0-9]\|confidence: 100" memory/ | wc -l)
low_conf=$(grep -rn "confidence: [12][0-9]" memory/ | wc -l)
echo "  High confidence (80+): $high_conf"
echo "  Low confidence (<30): $low_conf"
```

### Bulk Knowledge Import from Scan Results

```python
#!/usr/bin/env python3
"""Import scan results (Nmap, Nikto, etc.) as knowledge units."""
import re
import json
from datetime import date

def import_nmap_results(nmap_xml_path, target_name):
    """Convert Nmap XML output to knowledge units."""
    import xml.etree.ElementTree as ET
    tree = ET.parse(nmap_xml_path)
    root = tree.getroot()
    knowledge_units = []
    ku_counter = 1

    for host in root.findall('.//host'):
        addr = host.find('address').get('addr')
        for port in host.findall('.//port'):
            port_id = port.get('portid')
            protocol = port.get('protocol')
            state = port.find('state').get('state')
            service = port.find('service')
            svc_name = service.get('name', 'unknown') if service is not None else 'unknown'

            if state == 'open':
                ku = {
                    "id": f"KU-{date.today().strftime('%Y-%m')}-{ku_counter:03d}",
                    "type": "entity",
                    "target": target_name,
                    "confidence": 95,
                    "summary": f"Open port {port_id}/{protocol} ({svc_name}) on {addr}",
                    "tags": ["port", "infrastructure", svc_name]
                }
                knowledge_units.append(ku)
                ku_counter += 1

    return knowledge_units

if __name__ == "__main__":
    import sys
    results = import_nmap_results(sys.argv[1], sys.argv[2])
    for ku in results:
        print(json.dumps(ku))
```

### Knowledge Unit Dependency Graph

```bash
# Build and analyze dependency chains between knowledge units
python3 -c "
import re
from pathlib import Path
from collections import defaultdict

# Build adjacency list
graph = defaultdict(set)
all_nodes = set()

for md_file in Path('memory/').glob('*.md'):
    content = md_file.read_text()
    id_match = re.search(r'^id:\s*(KU-[\d-]+)', content, re.MULTILINE)
    if not id_match:
        continue
    node = id_match.group(1)
    all_nodes.add(node)
    linked = re.findall(r'KU-\d{4}-\d{2}-\d{3}', content)
    for link in linked:
        if link != node:
            graph[node].add(link)

# Find isolated nodes (no connections)
connected = set(graph.keys()) | set(n for targets in graph.values() for n in targets)
isolated = all_nodes - connected
print(f'Total nodes: {len(all_nodes)}')
print(f'Connected: {len(connected)}')
print(f'Isolated: {len(isolated)}')
if isolated:
    print(f'Isolated KUs: {sorted(isolated)[:10]}')

# Find longest chain
def find_longest_path(graph, start, visited=None):
    if visited is None:
        visited = set()
    visited.add(start)
    max_path = [start]
    for neighbor in graph.get(start, []):
        if neighbor not in visited:
            path = [start] + find_longest_path(graph, neighbor, visited.copy())
            if len(path) > len(max_path):
                max_path = path
    return max_path

for node in list(all_nodes)[:5]:
    path = find_longest_path(graph, node)
    if len(path) > 2:
        print(f'Chain from {node}: {\" -> \".join(path)}')
"
```

### Knowledge Archival and Rotation

```bash
# Archive old knowledge units and maintain active set
ARCHIVE_DIR="memory/archive/$(date +%Y-%m)"
mkdir -p "$ARCHIVE_DIR"

# Archive disproven hypotheses
grep -rln "type: archived\|confidence: 0" memory/*.md 2>/dev/null | while read file; do
  echo "[ARCHIVE] Moving $file to $ARCHIVE_DIR/"
  mv "$file" "$ARCHIVE_DIR/"
done

# Archive expired intelligence
TODAY=$(date +%Y-%m-%d)
grep -rn "^expires:" memory/*.md 2>/dev/null | while IFS=: read file _ expires; do
  expires=$(echo "$expires" | xargs)
  if [[ "$expires" != "null" ]] && [[ "$expires" < "$TODAY" ]]; then
    echo "[EXPIRED] Archiving $file (expired: $expires)"
    mv "$file" "$ARCHIVE_DIR/"
  fi
done

echo "Archived to: $ARCHIVE_DIR/"
ls "$ARCHIVE_DIR/" 2>/dev/null | wc -l
```

### Knowledge Completeness Validation

```bash
# Validate all knowledge units have required fields
REQUIRED_FIELDS="id type target confidence created updated tags linked source"
ERRORS=0

find memory/ -name "*.md" -not -path "*/archive/*" | while read file; do
  for field in $REQUIRED_FIELDS; do
    if ! grep -q "^${field}:" "$file"; then
      echo "[MISSING] $file: field '$field' not found"
      ERRORS=$((ERRORS + 1))
    fi
  done

  # Validate confidence is numeric and in range
  conf=$(grep "^confidence:" "$file" | grep -oP '\d+')
  if [ -n "$conf" ] && ([ "$conf" -lt 0 ] || [ "$conf" -gt 100 ]); then
    echo "[INVALID] $file: confidence=$conf (must be 0-100)"
  fi

  # Validate date format
  for date_field in created updated; do
    val=$(grep "^${date_field}:" "$file" | grep -oP '\d{4}-\d{2}-\d{2}')
    if [ -z "$val" ]; then
      echo "[INVALID] $file: $date_field has invalid date format"
    fi
  done
done
echo "Validation complete. Errors: $ERRORS"
```

### Multi-Format Knowledge Export

```bash
# Export knowledge base in multiple formats for different consumers
OUTPUT_DIR="exports/$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

# CSV export for spreadsheet analysis
echo "id,type,target,confidence,created,updated,summary" > "$OUTPUT_DIR/knowledge.csv"
find memory/ -name "*.md" -not -path "*/archive/*" | while read file; do
  id=$(grep "^id:" "$file" | awk '{print $2}')
  type=$(grep "^type:" "$file" | awk '{print $2}')
  target=$(grep "^target:" "$file" | sed 's/target: //' | tr ',' ';')
  conf=$(grep "^confidence:" "$file" | awk '{print $2}')
  created=$(grep "^created:" "$file" | awk '{print $2}')
  updated=$(grep "^updated:" "$file" | awk '{print $2}')
  summary=$(grep -A1 "## Summary" "$file" | tail -1 | tr ',' ';' | cut -c1-100)
  echo "$id,$type,$target,$conf,$created,$updated,$summary"
done >> "$OUTPUT_DIR/knowledge.csv"

echo "Exported: $OUTPUT_DIR/knowledge.csv ($(wc -l < "$OUTPUT_DIR/knowledge.csv") rows)"
```
