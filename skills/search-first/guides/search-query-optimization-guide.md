# Search Query Optimization Guide

> Techniques for crafting effective search queries across code repositories, documentation, and vulnerability databases.

---

## 1. Query Construction Principles

### Keyword Selection Strategy

```bash
# Start broad, narrow progressively
# Level 1: General concept
gh search code "authentication bypass"

# Level 2: Technology-specific
gh search code "authentication bypass" --language=python

# Level 3: Pattern-specific
gh search code "authenticate.*bypass.*token" --language=python
```

### Boolean and Filter Operators

```bash
# GitHub code search operators
gh search code "org:target sql injection" --filename=*.py
gh search code "repo:target/app password OR secret OR token"

# Combine filters for precision
gh search code "IDOR" --language=javascript --filename="*controller*"

# Exclude noise
gh search code "CVE-2024" --language=python -- -test -mock -example
```

---

## 2. Vulnerability Database Search

### NVD/CVE Search Patterns

```bash
# Search NVD by keyword
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=apache+struts+rce" \
  | jq '.vulnerabilities[:5] | .[].cve | {id, description: .descriptions[0].value, severity: .metrics.cvssMetricV31[0].cvssData.baseScore}'

# Search by CPE (product-specific)
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:apache:struts:2.5.0:*:*:*:*:*:*:*" \
  | jq '.vulnerabilities[].cve.id'

# Search ExploitDB
searchsploit "apache struts" --json | jq '.RESULTS_EXPLOIT[:5] | .[].Title'

# Search by date range
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2024-01-01T00:00:00.000&pubEndDate=2024-12-31T23:59:59.999&keywordSearch=rce" \
  | jq '.totalResults'
```

### Advisory Aggregation

```bash
# GitHub Security Advisories
gh api graphql -f query='
{
  securityAdvisories(first: 10, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    nodes {
      ghsaId
      summary
      severity
      publishedAt
    }
  }
}'

# OSV.dev (open source vulnerabilities)
curl -s -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"lodash","ecosystem":"npm"}}' \
  | jq '.vulns[:3] | .[].id'
```

---

## 3. Source Code Search Strategies

### Pattern-Based Code Search

```bash
# Find dangerous function usage
grep -rn "eval\|exec\|system\|popen" --include="*.py" .
grep -rn "dangerouslySetInnerHTML\|innerHTML" --include="*.tsx" --include="*.jsx" .

# Find hardcoded secrets
grep -rnE "(api[_-]?key|secret|token|password)\s*[=:]\s*['\"][^'\"]{8,}" --include="*.py" --include="*.js" .

# Find SQL injection patterns
grep -rnE "execute\(.*(%s|%d|\{|\+.*input)" --include="*.py" .
grep -rnE "query\(.*\`.*\$\{" --include="*.ts" --include="*.js" .
```

### Semantic Search with Embeddings

```python
from sentence_transformers import SentenceTransformer
import numpy as np

model = SentenceTransformer('all-MiniLM-L6-v2')

def search_codebase(query, code_snippets, top_k=5):
    query_embedding = model.encode([query])
    code_embeddings = model.encode(code_snippets)
    similarities = np.dot(code_embeddings, query_embedding.T).flatten()
    top_indices = similarities.argsort()[-top_k:][::-1]
    return [(code_snippets[i], similarities[i]) for i in top_indices]
```

---

## 4. Web Search for Security Research

### Google Dorking for Research

```
# Find disclosed vulnerabilities
"responsible disclosure" site:hackerone.com "target.com"
"bug bounty" site:medium.com "target technology"

# Find configuration leaks
site:pastebin.com "target.com" password
site:trello.com "target.com" credentials

# Find exposed documentation
site:target.com filetype:pdf "internal" OR "confidential"
site:docs.google.com "target.com"
```

### Academic and Technical Paper Search

```bash
# Search for technique papers
# Google Scholar: "SQL injection" "machine learning" detection 2024
# arXiv: cat:cs.CR "fuzzing" 2024

# Semantic Scholar API
curl -s "https://api.semanticscholar.org/graph/v1/paper/search?query=web+application+security+testing&limit=5&fields=title,year,citationCount" \
  | jq '.data[] | {title, year, citations: .citationCount}'
```

---

## 5. Search Result Prioritization

### Relevance Scoring Framework

```python
def score_search_result(result, context):
    score = 0.0
    
    # Recency (newer = more relevant for CVEs)
    if result.get("date"):
        days_old = (datetime.now() - result["date"]).days
        score += max(0, 1.0 - (days_old / 365))
    
    # Source authority
    authority_scores = {
        "nvd.nist.gov": 1.0,
        "github.com/security": 0.9,
        "hackerone.com": 0.85,
        "exploit-db.com": 0.8,
    }
    score += authority_scores.get(result["source"], 0.5)
    
    # Keyword match density
    keywords = context.get("keywords", [])
    text = result.get("text", "").lower()
    matches = sum(1 for k in keywords if k.lower() in text)
    score += (matches / max(len(keywords), 1)) * 0.5
    
    return score
```

---

## 6. Iterative Refinement Workflow

```bash
#!/bin/bash
# search-refine.sh — Iterative search with progressive narrowing
QUERY="$1"
CONTEXT="$2"

echo "[Phase 1] Broad search: $QUERY"
results_broad=$(gh search code "$QUERY" --limit 20 --json path,repository)

echo "[Phase 2] Filter by relevance"
echo "$results_broad" | jq -r '.[].repository.fullName' | sort -u > repos.txt

echo "[Phase 3] Deep dive into top repos"
head -5 repos.txt | while read repo; do
    echo "  Scanning: $repo"
    gh search code "$QUERY $CONTEXT" --repo="$repo" --json path,textMatches
done
```
