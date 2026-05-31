# Advanced Query Construction Guide

> Techniques for building precise Exa and semantic search queries optimized for security research, vulnerability discovery, and threat intelligence gathering.

## 1. Neural vs Keyword Search Modes

Exa supports two search modes with different strengths for security research:

```python
from exa_py import Exa

exa = Exa(api_key="EXA_API_KEY")

# Neural search — best for conceptual/semantic queries
# Finds pages that MATCH the meaning, not just keywords
neural_results = exa.search(
    "techniques for bypassing web application firewalls using encoding",
    type="neural",
    num_results=10,
)

# Keyword search — best for exact technical terms, CVE IDs, tool names
keyword_results = exa.search(
    "CVE-2024-3400 PAN-OS exploit proof of concept",
    type="keyword",
    num_results=10,
)

for r in neural_results.results:
    print(f"[Neural] {r.title} — {r.url}")
```

When to use each mode:
- **Neural**: Conceptual research ("how attackers exfiltrate data from air-gapped networks")
- **Keyword**: Specific identifiers (CVE IDs, tool names, error messages, hash values)

## 2. Date Filtering for Recent Vulnerabilities

Constrain results to specific time windows for fresh intelligence:

```python
from exa_py import Exa
from datetime import datetime, timedelta

exa = Exa(api_key="EXA_API_KEY")

# Last 7 days — catch newly disclosed vulnerabilities
one_week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
today = datetime.now().strftime("%Y-%m-%d")

recent_vulns = exa.search(
    "critical remote code execution vulnerability disclosed",
    type="neural",
    num_results=20,
    start_published_date=one_week_ago,
    end_published_date=today,
)

# Specific date range — research a known incident timeline
incident_results = exa.search(
    "SolarWinds supply chain compromise analysis",
    type="neural",
    num_results=15,
    start_published_date="2020-12-01",
    end_published_date="2021-03-01",
)

for r in recent_vulns.results:
    print(f"[{r.published_date}] {r.title}")
    print(f"  {r.url}")
```

## 3. Domain Filtering for Trusted Sources

Restrict results to authoritative security sources or exclude noise:

```python
from exa_py import Exa

exa = Exa(api_key="EXA_API_KEY")

# Include only trusted security research domains
trusted_results = exa.search(
    "zero-day exploitation techniques 2025",
    type="neural",
    num_results=15,
    include_domains=[
        "arxiv.org",
        "googleprojectzero.blogspot.com",
        "blog.trailofbits.com",
        "portswigger.net",
        "securelist.com",
        "unit42.paloaltonetworks.com",
    ],
)

# Exclude domains that aggregate without original research
filtered_results = exa.search(
    "kubernetes privilege escalation attack",
    type="neural",
    num_results=15,
    exclude_domains=[
        "medium.com",
        "reddit.com",
        "stackoverflow.com",
    ],
)

for r in trusted_results.results:
    print(f"[Trusted] {r.title} — {r.url}")
```

## 4. Query Templates for Common Security Research Tasks

Pre-built query patterns for recurring security research needs:

```python
from exa_py import Exa

exa = Exa(api_key="EXA_API_KEY")

SECURITY_QUERY_TEMPLATES = {
    "exploit_research": "proof of concept exploit for {cve_id} with technical analysis",
    "attack_technique": "real-world attack using {technique} against {target_type}",
    "defense_bypass": "bypassing {defense_mechanism} in modern {environment}",
    "tool_discovery": "open source security tool for {purpose} released {year}",
    "incident_analysis": "post-incident analysis of {incident_name} attack chain",
}

def search_template(template_name, num_results=10, **kwargs):
    query = SECURITY_QUERY_TEMPLATES[template_name].format(**kwargs)
    results = exa.search(query, type="neural", num_results=num_results)
    return results

# Usage examples
results = search_template(
    "exploit_research",
    cve_id="CVE-2024-21762",
)

results = search_template(
    "defense_bypass",
    defense_mechanism="EDR",
    environment="Windows 11 enterprise",
)

results = search_template(
    "tool_discovery",
    purpose="API security testing",
    year="2025",
)

for r in results.results:
    print(f"  {r.title} — {r.url}")
```

## 5. Content Extraction and Highlights

Retrieve page content alongside results for immediate analysis:

```python
from exa_py import Exa

exa = Exa(api_key="EXA_API_KEY")

# Get full text content for deep analysis
results_with_text = exa.search_and_contents(
    "SSRF exploitation techniques cloud metadata",
    type="neural",
    num_results=5,
    text=True,
)

# Get highlighted snippets for quick triage
results_with_highlights = exa.search_and_contents(
    "lateral movement techniques Active Directory",
    type="neural",
    num_results=10,
    highlights=True,
)

for r in results_with_highlights.results:
    print(f"\n[*] {r.title}")
    print(f"    URL: {r.url}")
    if r.highlights:
        for h in r.highlights[:3]:
            print(f"    > {h[:150]}...")
```

## 6. Combining Filters for Precision Queries

Chain multiple filters for highly targeted security research:

```python
from exa_py import Exa
from datetime import datetime, timedelta

exa = Exa(api_key="EXA_API_KEY")

def precision_security_search(topic, days_back=30, sources=None):
    start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

    params = {
        "type": "neural",
        "num_results": 15,
        "start_published_date": start_date,
        "text": True,
        "highlights": True,
    }
    if sources:
        params["include_domains"] = sources

    results = exa.search_and_contents(topic, **params)

    findings = []
    for r in results.results:
        findings.append({
            "title": r.title,
            "url": r.url,
            "date": r.published_date,
            "highlights": r.highlights[:3] if r.highlights else [],
            "text_preview": r.text[:500] if r.text else "",
        })
    return findings

# Example: Recent cloud security research from trusted sources
findings = precision_security_search(
    topic="AWS IAM privilege escalation new technique",
    days_back=14,
    sources=["rhinosecuritylabs.com", "blog.trailofbits.com", "securitylabs.datadoghq.com"],
)

for f in findings:
    print(f"\n[{f['date']}] {f['title']}")
    print(f"  {f['url']}")
    for h in f["highlights"]:
        print(f"  > {h[:120]}")
```

```bash
# Quick CLI search using curl for one-off queries
curl -s -X POST "https://api.exa.ai/search" \
  -H "x-api-key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "critical vulnerability disclosed this week",
    "type": "neural",
    "numResults": 5,
    "startPublishedDate": "2026-05-22"
  }' | jq '.results[] | {title, url, publishedDate}'
```
