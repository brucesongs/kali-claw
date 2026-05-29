# Exa Search Payloads

## Setup
```bash
export EXA_API_KEY="your_api_key_here"
EXA_BASE="https://api.exa.ai"
```

## Basic Search
```bash
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "CVE-2024 affecting nginx",
    "num_results": 10,
    "use_autoprompt": true
  }'
```

## Search Types

### Neural Search (Semantic)
```bash
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "techniques for bypassing web application firewalls",
    "type": "neural",
    "num_results": 10
  }'
```

### Keyword Search (Exact Match)
```bash
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "CVE-2024-3094 xz backdoor",
    "type": "keyword",
    "num_results": 10
  }'
```

### Auto Search (Let Exa Decide)
```bash
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Log4Shell exploitation techniques in the wild",
    "type": "auto",
    "num_results": 10
  }'
```

## Date Filtering
```bash
# Only results from last 30 days
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Spring Boot vulnerabilities",
    "num_results": 10,
    "start_published_date": "2024-04-01"
  }'

# Results within a specific window
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "zero day exploits disclosed",
    "start_published_date": "2024-01-01",
    "end_published_date": "2024-06-30",
    "num_results": 20
  }'
```

## Domain Filtering
```bash
# Search only security-focused sites
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "JWT security best practices",
    "num_results": 10,
    "include_domains": ["github.com", "portswigger.net", "owasp.org"]
  }'

# Exclude noise domains
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SQL injection prevention",
    "num_results": 10,
    "exclude_domains": ["stackoverflow.com", "medium.com", "reddit.com"]
  }'
```

## Content Extraction
```bash
# Get full text content with search
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Log4Shell exploitation techniques",
    "num_results": 5,
    "contents": {
      "text": true
    }
  }'

# Get highlighted snippets only
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SSRF cloud metadata exploitation",
    "num_results": 10,
    "contents": {
      "highlights": true
    }
  }'

# Get both text and highlights with length limit
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "container escape techniques",
    "num_results": 5,
    "contents": {
      "text": {"max_characters": 3000},
      "highlights": {"num_sentences": 3}
    }
  }'
```

## Find Similar Pages
```bash
# Find pages similar to a known security writeup
curl -X POST "$EXA_BASE/find_similar" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://portswigger.net/research/top-10-web-hacking-techniques-of-2023",
    "num_results": 10
  }'

# Find similar with domain filter
curl -X POST "$EXA_BASE/find_similar" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
    "num_results": 10,
    "exclude_domains": ["github.com"]
  }'
```

## Get Contents by URL
```bash
# Extract content from known URLs
curl -X POST "$EXA_BASE/contents" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "ids": [
      "https://blog.example.com/cve-2024-writeup",
      "https://security.example.com/advisory-001"
    ],
    "text": true
  }'
```

## Security Research Query Examples

### CVE Research
```bash
# Recent critical CVEs
"CVE-2024 affecting AWS services"
"critical vulnerabilities container runtimes 2024"
"zero day exploit disclosed this week"
"CVE proof of concept github"

# Specific product research
"nginx vulnerability remote code execution"
"kubernetes RBAC privilege escalation"
"chrome V8 type confusion exploit"
```

### Exploit Techniques
```bash
# Attack methodology
"SSRF bypass in cloud metadata services"
"SQL injection in GraphQL implementations"
"OAuth 2.0 redirect_uri validation bypass"
"deserialization exploit Java Spring"
"prototype pollution to RCE Node.js"

# Bypass techniques
"WAF bypass techniques 2024"
"CSP bypass using JSONP endpoints"
"AMSI bypass PowerShell latest"
```

### Tool Research
```bash
# Discovery
"best open-source SAST tools for Go"
"automated exploit frameworks 2024"
"subdomain enumeration tools comparison"
"cloud security posture management open source"

# Configuration
"nuclei custom templates writing guide"
"burp suite extension development"
"metasploit module development tutorial"
```

### Threat Intelligence
```bash
# Actor research
"APT groups targeting financial sector"
"ransomware campaigns healthcare 2024"
"nation state cyber operations attribution"

# Campaign tracking
"supply chain attack npm packages"
"cryptomining malware cloud environments"
"initial access brokers dark web"
```

## Python SDK Integration

```python
from exa_py import Exa

exa = Exa(api_key="your_api_key")

# Basic search with contents
results = exa.search_and_contents(
    "remote code execution vulnerabilities in popular CMS",
    type="neural",
    num_results=10,
    text=True,
    highlights=True,
    start_published_date="2024-01-01"
)

for result in results.results:
    print(f"Title: {result.title}")
    print(f"URL: {result.url}")
    print(f"Score: {result.score}")
    print(f"Text: {result.text[:200]}...")
    print("---")
```

### Batch Research Pipeline
```python
queries = [
    "CVE-2024 nginx remote code execution",
    "nginx configuration hardening guide",
    "nginx WAF bypass techniques",
]

all_results = []
for query in queries:
    results = exa.search(query, num_results=5, type="auto")
    all_results.extend(results.results)

# Deduplicate by URL
unique = {r.url: r for r in all_results}
print(f"Found {len(unique)} unique results from {len(queries)} queries")
```

### Continuous Monitoring
```python
import time
from datetime import datetime, timedelta

def monitor_new_vulns(keyword, interval_hours=6):
    last_check = datetime.now() - timedelta(hours=interval_hours)
    results = exa.search(
        f"{keyword} vulnerability disclosed",
        start_published_date=last_check.strftime("%Y-%m-%d"),
        num_results=20,
        type="auto"
    )
    return results.results

# Check every 6 hours for new findings
new_findings = monitor_new_vulns("kubernetes")
for finding in new_findings:
    print(f"[NEW] {finding.title}: {finding.url}")
```
