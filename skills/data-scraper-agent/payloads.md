# Data Scraper Agent Payloads

## CVE Scraping

### NVD API
```bash
# Search CVEs by keyword
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=apache" | \
  jq '.vulnerabilities[] | {cve: .cve.id, description: .cve.descriptions[0].value}'

# Get specific CVE
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-12345" | \
  jq '.vulnerabilities[0].cve'

# Paginated search (100 per page)
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nginx&resultsPerPage=100&startIndex=0"

# Filter by date range
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2024-01-01T00:00:00.000&pubEndDate=2024-12-31T23:59:59.999"

# Filter by CVSS severity
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL"
```

### Exploit-DB Scraping
```bash
# Search for exploits
searchsploit apache 2.4

# Export to JSON
searchsploit apache 2.4 --json

# Mirror exploit files locally
searchsploit -m 51234

# Search by CVE
searchsploit --cve 2024-12345

# Update database
searchsploit --update
```

### MITRE CVE List
```bash
# Download full CVE list
curl "https://cveawg.mitre.org/api/cve" -o cve_list.json

# Search recent CVEs by CNA
curl "https://cveawg.mitre.org/api/cve?cnaId=cisco&timeModified.gt=2024-01-01"
```

## GitHub Advisory Scraping

```bash
# Using GitHub API
curl "https://api.github.com/advisories?ecosystem=npm" \
  -H "Accept: application/vnd.github+json" | \
  jq '.[] | {id: .ghsa_id, summary: .summary, severity: .severity}'

# Filter by severity
curl "https://api.github.com/advisories?ecosystem=pip&severity=critical" \
  -H "Accept: application/vnd.github+json"

# Get advisory details
curl "https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx" \
  -H "Accept: application/vnd.github+json"
```

### GitHub Code Search for Secrets
```bash
# Search for exposed API keys
gh search code "AKIA" --language=python --json path,repository

# Search for hardcoded passwords
gh search code "password =" --filename=.env --json path,repository

# Search for private keys
gh search code "BEGIN RSA PRIVATE KEY" --json path,repository
```

## HTML Scraping (BeautifulSoup)

```python
import requests
from bs4 import BeautifulSoup

response = requests.get("https://example.com/advisories")
soup = BeautifulSoup(response.content, 'html.parser')

for advisory in soup.select('.advisory'):
    title = advisory.select_one('.title').text
    cve = advisory.select_one('.cve').text
    print(f"{cve}: {title}")
```

### Table Extraction
```python
import pandas as pd

tables = pd.read_html("https://example.com/vulnerabilities")
vuln_table = tables[0]
vuln_table.to_csv("vulnerabilities.csv", index=False)
```

### JavaScript-Rendered Content
```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto("https://example.com/dynamic-content")
    page.wait_for_selector(".vuln-list")
    content = page.content()
    browser.close()

soup = BeautifulSoup(content, 'html.parser')
```

## RSS/Atom Feed Parsing

```python
import feedparser

# Security advisories feed
feed = feedparser.parse("https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml")
for entry in feed.entries[:10]:
    print(f"{entry.title}: {entry.link}")

# Exploit-DB RSS
feed = feedparser.parse("https://www.exploit-db.com/rss.xml")
```

## Rate Limiting & Session Management

```python
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503])
session.mount("https://", HTTPAdapter(max_retries=retries))

def rate_limited_fetch(url, delay=1.0):
    time.sleep(delay)
    response = session.get(url, timeout=30)
    response.raise_for_status()
    return response.json()
```

### Proxy Rotation
```python
proxies = [
    "http://proxy1:8080",
    "http://proxy2:8080",
    "http://proxy3:8080",
]

import random
proxy = {"http": random.choice(proxies), "https": random.choice(proxies)}
response = requests.get(url, proxies=proxy)
```

## Data Extraction Patterns

### JSON Path Extraction
```bash
# Extract nested fields with jq
cat response.json | jq '.data.items[] | {id: .id, name: .name, severity: .metrics.cvssV3.baseSeverity}'

# Filter by condition
cat response.json | jq '.vulnerabilities[] | select(.cve.metrics.cvssMetricV31[0].cvssData.baseScore > 9.0)'

# Flatten nested arrays
cat response.json | jq '[.results[] | .references[]] | unique'
```

### CSV Output
```python
import csv
import json

with open("cves.json") as f:
    data = json.load(f)

with open("cves.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["CVE_ID", "Description", "CVSS_Score", "Published"])
    for vuln in data["vulnerabilities"]:
        cve = vuln["cve"]
        writer.writerow([
            cve["id"],
            cve["descriptions"][0]["value"][:200],
            cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
            cve.get("published", "N/A")
        ])
```

### Regex-Based Extraction
```python
import re

# Extract CVE IDs from text
cve_pattern = r'CVE-\d{4}-\d{4,7}'
cves = re.findall(cve_pattern, text)

# Extract IP addresses
ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
ips = re.findall(ip_pattern, text)

# Extract URLs
url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
urls = re.findall(url_pattern, text)

# Extract email addresses
email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
emails = re.findall(email_pattern, text)
```

## Threat Intelligence Feeds

```bash
# AlienVault OTX
curl "https://otx.alienvault.com/api/v1/pulses/subscribed" \
  -H "X-OTX-API-KEY: $OTX_KEY" | jq '.results[] | {name, created}'

# VirusTotal file report
curl "https://www.virustotal.com/api/v3/files/$SHA256" \
  -H "x-apikey: $VT_KEY"

# Shodan host lookup
curl "https://api.shodan.io/shodan/host/8.8.8.8?key=$SHODAN_KEY"

# Censys host search
curl "https://search.censys.io/api/v2/hosts/search" \
  -H "Authorization: Basic $CENSYS_AUTH" \
  -d '{"q": "services.http.response.headers.server: Apache/2.4"}'
```

## Caching & Deduplication

```python
import hashlib
import json
from pathlib import Path

CACHE_DIR = Path("./cache")
CACHE_DIR.mkdir(exist_ok=True)

def cached_fetch(url, ttl_hours=24):
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_file = CACHE_DIR / f"{cache_key}.json"
    
    if cache_file.exists():
        age_hours = (time.time() - cache_file.stat().st_mtime) / 3600
        if age_hours < ttl_hours:
            return json.loads(cache_file.read_text())
    
    response = rate_limited_fetch(url)
    cache_file.write_text(json.dumps(response))
    return response
```
