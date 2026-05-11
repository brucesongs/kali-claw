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
```

### Exploit-DB Scraping
```bash
# Search for exploits
searchsploit apache 2.4

# Export to JSON
searchsploit apache 2.4 --json
```

## GitHub Advisory Scraping
```bash
# Using GitHub API
curl "https://api.github.com/advisories?ecosystem=npm" -H "Accept: application/vnd.github+json" | \
  jq '.[] | {id: .ghsa_id, summary: .summary, severity: .severity}'
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
