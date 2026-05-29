# NVD API Scraping Guide

> Skill: data-scraper-agent | Type: practical
> Created: 2026-05-29 | Estimated Study Time: 30 minutes

## Overview

Master the NIST National Vulnerability Database (NVD) API 2.0 for automated CVE intelligence gathering — pagination, rate limiting, caching, and structured data extraction.

## Prerequisites

- curl and jq installed
- Python 3.8+ with requests library
- Optional: NVD API key (higher rate limits)

## 1. NVD API 2.0 Fundamentals

### Base URL and Authentication

```bash
NVD_BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"

# Without API key: 5 requests per 30 seconds
curl "$NVD_BASE?keywordSearch=apache"

# With API key: 50 requests per 30 seconds
curl "$NVD_BASE?keywordSearch=apache" -H "apiKey: $NVD_API_KEY"
```

### Response Structure

```json
{
  "resultsPerPage": 2000,
  "startIndex": 0,
  "totalResults": 12345,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-12345",
        "descriptions": [{"lang": "en", "value": "..."}],
        "metrics": {"cvssMetricV31": [...]},
        "references": [...]
      }
    }
  ]
}
```

## 2. Search Parameters

### Keyword Search
```bash
# Single keyword
curl "$NVD_BASE?keywordSearch=nginx"

# Exact phrase match
curl "$NVD_BASE?keywordSearch=remote+code+execution&keywordExactMatch"
```

### Date Range Filtering
```bash
# CVEs published in a specific range
curl "$NVD_BASE?pubStartDate=2024-01-01T00:00:00.000&pubEndDate=2024-12-31T23:59:59.999"

# CVEs modified recently (for monitoring)
curl "$NVD_BASE?lastModStartDate=2024-06-01T00:00:00.000&lastModEndDate=2024-06-30T23:59:59.999"
```

### CVSS Severity Filter
```bash
# Only CRITICAL (9.0-10.0)
curl "$NVD_BASE?cvssV3Severity=CRITICAL"

# Only HIGH (7.0-8.9)
curl "$NVD_BASE?cvssV3Severity=HIGH"
```

### CPE Match (Product-Specific)
```bash
# All CVEs for Apache HTTP Server 2.4.x
curl "$NVD_BASE?cpeName=cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"

# Vulnerable configuration search
curl "$NVD_BASE?virtualMatchString=cpe:2.3:a:microsoft:exchange_server:*"
```

## 3. Pagination Strategy

```python
import requests
import time

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
RATE_LIMIT_DELAY = 6.0  # seconds between requests (no API key)

def fetch_all_cves(params):
    all_vulns = []
    start_index = 0
    
    while True:
        params["startIndex"] = start_index
        params["resultsPerPage"] = RESULTS_PER_PAGE
        
        response = requests.get(NVD_BASE, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)
        total = data["totalResults"]
        
        print(f"Fetched {len(all_vulns)}/{total}")
        
        if len(all_vulns) >= total:
            break
        
        start_index += RESULTS_PER_PAGE
        time.sleep(RATE_LIMIT_DELAY)
    
    return all_vulns

# Usage
cves = fetch_all_cves({"keywordSearch": "kubernetes", "cvssV3Severity": "CRITICAL"})
```

## 4. Rate Limiting Best Practices

```python
from datetime import datetime, timedelta
import threading

class RateLimiter:
    def __init__(self, max_requests=5, window_seconds=30):
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self.requests = []
        self.lock = threading.Lock()
    
    def wait(self):
        with self.lock:
            now = datetime.now()
            self.requests = [t for t in self.requests if now - t < self.window]
            
            if len(self.requests) >= self.max_requests:
                sleep_time = (self.requests[0] + self.window - now).total_seconds()
                time.sleep(max(0, sleep_time) + 0.1)
            
            self.requests.append(datetime.now())

limiter = RateLimiter(max_requests=5, window_seconds=30)
```

## 5. Caching Strategy

```python
import json
import hashlib
from pathlib import Path

CACHE_DIR = Path("./nvd_cache")
CACHE_DIR.mkdir(exist_ok=True)
CACHE_TTL_HOURS = 4

def cached_nvd_fetch(params):
    cache_key = hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()[:16]
    cache_file = CACHE_DIR / f"{cache_key}.json"
    
    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < CACHE_TTL_HOURS * 3600:
            return json.loads(cache_file.read_text())
    
    limiter.wait()
    response = requests.get(NVD_BASE, params=params, timeout=30)
    response.raise_for_status()
    data = response.json()
    
    cache_file.write_text(json.dumps(data))
    return data
```

## 6. Data Processing Pipeline

```python
def extract_cve_summary(vuln):
    cve = vuln["cve"]
    
    # Get CVSS score
    cvss_score = None
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics:
        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    
    # Get English description
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "No description available"
    )
    
    return {
        "id": cve["id"],
        "description": description[:300],
        "cvss_score": cvss_score,
        "published": cve.get("published"),
        "references": [ref["url"] for ref in cve.get("references", [])[:5]]
    }

# Process all results
summaries = [extract_cve_summary(v) for v in cves]
critical = [s for s in summaries if s["cvss_score"] and s["cvss_score"] >= 9.0]
print(f"Found {len(critical)} critical CVEs out of {len(summaries)} total")
```

## Quick Reference

| Parameter | Example | Description |
|-----------|---------|-------------|
| keywordSearch | `apache http` | Text search in descriptions |
| cvssV3Severity | `CRITICAL` | Filter by severity level |
| pubStartDate | `2024-01-01T00:00:00.000` | Published after date |
| cpeName | `cpe:2.3:a:vendor:product:*` | Product-specific CVEs |
| resultsPerPage | `2000` | Max results per request |
| startIndex | `0` | Pagination offset |

## Integration with Other Skills

- **deep-research**: Feed CVE IDs into deep-research for full threat analysis
- **exa-search**: Cross-reference CVEs with exploit writeups via semantic search
- **security-review**: Use CVE data to check if project dependencies are affected
