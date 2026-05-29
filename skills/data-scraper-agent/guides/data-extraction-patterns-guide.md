# Data Extraction Patterns Guide

> Skill: data-scraper-agent | Type: methodology
> Created: 2026-05-29 | Estimated Study Time: 25 minutes

## Overview

Learn systematic data extraction patterns for security intelligence gathering — from structured APIs to unstructured web pages, with reliable parsing, error handling, and output formatting.

## Prerequisites

- Python 3.8+ with requests, beautifulsoup4, lxml
- jq for command-line JSON processing
- Basic understanding of HTML/CSS selectors

## 1. Extraction Strategy Selection

| Source Type | Tool | Best For |
|-------------|------|----------|
| REST API (JSON) | requests + jq | CVE databases, threat feeds |
| HTML pages | BeautifulSoup + lxml | Advisories, blog posts |
| JavaScript-rendered | Playwright | SPAs, dynamic dashboards |
| RSS/Atom feeds | feedparser | News, update notifications |
| PDF reports | pdfplumber | Threat reports, whitepapers |

## 2. API Response Extraction

### JSON Path Patterns
```bash
# Flat extraction
cat response.json | jq '.data[] | {id, name, severity}'

# Nested extraction with defaults
cat response.json | jq '.items[] | {
  id: .id,
  score: (.metrics.cvss.score // "N/A"),
  vector: (.metrics.cvss.vector // "unknown")
}'

# Conditional filtering
cat response.json | jq '[.vulnerabilities[] | select(.cvss >= 7.0)] | sort_by(-.cvss)'

# Array flattening
cat response.json | jq '[.results[].references[]] | unique | .[]'
```

### Python Extraction with Validation
```python
from dataclasses import dataclass
from typing import Optional

@dataclass
class VulnRecord:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    published: str
    affected_products: list

def extract_vuln(raw: dict) -> Optional[VulnRecord]:
    try:
        cve = raw["cve"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            ""
        )
        score = None
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metrics = cve.get("metrics", {}).get(metric_key, [])
            if metrics:
                score = metrics[0].get("cvssData", {}).get("baseScore")
                break
        
        return VulnRecord(
            cve_id=cve["id"],
            description=desc[:500],
            cvss_score=score,
            published=cve.get("published", ""),
            affected_products=[
                c.get("criteria", "")
                for c in cve.get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [])
            ][:10]
        )
    except (KeyError, IndexError, TypeError):
        return None
```

## 3. HTML Scraping Patterns

### CSS Selector Strategy
```python
from bs4 import BeautifulSoup
import requests

def scrape_advisory_page(url):
    response = requests.get(url, timeout=30, headers={
        "User-Agent": "Mozilla/5.0 (security-research)"
    })
    soup = BeautifulSoup(response.content, "lxml")
    
    advisories = []
    for item in soup.select(".advisory-item, .vuln-entry, tr.cve-row"):
        advisory = {
            "title": safe_text(item, ".title, .advisory-title, td:nth-child(1)"),
            "cve": safe_text(item, ".cve-id, .cve, td:nth-child(2)"),
            "severity": safe_text(item, ".severity, .risk-level, td:nth-child(3)"),
            "date": safe_text(item, ".date, .published, td:nth-child(4)"),
            "link": safe_attr(item, "a", "href"),
        }
        if advisory["cve"]:
            advisories.append(advisory)
    
    return advisories

def safe_text(element, selectors):
    for selector in selectors.split(", "):
        found = element.select_one(selector)
        if found:
            return found.get_text(strip=True)
    return ""

def safe_attr(element, tag, attr):
    found = element.select_one(tag)
    return found.get(attr, "") if found else ""
```

### Table Extraction
```python
import pandas as pd

def extract_tables(url):
    tables = pd.read_html(url)
    for i, table in enumerate(tables):
        if any(col.lower() in ["cve", "vulnerability", "severity"] 
               for col in table.columns):
            return table
    return tables[0] if tables else pd.DataFrame()
```

## 4. Regex-Based Extraction

```python
import re

PATTERNS = {
    "cve": r"CVE-\d{4}-\d{4,7}",
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "domain": r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    "hash_md5": r"\b[a-fA-F0-9]{32}\b",
    "hash_sha256": r"\b[a-fA-F0-9]{64}\b",
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "url": r"https?://[^\s<>\"'{}|\\^`\[\]]+",
}

def extract_iocs(text):
    results = {}
    for name, pattern in PATTERNS.items():
        matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
        if matches:
            results[name] = sorted(matches)
    return results
```

## 5. Output Formatting

### CSV Export
```python
import csv

def export_csv(records, filename):
    if not records:
        return
    fieldnames = records[0].keys() if isinstance(records[0], dict) else records[0].__dataclass_fields__.keys()
    
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            row = record if isinstance(record, dict) else record.__dict__
            writer.writerow(row)
```

### JSON Lines (for streaming)
```python
import json

def export_jsonl(records, filename):
    with open(filename, "w") as f:
        for record in records:
            obj = record if isinstance(record, dict) else record.__dict__
            f.write(json.dumps(obj) + "\n")
```

### Markdown Report
```python
def export_markdown(records, filename):
    with open(filename, "w") as f:
        f.write("# Extraction Results\n\n")
        f.write(f"Total records: {len(records)}\n\n")
        f.write("| CVE | CVSS | Description |\n")
        f.write("|-----|------|-------------|\n")
        for r in records[:50]:
            f.write(f"| {r['cve_id']} | {r['cvss_score'] or 'N/A'} | {r['description'][:80]} |\n")
```

## 6. Error Handling and Resilience

```python
import time
from requests.exceptions import RequestException

def resilient_fetch(url, max_retries=3, backoff=2.0):
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 429:
                wait = int(response.headers.get("Retry-After", backoff * (2 ** attempt)))
                time.sleep(wait)
                continue
            response.raise_for_status()
            return response
        except RequestException as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(backoff * (2 ** attempt))
    return None
```

## Quick Reference

| Pattern | Use Case | Reliability |
|---------|----------|-------------|
| API + jq | Structured data sources | High |
| BeautifulSoup | Static HTML pages | Medium |
| Playwright | JS-rendered content | High (slow) |
| Regex | IOC extraction from text | Medium |
| pandas.read_html | HTML tables | High |

## Integration with Other Skills

- **exa-search**: Discover URLs to scrape via semantic search
- **browser-qa**: Handle JavaScript-rendered pages requiring interaction
- **knowledge-ops**: Store extracted data as knowledge units for cross-session use
