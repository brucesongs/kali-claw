# Exa API Configuration Guide

> Skill: exa-search | Type: tool-specific
> Created: 2026-05-29 | Estimated Study Time: 20 minutes

## Overview

Complete reference for configuring and using the Exa API effectively — authentication, endpoint parameters, response handling, error management, and integration patterns for security research workflows.

## Prerequisites

- Exa API key (from dashboard.exa.ai)
- curl or Python requests/exa_py library
- Basic REST API familiarity

## 1. Authentication and Setup

### Environment Configuration
```bash
# Set API key
export EXA_API_KEY="your-api-key-here"

# Test connectivity
curl -X POST "https://api.exa.ai/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": "test", "num_results": 1}'
```

### Python SDK Setup
```python
from exa_py import Exa

exa = Exa(api_key="your-api-key")

# Or from environment
import os
exa = Exa(api_key=os.environ["EXA_API_KEY"])
```

## 2. API Endpoints

### `/search` — Find Pages by Query

```python
results = exa.search(
    query="remote code execution in Node.js applications",
    type="neural",           # "neural", "keyword", or "auto"
    num_results=10,          # 1-100
    use_autoprompt=True,     # Let Exa optimize the query
    start_published_date="2024-01-01",
    end_published_date=None,
    include_domains=["github.com", "portswigger.net"],
    exclude_domains=["medium.com"],
)
```

### `/search` with Contents — Search + Extract in One Call

```python
results = exa.search_and_contents(
    query="SSRF bypass techniques cloud metadata",
    type="neural",
    num_results=5,
    text=True,                       # Full page text
    highlights=True,                  # Relevant snippets
    text_max_characters=3000,         # Limit text length
    highlight_num_sentences=3,        # Sentences per highlight
)

for r in results.results:
    print(f"Title: {r.title}")
    print(f"URL: {r.url}")
    print(f"Score: {r.score}")
    print(f"Highlights: {r.highlights}")
    print(f"Text: {r.text[:200]}...")
```

### `/find_similar` — Find Pages Similar to a URL

```python
results = exa.find_similar(
    url="https://portswigger.net/research/top-10-web-hacking-techniques-of-2023",
    num_results=10,
    exclude_source_domain=True,
    start_published_date="2024-01-01",
)
```

### `/contents` — Extract Content from Known URLs

```python
results = exa.get_contents(
    ids=[
        "https://blog.example.com/cve-writeup",
        "https://security.example.com/advisory",
    ],
    text=True,
    highlights=True,
)
```

## 3. Search Type Selection

| Type | Use When | Example Query |
|------|----------|---------------|
| `neural` | Conceptual/broad research | "techniques for lateral movement in cloud environments" |
| `keyword` | Exact terms matter | "CVE-2024-3094 xz-utils" |
| `auto` | Unsure which is better | "Log4Shell impact assessment" |

### Auto-Prompt Feature

```python
# Let Exa rewrite your query for better results
results = exa.search(
    query="hack kubernetes",
    use_autoprompt=True    # Exa transforms to better query internally
)
```

## 4. Filtering Parameters

### Date Filtering
```python
# Published in the last 7 days
from datetime import datetime, timedelta
week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

results = exa.search(
    query="zero day exploit disclosed",
    start_published_date=week_ago,
)
```

### Domain Filtering
```python
# Security research sources only
SECURITY_DOMAINS = [
    "portswigger.net",
    "googleprojectzero.blogspot.com",
    "labs.watchtowr.com",
    "blog.assetnote.io",
    "research.nccgroup.com",
    "github.com",
    "arxiv.org",
]

results = exa.search(
    query="novel web vulnerability class",
    include_domains=SECURITY_DOMAINS,
)
```

## 5. Response Structure

```python
# SearchResult object
result = results.results[0]

result.title            # Page title
result.url              # Page URL
result.score            # Relevance score (0-1)
result.published_date   # Publication date (if available)
result.author           # Author (if available)
result.text             # Full text (if requested)
result.highlights       # Relevant snippets (if requested)
```

## 6. Error Handling

```python
from exa_py.exceptions import ExaError
import time

def safe_search(exa, query, max_retries=3, **kwargs):
    for attempt in range(max_retries):
        try:
            return exa.search(query, **kwargs)
        except ExaError as e:
            if "rate" in str(e).lower() and attempt < max_retries - 1:
                wait = 2 ** attempt
                time.sleep(wait)
                continue
            raise
    return None
```

### Common Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| 401 | Invalid API key | Check EXA_API_KEY |
| 429 | Rate limited | Wait and retry with backoff |
| 400 | Bad request | Check query parameters |
| 500 | Server error | Retry after delay |

## 7. Integration Patterns

### Batch Search Pipeline
```python
def batch_search(queries, delay=1.0):
    all_results = []
    seen_urls = set()
    
    for query in queries:
        results = safe_search(exa, query, num_results=10, type="auto")
        if results:
            for r in results.results:
                if r.url not in seen_urls:
                    seen_urls.add(r.url)
                    all_results.append(r)
        time.sleep(delay)
    
    return sorted(all_results, key=lambda r: r.score, reverse=True)
```

### Continuous Monitoring
```python
def monitor_topic(topic, check_interval_hours=6):
    from datetime import datetime, timedelta
    
    last_check = datetime.now() - timedelta(hours=check_interval_hours)
    start_date = last_check.strftime("%Y-%m-%d")
    
    results = exa.search_and_contents(
        query=topic,
        start_published_date=start_date,
        num_results=20,
        type="auto",
        highlights=True,
    )
    
    new_items = []
    for r in results.results:
        new_items.append({
            "title": r.title,
            "url": r.url,
            "highlights": r.highlights[:2] if r.highlights else [],
            "published": r.published_date,
        })
    
    return new_items
```

### Export Results
```python
import json

def export_results(results, filename):
    data = [{
        "title": r.title,
        "url": r.url,
        "score": r.score,
        "published": r.published_date,
        "text": r.text[:1000] if r.text else None,
    } for r in results.results]
    
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
```

## Quick Reference

| Action | Method | Key Params |
|--------|--------|------------|
| Search by query | `exa.search()` | query, type, num_results |
| Search + content | `exa.search_and_contents()` | + text, highlights |
| Find similar | `exa.find_similar()` | url, exclude_source_domain |
| Get content | `exa.get_contents()` | ids, text, highlights |
| Date filter | Any search method | start/end_published_date |
| Domain filter | Any search method | include/exclude_domains |

## Integration with Other Skills

- **data-scraper-agent**: Use Exa to discover URLs, then scrape full content with specialized parsers
- **deep-research**: Exa as primary discovery engine for multi-source intelligence
- **knowledge-ops**: Store high-value Exa results as knowledge units for cross-session retrieval
