# Structured Data Extraction Guide

> Extract and normalize structured data from APIs with robust pagination, error handling, and JSON transformation techniques.

## Prerequisites

- Python 3.8+ with httpx/requests
- jq for command-line JSON processing
- Basic understanding of REST API conventions

## 1. API Pagination Patterns

### Offset-Based Pagination

```python
import httpx

def fetch_all_offset(base_url: str, params: dict = None, page_size: int = 100) -> list:
    """Fetch all records using offset/limit pagination."""
    params = params or {}
    results = []
    offset = 0

    with httpx.Client(timeout=30) as client:
        while True:
            params.update({"offset": offset, "limit": page_size})
            resp = client.get(base_url, params=params)
            resp.raise_for_status()
            data = resp.json()

            items = data.get("results", data.get("data", []))
            if not items:
                break
            results.extend(items)
            offset += page_size

            # Respect total count if provided
            total = data.get("total", data.get("total_count"))
            if total and offset >= total:
                break

    return results
```

### Cursor-Based Pagination

```python
def fetch_all_cursor(base_url: str, headers: dict = None) -> list:
    """Fetch all records using cursor/next-page pagination."""
    results = []
    next_url = base_url

    with httpx.Client(timeout=30, headers=headers) as client:
        while next_url:
            resp = client.get(next_url)
            resp.raise_for_status()
            data = resp.json()

            items = data.get("results", data.get("items", []))
            results.extend(items)

            # Handle different cursor patterns
            next_url = (
                data.get("next")
                or data.get("pagination", {}).get("next_url")
                or data.get("links", {}).get("next")
            )

    return results
```

### Bash Cursor Pagination with jq

```bash
#!/bin/bash
# Paginate through a cursor-based API
BASE_URL="https://api.example.com/v1/records"
NEXT_URL="$BASE_URL"
OUTPUT="results.jsonl"
> "$OUTPUT"

while [ -n "$NEXT_URL" ] && [ "$NEXT_URL" != "null" ]; do
    RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$NEXT_URL")
    echo "$RESPONSE" | jq -c '.results[]' >> "$OUTPUT"
    NEXT_URL=$(echo "$RESPONSE" | jq -r '.next // empty')
    sleep 1
done

echo "Total records: $(wc -l < "$OUTPUT")"
```

## 2. JSON Normalization

### Flattening Nested Structures

```python
def flatten_json(obj: dict, prefix: str = "") -> dict:
    """Flatten nested JSON into dot-notation keys."""
    flat = {}
    for key, value in obj.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(flatten_json(value, full_key))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    flat.update(flatten_json(item, f"{full_key}[{i}]"))
                else:
                    flat[f"{full_key}[{i}]"] = item
        else:
            flat[full_key] = value
    return flat

# Example: CVE record normalization
raw_cve = {
    "id": "CVE-2024-1234",
    "metrics": {"cvssV3": {"baseScore": 9.8, "vector": "AV:N/AC:L"}},
    "affected": [{"vendor": "apache", "product": "httpd"}],
}
flat = flatten_json(raw_cve)
# {'id': 'CVE-2024-1234', 'metrics.cvssV3.baseScore': 9.8, ...}
```

### jq Transformations

```bash
# Flatten and extract specific fields from API response
curl -s "$API_URL" | jq '[.results[] | {
  id: .id,
  severity: .metrics.cvssV3.baseScore,
  vendor: .affected[0].vendor,
  product: .affected[0].product,
  published: .published,
  description: .descriptions[0].value
}]'

# Normalize inconsistent field names
cat raw-data.json | jq '[.[] | {
  id: (.id // .cve_id // .vulnerability_id),
  score: (.cvss_score // .metrics.baseScore // 0),
  title: (.title // .summary // .descriptions[0].value // "unknown")
}]'

# Group by severity
cat vulns.json | jq 'group_by(.severity) | map({severity: .[0].severity, count: length})'
```

## 3. Error Handling and Retry Logic

```python
import time
import httpx

class ResilientFetcher:
    """HTTP client with exponential backoff and error classification."""

    RETRYABLE_CODES = {429, 500, 502, 503, 504}

    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.client = httpx.Client(timeout=30, follow_redirects=True)

    def fetch(self, url: str, params: dict = None) -> dict:
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.client.get(url, params=params)
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code in self.RETRYABLE_CODES:
                    delay = self._backoff_delay(attempt, resp)
                    time.sleep(delay)
                    continue
                resp.raise_for_status()
            except httpx.ConnectError:
                if attempt == self.max_retries:
                    raise
                time.sleep(self._backoff_delay(attempt))
        raise RuntimeError(f"Failed after {self.max_retries} retries: {url}")

    def _backoff_delay(self, attempt: int, resp=None) -> float:
        if resp and resp.headers.get("Retry-After"):
            return float(resp.headers["Retry-After"])
        return self.base_delay * (2 ** attempt)

    def close(self):
        self.client.close()
```

## 4. Streaming Large Datasets

```python
import json
import httpx

def stream_jsonl(url: str, output_path: str, headers: dict = None):
    """Stream large API responses to JSONL file without loading all into memory."""
    with open(output_path, "w") as f:
        with httpx.stream("GET", url, headers=headers, timeout=60) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if line.strip():
                    record = json.loads(line)
                    normalized = normalize_record(record)
                    f.write(json.dumps(normalized) + "\n")

def normalize_record(record: dict) -> dict:
    """Normalize a single record to consistent schema."""
    return {
        "id": record.get("id", record.get("cve_id", "")),
        "severity": record.get("severity", "unknown"),
        "score": float(record.get("score", record.get("cvss", 0))),
        "description": record.get("description", "")[:500],
        "source": record.get("source", "unknown"),
    }
```

### Bash Streaming with jq

```bash
# Stream and transform large JSONL files
curl -s "$API_URL" | jq -c --stream 'fromstream(1|truncate_stream(inputs))' | \
while IFS= read -r record; do
    id=$(echo "$record" | jq -r '.id')
    score=$(echo "$record" | jq -r '.cvss_score // 0')
    echo "$id,$score" >> extracted.csv
done
```

## 5. Schema Validation

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class VulnerabilityRecord:
    id: str
    severity: str
    score: float
    description: str
    source: str

    @classmethod
    def from_api(cls, raw: dict) -> "VulnerabilityRecord":
        """Validate and construct from raw API data."""
        vuln_id = raw.get("id", "")
        if not vuln_id:
            raise ValueError("Missing required field: id")

        score = float(raw.get("score", raw.get("cvss", 0)))
        if not (0.0 <= score <= 10.0):
            raise ValueError(f"Invalid CVSS score: {score}")

        return cls(
            id=vuln_id,
            severity=raw.get("severity", "unknown").lower(),
            score=score,
            description=raw.get("description", "")[:1000],
            source=raw.get("source", "unknown"),
        )
```

## 6. Multi-Source Aggregation

```bash
#!/bin/bash
# Aggregate vulnerability data from multiple APIs into unified JSONL

OUTPUT="aggregated-vulns.jsonl"
> "$OUTPUT"

# Source 1: NVD
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50" | \
    jq -c '.vulnerabilities[] | {id: .cve.id, source: "nvd", score: (.cve.metrics.cvssMetricV31[0].cvssData.baseScore // 0)}' >> "$OUTPUT"

# Source 2: OSV
curl -s -X POST "https://api.osv.dev/v1/query" -d '{"package":{"name":"lodash","ecosystem":"npm"}}' | \
    jq -c '.vulns[] | {id: .id, source: "osv", score: (.severity[0].score // 0)}' >> "$OUTPUT"

# Deduplicate by ID
sort -t'"' -k4 -u "$OUTPUT" -o "$OUTPUT"
echo "Total unique records: $(wc -l < "$OUTPUT")"
```

## Quick Reference

| Pattern | Use Case | Key Function |
|---------|----------|--------------|
| Offset pagination | Fixed-size pages | `offset += page_size` |
| Cursor pagination | Real-time data | Follow `next` link |
| Exponential backoff | Rate limit handling | `delay * 2^attempt` |
| JSONL streaming | Large datasets | Line-by-line processing |
| Schema validation | Data integrity | Validate before store |

## Integration with Other Skills

- **data-scraper-agent**: Core data extraction patterns
- **osint**: Structured intelligence gathering from public APIs
- **repo-scan**: Parsing vulnerability database responses
