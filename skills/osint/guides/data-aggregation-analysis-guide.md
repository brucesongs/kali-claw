# OSINT Data Aggregation and Analysis Guide

## Introduction

Collecting OSINT data is only half the work — aggregating, deduplicating, and analyzing it into actionable intelligence is where value is created. This guide covers data normalization, correlation, and visualization techniques for turning raw OSINT into structured findings.

## Practical Steps

### 1. Data Normalization Pipeline

```python
import re
from datetime import datetime

def normalize_osint(raw_data):
    """Normalize diverse OSINT sources into a unified schema."""
    normalized = []
    for item in raw_data:
        entry = {
            "source": item.get("source", "unknown"),
            "timestamp": parse_timestamp(item.get("date", "")),
            "type": classify_entry(item),
            "raw": item,
            "indicators": extract_indicators(item.get("content", "")),
            "confidence": score_confidence(item),
        }
        normalized.append(entry)
    return normalized

def extract_indicators(text):
    """Extract IOC patterns from text."""
    patterns = {
        "ipv4": r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        "domain": r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b',
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
        "hash_md5": r'\b[a-fA-F0-9]{32}\b',
        "hash_sha256": r'\b[a-fA-F0-9]{64}\b',
        "cve": r'CVE-\d{4}-\d{4,}',
    }
    indicators = {}
    for ioc_type, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            indicators[ioc_type] = list(set(matches))
    return indicators
```

### 2. Cross-Source Correlation

```python
from collections import defaultdict

def correlate_findings(datasets):
    """Find connections across different OSINT sources."""
    correlation = {
        "shared_indicators": defaultdict(list),
        "timeline_gaps": [],
        "entity_clusters": [],
    }

    # Build indicator index
    indicator_map = defaultdict(list)
    for dataset in datasets:
        for entry in dataset:
            for ioc_type, values in entry["indicators"].items():
                for value in values:
                    indicator_map[(ioc_type, value)].append(entry)

    # Find shared indicators across sources
    for key, entries in indicator_map.items():
        if len(entries) > 1:
            correlation["shared_indicators"][key].extend(entries)

    return correlation
```

### 3. Deduplication Strategies

```python
import hashlib

def deduplicate(findings):
    """Remove duplicate findings across sources."""
    seen = set()
    unique = []

    for finding in findings:
        # Create content fingerprint
        content = str(sorted(finding["indicators"].items()))
        fingerprint = hashlib.sha256(content.encode()).hexdigest()

        if fingerprint not in seen:
            seen.add(fingerprint)
            unique.append(finding)

    return unique
```

### 4. Intelligence Report Generation

```python
def generate_report(correlated_data):
    """Produce structured intelligence report."""
    return {
        "executive_summary": summarize_findings(correlated_data),
        "iocs": {
            "domains": extract_unique(correlated_data, "domain"),
            "ips": extract_unique(correlated_data, "ipv4"),
            "hashes": extract_unique(correlated_data, "hash_sha256"),
            "urls": extract_unique(correlated_data, "url"),
        },
        "timeline": build_timeline(correlated_data),
        "confidence_assessment": assess_reliability(correlated_data),
        "recommendations": prioritize_actions(correlated_data),
    }
```

### 5. Visualization with Graphs

```python
def build_entity_graph(correlated_data):
    """Build relationship graph for visualization."""
    nodes = []
    edges = []

    for entity in correlated_data["entities"]:
        nodes.append({"id": entity["name"], "type": entity["type"]})

    for relation in correlated_data["relations"]:
        edges.append({
            "source": relation["from"],
            "target": relation["to"],
            "label": relation["type"],
        })

    return {"nodes": nodes, "edges": edges}
```

## References

- [MITRE — ATT&CK Knowledge Repository](https://attack.mitre.org/)
- [STIX/TAXII — Threat Intelligence Standards](https://oasis-open.github.io/cti-documentation/)
- [MISP — Threat Intelligence Platform](https://www.misp-project.org/)
- [OpenCTI — Threat Intelligence Platform](https://www.opencti.io/)
- [Maltego — OSINT Visualization](https://www.maltego.com/)
