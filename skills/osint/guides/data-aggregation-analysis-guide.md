# OSINT Data Aggregation and Analysis Guide

## Introduction

Collecting OSINT data is only half the work -- aggregating, deduplicating, and analyzing it into actionable intelligence is where value is created. This guide covers data normalization, correlation, and visualization techniques for turning raw OSINT into structured findings.

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

## Data Source Correlation Techniques

### Multi-Source Fusion

Effective OSINT analysis requires fusing data from disparate sources with different formats, reliability levels, and collection timestamps. The key challenge is establishing equivalence between entities described differently across sources.

```python
class DataSourceFusion:
    """Fuse intelligence from multiple heterogeneous OSINT sources."""

    SOURCE_RELIABILITY = {
        "certificate_transparency": 0.95,
        "whois": 0.90,
        "dns_passive": 0.85,
        "search_engine": 0.75,
        "social_media": 0.60,
        "forum_post": 0.50,
        "paste_site": 0.40,
    }

    def __init__(self):
        self.entity_store = {}
        self.relationship_graph = defaultdict(set)

    def ingest(self, source_name, raw_data, collection_time=None):
        """Ingest data from a single source with reliability scoring."""
        reliability = self.SOURCE_RELIABILITY.get(source_name, 0.30)
        collection_time = collection_time or datetime.utcnow()

        normalized = self._normalize_source(source_name, raw_data)

        for entry in normalized:
            entity_key = self._resolve_entity(entry)
            if entity_key in self.entity_store:
                self._merge_entity(entity_key, entry, reliability)
            else:
                self._create_entity(entity_key, entry, reliability, source_name)

    def _resolve_entity(self, entry):
        """Determine if an entry matches an existing entity."""
        # Check by primary identifiers first
        for identifier in entry.get("identifiers", []):
            for existing_key, existing in self.entity_store.items():
                if identifier in existing.get("all_identifiers", set()):
                    return existing_key

        # Fuzzy matching for near-matches
        return self._fuzzy_match(entry) or self._generate_key(entry)
```

### Correlation Scoring

```python
def calculate_correlation_score(entity_a, entity_b):
    """Score the strength of correlation between two entities."""
    score = 0.0
    max_score = 0.0

    # Shared indicators (weighted by type)
    indicator_weights = {
        "shared_ip": 0.30,
        "shared_domain": 0.25,
        "shared_email": 0.20,
        "shared_hash": 0.15,
        "shared_url": 0.10,
    }

    for indicator_type, weight in indicator_weights.items():
        max_score += weight
        if indicator_type == "shared_ip":
            shared = set(entity_a.get("ips", [])) & set(entity_b.get("ips", []))
            if shared:
                score += weight
        elif indicator_type == "shared_domain":
            shared = set(entity_a.get("domains", [])) & set(entity_b.get("domains", []))
            if shared:
                score += weight

    return score / max_score if max_score > 0 else 0.0
```

## Entity Resolution

Entity resolution determines whether two records from different sources refer to the same real-world entity. This is critical for avoiding both false merges and missed connections.

### Deterministic Matching

```python
def deterministic_match(record_a, record_b):
    """Match records based on exact field comparisons."""
    match_rules = [
        ("email", lambda a, b: a.get("email", "").lower() == b.get("email", "").lower()),
        ("ip_domain", lambda a, b: bool(set(a.get("ips", [])) & set(b.get("ips", [])))),
        ("domain_match", lambda a, b: bool(set(a.get("domains", [])) & set(b.get("domains", [])))),
        ("name_dob", lambda a, b: (
            a.get("name", "").lower() == b.get("name", "").lower()
            and a.get("dob") == b.get("dob")
        )),
    ]

    matches = []
    for rule_name, match_fn in match_rules:
        try:
            if match_fn(record_a, record_b):
                matches.append(rule_name)
        except (KeyError, TypeError):
            continue

    return {
        "is_match": len(matches) >= 1,
        "match_types": matches,
        "confidence": len(matches) / len(match_rules),
    }
```

### Probabilistic Matching

```python
from difflib import SequenceMatcher

def probabilistic_match(record_a, record_b, threshold=0.75):
    """Match records using fuzzy comparison with confidence scoring."""
    field_scores = {}

    # Name similarity
    if record_a.get("name") and record_b.get("name"):
        name_similarity = SequenceMatcher(
            None,
            record_a["name"].lower(),
            record_b["name"].lower()
        ).ratio()
        field_scores["name"] = name_similarity * 0.40

    # Location similarity
    if record_a.get("location") and record_b.get("location"):
        loc_similarity = SequenceMatcher(
            None,
            record_a["location"].lower(),
            record_b["location"].lower()
        ).ratio()
        field_scores["location"] = loc_similarity * 0.20

    # Username pattern similarity
    if record_a.get("username") and record_b.get("username"):
        username_similarity = SequenceMatcher(
            None,
            record_a["username"].lower(),
            record_b["username"].lower()
        ).ratio()
        field_scores["username"] = username_similarity * 0.25

    # Temporal proximity
    if record_a.get("timestamp") and record_b.get("timestamp"):
        time_diff = abs(
            (record_a["timestamp"] - record_b["timestamp"]).total_seconds()
        )
        temporal_score = max(0, 1 - (time_diff / 86400))  # Decay over 24h
        field_scores["temporal"] = temporal_score * 0.15

    total_score = sum(field_scores.values())
    return {
        "is_match": total_score >= threshold,
        "confidence": total_score,
        "field_scores": field_scores,
    }
```

## Timeline Analysis

Reconstructing the chronological sequence of events is essential for understanding attack timelines, data exposure windows, and the evolution of threats.

### Timeline Construction

```python
from datetime import datetime
from collections import defaultdict

def build_analytical_timeline(findings):
    """Build a detailed timeline from OSINT findings with gap analysis."""
    timeline = {
        "events": [],
        "clusters": [],
        "gaps": [],
        "key_moments": [],
    }

    # Sort all findings by timestamp
    sorted_findings = sorted(
        findings,
        key=lambda f: f.get("timestamp", datetime.min)
    )

    # Convert to timeline events
    for finding in sorted_findings:
        event = {
            "timestamp": finding["timestamp"],
            "source": finding["source"],
            "event_type": finding.get("type", "unknown"),
            "description": finding.get("description", ""),
            "severity": finding.get("severity", "info"),
            "entities": finding.get("entities", []),
            "indicators": finding.get("indicators", {}),
        }
        timeline["events"].append(event)

    # Cluster events into activity periods
    timeline["clusters"] = cluster_events(
        timeline["events"],
        max_gap_hours=6
    )

    # Identify gaps in coverage
    timeline["gaps"] = find_coverage_gaps(
        timeline["events"],
        min_gap_hours=24
    )

    # Highlight key moments
    timeline["key_moments"] = identify_key_moments(timeline["events"])

    return timeline

def cluster_events(events, max_gap_hours=6):
    """Group temporally proximate events into activity clusters."""
    if not events:
        return []

    clusters = []
    current_cluster = [events[0]]

    for event in events[1:]:
        time_gap = (event["timestamp"] - current_cluster[-1]["timestamp"]).total_seconds()
        if time_gap <= max_gap_hours * 3600:
            current_cluster.append(event)
        else:
            clusters.append(finalize_cluster(current_cluster))
            current_cluster = [event]

    clusters.append(finalize_cluster(current_cluster))
    return clusters

def finalize_cluster(events):
    """Summarize a cluster of related events."""
    return {
        "start": events[0]["timestamp"],
        "end": events[-1]["timestamp"],
        "duration_hours": (
            events[-1]["timestamp"] - events[0]["timestamp"]
        ).total_seconds() / 3600,
        "event_count": len(events),
        "event_types": list(set(e["event_type"] for e in events)),
        "sources": list(set(e["source"] for e in events)),
        "max_severity": max_severity(events),
    }
```

## Link Analysis Methodology

Link analysis reveals hidden relationships between entities that are not apparent when examining data points individually.

### Graph Construction

```python
class OSINTGraph:
    """Build and analyze relationship graphs from OSINT data."""

    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.node_index = defaultdict(set)

    def add_entity(self, entity_id, entity_type, attributes=None):
        """Add an entity as a graph node."""
        self.nodes[entity_id] = {
            "id": entity_id,
            "type": entity_type,
            "attributes": attributes or {},
            "degree": 0,
        }

    def add_relationship(self, source_id, target_id, rel_type, weight=1.0, metadata=None):
        """Add a relationship as a graph edge."""
        edge = {
            "source": source_id,
            "target": target_id,
            "type": rel_type,
            "weight": weight,
            "metadata": metadata or {},
        }
        self.edges.append(edge)

        # Update index
        self.node_index[source_id].add(target_id)
        self.node_index[target_id].add(source_id)

        # Update degree counts
        if source_id in self.nodes:
            self.nodes[source_id]["degree"] += 1
        if target_id in self.nodes:
            self.nodes[target_id]["degree"] += 1

    def find_central_entities(self, top_n=10):
        """Identify the most connected entities (highest centrality)."""
        sorted_nodes = sorted(
            self.nodes.values(),
            key=lambda n: n["degree"],
            reverse=True
        )
        return sorted_nodes[:top_n]

    def find_shortest_path(self, start_id, end_id):
        """Find the shortest relationship path between two entities."""
        from collections import deque

        visited = {start_id}
        queue = deque([(start_id, [start_id])])

        while queue:
            current, path = queue.popleft()
            for neighbor in self.node_index[current]:
                if neighbor == end_id:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None

    def find_communities(self):
        """Detect clusters of tightly connected entities."""
        communities = []
        assigned = set()

        for node_id in self.nodes:
            if node_id in assigned:
                continue

            community = self._expand_community(node_id, assigned)
            if len(community) >= 2:
                communities.append(community)
                assigned.update(community)

        return communities

    def _expand_community(self, start_id, assigned, min_weight=0.5):
        """Expand a community from a seed node using edge weights."""
        community = {start_id}
        frontier = {start_id}

        while frontier:
            current = frontier.pop()
            for neighbor in self.node_index[current]:
                if neighbor not in assigned and neighbor not in community:
                    edge_weight = self._get_edge_weight(current, neighbor)
                    if edge_weight >= min_weight:
                        community.add(neighbor)
                        frontier.add(neighbor)

        return community
```

## Data Visualization Tools

### Graph Visualization with NetworkX

```python
import json

def export_to_d3(graph_data):
    """Export graph data in D3.js compatible format."""
    d3_format = {
        "nodes": [],
        "links": [],
    }

    type_colors = {
        "domain": "#4CAF50",
        "ip": "#2196F3",
        "email": "#FF9800",
        "person": "#9C27B0",
        "organization": "#F44336",
        "tool": "#607D8B",
    }

    for node_id, node in graph_data["nodes"].items():
        d3_format["nodes"].append({
            "id": node_id,
            "group": node["type"],
            "color": type_colors.get(node["type"], "#999999"),
            "size": min(node["degree"] * 3 + 10, 60),
            "label": node["attributes"].get("name", node_id),
        })

    for edge in graph_data["edges"]:
        d3_format["links"].append({
            "source": edge["source"],
            "target": edge["target"],
            "value": edge.get("weight", 1),
            "type": edge.get("type", "unknown"),
        })

    return d3_format
```

### Timeline Visualization

```python
def generate_timeline_json(timeline_data):
    """Generate timeline data for visualization libraries."""
    visualization = {
        "scale": "time",
        "start": min(e["timestamp"] for e in timeline_data["events"]).isoformat(),
        "end": max(e["timestamp"] for e in timeline_data["events"]).isoformat(),
        "events": [],
        "clusters": [],
    }

    severity_colors = {
        "critical": "#D32F2F",
        "high": "#F44336",
        "medium": "#FF9800",
        "low": "#FFC107",
        "info": "#4CAF50",
    }

    for event in timeline_data["events"]:
        visualization["events"].append({
            "start": event["timestamp"].isoformat(),
            "content": event["description"][:100],
            "className": f"severity-{event['severity']}",
            "style": f"background-color: {severity_colors.get(event['severity'], '#999')}",
            "metadata": {
                "source": event["source"],
                "type": event["event_type"],
            },
        })

    return visualization
```

## Automated Data Pipeline Construction

### Pipeline Architecture

```python
class OSINTPipeline:
    """Orchestrate automated OSINT data collection, processing, and analysis."""

    def __init__(self, config):
        self.config = config
        self.collectors = []
        self.processors = []
        self.analyzers = []
        self.output_handlers = []

    def add_collector(self, collector):
        """Register a data collector (e.g., API client, scraper)."""
        self.collectors.append(collector)

    def add_processor(self, processor):
        """Register a data processor (e.g., normalizer, deduplicator)."""
        self.processors.append(processor)

    def add_analyzer(self, analyzer):
        """Register an analyzer (e.g., correlation engine, timeline builder)."""
        self.analyzers.append(analyzer)

    def run(self):
        """Execute the full pipeline."""
        # Phase 1: Collection
        raw_data = []
        for collector in self.collectors:
            try:
                data = collector.collect()
                raw_data.extend(data)
            except Exception as e:
                log_error(f"Collector {collector.name} failed: {e}")

        # Phase 2: Processing
        processed_data = raw_data
        for processor in self.processors:
            processed_data = processor.process(processed_data)

        # Phase 3: Analysis
        analysis_results = {}
        for analyzer in self.analyzers:
            result = analyzer.analyze(processed_data)
            analysis_results[analyzer.name] = result

        # Phase 4: Output
        for handler in self.output_handlers:
            handler.output(processed_data, analysis_results)

        return {
            "raw_count": len(raw_data),
            "processed_count": len(processed_data),
            "analysis": analysis_results,
        }
```

### Scheduled Collection

```bash
# Cron-based automated OSINT collection
# Run daily subdomain enumeration
0 6 * * * /opt/osint/scripts/subdomain-monitor.sh >> /var/log/osint/collection.log 2>&1

# Run weekly credential leak check
0 8 * * 1 /opt/osint/scripts/credential-monitor.sh >> /var/log/osint/credentials.log 2>&1

# Run monthly full reconnaissance update
0 2 1 * * /opt/osint/scripts/full-recon-update.sh >> /var/log/osint/monthly.log 2>&1
```

### Change Detection

```python
def detect_changes(previous_snapshot, current_snapshot):
    """Detect changes between two data snapshots."""
    changes = {
        "new": [],
        "removed": [],
        "modified": [],
    }

    prev_set = {item["fingerprint"]: item for item in previous_snapshot}
    curr_set = {item["fingerprint"]: item for item in current_snapshot}

    prev_keys = set(prev_set.keys())
    curr_keys = set(curr_set.keys())

    changes["new"] = [curr_set[k] for k in (curr_keys - prev_keys)]
    changes["removed"] = [prev_set[k] for k in (prev_keys - curr_keys)]

    for key in prev_keys & curr_keys:
        if prev_set[key]["content_hash"] != curr_set[key]["content_hash"]:
            changes["modified"].append({
                "previous": prev_set[key],
                "current": curr_set[key],
            })

    return changes
```

## Quality Assurance for OSINT Data

### Confidence Scoring Framework

```python
class ConfidenceScorer:
    """Assign confidence scores to OSINT findings based on multiple factors."""

    FACTOR_WEIGHTS = {
        "source_reliability": 0.30,
        "corroboration_count": 0.25,
        "data_freshness": 0.20,
        "collection_method": 0.15,
        "completeness": 0.10,
    }

    SOURCE_RELIABILITY = {
        "official_registry": 0.95,
        "certificate_transparency": 0.95,
        "direct_api": 0.90,
        "passive_dns": 0.85,
        "search_engine": 0.70,
        "social_media": 0.60,
        "forum": 0.45,
        "paste_site": 0.35,
        "unknown": 0.20,
    }

    def score_finding(self, finding):
        """Calculate composite confidence score for a finding."""
        scores = {}

        # Source reliability
        source_type = finding.get("source_type", "unknown")
        scores["source_reliability"] = self.SOURCE_RELIABILITY.get(source_type, 0.20)

        # Corroboration (how many sources confirm this finding)
        corroboration = finding.get("corroboration_count", 1)
        scores["corroboration_count"] = min(corroboration / 5, 1.0)

        # Data freshness
        if finding.get("timestamp"):
            age_days = (datetime.utcnow() - finding["timestamp"]).days
            scores["data_freshness"] = max(0, 1 - (age_days / 365))
        else:
            scores["data_freshness"] = 0.30

        # Collection method
        method = finding.get("collection_method", "unknown")
        method_scores = {
            "api_query": 0.90,
            "passive_collection": 0.80,
            "web_scraping": 0.60,
            "manual_entry": 0.50,
            "unknown": 0.30,
        }
        scores["collection_method"] = method_scores.get(method, 0.30)

        # Data completeness
        required_fields = finding.get("required_fields", [])
        filled_fields = sum(1 for f in required_fields if finding.get(f))
        scores["completeness"] = filled_fields / len(required_fields) if required_fields else 0.50

        # Weighted composite
        composite = sum(
            scores[factor] * weight
            for factor, weight in self.FACTOR_WEIGHTS.items()
        )

        return {
            "composite_score": round(composite, 3),
            "factor_scores": scores,
            "confidence_level": self._categorize_confidence(composite),
        }

    def _categorize_confidence(self, score):
        """Map numeric score to confidence category."""
        if score >= 0.80:
            return "high"
        elif score >= 0.60:
            return "medium"
        elif score >= 0.40:
            return "low"
        return "unverified"
```

### Data Validation Rules

```python
def validate_osint_finding(finding):
    """Apply validation rules to catch common data quality issues."""
    issues = []

    # Check for empty or missing critical fields
    critical_fields = ["timestamp", "source", "indicators"]
    for field in critical_fields:
        if not finding.get(field):
            issues.append(f"Missing critical field: {field}")

    # Validate timestamp sanity
    if finding.get("timestamp"):
        if finding["timestamp"] > datetime.utcnow():
            issues.append("Timestamp is in the future")
        if finding["timestamp"] < datetime(1990, 1, 1):
            issues.append("Timestamp is unreasonably old")

    # Validate indicator formats
    for ioc_type, values in finding.get("indicators", {}).items():
        for value in values:
            if not validate_indicator_format(ioc_type, value):
                issues.append(f"Invalid {ioc_type} format: {value}")

    # Check for poisoned data patterns
    if is_likely_honeypot(finding):
        issues.append("Finding matches honeypot patterns")

    return {
        "is_valid": len([i for i in issues if "critical" in i.lower()]) == 0,
        "issues": issues,
        "warning_count": len(issues),
    }
```

## Hands-on Exercises

Practice the techniques described in this guide against authorized targets or lab environments. Document your findings and methodology for each exercise.
## References

- [MITRE -- ATT&CK Knowledge Repository](https://attack.mitre.org/)
- [STIX/TAXII -- Threat Intelligence Standards](https://oasis-open.github.io/cti-documentation/)
- [MISP -- Threat Intelligence Platform](https://www.misp-project.org/)
- [OpenCTI -- Threat Intelligence Platform](https://www.opencti.io/)
- [Maltego -- OSINT Visualization](https://www.maltego.com/)
- [NetworkX -- Python Graph Library](https://networkx.org/)
- [D3.js -- Data Visualization](https://d3js.org/)
