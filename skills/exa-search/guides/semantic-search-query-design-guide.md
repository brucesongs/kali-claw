# Semantic Search Query Design Guide

> Skill: exa-search | Type: methodology
> Created: 2026-05-29 | Estimated Study Time: 25 minutes

## Overview

Master the art of crafting effective semantic search queries for security research — understanding how neural search differs from keyword search, optimizing query structure, and building multi-query research pipelines.

## Prerequisites

- Exa API access (API key)
- Understanding of security research domains
- Basic familiarity with information retrieval concepts

## 1. Neural vs Keyword Search

| Aspect | Neural (Semantic) | Keyword (Exact) |
|--------|-------------------|-----------------|
| Matching | Meaning/intent | Exact terms |
| Best for | Broad research, concepts | Specific CVEs, error messages |
| Example | "techniques for bypassing WAFs" | "CVE-2024-3094 xz backdoor" |
| Noise | May include tangential results | Misses rephrased content |
| Query style | Natural language statement | Boolean/exact phrases |

### When to Use Each

```
Neural: "methods attackers use to escape Docker containers"
→ Returns conceptual matches including "container breakout", "cgroup escape", etc.

Keyword: "CVE-2024-21626 runc leaky-vessels"
→ Returns exact matches for this specific vulnerability
```

## 2. Query Design Principles

### Principle 1: State What You Want to Find, Not What You're Looking For

```
WEAK: "SQL injection"
→ Too broad, returns tutorials, definitions, news

STRONG: "novel SQL injection techniques bypassing modern WAF rules in 2024"
→ Specific intent signals exactly what content is valuable
```

### Principle 2: Include Context Signals

```
WEAK: "SSRF attacks"
→ Generic results

STRONG: "SSRF exploitation targeting AWS EC2 metadata service IMDSv2 bypass"
→ Context narrows to specific technique + environment
```

### Principle 3: Match the Content's Voice

Write queries as if you're describing the page title or first paragraph:

```
WEAK: "how do I hack kubernetes?"
→ Question format doesn't match published content

STRONG: "kubernetes privilege escalation from pod to cluster-admin"
→ Matches how security researchers title their writeups
```

### Principle 4: Specify the Format You Want

```
Research paper: "academic analysis of TLS 1.3 downgrade attack vectors"
Blog post: "practical walkthrough exploiting deserialization in Java Spring"
Tool docs: "nuclei template writing guide for custom vulnerability checks"
Code: "proof of concept exploit for CVE-2024"
```

## 3. Security Domain Query Templates

### Vulnerability Research
```
"[product] [version] [vulnerability-type] [impact]"
"Apache Struts 2 remote code execution via OGNL injection"
"WordPress plugin arbitrary file upload leading to webshell"
"OpenSSL buffer overflow CVE proof of concept"
```

### Exploit Development
```
"[technique] exploit [target] [environment]"
"heap overflow exploitation techniques on modern Linux with ASLR"
"browser use-after-free exploit development Chrome V8 engine"
"return oriented programming bypass DEP and ASLR x64"
```

### Defense and Detection
```
"detection rules for [technique] [tool/format]"
"sigma rules detecting Cobalt Strike beacon traffic"
"yara rules for detecting fileless malware in memory"
"splunk queries for lateral movement detection active directory"
```

### Threat Intelligence
```
"[actor/campaign] [technique] [target-sector] [timeframe]"
"APT29 supply chain attack targeting government agencies 2024"
"ransomware group exploiting VPN vulnerabilities financial sector"
"Chinese APT using zero-day in edge devices"
```

## 4. Multi-Query Research Strategy

### Breadth-First: Explore a Topic
```python
queries = [
    "container escape techniques Docker 2024",           # broad survey
    "Docker socket mount privilege escalation",          # specific vector
    "cgroup escape container breakout Linux kernel",     # kernel-level
    "Kubernetes pod security admission bypass",          # orchestration layer
]
# Run all, deduplicate results, rank by relevance
```

### Depth-First: Deep Dive on One Topic
```python
queries = [
    "CVE-2024-21626 runc container escape",             # the vulnerability
    "leaky vessels exploit proof of concept",            # exploitation
    "runc working directory file descriptor leak",      # root cause
    "container escape patch analysis and bypass",       # post-patch research
]
# Chain results: understanding → exploitation → defense
```

### Triangulation: Validate Findings
```python
queries = [
    "is CVE-2024-12345 exploitable in production",      # practitioner view
    "CVE-2024-12345 patch analysis",                    # defense view
    "CVE-2024-12345 CVSS score controversy",            # risk assessment
]
# Cross-reference for accurate risk picture
```

## 5. Combining Filters with Queries

### Time-Bounded Research
```python
# Only recent content (last 90 days)
{
    "query": "new techniques for bypassing EDR solutions",
    "start_published_date": "2024-04-01",
    "num_results": 20,
    "type": "neural"
}
```

### Source-Quality Filtering
```python
# High-quality security sources only
{
    "query": "advanced persistent threat techniques 2024",
    "include_domains": [
        "portswigger.net",
        "googleprojectzero.blogspot.com",
        "labs.watchtowr.com",
        "blog.assetnote.io",
        "research.nccgroup.com"
    ],
    "num_results": 10
}
```

### Exclude Noise
```python
# Filter out low-quality aggregators
{
    "query": "SQL injection advanced techniques",
    "exclude_domains": [
        "medium.com",
        "dev.to",
        "stackoverflow.com",
        "geeksforgeeks.org"
    ],
    "num_results": 15
}
```

## 6. Query Refinement Loop

```
1. Start broad: "container security vulnerabilities"
   → Review results, identify promising threads

2. Narrow focus: "Docker container escape via exposed socket mount"
   → More specific, fewer but higher-quality results

3. Adjacent exploration: "detecting Docker socket abuse with falco rules"
   → Shift to defense perspective

4. Cross-reference: "container escape techniques comparison runtime engines"
   → Broaden again to compare findings
```

## 7. Common Mistakes

| Mistake | Example | Fix |
|---------|---------|-----|
| Too short | "XSS" | "stored XSS in rich text editors bypassing DOMPurify" |
| Question format | "how to hack APIs?" | "API security testing methodology for REST and GraphQL" |
| Tool-focused | "burp suite" | "web application testing workflow using intercepting proxy" |
| Too long | 50+ word query | Keep to 10-20 words, focused on content description |
| Mixing topics | "XSS and SQLi and SSRF" | Split into separate queries |

## Quick Reference

| Research Goal | Query Pattern |
|---------------|---------------|
| New CVE info | `"[CVE-ID] [product] [impact] [date]"` |
| Technique survey | `"[technique] methods [target] [year]"` |
| Tool comparison | `"[tool-category] comparison [use-case]"` |
| Threat actor | `"[group/alias] [technique] [sector] [timeframe]"` |
| Defense | `"detection [technique] [tool/format] rules"` |

## Integration with Other Skills

- **deep-research**: Use semantic search as first-pass discovery, then deep-dive on findings
- **data-scraper-agent**: Feed discovered URLs into scrapers for full content extraction
- **knowledge-ops**: Store high-value search results as knowledge units
