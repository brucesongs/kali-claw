# Iterative Search Patterns

> Guide for the deep-research skill — covers query refinement, source tracing, and automatic keyword expansion.

## Overview

Traditional research is linear: search → read → report. Iterative search transforms this into a feedback loop where each round of findings informs the next round of queries. This mirrors how experienced intelligence analysts work — each answer raises better questions.

## The Iterative Search Loop

```
Define Question
      │
      ▼
Generate Queries (2-3 variations)
      │
      ▼
Execute Search ──────────────────┐
      │                          │
      ▼                          │
Evaluate Results                 │
      │                          │
      ├── Gap found? ────────────┘
      │   (generate new queries)
      │
      ├── Conflict found? ───────┘
      │   (targeted verification)
      │
      └── Converged? → Synthesize Report
          (3 searches add nothing new)
```

## Query Refinement Strategies

### Strategy 1: Specificity Escalation

Start broad, narrow progressively based on what you find.

```
Round 1: "kubernetes security vulnerabilities 2026"
  → Discover: ingress controller is a hot topic

Round 2: "kubernetes ingress controller CVE 2026"
  → Discover: nginx-ingress has specific path traversal issues

Round 3: "nginx ingress controller path traversal CVE-2026-XXXXX"
  → Discover: exact PoC and affected versions
```

### Strategy 2: Lateral Expansion

When depth research plateaus, expand laterally to adjacent topics.

```
Original: "Redis authentication bypass"
  → Plateau: found 3 CVEs, no more results

Lateral:
  - "Redis sentinel security misconfiguration" (related component)
  - "Redis cluster unauthorized access" (different deployment model)
  - "Memcached vs Redis security comparison" (comparative perspective)
  - "Redis ACL bypass techniques" (adjacent attack surface)
```

### Strategy 3: Source-Type Rotation

When one source type is exhausted, switch to another.

```
Exhausted: Google search + NVD
Next: GitHub code search (PoCs, tools, detection rules)
Then: Security conference proceedings (DEF CON, Black Hat)
Then: Community forums (Reddit /r/netsec, HackerNews)
Then: Vendor advisories and changelogs
```

### Strategy 4: Temporal Bracketing

Adjust time ranges to find information from different eras.

```
# Recent (last 30 days) — for latest developments
"<topic>" after:2026-04-01

# Medium-term (last year) — for established knowledge
"<topic>" after:2025-01-01 before:2026-01-01

# Historical — for foundational research and evolution
"<topic>" "original" OR "first discovered" OR "initial disclosure"
```

## Source Tracing

### Forward Tracing

Found a key source → find everything that references it.

```bash
# Find who cites a specific CVE
"CVE-2026-12345" -site:nvd.nist.gov -site:cve.org

# Find who references a key research paper
"<paper-title>" OR "<author-name>" "<key-finding>"

# Find downstream tools/scripts based on a technique
site:github.com "<technique-name>" OR "<CVE-ID>" language:python
```

### Backward Tracing

Found a claim → trace back to the original source.

```
Blog post claims "X is vulnerable to Y"
  → Check: does the blog cite a source?
  → If yes: read the original source directly
  → If no: search for the original disclosure
    → "<vulnerability-description>" site:vendor.com
    → "<vulnerability-description>" advisory OR disclosure
```

## Automatic Keyword Expansion

### Entity Extraction → New Queries

After reading a key source, extract entities and generate follow-up queries.

```
Read source about APT28:
  Extracted: "Fancy Bear", "Sofacy", "Sednit", "X-Agent malware", "T1071"

New queries generated:
  - "Sofacy latest campaign 2026"        (alias)
  - "X-Agent malware detection YARA"     (tool)
  - "T1071 application layer protocol"   (technique)
```

### Synonym and Jargon Mapping

Security topics often have multiple names for the same thing.

```
SQL Injection → SQLi, blind SQLi, second-order injection, out-of-band SQLi
Privilege Escalation → privesc, local privilege escalation, LPE, EoP
Command Injection → OS command injection, shell injection, RCE via injection
Zero-Day → 0day, 0-day, in-the-wild exploit, unpatched vulnerability
```

## Convergence Detection

### When to Stop Iterating

1. **Source saturation**: last 3 searches returned only previously seen sources
2. **Claim verification**: all key claims have 2+ independent confirmations
3. **Gap closure**: all identified sub-questions have answers
4. **Diminishing novelty**: new sources add <10% new information per search

### Convergence Log Template

```markdown
| Round | New Sources | New Facts | Key Gaps Remaining |
|-------|-------------|-----------|-------------------|
| 1     | 12          | 15        | exploit status, mitigation, affected versions |
| 2     | 8           | 9         | mitigation details, detection rules |
| 3     | 3           | 2         | none significant |
→ CONVERGED at round 3
```

## Anti-Patterns to Avoid

1. **Query repetition**: searching the same terms across different engines (use different keywords instead)
2. **Depth-first tunnel vision**: going too deep on one sub-question while others remain unaddressed
3. **Source echo chamber**: multiple sources citing each other (trace back to the original)
4. **Recency bias**: only looking at recent sources when historical context matters
5. **Tool fixation**: using only one search tool when the topic spans multiple source types
