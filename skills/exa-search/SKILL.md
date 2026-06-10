---
name: exa-search
description: "Semantic search using Exa API for security research queries. Unlike keyword-based search, Exa understands context and retrieves high-quality, relevant results for technical research."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
  - Agent
metadata:
  domain: research
  tool_count: 0
  guide_count: 5
---




# Exa Search

## Summary

Unlike keyword-based search, Exa understands context and retrieves high-quality, relevant results for technical research.

**Domain**: research

## Skill Identity

| Attribute | Value |
|-----------|-------|
| Domain | Intelligence Gathering |
| Skill ID | exa-search |
| Version | 1.0.0 |
| Hacker Laws | Law 3 (Intelligence Over Force), Law 9 (Systematic Over Random) |
| Related Skills | deep-research, osint, social-intelligence |

## Purpose

Semantic search using Exa API for security research queries. Unlike keyword-based search, Exa understands context and retrieves high-quality, relevant results for technical research.

## Core Capabilities

1. **Semantic Search**: Context-aware query understanding
2. **Date Filtering**: Recent content prioritization
3. **Domain Filtering**: Target specific sources
4. **Content Extraction**: Full-text retrieval

## Use Cases

- **CVE Research**: "Recent CVEs affecting Spring Boot applications"
- **Exploit Techniques**: "SSRF bypass techniques in AWS metadata service"
- **Tool Research**: "Best tools for JWT security testing"
- **Threat Intelligence**: "APT campaigns targeting healthcare 2024"

## Exa API Reference

- **Endpoint**: https://api.exa.ai/search
- **Auth**: API key via X-API-Key header
- **Docs**: https://docs.exa.ai/

## Query Strategy

- **Semantic phrasing**: Frame queries as full sentences ("How does X bypass Y?") rather than keyword strings; Exa's embedding model rewards natural-language intent.
- **Iterative narrowing**: Start broad, then re-query with terms surfaced by the first batch to drill into specifics.
- **Source class filters**: Restrict to `includeDomains` (e.g., `["github.com","arxiv.org"]`) for code/research, or `excludeDomains` for noisy aggregators.
- **Recency bias**: Use `startPublishedDate` to suppress stale CVE write-ups when chasing live threats.

## Result Triage

1. Reject low-authority hosts (link farms, scraped mirrors) by domain reputation.
2. Cross-reference at least two independent sources before treating a claim as fact.
3. Extract canonical artifacts (CVE IDs, commit hashes, IoCs) into structured notes for knowledge-ops.
4. Flag contradictory findings and escalate to deep-research instead of silently discarding.

## Rate Limits & Cost Control

- Exa enforces per-minute and per-day quotas — batch related queries and cache responses by query hash.
- Prefer `numResults: 10-20` per call; pagination is cheaper than re-querying.
- Use `useAutoprompt: false` once you have a polished query to avoid silent rewrites that inflate cost.
- Stream large content extractions instead of `getContents` on a long URL list.

## Common Pitfalls

- **Treating Exa as a keyword engine** — short keyword queries underperform; semantic models need context.
- **Skipping verification** — semantic results can hallucinate relevance; always sanity-check top hits.
- **Date drift** — without `startPublishedDate`, archive copies of old CVE posts can outrank current advisories.
- **Domain blindness** — failing to include vendor-specific domains misses authoritative primary sources.

## Advanced Query Patterns

- **Boolean composition**: Combine semantic queries with `includeText` / `excludeText` filters for precision targeting.
- **Category targeting**: Use `category: "research paper"` or `category: "github"` to narrow the search space before applying semantic filters.
- **Proximity search**: Embed technical terms in natural context ("zero-day exploit chain exploiting deserialization in Java") rather than listing keywords.
- **Multi-hop retrieval**: Use first-pass results to identify key authors, then search for their other publications with `author: "name"`.

## Content Extraction Workflow

1. Run initial search with `numResults: 10` to identify the most relevant documents.
2. For top 3-5 hits, call `getContents` with `text: true` to retrieve full-text content.
3. Parse extracted text for canonical identifiers (CVE IDs, commit hashes, CWE numbers, CVSS scores).
4. Store structured extractions in knowledge-ops with source URL, extraction date, and confidence score.
5. For ambiguous or contradictory results, cross-reference with a second query using different phrasing.

## Integration with Research Pipelines

- **OSINT correlation**: Feed Exa results into osint skill for cross-validation against multiple intelligence sources.
- **Deep-research handoff**: When Exa surfaces a complex topic, escalate to deep-research for systematic multi-source analysis.
- **Chronicle logging**: Archive search queries and results in chronicle for future reference and trend analysis.
- **Article writing**: Structure Exa findings into report-ready sections using article-writing templates.

## Monitoring and Automation

- Set up recurring queries for high-priority topics (e.g., new CVEs for monitored products) with date-filtered searches.
- Track result count changes over time to detect surges in publication activity around specific vulnerabilities.
- Automate source discovery: periodically search for new security blogs and research outlets to expand coverage.
- Log all API calls (query, timestamp, result count, cost) for budget tracking and query optimization.

## Quality Assurance

- Validate each result against the original query intent — semantic search can return topically adjacent but irrelevant results.
- Track precision@k (fraction of top-k results that are relevant) across query types to identify systematic weaknesses.
- Maintain a golden dataset of known-good queries and expected results for regression testing after API changes.
- Audit cost-per-actionable-finding to optimize query strategies over time.

## Integration

- Use after **deep-research** when primary sources are insufficient
- Feed results to **knowledge-ops**
- Complement **social-intelligence** for broader coverage
