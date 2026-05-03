# Skill: Deep Research

> **Supplementary Files**:
> - `payloads.md` — Search query templates, OSINT operator quick-reference, and data-extraction commands organized by research scenario
> - `test-cases.md` — Structured test cases covering threat intelligence research, vulnerability analysis, attack technique investigation, and adversary profiling with severity levels and summary tables

## Description

Multi-source intelligence gathering through systematic web research — producing thorough, cited reports from diverse sources. This skill transforms raw information into actionable security intelligence by planning research questions, executing parallel searches across multiple engines, deep-reading key sources, and synthesizing findings into structured reports.

Difference from the `osint` skill: osint focuses on tool-driven passive reconnaissance against specific targets (domain enumeration, email harvesting, Shodan queries). Deep research focuses on topic-level investigation — understanding threat landscapes, analyzing vulnerabilities, profiling adversaries, and evaluating attack techniques — by synthesizing information from many sources into a coherent report.

## Use Cases

- Vulnerability deep-dive: researching a newly disclosed CVE, its exploit status, affected systems, and mitigation strategies
- Threat actor profiling: building a comprehensive picture of an APT group's TTPs, campaigns, and IOCs
- Attack technique evaluation: investigating the current state of a specific attack method (e.g., Kerberoasting variants in 2026)
- Technology security assessment: researching known vulnerabilities and attack surfaces of a target technology stack before engagement
- Competitive intelligence: analyzing security products, frameworks, or defensive tools for evaluation purposes
- Regulatory and compliance research: investigating security requirements for specific industries or jurisdictions
- Post-exploitation context: researching internal technologies discovered during a pentest to find associated vulnerabilities

## Core Tools

### Search Engines & Aggregators

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Google Dorking | Precision search with operators | `site:github.com "password" filetype:env` |
| Shodan | Internet-facing device search | `shodan search "apache 2.4.49"` |
| Censys | Host and certificate search | `censys search "services.tls.certificate.parsed.names: target.com"` |
| Exa | Semantic web search | `web_search_exa(query: "<topic>", numResults: 10)` |

### Vulnerability & Threat Databases

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| NVD (NIST) | CVE database lookup | `curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<term>"` |
| Exploit-DB | Public exploit archive | `searchsploit apache 2.4` |
| CVE Details | CVE statistics and analysis | `curl -s "https://www.cvedetails.com/cve/<CVE-ID>/"` |
| MITRE ATT&CK | Adversary tactic and technique reference | Web: `attack.mitre.org/techniques/<ID>` |

### Code & Credential Search

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| GitHub Search | Code and repository search | `gh search code "<keyword>" --language python` |
| GitDorks | Automated GitHub dorking | `gitdorks -gd gitdorks_list.txt -tf target.txt` |
| Pastebin Monitor | Leaked data search | `curl -s "https://psbdmp.ws/api/search/<keyword>"` |

### Content Extraction

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Firecrawl | Full-page scraping with extraction | `firecrawl_scrape(url: "<url>")` |
| Web Reader | URL to markdown conversion | `webReader(url: "<url>", return_format: "markdown")` |
| curl + jq | API data extraction | `curl -s <api-url> \| jq '.data[]'` |

## Methodology

### Deep Research Six-Phase Process

**Phase 1: Define Research Scope**

Clarify the research goal and decompose into 3-5 specific sub-questions.

```
Topic: "Security of Kubernetes ingress controllers"
Sub-questions:
  1. What CVEs have been disclosed for popular ingress controllers?
  2. What misconfiguration patterns lead to compromise?
  3. What are the current best practices for hardening?
  4. What real-world breach cases involved ingress controllers?
  5. What tools exist for auditing ingress configurations?
```

**Phase 2: Plan Search Strategy**

For each sub-question, prepare 2-3 keyword variations targeting different source types:
- Academic/official sources (NVD, MITRE, vendor advisories)
- Security blogs and research (Project Zero, Praetorian, etc.)
- Community discussions (Reddit, HackerNews, StackOverflow)
- Code repositories (GitHub, GitLab)

**Phase 3: Execute Multi-Source Search**

Search using multiple engines per sub-question. Aim for 15-30 unique sources total.

```bash
# Search query variations
"nginx ingress controller CVE 2025 2026"
"kubernetes ingress security vulnerability"
"ingress controller misconfiguration exploit"
site:github.com "ingress-nginx" vulnerability
```

**Phase 4: Deep-Read Key Sources**

Fetch full content from the 3-5 most promising sources per sub-question. Do not rely on search snippets alone.

**Phase 5: Cross-Reference and Validate**

- Require at least 2 independent sources for every key claim
- Flag single-source claims as "unverified"
- Prefer sources from the last 12 months for current topics
- Separate confirmed facts from estimates and opinions

**Phase 6: Synthesize Report**

Structure findings into a cited report with executive summary, themed sections, key takeaways, and full source list.

### Defense Perspective

- **Intelligence hygiene**: Verify sources before acting on findings; outdated exploits may waste time
- **OPSEC in research**: Use isolated environments when researching sensitive topics to avoid tipping off defenders
- **Source reliability**: Tier sources by reliability (vendor advisory > security firm blog > personal blog > forum post)
- **Bias awareness**: Security vendors may overstate threats to sell products; cross-reference with independent sources

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: CVE Deep-Dive Report

1. Select a recently disclosed CVE (e.g., from the last 30 days)
2. Research: affected software, exploit status, proof-of-concept availability, patch status
3. Search: NVD, Exploit-DB, GitHub, security blogs
4. Produce: structured report with executive summary, technical analysis, remediation guidance

### Exercise 2: Threat Actor Profile

1. Select an APT group (e.g., APT28, Lazarus Group)
2. Research: known campaigns, TTPs mapped to MITRE ATT&CK, IOCs, targets
3. Search: threat intelligence reports, MITRE ATT&CK, vendor blogs, academic papers
4. Produce: adversary profile with campaign timeline and detection opportunities

### Exercise 3: Attack Technique Investigation

1. Select an attack technique (e.g., DLL sideloading, adversary-in-the-middle)
2. Research: how it works, detection methods, defensive measures, recent variants
3. Search: MITRE ATT&CK, security research blogs, detection rule repositories
4. Produce: technique analysis with detection rules and mitigation checklist

## Report Template

```markdown
# [Topic]: Research Report
*Generated: [date] | Sources: [N] | Confidence: [High/Medium/Low]*

## Executive Summary
[3-5 sentence overview of key findings]

## 1. [First Major Theme]
[Findings with inline citations]
- Key point ([Source Name](url))
- Supporting data ([Source Name](url))

## 2. [Second Major Theme]
[Findings with inline citations]

## 3. [Third Major Theme]
[Findings with inline citations]

## Key Takeaways
- [Actionable insight 1]
- [Actionable insight 2]
- [Actionable insight 3]

## Sources
1. [Title](url) — [one-line summary]
2. [Title](url) — [one-line summary]

## Methodology
Searched [N] queries across [engines used].
Analyzed [M] sources in depth.
Sub-questions investigated: [list]
```
