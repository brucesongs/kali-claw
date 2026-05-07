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
- Continuous threat monitoring: tracking CVE feeds, dark web mentions, and code leaks over time for ongoing engagements
- Social intelligence correlation: combining deep-research findings with social platform intelligence (see `skills/social-intelligence/SKILL.md`) for comprehensive target profiling

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

**Phase 7: Continuous Monitoring**

Establish ongoing intelligence collection for time-sensitive topics.

```
Monitoring Setup:
  1. Define monitoring targets (CVE feeds, code repos, paste sites, dark web)
  2. Set polling frequency per source:
     - CVE feeds (NVD, CISA KEV): daily
     - GitHub commit/issue watch: daily
     - Pastebin/paste sites: every 6 hours
     - Shodan exposure diff: weekly
  3. Define change triggers:
     - New CVE matching target technology
     - New PoC code published
     - Target mentioned in paste/leak
     - Attack surface change detected
  4. Generate diff reports comparing current vs. previous snapshot
```

Key commands for continuous monitoring:

```bash
# NVD new CVE feed (last 24 hours)
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=$(date -d '1 day ago' +%Y-%m-%dT00:00:00.000)&pubEndDate=$(date +%Y-%m-%dT23:59:59.999)" | jq '.vulnerabilities[] | {id: .cve.id, description: .cve.descriptions[0].value}'

# CISA KEV catalog check
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | jq '.vulnerabilities[-10:]'

# Shodan diff (compare saved vs current)
shodan search "org:TargetCorp" --limit 100 > current_exposure.json
diff previous_exposure.json current_exposure.json

# GitHub repo watch for security-relevant commits
gh api "/repos/{owner}/{repo}/commits?since=$(date -d '1 day ago' +%Y-%m-%dT00:00:00Z)" | jq '.[].commit.message'
```

**Phase 8: Intelligence Correlation**

Cross-reference findings from multiple sources to build a coherent intelligence picture.

```
Correlation Process:
  1. Entity extraction: pull IOCs (IPs, domains, hashes), CVEs, tool names,
     threat actor names from all collected sources
  2. Cross-source linking: same IOC appearing in 2+ independent sources
     increases confidence from LOW to MEDIUM/HIGH
  3. MITRE ATT&CK mapping: map observed techniques to ATT&CK IDs,
     identify coverage gaps in detection
  4. Confidence scoring:
     - HIGH: 3+ independent authoritative sources confirm
     - MEDIUM: 2 sources or 1 authoritative + corroborating evidence
     - LOW: single source or unverified claim
  5. Entity relationship mapping:
     Threat Actor ↔ Campaign ↔ Malware ↔ IOC ↔ Vulnerability ↔ Target
```

```bash
# Extract IOCs from a collected report
grep -oP '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' report.txt | sort -u > iocs_ip.txt
grep -oP '\b[a-fA-F0-9]{64}\b' report.txt | sort -u > iocs_sha256.txt
grep -oP 'CVE-\d{4}-\d{4,}' report.txt | sort -u > iocs_cve.txt

# Cross-reference IPs against threat intel
while read ip; do
  echo "=== $ip ==="
  curl -s "https://www.abuseipdb.com/check/$ip" | grep -oP 'confidence.*?%'
done < iocs_ip.txt

# Map CVEs to MITRE ATT&CK techniques
# Use ATT&CK Navigator or manual mapping via attack.mitre.org
```

**Phase 9: Adaptive Refinement**

Iteratively refine research based on emerging findings — the research loop.

```
Adaptive Loop:
  1. Review Phase 6 report for gaps and unverified claims
  2. Generate new sub-questions from discoveries:
     - Unexpected finding → "Why does this exist? What else is affected?"
     - Conflicting sources → "Which is correct? What's the latest data?"
     - Partial answer → "What's missing? Where else can I find this?"
  3. Execute targeted searches for new sub-questions
  4. Deep-read new sources, update the report
  5. Repeat until:
     - All key claims have 2+ source confirmation
     - No significant gaps remain
     - Diminishing returns on new queries (3 consecutive searches add no new info)
```

This phase transforms deep research from a single-pass process into an iterative intelligence cycle, similar to the OODA loop (Observe-Orient-Decide-Act) used in military intelligence.

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

## Hacker Laws

1. **First Principles Thinking** — Don't just search; understand how search engines index, how CVE databases correlate, how threat intelligence is produced. Design your research strategy from the ground up for each topic.
2. **Divergent Thinking First** — Use at least 3 source types per sub-question (official databases, security blogs, community forums, code repositories). Single-source research has blind spots.
3. **Trust but Verify** — Every key claim requires 2+ independent sources. Vendor reports may overstate threats; blog posts may be outdated; forum posts may be fabricated.

## Learning Resources

  **This skill's supplementary files**: payloads.md, test-cases.md

  **Guides**: guides/iterative-search-patterns.md, guides/continuous-monitoring.md, guides/intelligence-correlation.md, guides/mcp-integration.md

  **Related skills**: skills/osint/SKILL.md, skills/social-intelligence/SKILL.md, skills/social-engineering/SKILL.md, skills/autonomous-loops/SKILL.md, skills/continuous-learning/SKILL.md

  **External resources**:
  - **MITRE ATT&CK**: [attack.mitre.org](https://attack.mitre.org/)
  - **CISA Known Exploited Vulnerabilities**: [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  - **NVD**: [nvd.nist.gov](https://nvd.nist.gov/)
  - **Exploit-DB**: [exploit-db.com](https://www.exploit-db.com/)
  - **OSINT Framework**: [osintframework.com](https://osintframework.com/)
