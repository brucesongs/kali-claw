---
name: deep-research
description: "Multi-source intelligence gathering through systematic web research — producing thorough, cited reports from diverse sources."
origin: openclaw
version: "0.2.0.2"
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
  guide_count: 6
  mitre: "T1592-Gather Victim Host Info, T1593-Search Open Websites/Domains, T1590-Gather Victim Network Info, T1589-Gather Victim Identity Information"
  last_reviewed: "2026-08-19"
---




# Skill: Deep Research

> **Supplementary Files**:
> - `payloads.md` — Search query templates, OSINT operator quick-reference, and data-extraction commands organized by research scenario
> - `test-cases.md` — Structured test cases covering threat intelligence research, vulnerability analysis, attack technique investigation, and adversary profiling with severity levels and summary tables
> - `guides/iterative-search-patterns.md` — Query expansion and contraction patterns, parallel search fan-out, search log discipline
> - `guides/continuous-monitoring.md` — Ongoing intelligence collection, polling cadence, change detection triggers
> - `guides/intelligence-correlation.md` — Entity linking, IOC cross-referencing, MITRE ATT&CK mapping, confidence scoring
> - `guides/mcp-integration.md` — Model Context Protocol server wiring for automated research pipelines
> - `guides/source-validation-guide.md` — Source credibility scoring, cross-validation, misinformation detection, provenance tracking
> - `guides/multi-source-synthesis-guide.md` — Multi-source intelligence synthesis, triangulation, confidence rubric, bias filtering, citation chain verification

## Summary

Deep Research skill domain covering research operations.

**Domain**: research

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

## Triangulation Principle

The triangulation principle requires evidence from at least three *independent* vectors before elevating a claim to confirmed status. Three blog posts that all cite the same vendor advisory count as one source, not three.

The three vectors that should be represented in any robust synthesis:

1. **Authoritative vector** — NVD, MITRE ATT&CK, vendor PSIRT, CISA KEV, academic papers, court filings
2. **Practitioner vector** — independent security firm blogs, conference talks, researcher social threads, GitHub PoC repositories
3. **Community vector** — Reddit, HackerNews, vendor support forums, sector-specific ISAC feeds

If a claim appears in only one vector, it stays at LOW confidence regardless of how authoritative that single vector is. See `guides/multi-source-synthesis-guide.md` for the full independence test and rubric.

## Confidence Scoring Framework

Every claim in a synthesis product carries one of four confidence levels. The rubric is mechanical so that two analysts reviewing the same evidence arrive at the same score.

| Level | Definition | Required Evidence |
|-------|------------|-------------------|
| **CONFIRMED** | Verified, ready to drive action | 3+ independent sources across all 3 vectors, primary source located, no unresolved contradictions |
| **LIKELY** | Strong evidence, minor gap | 2+ independent sources across 2+ vectors, primary source located, contradictions resolved |
| **POSSIBLE** | Plausible, needs more work | 1-2 sources, single-vector coverage, or primary source not located |
| **UNVERIFIED** | Claim exists, cannot yet evaluate | Single source, no primary reference, or contradictory authoritative sources |

Numeric scoring (0-100) and code are provided in `guides/multi-source-synthesis-guide.md`.

## Bias Filtering

Security content is produced by people and organizations with incentives. A vendor selling an EDR product has every reason to amplify the severity of a technique their product detects. Bias filtering is the discipline of asking "what does this source want me to believe, and would they benefit if I believed it?"

Common biases that affect security research synthesis:

- **Vendor commercial bias** — the source sells a product that mitigates the described threat
- **Disclosed-but-not-exploited bias** — PoC existence is conflated with in-the-wild exploitation
- **Single-researcher echo** — many secondary sources all trace back to one researcher's thread
- **Stale conventional wisdom** — claim was accurate years ago, repeated ever since, facts changed underneath
- **Ideological framing** — nation-state attribution claims that outrun the technical evidence
- **Hype cycle bias** — fashionable topics attract coverage disproportionate to actual impact

Each bias has a tell — a pattern you can grep for. See `guides/multi-source-synthesis-guide.md` for the detection script and credibility adjustment formula.

## Citation Chain Verification

A typical threat intelligence report says "Threat actor X uses technique Y." The report does not name a primary source. Another blog picks it up. Within a week, the claim has "broad support" — but every link cites another link, and the chain bottoms out at either one original claim with no supporting evidence or a misreading of an unrelated primary source.

Citation chain verification is the discipline of always asking "where did this originally come from?" The chain-walk procedure follows outbound references recursively until it reaches a primary authoritative source (vendor advisory, NVD entry, MITRE page) or terminates without finding one.

The three possible chain-walk outcomes:

- **Clean chain** — terminates at authoritative primary; carry claim forward with high confidence
- **Self-referential cluster** — bounces between aggregators; downgrade to UNVERIFIED
- **Mutated chain** — primary says something subtly different from the aggregator claim; document the mutation and re-score

## Threat Actor Attribution Methodology

Attribution is the most error-prone area of threat intelligence research. Technical indicators support *capability* claims; they rarely support *identity* claims. A responsible synthesis separates the two.

**What technical evidence can support:**

- Tools and infrastructure used (malware families, C2 domains, certificate patterns)
- TTPs observed (mapped to MITRE ATT&CK technique IDs)
- Targeting patterns (sectors, regions, organization sizes)
- Operational tempo (timing, frequency, campaign duration)

**What technical evidence cannot support alone:**

- Identity of the sponsoring government
- Motivation beyond what the targeting implies
- Coordination with other actors or campaigns
- Whether the actor is a contractor, military unit, or proxy

When sources make identity claims, apply extra scrutiny:

```
Attribution claim checklist:
  [ ] Government attribution (indictment, advisory, sanctioned entity list)?
  [ ] Multiple independent firms agree on identity?
  [ ] Firms disagree but agree on capability?
  [ ] Does the source benefit politically or commercially from the attribution?
```

If only one box can be checked, the identity claim is POSSIBLE at best — never CONFIRMED. If firms disagree, present all positions rather than picking one. See `guides/multi-source-synthesis-guide.md` for the contradiction resolution procedure.

## Synthesis Product Structure

The output of a synthesis loop is an auditable document, not just a narrative. Every claim must trace back to a numbered entry in an evidence register so a reviewer can verify the chain.

Required sections of a synthesis product:

1. **Scope** — primary question, sub-questions, time horizon, exclusions
2. **Evidence Inventory** — total sources, breakdown by vector, independence analysis, discarded derivative sources
3. **Claims Register** — numbered list of every claim with confidence level and citation chain summary
4. **Contradictions Log** — every contradiction encountered and how it was resolved
5. **Bias Audit** — bias flags raised and credibility adjustments applied
6. **Findings** — the narrative product (what stakeholders actually read)
7. **Open Questions** — unresolved claims, follow-up research needed
8. **Provenance** — full citation list with role (primary, secondary, aggregator) and weight

A synthesis product that omits sections 1-5 and 7-8 cannot withstand review. A reviewer who disagrees with a confidence verdict must be able to point at the specific line where the evidence was characterized differently.

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

### Exercise 4: Multi-Source Synthesis Drill

1. Pick a contested claim in the threat landscape (e.g., "is CVE-2025-XXXX exploited in the wild?")
2. Decompose into 3-5 sub-questions
3. Collect from all three vectors (authoritative, practitioner, community)
4. Run the independence check and citation chain walk
5. Produce a synthesis product with claims register, contradictions log, and bias audit
6. See `guides/multi-source-synthesis-guide.md` for the full walkthrough

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

## Detection Methods

### Research Activity Patterns
- **Mass query patterns**: Single source executing thousands of queries across many databases.
- **Cross-source correlation**: Aggregating data from disparate sources (typical OSINT recon signature).
- **Off-hours research**: Bulk research during low-traffic hours.

### SIEM Detection Rules
- **Splunk SPL**: `index=research sourcetype=query | stats dc(source_db) as src_count by user | where src_count > 10`
- **Threat intel platform**: Recorded Future / Maltego usage logging.

## Defense Evasion Techniques

### Distributed Research
- **Spread across accounts**: Use multiple accounts to avoid per-account rate limits.
- **Distributed timing**: Pace queries over long period; below baseline.
- **Use sanctioned tools**: Subscribe to legitimate threat intel platforms (Recorded Future, Mandiant); appears as normal analyst work.

### Source Concealment
- **Tor + VPN chain**: Anonymize research source.
- **Residential proxies**: Mimic real user IPs.
- **Cached research**: Cache results; avoid re-querying same data.

## Hacker Laws

1. **First Principles Thinking** — Don't just search; understand how search engines index, how CVE databases correlate, how threat intelligence is produced. Design your research strategy from the ground up for each topic.
2. **Divergent Thinking First** — Use at least 3 source types per sub-question (official databases, security blogs, community forums, code repositories). Single-source research has blind spots.
3. **Trust but Verify** — Every key claim requires 2+ independent sources. Vendor reports may overstate threats; blog posts may be outdated; forum posts may be fabricated.

## Learning Resources

  **This skill's supplementary files**: payloads.md, test-cases.md

  **Guides**: guides/iterative-search-patterns.md, guides/continuous-monitoring.md, guides/intelligence-correlation.md, guides/mcp-integration.md, guides/source-validation-guide.md, guides/multi-source-synthesis-guide.md

  **Related skills**: skills/osint/SKILL.md, skills/social-intelligence/SKILL.md, skills/social-engineering/SKILL.md, skills/autonomous-loops/SKILL.md, skills/continuous-learning/SKILL.md

  **External resources**:
  - **MITRE ATT&CK**: [attack.mitre.org](https://attack.mitre.org/)
  - **CISA Known Exploited Vulnerabilities**: [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  - **NVD**: [nvd.nist.gov](https://nvd.nist.gov/)
  - **Exploit-DB**: [exploit-db.com](https://www.exploit-db.com/)
  - **OSINT Framework**: [osintframework.com](https://osintframework.com/)
