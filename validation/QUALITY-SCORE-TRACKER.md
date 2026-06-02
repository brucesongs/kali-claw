# Skill Quality Score Tracker

> **Objective**: Track quality scores for all 49 skill domains based on documentation depth and completeness.
> **Scored**: 2026-06-02 | **Last Updated**: 2026-06-02 (v0.1.16, scoring v2)

---

## Scoring Methodology (v2)

| Component | Weight | Metrics |
|-----------|--------|---------|
| SKILL.md | 15% | Section count (## headings), normalized against thresholds |
| payloads.md | 30% | Word count + section count + code block count (capped at 100) |
| test-cases.md | 30% | Test case count + field completeness (7 expected fields, capped at 100) |
| guides/ | 25% | Composite: file count (40%) + avg word count (30%) + key section presence (30%) |

## Tier Definitions (v2)

| Tier | Score Range | Description |
|------|-------------|-------------|
| **Weak** | 0-39.9 | Missing critical components or extremely thin coverage |
| **Adequate** | 40-59.9 | Has all components, some depth |
| **Strong** | 60-79.9 | Good coverage across all components |
| **Excellent** | 80-91.9 | Comprehensive coverage, room for depth improvement |
| **Distinguished** | 92-100 | Best-in-class depth and quality across all components |

---

## Tier Distribution

| Tier | Count | Percentage |
|------|-------|------------|
| Weak | 0 | 0% |
| Adequate | 0 | 0% |
| Strong | 0 | 0% |
| Excellent | 49 | 100% |
| Distinguished | 0 | 0% |

---

## Quality Scores (v2)

| # | Skill | Overall | SKILL.md | Payloads | Test Cases | Guides | Tier |
|---|-------|---------|----------|----------|------------|--------|------|
| 1 | cloud-security | 90.1 | 87.0 | 93.3 | 93.8 | 83.9 | Excellent |
| 2 | vulnerability-assessment | 89.3 | 92.0 | 93.3 | 92.5 | 79.0 | Excellent |
| 3 | article-writing | 89.2 | 100.0 | 93.3 | 90.0 | 76.7 | Excellent |
| 4 | autonomous-loops | 89.0 | 88.0 | 93.3 | 92.5 | 80.3 | Excellent |
| 5 | osint | 89.0 | 95.0 | 91.0 | 92.5 | 78.7 | Excellent |
| 6 | network-pentest | 88.9 | 89.0 | 92.3 | 93.8 | 78.8 | Excellent |
| 7 | security-bounty-hunter | 88.4 | 87.0 | 91.5 | 90.0 | 83.7 | Excellent |
| 8 | social-intelligence | 88.2 | 95.0 | 91.1 | 90.0 | 78.4 | Excellent |
| 9 | ai-security | 88.1 | 92.0 | 91.6 | 90.0 | 79.5 | Excellent |
| 10 | security-misconfiguration | 87.5 | 83.0 | 90.8 | 93.8 | 78.8 | Excellent |
| 11 | verification-loop | 87.5 | 97.0 | 92.1 | 90.0 | 73.1 | Excellent |
| 12 | council | 87.4 | 100.0 | 93.3 | 90.0 | 69.7 | Excellent |
| 13 | repo-scan | 87.4 | 84.0 | 93.3 | 90.0 | 79.3 | Excellent |
| 14 | binary-reverse | 87.3 | 83.0 | 90.3 | 93.8 | 78.5 | Excellent |
| 15 | social-engineering | 87.3 | 83.0 | 93.3 | 92.5 | 76.6 | Excellent |
| 16 | terminal-ops | 87.3 | 83.0 | 91.1 | 92.5 | 78.9 | Excellent |
| 17 | web-auth-bypass | 87.3 | 81.0 | 90.0 | 93.0 | 80.9 | Excellent |
| 18 | digital-forensics | 87.1 | 92.0 | 93.3 | 85.5 | 78.5 | Excellent |
| 19 | container-security | 87.0 | 92.0 | 93.2 | 93.8 | 68.5 | Excellent |
| 20 | wifi-pentest | 86.9 | 89.0 | 87.7 | 92.5 | 78.1 | Excellent |
| 21 | data-scraper-agent | 86.8 | 80.0 | 93.6 | 92.5 | 76.0 | Excellent |
| 22 | exa-search | 86.8 | 80.0 | 93.4 | 92.5 | 76.2 | Excellent |
| 23 | logging-monitoring | 86.6 | 76.0 | 92.7 | 92.5 | 78.5 | Excellent |
| 24 | api-security | 86.5 | 83.0 | 87.4 | 93.0 | 79.6 | Excellent |
| 25 | mobile-security | 86.4 | 87.0 | 89.0 | 85.5 | 84.0 | Excellent |
| 26 | recon-osint | 86.4 | 81.0 | 88.4 | 86.8 | 86.8 | Excellent |
| 27 | security-review | 86.4 | 87.0 | 86.7 | 90.0 | 81.4 | Excellent |
| 28 | web-xss | 86.4 | 80.0 | 90.9 | 92.5 | 77.6 | Excellent |
| 29 | crypto-attacks | 86.2 | 89.0 | 92.0 | 93.8 | 68.7 | Excellent |
| 30 | search-first | 85.9 | 85.0 | 84.9 | 92.5 | 79.8 | Excellent |
| 31 | knowledge-ops | 85.8 | 91.0 | 84.4 | 90.0 | 79.1 | Excellent |
| 32 | mcp-server-patterns | 85.7 | 83.0 | 93.5 | 83.0 | 81.2 | Excellent |
| 33 | hardware-security | 85.4 | 81.0 | 92.8 | 92.5 | 70.5 | Excellent |
| 34 | supply-chain-security | 85.3 | 83.0 | 89.9 | 95.0 | 69.5 | Excellent |
| 35 | multi-agent-collaboration | 85.2 | 84.0 | 83.1 | 90.0 | 82.8 | Excellent |
| 36 | chronicle | 85.1 | 95.0 | 80.0 | 90.0 | 79.5 | Excellent |
| 37 | docker-patterns | 85.0 | 85.0 | 82.6 | 92.5 | 79.0 | Excellent |
| 38 | web-sqli | 84.9 | 76.0 | 70.9 | 97.5 | 92.0 | Excellent |
| 39 | web-access-control | 84.4 | 83.0 | 91.2 | 89.2 | 71.1 | Excellent |
| 40 | deep-research | 84.3 | 92.0 | 75.5 | 96.2 | 76.0 | Excellent |
| 41 | browser-qa | 84.1 | 80.0 | 93.7 | 92.5 | 65.1 | Excellent |
| 42 | codebase-onboarding | 83.8 | 89.0 | 91.9 | 85.5 | 69.0 | Excellent |
| 43 | safety-guard | 83.7 | 100.0 | 80.0 | 90.0 | 70.6 | Excellent |
| 44 | web-ssrf | 83.6 | 92.0 | 87.3 | 86.8 | 70.3 | Excellent |
| 45 | insecure-design | 82.7 | 89.0 | 88.8 | 85.5 | 68.3 | Excellent |
| 46 | password-attack | 82.5 | 87.0 | 87.6 | 88.0 | 67.2 | Excellent |
| 47 | ai-fuzzing | 82.4 | 84.0 | 90.4 | 90.0 | 62.6 | Excellent |
| 48 | continuous-learning | 81.6 | 91.0 | 93.3 | 66.3 | 80.3 | Excellent |
| 49 | post-exploitation | 80.1 | 92.0 | 88.8 | 86.8 | 54.7 | Excellent |

---

## Summary Statistics (v2)

| Metric | Value |
|--------|-------|
| Average Score | 86.1 |
| Median Score | 86.6 |
| Highest Score | 90.1 (cloud-security) |
| Lowest Score | 80.1 (post-exploitation) |
| Score Range | 10.0 |

---

## v0.1.16 Summary (Scoring v2)

### Scoring v2 Changes

| Change | v1 | v2 |
|--------|----|----|
| Score inflation | Scores up to 125.7 | All capped at 100 |
| Guide metric | File count only | Composite (files 40% + words 30% + sections 30%) |
| Top tier | Excellent (80-100) | Distinguished (92+) added above Excellent (80-91.9) |
| Component caps | None | All capped at 100 |

### Impact

| Metric | v1 (v0.1.15) | v2 (v0.1.16) | Change |
|--------|-------------|-------------|--------|
| Average | 88.6 | 86.1 | -2.5 (more accurate) |
| Minimum | 85.3 | 80.1 | -5.2 (exposed gaps) |
| Maximum | 99.7 | 90.1 | -9.6 (inflation removed) |
| Range | 14.4 | 10.0 | -4.4 (tighter cluster) |
| Distinguished | N/A | 0 | New tier, room to grow |

### Key Insight

The v2 scoring system revealed that guide quality is the primary differentiator. Council dropped from 99.7 to 87.4 (guide score: 69.7 vs old 80.0) because its guides have low average word count despite many files. Post-exploitation at 80.1 has the weakest guides (54.7). To reach Distinguished, skills need deep, substantive guides — not just many files.

---

## Notes

- **49 Excellent skills** — 100% at Excellent tier
- **0 Distinguished** — new tier provides growth target
- **Top 5**: cloud-security (90.1), vulnerability-assessment (89.3), article-writing (89.2), autonomous-loops (89.0), osint (89.0)
- **CI quality gate** — baseline 86.1, blocks PRs on avg regression >1.0 or per-skill >5.0
- **10 integration scenarios** — all PASS (INT-001 through INT-010)
