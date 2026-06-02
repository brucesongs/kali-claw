# Skill Quality Score Tracker

> **Objective**: Track quality scores for all 49 skill domains based on documentation depth and completeness.
> **Scored**: 2026-06-03 | **Last Updated**: 2026-06-03 (v0.1.17, scoring v2)

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
| 1 | cloud-security | 91.2 | 87.0 | 93.3 | 93.8 | 88.0 | Excellent |
| 2 | network-pentest | 90.9 | 89.0 | 92.3 | 93.8 | 86.9 | Excellent |
| 3 | article-writing | 90.6 | 100.0 | 93.3 | 90.0 | 82.5 | Excellent |
| 4 | vulnerability-assessment | 90.6 | 92.0 | 93.3 | 92.5 | 84.1 | Excellent |
| 5 | autonomous-loops | 90.5 | 88.0 | 93.3 | 92.5 | 86.2 | Excellent |
| 6 | osint | 90.3 | 95.0 | 91.0 | 92.5 | 84.1 | Excellent |
| 7 | social-intelligence | 90.0 | 95.0 | 91.1 | 90.0 | 85.5 | Excellent |
| 8 | verification-loop | 90.0 | 97.0 | 92.1 | 90.0 | 83.1 | Excellent |
| 9 | council | 89.9 | 100.0 | 93.3 | 90.0 | 79.7 | Excellent |
| 10 | security-bounty-hunter | 89.7 | 87.0 | 91.5 | 90.0 | 88.8 | Excellent |
| 11 | container-security | 89.5 | 92.0 | 93.2 | 93.8 | 78.5 | Excellent |
| 12 | ai-security | 89.2 | 92.0 | 91.6 | 90.0 | 83.6 | Excellent |
| 13 | security-misconfiguration | 89.0 | 83.0 | 90.8 | 93.8 | 84.6 | Excellent |
| 14 | crypto-attacks | 88.7 | 89.0 | 92.0 | 93.8 | 78.7 | Excellent |
| 15 | ai-fuzzing | 88.2 | 84.0 | 90.4 | 90.0 | 85.9 | Excellent |
| 16 | hardware-security | 87.9 | 81.0 | 92.8 | 92.5 | 80.5 | Excellent |
| 17 | supply-chain-security | 87.8 | 83.0 | 89.9 | 95.0 | 79.5 | Excellent |
| 18 | repo-scan | 87.4 | 84.0 | 93.3 | 90.0 | 79.3 | Excellent |
| 19 | binary-reverse | 87.3 | 83.0 | 90.3 | 93.8 | 78.5 | Excellent |
| 20 | social-engineering | 87.3 | 83.0 | 93.3 | 92.5 | 76.6 | Excellent |
| 21 | terminal-ops | 87.3 | 83.0 | 91.1 | 92.5 | 78.9 | Excellent |
| 22 | web-auth-bypass | 87.3 | 81.0 | 90.0 | 93.0 | 80.9 | Excellent |
| 23 | digital-forensics | 87.1 | 92.0 | 93.3 | 85.5 | 78.5 | Excellent |
| 24 | continuous-learning | 87.0 | 91.0 | 93.3 | 84.2 | 80.3 | Excellent |
| 25 | web-access-control | 86.9 | 83.0 | 91.2 | 89.2 | 81.2 | Excellent |
| 26 | wifi-pentest | 86.9 | 89.0 | 87.7 | 92.5 | 78.1 | Excellent |
| 27 | data-scraper-agent | 86.8 | 80.0 | 93.6 | 92.5 | 76.0 | Excellent |
| 28 | exa-search | 86.8 | 80.0 | 93.4 | 92.5 | 76.2 | Excellent |
| 29 | browser-qa | 86.7 | 80.0 | 93.7 | 92.5 | 75.2 | Excellent |
| 30 | logging-monitoring | 86.6 | 76.0 | 92.7 | 92.5 | 78.5 | Excellent |
| 31 | api-security | 86.5 | 83.0 | 87.4 | 93.0 | 79.6 | Excellent |
| 32 | insecure-design | 86.4 | 89.0 | 88.8 | 85.5 | 83.0 | Excellent |
| 33 | mobile-security | 86.4 | 87.0 | 89.0 | 85.5 | 84.0 | Excellent |
| 34 | recon-osint | 86.4 | 81.0 | 88.4 | 86.8 | 86.8 | Excellent |
| 35 | security-review | 86.4 | 87.0 | 86.7 | 90.0 | 81.4 | Excellent |
| 36 | web-xss | 86.4 | 80.0 | 90.9 | 92.5 | 77.6 | Excellent |
| 37 | codebase-onboarding | 86.3 | 89.0 | 91.9 | 85.5 | 79.1 | Excellent |
| 38 | post-exploitation | 86.3 | 92.0 | 88.8 | 86.8 | 79.5 | Excellent |
| 39 | safety-guard | 86.2 | 100.0 | 80.0 | 90.0 | 80.6 | Excellent |
| 40 | password-attack | 86.1 | 87.0 | 87.6 | 88.0 | 81.7 | Excellent |
| 41 | web-ssrf | 86.1 | 92.0 | 87.3 | 86.8 | 80.4 | Excellent |
| 42 | search-first | 85.9 | 85.0 | 84.9 | 92.5 | 79.8 | Excellent |
| 43 | knowledge-ops | 85.8 | 91.0 | 84.4 | 90.0 | 79.1 | Excellent |
| 44 | mcp-server-patterns | 85.7 | 83.0 | 93.5 | 83.0 | 81.2 | Excellent |
| 45 | multi-agent-collaboration | 85.2 | 84.0 | 83.1 | 90.0 | 82.8 | Excellent |
| 46 | chronicle | 85.1 | 95.0 | 80.0 | 90.0 | 79.5 | Excellent |
| 47 | docker-patterns | 85.0 | 85.0 | 82.6 | 92.5 | 79.0 | Excellent |
| 48 | web-sqli | 84.9 | 76.0 | 70.9 | 97.5 | 92.0 | Excellent |
| 49 | deep-research | 84.3 | 92.0 | 75.5 | 96.2 | 76.0 | Excellent |

---

## Summary Statistics (v2)

| Metric | Value |
|--------|-------|
| Average Score | 87.5 |
| Median Score | 86.9 |
| Highest Score | 91.2 (cloud-security) |
| Lowest Score | 84.3 (deep-research) |
| Score Range | 6.9 |

---

## v0.1.17 Summary

### Changes from v0.1.16

| Metric | v0.1.16 | v0.1.17 | Change |
|--------|---------|---------|--------|
| Average | 86.1 | 87.5 | +1.4 |
| Minimum | 80.1 | 84.3 | +4.2 |
| Maximum | 90.1 | 91.2 | +1.1 |
| Range | 10.0 | 6.9 | -3.1 (tighter) |
| Key sections < 3/3 | 15 | 0 | All fixed |

### Biggest Movers

| Skill | v0.1.16 | v0.1.17 | Change | Why |
|-------|---------|---------|--------|-----|
| cloud-security | 90.1 | 91.2 | +1.1 | 3 new guides (AWS/Azure/post-exploitation) |
| security-bounty-hunter | 88.4 | 89.7 | +1.3 | 3 new guides |
| post-exploitation | 80.1 | 86.3 | +6.2 | 2 new guides + key sections fixed |
| ai-fuzzing | 82.4 | 88.2 | +5.8 | 2 new guides + key sections fixed |
| password-attack | 82.5 | 86.1 | +3.6 | 2 new guides + key sections fixed |
| insecure-design | 82.7 | 86.4 | +3.7 | 2 new guides + key sections fixed |
| continuous-learning | 81.6 | 87.0 | +5.4 | 3 new test cases |
| container-security | 87.0 | 89.5 | +2.5 | Key section + 3 new guides |

---

## Notes

- **49 Excellent skills** — 100% at Excellent tier
- **0 Distinguished** — cloud-security at 91.2 is closest (0.8 away)
- **Top 5**: cloud-security (91.2), network-pentest (90.9), article-writing (90.6), vulnerability-assessment (90.6), autonomous-loops (90.5)
- **CI quality gate** — baseline 87.5, blocks PRs on avg regression >1.0 or per-skill >5.0
- **10 integration scenarios** — all PASS (INT-001 through INT-010)
