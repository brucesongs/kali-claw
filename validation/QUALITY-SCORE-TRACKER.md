# Skill Quality Score Tracker

> **Objective**: Track quality scores for all 49 skill domains based on documentation depth and completeness.
> **Scored**: 2026-05-29 | **Last Updated**: 2026-05-29 (v0.1.13)

---

## Scoring Methodology

| Component | Weight | Metrics |
|-----------|--------|---------|
| SKILL.md | 15% | Section count (## headings), normalized against thresholds |
| payloads.md | 30% | Word count + section count + code block count |
| test-cases.md | 30% | Test case count + field completeness (7 expected fields) |
| guides/ | 25% | Number of guide files |

## Tier Definitions

| Tier | Score Range | Description |
|------|-------------|-------------|
| **Weak** | 0-40 | Missing critical components or extremely thin coverage |
| **Adequate** | 40-60 | Has all components, some depth |
| **Strong** | 60-80 | Good coverage across all components |
| **Excellent** | 80-100 | Best-in-class, comprehensive coverage |

---

## Tier Distribution

| Tier | Count | Percentage | Change from v0.1.12 |
|------|-------|------------|---------------------|
| Weak | 0 | 0% | ↓9 (from 9) |
| Adequate | 27 | 55% | ↑9 (from 18) |
| Strong | 20 | 41% | ±0 (from 20) |
| Excellent | 2 | 4% | ±0 (from 2) |

---

## Quality Scores

| # | Skill | Overall | SKILL.md | Payloads | Test Cases | Guides | Tier |
|---|-------|---------|----------|----------|------------|--------|------|
| 1 | web-sqli | 89.6 | 76.0 | 50.3 | 80.5 | 156.0 | Excellent |
| 2 | recon-osint | 81.0 | 81.0 | 56.0 | 86.8 | 104.0 | Excellent |
| 3 | osint | 72.4 | 95.0 | 56.9 | 92.5 | 53.3 | Strong |
| 4 | deep-research | 72.1 | 92.0 | 53.5 | 96.3 | 53.3 | Strong |
| 5 | mobile-security | 71.9 | 87.0 | 44.1 | 85.5 | 80.0 | Strong |
| 6 | network-pentest | 71.1 | 68.0 | 42.7 | 93.8 | 80.0 | Strong |
| 7 | binary-reverse | 70.0 | 76.0 | 62.6 | 93.8 | 46.7 | Strong |
| 8 | wifi-pentest | 68.5 | 68.0 | 57.3 | 92.5 | 53.3 | Strong |
| 9 | supply-chain-security | 66.7 | 76.0 | 56.1 | 95.0 | 40.0 | Strong |
| 10 | api-security | 66.6 | 76.0 | 52.6 | 98.0 | 40.0 | Strong |
| 11 | vulnerability-assessment | 66.5 | 76.0 | 46.8 | 92.5 | 53.3 | Strong |
| 12 | cloud-security | 65.8 | 87.0 | 37.5 | 93.8 | 53.3 | Strong |
| 13 | web-auth-bypass | 65.3 | 81.0 | 49.5 | 94.3 | 40.0 | Strong |
| 14 | social-engineering | 65.1 | 76.0 | 53.1 | 92.5 | 40.0 | Strong |
| 15 | crypto-attacks | 62.5 | 68.0 | 47.1 | 93.8 | 40.0 | Strong |
| 16 | chronicle | 62.4 | 95.0 | 77.4 | 66.4 | 20.0 | Strong |
| 17 | safety-guard | 62.1 | 100.0 | 78.0 | 62.2 | 20.0 | Strong |
| 18 | digital-forensics | 62.0 | 76.0 | 50.0 | 85.5 | 40.0 | Strong |
| 19 | container-security | 60.8 | 76.0 | 37.5 | 93.8 | 40.0 | Strong |
| 20 | autonomous-loops | 60.8 | 88.0 | 73.5 | 51.9 | 40.0 | Strong |
| 21 | hardware-security | 60.3 | 81.0 | 64.1 | 63.0 | 40.0 | Strong |
| 22 | web-xss | 60.0 | 80.0 | 48.7 | 78.0 | 40.0 | Strong |
| 23 | ai-security | 59.8 | 76.0 | 71.3 | 73.4 | 20.0 | Adequate |
| 24 | post-exploitation | 59.6 | 76.0 | 40.6 | 86.8 | 40.0 | Adequate |
| 25 | password-attack | 59.6 | 60.0 | 47.4 | 88.0 | 40.0 | Adequate |
| 26 | continuous-learning | 59.3 | 91.0 | 69.0 | 66.4 | 20.0 | Adequate |
| 27 | ai-fuzzing | 59.3 | 84.0 | 65.2 | 51.5 | 46.7 | Adequate |
| 28 | web-access-control | 59.2 | 72.0 | 33.3 | 89.3 | 46.7 | Adequate |
| 29 | security-review | 59.2 | 87.0 | 44.0 | 76.7 | 40.0 | Adequate |
| 30 | multi-agent-collaboration | 59.2 | 84.0 | 52.1 | 70.0 | 40.0 | Adequate |
| 31 | verification-loop | 59.0 | 97.0 | 52.0 | 63.0 | 40.0 | Adequate |
| 32 | web-ssrf | 58.1 | 76.0 | 52.4 | 86.8 | 20.0 | Adequate |
| 33 | logging-monitoring | 57.9 | 76.0 | 45.8 | 92.5 | 20.0 | Adequate |
| 34 | knowledge-ops | 57.8 | 91.0 | 59.9 | 48.5 | 46.7 | Adequate |
| 35 | article-writing | 57.3 | 100.0 | 47.2 | 55.0 | 46.7 | Adequate |
| 36 | council | 57.2 | 100.0 | 62.7 | 44.5 | 40.0 | Adequate |
| 37 | social-intelligence | 56.9 | 95.0 | 33.4 | 70.0 | 46.7 | Adequate |
| 38 | security-misconfiguration | 56.2 | 76.0 | 39.0 | 93.8 | 20.0 | Adequate |
| 39 | mcp-server-patterns | 55.2 | 83.0 | 46.1 | 63.0 | 40.0 | Adequate |
| 40 | security-bounty-hunter | 54.0 | 87.0 | 45.9 | 51.5 | 46.7 | Adequate |
| 41 | search-first | 52.6 | 85.0 | 48.0 | 51.5 | 40.0 | Adequate |
| 42 | codebase-onboarding | 52.6 | 89.0 | 37.8 | 48.5 | 53.3 | Adequate |
| 43 | insecure-design | 52.4 | 68.0 | 38.4 | 85.5 | 20.0 | Adequate |
| 44 | terminal-ops | 48.4 | 76.0 | 38.5 | 51.5 | 40.0 | Adequate |
| 45 | docker-patterns | 47.3 | 85.0 | 30.4 | 51.5 | 40.0 | Adequate |
| 46 | repo-scan | 45.5 | 84.0 | 31.7 | 44.5 | 40.0 | Adequate |
| 47 | data-scraper-agent | 44.3 | 40.0 | 31.4 | 63.0 | 40.0 | Adequate |
| 48 | browser-qa | 41.4 | 40.0 | 29.2 | 55.5 | 40.0 | Adequate |
| 49 | exa-search | 40.4 | 40.0 | 44.8 | 36.5 | 40.0 | Adequate |

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Average Score | 59.4 |
| Median Score | 59.2 |
| Highest Score | 89.6 (web-sqli) |
| Lowest Score | 40.4 (exa-search) |
| Score Range | 49.2 |

---

## v0.1.13 Improvements Summary

### Fixes Applied
1. **SCORE.sh section matching** — Replaced name-based matching with heading-count approach (counts `##` headings, normalized against thresholds 6/10/15). Eliminates false low scores from non-standard section naming.
2. **SCORE.sh test case pattern** — Changed `### TC-` to `^##+ TC-` to match both `## TC-` and `### TC-` formats.
3. **SCORE.sh field completeness** — Updated pattern matching to recognize "Steps", "Expected Output", "Objective" in addition to original patterns.

### Content Added
| Skill | Changes | Impact |
|-------|---------|--------|
| data-scraper-agent | Expanded payloads.md (116→647 words) + 2 guides + 3 test cases | 18.5 → 44.3 |
| browser-qa | Expanded payloads.md (130→708 words) + 2 guides + 2 test cases | 19.9 → 41.4 |
| exa-search | Expanded payloads.md (211→823 words) + 2 guides | 19.9 → 40.4 |

### Tier Movement Summary
| Movement | Count | Skills |
|----------|-------|--------|
| Weak → Adequate | 9 | data-scraper-agent, browser-qa, exa-search, docker-patterns, codebase-onboarding, article-writing, repo-scan, search-first, knowledge-ops |

---

## Notes

- **Zero Weak skills** — All 49 skills now at Adequate tier or above
- **Scoring approach change**: SKILL.md now scores by structural depth (heading count) rather than specific section name matching, which is more fair across different skill styles
- **Next targets for Strong tier**: ai-security, post-exploitation, password-attack, continuous-learning (all at 59.x, just below 60 threshold)
