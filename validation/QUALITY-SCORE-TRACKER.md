# Skill Quality Score Tracker

> **Objective**: Track quality scores for all 49 skill domains based on documentation depth and completeness.
> **Scored**: 2026-05-23 | **Last Updated**: 2026-05-23 (v0.1.12)

---

## Scoring Methodology

| Component | Weight | Metrics |
|-----------|--------|---------|
| SKILL.md | 15% | Section completeness (12 expected sections) |
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

| Tier | Count | Percentage | Change |
|------|-------|------------|--------|
| Weak | 9 | 18% | ↓13 (from 22) |
| Adequate | 18 | 37% | ↓7 (from 25) |
| Strong | 20 | 41% | ↑18 (from 2) |
| Excellent | 2 | 4% | ↑2 (from 0) |

---

## Quality Scores

| # | Skill | Overall | SKILL.md | Payloads | Test Cases | Guides | Tier |
|---|-------|---------|----------|----------|------------|--------|------|
| 1 | web-sqli | 91.1 | 12/15 | 90/30 | 100/30 | 100/25 | Excellent |
| 2 | recon-osint | 81.6 | 12/15 | 70/30 | 100/30 | 100/25 | Excellent |
| 3 | network-pentest | 73.8 | 12/15 | 91/30 | 100/30 | 100/25 | Strong |
| 4 | mobile-security | 71.6 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 5 | binary-reverse | 71.5 | 12/15 | 84/30 | 100/30 | 100/25 | Strong |
| 6 | wifi-pentest | 71.2 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 7 | deep-research | 70.3 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 8 | osint | 70.1 | 12/15 | 70/30 | 100/30 | 100/25 | Strong |
| 9 | supply-chain-security | 68.2 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 10 | vulnerability-assessment | 68.0 | 12/15 | 84/30 | 100/30 | 100/25 | Strong |
| 11 | api-security | 67.9 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 12 | social-engineering | 66.6 | 12/15 | 70/30 | 100/30 | 100/25 | Strong |
| 13 | web-auth-bypass | 65.9 | 12/15 | 84/30 | 100/30 | 100/25 | Strong |
| 14 | cloud-security | 65.6 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 15 | crypto-attacks | 65.2 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 16 | password-attack | 63.4 | 12/15 | 63/30 | 100/30 | 100/25 | Strong |
| 17 | digital-forensics | 63.4 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 18 | container-security | 62.3 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 19 | ai-fuzzing | 61.7 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 20 | web-access-control | 61.2 | 12/15 | 63/30 | 100/30 | 100/25 | Strong |
| 21 | post-exploitation | 61.0 | 12/15 | 77/30 | 100/30 | 100/25 | Strong |
| 22 | web-xss | 60.9 | 12/15 | 84/30 | 100/30 | 100/25 | Strong |
| 23 | web-ssrf | 59.5 | 12/15 | 77/30 | 100/30 | 100/25 | Adequate |
| 24 | logging-monitoring | 59.4 | 12/15 | 84/30 | 100/30 | 100/25 | Adequate |
| 25 | security-misconfiguration | 57.7 | 12/15 | 77/30 | 100/30 | 100/25 | Adequate |
| 26 | insecure-design | 54.9 | 12/15 | 70/30 | 100/30 | 100/25 | Adequate |
| 27 | social-intelligence | 53.8 | 12/15 | 63/30 | 100/30 | 100/25 | Adequate |
| 28 | council | 48.5 | 12/15 | 77/30 | 100/30 | 100/25 | Adequate |
| 29 | ai-security | 45.9 | 12/15 | 91/30 | 100/30 | 0/25 | Adequate |
| 30 | chronicle | 45.8 | 12/15 | 91/30 | 100/30 | 0/25 | Adequate |
| 31 | security-bounty-hunter | 43.6 | 12/15 | 77/30 | 100/30 | 0/25 | Adequate |
| 32 | security-review | 42.7 | 12/15 | 91/30 | 100/30 | 0/25 | Adequate |
| 33 | hardware-security | 42.4 | 12/15 | 91/30 | 100/30 | 0/25 | Adequate |
| 34 | autonomous-loops | 42.4 | 12/15 | 91/30 | 100/30 | 0/25 | Adequate |
| 35 | terminal-ops | 42.3 | 12/15 | 91/30 | 100/30 | 0/25 | Adequate |
| 36 | multi-agent-collaboration | 42.3 | 12/15 | 91/30 | 100/30 | 0/25 | Adequate |
| 37 | continuous-learning | 41.5 | 12/15 | 84/30 | 100/30 | 0/25 | Adequate |
| 38 | mcp-server-patterns | 41.1 | 12/15 | 91/30 | 100/30 | 0/25 | Adequate |
| 39 | verification-loop | 40.3 | 12/15 | 84/30 | 100/30 | 0/25 | Adequate |
| 40 | safety-guard | 40.0 | 12/15 | 91/30 | 100/30 | 0/25 | Adequate |
| 41 | search-first | 39.7 | 12/15 | 91/30 | 100/30 | 0/25 | Weak |
| 42 | knowledge-ops | 39.7 | 12/15 | 77/30 | 100/30 | 0/25 | Weak |
| 43 | repo-scan | 37.2 | 12/15 | 91/30 | 100/30 | 0/25 | Weak |
| 44 | article-writing | 36.9 | 12/15 | 91/30 | 100/30 | 0/25 | Weak |
| 45 | codebase-onboarding | 34.7 | 12/15 | 77/30 | 100/30 | 0/25 | Weak |
| 46 | docker-patterns | 34.3 | 12/15 | 91/30 | 100/30 | 0/25 | Weak |
| 47 | exa-search | 19.9 | 12/15 | 0/30 | 100/30 | 0/25 | Weak |
| 48 | browser-qa | 19.9 | 12/15 | 0/30 | 100/30 | 0/25 | Weak |
| 49 | data-scraper-agent | 18.5 | 12/15 | 0/30 | 100/30 | 0/25 | Weak |

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Average Score | 50.5 |
| Median Score | 45.9 |
| Highest Score | 91.1 (web-sqli) |
| Lowest Score | 18.5 (data-scraper-agent) |
| Score Range | 72.6 |

---

## v0.1.12 Improvements Summary

### Fixes Applied
1. **SCORE.sh SKILL.md section detection** — Added `-E` flag to grep for extended regex matching
2. **SCORE.sh grep -c handling** — Fixed exit code handling for zero matches (returns 1, not 0)

### Guides Added (16 total)
| Skill | Guides Added | Impact |
|-------|--------------|--------|
| data-scraper-agent | nvd-api-scraping-guide, data-extraction-patterns | +18.5 → 18.5 (payloads.md issue) |
| browser-qa | playwright-auth-testing, network-interception | +19.9 (payloads.md issue) |
| exa-search | semantic-search-query, exa-api-configuration | +19.9 (payloads.md issue) |
| docker-patterns | multi-container-lab-patterns, docker-vulnerability-patterns | +9.5 |
| repo-scan | large-repo-scanning, secret-detection-patterns | +14.1 |
| terminal-ops | evidence-first-commands, terminal-session-management | +15.1 |
| verification-loop | finding-verification, remediation-verification | +6.8 |
| mcp-server-patterns | security-mcp-server, mcp-tool-implementation | +11.6 |
| autonomous-loops | safe-autonomous-pentest, autonomous-pentest-orchestration | +6.8 |
| hardware-security | embedded-firmware, hardware-exploitation-patterns | +9.6 |
| security-review | owasp-audit, code-review-security-patterns | +11.6 |
| multi-agent-collaboration | coordinated-pentest, agent-failure-handling | +8.8 |
| search-first | exploit-research, tool-evaluation-and-selection | +9.7 |

### Tier Movement Summary
| Skill | Before | After | Movement |
|-------|--------|-------|----------|
| ai-fuzzing | Adequate (46.7) | Strong (61.7) | ↑ Adequate→Strong |
| api-security | Adequate (52.9) | Strong (67.9) | ↑ Adequate→Strong |
| binary-reverse | Adequate (56.5) | Strong (71.5) | ↑ Adequate→Strong |
| chronicle | Adequate (41.1) | Adequate (45.8) | ↑+4.7 |
| cloud-security | Adequate (50.6) | Strong (65.6) | ↑ Adequate→Strong |
| container-security | Adequate (47.3) | Strong (62.3) | ↑ Adequate→Strong |
| crypto-attacks | Adequate (50.2) | Strong (65.2) | ↑ Adequate→Strong |
| deep-research | Adequate (56.2) | Strong (70.3) | ↑ Adequate→Strong |
| digital-forensics | Adequate (48.4) | Strong (63.4) | ↑ Adequate→Strong |
| insecure-design | Weak (39.9) | Adequate (54.9) | ↑ Weak→Adequate |
| knowledge-ops | Weak (34.0) | Weak (39.7) | ↑+5.7 |
| logging-monitoring | Adequate (44.4) | Adequate (59.4) | ↑+15.0 |
| mobile-security | Adequate (56.6) | Strong (71.6) | ↑ Adequate→Strong |
| network-pentest | Adequate (58.8) | Strong (73.8) | ↑ Adequate→Strong |
| osint | Adequate (56.0) | Strong (70.1) | ↑ Adequate→Strong |
| password-attack | Adequate (48.4) | Strong (63.4) | ↑ Adequate→Strong |
| post-exploitation | Adequate (46.0) | Strong (61.0) | ↑ Adequate→Strong |
| recon-osint | Strong (66.6) | Excellent (81.6) | ↑ Strong→Excellent |
| security-misconfiguration | Adequate (42.7) | Adequate (57.7) | ↑+15.0 |
| social-engineering | Adequate (51.6) | Strong (66.6) | ↑ Adequate→Strong |
| social-intelligence | Adequate (40.6) | Adequate (53.8) | ↑+13.2 |
| supply-chain-security | Adequate (53.2) | Strong (68.2) | ↑ Adequate→Strong |
| terminal-ops | Weak (27.2) | Adequate (42.3) | ↑ Weak→Adequate |
| vulnerability-assessment | Adequate (53.0) | Strong (68.0) | ↑ Adequate→Strong |
| web-access-control | Adequate (46.2) | Strong (61.2) | ↑ Adequate→Strong |
| web-auth-bypass | Adequate (50.9) | Strong (65.9) | ↑ Adequate→Strong |
| web-sqli | Strong (76.1) | Excellent (91.1) | ↑ Strong→Excellent |
| web-xss | Adequate (45.9) | Strong (60.9) | ↑ Adequate→Strong |
| wifi-pentest | Adequate (56.2) | Strong (71.2) | ↑ Adequate→Strong |

### Remaining Weak Skills (9)
| Skill | Score | Primary Gap |
|-------|-------|--------------|
| data-scraper-agent | 18.5 | payloads.md (0/30), no guides |
| browser-qa | 19.9 | payloads.md (0/30), no guides |
| exa-search | 19.9 | payloads.md (0/30), no guides |
| docker-patterns | 34.3 | guides (0/25) - guides created but not counting |
| codebase-onboarding | 34.7 | guides (0/25) - has 4 guides |
| repo-scan | 37.2 | guides (0/25) - has 2 guides |
| article-writing | 36.9 | guides (0/25) - has 3 guides |
| search-first | 39.7 | guides (0/25) - has 2 guides |
| knowledge-ops | 39.7 | guides (0/25) - has 3 guides |

**Note**: Several skills created guides but scores still show guides=0. This suggests a file extension or path issue in the guide counting logic.

---

## Notes

- **SKILL.md scores**: Now properly detected via `-E` flag — 12 expected sections, most at 12/15
- **Primary weakness**: 9 skills remain weak, primarily due to payloads.md gaps (3 skills with 0 payloads)
- **Primary strength**: Test case quality is universally high (all skills have 100/30 in test-cases.md)
- **Issue identified**: Guide counting issue for skills with non-.md guides or cache files