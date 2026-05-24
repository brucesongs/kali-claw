# Skill Quality Scoring Guide

> Comprehensive documentation of the quality scoring system for kali-claw skill domains.

---

## Overview

The quality scoring system quantifies documentation depth and completeness for each of the 49 skill domains. Unlike the binary FULL/not-FULL status (v0.1.8), this provides granular metrics across four components: SKILL.md, payloads.md, test-cases.md, and guides/.

---

## Metrics

### 1. Payload Coverage (30% of overall score)

| Metric | File | What It Measures | Weak | Adequate | Strong | Excellent |
|--------|------|------------------|------|----------|--------|-----------|
| payload_word_count | payloads.md | Attack pattern depth | <300 | 300-1000 | 1000-2000 | >2000 |
| payload_section_count | payloads.md | Attack type breadth (## headings) | <5 | 5-7 | 7-9 | >9 |
| payload_code_blocks | payloads.md | Actionable payloads (``` blocks) | <20 | 20-35 | 35-50 | >50 |

### 2. Test Case Quality (30% of overall score)

| Metric | File | What It Measures | Weak | Adequate | Strong | Excellent |
|--------|------|------------------|------|----------|--------|-----------|
| test_case_count | test-cases.md | Test coverage breadth (TC- entries) | <3 | 3-5 | 5-8 | >8 |
| field_completeness_score | test-cases.md | Test case structure quality (0-1) | <0.5 | 0.5-0.7 | 0.7-0.85 | >0.85 |

**Field Completeness** checks for presence of 7 key fields:
1. Severity (CRITICAL/HIGH/MEDIUM/LOW)
2. Prerequisites / Pre-conditions
3. Test Steps (numbered or bulleted)
4. Expected Results / Expected Outcomes
5. Reference to payloads.md
6. Remediation / Defense guidance
7. Pass Criteria / Verification checklist

### 3. Guide Depth (25% of overall score)

| Metric | File | What It Measures | Weak | Adequate | Strong | Excellent |
|--------|------|------------------|------|----------|--------|-----------|
| guide_file_count | guides/ | Learning depth (.md, .py, .sh files) | 0 | 1-2 | 3-5 | >5 |

### 4. SKILL.md Completeness (15% of overall score)

| Metric | File | What It Measures | Weak | Adequate | Strong | Excellent |
|--------|------|------------------|------|----------|--------|-----------|
| skill_section_score | SKILL.md | Documentation completeness (0-1) | <0.5 | 0.5-0.7 | 0.7-0.85 | >0.85 |

**Section Completeness** checks for presence of 8 expected sections:
1. Description
2. Use Cases
3. Core Tools (table)
4. Methodology / Attack Chain
5. Defense Perspective
6. Practical Steps
7. Hacker Laws
8. Learning Resources

---

## Score Calculation

Each metric is normalized to a 0-100 scale based on its tier thresholds.

**Component Scores:**
- `payloads_md` = average of (payload_word + payload_section + payload_code)
- `test_cases_md` = average of (test_case + field)
- `guides` = guide score
- `skill_md` = skill_section score

**Overall Score:**
```
overall = (skill_md * 0.15) + (payloads_md * 0.30) + (test_cases_md * 0.30) + (guides * 0.25)
```

---

## Scoring Script

Run `./validation/SCORE.sh` to compute scores for all skills:

```bash
cd /path/to/kali-claw-en
./validation/SCORE.sh
```

Outputs:
- JSON file per skill: `validation/evidence/quality-scores/{skill}.json`
- Update `validation/QUALITY-SCORE-TRACKER.md` with results

---

## Tier Distribution (v0.1.11)

| Tier | Count | Percentage |
|------|-------|------------|
| Weak | 22 | 45% |
| Adequate | 25 | 51% |
| Strong | 2 | 4% |
| Excellent | 0 | 0% |

---

## Findings

### Top Skills (Strong Tier)

| Rank | Skill | Overall Score | Strength |
|------|-------|---------------|----------|
| 1 | web-sqli | 76.1 | 24 guides (best-in-class), strong payloads and test cases |
| 2 | recon-osint | 66.6 | Balanced across all components, good guide count |

### Skills Needing Enrichment (Weak Tier — Bottom 10)

| Rank | Skill | Overall Score | Primary Gap |
|------|-------|---------------|-------------|
| 49 | data-scraper-agent | 4.7 | No guides, minimal test cases |
| 48 | browser-qa | 6.1 | No guides, minimal payloads |
| 47 | exa-search | 7.1 | No guides, minimal payloads and test cases |
| 46 | repo-scan | 23.1 | No guides, weak payloads |
| 45 | docker-patterns | 24.8 | No guides, weak payloads |
| 44 | terminal-ops | 27.2 | No guides, weak test cases |
| 43 | codebase-onboarding | 29.0 | Weak test cases despite guides |
| 42 | mcp-server-patterns | 29.5 | No guides, weak test cases |
| 41 | search-first | 30.0 | No guides, weak test cases |
| 40 | security-review | 31.1 | No guides, average test cases |

### Key Insights

1. **Guide poverty is the main weakness**: 22 skills (45%) have 0 guides. Adding even 1-2 guides would significantly boost their scores.
2. **Test cases are generally strong**: Many skills score 80-90% in the test-cases.md dimension.
3. **SKILL.md section detection needs refinement**: Current grep patterns are too strict. All skills show 0/15, but actual documentation exists.
4. **No Excellent tier skills**: The highest score is 76.1 (web-sqli), below the 80-point threshold. This indicates room for improvement even at the top.

### Recommended Enrichment Priorities

**Quick wins** (adding 1-2 guides to reach Adequate tier):
- docker-patterns (24.8 → ~45)
- terminal-ops (27.2 → ~47)
- search-first (30.0 → ~50)
- mcp-server-patterns (29.5 → ~50)

**Mid-tier improvements** (adding guides + payloads):
- repo-scan (23.1 → ~50)
- codebase-onboarding (29.0 → ~50, also needs more test cases)
- security-review (31.1 → ~55)

**Long-term investments** (comprehensive enrichment):
- data-scraper-agent (4.7 → needs guides + test cases + payloads)
- browser-qa (6.1 → needs guides + payloads)
- exa-search (7.1 → needs guides + payloads + test cases)

---

## Known Limitations

1. **SKILL.md section detection**: Current regex patterns don't match all section name variations. Many SKILL.md files have the expected content under slightly different headings.
2. **Field completeness pattern matching**: Simple keyword matching may miss fields expressed differently (e.g., "Required Tools" instead of "Prerequisites").
3. **Guide quality not assessed**: The script counts guide files but doesn't evaluate their content quality or relevance.

---

## Changes Since Last Score

| Skill | Previous | Current | Delta |
|-------|----------|---------|-------|
| N/A | N/A | N/A | N/A (first score baseline) |