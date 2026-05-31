# Scoring Methodology

> Formal reference for the kali-claw skill quality scoring system.
> Implementation: `validation/SCORE.sh`

---

## Component Weights

| Component | Weight | Source File | Description |
|-----------|--------|-------------|-------------|
| SKILL.md | 15% | `skills/<name>/SKILL.md` | Structural depth (## heading count) |
| payloads.md | 30% | `skills/<name>/payloads.md` | Average of word count, section count, code block count |
| test-cases.md | 30% | `skills/<name>/test-cases.md` | Average of test case count and field completeness |
| guides/ | 25% | `skills/<name>/guides/*.md` | Number of guide files |

---

## Tier Boundaries

| Tier | Score Range | Description |
|------|-------------|-------------|
| Weak | 0 - 39.9 | Missing critical components or extremely thin coverage |
| Adequate | 40.0 - 59.9 | Has all components, some depth |
| Strong | 60.0 - 79.9 | Good coverage across all components |
| Excellent | 80.0 - 100.0 | Best-in-class, comprehensive coverage |

---

## Per-Metric Normalization

Each raw metric is normalized to 0-100 using tier thresholds:

### Payload Word Count

| Tier | Range | Score |
|------|-------|-------|
| Weak | 0 - 999 | 0 - 40 |
| Adequate | 1000 - 1999 | 40 - 60 |
| Strong | 2000+ | 60 - 80 |
| Excellent | 2000+ (overflow) | 80 - 100 |

Thresholds: `compute_normalized_score $count 300 1000 2000 2000`

### Payload Section Count (## headings)

| Tier | Range | Score |
|------|-------|-------|
| Weak | 0 - 6 | 0 - 40 |
| Adequate | 7 - 8 | 40 - 60 |
| Strong | 9+ | 60 - 80 |
| Excellent | 9+ (overflow) | 80 - 100 |

Thresholds: `compute_normalized_score $count 5 7 9 9`

### Payload Code Blocks

| Tier | Range | Score |
|------|-------|-------|
| Weak | 0 - 19 | 0 - 40 |
| Adequate | 20 - 34 | 40 - 60 |
| Strong | 35 - 49 | 60 - 80 |
| Excellent | 50+ | 80 - 100 |

Thresholds: `compute_normalized_score $count 20 35 50 50`

### Test Case Count (## TC- or ### TC- headings)

| Tier | Range | Score |
|------|-------|-------|
| Weak | 0 - 2 | 0 - 40 |
| Adequate | 3 - 4 | 40 - 60 |
| Strong | 5 - 7 | 60 - 80 |
| Excellent | 8+ | 80 - 100 |

Thresholds: `compute_normalized_score $count 3 5 8 8`

### Field Completeness (7 patterns)

Checks for presence of these patterns in test-cases.md:

1. **Severity**: `Severity|CRITICAL|HIGH|MEDIUM|LOW`
2. **Prerequisites**: `Prerequisite|Pre-condition|Pre-requisite`
3. **Steps**: `Test Step|Steps|Step [0-9]`
4. **Expected Output**: `Expected Result|Expected Outcome|Expected Output`
5. **Objective**: `Objective|Purpose|Goal`
6. **Remediation**: `Remediation|Defense|Mitigation`
7. **Pass Criteria**: `Pass Criteria|Verification|Checklist`

Score = (matched patterns / 7) * 100

### Guide File Count

| Tier | Range | Score |
|------|-------|-------|
| Weak | 0 | 0 - 40 |
| Adequate | 1 - 2 | 40 - 60 (approx) |
| Strong | 3 - 4 | 60 - 80 |
| Excellent | 5+ | 80 - 100 |

Thresholds: `compute_normalized_score $count 0 2 5 5`

**Cap**: Guide score is capped at 100 to prevent overflow from skills with many guides.

### SKILL.md Section Score (## heading count)

| Headings | Score |
|----------|-------|
| 0 - 5 | 0 - 40 (linear) |
| 6 - 9 | 40 - 60 |
| 10 - 14 | 60 - 80 |
| 15+ | 80 - 100 (capped) |

---

## Component Score Computation

### payloads.md Component

```
payload_component = (payload_word_score + payload_section_score + payload_code_score) / 3
```

### test-cases.md Component

```
testcase_component = (test_case_score + field_completeness_score) / 2
```

### Overall Score

```
overall = (skill_md_score * 0.15) + (payload_component * 0.30) + (testcase_component * 0.30) + (guide_score * 0.25)
```

---

## Worked Example: web-sqli

Raw metrics:
- payload_word_count: 917 → normalized: 36.7 (Weak tier)
- payload_section_count: 8 → normalized: 60.0 (Adequate/Strong boundary)
- payload_code_blocks: 26 → normalized: 48.0 (Adequate tier)
- test_case_count: 12 → normalized: 90.0 (Excellent tier)
- field_completeness: 1.00 → normalized: 100.0
- guide_file_count: 14 → normalized: 100.0 (capped)
- skill_section_score: 12 headings → 0.76 → 76.0

Component scores:
- SKILL.md: 76.0
- payloads.md: (36.7 + 60.0 + 48.0) / 3 = 48.2
- test-cases.md: (90.0 + 100.0) / 2 = 95.0
- guides: 100.0

Overall: (76.0 * 0.15) + (48.2 * 0.30) + (95.0 * 0.30) + (100.0 * 0.25) = 11.4 + 14.5 + 28.5 + 25.0 = 79.4

Tier: Strong (60-80)

---

## Running the Scorer

```bash
cd /path/to/kali-claw-en
bash validation/SCORE.sh
```

Output: JSON files in `validation/evidence/quality-scores/<skill>.json`

---

## Known Limitations

1. **Word count includes code blocks** — Payload word count includes words inside code fences, which may inflate scores for code-heavy payloads
2. **Field completeness is binary** — Each pattern is either present or absent; no partial credit for incomplete fields
3. **Guide quality not measured** — Only file count matters; a 10-line guide scores the same as a 500-line guide
4. **SKILL.md heading count is structural** — Measures document structure, not content quality
