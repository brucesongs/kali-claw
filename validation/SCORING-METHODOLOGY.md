# Scoring Methodology v2

> Formal reference for the kali-claw skill quality scoring system.
> Implementation: `validation/SCORE.sh`

---

## Component Weights

| Component | Weight | Source File | Description |
|-----------|--------|-------------|-------------|
| SKILL.md | 15% | `skills/<name>/SKILL.md` | Structural depth (## heading count) |
| payloads.md | 30% | `skills/<name>/payloads.md` | Average of word count, section count, code block count |
| test-cases.md | 30% | `skills/<name>/test-cases.md` | Average of test case count and field completeness |
| guides/ | 25% | `skills/<name>/guides/*` | Composite: file count (40%) + avg word count (30%) + key section presence (30%) |

---

## Tier Boundaries (v2)

| Tier | Score Range | Description |
|------|-------------|-------------|
| Weak | 0 - 39.9 | Missing critical components or extremely thin coverage |
| Adequate | 40.0 - 59.9 | Has all components, some depth |
| Strong | 60.0 - 79.9 | Good coverage across all components |
| Excellent | 80.0 - 91.9 | Comprehensive coverage, room for depth improvement |
| Distinguished | 92.0 - 100.0 | Best-in-class depth and quality across all components |

---

## v2 Changes from v1

1. **Score inflation cap**: All normalized and component scores capped at 100 (no overflow)
2. **Guide quality metric**: Replaced raw file count with composite metric
3. **Distinguished tier**: New tier at 92+ to differentiate top skills
4. **Component caps**: Payload and test-case component scores capped at 100

---

## Per-Metric Normalization

Each raw metric is normalized to 0-100 using tier thresholds. All scores are hard-capped at 100.

### Payload Word Count

Thresholds: `compute_normalized_score $count 300 1000 2000 2000`

| Tier | Range | Score |
|------|-------|-------|
| Weak | 0 - 999 | 0 - 40 |
| Adequate | 1000 - 1999 | 40 - 60 |
| Strong | 2000+ | 60 - 80 |
| Excellent | 2000+ (capped) | 80 - 100 |

### Payload Section Count (## headings)

Thresholds: `compute_normalized_score $count 5 7 9 9`

| Tier | Range | Score |
|------|-------|-------|
| Weak | 0 - 4 | 0 - 40 |
| Adequate | 5 - 6 | 40 - 60 |
| Strong | 7 - 8 | 60 - 80 |
| Excellent | 9+ (capped) | 80 - 100 |

### Payload Code Blocks

Thresholds: `compute_normalized_score $count 20 35 50 50`

| Tier | Range | Score |
|------|-------|-------|
| Weak | 0 - 19 | 0 - 40 |
| Adequate | 20 - 34 | 40 - 60 |
| Strong | 35 - 49 | 60 - 80 |
| Excellent | 50+ (capped) | 80 - 100 |

### Test Case Count (## TC- or ### TC- headings)

Thresholds: `compute_normalized_score $count 3 5 8 8`

| Tier | Range | Score |
|------|-------|-------|
| Weak | 0 - 2 | 0 - 40 |
| Adequate | 3 - 4 | 40 - 60 |
| Strong | 5 - 7 | 60 - 80 |
| Excellent | 8+ (capped) | 80 - 100 |

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

### SKILL.md Section Score (## heading count)

| Headings | Score |
|----------|-------|
| 0 - 5 | 0 - 40 (linear) |
| 6 - 9 | 40 - 60 |
| 10 - 14 | 60 - 80 |
| 15+ | 80 - 100 (capped) |

---

## Guide Quality Composite (v2 new)

The guides component is now a composite metric with three sub-scores:

### Sub-score 1: File Count (40% weight)

| Tier | File Count | Score |
|------|------------|-------|
| Weak | 0 - 1 | 0 - 40 |
| Adequate | 2 - 4 | 40 - 60 |
| Strong | 5 - 7 | 60 - 80 |
| Excellent | 8+ (capped) | 80 - 100 |

### Sub-score 2: Average Word Count (30% weight)

| Tier | Avg Words | Score |
|------|-----------|-------|
| Weak | 0 - 199 | 0 - 40 |
| Adequate | 200 - 499 | 40 - 60 |
| Strong | 500 - 999 | 60 - 80 |
| Excellent | 1000+ (capped) | 80 - 100 |

### Sub-score 3: Key Section Presence (30% weight)

Checks for presence of three key section types across all guide files:

1. **Introduction/Objective**: `Introduction|Objective|Overview|Purpose`
2. **Hands-on/Practice**: `Hands-on|Practice|Exercise|Lab|Walkthrough|Tutorial|Step-by-step`
3. **References/Resources**: `References|Resources|See also|Further reading|Links`

Score = (matched sections / 3) * 100

### Composite Formula

```
guide_score = (file_count_score * 0.40) + (avg_word_score * 0.30) + (key_section_score * 0.30)
```

Capped at 100.

---

## Component Score Computation

### payloads.md Component (capped at 100)

```
payload_component = min(100, (payload_word_score + payload_section_score + payload_code_score) / 3)
```

### test-cases.md Component (capped at 100)

```
testcase_component = min(100, (test_case_score + field_completeness_score) / 2)
```

### Overall Score

```
overall = (skill_md_score * 0.15) + (payload_component * 0.30) + (testcase_component * 0.30) + (guide_score * 0.25)
```

---

## v2 Baseline (2026-06-02)

| Metric | Value |
|--------|-------|
| Skills scored | 49 |
| Min score | 80.1 (post-exploitation) |
| Max score | 90.1 (cloud-security) |
| Average | 86.1 |
| Distinguished | 0 |
| Excellent | 49 |
| Strong | 0 |

---

## Known Limitations

1. **Word count includes code blocks** — Payload word count includes words inside code fences
2. **Field completeness is binary** — Each pattern is either present or absent
3. **SKILL.md heading count is structural** — Measures document structure, not content quality
4. **Guide key sections are presence-only** — Does not measure depth of sections, just whether they exist
