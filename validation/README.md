# Validation System

> Quality assurance infrastructure for kali-claw's 49 skill domains.

---

## Quick Start

### Run Three-Axis Skill Validation (v0.3.8+)

```bash
python3 validation/check-skill-usability.py --ranking docs/SKILL_VALIDATION_RANKING_$(date +%F).md
```

Validates all 139 skills on three axes (completeness six-dimension score /
usability bash-syntax + structure gates / reliability outdated-patterns +
freshness) and writes a full ranking report. Exit 0 = clean, 2 = findings
listed in the report. Single skill: `--skill NAME`. Optional URL liveness:
`--urls 30`.

### Run Quality Scoring

```bash
bash validation/SCORE.sh
```

Generates JSON score files in `validation/evidence/quality-scores/`.

### View Results

Check `validation/QUALITY-SCORE-TRACKER.md` for the latest tier distribution and per-skill scores.

---

## File Index

| File | Purpose |
|------|---------|
| `check-skill-usability.py` | Three-axis validator + ranking generator (v0.3.5 methodology, formalized) |
| `gen-skill-handbook.py` | Regenerates SKILL_INDEX.json + SKILL_HANDBOOK.md from frontmatter |
| `check-tool-versions.py` | Kali tool baseline drift checker |
| `skill-lint.py` | SKILL.md structural linter (Defense Triple, frontmatter, translation residue) |
| `validate-payloads.py` / `validate-testcases.py` | Payload/TC existence and pattern validators |
| `SCORE.sh` | Automated scoring script (7 metrics, 4 components) |
| `SCORING-METHODOLOGY.md` | Formal scoring methodology reference |
| `QUALITY-SCORE-TRACKER.md` | Per-skill scores and tier distribution |
| `QUALITY-SCORE-GUIDE.md` | Scoring system overview and improvement strategies |
| `VALIDATION-GUIDE.md` | Test case execution playbook |
| `VALIDATION-TRACKER.md` | Practice validation execution log (49 test cases) |
| `INTEGRATION-SCENARIOS.md` | 7 cross-skill integration test definitions |
| `INTEGRATION-TRACKER.md` | Integration test results (7/7 PASS) |
| `WEAK-SKILL-IMPROVEMENT-PLANS.md` | Historical improvement plans (completed) |

---

## Directory Structure

```
validation/
├── SCORE.sh                      # Scoring engine
├── SCORING-METHODOLOGY.md        # Methodology reference
├── QUALITY-SCORE-TRACKER.md      # Score tracker
├── QUALITY-SCORE-GUIDE.md        # Scoring guide
├── VALIDATION-GUIDE.md           # Execution playbook
├── VALIDATION-TRACKER.md         # Execution log
├── INTEGRATION-SCENARIOS.md      # Integration tests
├── INTEGRATION-TRACKER.md        # Integration results
├── WEAK-SKILL-IMPROVEMENT-PLANS.md  # Historical plans
├── README.md                     # This file
└── evidence/
    ├── quality-scores/           # Per-skill JSON score files
    │   ├── web-sqli.json
    │   ├── recon-osint.json
    │   └── ... (49 files)
    └── integration/              # Integration test evidence
```

---

## Scoring Overview

**Components** (weighted):
- SKILL.md: 15% — structural depth
- payloads.md: 30% — word count + sections + code blocks
- test-cases.md: 30% — test case count + field completeness
- guides/: 25% — guide file count

**Tiers**: Weak (0-40) | Adequate (40-60) | Strong (60-80) | Excellent (80-100)

See `SCORING-METHODOLOGY.md` for full formula details and thresholds.

---

## Workflow

1. Make skill improvements (add guides, expand payloads, add test cases)
2. Run `bash validation/SCORE.sh`
3. Review JSON output in `evidence/quality-scores/`
4. Update `QUALITY-SCORE-TRACKER.md` with new scores
5. Repeat until target tier is reached
