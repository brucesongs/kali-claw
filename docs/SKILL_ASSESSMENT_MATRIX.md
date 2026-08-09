# SKILL Assessment Matrix

> **Project**: [Usage Instructions + Capability Assessment for 139 SKILLs](./SKILL_ASSESSMENT_METHODOLOGY.md)
> **Last updated**: 2026-08-09 (Pilot complete)
> **Progress**: 2 / 139 SKILLs assessed (1.4%)

## Summary Statistics

| Grade | Count | SKILLs |
|-------|-------|--------|
| Distinguished (90-100) | 0 | — |
| Excellent (80-89) | 0 | — |
| Good (70-79) | 2 | ics-fieldbus-attack, multi-agent-runtime-engineering |
| Fair (60-69) | 0 | — |
| Needs Improvement (<60) | 0 | — |
| **Pending assessment** | 137 | (see Wave plan in methodology) |

**Current average (Pilot)**: 78/100
**Target**: Distinguished (90+) average after Wave 2 fixes

---

## All Assessed SKILLs

| # | SKILL | Date | D1 Compliance | D2 Content | D3 Syntax | D4 Refs | D5 ATT&CK | D6 Usability | **Total** | **Grade** | Findings |
|---|-------|------|---------------|-----------|-----------|---------|-----------|--------------|-----------|-----------|----------|
| 1 | `ics-fieldbus-attack` | 2026-08-09 | 5 | 5 | 3 | 3 | 4 | 4 | **79** | Good | 1 P1 / 1 P2 / 2 P3 |
| 2 | `multi-agent-runtime-engineering` | 2026-08-09 | 5 | 5 | 3 | 2 | 4 | 4 | **77** | Good | 1 P1 / 3 P2 / 1 P3 |
| 3-139 | (pending) | — | — | — | — | — | — | — | — | — | — |

---

## Common Findings Across Pilot

Both Pilot SKILLs share:

- **Missing tool install hints** (F-002 in both): Kali 2026.1 default install lacks jq / pyModbusTCP / openai SDK / anthropic SDK / cpppo / parallel. Payloads assume these exist.
- **Frontmatter mitre field too narrow** (F-003 in ics-fieldbus, F-005 in multi-agent): body content references more T-codes than frontmatter declares.

## Scoring Trends Observed in Pilot

- **D1 Compliance**: consistently 5/5 (lint clean since v0.2.3)
- **D2 Content Completeness**: consistently 5/5 (v0.2.0.2 standard ensures rich content)
- **D3 Command Syntax**: 3/5 ceiling in Pilot — common issue is missing tools; SKILLs need explicit `apt install` / `pip install` hints
- **D4 References**: 2-3/5 — most SKILLs need richer external citations
- **D5 Alignment**: 4/5 — v0.2.5 ATT&CK mapping addition helps; frontmatter mitre field is consistently too narrow
- **D6 Usability**: 4/5 — structure is strong; quick-start section (added by these guides) is the consistent gap

**Insight**: Pilot scores (77-79) are below v0.2.3.2 Defense Perspective scores (3.5-5.0) because the 6-dimension model is more comprehensive. This is **expected and valuable** — surfaces real gaps the 4-dimension model missed.

---

## Wave Schedule

| Wave | SKILLs | Status |
|------|--------|--------|
| Pilot | 2 (ics-fieldbus, multi-agent-runtime) | ✅ Complete (2026-08-09) |
| Wave 1 | 10 top-frequency attack SKILLs | ⏳ Pending |
| Wave 2 | 3 remaining v0.2.3.2-sampled SKILLs | ⏳ Pending |
| Wave 3-7 | 124 remaining SKILLs | ⏳ Pending |

See [methodology §6](./SKILL_ASSESSMENT_METHODOLOGY.md#6-wave-schedule) for full Wave breakdown.

---

## Methodology Revision Log

| Date | Change | Rationale |
|------|--------|-----------|
| 2026-08-09 | Initial methodology | Pilot baseline |
| (future) | (entries to be added after each Wave) | — |

**Pilot observations to potentially revise in methodology**:

1. D3 sample size of 10 may be too small for SKILLs with >100 commands; consider scaling to 15-20 for payloads >2000 lines
2. D4 "References" dimension could be split into "External URLs" and "Authoritative standards" (IEC 62443, NIST, MITRE) since they have different weight
3. Frontmatter mitre field is consistently under-populated; consider adding it as a separate sub-dimension of D5

These will be evaluated after Wave 1 to see if they recur.
