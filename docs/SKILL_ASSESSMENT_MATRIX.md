# SKILL Assessment Matrix

> **Project**: [Usage Instructions + Capability Assessment for 139 SKILLs](./SKILL_ASSESSMENT_METHODOLOGY.md)
> **Last updated**: 2026-08-17 (Wave 1 complete — Batch 1 + Batch 2)
> **Progress**: 12 / 139 SKILLs assessed (8.6%)

## Summary Statistics

| Grade | Count | SKILLs |
|-------|-------|--------|
| Distinguished (90-100) | 0 | — |
| Excellent (80-89) | 6 | embedded-rtos-security, pam-privilege-attack, patch-to-poc-pipeline, sase-sse-attack, reverse-engineering-advanced, gitops-security |
| Good (70-79) | 6 | ics-fieldbus-attack, multi-agent-runtime-engineering, hf-vhf-radio-attack, automotive-vehicle-security, blockchain-web3, vulnerability-assessment |
| Fair (60-69) | 0 | — |
| Needs Improvement (<60) | 0 | — |
| **Pending assessment** | 127 | (Wave 2-7) |

**Current average (12 SKILLs)**: 79.1/100
**Range**: 70-86
**Target**: Distinguished (90+) average after P1/P2 fixes

---

## All Assessed SKILLs

| # | SKILL | Date | D1 | D2 | D3 | D4 | D5 | D6 | **Total** | **Grade** | Findings |
|---|-------|------|----|----|----|----|----|----|-----------|-----------|----------|
| 1 | `ics-fieldbus-attack` | 2026-08-09 | 5 | 5 | 3 | 3 | 4 | 4 | **79** | Good | 1 P1 / 1 P2 / 2 P3 |
| 2 | `multi-agent-runtime-engineering` | 2026-08-09 | 5 | 5 | 3 | 2 | 4 | 4 | **77** | Good | 1 P1 / 3 P2 / 1 P3 |
| 3 | `hf-vhf-radio-attack` | 2026-08-09 | 5 | 5 | 3 | 1 | 3 | 4 | **71** | Good | 1 P1 / 2 P2 / 1 P3 |
| 4 | `embedded-rtos-security` | 2026-08-09 | 5 | 5 | 4 | 5 | 4 | 4 | **83** | Excellent | 0 P1 / 2 P2 / 2 P3 |
| 5 | `automotive-vehicle-security` | 2026-08-09 | 5 | 5 | 2 | 2 | 4 | 5 | **75** | Good | 1 P1 / 2 P2 / 1 P3 |
| 6 | `blockchain-web3` | 2026-08-09 | 5 | 5 | 2 | 4 | 1 | 4 | **70** | Good | 2 P1 / 1 P2 / 1 P3 |
| 7 | `pam-privilege-attack` | 2026-08-09 | 5 | 5 | 4 | 5 | 4 | 4 | **81** | Excellent | 0 P1 / 1 P2 / 2 P3 |
| 8 | `patch-to-poc-pipeline` | 2026-08-17 | 5 | 5 | 4 | 4 | 3 | 4 | **82** | Excellent | 0 P1 / 1 P2 / 1 P3 |
| 9 | `sase-sse-attack` | 2026-08-17 | 5 | 5 | 4 | 5 | 5 | 4 | **86** | Excellent | 0 P1 / 1 P2 / 1 P3 |
| 10 | `reverse-engineering-advanced` | 2026-08-17 | 5 | 5 | 4 | 4 | 4 | 4 | **83** | Excellent | 0 P1 / 1 P2 / 1 P3 |
| 11 | `gitops-security` | 2026-08-17 | 5 | 5 | 4 | 4 | 5 | 4 | **84** | Excellent | 0 P1 / 0 P2 / 2 P3 |
| 12 | `vulnerability-assessment` | 2026-08-17 | 5 | 5 | 4 | 3 | 2 | 4 | **76** | Good | 1 P1 / 1 P2 / 1 P3 |
| 13-139 | (pending) | — | — | — | — | — | — | — | — | — | — |

---

## Common Findings Across Wave 1 (12 SKILLs)

Recurring patterns:

- **D3 ceiling 4/5 in 7 SKILLs**: Kali 2026.1 default lacks many tools; payloads rarely include install hints. Recurs in 6/7 SKILLs.
- **D4 references weak in 4/7 SKILLs**: hf-vhf (0 URLs), automotive (3 URLs), blockchain-web3 (0 CVEs), ics-fieldbus (3 URLs). pam-privilege (24 URLs) is the benchmark.
- **D5 frontmatter mitre field under-populated in 6/7 SKILLs**: body content references more T-codes than frontmatter declares. Only multi-agent-runtime-engineering has the v0.2.5 MITRE Mapping section.
- **D6 usability consistently 4-5/5**: SKILL structure strong; the new usage-and-assessment.md guides fill the "quick-start" gap.

## Scoring Trends Observed

- **D1 Compliance**: 5/5 across all 7 (lint clean since v0.2.3)
- **D2 Content Completeness**: 5/5 across all 7 (v0.2.0.2 standard ensures rich content)
- **D3 Command Syntax**: 2-4/5 — hardware-dependent SKILLs (hf-vhf, automotive) score low; software SKILLs (embedded-rtos, pam) score higher
- **D4 References**: 1-5/5 — wide variance; theory-heavy SKILLs (hf-vhf) often lack URLs; vendor-specific (pam) have many
- **D5 Alignment**: 1-4/5 — blockchain-web3 (0 T-codes in body) is the worst; embedded-rtos (6 T-codes) is benchmark
- **D6 Usability**: 4-5/5 — structure is consistently strong

**Insight**: Pilot + Wave 1 Batch 1 (7 SKILLs) average is 76.6, below v0.2.3.2 Defense Perspective average. The 6-dim model surfaces real gaps that the 4-dim model missed (D3 tooling, D4 references, D5 frontmatter mitre). This validates the methodology.

---

## Wave Schedule

| Wave | SKILLs | Status |
|------|--------|--------|
| Pilot | 2 (ics-fieldbus, multi-agent-runtime) | ✅ Complete (2026-08-09) |
| Wave 1 Batch 1 | 5 (hf-vhf, embedded-rtos, automotive, blockchain-web3, pam-privilege) | ✅ Complete (2026-08-09) |
| Wave 1 Batch 2 | 5 (patch-to-poc, sase-sse, reverse-eng-advanced, gitops, vuln-assessment) | ✅ Complete (2026-08-17) |
| Wave 2 | 3 remaining v0.2.3.2-sampled | ⏳ Pending |
| Wave 3-7 | 124 remaining | ⏳ Pending |

Progress: 12/139 = 8.6%

See [methodology §6](./SKILL_ASSESSMENT_METHODOLOGY.md#6-wave-schedule) for full Wave breakdown.

---

## Methodology Revision Log

| Date | Change | Rationale |
|------|--------|-----------|
| 2026-08-09 | Initial methodology | Pilot baseline |
| 2026-08-09 | Wave 1 Batch 1 confirmed Pilot scoring patterns | D3/D4/D5 patterns recur; methodology holds |

**Observations from Wave 1 Batch 1 to inform Wave 1 Batch 2**:

1. D3 ceiling 4/5 for software SKILLs is consistent — install hint absence is systemic, not SKILL-specific
2. Theory-heavy SKILLs (hardware-dependent) score D3=2-3; this is expected and documented in evidence
3. D4 URL benchmark: pam-privilege (24 URLs) sets the bar; SKILLs with <5 URLs should be flagged
4. D5 frontmatter mitre under-population is now systemic (6/7) — may warrant a separate sub-dimension or batch fix in next minor
5. Effective per-SKILL time: ~10-15 min actual (Pilot estimate of 25 min was conservative)
