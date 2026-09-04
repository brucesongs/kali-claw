# pqc-implementation-attack — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-09-05 | **Reviewer**: Claude (re-assessment) | **Version**: v0.3.1
> **Overall Score**: **77/100 (Good)** | **Re-assessment (v0.3.1)** — was 77/100 (Good) on 2026-09-04 (v0.3.0 release assessment)

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / warnings |
| 2. Content Completeness | **3** | payloads 424 + TC 224 + 2 guides; 13 H2 |
| 3. Command Syntax | **3** | Re-assessment — tool availability varies by domain |
| 4. References | **4** | 19 URLs + 0 CVEs |
| 5. MITRE/OWASP Alignment | **4** | 5 ATT&CK T-codes |
| 6. Usability | **4** | 13 H2 + 15 H3 structure |
| **Weighted Total** | **77/100** | **Good** |

## Findings

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| F-PQI2-003 | P3 | 0 CVEs | Open by policy: only NVD-verified implementation CVEs are cited (payloads.md §2.3); close when affected-range data stabilizes |

### Closed in v0.3.1

| ID | Was | Resolution |
|----|-----|------------|
| F-PQI2-004 | P3 (TC coverage thin, 5) | ✅ Expanded to 10 TCs (firmware symbol diff, dudect constant-time verification, fault-budget quantification, keygen RNG defect, cross-victim key reuse) |

## Re-assessment Note

v0.3.1 re-assessment. Prior evidence preserved at [evidence/2026-09-04/](../evidence/2026-09-04/).
Scope discipline: implementation-layer only; protocol/migration content cross-references
`quantum-crypto-attack` and `post-quantum-migration-attack` instead of duplicating.

## Validation Evidence

- [evidence/2026-09-05/lint.json](../evidence/2026-09-05/lint.json)
