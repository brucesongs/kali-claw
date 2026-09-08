# command-injection-advanced — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-09-08 | **Reviewer**: Claude (re-assessment) | **Version**: v0.3.3
> **Overall Score**: **80/100 (Excellent)** | **Re-assessment (v0.3.3)** — TC header normalization + expansion

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / warnings |
| 2. Content Completeness | **3** | payloads 597 + TC 493 + 5 guides; 13 H2 |
| 3. Command Syntax | **3** | Batch re-assessment — tool availability varies by domain |
| 4. References | **5** | 22 URLs + 4 CVEs |
| 5. MITRE/OWASP Alignment | **4** | 5 ATT&CK T-codes |
| 6. Usability | **4** | 13 H2 + 34 H3 structure |
| **Weighted Total** | **80/100** | **Excellent** |

## Findings

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| — | — | No open findings | — |

### Closed in v0.3.3

| ID | Was | Resolution |
|----|-----|------------|
| F-COMM-004 | P3 (TC coverage thin — counting artifact, legacy headers) | ✅ Headers normalized to TC-CI-nnn + 4 new cases (blind time-based, filter evasion, argument injection, OOB) — 10 countable TCs |

## Re-assessment Note

v0.3.3: legacy 'Test Case N' headers normalized; the 0-TC finding was a
counting artifact over healthy content. Prior evidence preserved.

## Validation Evidence

- [evidence/2026-09-08/lint.json](../evidence/2026-09-08/lint.json)
