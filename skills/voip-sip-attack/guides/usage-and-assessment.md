# voip-sip-attack — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-09-05 | **Reviewer**: Claude (re-assessment) | **Version**: v0.3.1
> **Overall Score**: **74/100 (Good)** | **Re-assessment (v0.3.1)** — was 56/100 (Poor) on 2026-09-04

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / warnings |
| 2. Content Completeness | **4** | payloads 913 + TC 294 + 1 guides; 8 H2 |
| 3. Command Syntax | **3** | Re-assessment — tool availability varies by domain |
| 4. References | **3** | 6 URLs + 5 CVEs |
| 5. MITRE/OWASP Alignment | **4** | 5 ATT&CK T-codes |
| 6. Usability | **3** | 8 H2 + 25 H3 structure |
| **Weighted Total** | **74/100** | **Good** |

## Findings

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| — | — | No open findings | — |

### Closed in v0.3.1

| ID | Was | Resolution |
|----|-----|------------|
| F-VOIP-003 | P3 (0 CVEs) | ✅ Added 5 NVD-verified CVEs (FreeSWITCH ×3, Kamailio ×2) — payloads §19 |
| F-VOIP-004 | P3 (TC coverage thin, 8) | ✅ Expanded to 12 TCs (TC-V009..012: toll fraud, registration hijack, BYE/CANCEL injection, SIPS/SRTP downgrade) |

## Re-assessment Note

v0.3.1 re-assessment after P3 backlog clearance. Prior evidence preserved
at [evidence/2026-09-04/](../evidence/2026-09-04/).

## Validation Evidence

- [evidence/2026-09-05/lint.json](../evidence/2026-09-05/lint.json)
