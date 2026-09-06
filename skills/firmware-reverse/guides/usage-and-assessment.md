# firmware-reverse — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-09-07 | **Reviewer**: Claude (re-assessment) | **Version**: v0.3.2
> **Overall Score**: **83/100 (Excellent)** | **Re-assessment (v0.3.2)** — 0-CVE clearance batch (was 74/100 on 2026-09-04)

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / warnings |
| 2. Content Completeness | **4** | payloads 1182 + TC 266 + 4 guides; 12 H2 |
| 3. Command Syntax | **3** | Batch re-assessment — tool availability varies by domain |
| 4. References | **5** | 36 URLs + 4 CVEs |
| 5. MITRE/OWASP Alignment | **4** | 5 ATT&CK T-codes |
| 6. Usability | **4** | 12 H2 + 10 H3 structure |
| **Weighted Total** | **83/100** | **Excellent** |

## Findings

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| F-FIRM-004 | P3 | TC coverage thin (8 test cases) | Expand to 10+ TCs in a later batch |

## Re-assessment Note

v0.3.2 batch re-assessment (0-CVE P3 clearance). CVEs, where present, were
verified one-by-one against the NVD API on 2026-09-07; skills with no applicable
CVE class have the finding closed by policy (meta/activity domain).
Prior evidence directories are preserved.

## Validation Evidence

- [evidence/2026-09-07/lint.json](../evidence/2026-09-07/lint.json)
