# threat-hunting — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-09-07 | **Reviewer**: Claude (re-assessment) | **Version**: v0.3.2
> **Overall Score**: **86/100 (Excellent)** | **Re-assessment (v0.3.2)** — 0-CVE clearance batch (was 86/100 on 2026-09-04)

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / warnings |
| 2. Content Completeness | **4** | payloads 1175 + TC 253 + 3 guides; 19 H2 |
| 3. Command Syntax | **3** | Batch re-assessment — tool availability varies by domain |
| 4. References | **5** | 31 URLs + 0 CVEs |
| 5. MITRE/OWASP Alignment | **5** | 46 ATT&CK T-codes |
| 6. Usability | **4** | 19 H2 + 21 H3 structure |
| **Weighted Total** | **86/100** | **Excellent** |

## Findings

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| F-THRE-003 | P3 (closed by policy) | 0 CVEs — no applicable CVE class for this meta/activity domain | N/A |

## Re-assessment Note

v0.3.2 batch re-assessment (0-CVE P3 clearance). CVEs, where present, were
verified one-by-one against the NVD API on 2026-09-07; skills with no applicable
CVE class have the finding closed by policy (meta/activity domain).
Prior evidence directories are preserved.

## Validation Evidence

- [evidence/2026-09-07/lint.json](../evidence/2026-09-07/lint.json)
