# ad-ldap-attack — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-09-04 | **Reviewer**: Claude (batch) | **Version**: v0.2.0.2
> **Overall Score**: **71/100 (Good)** | **Wave 4** (batch assessment, no practical validation)

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / warnings |
| 2. Content Completeness | **4** | payloads 1195 + TC 243 + 4 guides; 8 H2 |
| 3. Command Syntax | **3** | Batch assessment — tool availability varies by domain |
| 4. References | **4** | 23 URLs + 0 CVEs |
| 5. MITRE/OWASP Alignment | **2** | 2 ATT&CK T-codes |
| 6. Usability | **3** | 8 H2 + 24 H3 structure |
| **Weighted Total** | **71/100** | **Good** |

## Findings

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| F-ADLD-003 | P3 | 0 CVEs | Add known CVEs |
| F-ADLD-004 | P3 | TC coverage thin（8 test cases） | Add AAA-format test cases |

## Batch Assessment Note

This is a Wave 4 batch assessment (no per-SKILL practical validation).
For full practical validation, see Wave 1/2 methodology.

## Validation Evidence

- [evidence/2026-09-04/lint.json](../evidence/2026-09-04/lint.json)
