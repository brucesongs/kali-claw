# llm-red-team — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-09-04 | **Reviewer**: Claude (batch) | **Version**: v0.2.0.2
> **Overall Score**: **71/100 (Good)** | **Wave 6** (batch assessment, no practical validation)

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / warnings |
| 2. Content Completeness | **4** | payloads 1723 + TC 209 + 3 guides; 11 H2 |
| 3. Command Syntax | **3** | Batch assessment — tool availability varies by domain |
| 4. References | **5** | 55 URLs + 0 CVEs |
| 5. MITRE/OWASP Alignment | **1** | 0 ATT&CK T-codes |
| 6. Usability | **3** | 11 H2 + 21 H3 structure |
| **Weighted Total** | **71/100** | **Good** |

## Findings

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| F-LLMR-001 | **P1** | 0 ATT&CK T-codes | Add MITRE mapping |
| F-LLMR-003 | P3 | 0 CVEs | Add known CVEs |

## Batch Assessment Note

This is a Wave 6 batch assessment (no per-SKILL practical validation).
For full practical validation, see Wave 1/2 methodology.

## Validation Evidence

- [evidence/2026-09-04/lint.json](../evidence/2026-09-04/lint.json)
