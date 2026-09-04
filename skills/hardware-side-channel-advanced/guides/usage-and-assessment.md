# hardware-side-channel-advanced — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-09-05 | **Reviewer**: Claude (re-assessment) | **Version**: v0.3.1
> **Overall Score**: **77/100 (Good)** | **Re-assessment (v0.3.1)** — was 59/100 (Poor) on 2026-09-04

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / warnings |
| 2. Content Completeness | **2** | payloads 313 + TC 129 + 1 guides; 13 H2 |
| 3. Command Syntax | **3** | Re-assessment — tool availability varies by domain |
| 4. References | **5** | 10 URLs + 8 CVEs |
| 5. MITRE/OWASP Alignment | **4** | 5 ATT&CK T-codes |
| 6. Usability | **4** | 13 H2 + 4 H3 structure |
| **Weighted Total** | **77/100** | **Good** |

## Findings

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| — | — | No open findings | — |

### Closed in v0.3.1

| ID | Was | Resolution |
|----|-----|------------|
| F-HARDW-003 | P3 (0 CVEs) | ✅ Added 8 NVD-verified CVEs (Spectre ×2, Meltdown, MDS ×3, Plundervolt, LVI) — payloads §9 |
| F-HARDW-004 | P3 (TC coverage thin, 5) | ✅ Expanded to 10 TCs (CPA full recovery, template attack, cross-VM Flush+Reload, enclave undervolt fault, DFA) |
| — | content debt | ✅ Payloads 86 → 313 lines: placeholder garbage removed; added SPA/template workflows, RSA CRT timing, EM near-field methodology, Prime+Probe/Flush+Reload code, Meltdown/MDS/LVI/SGX primitives, DFA + Rowhammer, countermeasure assessment, detection engineering; ATT&CK mapping expanded 1 → 5 T-codes |

## Re-assessment Note

v0.3.1 re-assessment after P3 clearance + payload expansion. Prior evidence
preserved at [evidence/2026-09-04/](../evidence/2026-09-04/).
Domain boundary: lattice/PQC single-trace SCA lives in `pqc-implementation-attack`.

## Validation Evidence

- [evidence/2026-09-05/lint.json](../evidence/2026-09-05/lint.json)
