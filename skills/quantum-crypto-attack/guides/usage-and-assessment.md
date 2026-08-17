# quantum-crypto-attack — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-17 | **Reviewer**: Claude | **Version**: v0.2.0.2
> **Overall Score**: **80/100 (Good)** | **Findings**: P3:1
> **Wave 2** | Practical validation: ✅

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0/0 |
| 2. Content Completeness | **5** | payloads 2360 + TC 313 + 3 guides; **22 H2**（最多!） |
| 3. Command Syntax (validated) | **3** | SNDL 场景 + Grover 影响评估有效 |
| 4. References | **4** | 10 URLs + 2 CVEs |
| 5. MITRE/OWASP Alignment | **5** | **8 ATT&CK T-codes**（v0.2.5 已加 MITRE Mapping）✅ |
| 6. Usability | **4** | 22 节覆盖全面（Shor/Grover/SNDL/QKD/PQC/国密） |
| **Weighted Total** | **80/100** | **Good** |

## Practical Validation (2026-08-17)

RSA-2048 vs ML-KEM-768 密钥对比 + SNDL 场景推演 + Grover 安全性分析

## Findings & Priorities

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| F-QC-001 | P3 | 可补 Kyber 勒索软件 2026-03 案例 | 补 CSA 报告链接 |


## Validation Evidence

- [evidence/2026-08-17/lint.json](../evidence/2026-08-17/lint.json)
- Kali VM: parallels@10.211.55.5

## Reviewer Sign-off

- Reviewer: Claude (Wave 2)
- Approved by: _______________ Date: _______
