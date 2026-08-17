# dns-attacks — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-17 | **Reviewer**: Claude | **Version**: v0.2.0.2
> **Overall Score**: **72/100 (Good)** | **Findings**: **P1**:1 P2:1
> **Wave 2** | Practical validation: ✅

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0/0 |
| 2. Content Completeness | **5** | payloads 2430 + TC 148 + **8 guides**; 19 H2 |
| 3. Command Syntax (validated) | **4** | dig/nslookup/host/dnswalk/fierce 全部可用 ✅ |
| 4. References | **2** | **5 URLs; 0 CVEs**（偏少） |
| 5. MITRE/OWASP Alignment | **2** | **0 ATT&CK T-codes** ⚠️ |
| 6. Usability | **4** | 19 节覆盖全面（缓存投毒/DNSSEC/隧道/域传送） |
| **Weighted Total** | **72/100** | **Good** |

## Practical Validation (2026-08-17)

DNS 查询 + DNSSEC 检查 + 缓存投毒模式 + 子域枚举（dig/fierce 可用）

## Findings & Priorities

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| F-DNS-001 | **P1** | **0 ATT&CK T-codes** | 加 T1071.004 DNS / T1584.002 DNS Server / T1090.001 Internal Proxy |
| F-DNS-002 | P2 | URLs 少（5）+ 0 CVEs | 补 DNSFlagDay / Kaminsky CVE / BIND CVE |


## Validation Evidence

- [evidence/2026-08-17/lint.json](../evidence/2026-08-17/lint.json)
- Kali VM: parallels@10.211.55.5

## Reviewer Sign-off

- Reviewer: Claude (Wave 2)
- Approved by: _______________ Date: _______
