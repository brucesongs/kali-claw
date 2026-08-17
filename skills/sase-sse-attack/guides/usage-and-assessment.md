# sase-sse-attack — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-17 | **Reviewer**: Claude (automated + human review) | **Version**: v0.2.0.2
> **Overall Score**: **86/100 (Excellent)** | **Findings**: P2:1 P3:1
> **Wave 1 Batch 2** | Practical validation: ✅

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / 0 warnings |
| 2. Content Completeness | **5** | payloads 2424 + TC 279 + **8 guides**（最多）; 13 H2 + 23 H3 |
| 3. Command Syntax (validated) | **4** | 配置审计 + 敏感信息检测有效 |
| 4. References | **5** | **46 URLs**（Wave 1 Batch 2 最高!）; 0 CVEs |
| 5. MITRE/OWASP Alignment | **5** | 6 ATT&CK T-codes + frontmatter 完整 ✅ |
| 6. Usability | **4** | 覆盖 Zscaler ZIA/ZPA + Netskope + Cloudflare One + Umbrella |
| **Weighted Total** | **86/100** | **Excellent** |

## Usage Instructions

### What this SKILL does

See `SKILL.md` Summary + Description for full details.

### When to use it

See SKILL.md Use Cases section.

### How to start

See SKILL.md Practical Steps section.

## Practical Validation

### D3 实战验证（2026-08-17）

**ZPA connector 配置审计**：
- 检出硬编码 `provisioning_key: prov_key_AB12CD34EF56`
- 检出 `log_level: debug` 信息泄漏

✅ **SKILL 的 SASE 配置审计模式有效**


## Findings & Priorities

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| F-SASE-001 | P2 | 0 CVEs despite 46 URLs | 补充 Zscaler/Netskope 已知 CVE |
| F-SASE-002 | P3 | TC 偏薄（279 行 vs 2424 payloads） | 补 ≥10 TC |


## Validation Evidence

- [evidence/2026-08-17/lint.json](../evidence/2026-08-17/lint.json)
- Kali VM: parallels@10.211.55.5 (Kali 2026.1, aarch64)

## Reviewer Sign-off

- Reviewer: Claude (Wave 1 Batch 2)
- Approved by: _______________ Date: _______
