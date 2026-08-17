# reverse-engineering-advanced — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-17 | **Reviewer**: Claude (automated + human review) | **Version**: v0.2.0.2
> **Overall Score**: **83/100 (Excellent)** | **Findings**: P2:1 P3:1
> **Wave 1 Batch 2** | Practical validation: ✅

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / 0 warnings |
| 2. Content Completeness | **5** | payloads 1624 + **TC 1198**（最多!）+ 2 guides; 17 H2 + 25 H3 |
| 3. Command Syntax (validated) | **4** | Ghidra headless 运行 + strings/readelf 提取成功 |
| 4. References | **4** | 10 URLs; 0 CVEs |
| 5. MITRE/OWASP Alignment | **4** | 4 ATT&CK T-codes + frontmatter 完整 ✅ |
| 6. Usability | **4** | 17 个 H2 节（anti-RE / 加壳 / 混淆 / 反调试 覆盖全面） |
| **Weighted Total** | **83/100** | **Excellent** |

## Usage Instructions

### What this SKILL does

See `SKILL.md` Summary + Description for full details.

### When to use it

See SKILL.md Use Cases section.

### How to start

See SKILL.md Practical Steps section.

## Practical Validation

### D3 实战验证（2026-08-17）

**目标**：VM `/usr/bin/ls`（ARM aarch64, stripped, PIE）

```bash
# Ghidra headless
/usr/share/ghidra/support/analyzeHeadless ~/re-lab Proj -import /usr/bin/ls

# 快速分析
file target_binary    # ELF 64-bit ARM aarch64, stripped
readelf -h target     # Type: DYN, Machine: AArch64
strings target | grep GLIBC  # GLIBC_2.17 到 2.38
```

✅ **SKILL 的 RE 模式有效**（Ghidra headless + strings + readelf 链路）


## Findings & Priorities

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| F-RE-001 | P2 | Ghidra headless 内置脚本 ListSymbols.java 缺失 | 文档化可用内置脚本清单 |
| F-RE-002 | P3 | 0 CVEs | 补充反混淆/脱壳相关 CVE |


## Validation Evidence

- [evidence/2026-08-17/lint.json](../evidence/2026-08-17/lint.json)
- Kali VM: parallels@10.211.55.5 (Kali 2026.1, aarch64)

## Reviewer Sign-off

- Reviewer: Claude (Wave 1 Batch 2)
- Approved by: _______________ Date: _______
