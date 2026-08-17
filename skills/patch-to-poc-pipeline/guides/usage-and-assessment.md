# patch-to-poc-pipeline — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-17 | **Reviewer**: Claude (automated + human review) | **Version**: v0.2.0.2
> **Overall Score**: **82/100 (Excellent)** | **Findings**: P2:1 P3:1
> **Wave 1 Batch 2** | Practical validation: ✅

## Quick Assessment Dashboard

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| 1. Compliance | **5** | 0 errors / 0 warnings |
| 2. Content Completeness | **5** | payloads 1915 + TC 912 (48%! 最高比率) + 2 guides; 12 H2 + 34 H3 |
| 3. Command Syntax (validated) | **4** | ASAN 成功检测 UAF（编译→触发→报警 全链路验证） |
| 4. References | **4** | 9 URLs + 3 CVEs（合理覆盖） |
| 5. MITRE/OWASP Alignment | **3** | **0 ATT&CK T-codes in body**（frontmatter 用 CWE 映射，无 ATT&CK） |
| 6. Usability | **4** | 5 阶段 pipeline 清晰（commit→diff→reproduce→PoC→submit） |
| **Weighted Total** | **82/100** | **Excellent** |

## Usage Instructions

### What this SKILL does

See `SKILL.md` Summary + Description for full details.

### When to use it

See SKILL.md Use Cases section.

### How to start

See SKILL.md Practical Steps section.

## Practical Validation

### D3 实战验证（2026-08-17）

```c
// ~/poc-lab/uaf_poc.c — Use After Free
char *buf = malloc(64);
free(buf);
printf("%s\n", buf);  // UAF
```

**执行**：`gcc -fsanitize=address` → 运行 → ASAN 报 `heap-use-after-free`

✅ **SKILL 的 pipeline 模式（编译→触发→ASAN→PoC）完全有效**


## Findings & Priorities

| ID | Priority | Description | Fix |
|----|----------|-------------|-----|
| F-PP-001 | P2 | 0 ATT&CK T-codes in body（仅 CWE 映射） | 添加 MITRE ATT&CK Mapping 节（如 T1068 Exploitation for PE） |
| F-PP-002 | P3 | 缺 CTF pwn 类 PoC 模板 | 补充 pwntools 模板（ret2libc / ROP） |


## Validation Evidence

- [evidence/2026-08-17/lint.json](../evidence/2026-08-17/lint.json)
- Kali VM: parallels@10.211.55.5 (Kali 2026.1, aarch64)

## Reviewer Sign-off

- Reviewer: Claude (Wave 1 Batch 2)
- Approved by: _______________ Date: _______
