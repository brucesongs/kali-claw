# kali-claw v0.2.5.3 版本说明 — 应用 Wave 1 Batch 2 实战 findings 🛠️

> **版本编号**：v0.2.5.3（patch release）
> **发布日期**：2026 年 8 月 17 日
> **版本类型**：批量 SKILL 内容改进（Wave 1 Batch 2 实战验证 findings）
> **上一版本**：v0.2.5.2（2026-08-16，批量应用 14 findings）
> **下一里程碑**：v0.2.6（月度审查）或 Wave 2（3 个 v0.2.3.2 剩余）

---

## 一、版本概述

v0.2.5.3 将 **Wave 1 Batch 2**（2026-08-17 实战验证）发现的 11 个 SKILL gap 应用到 5 个 SKILL 的 payloads.md。

**核心产出**：
- 5 个 SKILL payloads.md 新增内容（合计 +250 行）
- 5 个 SKILL.md last_reviewed 更新
- skill-lint 保持 0/0/139

---

## 二、11 个 findings 应用详情

### vulnerability-assessment（F-VA-001 ~ 003）

| Finding | 优先级 | 内容 | 应用 |
|---------|-------|------|------|
| F-VA-001 | **P1** | 0 ATT&CK T-codes | ✅ 新增 6 行 ATT&CK 映射表（T1046/T1595/T1592/T1087/T1613/T1580）|
| F-VA-002 | P2 | URLs 少（5 个）| ✅ 补充 8 个权威参考（NVD/CVSS/OWASP/CIS/MITRE/PTES/NIST）|
| F-VA-003 | P3 | TC 偏薄 | 记录为 backlog（不立即补）|

### patch-to-poc-pipeline（F-PP-001 ~ 002）

| Finding | 优先级 | 内容 | 应用 |
|---------|-------|------|------|
| F-PP-001 | P2 | 0 ATT&CK T-codes | ✅ 新增 5 行映射（T1068/T1203/T1190/T1059.004/T1620）|
| F-PP-002 | P3 | 缺 pwn 模板 | ✅ 补充 pwntools ret2libc + ROP + one-gadget 模板 |

### sase-sse-attack（F-SASE-001 ~ 002）

| Finding | 优先级 | 内容 | 应用 |
|---------|-------|------|------|
| F-SASE-001 | P2 | 0 CVEs | ✅ 补充 Zscaler/Netskope/Cloudflare One 共 9 个 CVE |
| F-SASE-002 | P3 | TC 偏薄 | 记录为 backlog |

### reverse-engineering-advanced（F-RE-001 ~ 002）

| Finding | 优先级 | 内容 | 应用 |
|---------|-------|------|------|
| F-RE-001 | P2 | Ghidra ListSymbols.java 缺失 | ✅ 补充内置脚本清单 + 3 种替代方案 |
| F-RE-002 | P3 | 0 CVEs | ✅ 补充 Ghidra/IDA/OpenPLC 共 5 个 CVE |

### gitops-security（F-GIT-001 ~ 002）

| Finding | 优先级 | 内容 | 应用 |
|---------|-------|------|------|
| F-GIT-001 | P3 | 缺 gitleaks | ✅ 补充 gitleaks + detect-secrets 完整命令 |
| F-GIT-002 | P3 | 缺 Kyverno/OPA | ✅ 补充 Kyverno 策略 + OPA/conftest 示例 |

### 统计

| 优先级 | 数量 | 关闭 |
|-------|------|------|
| **P1** | 1 | 1/1 ✅ |
| P2 | 4 | 4/4 ✅ |
| P3 | 6 | 4 应用 + 2 记录为 backlog |
| **合计** | **11** | **10 应用 + 2 backlog** |

---

## 三、修改文件清单

| 文件 | 改动 | 新增行 |
|------|------|-------|
| `skills/vulnerability-assessment/payloads.md` | +ATT&CK 映射 + 参考资料 | +33 |
| `skills/patch-to-poc-pipeline/payloads.md` | +ATT&CK + pwntools 模板 | +74 |
| `skills/sase-sse-attack/payloads.md` | +Zscaler/Netskope/Cloudflare CVEs | +35 |
| `skills/reverse-engineering-advanced/payloads.md` | +Ghidra 脚本 + RE CVEs | +52 |
| `skills/gitops-security/payloads.md` | +gitleaks + Kyverno/OPA | +108 |
| 5 个 SKILL.md | last_reviewed → 2026-08-17 | ±5 |
| `RELEASE-v0.2.5.3.md` | 新建 | 新增 |
| `VERSION` | 0.2.5.2 → 0.2.5.3 | ±1 |
| `CHANGELOG.md` / `UPDATELOG.md` / `MEMORY.md` / `README.md` / `CLAUDE.md` / `AGENTS.md` | 版本同步 | +40 |

---

## 四、实战 findings 累计关闭

| Patch | 来源 | 关闭数 | 累计 |
|-------|------|-------|------|
| v0.2.5.1 | ics-fieldbus-attack 验证 | 4 | 4 |
| v0.2.5.2 | 4 SKILL 批量验证 | 14 | 18 |
| **v0.2.5.3** | **Wave 1 Batch 2** | **10** | **28** |

---

## 五、版本签名

```
版本编号：v0.2.5.3
发布日期：2026-08-17
上一版本：v0.2.5.2
修改 SKILL 数：5
新增 payloads 行数：~302
P1 关闭：1/1
实战 findings 累计关闭：28
skill-lint：0/0/139
```

**kali-claw 团队**
**2026 年 8 月 17 日**
