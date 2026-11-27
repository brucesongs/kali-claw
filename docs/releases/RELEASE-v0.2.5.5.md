# kali-claw v0.2.5.5 版本说明 — 批量补 ATT&CK 映射 🛠️

> **版本编号**：v0.2.5.5（patch release）
> **发布日期**：2026 年 8 月 19 日
> **上一版本**：v0.2.5.4（2026-08-17，Wave 2 findings）

---

## 一、版本概述

将 Wave 3 批量评估发现的 **5 个 P1 finding（0 ATT&CK T-codes）** 全部修复。为 5 个 SKILL 的 payloads.md 新增 `MITRE ATT&CK Mapping` 章节。

---

## 二、5 个 P1 修复详情

| SKILL | 新增 T-codes | 映射数量 |
|-------|-------------|---------|
| `deep-research` | T1592/T1595/T1589/T1213/T1082 | 5 行 |
| `deception-honeypot` | T1595/T1190/T1046/T1098/T1071/T1560 | 6 行 |
| `social-intelligence` | T1592.003/T1566.002/T1566.003/T1599.001/T1592.004 | 5 行 |
| `cloud-security` | T1580/T1078.004/T1530/T1552.005/T1496/T1610/T1555.006 | 7 行 |
| `ai-security` | T1592.005/T1190/T1562.001/T1557/T1195.001/T1005 | 6 行 |

每个映射表包含：ATT&CK Technique ID + 对应攻击活动 + Detection Hint（SIEM/WAF/IDS/EDR/CloudTrail）。

---

## 三、修改文件

| 文件 | 改动 |
|------|------|
| 5 个 `payloads.md` | +MITRE ATT&CK Mapping 节（合计 +35 行）|
| 5 个 `SKILL.md` | last_reviewed → 2026-08-19 |
| RELEASE / VERSION / CHANGELOG / UPDATELOG / MEMORY / README | 版本同步 |

---

## 四、实战 findings 累计关闭

| Patch | 关闭 | 累计 |
|-------|------|------|
| v0.2.5.1 ~ v0.2.5.4 | 32 | 32 |
| **v0.2.5.5** | **5** | **37** ✅ |

---

## 五、版本签名

```
版本编号：v0.2.5.5
发布日期：2026-08-19
修改 SKILL 数：5
P1 关闭：5/5（0 ATT&CK → 补映射）
实战 findings 累计：37
skill-lint：0/0/139
```
