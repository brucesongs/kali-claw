# kali-claw v0.3.5 版本说明 — 全量 SKILL 验证与完整性排序 🏅

> **版本编号**：v0.3.5（patch release）
> **发布日期**：2026 年 9 月 9 日
> **版本类型**：可用性/可靠性验证 + 机械性修复 + 排名报告
> **上一版本**：v0.3.4（2026-09-09，Q4 工具基线提前）
> **下一里程碑**：第 4 次月度审查（2026-10-05，零 backlog 首查 + pqi 稳定性复查）

---

## 一、版本概述

对全部 139 个 SKILL 执行三轴验证（完整性六维分 / 可用性 / 可靠性）并按完整性排名，验证中发现的机械性问题当场清零，产出排名报告 `docs/SKILL_VALIDATION_RANKING_2026-09-09.md`。

## 二、验证结论

| 轴 | 结论 |
|----|------|
| **完整性（主排序）** | 均分 **81.1**，区间 65-92：Excellent 57 / Good 76 / Fair 6，无 Poor；Top 3：5g-telecom-attack 92、quantum-crypto-attack 92、ad-cs-abuse 89 |
| **可用性** | A 105 / B 6 / C 28（B/C 为结构性缺口——豁免 meta 的 TC 策略保留 + 少量 H2 偏薄）；**命令健康度全绿：bash 语法错误块 102 → 0** |
| **可靠性** | A 131 / B 4（认证门引用）/ **C 4（真死链）**；审查新鲜度全员 ≤2 天（truth-sync 红利）；过时模式 6 → 0 |

## 三、机械性修复（验证驱动，全部清零）

| 类 | 数量 | 处置 |
|----|------|------|
| bash 语法错误块 | 102 → **0** | 围栏错标 ~47（text/PowerShell/Python/SPL/PromQL/JavaScript 归位）、会话转录注释 ~60（(gdb)/msf6>/meterpreter> 等）、真实 shell 缺陷 ~15（混合引号、jq 漏引号、printf 拼接、awk 嵌套、未引用括号等）、嵌套围栏渲染缺陷 1（~~~ 波浪围栏）|
| 占位桩 | 3 → **0** | DLP-bypass / edge-computing-security / identity-provider-attack 的 "Additional Payloads" 垃圾段替换为域内容 |
| 过时模式 | 6 → **0** | docker-compose 命令 ×2、Frida pre-17 API ×3、hashcat -O、旧版本字符串 |

## 四、URL 活性抽查（Top 30 × 公网链接，55 个）

存活 22 / 认证门或反爬 8（服务存活）/ **真死链 5**（osmocom 双仓库迁移、Hermez trusted-setup 仓库消失、mbedcloud 服务 EOL ×2、bluepill 页面失联）——分布在 4 个技能，按计划仅入报告（R3-1，~15 min 修复量，下个 patch 顺手）。

## 五、产出物

| 文件 | 内容 |
|------|------|
| `docs/SKILL_VALIDATION_RANKING_2026-09-09.md` | 240 行：方法论 / 统计 / Top 20 / Bottom 10 / **全 139 排名表**（六维分 + 双等级 + CVE 年份 + 结构指标）/ findings register / 建议行动 |
| 33 个技能的 payloads/guides/SKILL/test-cases 修复 | 见第三节 |
| `/tmp/validate-all.py` | 验证器（占位符感知的 bash -n、词边界 TODO、检测器上下文排除）——建议后续沉淀进 `validation/` |

## 六、验证

| 检查 | 结果 |
|------|------|
| skill-lint | 139/139, 0/0 |
| validate-payloads / validate-testcases | 0 errors |
| bash 语法错误块 / 占位 / 过时模式 | 0 / 0 / 0 |
| 抽查（会话注释、围栏语言、引号修复）复核 | 通过 |

Commits：6cb75a3（机械修复）/ 6627603（排名报告）/ 本提交（release）。

## 七、后续规划

| 优先级 | 任务 | 预估 | 触发条件 |
|-------|------|------|---------|
| P1 | 第 4 次月度审查 + pqi 3 周稳定性复查（引用本报告作基线）| ≤2h | 2026-10-05 |
| P2 | 死链修整（4 技能 5 链接）+ Bottom 技术孪生加深（DLP-bypass / edge-security）| ~2h | 下个 patch |
| P3 | 验证器沉淀进 validation/（check-skill-usability.py）+ 白名单扩充 | ~1h | 下次月度审查前 |

## 八、版本签名

```
版本编号：v0.3.5
发布日期：2026-09-09
版本类型：全量验证 + 排名 + 机械清零
上一版本：v0.3.4
skill-lint：0/0/139（保持）
验证范围：139/139 技能，三轴
修复：语法 102→0、占位 3→0、过时 6→0
排名：均分 81.1（65-92），无 Poor；报告 docs/SKILL_VALIDATION_RANKING_2026-09-09.md
```

**kali-claw 团队**
**2026 年 9 月 9 日**
