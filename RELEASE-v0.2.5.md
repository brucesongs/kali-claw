# kali-claw v0.2.5 版本说明 — 第 1 次 v0.2.4 后月度审查 🔍

> **版本编号**：v0.2.5（patch release）
> **发布日期**：2026 年 8 月 11 日
> **版本类型**：Phase 2 Track 1 月度质量审查（A+B 范围）
> **上一版本**：v0.2.4（2026-08-10，Minor Release：3 阶段累积）
> **下一里程碑**：v0.2.6（2026-08 月度审查）

---

## 项目地址

- **GitHub 仓库**：[https://github.com/brucesongs/kali-claw](https://github.com/brucesongs/kali-claw)
- **主分支**：[main](https://github.com/brucesongs/kali-claw/tree/main)

---

## 一、版本概述

v0.2.5 是 kali-claw **第 1 次 v0.2.4 minor 后月度审查**（提前至 2026-08-09，原计划 2026-09-05）。执行范围 A（核心必做）+ B（ATT&CK 显式映射 P3 findings）。

**关键产出**：
- A.1：skill-lint 全量审查（139/139 pass，0/0 errors/warnings，与 v0.2.4 一致）
- A.2：2 个 v0.2.4 新 SKILL 使用反馈抽样（稳定，无需修改）
- A.3：GitHub Issues / PRs 检查（0 open）
- B：处理 v0.2.3.2 deferred 的 3 个 P3 ATT&CK 显式映射 findings

**实际工时**：~25min（vs 预估 3.5h，节省 88%）

---

## 二、版本亮点

### 1. 3 个 P3 ATT&CK 映射落地

为以下 3 个 SKILL 新增 `## MITRE ATT&CK Mapping` 章节：

| SKILL | 新增映射 ATT&CK 技术数 |
|-------|---------------------|
| `multi-agent-runtime-engineering` | 6（T1059.004 / T1027 / T1106 / T1057 / T1070.004 / T1620） |
| `blockchain-l2-attack` | 7（T1552 / T1068 / T1570 / T1027 / T1565.002 / T1070.004 / T1486） |
| `quantum-crypto-attack` | 7（T1040 / T1573.002 / T1557 / T1529 / T1486 / T1606 / T1620） |

每个 ATT&CK 映射表包含：技术 ID + 对应攻击向量 + 检测提示（Sigma/Falco/YARA/SIEM）。

### 2. lint 状态保持

v0.2.4 已 clean，v0.2.5 后仍 clean：
- 139/139 SKILL 通过
- 0 errors / 0 warnings
- 32 INFO finding（与 v0.2.4 一致）

### 3. GitHub 状态

- 0 open issues
- 0 open PRs
- 22 个历史 PR 全部 MERGED

---

## 三、阶段成果

### 阶段 A — 核心必做

| 任务 | 状态 | 工时 |
|------|------|------|
| A.1 skill-lint 全量审查 | ✅ 完成 | 3min |
| A.2 2 个新 SKILL 抽样（更新 last_reviewed） | ✅ 完成 | 5min |
| A.3 GitHub Issues / PRs 检查 | ✅ 完成（0 open） | 2min |
| chronicle/2026-09/skill-review-2026-08-09.md | ✅ 完成 | — |

### 阶段 B — ATT&CK 映射（v0.2.3.2 deferred）

| SKILL | 修复方式 |
|-------|---------|
| `multi-agent-runtime-engineering` | 新增 `## MITRE ATT&CK Mapping` 节（6 行表格） |
| `blockchain-l2-attack` | 新增 `## MITRE ATT&CK Mapping` 节（7 行表格）+ 注释 frontmatter TA0006 是 primary vector |
| `quantum-crypto-attack` | 新增 `## MITRE ATT&CK Mapping` 节（7 行表格）+ 包含 2026-03 Kyber ransomware 映射（T1486/T1529） |

---

## 四、关键决策

### 决策 1：审查范围 A+B

执行核心必做 + ATT&CK 映射；跳过长期监控项 C（Ghidra 12 实证 / EU AI Act implementing acts 监控 / 反馈驱动的内容补充）— 触发条件未达。

### 决策 2：提前到 2026-08-09 执行

用户在 2026-08-09 启动 v0.2.5；月度审查名义上是 9/5。提前执行不损失价值：
- v0.2.4 后状态稳定
- ATT&CK 映射 P3 不依赖时间窗口
- 下次月度审查可以提前到 9/5 或延后

### 决策 3：v0.2.5 作为 patch 版本

不 bump minor（无新 SKILL），不 bump major（无破坏性变更）。仅 patch：
- 2 个新 SKILL `last_reviewed` 字段更新
- 3 个 SKILL ATT&CK 映射补充
- chronicle + RELEASE

---

## 五、修改文件清单

| 文件 | 改动 |
|------|------|
| `skills/multi-agent-runtime-engineering/SKILL.md` | +MITRE ATT&CK Mapping 节 |
| `skills/blockchain-l2-attack/SKILL.md` | +MITRE ATT&CK Mapping 节 |
| `skills/quantum-crypto-attack/SKILL.md` | +MITRE ATT&CK Mapping 节 |
| `skills/eu-ai-act-compliance-redteam/SKILL.md` | last_reviewed 字段更新 |
| `skills/ai-agent-supply-chain-attack/SKILL.md` | last_reviewed 字段更新 |
| `chronicle/2026-09/skill-review-2026-08-09.md` | 新建月度审查记录 |
| `RELEASE-v0.2.5.md` | 新建发布说明（本文档） |
| `VERSION` | 0.2.4 → 0.2.5 |
| `CHANGELOG.md` | 追加 v0.2.5 条目 |
| `UPDATELOG.md` | 追加 v0.2.5 条目 |
| `MEMORY.md` | 追加 2026-08-09 v0.2.5 决策记录 |

---

## 六、统计对比

### 工时分解

| 阶段 | 预估 | 实际 |
|------|------|------|
| A.1 备份 + skill-lint | 30min | ~3min |
| A.2 2 个新 SKILL 抽样 | 1h | ~5min |
| A.3 Issues 检查 | 5min | ~2min |
| B ATT&CK 映射（3 个 SKILL） | 1.5h | ~10min |
| C chronicle + RELEASE + commit + push | 30min | ~5min |
| **合计** | **~3.5h** | **~25min** |

### v0.2.4 → v0.2.5 变化

| 维度 | v0.2.4 | v0.2.5 |
|------|--------|--------|
| SKILL 总数 | 139 | 139（不变） |
| skill-lint | 0/0/139 | **0/0/139** |
| ATT&CK 显式映射覆盖（P3 findings 关闭数） | 0/3 | **3/3** ✅ |
| 总 commit 数（v0.2.4 cycle） | 4 | 1（v0.2.5） |

---

## 七、风险与对策

| 风险 | 概率 | 影响 | 对策 |
|------|------|------|------|
| ATT&CK 映射技术 ID 错误 | 低 | 低 | 引用 MITRE 官方文档；下次审查时可校验 |
| 提前执行导致下次月度审查"双倍间隔"（2026-09-05 → 实际 10 月） | 低 | 低 | 在 PHASE2_ROADMAP 中已说明"提前完成可调整节奏" |
| v0.2.4 后真实使用反馈未到（仅 1 天间隔） | 中 | 低 | v0.2.6（9 月）再审查时反馈应充分 |

---

## 八、后续路线

### v0.2.6（2026-09 月度审查）

- 第 2 次月度审查
- 评估 v0.2.4 2 个新 SKILL 在 1 个月后的实际使用反馈
- 评估 ATT&CK 映射是否需要在更多 SKILL 中推广

### v0.2.7 ~ v0.2.x（2026-Q4）

- 季度工具基线 2026-11
- EU AI Act implementing acts 监控（预计 2026-Q4 发布）
- 半年 Defense Perspective 内容质量第 2 期抽样（2027-02）

### v0.3 minor（2026-Q4 ~ 2027-Q1）

- 基于 v0.2.3.3 P1 候选决定是否新增 SKILL
- 基于 v0.2.5 ATT&CK 映射反馈决定是否推广

---

## 九、验证

```bash
$ cat VERSION
0.2.5

$ python3 validation/skill-lint.py
============================================================
Total skills:    139
Passed (no ERR): 139 (100%)
Failed:          0
Total errors:    0
Total warnings:  0
============================================================
```

---

## 十、版本签名

```
版本编号：v0.2.5（patch release）
发布日期：2026-08-11
版本类型：Phase 2 Track 1 月度质量审查（A+B 范围）
项目地址：https://github.com/brucesongs/kali-claw
许可证：MIT

上一版本：v0.2.4（2026-08-10，Minor Release）
本次工时：~25min（vs 预估 3.5h，节省 88%）
新增文件：2（RELEASE-v0.2.5.md + chronicle/2026-08/skill-review-2026-08-11.md）
修改文件：~8（3 个 ATT&CK 映射 + 2 个 last_reviewed + VERSION + CHANGELOG + UPDATELOG + MEMORY）
SKILL 修改：5（3 内容增强 + 2 metadata 更新）
SKILL 总数：139（不变）
skill-lint：0 errors / 0 warnings（保持）
P3 findings 关闭：3/3 ✅
```

**kali-claw 团队**
**2026 年 8 月 11 日**
**Phase 2 Track 1 — 第 1 次 v0.2.4 后月度审查 ✅**
