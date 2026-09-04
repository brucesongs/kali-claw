# kali-claw v0.3.0 版本说明 — PQC 实现层攻击域 🆕

> **版本编号**：v0.3.0（minor release）
> **发布日期**：2026 年 9 月 4 日
> **版本类型**：新技能域 + 薄壳域退役
> **上一版本**：v0.2.7（2026-09-04，评估项目收尾）
> **下一里程碑**：P3 backlog 分批清偿；Q4 工具基线 2026-11

---

## 一、版本概述

v0.3.0 落地 2026-08-06 SKILL 候选评估的两个 P1 候选（各 36/75 分）：**「PQC 实施层攻击」与「Kyber 勒索软件」**，合并为 1 个新域，同时退役与其余量子技能重叠的薄壳域。技能总数 **139 不变**（+1 新建 -1 退役），所有写死 139 的引用免改。

- **新建**：`pqc-implementation-attack` — PQC **实现层**攻击（FIPS 203/ML-KEM 生态的代码缺陷面，而非协议层）
- **退役**：`quantum-cryptography-transition`（59/100 薄壳，payloads 86 行多为占位符）— 独有内容并入 `post-quantum-migration-attack`
- **顺手修复**：`docs/SKILL_INDEX.json` 陈旧问题（缺 v0.2.4 两技能、含已退役技能）→ 与目录全量对账 139/139

---

## 二、新 SKILL：`pqc-implementation-attack`

### 设计依据

探索发现 Kyber/ML-KEM **协议层**内容已充分（`quantum-crypto-attack` 80 分、`post-quantum-migration-attack` 83 分，合计提及 Kyber 100+ 次）；真缺口在**实现层**——KyberSlash 类时序泄露、单迹侧信道、故障注入、RNG 缺陷、Kyber 勒索软件分诊（2026-03 CSA 事件此前仅一行映射）。新域严格限定实现层，协议/迁移内容以交叉引用指向两个既有技能（KyberSlash 内容查重独有）。

### 产出（v0.2.4 出厂标准）

| 文件 | 规模 | 内容 |
|------|------|------|
| `SKILL.md` | ~300 行 | 指纹→缺陷映射→远程预筛→实验室利用→恢复 五阶段方法论、Defense Triple、mitre 5 T-code（T1600/T1600.001/T1110.002/T1486/T1040）|
| `payloads.md` | 424 行 / 12 章 | TLS/固件指纹、KyberSlash advisory 映射（含强制 NVD 核验门）、远程时序 harness + Welch 统计、模板/DL 单迹 SCA 全链、电压毛刺故障注入、pqm4 方法论、RNG/密钥生成缺陷、combiner 审查、勒索软件分诊 + 恢复 |
| `test-cases.md` | 5 TC（TC-PQI-001..005）| 库指纹审计 / 远程时序 / 混合降级与 combiner / 单迹 SCA 实验室（Critical）/ 勒索软件分诊 |
| `guides/kyber-ransomware-retrospective.md` | ~200 行 | 2026-03 事件复盘（家族结构、经典恢复三板斧为何失效、实战缺陷四类）+ 攻击面综述 |
| 出厂评估 | **77/100（Good）** | 无 P1/P2；2 条 P3 记 backlog（0 CVEs 为刻意策略——只引可核验编号；5 TC 为出厂标准）|

### CVE 纪律

实现层 CVE 记忆精度风险高 → payloads §2.3 内置**强制 NVD 核验门**：任何进入报告的 CVE 必须通过 NVD API 确认且受影响范围覆盖被指纹的版本；不确定的以"KyberSlash 类时序泄露"描述而不编号。

---

## 三、退役：`quantum-cryptography-transition`

| 项 | 处置 |
|----|------|
| 评分与问题 | 59/100（Poor），payloads 86 行且多为占位符（含误配的 AI 工具 garak/PyRIT），与 80/83 分的两个量子技能重叠 |
| 独有内容保留 | 组织侧迁移防御矩阵（FIPS 203/204/205 选型、HKDF-not-XOR、QKD 部署边界、侧信道防护、HNDL 优先级）+ 3 条就绪度快速检查 → `post-quantum-migration-attack/payloads.md` 新章节 "Transition Program Quick Reference" |
| 重复内容 | HNDL/混合降级/combiner/QKD → 既有 §2/§3/§4/§8 已覆盖；实现层侧信道 → 新技能 |
| 目录处置 | `git rm -r`（git 历史可找回）；SKILL_INDEX.json 双域引用（crypto/quantum）已清理 |
| 接收方 | `post-quantum-migration-attack` last_reviewed → 2026-09-04 |

---

## 四、SKILL_INDEX.json 修正（顺手）

索引此前陈旧：137 条（缺 v0.2.4 的 `ai-agent-supply-chain-attack`、`eu-ai-act-compliance-redteam`，含已退役技能）。本次以各 SKILL.md frontmatter 为权威同步：删退役、补缺失、增新域 → **139 条与目录全量对账一致**（assert 通过），metadata 更新至 v0.3.0。

---

## 五、验证

| 检查 | 结果 |
|------|------|
| skill-lint 全量 | **139/139, 0 errors / 0 warnings** |
| validate-payloads / validate-testcases（新技能单独） | 0 errors / 0 warnings |
| 翻译残留（4 个内容文件） | 0 |
| 查重 | KyberSlash 内容新技能独有；协议/迁移内容交叉引用 |
| 评估闭环 | usage-and-assessment.md = 139/139（新技能出厂自带，退役技能随目录移除）|
| SKILL_INDEX.json | 139 条 = 目录 139，双向对账通过 |

---

## 六、修改文件

| 类别 | 文件 |
|------|------|
| 新增 | `skills/pqc-implementation-attack/`（8 个文件）|
| 删除 | `skills/quantum-cryptography-transition/`（5 个文件）|
| 修改 | `skills/post-quantum-migration-attack/{payloads.md,SKILL.md}`（合并 + last_reviewed）|
| 修改 | `docs/SKILL_INDEX.json`（139 条对账）|
| 版本同步 | `VERSION` + CHANGELOG / UPDATELOG / README / AGENTS / CLAUDE / MEMORY + 本文档 |

Commits：66b985e（新 SKILL）、1d5aa6f（退役合并）、本提交（索引 + 发布）。

---

## 七、后续规划

| 优先级 | 任务 | 预估 | 触发条件 |
|-------|------|------|---------|
| P1 | P3 backlog 分批清偿（69 条；重点 4 个 Poor 技能的 0-CVE/TC 薄）| 按批 | 下次 patch 系列 |
| P2 | `pqc-implementation-attack` 出厂 3 周后稳定性复查（沿用 v0.2.4 抽样惯例）| ~30min | 2026-09 月度审查 |
| Q4 | 季度工具基线 2026-11 | ~4h | 2026-11 |
| 2027-02 | Defense Triple 半年完整性审计 | ~8h | 半年节点 |

---

## 八、版本签名

```
版本编号：v0.3.0
发布日期：2026-09-04
版本类型：minor（新域 + 退役）
上一版本：v0.2.7
SKILL 数：139（+1 pqc-implementation-attack / -1 quantum-cryptography-transition）
skill-lint：0/0/139
新 SKILL：pqc-implementation-attack（77/100 出厂评估，0 P1/P2）
退役 SKILL：quantum-cryptography-transition（59/100，并入 post-quantum-migration-attack）
SKILL_INDEX.json：139 条与目录对账一致
```

**kali-claw 团队**
**2026 年 9 月 4 日**
