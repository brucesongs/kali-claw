# kali-claw 维护节奏计划（Maintenance Cadence v1）

> **制定日期**：2026-11-19 | **背景**：v0.3.6→v0.4.0 冲刺（10 天 6 版）后的节奏校准
> **原则**：可持续 > 爆发；自动化承担例行；人/agent 时间花在只有人/agent 能做的事上

---

## 0. 工时估算校准表（基于 v0.3.6~v0.4.0 实测）

| 工作类型 | 原估 vs 实测 | 校准系数 | 原因 |
|---------|-------------|---------|------|
| 验证器/工具开发 | 估 1h / 实 3h | **×3** | 校准循环不可预见（本轮 6 轮）；含真实 bug 发现 |
| 内容重建（孪生加深）| 估 2h / 实 1.5h | ×0.75~1.5 | 依赖 NVD 核验等待与多副本修复 |
| 里程碑审查 | 估 2h / 实 1h | **×0.5** | 自动化红利（validator + handbook 各 1 条命令）|
| 机械批处理（freshness/relabel）| 估 30min / 实 15min | ×0.5 | 脚本断言式迁移 |
| 死链/突发事件响应 | — | ×2 | 网络不通需换路径验证（curl 000 → web search）|

**规则**：排期一律用"校准后估时 + 30% 缓冲"；单日计划任务总量 ≤2 项。

## 1. 日常节奏（工作日，合计 45-75min/天）

| 时段 | 事项 | 时长 |
|------|------|------|
| 启动 | SOUL/USER/memory 读取 + `git pull` + gates（lint + validator 两条命令）| 10min |
| 情报 | NVD 新 CVE 扫描（Top30 工具关键词）+ GitHub Advisories；命中→记 findings 不当场修 | 15-20min |
| 主线 | 当日周主题任务（见 §2，每天只取 1 项）| 20-40min |
| 收尾 | `memory/YYYY-MM-DD.md` 当日笔记 | 5min |

**反模式（不做）**：不每日 bump last_reviewed（阈值移动教训）；不追求每日 release；不同时开多线任务；周末不排任务（可选靶场自选）。

## 2. 周主题轮转（周一~周五）

| 日 | 主题 | 内容 | 时长 |
|----|------|------|------|
| 一 | **威胁情报吸收** | 新 CVE → 对应技能 CVE 表更新（NVD 核验门）；供应链事件分诊（Trivy 模式）| 40min |
| 二 | **工具漂移** | `check-tool-versions.py` 在线抽查 10 个轮值工具；MAJOR 跳版→开 finding | 30min |
| 三 | **内容深化（轮值）** | 从轮值池取 1 技能：当前池 = identity-provider-attack(72.3) → codebase-onboarding(75.7) → chronicle(78.2) → knowledge-ops(78.2)，之后按"最低分优先"补充 | 60min |
| 四 | **实战验证** | cybergym 1-2 题 / 本地靶场（Docker lab）；evidence 落盘——补齐全仓最大短板（live validation）| 60min |
| 五 | **质量收口** | validator `--ranking` 生成周基线 diff；修复本周 findings；周 chronicle；如有实质变更→1 个 patch release | 40min |

## 3. 月度 / 季度 / 半年

| 周期 | 事项 | 估时（校准后）| 触发 |
|------|------|--------------|------|
| 月度审查（每月第 1 个周一）| 全量三轴基线 + freshness **>80d 整批** truth-sync + 新技能稳定性复查 + backlog 清点 + patch release | **1-1.5h** | 12-07（第 5 次）、01-04、02-01… |
| 季度（3/6/9/12 月）| KALI_TOOLS_BASELINE 全量扫描 + diff + 引用兼容修复；新域候选评估（0-2 个新增/退役）| **4-5h，拆 4 个周四** | 2026-12 周（12/14-18）|
| 半年 | Defense Triple 全量完整性审计 | 8h，拆 2 周 | 2027-02 |
| 按需 | 死链 / 供应链突发事件 / CI 爆红响应 | ×2 估时 | 事件驱动 |

**发布节奏**：patch ≤1/周（仅周五收口或有安全事件时）；minor 每季度 ≤1（含新技能/结构变更）；freshness-only 变更并入月度 patch，不单独发版。

## 4. 未来 4 周具体日历（2026-11-23 ~ 12-18）

| 周 | 一 | 二 | 三 | 四 | 五 |
|----|----|----|----|----|----|
| 前置 11/21(六) | **前置**：NVD 扫描器沉淀（validation/scan-new-cves.py，/tmp 原稿已清理需重写）+ 3 关键词自测（Captain 指定周末加速）| — | — | — | — |
| 11/23 | 情报：scanner 正式首扫（--since 11-10，全 Top30）+ findings 分诊 + 命中 CVE 吸收（NVD 核验门）| 漂移：Top10 抽查 | 深化 #1：identity-provider-attack 72.3→80 | 实战：cybergym smoke 1 题 | 收口 + 周 chronicle（试运行首周）|
| 11/30 | 情报 | 漂移 | 深化 #2：codebase-onboarding 75.7→80 | 实战：cybergym 1 题 | 收口（如需 patch）|
| **12/07** | **月度审查 #5**（三轴基线 + >80d sweep + release）| 漂移 | 深化 #3：chronicle | 实战 | 收口 |
| 12/14 | 情报 | **季度基线 D1**：Top27 工具扫描 | 深化 #4：knowledge-ops | **季度基线 D2**：diff + MAJOR 影响 | **季度基线 D3**：引用修复 + 2026-12 minor release |

> 12/21 起进入 1 月循环（月度审查 01-04）；周四实战线持续——它是最接近"live pentest validation"战略目标的长线投资。

## 5. 度量与退出条件

- **节奏健康度**：周计划完成率 ≥80% 连续 4 周 → 计划可信；<50% → 下调日预算 30%
- **质量回归线**：lint 或 validator 任一非绿即当日最高优先（停止主线修复门）
- **每季度末**复盘本文件：估时系数重校准 + 轮值池刷新

---

*本文件取代零散的"下个 patch/下次审查"口头排期；变更需记 memory。*
