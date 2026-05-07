# kali-claw v0.1.3 正式发布：建立持续情报运营能力

> 1 个全新技能领域 + 1 个深度增强技能，打通"社交雷达"到"情报分析台"的完整情报链

---

## 版本概览

| | |
|---|---|
| **版本号** | v0.1.3 |
| **发布日期** | 2026 年 5 月 6 日 |
| **技能领域** | 36 → 37（+1 新建，+1 深度增强） |
| **运行环境** | Kali Linux 2025-2 (ARM64) |
| **工具覆盖** | 518 Kali 安全工具（100%） |
| **开源协议** | MIT |

---

## 这一次，我们解决了什么问题？

v0.1.2 让 kali-claw 具备了质量保障、安全自动化和经验积累的能力。但在实际渗透测试中，我们发现了情报维度的缺失：

> **能研究，但不够实时、不够持续、不够社交。**

具体来说：

- 只能从权威源（NVD、MITRE、安全博客）做深度研究，**无法获取社交平台上正在发生的讨论**——员工抱怨、技术泄露、社区舆情
- deep-research 是单次快照，**无法持续监控**变化——新 CVE、代码泄露、攻击面变化
- 多源情报各自为政，**缺少系统化的关联和置信度评分**——同一 IOC 出现在 3 个源里时，无法自动识别和标记
- 研究是线性的，**缺少基于发现自动追问的迭代能力**——发现线索后无法自动深挖

v0.1.3 正是为解决这些问题而来。

---

## 两大核心升级

### 1. Social Intelligence — 全新技能域：社交平台实时情报

**一句话：把 Reddit、HackerNews、Twitter/X、YouTube 变成你的情报信息源。**

五阶段方法论：定义目标关键词 → 选择平台 → 并行检索 → 去重重排序 → 主题聚类报告。覆盖 7 大信息源类型：Reddit、HackerNews、Twitter/X、YouTube、安全论坛、paste 站点、暗网。

**典型场景：** 渗透测试前搜集目标情报——发现目标公司员工在 Reddit /r/sysadmin 上抱怨"新 VPN 经常断线"，在 HackerNews 上有人讨论该公司的技术架构，在 Glassdoor 上的差评透露安全培训走过场。这些社交信号直接映射为社工攻击向量：VPN 主题钓鱼邮件的成功率会显著高于通用钓鱼。

**完整配套：**
- `SKILL.md` — 5 阶段方法论 + 工具表 + 报告模板
- `payloads.md` — 7 大平台搜索查询模板（Reddit API、HN Algolia、X 高级搜索、yt-dlp 字幕提取等）
- `test-cases.md` — 5 个结构化测试用例
- `guides/reddit-hackernews-osint.md` — Reddit + HN 情报收集深度指南
- `guides/twitter-youtube-osint.md` — X + YouTube 情报收集深度指南
- `guides/sentiment-analysis.md` — 安全情绪分析：从员工吐槽到社工攻击向量

---

### 2. Deep Research 深度增强 — 从单次研究到持续情报运营

**一句话：研究不再是"做一次就完"，而是持续运转的情报机器。**

在原有 6 阶段方法论基础上，新增 3 个阶段和 4 个深度指南：

**Phase 7: Continuous Monitoring（持续监控）**
— 定义监控目标（CVE feed、代码仓库、paste 站点、暗网），设定轮询频率，快照 diff 对比，变化触发告警。

**Phase 8: Intelligence Correlation（情报关联）**
— 跨源 IOC 提取 → 合并去重 → 5 级置信度评分 → MITRE ATT&CK 映射 → 实体关系图（Actor ↔ Campaign ↔ Malware ↔ IOC ↔ Vulnerability）。

**Phase 9: Adaptive Refinement（迭代精化）**
— 基于报告识别知识空白 → 自动生成新子问题 → 定向搜索 → 更新报告 → 收敛检测（3 次搜索无新增信息即停止）。

**4 个新增深度指南：**
- `iterative-search-patterns.md` — 查询精化策略、来源追溯、关键词扩展、收敛检测
- `continuous-monitoring.md` — 监控架构、快照 diff 模式、告警触发条件
- `intelligence-correlation.md` — IOC 关联、置信度评分框架、ATT&CK 集成
- `mcp-integration.md` — Shodan/VirusTotal/GreyNoise/Firecrawl MCP 接入配置

---

## 情报能力全景

```
社交雷达                  情报分析台                行动
┌────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ social-         │    │ deep-research     │    │ social-          │
│ intelligence    │───→│ (9 阶段完整流程)   │───→│ engineering      │
│                │    │                  │    │                  │
│ "人们在说什么"  │    │ "事实是什么"       │    │ "如何利用情报"    │
└────────────────┘    └──────────────────┘    └──────────────────┘
     │                      │
     │   osint              │   Phase 7: 持续监控
     │   (被动收集)          │   Phase 8: 情报关联
     │                      │   Phase 9: 迭代精化
     ▼                      ▼
社交信号 + 资产情报 = 持续运转的情报引擎
```

**v0.1.0 是一个攻击技术全面的渗透测试工具库。**

**v0.1.1 是一个从侦察到报告全流程覆盖的渗透测试智能体。**

**v0.1.2 是一个做得好、做得安全的渗透测试智能体。**

**v0.1.3 是一个拥有持续情报运营能力的渗透测试智能体。**

---

## 技能协同示例

### 完整情报收集流水线

```
social-intelligence（社交雷达：发现目标讨论和泄露）
  → osint（被动收集：域名、邮件、子域）
    → deep-research Phase 1-6（深度分析：CVE、威胁情报）
      → deep-research Phase 7（持续监控：变化检测 + 告警）
        → deep-research Phase 8（情报关联：IOC + ATT&CK 映射）
          → social-engineering（利用情报：精准社工攻击）
```

### 社交情报驱动的社会工程

```
social-intelligence（发现员工在 Reddit 抱怨 VPN）
  → deep-research（研究该 VPN 产品的 CVE 和漏洞）
    → social-engineering（设计 "VPN 升级通知" 钓鱼邮件）
```

### 持续威胁监控

```
deep-research Phase 7（每日 CVE 监控 + Shodan 暴露面 diff）
  → deep-research Phase 8（新发现关联到已知威胁组织）
    → social-intelligence（监控安全社区对该威胁的讨论）
```

---

## 未来路线图

v0.1.3 之后，路线图更新为：

**第一梯队（高优先级）：** `codebase-onboarding`（快速代码库理解）、`knowledge-ops`（知识图谱管理）

**第二梯队（中优先级）：** `article-writing`（安全报告撰写）、`browser-qa`（浏览器安全测试）、`data-scraper-agent`（结构化数据提取）、`exa-search`（高级网络搜索）

**第三梯队（未来探索）：** `mcp-server-patterns`（MCP 服务器集成）、`council`（多视角分析）、`strategic-compact`（战略上下文管理）

---

## 升级指南

已有 kali-claw 工作区的用户，只需一条命令：

```bash
cd ~/.openclaw/workspace-kali-claw/
git pull origin main
```

新用户请参考 README.md 的 Quick Start 章节。

---

## 版本规划

kali-claw 采用语义化版本号 MAJOR.MINOR.PATCH：

- 每次实质性变更 PATCH +1
- PATCH 超过 1024 时，MINOR +1，PATCH 归零
- 当前版本：**0.1.3**

---

## 项目链接

- GitHub: https://github.com/brucesongs/kali-claw
- OpenClaw: https://github.com/openclaw/openclaw
- 完整变更记录: CHANGELOG.md
- 技能补充调研报告: UPDATELOG.md
- Deep Research 调研报告: memory/2026-05-05-deep-research-migration-report.md

---

*kali-claw — 由 OpenClaw Agent Framework 驱动的 AI 渗透测试智能体*
