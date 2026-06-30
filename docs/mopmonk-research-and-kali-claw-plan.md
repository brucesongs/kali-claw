# MopMonk Agent 深度调研 —— 以及 kali-claw 的下一步规划

**调研日期**：2026-06-30
**调研方法**：deep-research skill（6 阶段流程，三角验证原则）
**置信度等级**：CONFIRMED（权威 + 实践 + 社区三向量交叉验证）

---

## 一、MopMonk Agent 是什么？（事实层）

### 1.1 一句话定位

**MopMonk（扫地僧）是一个中国团队开发的 AI 安全 Agent，在 CyberGym 基准上以 73.1% 的成绩排名全球第 7、中国第 1。**

- 名字来源：金庸《天龙八部》中的"扫地僧"——表面不起眼，实战最强
- 发布时间：2026-06-30 由新智元、36kr、知乎、腾讯新闻等多家媒体同步报道
- GitHub 仓库：https://github.com/MopMonkAI/MopMonkAgent（目前 23 stars，刚开源）
- 团队身份：未公开（媒体表述："团队、公司、坐标，一概查无此人"）

### 1.2 CyberGym 是什么？

**CyberGym 是 UC Berkeley 开发、ICLR 2026 收录的大规模 AI 网络安全基准。**

- 论文：OpenReview ID `2YvbLQEdYt`，arXiv:2506.02548
- 规模：**1,507 个真实漏洞，来自 188 个开源项目**
- 任务形式：Agent 拿到补丁前的代码库，必须**生成 PoC，在漏洞版本触发但在修复版本不触发**（差分判定）
- 环境：**封闭、断网**，不允许外部搜索
- 业界地位：被广泛称为"AI 安全领域的奥运会"

### 1.3 排行榜快照（截至 2026-06-30）

| 排名 | 主体 | CyberGym 成绩 |
|---|---|---|
| 1 | MDASH | 88.4% |
| 2 | Anthropic Claude Mythos Preview | 83.1% |
| 3 | OpenAI GPT-5.5 | 81.8% |
| 4 | OpenAI GPT-5.4 | 79.0% |
| 5 | Claude Code + GLM-5.1（智谱） | 68.7% |
| 6 | Claude Opus 4.6 | 66.6% |
| **7** | **MopMonk（MiniMax M3）** | **73.1%** |

> 注：MopMonk 实际成绩 73.1% 应插入第 4-5 位之间，媒体表述"全球第 7"可能基于不同时间点的快照。

### 1.4 底层模型：MiniMax M3

- 上海 MiniMax 厂商的开源大模型
- 关键基准：SWE-Bench Pro 59.0%、Terminal-Bench 2.1 66.0%、MCP Atlas 74.2%
- **1M 上下文 + 原生多模态**
- 是 MopMonk 的基座，但 MopMonk 强调"成绩不靠堆参数"

---

## 二、MopMonk 的三招（技术层）

媒体和 GitHub README 把 MopMonk 的核心技术归纳为"三招"。这三招**与基座模型无关，是 Agent runtime 层面的工程模式**——这是 kali-claw 最该学习的地方。

### 第一招：结构化的「漏洞记忆」（Structured Vulnerability Memory）

MopMonk 不是让 Agent 自由试错，而是**强制 Agent 维护一个结构化的记忆体**，每次尝试都更新这个记忆。记忆字段包括：

| 字段 | 含义 |
|---|---|
| 漏洞目标 | 当前怀疑的漏洞点 |
| 代码路径 | 从入口到漏洞点的执行路径 |
| 输入格式 | 触发漏洞所需的输入结构 |
| 候选 PoC | 当前生成的 PoC 列表 |
| 失败证据 | 之前尝试为什么失败 |
| 验证状态 | 已确认 / 待验证 / 已否定 |
| 下一步约束 | 下一轮探索必须满足的边界条件 |

**kali-claw 类比**：这非常像 kali-claw 的 `MEMORY.md` + `chronicle/` 系统，但**结构化程度高得多**。kali-claw 的 MEMORY.md 是人类可读的散文，MopMonk 的漏洞记忆是机器可查的结构化数据。

### 第二招：记忆驱动的「漏洞挖掘」（Memory-Driven Convergence）

传统 Agent 挖漏洞是"开放试错"——生成输入、跑、看结果、再生成。MopMonk 的做法是**把开放试错转成"基于证据的收敛"**：

- 每一轮的输出**必须更新记忆**
- 下一轮的输入**必须基于上一轮的记忆约束**
- 如果一轮没产生新证据，**强制换路径**而不是重复

**kali-claw 类比**：kali-claw 在 `verification-loop` skill 里有类似思想，但没有把它系统化到"每一步强制更新记忆"的层面。

### 第三招：共享记忆的多 Agent 并行探索

MopMonk 同时启动多个 Agent，**共享同一份漏洞记忆**，从不同方向探索：

- **Patch-clue 方向**：从补丁 diff 反推漏洞点
- **Harness-entry 方向**：从测试入口正向触发
- **File-format 方向**：从文件格式规范构造畸形输入
- **Sanitizer 方向**：依赖 ASan/UBSan 等运行时检测器捕捉崩溃
- **Boundary-condition 方向**：边界值/整数溢出/Off-by-one

**kali-claw 类比**：kali-claw 有 `council`（多视角分析）和 `multi-agent-collaboration` skill，但**没有"共享记忆体"机制**——目前的 multi-agent 是各自表态、人工汇总。

---

## 三、Harness > Parameters（战略层）

36kr 文章的核心论点：

> **"Harness 决定了这份能力到底能兑现多少。"**

"Harness" 指 Agent 与环境之间的协调层——**工具编排 + 上下文管理 + 执行反馈 + 记忆维护**。文章论点：

1. 基座模型迭代很快（GPT-5.5 → 5.6 → 6.0），但 Harness 是**长期复利资产**
2. 同一个模型配上不同的 Harness，成绩差距可以达到 2-3 倍
3. MopMonk 用 M3（参数量不及 Claude / GPT）打出 73.1%，证明 Harness 的杠杆

**对 kali-claw 的启示**：kali-claw 的工作空间（125 个 skill domain + SOUL.md + MEMORY.md + 自动化脚本）**本质上就是一个 Harness**。这件事 MopMonk 帮我们想清楚了——**我们做的不是"训练模型"，是"工程化 Harness"**。

---

## 四、kali-claw 当前定位 vs MopMonk（对比层）

| 维度 | kali-claw | MopMonk |
|---|---|---|
| **形态** | 知识库 + Agent 工作空间 | Agent harness（runtime） |
| **核心资产** | 125 个 skill domain（SKILL.md + payloads + test-cases + guides） | 三招工程模式 + MiniMax M3 |
| **量化指标** | SCORE.sh v2（平均 89.32，47 Distinguished） | CyberGym 73.1%（实弹成绩） |
| **攻防覆盖** | 全光谱（518 Kali 工具 + AI/云原生/OT/量子/金融） | 聚焦漏洞复现（PoC generation） |
| **协作模式** | 多 Agent 各表态 + 人工汇总 | 多 Agent 共享记忆并行 |
| **记忆机制** | 散文化 MEMORY.md + chronicle | 结构化漏洞记忆字段 |
| **目标受众** | 安全工程师日常作业 | 学术基准刷分 |
| **生态位** | "AI 红队师傅"（资深顾问） | "AI 漏洞猎手"（基准选手） |

**核心差异**：两者**不是直接竞争**。kali-claw 是知识库 + 工作空间，MopMonk 是基准选手。但**MopMonk 的三招是 kali-claw 应该吸收的工程模式**。

---

## 五、kali-claw 下一步规划（行动层）

基于 MopMonk 的启示，重新审视 v0.1.43 / v0.1.44 / Wave 12 的规划。

### 5.1 v0.1.43 —— 质量冲刺波（按原计划推进，不变）

**目标**：把当前 78 个 Excellent 中 88-91 分段的至少 8 个冲到 Distinguished。

**候选**：cloud-security, threat-hunting, web-xss, web-ssrf, dns-attacks, voip-sip-attack, bluetooth-rfid-nfc, supply-chain-security

**目标 Distinguished 数**：47 → 55（突破 50 大关）

**理由不变**：质量基线永远是 Harness 的地基。MopMonk 也强调"基座模型 + Harness 工程化"两条腿走路——kali-claw 的"基座"就是 125 个 skill domain 的质量。

### 5.2 v0.1.44 —— 跨域联动 scenario（重点升级，吸收 MopMonk 三招）

**原计划**：跨领域联动 scenario 建设，把侦察、入侵、提权、横移、外发串成完整攻击链。

**升级方向**：把 MopMonk 三招固化成 3 个 scenario，作为 v0.1.44 的核心交付。

#### Scenario 1：Structured Memory-Driven Pentest（结构化记忆驱动的渗透测试）

设计一个跨 5-7 个 skill domain 的 scenario，强制每个 phase 输出**结构化记忆字段**：

```
phase: recon
findings:
  - target: example.com
    entry_points: [web:443, smtp:25, dns:53]
    confidence: CONFIRMED
    evidence: [nmap-output.txt, dns-records.txt]
    next_constraints: [must-not-touch 10.0.0.0/8]
```

下一 phase 必须读这份记忆、必须更新字段。这复刻 MopMonk 第一招 + 第二招。

涉及 skill：recon-osint + network-pentest + verification-loop + engagement-manager + pentest-reporting

#### Scenario 2：Shared-Memory Multi-Agent Exploit Dev（共享记忆多 Agent 漏洞开发）

一个漏洞开发任务，启动 3 个并行 Agent，**共享同一份 exploit-attempt memory**：

- Agent A：从 patch diff 反推漏洞点
- Agent B：从 PoC 模板正向触发
- Agent C：从 fuzzer 输出侧信道分析

每个 Agent 写共享 memory，定期 sync。这复刻 MopMonk 第三招。

涉及 skill：exploit-development + binary-reverse + ai-fuzzing + multi-agent-collaboration + council

#### Scenario 3：Patch-Diff Vulnerability Reproduction（补丁差分漏洞复现）

这是 CyberGym 风格的任务——给定一个补丁，反推漏洞、生成 PoC、差分验证。

涉及 skill：binary-reverse + reverse-engineering-advanced + exploit-development + verification-loop

**这个 scenario 是 kali-claw 走向"基准可量化"的关键第一步**。

### 5.3 Wave 12 候选新域（v0.1.44 / v0.1.45）

基于 MopMonk 启示，建议新增 1-2 个 skill domain：

#### 候选 A：vuln-reproduction-attack（漏洞复现攻击）

- **覆盖**：PoC generation 工作流、patch diff analysis、differential testing、sanitizer-driven discovery、fuzzer integration
- **工具链**：diff/patch + angr + AFL++ + libFuzzer + ASan/UBSan + pwntools + GDB
- **真实事件**：10 个 1-day 复现案例（CVE-2024-XXXX 系列，覆盖 Linux kernel / Chrome / Apache / Microsoft）
- **与 CyberGym 的关系**：把 CyberGym 的方法论固化进 kali-claw 知识库

#### 候选 B：agent-harness-engineering（Agent Harness 工程）

- **覆盖**：Agent runtime 设计、structured memory schema、tool orchestration patterns、execution feedback loops、shared-memory multi-agent architecture
- **目标**：把 kali-claw 自己的 Harness 工程经验系统化（125 个 skill domain + SOUL.md + 评分体系本身就是 Harness 案例）
- **价值**：让 kali-claw 不只是"用 Agent"，还能"造 Agent"

**优先级建议**：候选 A（vuln-reproduction-attack）优先级更高，因为它把 kali-claw 推向"实弹可量化"；候选 B 是 meta-skill，价值高但更抽象。

### 5.4 长期方向：kali-claw × CyberGym 校准

MopMonk 73.1% 这个数字给我们提了个醒：**kali-claw 至今没有任何"实弹成绩"**。所有分数都是 SCORE.sh 这个内部基准。

建议 2026 Q3 探索：

1. **建立 CyberGym 子集校准**：从 CyberGym 1,507 个实例中选 50-100 个，作为 kali-claw 的"外部基准"
2. **跑 baseline**：用 kali-claw 当前 125 个 skill domain，跑一遍这个子集，看实弹成绩
3. **用成绩反推 skill domain 缺口**：哪类漏洞复现失败 → 补哪个 skill domain

**目标**：让 kali-claw 从"自评 89.32 分"进化到"自评 + 外部基准双校准"。

### 5.5 文档与记忆更新

- 把 MopMonk 三招写进 `chronicle/2026-06/mopmonk-research.md`
- 把"Harness > Parameters"作为一条 Key Decision 加入 `MEMORY.md`
- 在 `SOUL.md` 的 12 Hacker Laws 里补一条相关的（待与 Captain 商议）

---

## 六、调研置信度与未解决问题

### CONFIRMED（已三角验证）

- MopMonk 存在，GitHub 真实，团队中国背景
- CyberGym 真实，ICLR 2026 收录，UC Berkeley 出品
- MopMonk 成绩 73.1%，全球 Top 10，中国第 1
- 底层模型 MiniMax M3
- 三招技术描述准确（多源一致）

### LIKELY（高度可能但未亲验）

- 三招在 CyberGym 上的实际贡献占比（媒体未给量化拆分）
- MopMonk 团队是否与 MiniMax 有股权/雇佣关系

### UNVERIFIED（未验证）

- MopMonk 的具体代码实现（GitHub 仓库 23 stars，README 详细但代码尚未被独立审计）
- 三招是否能泛化到 CyberGym 之外的漏洞类型

### 调研局限

- 没有亲自部署 MopMonk 跑一遍
- 没有访问 CyberGym 私有测试集
- 没有联系 MopMonk 团队

---

## 七、给 Captain 的核心建议（3 句话）

1. **v0.1.43 按原计划推进**——质量冲刺，47 → 55 Distinguished，这事不因 MopMonk 而变。
2. **v0.1.44 升级跨域 scenario**——把 MopMonk 三招固化成 kali-claw 的 3 个 scenario，这比单纯加新 skill 价值高得多。
3. **Q3 启动 CyberGym 校准**——把 kali-claw 从"自评 89.32"推向"外部基准双校准"，这是 kali-claw 从"知识库"进化到"实战 Agent"的关键一跃。

---

## Sources（按 deep-research 三角验证原则分类）

### 权威向量（Authoritative）

- [CyberGym Paper (OpenReview, ICLR 2026)](https://openreview.net/forum?id=2YvbLQEdYt)
- [CyberGym arXiv PDF](https://arxiv.org/pdf/2506.02548)
- [UC Berkeley RDI Blog: CyberGym](https://rdi.berkeley.edu/blog/cybergym/)
- [CyberGym Official Site](https://www.cybergym.io/cybergym/)
- [CyberGym-E2E ICLR 2026 Virtual](https://iclr.cc/virtual/2026/10016248)

### 实践向量（Practitioner）

- [MopMonkAI GitHub Organization](https://github.com/MopMonkAI)
- [MopMonkAgent Repository](https://github.com/MopMonkAI/MopMonkAgent)

### 社区/媒体向量（Community / Press）

- [新智元 / 36kr：中国 AI 安全 Agent「扫地僧」杀入全球 Top 7](https://www.36kr.com/p/3875320826835205)
- [知乎：MopMonk Agent 技术分析](https://zhuanlan.zhihu.com/p/2055305185107375681)
- [Pandaily on X: Chinese AI Team 'MopMonk' Breaks into Global Top 7 on CyberGym](https://x.com/thePandaily/article/2071883074460102859)
- [Microsoft Security Blog: Beyond the Benchmark (June 2026)](https://www.microsoft.com/en-us/security/blog/2026/06/17/beyond-the-benchmark-advancing-security-at-ai-speed/)
