# multi-agent-runtime-engineering — 使用说明与能力评估

> **评估日期**：2026-08-09 | **评估者**：Claude（自动化 + 人工审查） | **评估版本**：v0.2.0.2
> **总分**：**77/100（良好）** | **问题**：P0:0 P1:1 P2:3 P3:1
> **Pilot**：新方法学下第 2 个评估的 SKILL

## 评估速览

| 维度 | 得分（1-5） | 说明 |
|------|-----------|------|
| 1. 合规性（lint） | **5** | 0 errors / 0 warnings / 0 findings（完美） |
| 2. 内容完整性 | **5** | payloads 3032 行 + test-cases 972 行；12 H2 + 28 H3；16 个代码块 |
| 3. 命令语法（Kali VM 实测） | **3** | 7/10 PASS（70%）；3 个失败均为缺工具（jq/openai/anthropic/sem）；0 broken |
| 4. 参考文献 | **2** | **SKILL.md 0 个唯一 URL**；1 个 CVE；亟需 Anthropic/LangGraph/MopMonk 等参考 |
| 5. MITRE/OWASP 对齐 | **4** | 6 个 ATT&CK T-codes（v0.2.5 新增）；frontmatter 标 "N/A — meta-skill"，body ATT&CK Mapping 章节作为合理替代 |
| 6. 可用性 | **4** | 5 层栈架构清晰；anti-pattern 目录是亮点；概念密度高（MopMonk 招一二三 可能让新手困惑） |
| **加权总分** | **77/100** | **良好** — 工程参考扎实，外部引用偏弱 |

---

## 使用说明

### 这个 SKILL 做什么（一句话）

为攻击型多智能体系统定义**运行时工程模式** — 结构化 JSON 内存 schema、内存驱动收敛规则、通过 POSIX `flock` + 原子写 + 版本向量的共享内存多智能体协调。灵感来自 MopMonk Agent（CyberGym 73.1%，中国第一），证明 harness 工程胜过基础模型参数堆砌。这是一个**元能力 SKILL** — 提供工程纪律，不是具体攻击技术。

### 何时使用（触发场景）

1. 在复杂 engagement 上编排 3+ 个 Claude/GPT/本地 LLM 智能体，需要协调底层
2. 想复现 MopMonk 式收敛（failed_attempts 记忆 → 不重复死路）
3. 自建多智能体 runtime，避免重新发明基于 POSIX 的协调
4. 跨并行智能体需要共享可变状态，且不想用数据库或消息中间件
5. 为 engagement 后回放，写 agent 决策的 write-ahead log

### 如何开始（5 步快速上手）

1. **验证 Python + jq 环境** — `python3 --version && jq --version`（jq 缺失则 `apt install jq`）
2. **定义内存 schema** — 从 `payloads.md` §1 复制 5 个规范 schema（engagement / exploit-attempt / patch-diff-repro / evidence / decision-log）
3. **启动 N 个并行智能体** — 共享内存目录（`/tmp/engagement-mem/`）；每个 agent 用 `flock + 原子写` 更新 JSON
4. **应用收敛规则** — 每个动作产生 delta 或触发 path switch；`failed_attempts_on_active_path` 阈值驱动切换
5. **engagement 后回放** — 遍历 decision-log JSONL；核对每个收敛事件与 path switch

### 新手常见坑

- **"招一二三" 术语** — MopMonk Agent 研究使用 Layer 1/2/3（结构化内存 / 收敛 / 共享协调）；SKILL 保留中文术语（扫地僧 / 招一/二/三）作为文化语境，但它们清晰映射到 Layer 1/2/3
- **POSIX flock 语义** — `flock(fd, LOCK_EX)` 阻塞；忘了解锁（`LOCK_UN`）会死锁。用 context manager
- **原子写模式** — 写临时文件 → fsync → rename；不要写目标文件后再 fsync（有竞态窗口）
- **版本向量算术** — `(child, parent)` 元组要逐元素比较；朴素 `>` 会失败
- **拓扑选择重要** — 并行探索者（parallel-explorers）适合 bug-class 覆盖；流水线（pipeline）适合阶段顺序（侦察 → 利用 → 外传）

### 交叉引用（相关 SKILL）

| 相关 SKILL | 何时切换 |
|-----------|---------|
| `multi-agent-collaboration` | 更高层协调模式（攻击阶段分解、Coordinator-Worker 等） |
| `autonomous-loops` | 自循环模式（Sequential、Watch、Batch、Learning） |
| `verification-loop` | agent 输出的六阶段验证流程 |
| `council` | 单 agent 决策的三视角分析（攻击者/防御者/审计者） |
| `continuous-learning` | 捕获 agent 运行洞察供后续使用 |
| `detection-engineering` | 防御者使用对称模式做并行威胁狩猎 |

---

## 能力评估详情

### 维度 1：合规性

- **证据**：`skill-lint.py --skill multi-agent-runtime-engineering`
- **结果**：0 errors、0 warnings、0 findings（完美合规）
- **得分**：**5/5**

### 维度 2：内容完整性

- **证据**：
  - SKILL.md：12 个 H2 节 + 28 个 H3 子节 + 16 个代码块
  - payloads.md：3032 行（语料库中最详尽）
  - test-cases.md：972 行（丰富）
  - guides/：原有 1 个 + 本文件为第 2 个
- **覆盖**：5 层 runtime stack 完整描述；anti-pattern 目录（5 个模式）；收敛状态机；拓扑选择矩阵
- **得分**：**5/5**

### 维度 3：命令语法（Kali VM 实测）

- **方法**：在 Parallels VM（Kali 2026.1）执行 10 条命令
- **通过率**：7/10 = 70%
- **分类分布**：10 full（纯软件 SKILL，无 theory-only）
- **证据文件**：[evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- **关键失败**：
  - `jq` 缺失（F-002）— JSON 操作模式的核心
  - `openai` / `anthropic` Python SDK 缺失（F-003）
  - `sem`（GNU parallel）缺失（F-004）
- **得分**：**3/5**（评分标准："70-84% 通过 或 1 个 broken" — 本次 70% 通过 + 0 broken）

### 维度 4：参考文献

- **证据**：
  - **SKILL.md 中 0 个唯一 URL** ← 严重缺口（F-001）
  - 1 个 CVE 引用
  - 中文媒体引用（36kr MopMonk 报道）嵌入 description
- **改进空间**（高价值）：补充链接到
  - Anthropic 多智能体研究博客系列
  - LangGraph 文档
  - AutoGen（Microsoft）论文
  - Magentic-One（Microsoft）论文
  - MopMonk / CyberGym 73.1% 案例研究（kali-claw 内部文档）
- **得分**：**2/5**

### 维度 5：MITRE/OWASP 对齐

- **证据**：
  - body 含 6 个 ATT&CK T-codes（v0.2.5 新增）：T1027、T1057、T1059.004、T1070.004、T1106、T1620
  - frontmatter `mitre: "N/A — meta-skill (runtime engineering, not a specific ATT&CK technique)"` 正确标注元能力性质
  - body 有 `## MITRE ATT&CK Mapping` 章节（v0.2.5 新增），含 6 行表格映射 runtime 模式到 ATT&CK 技术
- **得分**：**4/5**（v0.2.5 改进优秀；frontmatter 标注合理）

### 维度 6：可用性

- **优点**：
  - 5 层栈架构易记且有说服力
  - Anti-pattern 目录（5 个模式 + 检测规则 + 修复）独到且有价值
  - 收敛状态机有明确 schema
  - 文末交叉引用相关 SKILL
  - Skill Identity 章节前置明确元能力定位
- **不足**：
  - 概念密度高 — 新手可能被首段 "POSIX flock + 原子写 + 版本向量" 劝退
  - MopMonk 中文术语（扫地僧、招一二三）尽管 v0.2.2 加了斜体 + 英文释义，仍可能让非中文读者困惑
  - 缺一个完整 engagement 的端到端示例（只有 schema 与模式）
- **得分**：**4/5**

---

## 问题与优先级

| ID | 优先级 | 描述 | 推荐修复 |
|----|-------|------|---------|
| F-001 | **P1** | SKILL.md 0 个唯一 URL — 无外部参考 | 补充 5-10 个参考：Anthropic 多智能体研究博客、LangGraph 文档、AutoGen 论文、Magentic-One、MopMonk 案例研究、POSIX flock man 手册、JSON Schema 规范 |
| F-002 | P2 | `jq` 不在 Kali 2026.1 默认安装 | payloads.md 前置条件补 `apt install jq`（jq 是 JSON 操作模式的基础） |
| F-003 | P2 | `openai` / `anthropic` Python SDK 默认未安装 | payloads.md 前置条件补 `pip install openai anthropic` |
| F-004 | P2 | `sem`（GNU parallel）缺失 | 相关 payloads 补 `apt install parallel` |
| F-005 | P3 | frontmatter `mitre: "N/A — meta-skill"` 可补 "详见 body MITRE ATT&CK Mapping" | 更新 frontmatter mitre 字段引用 body 映射 |

**问题合计**：1 P1 + 3 P2 + 1 P3 = 5（0 P0）

---

## 验证证据

- **Kali VM 运行日志**：[evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- **Lint JSON**：[evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- **Kali VM**：parallels@10.211.55.5（Kali 2026.1，kernel 6.18.12，aarch64）
- **评估方法**：抽样 10 个 payload（按组件分层：文件系统 / Python / IPC / SDK / shell）

---

## 评估签字

- 评估者：Claude（自动化评估 + Pilot 人工审查）
- 批准人：_______________ 日期：_______
- Pilot 审查：本 SKILL 为第 2 个校准目标；确认评分标准能区分标杆（ics-fieldbus-attack 79/100）与待改进两类

---

## 参考资料

- [Anthropic Multi-Agent Research System](https://www.anthropic.com/research/multi-agent-research-system) — 博客系列（TODO：F-001）
- [LangGraph documentation](https://langchain-ai.github.io/langgraph/) — 竞品框架（TODO：F-001）
- [AutoGen paper (Microsoft)](https://arxiv.org/abs/2308.08155) — 多智能体对话（TODO：F-001）
- [MopMonk CyberGym 案例研究](../../../docs/mopmonk-research-and-kali-claw-plan.md) — kali-claw 内部
- [SKILL 评估方法学](../../../docs/SKILL_ASSESSMENT_METHODOLOGY.md) — 方法学参考
