# Phase 2 路线图 — kali-claw 持续维护 + xAgent 启动

> **规划日期**：2026-08-03  
> **时间窗口**：2026-08（1 个月快速验证）  
> **前提**：Phase 1 已完成（v0.2.1 稳定版，137 SKILLs，100% Defense Triple）

---

## 一、双线并行架构

```
Phase 2 (2026-08)
├── Track 1: kali-claw 持续维护（轻量级，~20% 精力）
│   ├── 月度 SKILL 质量审查
│   ├── 季度工具基线更新
│   ├── 按需新增 SKILL（市场驱动）
│   └── 文档/自动化维护
│
└── Track 2: xAgent 项目启动（核心，~80% 精力）
    ├── Week 1: 架构设计 + 仓库初始化
    ├── Week 2: 3 个试点 Agent 原型
    ├── Week 3: rcogo 平台集成
    └── Week 4: 多智能体协作原型 + 演示
```

---

## 二、Track 1: kali-claw 持续维护

### 2.1 维护节奏

| 周期 | 任务 | 工具 | 预估工时 |
|------|------|------|---------|
| **月度** | SKILL 质量审查 | `skill-lint.py` + `validate-payloads.py` + `validate-testcases.py` | 2h |
| **季度** | 工具版本基线更新 | 扫描 SKILL → 查询 Kali 版本 → 更新 `KALI_TOOLS_BASELINE_*.md` | 4h |
| **半年** | Defense Triple 完整性审计 | 全量 `skill-lint.py --json` + 修复 | 8h |
| **年度** | 战略评估 + 新域规划 | 市场分析 + 新 SKILL 候选评估 | 16h |

### 2.2 2026-08 维护计划

| 任务 | 内容 | 预估 |
|------|------|------|
| 月度质量审查 | `python3 validation/skill-lint.py` 全量运行；修复 warnings | 2h |
| 文档同步 | 检查 README/AGENTS/CLAUDE 与实际 SKILL 库一致性 | 1h |
| GitHub Issues 处理 | 响应社区反馈（如有） | 按需 |
| 新 SKILL 候选评估 | 评估是否需要新增 SKILL（如 AI 安全法规、EU AI Act 合规等） | 2h |

### 2.3 kali-claw 作为 xAgent 的 SKILL 依赖库

```
xAgent 项目
├── 引用 kali-claw 作为 Git Submodule 或 NPM 包
├── 按需加载 SKILL（progressive disclosure）
└── 不修改 kali-claw 仓库（保持 SKILL 库纯净性）

kali-claw 仓库
├── 保持 SKILL 库维护者定位
├── 持续维护 137 个 SKILL
└── 为 xAgent 提供"原料"
```

---

## 三、Track 2: xAgent 项目启动

### 3.1 项目定位

**xAgent** 是将 kali-claw SKILL 库转变为**可交付安全智能体**的新项目。

- **仓库**：独立新仓库（`github.com/brucesongs/xagent` 或公司内部 Git）
- **依赖**：kali-claw 作为 SKILL 依赖库
- **目标**：选择 3 个试点场景，验证"SKILL → Agent"转换可行性
- **集成**：rcogo 原生智能体平台

### 3.2 3 个试点 Agent 候选

基于 kali-claw SKILL 覆盖和市场需求，推荐以下 3 个试点：

| # | Agent 名称 | 基于 SKILL | 场景 | 价值 |
|---|-----------|-----------|------|------|
| 1 | **Web 渗透测试 Agent** | web-xss, web-sqli, web-ssrf, web-auth-bypass, api-security, command-injection-advanced | 自动化 Web 应用渗透测试：发现 → 验证 → 利用 → 报告 | 最成熟的攻击链；市场需求最大 |
| 2 | **云安全审计 Agent** | cloud-security, container-security, kubernetes-attack, cspm-casb-attack, iam-privilege-attack | 自动化云环境安全审计：配置扫描 → 权限分析 → 风险报告 | 企业云安全合规刚需 |
| 3 | **AI 安全红队 Agent** | ai-safety-redteam-advanced, llm-red-team, ai-agent-security, ai-agent-framework-attack | LLM 应用安全测试：prompt injection → jailbreak → 数据泄露 | 市场热点；技术差异化 |

### 3.3 Week-by-Week 计划

#### Week 1 (8/4 ~ 8/10): 架构设计 + 仓库初始化

| 日期 | 任务 | 产出 |
|------|------|------|
| 8/4 (Mon) | xAgent 架构设计文档 | `xagent/docs/ARCHITECTURE.md` |
| 8/5 (Tue) | 仓库初始化 + 项目脚手架 | Git 仓库 + 基础目录结构 |
| 8/6 (Wed) | kali-claw 集成方案（submodule vs clone vs package） | 集成方案决策 + 实现 |
| 8/7 (Thu) | Agent runtime 设计（SKILL 加载 + 工具调用 + LLM 对接） | `xagent/docs/RUNTIME_DESIGN.md` |
| 8/8 (Fri) | rcogo 平台调研 + 集成方案 | `xagent/docs/RCOGO_INTEGRATION.md` |
| 8/9-10 (周末) | 原型验证：最小 Agent（读取 1 个 SKILL → 调用 LLM → 输出建议） | PoC demo |

#### Week 2 (8/11 ~ 8/17): 3 个试点 Agent 原型

| 日期 | Agent | 任务 |
|------|-------|------|
| 8/11-12 | Web 渗透 Agent | 加载 web-* SKILLs；实现 recon → scan → exploit 链 |
| 8/13-14 | 云安全审计 Agent | 加载 cloud-* SKILLs；实现 AWS/Azure 配置审计 |
| 8/15-16 | AI 安全红队 Agent | 加载 ai-* SKILLs；实现 prompt injection 自动化测试 |
| 8/17 (Sun) | 3 个 Agent 集成测试 | 端到端验证 |

#### Week 3 (8/18 ~ 8/24): rcogo 平台集成

| 日期 | 任务 |
|------|------|
| 8/18-19 | rcogo Agent 注册 + 身份管理 |
| 8/20-21 | rcogo 工具调用 + SKILL 加载 |
| 8/22-23 | rcogo 多 Agent 协调（coordinator-worker 模式） |
| 8/24 | 集成测试 + Bug 修复 |

#### Week 4 (8/25 ~ 8/31): 多智能体协作 + 演示

| 日期 | 任务 |
|------|------|
| 8/25-26 | 多 Agent 协作原型（Web Agent + 云 Agent 联合测试） |
| 8/27-28 | 演示场景设计 + 文档 |
| 8/29 | 内部演示 + 反馈收集 |
| 8/30-31 | 总结 + xAgent v0.1.0 发布 |

### 3.4 xAgent 技术栈建议

```
xAgent 技术栈
├── LLM 后端
│   ├── Claude (Anthropic API / Claude Code)
│   ├── GPT-4 (OpenAI API)
│   └── 本地模型 (Ollama / vLLM)
├── Agent 框架
│   ├── 选项 A: Claude Agent SDK (Anthropic 官方)
│   ├── 选项 B: LangGraph (成熟生态)
│   ├── 选项 C: 自研轻量框架 (最小依赖)
│   └── 选项 D: rcogo 原生框架
├── SKILL 加载
│   ├── kali-claw Git submodule
│   ├── Progressive disclosure (YAML → Summary → Full)
│   └── 动态加载 (按场景按需加载)
├── 工具执行
│   ├── Bash (Kali Linux 工具)
│   ├── Docker (沙箱化工具执行)
│   └── rcogo 工具桥接
└── 输出
    ├── 结构化报告 (JSON + Markdown)
    ├── SIEM 规则生成 (Sigma / Splunk SPL)
    └── 修复建议 (带优先级)
```

### 3.5 xAgent 仓库结构（建议）

```
xagent/
├── README.md
├── docs/
│   ├── ARCHITECTURE.md          ← Agent 架构设计
│   ├── RUNTIME_DESIGN.md        ← 运行时设计
│   ├── RCOGO_INTEGRATION.md     ← rcogo 集成方案
│   └── AGENT_DESIGN.md          ← 每个 Agent 的设计文档
├── agents/
│   ├── web-pentest/             ← Web 渗透 Agent
│   │   ├── agent.yaml           ← Agent 配置
│   │   ├── skills.yaml          ← 依赖的 SKILL 列表
│   │   └── handler.py           ← Agent 逻辑
│   ├── cloud-audit/             ← 云安全审计 Agent
│   └── ai-redteam/              ← AI 安全红队 Agent
├── runtime/
│   ├── skill_loader.py          ← kali-claw SKILL 加载器
│   ├── tool_executor.py         ← 工具执行引擎
│   ├── llm_client.py            ← LLM 后端抽象
│   └── report_generator.py      ← 报告生成器
├── integrations/
│   └── rcogo/                   ← rcogo 平台适配层
├── tests/
│   └── e2e/                     ← 端到端测试
├── kali-claw/                   ← Git submodule → kali-claw 仓库
└── pyproject.toml
```

---

## 四、Phase 2 成功标志

### Track 1: kali-claw 维护

- [ ] 月度质量审查通过（skill-lint 0 errors）
- [ ] 文档与实际 SKILL 库一致
- [ ] GitHub Issues 响应 < 48h

### Track 2: xAgent 原型

- [ ] xAgent 仓库初始化完成
- [ ] kali-claw SKILL 成功加载（progressive disclosure 验证）
- [ ] 3 个试点 Agent 原型可运行
- [ ] rcogo 平台集成验证
- [ ] 多 Agent 协作演示成功
- [ ] xAgent v0.1.0 发布

### 关键指标

| 指标 | 目标 |
|------|------|
| xAgent 试点数 | 3 个 |
| SKILL 加载成功率 | >95% |
| Agent 端到端执行 | 可演示完整攻击链 |
| rcogo 集成 | Agent 可注册 + 执行 + 报告 |
| 多 Agent 协作 | 至少 2 个 Agent 协同工作 |

---

## 五、风险与对策

| 风险 | 概率 | 影响 | 对策 |
|------|------|------|------|
| rcogo 平台 API 不稳定/文档不足 | 中 | 高 | Week 1 优先调研；准备 Plan B（自研 runtime） |
| SKILL → Agent 转换复杂度超预期 | 中 | 中 | 从最简单的 SKILL 开始（如 web-xss）；渐进式 |
| LLM 成本过高 | 低 | 中 | 支持 Haiku/本地模型；按需加载减少 token |
| kali-claw 维护占用过多精力 | 低 | 低 | 自动化优先；月度审查 < 2h |
| 多 Agent 协作设计复杂 | 中 | 中 | Week 4 才开始；Week 1-3 先做好单 Agent |

---

## 六、Phase 3 预告（2026-09+）

Phase 2 验证成功后，Phase 3 方向：

1. **xAgent 开源发布**（v0.2.0）
   - LICENSE（MIT / Apache 2.0）
   - CONTRIBUTING.md
   - Issue/PR 模板
   - 社区指南

2. **kali-claw + xAgent 融合产品**
   - kali-claw 提供 SKILL 库
   - xAgent 提供智能体运行时
   - 一键部署：`docker-compose up`

3. **社区运营**
   - 微信群 / Discord
   - 技术博客
   - 会议分享（DEF CON / Black Hat / KCon）

---

## 七、立即行动项

### 本周（8/3 ~ 8/9）

```
□ 创建 xAgent 仓库
□ 编写 ARCHITECTURE.md
□ 调研 rcogo 平台 API
□ kali-claw 月度质量审查
□ 选择 Agent 框架（Claude SDK / LangGraph / 自研）
□ 最小 PoC：读取 1 个 SKILL → 调用 LLM → 输出渗透建议
```

---

**规划日期**：2026-08-03  
**执行周期**：2026-08（1 个月）  
**目标**：xAgent v0.1.0 原型验证 + kali-claw 维护体系建立
