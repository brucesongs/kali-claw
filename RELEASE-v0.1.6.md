# kali-claw v0.1.6 正式发布：10 个基础设施技能从"理解"到"可执行"

> 2026年5月14日发布 | 45 技能域（数量不变）| 基础设施技能全面补强

---

## 核心能力升级

v0.1.6 不新增技能域，而是为 10 个仅有 SKILL.md 的基础设施技能补充操作手册，从"理解概念"升级到"可直接执行"。这些技能覆盖代理行为层（循环、验证、学习、安全）和工具层（终端操作、搜索、扫描、Docker、记录）。

### 三层补强策略

| 层级 | 技能 | 补充内容 |
|------|------|---------|
| **FULL** | `autonomous-loops`, `security-review` | payloads + test-cases + guides |
| **PARTIAL** | `repo-scan`, `terminal-ops`, `verification-loop`, `docker-patterns`, `search-first` | payloads + test-cases |
| **MINIMAL** | `continuous-learning`, `safety-guard`, `chronicle` | SKILL.md ECC Orchestration |

---

## 核心技能详解

### FULL 补强（2 个技能）

#### 1. autonomous-loops：自主循环元技能

**问题**：自主循环模式已在 SKILL.md 中定义，但缺乏具体的命令模板和操作手册。

**解决方案**：补充 Scope Lock 模板（4 种循环各一）、速率限制配置、循环命令模板、错误处理响应模板。新增指南《安全自主渗透测试》覆盖自主 vs 手动决策矩阵、Scope Lock 构建方法、循环模式组合策略。

**ECC 编排**：Meta-Skill（定义循环模式供所有技能消费）

#### 2. security-review：安全审计框架

**问题**：安全审查方法论完整，但缺乏具体的测试载荷和审计操作手册。

**解决方案**：补充秘密检测命令、注入测试载荷（SQLi/命令/LDAP/SSTI）、认证测试模式、安全头验证、依赖审计命令。新增指南《OWASP 审计方法论》覆盖审计规划、攻击面映射、优先级排序。

**ECC 编排**：Sequential Pipeline（surface map → review → evidence → report）

### PARTIAL 补强（5 个技能）

- **repo-scan** — 分类命令、库检测、安全热点 grep、秘密扫描、判定辅助 | Batch Processing
- **terminal-ops** — 侦察/利用/后渗透命令、证据捕获模式、调试排错 | Sequential Pipeline
- **verification-loop** — SQLi/XSS/认证/网络验证载荷、误报消除清单、补丁验证 | Sequential Pipeline
- **docker-patterns** — 快速启动、额外实验室配置、证据提取、清理命令 | Sequential Pipeline
- **search-first** — searchsploit/gh/msf/nuclei 搜索模板、评估评分矩阵 | Learning Cycle

### MINIMAL 补强（3 个技能）

- **continuous-learning** — 添加 Learning Cycle 消费者 Orchestration
- **safety-guard** — 添加跨切面拦截器 Orchestration
- **chronicle** — 添加 Sequential Pipeline (record → index → distill) Orchestration

---

## 技能域演进表

| 版本 | 技能数 | 新增 | 深化 | 补强 |
|------|--------|------|------|------|
| v0.1.0 | 25 | 25 | — | — |
| v0.1.1 | 31 | 6 | — | — |
| v0.1.2 | 37 | 6 | — | — |
| v0.1.3 | 37 | 2 | 2 | — |
| v0.1.4 | 43 | 6 | 1 | — |
| v0.1.5 | 45 | 2 | 3 | — |
| **v0.1.6** | **45** | **—** | **—** | **10** |

---

## 下一步计划（v0.2.0）

- 技能域实践验证（每个 FULL/PARTIAL 技能完成至少一个 test-case 实操）
- 跨技能编排集成测试（验证 ECC Pipeline 端到端流程）
- 技能质量评分系统（payloads/test-cases/guides 覆盖率指标）
- 探索新增安全技能域（AI 安全、供应链安全深度、硬件安全）
