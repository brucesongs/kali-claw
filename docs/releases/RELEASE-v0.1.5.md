# kali-claw v0.1.5 正式发布：攻击面扩展 + 安全决策增强

> 2026年5月14日发布 | 43 → 45 技能域 | 攻击自动化 + 多视角分析

---

## 核心能力升级

v0.1.5 在两个方向同时发力：**攻击面扩展**（AI Fuzzing + 移动/云安全深化）和**元能力增强**（多视角分析 + Bug Bounty 实战化）。

### 新增 2 个技能域 + 深化 3 个现有技能

**新增技能域：**
1. **`ai-fuzzing`** — AI 辅助自动化漏洞发现（AFL++, libFuzzer, Honggfuzz）
2. **`council`** — 多视角安全分析（Attack/Defense/Audit 三视角决策框架）

**深化技能：**
3. **`mobile-security`** — 跨平台框架安全（React Native, Flutter）+ 移动云集成安全
4. **`cloud-security`** — K8s 深度安全 + Serverless 安全 + IaC 审计
5. **`security-bounty-hunter`** — 补全 payloads/test-cases/guides，ECC 自动化编排

---

## 核心技能详解

### 1. ai-fuzzing：自动化漏洞发现引擎

**问题**：手工漏洞挖掘效率有限，如何系统化地发现二进制、Web API、网络协议中的未知漏洞？

**解决方案**：覆盖率引导 Fuzzing + AI 辅助种子生成 + 崩溃自动分类

- **6 阶段方法论**：目标分析 → 语料准备 → Fuzzing 执行 → 崩溃分诊 → 验证确认 → 报告生成
- **3 大 Fuzzing 领域**：二进制（AFL++）、Web API（Schemathesis/RESTler）、协议（BooFuzz）
- **ECC 编排**：Learning Cycle 迭代优化 Fuzzing 策略

### 2. council：多视角安全决策

**问题**：安全评估往往陷入单一视角盲区。

**解决方案**：三视角并行分析 + 偏见缓解 + 共识构建

- **3 种分析视角**：Attacker（漏洞优先）、Defender（加固优先）、Auditor（合规优先）
- **决策矩阵**：Impact x Likelihood 风险评分
- **ECC 编排**：Sequential Pipeline 确保各视角独立分析后再综合

### 3. mobile-security 深化

| 新增指南 | 关键内容 |
|---------|---------|
| react-native-flutter-security.md | RN JS bundle 提取、Flutter Dart snapshot 逆向、WebView 桥接利用 |
| mobile-api-security-testing.md | 高级证书固定绕过、GraphQL 移动端攻击、WebSocket 劫持 |
| mobile-cloud-integration.md | Firebase 审计、AWS Cognito 缺陷、OAuth 2.0 PKCE 绕过 |

### 4. cloud-security 深化

| 新增指南 | 关键内容 |
|---------|---------|
| kubernetes-security-deep-dive.md | RBAC 提权、Pod 安全标准、网络策略绕过、Secrets 泄露 |
| serverless-security.md | Lambda 注入、Azure Functions 攻击面、冷启动泄露 |
| infrastructure-as-code-security.md | Terraform/CFN 审计、Helm Chart 安全、CI/CD 攻击面 |

### 5. security-bounty-hunter 补强

从仅有 SKILL.md（142 行）扩展为完整技能包：

- **payloads.md** — semgrep 规则、Nuclei 模板、SQLi/SSRF/XSS/IDOR 载荷、PoC 模板
- **test-cases.md** — HackerOne 模拟、scope 验证、披露流程、报告质量
- **3 个 guides** — 方法论、负责任披露、自动化（ECC Watch Loop）

---

## ECC 编排增强

| 技能 | ECC 模式 | 编排理由 |
|------|---------|---------|
| ai-fuzzing | Learning Cycle | Fuzzing 迭代优化——覆盖率反馈驱动策略改进 |
| council | Sequential Pipeline | 多视角需独立完成后再综合 |
| mobile-security | Sequential Pipeline | 反编译→分析→Hook→验证顺序推进 |
| cloud-security | Batch Processing | 多集群/多账户并行审计 |
| security-bounty-hunter | Watch Loop + Sequential | 持续监控 + 发现→验证→报告流水线 |

---

## 技能域演进

| 版本 | 技能数 | 核心主题 |
|------|--------|---------|
| v0.1.2 | 31→37 | 基础安全域扩展 |
| v0.1.3 | 37→37 | 持续监控能力 |
| v0.1.4 | 37→43 | 代码审计→知识→报告闭环 |
| **v0.1.5** | **43→45** | **攻击自动化 + 安全决策增强** |

---

## 下一步计划（v0.1.6）

1. **Multi-Agent Collaboration** — 多代理协同渗透测试
2. **MCP Server Patterns** — 安全工具 MCP 服务器集成
3. **AI-Assisted Exploit Development** — AI 驱动的漏洞利用开发
4. **Strategic Context Management** — 长期项目的上下文压缩和优先级信息保留
