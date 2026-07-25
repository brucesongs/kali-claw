# kali-claw v0.2.0.5 版本说明

> **版本编号**：v0.2.0.5  
> **发布日期**：2026 年 7 月 26 日  
> **版本类型**：质量升级版本（Phase 2 启动 + 文档基线对齐）  
> **上一版本**：v0.2.0.4（2026-07-24）  
> **下一里程碑**：v0.2.0.6（Task 1.3 完成 + Phase 2 Batch 3-5）

---

## 项目地址

- **GitHub 仓库**：[https://github.com/brucesongs/kali-claw](https://github.com/brucesongs/kali-claw)
- **主分支**：[main](https://github.com/brucesongs/kali-claw/tree/main)
- **版本标签**：待发布（v0.2.0.5 release tag）
- **问题反馈**：[GitHub Issues](https://github.com/brucesongs/kali-claw/issues)
- **讨论区**：[GitHub Discussions](https://github.com/brucesongs/kali-claw/discussions)

---

## 一、版本概述

kali-claw 是基于 OpenClaw 框架构建的 AI 渗透测试智能体工作空间，覆盖 **130 个安全技能域**，掌握 Kali Linux 2025-2 全部 518 款安全工具。本仓库作为智能体的结构化知识库与配置系统，配套自动化脚本完成校验、编排与报告工作。

v0.2.0.5 是 kali-claw **Phase 1 SKILL 库完善项目**的第五个迭代版本。本次发布聚焦于两件事：

1. **Phase 2 标准化启动**：完成 Batch 1-2 共 20 个非高优先级 SKILL 的标准化升级
2. **文档基线对齐**：将仓库根目录全部核心文档（README、AGENTS、CLAUDE、CHANGELOG、10 个 GUIDE、IDENTITY、MEMORY、UPDATELOG、VERSION、HEARTBEAT、TOOLS、USER）统一对齐到 v0.2.0.4 现状

截至本版本发布，Phase 1 累计完成 **35/130 个 SKILL**（27%）的深度质量升级，覆盖网络安全、Web 安全、后渗透、凭证攻击、社会工程、OSINT、云安全、容器安全、二进制逆向、漏洞利用开发、5G 通信、汽车安全、区块链等核心攻击域。

---

## 二、版本亮点

### 1. Phase 2 标准化启动（20 个 SKILL 完成）

按 `PHASE2_PROGRESS.md` 与 `SKILL_REMEDIATION_LIST.json` 规划，完成 Batch 1-2 共 20 个 SKILL 的标准化升级。

#### Batch 1（10 个）

5g-telecom-attack、ad-cs-abuse、ad-ldap-attack、agentic-pentest、ai-agent-framework-attack、ai-agent-security、ai-fuzzing、ai-security、anti-forensics、automotive-vehicle-security

#### Batch 2（10 个）

autonomous-loops、av-edr-evasion、blockchain-l2-attack、blockchain-web3、bluetooth-rfid-nfc、browser-qa、chronicle、ci-cd-supply-chain-attack、cloud-identity-attack、cloud-native-vuln-research

每个 SKILL 均完成：

- 添加 `## Detection Methods` 章节（含 Sigma/Splunk SPL/Sysmon/Falco 检测规则）
- 添加 `## Defense Evasion Techniques` 章节（现代攻击规避技术）
- 版本升级至 `v0.2.0.2`
- 添加 `last_reviewed: 2026-07-26` 元数据
- 翻译残留全部清零

### 2. 仓库瘦身（3.7 GB → 19 MB）

清理历史遗留的 CyberGym 评估 evidence 大文件：

- **清理前**：`.git/` 目录 3.7 GB（最大单文件 594 MB 的 `repo-vul.tar.gz`）
- **清理后**：`.git/` 目录 19 MB（减少 99.5%）
- **保留**：所有有价值的代码与文档（3 个 v0.1.47 SKILL + validation 脚本 + RELEASE 文档）
- **强化**：`.gitignore` 添加规则，阻止 `validation/evidence/cybergym/**/repo-vul.tar.gz` 等大文件再次进入仓库

### 3. 文档基线全面对齐 v0.2.0.4

完成仓库根目录全部核心文档的现代化更新：

| 文档类别 | 文档列表 | 更新内容 |
|---------|---------|---------|
| 入口文档 | README.md | 111 → 130 SKILL；v0.2.0.4 徽章；Defense Triple；新版 Roadmap；Release Documents 索引表 |
| Agent 配置 | AGENTS.md | v0.2.0.4 徽章；130 SKILL；Defense Triple Standard 章节 |
| 开发指南 | CLAUDE.md | 130 domains；Phase 1 Project Artifacts 表；Phase 1 Workflow 章节；SOCKS5 代理说明 |
| 变更日志 | CHANGELOG.md | 新增 v0.2.0.1-v0.2.0.4 详细条目（含质量指标对比） |
| 平台指南 | 10 个 GUIDE-*.md | 全部添加 Update Notice；版本/技能数引用同步到 130 |
| 身份记忆 | IDENTITY.md, MEMORY.md | 时间戳/Current Status 更新；新增 5 个 v0.2.0.x 决策条目 |
| 历史日志 | UPDATELOG.md | 顶部追加 v0.2.0.4 + v0.2.0.5 条目（历史 v0.1.x 保留） |
| 工作记忆 | HEARTBEAT.md, TOOLS.md, USER.md | SKILL 数引用同步：127/111/49 → 130 |
| 版本基线 | VERSION | `0.1.39` → `0.2.0.4` |

### 4. 推送策略经验沉淀

发现并解决了 v0.1.x 时代 evidence 大文件阻塞推送的问题：

- **问题**：直接推送 `phase1/skill-audit` 分支时，packfile 达到 **3.9 GB**（含 24 个 commits + evidence tarballs）
- **失败现象**：通过 SOCKS5 代理反复推送均超时（HTTP 408）
- **解决方案**：创建轻量分支 `phase1-lightweight`，仅 cherry-pick Phase 1 commits（基于 `origin/main`），packfile 缩小到 **157 KB**（减少 24,849 倍）
- **结果**：首次 push 即成功，通过 PR 合并到 main
- **沉淀**：详见 RELEASE-v0.2.0.4.md 附录（推送策略案例研究）

---

## 三、详细更新内容

### 1. Phase 2 Batch 1 SKILLs 详解

#### 5g-telecom-attack（5G 通信攻击）

- **Detection Methods**：5G Core (SBA)、RAN（IMSI Catcher、Rogue gNodeB）、Core Network Behavioral、SIEM/Probe Detection
- **Defense Evasion**：IMSI Catcher Stealth（5G Stingray 改进）、Signaling Attack Stealth、Network Slice Exploitation、CPE/UE Side Channel

#### ad-cs-abuse（Active Directory Certificate Services 滥用）

- **Detection Methods**：ADCS 特定 Event IDs（4886/4887/4885/5136/4662/4768）、Behavioral Indicators（ESC1-8 patterns）、SIEM Rules
- **Defense Evasion**：Template Modification Stealth、PKINIT Stealth、ESC8 NTLM Relay Stealth
- **保留**：原有 Anti-Forensics and OPSEC Considerations 章节

#### ad-ldap-attack（Active Directory / LDAP 攻击）

- **Detection Methods**：Domain Controller Audit Events（1644/2887/2889/4662/4768/4769/4624/7045）、Behavioral Indicators、SIEM Rules
- **Defense Evasion**：LDAP Enumeration Stealth、Kerberoasting Stealth、DCSync Stealth、Lateral Movement Stealth

#### agentic-pentest（自治渗透测试）

- **Detection Methods**：Agentic/LLM Activity、Process/Endpoint、SIEM Rules
- **Defense Evasion**：Prompt Injection Stealth、Tool Call Stealth、Memory/State Exploitation、Identity/Auth Abuse

#### ai-agent-framework-attack（AI Agent 框架攻击）

- **Detection Methods**：LLM Gateway/Proxy、Behavioral、SIEM Rules
- **Defense Evasion**：Prompt Injection Stealth、Tool Call Stealth、Memory/State Exploitation、Side-Channel Exfiltration

#### ai-agent-security（AI Agent 安全）

- **Detection Methods**：MCP/Tool Abuse、Sandbox/Runtime、Multi-Agent Communication、SIEM Rules
- **Defense Evasion**：Prompt Injection Stealth、Tool Poisoning Stealth、Sandbox Escape Stealth、Multi-Agent Hijack Stealth

#### ai-fuzzing（AI 辅助模糊测试）

- **Detection Methods**：Fuzzer Process Detection、Target Application Indicators、SIEM Rules
- **Defense Evasion**：Fuzzer Obfuscation、Coverage Stealth、Crash Artifact Cleanup

#### ai-security（AI 安全）

- **Detection Methods**：LLM Inference、Training Pipeline、RAG/Vector Store、SIEM Rules
- **保留**：原有 Defense Evasion Techniques 章节

#### anti-forensics（反取证）

- **Detection Methods**：Filesystem-Level、Log Tampering、Memory Forensics、SIEM Rules
- **Defense Evasion**：Sophisticated Timestamp Manipulation、Log Cleaning Beyond Simple Clearing、Hidden Storage、Memory-Resident Evasion、Anti-Memory Forensics

#### automotive-vehicle-security（汽车车辆安全）

- **Detection Methods**：CAN Bus Anomaly、UDS Diagnostic、Key Fob/RF、GNSS/Positioning、SIEM
- **Defense Evasion**：CAN Injection Stealth、Diagnostic Session Stealth、Key Fob Attack Stealth、GNSS Spoofing Stealth、EV Charging Stealth

### 2. Phase 2 Batch 2 SKILLs 详解

#### autonomous-loops（自治循环）

- **Detection Methods**：Autonomous Loop Indicators、SIEM Rules
- **Defense Evasion**：Loop Stealth、Self-Modification Stealth

#### av-edr-evasion（AV/EDR 规避）

- **Detection Methods**：AV/EDR Telemetry、Behavioral、SIEM Rules
- **Defense Evasion**：AMSI/ETW Bypass、Direct Syscalls、Process Injection Stealth、Driver/Kernel Bypass、EDR Splitting、Memory-Only Operations

#### blockchain-l2-attack（区块链 L2 攻击）

- **Detection Methods**：L2 Bridge/Sequencer、Smart Contract Audit、SIEM Rules
- **Defense Evasion**：Bridge Exploitation Stealth、Sequencer Exploitation Stealth、Smart Contract Stealth

#### blockchain-web3（Web3 / 智能合约）

- **Detection Methods**：Smart Contract Audit、On-Chain Anomaly、SIEM Rules
- **Defense Evasion**：Smart Contract Exploit Stealth、On-Chain Laundering、MEV/Front-Running Stealth

#### bluetooth-rfid-nfc（蓝牙/RFID/NFC）

- **保留**：原有 Detection Methods 章节
- **新增 Defense Evasion**：Bluetooth Stealth、RFID/NFC Stealth、Relay Attack Stealth、Rolling Code Exploitation Stealth、Wireless Covert Channels

#### browser-qa（浏览器自动化测试）

- **Detection Methods**：Browser Automation Detection、SIEM Rules
- **Defense Evasion**：Stealth Automation、Fingerprint Mimicry、Proxy/Network Stealth

#### chronicle（Google Chronicle SIEM）

- **Detection Methods**：Chronicle SIEM Native Detections、Common Rule Categories、YARA-L 示例
- **Defense Evasion**：Bypassing Chronicle Ingestion、Rule Bypass

#### ci-cd-supply-chain-attack（CI/CD 供应链攻击）

- **Detection Methods**：CI/CD Pipeline、Dependency Supply Chain、SIEM Rules
- **Defense Evasion**：CI/CD Compromise Stealth、Dependency Confusion Stealth、Build Artifact Stealth、Source Code Stealth、SBOM Evasion

#### cloud-identity-attack（云身份攻击）

- **Detection Methods**：Identity Provider Audit Logs、Behavioral Anomalies、Conditional Access Policy Bypass、SIEM Rules
- **Defense Evasion**：Identity Evasion、MFA Bypass、Conditional Access Bypass、Token Theft Stealth、Cloud Persistence Stealth

#### cloud-native-vuln-research（云原生漏洞研究）

- **Detection Methods**：Vulnerability Research Detection、Runtime Vulnerability、Common Vulnerable Component Categories、SIEM Rules
- **Defense Evasion**：Vulnerability Research Stealth、Exploit Stealth、Reporting Stealth、Defensive Counter-Perspective

---

## 四、Phase 1 累计成果

### 完整 SKILL 升级清单（35 个）

#### Phase 1 P0/P1（15 个，v0.2.0.2 全部完成）

P0 核心域：network-pentest、post-exploitation、web-xss  
P1 重要域：web-sqli、web-ssrf、web-auth-bypass、api-security、password-attack、privilege-escalation、social-engineering、osint、cloud-security、container-security、binary-reverse、exploit-development

#### Phase 2 Batch 1-2（20 个，v0.2.0.2 完成）

5g-telecom-attack、ad-cs-abuse、ad-ldap-attack、agentic-pentest、ai-agent-framework-attack、ai-agent-security、ai-fuzzing、ai-security、anti-forensics、automotive-vehicle-security、autonomous-loops、av-edr-evasion、blockchain-l2-attack、blockchain-web3、bluetooth-rfid-nfc、browser-qa、chronicle、ci-cd-supply-chain-attack、cloud-identity-attack、cloud-native-vuln-research

### 质量指标对照

| 指标 | v0.2.0.1（升级前） | v0.2.0.5（本版本） | 提升 |
|------|-------------------|------------------|------|
| 高优先级 SKILL 完成数 | 0/15 | **15/15 (100%)** | +15 |
| 标准化 SKILL 完成数 | 0/100 | **20/100 (20%)** | +20 |
| **总累计** | **0/130** | **35/130 (27%)** | +35 |
| SKILL 版本统一 | 各为 0.1.x | **全部 v0.2.0.2** | +100% |
| 防御视角表格化 | 部分 | **100%**（已升级 SKILL） | 显著 |
| 检测方法章节 | 30% | **100%**（已升级 SKILL） | +70% |
| 防御规避技术章节 | 20% | **100%**（已升级 SKILL） | +80% |
| 翻译残留 | 多处 | **全部清零** | 100% 清理 |
| `.git/` 目录大小 | 3.7 GB | **19 MB** | -99.5% |

### 安全域覆盖（35 个 SKILL 已升级）

```
网络攻击域        ✓ network-pentest / 5g-telecom-attack
Web 攻击域        ✓ web-xss / web-sqli / web-ssrf / web-auth-bypass
凭证访问域        ✓ password-attack
后渗透域          ✓ post-exploitation / privilege-escalation / anti-forensics
社会工程域        ✓ social-engineering
情报收集域        ✓ osint
API 安全域        ✓ api-security
云安全域          ✓ cloud-security / cloud-identity-attack / cloud-native-vuln-research
容器安全域        ✓ container-security
二进制分析域      ✓ binary-reverse
漏洞利用开发域    ✓ exploit-development
AI 安全域         ✓ ai-security / ai-fuzzing / ai-agent-security / ai-agent-framework-attack / agentic-pentest / autonomous-loops
AD 攻击域         ✓ ad-cs-abuse / ad-ldap-attack
区块链域          ✓ blockchain-l2-attack / blockchain-web3
汽车安全域        ✓ automotive-vehicle-security
AV/EDR 规避域     ✓ av-edr-evasion
无线域            ✓ bluetooth-rfid-nfc
浏览器域          ✓ browser-qa
观测域            ✓ chronicle
供应链域          ✓ ci-cd-supply-chain-attack
```

---

## 五、安装与使用

### 快速开始

```bash
# 克隆仓库
git clone https://github.com/brucesongs/kali-claw.git
cd kali-claw

# 启动 Claude Code（或 Cursor / Windsurf / OpenClaw / Hermes / Codex / OpenCode）
claude

# 初始化（自动加载所有 SKILL）
/init

# 自然语言安排工作（示例）
# "帮我分析 kali-claw 的所有技能，生成详细使用手册"
# "针对 web-xss 技能，给出完整攻击链与检测规则"
# "使用 cloud-security 技能评估 AWS 环境的 IAM 配置"
```

### 文件结构

```
kali-claw/
├── skills/                          # 130 个安全技能库
│   ├── network-pentest/             # v0.2.0.2 (Defense Triple 标准)
│   ├── post-exploitation/           # v0.2.0.2
│   ├── web-xss/                     # v0.2.0.2
│   ├── api-security/                # v0.2.0.2
│   ├── container-security/          # v0.2.0.2
│   └── ... (共 130 个域，其中 35 个已升级到 v0.2.0.2)
├── validation/                      # 自动化校验脚本
├── RELEASE-v0.2.0.*.md              # 版本说明文档（v0.2.0.1 ~ v0.2.0.5）
├── PHASE2_PROGRESS.md               # Phase 2 标准化进度跟踪
└── GUIDE-*.md                       # 10 个 agent 平台使用指南
```

### 平台支持

| 平台 | 指南 |
|------|------|
| OpenClaw | [GUIDE-OPENCLAW-zh.md](GUIDE-OPENCLAW-zh.md) / [en](GUIDE-OPENCLAW-en.md) |
| Claude Code | [GUIDE-CLAUDECODE-zh.md](GUIDE-CLAUDECODE-zh.md) / [en](GUIDE-CLAUDECODE-en.md) |
| OpenAI Codex | [GUIDE-CODEX-zh.md](GUIDE-CODEX-zh.md) / [en](GUIDE-CODEX-en.md) |
| Hermes Agent | [GUIDE-HERMES-zh.md](GUIDE-HERMES-zh.md) / [en](GUIDE-HERMES-en.md) |
| OpenCode | [GUIDE-OPENCODE-zh.md](GUIDE-OPENCODE-zh.md) / [en](GUIDE-OPENCODE-en.md) |

---

## 六、SKILL 标准说明

所有 SKILL 遵循 **Anthropic Agent Skills Open Standard**（2025），采用渐进式披露设计：

### 第一阶段（广告层）

YAML 前言 + `## Summary` 部分，在技能扫描时加载。

```yaml
---
name: container-security
description: "Container security covers the complete lifecycle..."
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
metadata:
  domain: cloud
  tool_count: 6
  guide_count: 5
  mitre: "TA0008-Lateral Movement"
  last_reviewed: "2026-07-26"
---
```

### 第二阶段（快速参考层）

`## Core Tools` + `## Methodology` 部分，在技能激活时加载。

### 第三阶段（详细层）

`## Practical Steps` + Defense Triple 部分，在任务执行时加载：

- **Defense Perspective**（防御视角，表格化）
- **Detection Methods**（检测方法，含 SIEM 规则）
- **Defense Evasion Techniques**（防御规避技术）

---

## 七、版本路线图

### 已发布版本

| 版本 | 日期 | 主要内容 |
|------|------|---------|
| v0.2.0.1 | 2026-07-16 | 项目战略定位与计划文档 |
| v0.2.0.2 | 2026-07-19 | 完成 8 个高优先级 SKILL 升级（53%） |
| v0.2.0.3 | 2026-07-21 | 完成累计 12 个高优先级 SKILL 升级（80%） |
| v0.2.0.4 | 2026-07-24 | Phase 1 第一阶段完成（15/15 = 100%）— 里程碑版本 |
| **v0.2.0.5** | **2026-07-26** | **Phase 2 Batch 1-2 完成（20 SKILLs）+ 文档基线对齐 + 仓库瘦身** |

### 后续版本

| 版本 | 预计日期 | 主要内容 |
|------|---------|---------|
| v0.2.0.6 | 2026-08-02 | Phase 2 Batch 3-5 完成（累计 50/100 标准化）+ Task 1.3 启动 |
| v0.2.0.7 | 2026-08-09 | Task 1.3 完成（7 个新 SKILL：AI RedTeam/IdP/DLP/Edge/Quantum/SCA/5G） |
| v0.2.0.8 | 2026-08-16 | Task 1.4 文档输出完成 |
| v0.2.0.9 | 2026-08-22 | Task 1.5 自动化（CI/CD + lint 脚本）完成 |
| **v0.2.1** | **2026-08-23** | **Phase 1 全部完成，发布稳定版本** |

### Phase 1 全程目标

- SKILL 总数：130 → **150+**（含 Task 1.3 新增）
- 平均完成度：95.4% → **98%+**
- 防御视角覆盖率：86% → **100%**
- 自动化校验脚本：1 个 → **5 个**

---

## 八、下一版本（v0.2.0.6）预告

下一版本将聚焦 **Phase 2 加速 + Task 1.3 启动**。

### Phase 2 Batch 3-5（30 个 SKILLs）

按字母序推进，覆盖：

- **Batch 3**：cms-framework-attack、codebase-onboarding、command-injection-advanced、concurrency-exploitation、confidential-computing-attack、continuous-learning、council、cps-attack、crypto-attacks、cspm-casb-attack
- **Batch 4**：darkweb-intel、data-exfiltration-attack、data-platform-attack、data-scraper-agent、database-attack、deception-honeypot、deep-research、detection-engineering、digital-forensics、dns-attacks
- **Batch 5**：docker-patterns、edge-computing-attack、email-protocol-attack、email-security-deep、embedded-rtos-security、engagement-manager、exa-search、file-inclusion、firmware-reverse、game-anticheat-bypass

### Task 1.3 启动（与 Phase 2 并行）

创建 7 个战略价值高的新 SKILL：

1. **ai-safety-redteam-advanced**（AI 安全红队进阶）
2. **identity-provider-attack**（身份提供商攻击）
3. **data-loss-prevention-bypass**（数据防泄漏绕过）
4. **edge-computing-security**（边缘计算安全）
5. **quantum-cryptography-transition**（量子密码迁移）
6. **hardware-side-channel-advanced**（硬件侧信道进阶）
7. **5g-6g-telecom-attack-advanced**（5G/6G 电信攻击进阶）

完成后将发布 **v0.2.1 稳定版本**。

---

## 九、致谢与协作

### 工作模式

kali-claw 的日常开发遵循以下协作模式：

```
人类工程师：战略意图、需求定义、质量审查
              ↓
Claude Code：扫描分析、内容生成、验证执行
              ↓
人类工程师：决策反馈、优先级调整
              ↓
迭代优化
```

### Phase 1 关键决策时间线

- **2026-07-17**：启动 Phase 1，选择 Direction B（全量优化）
- **2026-07-17**：提前完成周末准备工作（节省 12h）
- **2026-07-19**：提前启动 Day 1（节省 1 天）
- **2026-07-19**：修正版本基线至 v0.2.0.2（避免后续错误）
- **2026-07-21**：完成 12/15 SKILL（80%）
- **2026-07-24**：完成 15/15 SKILL（100%）— Phase 1 第一阶段里程碑
- **2026-07-26**：Phase 2 Batch 1-2 完成（20 SKILLs）+ 仓库瘦身 + 文档基线对齐

### 反馈渠道

- **GitHub Issues**：[https://github.com/brucesongs/kali-claw/issues](https://github.com/brucesongs/kali-claw/issues)
- **GitHub Discussions**：[https://github.com/brucesongs/kali-claw/discussions](https://github.com/brucesongs/kali-claw/discussions)
- **Pull Requests**：欢迎通过 PR 贡献
- **安全漏洞报告**：请通过负责任披露流程

### 相关文档

- [RELEASE-v0.2.0.1.md](RELEASE-v0.2.0.1.md) — 项目战略定位与长远规划
- [RELEASE-v0.2.0.2.md](RELEASE-v0.2.0.2.md) — v0.2.0.2 版本说明
- [RELEASE-v0.2.0.3.md](RELEASE-v0.2.0.3.md) — v0.2.0.3 版本说明
- [RELEASE-v0.2.0.4.md](RELEASE-v0.2.0.4.md) — Phase 1 Task 1.2 Phase 1 完成（15/15 = 100%）
- [CLAUDE.md](CLAUDE.md) — 项目结构与开发指南
- [CHANGELOG.md](CHANGELOG.md) — 完整变更日志
- [PHASE2_PROGRESS.md](PHASE2_PROGRESS.md) — Phase 2 标准化进度跟踪

---

## 十、版本签名

```
版本编号：v0.2.0.5
发布日期：2026-07-26
分支：main（合并自 docs/update-core-files-v0.2.0.4 + phase2/standardization）
版本类型：质量升级版本（Phase 2 启动 + 文档基线对齐）
项目地址：https://github.com/brucesongs/kali-claw
许可证：参见仓库 LICENSE 文件
```

**kali-claw 团队**  
**2026 年 7 月 26 日**
