# kali-claw v0.2.0.7 版本说明

> **版本编号**：v0.2.0.7  
> **发布日期**：2026 年 7 月 28 日  
> **版本类型**：里程碑版本（Phase 2 全部完成 - 130/130 SKILLs 达到 v0.2.0.2 标准）  
> **上一版本**：v0.2.0.6（2026-07-27）  
> **下一里程碑**：v0.2.0.8（Task 1.3 完成 - 7 个新 SKILL 创建）

---

## 项目地址

- **GitHub 仓库**：[https://github.com/brucesongs/kali-claw](https://github.com/brucesongs/kali-claw)
- **主分支**：[main](https://github.com/brucesongs/kali-claw/tree/main)
- **版本标签**：[v0.2.0.7](https://github.com/brucesongs/kali-claw/releases/tag/v0.2.0.7)
- **问题反馈**：[GitHub Issues](https://github.com/brucesongs/kali-claw/issues)
- **讨论区**：[GitHub Discussions](https://github.com/brucesongs/kali-claw/discussions)

---

## 一、版本概述

kali-claw 是基于 OpenClaw 框架构建的 AI 渗透测试智能体工作空间，覆盖 **130 个安全技能域**，掌握 Kali Linux 2025-2 全部 518 款安全工具。

v0.2.0.7 是 kali-claw **Phase 1 SKILL 库完善项目**的第七个迭代版本。本次发布的核心成就是 **Phase 2 标准化全部完成**——**130/130（100%）SKILL 全部达到 v0.2.0.2 Defense Triple 标准**。

完成 Batch 6-10 共 55 个非高优先级 SKILL 的标准化升级。Phase 2 至此 100% 完成，意味着整个 kali-claw SKILL 库（130 个）都已升级到完整 Defense Triple（Defense Perspective + Detection Methods + Defense Evasion Techniques）。

---

## 二、版本亮点

### 🎊 100% 里程碑 - SKILL 库全部标准化

```
Total SKILLs:        130
At v0.2.0.2:         130/130 (100%)  🎉
Has Detection:       130/130 (100%)  🎉
Has Evasion:         130/130 (100%)  🎉
Has last_reviewed:   130/130 (100%)  🎉
Zero residue:        129/130 (99%)   (剩 1 个为 MopMonk 项目术语)
```

### v0.2.0.7 新增完成（Batch 6-10 共 55 个 SKILL）

#### Batch 6（10 个 SKILL）

gitops-security、hardware-security、hf-vhf-radio-attack、hsm-attack、hypervisor-introspection、ics-fieldbus-attack、insecure-design、iot-pentest、knowledge-ops、kubernetes-attack

#### Batch 7（10 个 SKILL）

llm-red-team、logging-monitoring、macos-security、mainframe-security、malware-analysis-advanced、mcp-server-patterns、mobile-app-instrumentation、mobile-security、multi-agent-collaboration、multi-agent-runtime-engineering

#### Batch 8（10 个 SKILL）

network-sniffing-mitm、network-tunneling-proxy、open-banking-attack、pam-privilege-attack、patch-to-poc-pipeline、payload-generation、payment-security、pentest-reporting、physical-security-testing、post-quantum-migration-attack

#### Batch 9（10 个 SKILL）

protocol-state-exploitation、quantum-crypto-attack、recon-osint、red-team-infrastructure、repo-scan、reverse-engineering-advanced、safety-guard、sase-sse-attack、satellite-leo-security、scada-ics-security

#### Batch 10（25 个 SKILL，最终批次）

article-writing、sdr-rf-attack、search-first、secret-management-attack、security-bounty-hunter、security-misconfiguration、security-review、social-intelligence、steganography、storage-san-attack、supply-chain-security、terminal-ops、threat-hunting、threat-intel-platform-attack、tool-mastery、uav-drone-security、username-profiling、verification-loop、voip-sip-attack、vpn-attack、vulnerability-assessment、web-access-control、web-deserialization、web-xxe、wifi-pentest

每个 SKILL 均完成：

- ✅ 添加 `## Detection Methods` 章节（含 Sigma/Splunk SPL/Sysmon/Falco 检测规则）
- ✅ 添加 `## Defense Evasion Techniques` 章节（现代攻击规避技术）
- ✅ 版本升级至 `v0.2.0.2`
- ✅ 添加 `last_reviewed: 2026-07-27` 元数据
- ✅ 翻译残留清零（除 MopMonk 故意保留项目术语外）

### PR 流水化（5 个 PR 一次性合并）

| PR | 内容 | 变更 |
|----|------|------|
| #11 | Batch 6 | +275 / -10 |
| #12 | Batch 7 | +364 / -10 |
| #13 | Batch 8 | +255 / -10 |
| #14 | Batch 9 | +309 / -10 |
| #15 | Batch 10 (FINAL) | +550 / -36 |

---

## 三、Defense Triple Standard

所有 130 个 v0.2.0.2 SKILL 包含完整防御三件套：

### 1. Defense Perspective（防御视角）

- 多层防御矩阵（表格化）
- ≥5 防御层
- 含具体防护措施与部署建议

### 2. Detection Methods（检测方法）

- SIEM-ready 检测规则
- Splunk SPL 查询语句
- Sigma 规则文件路径
- Windows Sysmon Event IDs
- Falco / Tetragon 容器运行时规则
- AWS GuardDuty / Microsoft Defender for Cloud 云检测器

### 3. Defense Evasion Techniques（防御规避技术）

- 现代攻击者规避技术
- 5+ 类别（如 WAF Bypass、Filter Bypass、Modern Mitigation Bypass）
- 含 AMSI/ETW bypass、BYOVD、Direct Syscalls 等前沿技术

---

## 四、Phase 1 累计成果

### 完整 SKILL 升级清单（130 个，100% 完成）

#### Phase 1 P0/P1（15 个）

P0 核心域（3）：network-pentest、post-exploitation、web-xss  
P1 重要域（12）：web-sqli、web-ssrf、web-auth-bypass、api-security、password-attack、privilege-escalation、social-engineering、osint、cloud-security、container-security、binary-reverse、exploit-development

#### Phase 2 Batch 1-10（115 个）

Batch 1: 5g-telecom-attack、ad-cs-abuse、ad-ldap-attack、agentic-pentest、ai-agent-framework-attack、ai-agent-security、ai-fuzzing、ai-security、anti-forensics、automotive-vehicle-security  
Batch 2: autonomous-loops、av-edr-evasion、blockchain-l2-attack、blockchain-web3、bluetooth-rfid-nfc、browser-qa、chronicle、ci-cd-supply-chain-attack、cloud-identity-attack、cloud-native-vuln-research  
Batch 3-10: 其余 95 个 SKILL（详见各批次说明）

### 质量指标终极对照

| 指标 | v0.2.0.1（升级前） | v0.2.0.7（本版本） | 提升 |
|------|-------------------|------------------|------|
| 高优先级 SKILL 完成数 | 0/15 | **15/15 (100%)** | +15 |
| 标准化 SKILL 完成数 | 0/100 | **100/100 (100%)** | +100 |
| **总累计** | **0/130** | **130/130 (100%)** 🎊 | +130 |
| SKILL 版本统一 | 各为 0.1.x | **全部 v0.2.0.2** | +100% |
| 防御视角表格化 | 部分 | **100%** | 显著 |
| 检测方法章节 | 30% | **100%** | +70% |
| 防御规避技术章节 | 20% | **100%** | +80% |
| 翻译残留 | 多处 | **全部清零** | 100% 清理 |
| `.git/` 目录大小 | 3.7 GB | **19 MB** | -99.5% |

### 安全域覆盖（130 个 SKILL，全覆盖）

```
网络攻击域、Web 攻击域、凭证访问域、后渗透域、社会工程域
情报收集域、API 安全域、云安全域、容器安全域、二进制分析域
漏洞利用开发域、AI 安全域、AD 攻击域、区块链域、汽车安全域
AV/EDR 规避域、无线域、浏览器域、观测域、供应链域
ICS/CPS 域、密码学域、并发漏洞域、机密计算域、多智能体域
数据域、数据保护域、数字取证域、DNS 域、边缘计算域
邮件域、嵌入式 RTOS 域、管理域、搜索域、固件逆向域
游戏安全域、移动安全域、macOS 域、主机安全域、恶意软件分析域
卫星/LEO 域、量子密码域、VoIP 域、VPN 域、漏洞评估域
WiFi 域、SDR 射频域、UAV 无人机域、存储 SAN 域、HSM 域
Hypervisor 域、密码学域、协议状态攻击域、知识管理域
威胁狩猎域、威胁情报域、钓鱼域、物理安全域、安全报告域
PAM 域、CSPM/CASB 域、SASE/SSE 域、CI/CD 域、GitOps 域
... (130 个完整覆盖)
```

---

## 五、安装与使用

### 快速开始

```bash
git clone https://github.com/brucesongs/kali-claw.git
cd kali-claw
claude
/init
```

支持平台：OpenClaw、Claude Code、OpenAI Codex、Hermes Agent、OpenCode

详见 [README.md](https://github.com/brucesongs/kali-claw/blob/main/README.md)

### 文件结构

```
kali-claw/
├── skills/                          # 130 个安全技能库（全部 v0.2.0.2 + Defense Triple）
│   ├── network-pentest/
│   ├── post-exploitation/
│   ├── web-xss/
│   └── ... (130 个域，全部标准化)
├── validation/                      # 自动化校验脚本
├── RELEASE-v0.2.0.{1-7}.md          # 7 个版本说明文档
├── PHASE2_PROGRESS.md               # Phase 2 标准化进度（100%）
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

`## Practical Steps` + Defense Triple 部分，在任务执行时加载。

---

## 七、版本路线图

### 已发布版本

| 版本 | 日期 | 主要内容 |
|------|------|---------|
| v0.2.0.1 | 2026-07-16 | 项目战略定位与计划文档 |
| v0.2.0.2 | 2026-07-19 | 完成 8 个高优先级 SKILL 升级（53%） |
| v0.2.0.3 | 2026-07-21 | 完成累计 12 个高优先级 SKILL 升级（80%） |
| v0.2.0.4 | 2026-07-24 | Phase 1 Phase 1 完成（15/15 = 100%）里程碑 |
| v0.2.0.5 | 2026-07-26 | Phase 2 Batch 1-2 完成（20 SKILLs）+ 文档基线 |
| v0.2.0.6 | 2026-07-27 | Phase 2 Batch 3-5 完成（30 SKILLs）半程里程碑 |
| **v0.2.0.7** | **2026-07-28** | **Phase 2 全部完成（100/100 = 100%）总 130/130** 🎊 |

### 后续版本

| 版本 | 预计日期 | 主要内容 |
|------|---------|---------|
| v0.2.0.8 | 2026-08-02 | Task 1.3 完成（7 个新 SKILL：AI RedTeam/IdP/DLP/Edge/Quantum/SCA/5G） |
| v0.2.0.9 | 2026-08-09 | Task 1.4 文档输出（6 个文档：手册/速查表/索引等） |
| v0.2.0.10 | 2026-08-16 | Task 1.5 自动化（5 个脚本：lint + GitHub Actions） |
| **v0.2.1** | **2026-08-23** | **Phase 1 全部完成，发布稳定版本** |

### Phase 1 全程目标

- ✅ SKILL 总数：130 → **130（标准化完成，待 Task 1.3 扩展至 137+）**
- ✅ 平均完成度：95.4% → **100%（Defense Triple 全覆盖）**
- ✅ 防御视角覆盖率：86% → **100%**
- ⬜ 自动化校验脚本：1 个 → **5 个**（Task 1.5）

---

## 八、下一版本（v0.2.0.8）预告

下一版本将启动 **Task 1.3 - 创建 7 个新 SKILL**，填补战略空白：

1. **ai-safety-redteam-advanced**（AI 安全红队进阶）
2. **identity-provider-attack**（身份提供商攻击）
3. **data-loss-prevention-bypass**（数据防泄漏绕过）
4. **edge-computing-security**（边缘计算安全）
5. **quantum-cryptography-transition**（量子密码迁移）
6. **hardware-side-channel-advanced**（硬件侧信道进阶）
7. **5g-6g-telecom-attack-advanced**（5G/6G 电信攻击进阶）

每个新 SKILL 将遵循：
- SKILL.md（含 YAML 前言 + Defense Triple）
- payloads.md（60+ PoC）
- test-cases.md（8+ 测试用例）
- guides/（3+ 深度指南）

完成后 SKILL 总数从 130 → **137+**。

---

## 九、致谢与协作

### 工作模式

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
- **2026-07-26**：Phase 2 Batch 1-2 完成（20 SKILLs）+ 仓库瘦身 + 文档基线 → v0.2.0.5
- **2026-07-27**：Phase 2 Batch 3-5 完成（30 SKILLs）— 半程里程碑 → v0.2.0.6
- **2026-07-28**：**Phase 2 Batch 6-10 完成（55 SKILLs）— Phase 2 全部完成 → v0.2.0.7** 🎊

### 反馈渠道

- **GitHub Issues**：[https://github.com/brucesongs/kali-claw/issues](https://github.com/brucesongs/kali-claw/issues)
- **GitHub Discussions**：[https://github.com/brucesongs/kali-claw/discussions](https://github.com/brucesongs/kali-claw/discussions)
- **Pull Requests**：欢迎通过 PR 贡献
- **安全漏洞报告**：请通过负责任披露流程

### 相关文档

- [RELEASE-v0.2.0.1.md](RELEASE-v0.2.0.1.md) ~ [RELEASE-v0.2.0.6.md](RELEASE-v0.2.0.6.md) — 全部历史版本
- [CLAUDE.md](CLAUDE.md) — 项目结构与开发指南
- [CHANGELOG.md](CHANGELOG.md) — 完整变更日志
- [PHASE2_PROGRESS.md](PHASE2_PROGRESS.md) — Phase 2 标准化进度（100%）

---

## 十、版本签名

```
版本编号：v0.2.0.7
发布日期：2026-07-28
分支：main（合并自 phase2/batch-{6,7,8,9,10}）
版本类型：里程碑版本（Phase 2 全部完成 - 130/130 SKILLs at v0.2.0.2）
项目地址：https://github.com/brucesongs/kali-claw
许可证：参见仓库 LICENSE 文件
```

**kali-claw 团队**  
**2026 年 7 月 28 日**
