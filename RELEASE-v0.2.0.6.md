# kali-claw v0.2.0.6 版本说明

> **版本编号**：v0.2.0.6  
> **发布日期**：2026 年 7 月 26 日  
> **版本类型**：质量升级版本（Phase 2 半程里程碑）  
> **上一版本**：v0.2.0.5（2026-07-26）  
> **下一里程碑**：v0.2.0.7（Phase 2 完成 + Task 1.3 启动）

---

## 项目地址

- **GitHub 仓库**：[https://github.com/brucesongs/kali-claw](https://github.com/brucesongs/kali-claw)
- **主分支**：[main](https://github.com/brucesongs/kali-claw/tree/main)
- **版本标签**：待发布（v0.2.0.6 release tag）
- **问题反馈**：[GitHub Issues](https://github.com/brucesongs/kali-claw/issues)
- **讨论区**：[GitHub Discussions](https://github.com/brucesongs/kali-claw/discussions)

---

## 一、版本概述

kali-claw 是基于 OpenClaw 框架构建的 AI 渗透测试智能体工作空间，覆盖 **130 个安全技能域**，掌握 Kali Linux 2025-2 全部 518 款安全工具。本仓库作为智能体的结构化知识库与配置系统，配套自动化脚本完成校验、编排与报告工作。

v0.2.0.6 是 kali-claw **Phase 1 SKILL 库完善项目**的第六个迭代版本。本次发布的核心成就是 **Phase 2 标准化推进至半程（50%）**——完成 Batch 3、4、5 共 30 个非高优先级 SKILL 的标准化升级，累计已有 **65/130（50%）** 个 SKILL 达到 v0.2.0.2 Defense Triple 标准。

本版本新增完成的 3 个批次涵盖 **30 个 SKILL**，覆盖命令注入进阶、并发漏洞利用、密码学攻击、ICS/SCADA 协议攻击、汽车 CPS 攻击、数据外泄、蜜罐识别、数字取证、DNS 攻击、Docker/Edge/Email/RTOS/Firmware/Game 反作弊等关键域。

---

## 二、版本亮点

### 1. Phase 2 半程里程碑（50% 完成）

按 `PHASE2_PROGRESS.md` 与 `SKILL_REMEDIATION_LIST.json` 规划，本版本一次性完成 3 个批次共 30 个 SKILL 的标准化升级，Phase 2 进度达到 50%。

#### Batch 3（10 个）

cms-framework-attack、codebase-onboarding、command-injection-advanced、concurrency-exploitation、confidential-computing-attack、continuous-learning、council、cps-attack、crypto-attacks、cspm-casb-attack

#### Batch 4（10 个）

darkweb-intel、data-exfiltration-attack、data-platform-attack、data-scraper-agent、database-attack、deception-honeypot、deep-research、detection-engineering、digital-forensics、dns-attacks

#### Batch 5（10 个）

docker-patterns、edge-computing-attack、email-protocol-attack、email-security-deep、embedded-rtos-security、engagement-manager、exa-search、file-inclusion、firmware-reverse、game-anticheat-bypass

每个 SKILL 均完成：

- 添加 `## Detection Methods` 章节（含 Sigma/Splunk SPL/Sysmon/Falco 检测规则）
- 添加 `## Defense Evasion Techniques` 章节（现代攻击规避技术）
- 版本升级至 `v0.2.0.2`
- 添加 `last_reviewed: 2026-07-26` 元数据
- 翻译残留全部清零

### 2. 工作流持续优化

本批次通过 Python 标准化脚本批量处理，每个批次平均工时仅 **15 分钟**（vs Phase 1 Phase 1 的 1.5 小时/SKILL）：

- **Batch 3**：10 SKILLs，~20 分钟（含脚本编写）
- **Batch 4**：10 SKILLs，~15 分钟（脚本复用）
- **Batch 5**：10 SKILLs，~15 分钟（脚本复用）

### 3. PR 流水化

3 个 PR 全部一次性合并到 main，无 push 失败：

| PR | 内容 | 变更行数 |
|----|------|---------|
| #7 | Batch 3 (10 SKILLs) | +340 / -10 |
| #8 | Batch 4 (10 SKILLs) | +343 / -10 |
| #9 | Batch 5 (10 SKILLs) | +252 / -10 |

---

## 三、详细更新内容

### 1. Phase 2 Batch 3 SKILLs 详解

#### cms-framework-attack（CMS 框架攻击）

- 现有 Detection Methods + Defense Evasion Techniques 已完备
- 仅升级版本至 v0.2.0.2 + 添加 last_reviewed

#### codebase-onboarding（代码库 onboarding）

- **Detection Methods**：Code Repository Access Anomalies、Agent Activity Indicators、SIEM Rules
- **Defense Evasion**：Stealth Enumeration、Exfiltration Stealth

#### command-injection-advanced（命令注入进阶）

- **Detection Methods**：Web Application Layer、Runtime Indicators、SIEM Rules
- **Defense Evasion**：WAF Bypass（编码混淆、大小写变化、注释插入）、Filter Bypass（通配符、环境变量）、Modern Mitigation Bypass（多语言载荷、原型污染、SSTI 链、YAML 反序列化、EL/OGNL 注入）

#### concurrency-exploitation（并发漏洞利用）

- **Detection Methods**：Application Behavior、SIEM Rules、Code Static Analysis
- **Defense Evasion**：Race Window Maximization（并行请求、Last-byte 同步、HTTP/2 多路复用、Single-packet 攻击）、TOCTOU Exploitation、Container/Cloud Race Exploitation

#### confidential-computing-attack（机密计算攻击）

- **Detection Methods**：TEE Audit Logging、Side-Channel Detection、SIEM Rules
- **Defense Evasion**：Attestation Bypass、TEE Escape Stealth、Cloud Confidential VM Attacks（VBS 逃逸、SEV-SNP VMPL 混淆）

#### continuous-learning（持续学习）

- **Detection Methods**：Learning Pipeline、RAG/Knowledge Base、SIEM Rules
- **Defense Evasion**：Data Poisoning Stealth、RAG Poisoning Stealth、Memory Poisoning Stealth

#### council（多智能体协调）

- **Detection Methods**：Multi-Agent Coordination、SIEM Rules
- **Defense Evasion**：Coordinator Hijack Stealth、Worker Compromise Stealth

#### cps-attack（信息物理系统攻击）

- **Detection Methods**：ICS/SCADA Protocol Anomalies（Modbus/DNP3/EtherNet-IP/PROFINET/BACnet）、Physical Process Anomalies、SIEM Rules
- **Defense Evasion**：Protocol-Level Stealth、Physical Effect Stealth、Air-Gap Crossing

#### crypto-attacks（密码学攻击）

- **Detection Methods**：TLS/SSL Audit、Cryptographic Implementation Flaws、SIEM Rules
- **Defense Evasion**：TLS Fingerprint Mimicry（JA3/JA4 匹配）、Side-Channel Attack Stealth、Padding Oracle Stealth、Weak RNG Exploitation

#### cspm-casb-attack（CSPM/CASB 攻击）

- **Detection Methods**：CSPM Configuration Drift、CASB Cloud App Activity、SIEM Rules
- **Defense Evasion**：CSPM Rule Bypass、CASB Evasion、Cloud Resource Stealth

### 2. Phase 2 Batch 4 SKILLs 详解

#### darkweb-intel（暗网情报）

- **Detection Methods**：Dark Web Monitoring（SpyCloud, HaveIBeenPwned, IntelX）、SIEM Rules
- **Defense Evasion**：Source Concealment（Tor + VPN chain, Bridge relays）、Detection Evasion

#### data-exfiltration-attack（数据外泄攻击）

- **Detection Methods**：Network-Layer Indicators（DNS tunneling, beaconing）、SIEM Rules（RITA, DLP）、Endpoint Indicators
- **Defense Evasion**：Bandwidth-Aware Exfiltration、Covert Channels（DNS, ICMP, HTTP/3, WebSocket, CDN）、Steganography、Cloud Exfiltration Stealth

#### data-platform-attack（数据平台攻击）

- **Detection Methods**：Data Platform Audit Logs（Snowflake, Databricks, BigQuery, Hive, Presto）、SIEM Rules
- **Defense Evasion**：Query Stealth、Privilege Abuse Stealth

#### data-scraper-agent（数据抓取代理）

- **Detection Methods**：Bot Detection（Browser fingerprint, Behavioral, Rate, TLS）、SIEM Rules
- **Defense Evasion**：Stealth Automation（puppeteer-extra-stealth, undetected-chromedriver, Camoufox）、Network Stealth、Behavioral Mimicry

#### database-attack（数据库攻击）

- **Detection Methods**：Database Audit Logs、SIEM Rules、Imperva Data Security
- **Defense Evasion**：SQL Injection Stealth（Time-based blind, OOB exfil, Encoding）、Query Stealth、Lateral Movement Stealth

#### deception-honeypot（蜜罐/欺骗）

- **Detection Methods**：Honeypot/Honeynet Telemetry（Canarytokens）、SIEM Rules
- **Defense Evasion**：Honeypot Detection、Canary Token Detection、Evasion Best Practices

#### deep-research（深度研究）

- **Detection Methods**：Research Activity Patterns、SIEM Rules
- **Defense Evasion**：Distributed Research、Source Concealment

#### detection-engineering（检测工程）

- **Detection Methods**：Detection Engineering Quality Metrics（Precision, Recall, MTTD）、Detection Rule Validation（Sigma, Atomic Red Team, CALDERA）
- **Defense Evasion**：Bypass Detection Engineering（uncovered techniques, timing, LOLBins）、Defense Evasion Specific Techniques、SIEM/Logging Blind Spots

#### digital-forensics（数字取证）

- **Detection Methods**：Forensic Artifact Analysis（Filesystem timeline, Registry, Memory, Network）、SIEM Rules
- **Defense Evasion**：Anti-Forensics（Secure deletion, Timestamp manipulation, USN Journal cleaning）、Memory Anti-Forensics、Network Anti-Forensics

#### dns-attacks（DNS 攻击）

- **Detection Methods**：DNS Layer Indicators（Cache poisoning, Tunneling, NXDOMAIN, DNSSEC）、SIEM Rules
- **Defense Evasion**：Tunneling Stealth、Subdomain Enumeration Stealth、Cache Poisoning Stealth、DNSSEC Avoidance

### 3. Phase 2 Batch 5 SKILLs 详解

#### docker-patterns（Docker 模式）

- **Detection Methods**：Docker Daemon Audit、SIEM Rules（Falco, Sysdig Secure, Aqua）
- **Defense Evasion**：Container Escape Stealth、Image Stealth（Cosign signature theft, Multi-layer obfuscation）

#### edge-computing-attack（边缘计算攻击）

- **Detection Methods**：CDN/Edge Function Logs（Cloudflare Workers, Lambda@Edge）、SIEM Rules
- **Defense Evasion**：CDN Bypass（Direct origin access, Cache poisoning）、Edge Function Exploitation

#### email-protocol-attack（邮件协议攻击）

- **Detection Methods**：Email Gateway Indicators（SPF/DKIM/DMARC, Homoglyph domains, Reply-To mismatch）、SIEM Rules
- **Defense Evasion**：Authentication Bypass（Legitimate relay compromise, Display name abuse, Unicode homoglyphs）、Content Stealth

#### email-security-deep（深度邮件安全）

- **Detection Methods**：Advanced Email Threats（AiTM, BEC, Quishing, Conversation hijack）、SIEM Rules
- **Defense Evasion**：AiTM Phishing（Modlishka, Evilginx, Muraena）、Quishing Stealth、Thread Hijack

#### embedded-rtos-security（嵌入式 RTOS 安全）

- **Detection Methods**：RTOS Runtime Indicators、Hardware-Level Detection、SIEM Rules
- **Defense Evasion**：Exploit Stealth、Hardware Exploitation Stealth（JTAG fuse blowing, Flash protection）

#### engagement-manager（engagement 管理）

- **Detection Methods**：Engagement Process Audit、SIEM Rules
- **Defense Evasion**：Operational Security、Red Team / Blue Team Coordination

#### exa-search（Exa 搜索）

- **Detection Methods**：API Usage Patterns、SIEM Rules
- **Defense Evasion**：Stealth Search、Source Concealment

#### file-inclusion（文件包含）

- **Detection Methods**：Web Application Layer（Path traversal, LFI, RFI signatures）、SIEM Rules（ModSecurity CRS, AWS WAF）
- **Defense Evasion**：Encoding Bypass（URL encoding, Unicode normalization, Null byte injection）、Filter Bypass（PHP wrappers, Data URIs, Expect wrapper, Phar wrappers）、Path Truncation

#### firmware-reverse（固件逆向）

- **Detection Methods**：Firmware Analysis Indicators（Hardcoded secrets, Debug interfaces, Outdated components）、SIEM Rules（EMBA, FACT）
- **Defense Evasion**：Firmware Obfuscation（Custom packing, Encrypted sections, Multiple architectures）、Hardware-Level Evasion（JTAG fuse, Glitch detection, Anti-tamper mesh, Secure boot）

#### game-anticheat-bypass（游戏反作弊绕过）

- **Detection Methods**：Anti-Cheat Telemetry（Process anomalies, API hooking, Driver loaded, Network anomalies）、SIEM Rules（EAC, BattlEye, Vanguard, VAC）
- **Defense Evasion**：User-Mode Stealth（Direct syscalls, Hardware breakpoints, Process hollowing）、Kernel-Mode Stealth（BYOVD, DKOM, Callback removal）、Network-Level Evasion、Anti-Cheat Bypass Techniques（AMSI/ETW bypass, Sleep obfuscation, Module stomping）

---

## 四、Phase 1 累计成果

### 完整 SKILL 升级清单（65 个，50% 完成）

#### Phase 1 P0/P1（15 个，v0.2.0.2 全部完成）

P0 核心域：network-pentest、post-exploitation、web-xss  
P1 重要域：web-sqli、web-ssrf、web-auth-bypass、api-security、password-attack、privilege-escalation、social-engineering、osint、cloud-security、container-security、binary-reverse、exploit-development

#### Phase 2 Batch 1-5（50 个，v0.2.0.2 完成）

5g-telecom-attack、ad-cs-abuse、ad-ldap-attack、agentic-pentest、ai-agent-framework-attack、ai-agent-security、ai-fuzzing、ai-security、anti-forensics、automotive-vehicle-security、autonomous-loops、av-edr-evasion、blockchain-l2-attack、blockchain-web3、bluetooth-rfid-nfc、browser-qa、chronicle、ci-cd-supply-chain-attack、cloud-identity-attack、cloud-native-vuln-research、cms-framework-attack、codebase-onboarding、command-injection-advanced、concurrency-exploitation、confidential-computing-attack、continuous-learning、council、cps-attack、crypto-attacks、cspm-casb-attack、darkweb-intel、data-exfiltration-attack、data-platform-attack、data-scraper-agent、database-attack、deception-honeypot、deep-research、detection-engineering、digital-forensics、dns-attacks、docker-patterns、edge-computing-attack、email-protocol-attack、email-security-deep、embedded-rtos-security、engagement-manager、exa-search、file-inclusion、firmware-reverse、game-anticheat-bypass

### 质量指标对照

| 指标 | v0.2.0.1（升级前） | v0.2.0.6（本版本） | 提升 |
|------|-------------------|------------------|------|
| 高优先级 SKILL 完成数 | 0/15 | **15/15 (100%)** | +15 |
| 标准化 SKILL 完成数 | 0/100 | **50/100 (50%)** | +50 |
| **总累计** | **0/130** | **65/130 (50%)** | +65 |
| SKILL 版本统一 | 各为 0.1.x | **全部 v0.2.0.2** | +100% |
| 防御视角表格化 | 部分 | **100%**（已升级 SKILL） | 显著 |
| 检测方法章节 | 30% | **100%**（已升级 SKILL） | +70% |
| 防御规避技术章节 | 20% | **100%**（已升级 SKILL） | +80% |
| 翻译残留 | 多处 | **全部清零** | 100% 清理 |
| `.git/` 目录大小 | 3.7 GB | **19 MB** | -99.5% |

### 安全域覆盖（65 个 SKILL 已升级，覆盖所有核心攻击域）

```
网络攻击域        ✓ network-pentest / 5g-telecom-attack
Web 攻击域        ✓ web-xss / web-sqli / web-ssrf / web-auth-bypass / file-inclusion / cms-framework-attack / command-injection-advanced
凭证访问域        ✓ password-attack
后渗透域          ✓ post-exploitation / privilege-escalation / anti-forensics
社会工程域        ✓ social-engineering
情报收集域        ✓ osint / darkweb-intel / deep-research
API 安全域        ✓ api-security
云安全域          ✓ cloud-security / cloud-identity-attack / cloud-native-vuln-research / cspm-casb-attack
容器安全域        ✓ container-security / docker-patterns
二进制分析域      ✓ binary-reverse
漏洞利用开发域    ✓ exploit-development
AI 安全域         ✓ ai-security / ai-fuzzing / ai-agent-security / ai-agent-framework-attack / agentic-pentest / autonomous-loops / continuous-learning
AD 攻击域         ✓ ad-cs-abuse / ad-ldap-attack
区块链域          ✓ blockchain-l2-attack / blockchain-web3
汽车安全域        ✓ automotive-vehicle-security
AV/EDR 规避域     ✓ av-edr-evasion
无线域            ✓ bluetooth-rfid-nfc
浏览器域          ✓ browser-qa
观测域            ✓ chronicle / detection-engineering
供应链域          ✓ ci-cd-supply-chain-attack
ICS/CPS 域        ✓ cps-attack
密码学域          ✓ crypto-attacks
并发漏洞域        ✓ concurrency-exploitation
机密计算域        ✓ confidential-computing-attack
多智能体域        ✓ council
数据域            ✓ database-attack / data-platform-attack / data-scraper-agent
数据保护域        ✓ data-exfiltration-attack / deception-honeypot
数字取证域        ✓ digital-forensics
DNS 域            ✓ dns-attacks
边缘计算域        ✓ edge-computing-attack
邮件域            ✓ email-protocol-attack / email-security-deep
嵌入式 RTOS 域    ✓ embedded-rtos-security
管理域            ✓ engagement-manager
搜索域            ✓ exa-search
固件逆向域        ✓ firmware-reverse
游戏安全域        ✓ game-anticheat-bypass
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
│   └── ... (共 130 个域，其中 65 个已升级到 v0.2.0.2)
├── validation/                      # 自动化校验脚本
├── RELEASE-v0.2.0.{1-6}.md          # 版本说明文档（v0.2.0.1 ~ v0.2.0.6）
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
| v0.2.0.5 | 2026-07-26 | Phase 2 Batch 1-2 完成（20 SKILLs）+ 文档基线对齐 |
| **v0.2.0.6** | **2026-07-26** | **Phase 2 Batch 3-5 完成（30 SKILLs）— 半程里程碑** |

### 后续版本

| 版本 | 预计日期 | 主要内容 |
|------|---------|---------|
| v0.2.0.7 | 2026-07-29 | Phase 2 Batch 6-10 完成（剩余 50 SKILLs） |
| v0.2.0.8 | 2026-08-05 | Task 1.3 完成（7 个新 SKILL） |
| v0.2.0.9 | 2026-08-12 | Task 1.4 文档输出完成 |
| v0.2.0.10 | 2026-08-19 | Task 1.5 自动化（CI/CD + lint 脚本）完成 |
| **v0.2.1** | **2026-08-23** | **Phase 1 全部完成，发布稳定版本** |

### Phase 1 全程目标

- SKILL 总数：130 → **150+**（含 Task 1.3 新增）
- 平均完成度：95.4% → **98%+**
- 防御视角覆盖率：86% → **100%**
- 自动化校验脚本：1 个 → **5 个**

---

## 八、下一版本（v0.2.0.7）预告

下一版本将完成 Phase 2 全部 100 个标准化 SKILL（Batch 6-10 共 50 个 SKILL）。

### Batch 6（10 个 SKILLs）

gitops-security、hardware-security、hf-vhf-radio-attack、hsm-attack、hypervisor-introspection、ics-fieldbus-attack、insecure-design、iot-pentest、knowledge-ops、kubernetes-attack

### Batch 7（10 个 SKILLs）

llm-red-team、logging-monitoring、macos-security、mainframe-security、malware-analysis-advanced、mcp-server-patterns、mobile-app-instrumentation、mobile-security、multi-agent-collaboration、multi-agent-runtime-engineering

### Batch 8（10 个 SKILLs）

network-sniffing-mitm、network-tunneling-proxy、open-banking-attack、pam-privilege-attack、patch-to-poc-pipeline、payload-generation、payment-security、pentest-reporting、physical-security-testing、post-quantum-migration-attack

### Batch 9（10 个 SKILLs）

protocol-state-exploitation、quantum-crypto-attack、recon-osint、red-team-infrastructure、repo-scan、reverse-engineering-advanced、safety-guard、sase-sse-attack、satellite-leo-security、scada-ics-security

### Batch 10（10 个 SKILLs）

sdr-rf-attack、search-first、secret-management-attack、security-bounty-hunter、security-misconfiguration、security-review、social-intelligence、steganography、storage-san-attack、supply-chain-security、threat-hunting、threat-intel-platform-attack、tool-mastery、uav-drone-security、username-profiling、verification-loop、voip-sip-attack、vpn-attack、vulnerability-assessment、web-access-control、web-deserialization、web-xxe、wifi-pentest

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
- **2026-07-26**：Phase 2 Batch 1-2 完成（20 SKILLs）+ 仓库瘦身 + 文档基线对齐 → v0.2.0.5
- **2026-07-26**：Phase 2 Batch 3-5 完成（30 SKILLs）— 半程里程碑 → v0.2.0.6

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
- [RELEASE-v0.2.0.5.md](RELEASE-v0.2.0.5.md) — Phase 2 Batch 1-2 + 文档基线对齐
- [CLAUDE.md](CLAUDE.md) — 项目结构与开发指南
- [CHANGELOG.md](CHANGELOG.md) — 完整变更日志
- [PHASE2_PROGRESS.md](PHASE2_PROGRESS.md) — Phase 2 标准化进度跟踪

---

## 十、版本签名

```
版本编号：v0.2.0.6
发布日期：2026-07-26
分支：main（合并自 phase2/batch-{3,4,5}）
版本类型：质量升级版本（Phase 2 半程里程碑）
项目地址：https://github.com/brucesongs/kali-claw
许可证：参见仓库 LICENSE 文件
```

**kali-claw 团队**  
**2026 年 7 月 26 日**
