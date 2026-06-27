# OpenClaw + kali-claw 完整使用指南

> 面向 v0.1.39 | 从零开始，手把手教你搭建和使用 AI 渗透测试智能体（111 个技能域、33 个 Distinguished）

---

## 一、概念理解

### 1.1 OpenClaw 是什么

OpenClaw 是一个 **AI 智能体运行框架**，通过 npm 安装，提供以下核心能力：

- **智能体管理** — 创建、列表、删除 AI 智能体（`openclaw agents add/list/remove`）
- **独立工作空间** — 每个智能体拥有独立的文件目录，互不干扰
- **网关服务** — 提供统一的对话入口（`openclaw gateway start`）
- **会话管理** — 自动加载工作空间中的配置和记忆文件
- **心跳轮询** — 定期触发智能体执行自动化任务

**类比理解**：如果把 OpenClaw 想象成手机操作系统（比如 iOS），那 kali-claw 就是一个安装在上面的 App。操作系统提供运行环境和管理能力，App 提供具体功能。

### 1.2 kali-claw 是什么

kali-claw 是基于 OpenClaw 框架的 **预构建渗透测试智能体工作空间**。它不是一个传统的软件代码仓库，而是一个 **Markdown 格式的知识库 + 配置系统 + 自动化脚本** 的组合。

核心组成：

- **111 个安全技能域** — 覆盖 Web 安全、网络渗透、密码攻击、云与身份、容器与云原生、AI/LLM 安全、企业身份（Entra ID/Okta）、现代企业栈（PAM/CI-CD/CSPM-CASB/SASE-SSE）、关键基础设施（SCADA/ICS）、区块链/Web3、移动与物联网、量子与后量子、无线电/卫星等
- **518 个 Kali Linux 工具知识库** — 从 nmap 到 sqlmap，从 burpsuite 到 metasploit
- **12 条黑客法则** — 定义智能体的思维方式（第一性原理、发散思维、最小攻击面等）
- **三层记忆系统** — 每日日志 / 月度编年史 / 长期精炼知识
- **Agent Skills 开放标准合规** — 所有 SKILL.md 文件使用 Anthropic 2025 年发布的 YAML frontmatter 标准（`name`、`description`、`compatibility`、`allowed-tools`、`metadata`）
- **质量评分体系（SCORE.sh v2）** — 7 项指标 × 4 组件 × 5 级分层（Distinguished / Excellent / Strong / Adequate / Weak）
- **自动化验证与编排** — `validation/` 目录下 10+ 个脚本：心跳检查、备份、漂移检测、场景运行器、端到端编排、报告生成

**与直接使用 ChatGPT/Claude 的区别**：

| 特性 | ChatGPT/Claude | kali-claw |
|------|----------------|-----------|
| 持久记忆 | 无（每次对话从零开始） | 有（文件级三层记忆系统） |
| 技能体系 | 无 | 111 个领域、结构化技能 |
| 工具执行 | 不能直接执行命令 | 可调用 Kali Linux 全部 518 安全工具 |
| 人格一致性 | 无 | SOUL.md 定义固定人格 + 12 条法则 |
| 学习进化 | 无 | 通过记忆和心跳持续学习 |
| 攻击载荷库 | 无 | 每个技能含数 MB 的 payloads.md |
| 检测规则对应 | 无 | 蓝队视角 + Sigma/SPL/KQL 规则 |
| 真实事件复盘 | 无 | SolarWinds / Capital One / 3CX / xz-utils 等深度案例 |

### 1.3 整体架构

```
用户
  |
  v
OpenClaw Gateway（网关服务）
  |
  v
kali-claw 工作空间
  +-- SOUL.md              <-- 智能体人格（是谁、怎么思考）
  +-- USER.md              <-- 用户信息（帮助谁、什么偏好）
  +-- IDENTITY.md          <-- 技能标签（111 行 skill tags）
  +-- AGENTS.md            <-- 工作空间配置 + 会话启动流程
  +-- MEMORY.md            <-- 长期精炼知识
  +-- TOOLS.md             <-- 518 工具学习进度
  +-- HEARTBEAT.md         <-- 心跳自动化任务
  +-- CHANGELOG.md         <-- 版本变更日志（v0.1.1 → v0.1.39）
  +-- skills/              <-- 111 个技能域
  |   +-- web-sqli/
  |   |   +-- SKILL.md        <-- 含 YAML frontmatter（Agent Skills 标准）
  |   |   +-- payloads.md     <-- 攻击载荷
  |   |   +-- test-cases.md   <-- 测试用例
  |   |   +-- guides/         <-- 深度指南
  |   +-- ci-cd-supply-chain-attack/
  |   +-- pam-privilege-attack/
  |   +-- cspm-casb-attack/
  |   +-- sase-sse-attack/
  |   +-- ad-cs-abuse/
  |   +-- cloud-identity-attack/
  |   +-- ... (共 111 个)
  +-- validation/          <-- 自动化验证与编排
  |   +-- SCORE.sh               <-- 质量评分引擎
  |   +-- heartbeat.sh            <-- 工作空间健康检查
  |   +-- orchestrator.sh         <-- 端到端渗透编排
  |   +-- scenario-runner.sh      <-- 跨技能场景执行
  |   +-- tool-selector.sh        <-- 目标→工具映射
  |   +-- report-generator.sh     <-- 自动报告生成
  |   +-- update-skill-standard.py <-- SKILL.md 标准对齐
  |   +-- engagement-template/    <-- 授权渗透模板
  |   +-- evidence/               <-- 评分与场景证据
  +-- memory/              <-- 每日记忆日志
  +-- chronicle/           <-- 月度里程碑
  +-- docs/                <-- 长篇设计文档与规划
  +-- bak/                 <-- 备份目录
```

**会话启动流程**（每次对话开始时自动执行）：

```
1. 读取 SOUL.md      --> 加载人格和 12 条黑客法则
2. 读取 USER.md      --> 了解用户是谁、有什么偏好
3. 读取今日记忆       --> 获取今天和昨天的上下文
4. 读取 MEMORY.md    --> 加载长期精炼知识
5. 准备就绪           --> 开始对话
```

整个过程是自动的，你不需要手动操作。

### 1.4 质量分级体系（v0.1.16 引入，v0.1.39 当前状态）

kali-claw 内置了一套 **客观可量化** 的技能质量评分系统，每个技能域都会得到一个 0-100 的分数，对应 5 个等级：

| 等级 | 分数段 | v0.1.39 数量 | 含义 |
|------|--------|--------------|------|
| **Distinguished（卓越）** | 92.0 - 100 | **33** | 同类最佳深度，可作为参考实现 |
| **Excellent（优秀）** | 80.0 - 91.9 | **78** | 全面覆盖，仅个别维度有提升空间 |
| Strong（良好） | 60.0 - 79.9 | 0 | 较好覆盖 |
| Adequate（合格） | 40.0 - 59.9 | 0 | 组件齐全但深度不足 |
| Weak（薄弱） | 0 - 39.9 | 0 | 缺失关键组件 |

**当前状态（v0.1.39）**：
- 111/111 技能达到 Excellent+（**100%**）
- 平均分：**88.78**
- 最低分 / 最高分：85.1 / 94.6
- Distinguished 比例：33/111 ≈ **30%**

评分细节见 `validation/SCORING-METHODOLOGY.md`，每技能的 JSON 证据在 `validation/evidence/quality-scores/`。

---

## 二、环境准备

### 2.1 方案 A：Kali Linux 本机运行（推荐）

**最简单的方案**：直接在 Kali Linux 上安装 OpenClaw，智能体可以直接调用所有安全工具。

**系统要求**：

- Kali Linux 2025.x（ARM64 / x86_64 均可）
- Node.js >= 18
- 磁盘空间 >= 500MB

**安装 Node.js**：

```bash
# 方式一：直接安装
sudo apt update
sudo apt install -y nodejs npm

# 方式二：使用 nvm 安装最新 LTS（推荐）
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
source ~/.bashrc
nvm install --lts
```

**验证安装**：

```bash
node --version
# 应输出 v18.x.x 或更高版本
```

### 2.2 方案 B：远程 Kali（SSH 访问）

**适用场景**：你在 Mac 或 Windows 上工作，不想装虚拟机，但有一台远程 Kali Linux 服务器。

**架构**：OpenClaw 安装在你的本机（Mac/Windows/Linux），kali-claw 通过 SSH 远程调用 Kali Linux 上的安全工具。

**配置步骤**：

```bash
# 1. 生成 SSH 密钥（如果还没有）
ssh-keygen -t ed25519 -C "kali-claw"

# 2. 将公钥复制到远程 Kali
ssh-copy-id user@kali-host

# 3. 验证连接和工具可用
ssh user@kali-host "nmap --version"
# 应输出 nmap 版本信息

# 4. 测试更多工具
ssh user@kali-host "sqlmap --version && nikto -Version"
```

**在 USER.md 中记录远程连接信息**：

```markdown
- **Kali Host**: user@192.168.1.100
- **Connection**: SSH via ed25519 key
- **Access**: nmap, sqlmap, nikto, hydra, metasploit
```

### 2.3 方案 C：Docker 容器

**适用场景**：不想装完整 Kali 系统，用 Docker 快速搭建。

```bash
# 1. 拉取 Kali 镜像
docker pull kalilinux/kali-rolling

# 2. 启动容器并安装安全工具
docker run -it --name kali-claw-env kalilinux/kali-rolling /bin/bash
# 在容器内执行：
apt update && apt install -y nmap sqlmap nikto hydra metasploit-framework

# 3. 退出容器后，以后用以下命令重新进入
docker start -ai kali-claw-env
```

kali-claw 工作空间在宿主机上，通过卷挂载或 SSH 连接到容器。

### 2.4 环境检查清单

在继续之前，确认以下各项：

- [ ] Node.js >= 18 已安装（`node --version`）
- [ ] OpenClaw 已安装（`npm list -g openclaw` 或 `openclaw --version`）
- [ ] Kali Linux 可用（本机 / SSH 远程 / Docker 容器均可）
- [ ] 基本 Kali 工具可用（运行 `nmap --version` 验证）
- [ ] 网络连接正常（智能体需要联网获取信息）

---

## 三、安装与初始化

### 3.1 安装 OpenClaw

```bash
npm install -g openclaw@latest
```

**验证安装**：

```bash
openclaw --version
```

**常见问题**：

| 问题 | 解决方案 |
|------|---------|
| 权限不足 (EACCES) | 使用 `sudo npm install -g openclaw@latest` |
| npm 镜像超时（国内用户） | `npm config set registry https://registry.npmmirror.com` |
| Node.js 版本过低 | 使用 nvm 安装最新 LTS |

### 3.2 创建专用智能体

```bash
openclaw agents add kali-claw --workspace ~/.openclaw/workspace-kali-claw
```

**为什么要创建专用智能体（而不是用 main）**：

- **独立工作空间** — kali-claw 的记忆、技能、配置与其他智能体完全隔离
- **独立记忆** — 渗透测试知识不会被其他智能体的对话覆盖
- **独立配置** — 可以单独设置模型、权限、路由
- **独立管理** — 可以单独启停、更新、重置

### 3.3 克隆 kali-claw 工作空间

```bash
cd ~/.openclaw/workspace-kali-claw/
git clone https://github.com/brucesongs/kali-claw.git .
```

**注意末尾的点号（.）** — 它表示克隆到当前目录，而不是创建子目录。

**验证克隆成功**：

```bash
ls -la
```

应看到以下文件和目录：

```
SOUL.md           CHANGELOG.md      MEMORY.md
AGENTS.md         CLAUDE.md         TOOLS.md
IDENTITY.md       HEARTBEAT.md      README.md
USER.md           LICENSE           VERSION
skills/           validation/       memory/
chronicle/        docs/             bak/
GUIDE-OPENCLAW-zh.md   GUIDE-OPENCLAW-en.md
RELEASE-v0.1.X.md（每个版本一份发布说明）
```

### 3.4 首次配置（4 个文件必须修改）

克隆完成后，**必须修改以下 4 个文件**，让智能体知道你是谁、它应该扮演什么角色。

#### 文件一：USER.md — 填写你的信息

```markdown
# 修改前（默认值）
## Basic Info
- **Name**: kali-claw
- **Title**: Captain
- **Timezone**: Asia/Shanghai (CST)
- **Language Preference**: Chinese primary, technical terms in English

# --------------------------------

# 修改后（你的实际信息，示例）
## Basic Info
- **Name**: Alex
- **Title**: Captain
- **Timezone**: America/New_York (EST)
- **Language Preference**: English primary

## Key Interests
- Bug Bounty Hunting
- Web Application Security
- CTF Competitions
- Python Security Tools

## Current Focus
- Preparing for OSCP certification
- Learning SQL injection and XSS techniques
- Building a home lab with DVWA and Juice Shop

## Preferences & Style
- **Technical Communication**: Step-by-step with commands
- **Learning Style**: Theory first, then hands-on
- **Problem Solving**: Discuss approach first, then execute
```

#### 文件二：SOUL.md — 修改昵称和角色描述

```markdown
# 修改前（默认值，位于 "Identity" 部分）
- **Nickname**: kali-claw
- **Role**: Senior Penetration Testing Engineer -- Master of all Kali Linux security tools

# --------------------------------

# 修改后（示例）
- **Nickname**: pentest-buddy
- **Role**: Security Learning Assistant -- Helping me master penetration testing step by step
```

> 注意：只修改 Identity 部分的昵称和角色描述，**不要修改 12 条黑客法则**，它们是通用的安全思维框架。

#### 文件三：IDENTITY.md — 调整技能标签

IDENTITY.md 中的技能标签表格（v0.1.39 有 111 行）决定了智能体的"能力图谱"。你可以：

- **删除不需要的技能行** — 比如不关心 WiFi 渗透测试，就删掉 Wireless Security 行
- **添加自定义技能** — 在表格中添加新的领域

```markdown
# 示例：如果你只关注 Web 安全和代码审计，只保留这些行：

| Domain | Core Capabilities | Related Laws |
|--------|-------------------|--------------|
| Web Security | SQL injection, XSS, SSRF, auth bypass, access control | Trust but Verify, Minimize Attack Surface |
| API Security | REST/GraphQL testing, auth bypass, rate limiting | Trust but Verify |
| Security Review | OWASP Top 10 audit, source code audit, dependency scan | Trust but Verify, Minimize Attack Surface |
| Repo Scan | Codebase security, library detection, secret scanning | First Principles, Trust but Verify |
| Search First | Exploit/tool search, existing solution discovery | Information Wants to Be Free |
```

#### 文件四：AGENTS.md — 更新智能体配置块

```markdown
# 修改前（默认值，位于 "Agent Config" 部分）
- **Agent Name**: kali-claw
- **Runtime Environment**: Kali Linux
- **Role**: Penetration Testing Engineer
- **Specialty**: Security tools + penetration testing + vulnerability research
- **Work Mode**: 24/7 Continuous

# --------------------------------

# 修改后（示例）
- **Agent Name**: pentest-buddy
- **Runtime Environment**: Kali Linux (remote SSH at 192.168.1.100)
- **Role**: Security Learning Assistant
- **Specialty**: Web penetration testing + vulnerability discovery
- **Work Mode**: On-demand
```

### 3.5 启动并验证

```bash
openclaw gateway start
```

启动后，在网关中发送测试消息验证智能体正常：

```
> 你好，请介绍一下你自己
```

智能体应该回复包含你修改后的昵称、角色描述以及技能概览。

```
> 你记得我的名字和偏好是什么吗？
```

智能体应该能从 USER.md 中读取并正确回答。

### 3.6 运行质量评分（可选但推荐）

克隆完成后，可以运行一次评分脚本，确认所有技能都到位：

```bash
bash validation/SCORE.sh
```

这会生成所有 111 个技能域的 JSON 评分文件到 `validation/evidence/quality-scores/`。如果你计划自己改造技能，这套分数能帮你定位薄弱环节。

---

## 四、核心概念详解

### 4.1 技能系统

kali-claw 拥有 **111 个技能域**，按攻击面/防御面/能力类型大致分为 8 大类：

**Web 与 API 攻击**

| 技能域 | 说明 |
|--------|------|
| web-sqli / web-xss / web-ssrf | 经典 Web 三件套（含 CSP 绕过、云元数据 SSRF） |
| web-auth-bypass / web-access-control | 认证绕过、IDOR、OAuth/JWT 攻击 |
| web-xxe / web-deserialization / file-inclusion | XML 外部实体、Java/PHP/.NET 反序列化、LFI/RFI |
| cms-framework-attack | WordPress/Joomla/Drupal 渗透 |
| api-security | REST/GraphQL、速率限制、参数篡改 |
| email-security-deep | AiTM 钓鱼、邮件网关绕过（Proofpoint/Mimecast）、CVE-2024-21413 |
| browser-qa | Playwright/Puppeteer 自动化浏览器安全测试 |

**网络与基础设施**

| 技能域 | 说明 |
|--------|------|
| network-pentest / recon-osint | 扫描、利用、横向移动、子域名枚举 |
| network-sniffing-mitm / network-tunneling-proxy | 流量劫持、SSH/DNS/ICMP 隧道、SOCKS 代理链 |
| dns-attacks | DNS 重绑定、SAD DNS、DoH/DoT/DoQ 隧道、子域名接管 |
| vpn-attack / sase-sse-attack | 传统 VPN + 现代边缘（Zscaler / Netskope / Cloudflare One / Cisco Umbrella） |
| email-protocol-attack | SMTP 枚举、SPF/DKIM/DMARC 绕过 |
| voip-sip-attack | SIP 偷听、VLAN hopping |

**身份与企业栈**

| 技能域 | 说明 |
|--------|------|
| ad-ldap-attack | AD/LDAP/Kerberos（AS-REP Roasting、Kerberoasting、DCSync、PTH） |
| ad-cs-abuse | AD 证书服务 ESC1-ESC15、PetitPotam、Certifried (CVE-2022-26923) |
| cloud-identity-attack | Entra ID / Okta / Auth0、PRT 盗窃、Golden SAML |
| pam-privilege-attack | CyberArk / BeyondTrust / Delinea / ManageEngine / WALLIX 等 8 大 PAM 厂商 |
| ci-cd-supply-chain-attack | Jenkins、GitLab CI、GitHub Actions、Argo CD、xz-utils / SolarWinds / 3CX 复盘 |
| cspm-casb-attack | Wiz / Prisma Cloud / Netskope、OPA/Kyverno 策略绕过 |

**云与容器**

| 技能域 | 说明 |
|--------|------|
| cloud-security | AWS/Azure/GCP、IAM、S3 暴露、元数据攻击 |
| container-security / kubernetes-attack | Docker 逃逸、K8s RBAC、Pod Escape、runc CVE-2024-21626 |
| cloud-native-vuln-research | CVE 方法论、PoC 复现、nuclei 模板 |
| secret-management-attack | gitleaks/semgrep/trufflehog、Vault/CI-CD/registry 利用 |

**密码学与新兴技术**

| 技能域 | 说明 |
|--------|------|
| crypto-attacks | 弱算法、Padding Oracle、TLS 问题、后量子迁移、KyberSlash |
| quantum-crypto-attack | NIST PQC、混合 TLS、QKD/BB84、SM2/3/4 国密 |
| blockchain-web3 | 智能合约审计、DeFi 重入、跨链桥、MEV、ERC-777 |
| llm-red-team / ai-security / ai-agent-security | LLM 越狱（GCG/AutoDAN/Crescendo）、MCP 投毒、RAG 投毒 |
| agentic-pentest | PentestGPT、HexStrike、多智能体团队协调 |

**移动 / 物联网 / 嵌入式 / 硬件**

| 技能域 | 说明 |
|--------|------|
| mobile-security / mobile-app-instrumentation | iOS/Android、SSL Pinning 绕过、Frida/Objection/r2frida |
| iot-pentest | MQTT、CoAP、AMQP、IoT 云后端 |
| firmware-reverse / hardware-security | 固件提取、JTAG/UART、侧信道 |
| embedded-rtos-security | VxWorks / QNX / FreeRTOS / ThreadX / Zephyr |
| bluetooth-rfid-nfc | BLE GATT、MIFARE、NFC 克隆 |

**关键基础设施与物理**

| 技能域 | 说明 |
|--------|------|
| scada-ics-security / ics-fieldbus-attack | Modbus、S7comm、EtherNet/IP、OPC UA、Profibus、DNP3、IEC 61850 |
| storage-san-attack | iSCSI/FC/NFSv4/SMB3/S3、NetApp/Dell EMC/QNAP/Synology/TrueNAS |
| hypervisor-introspection | VMware ESXi / Hyper-V / KVM / Xen、LibVMI / DRAKVUF、VENOM |
| satellite-leo-security | Starlink / Iridium / Viasat KA-SAT、DVB-S2 / VSAT、AcidRain |
| sdr-rf-attack / hf-vhf-radio-attack | ADS-B、AIS、ACARS、POCSAG、APRS |
| 5g-telecom-attack | PFCP、GTP、IMSI catchers、O-RAN |
| automotive-vehicle-security | CAN/UDS、key fobs、EV charging |
| uav-drone-security | MAVLink、PX4、GPS 欺骗、DroneID |
| physical-security-testing | 锁具绕过、RFID 克隆、USB 武器（Ducky/Bunny） |
| mainframe-security | z/OS / RACF / CICS / DB2 / JES2 |
| game-anticheat-bypass | EAC / BattlEye / Vanguard / BYOVD |

**防御 / 取证 / 元能力**

| 技能域 | 说明 |
|--------|------|
| digital-forensics / anti-forensics | 磁盘/内存/网络取证、反取证 |
| threat-hunting / detection-engineering | 假设驱动狩猎、Sigma/YARA、ATT&CK 检测工程 |
| deception-honeypot | SSH/Web/ICS/AI 蜜罐、honeytoken |
| pentest-reporting / article-writing | Dradis/Faraday、CVSS 评分、CVE 披露 |
| engagement-manager | 授权渗透全生命周期、范围管理、证据链 |
| security-review / repo-scan | OWASP Top 10、源码审计、依赖扫描 |
| security-bounty-hunter | Bug Bounty、PoC 开发、负责任披露 |
| codebase-onboarding / knowledge-ops | 快速理解陌生代码库、知识图谱管理 |
| exa-search / deep-research / data-scraper-agent | 多源情报综合、CVE 抓取、语义搜索 |
| autonomous-loops / multi-agent-collaboration / council | 自主编排、多视角分析（攻击/防御/审计三方） |
| safety-guard / terminal-ops / search-first / verification-loop | 安全守卫、终端操作、先搜索再利用、多阶段验证 |
| docker-patterns / continuous-learning / chronicle / tool-mastery / mcp-server-patterns | 实验室、持续学习、编年史、工具精通、MCP 集成 |

**技能结构** — 每个技能域包含以下文件（符合 Agent Skills Open Standard）：

```
skills/web-sqli/
+-- SKILL.md          <-- 技能定义（含 YAML frontmatter）
+-- payloads.md       <-- 攻击载荷和命令
+-- test-cases.md     <-- 结构化测试用例
+-- guides/           <-- 深度学习材料（多个文件）
```

**SKILL.md 的渐进式披露（Progressive Disclosure）** — 这是 Agent Skills 开放标准的核心设计：

- **Stage 1（广告）** — YAML frontmatter + `## Summary` —— 在技能扫描时加载
- **Stage 2（快速参考）** — `## Core Tools` + `## Methodology` —— 在技能激活时加载
- **Stage 3（详细）** — `## Practical Steps` + `## Defense Perspective` —— 在任务执行时加载

这种设计让智能体在不需要时只看 frontmatter，需要时再逐层加载详细内容，节省 token 又保证深度。

**如何触发技能** — 不需要手动调用！用自然语言描述任务，智能体自动匹配技能：

```
用户：帮我扫描 192.168.1.0/24 网段的开放端口

--> 智能体匹配到 network-pentest + terminal-ops 技能
--> 自动选择 nmap 作为工具
--> 执行扫描并分析结果
--> 给出端口/服务/潜在风险的报告
```

**ECC 编排模式**简介 — 复杂任务时，智能体会组合多个技能，采用以下 6 种编排模式之一：

1. **Sequential Pipeline** — 按顺序依次执行（侦察 -> 扫描 -> 利用 -> 后渗透）
2. **Watch Loop** — 持续监控循环（等待特定条件触发）
3. **Batch Processing** — 批量处理多个目标
4. **Learning Cycle** — 学习-实践-验证循环
5. **Meta-Skill** — 一个技能调用多个子技能
6. **Cross-cutting Interceptor** — 贯穿全程的拦截器（如 safety-guard）

### 4.2 记忆系统

kali-claw 的记忆系统是 **三层架构**，从底层到顶层越来越精炼：

**第一层：每日日志** `memory/YYYY-MM-DD.md`

- 记录每天做了什么、发现了什么、学了什么
- 原始且详细，类似工作笔记
- 自动创建，智能体每次会话都会写入

**第二层：月度编年史** `chronicle/YYYY-MM/*.md`

- 从每日日志中提炼重要里程碑
- 记录关键决策、突破性发现、重要的经验教训
- 每月一个文件

**第三层：长期精炼知识** `MEMORY.md`（根目录）

- 从所有记忆中提炼的核心知识
- 记录工具偏好、方法论、关键决策、长期经验
- 只在主会话中加载（群聊中不会泄露）

**自动蒸馏流程**：

```
每日日志 (memory/)
    |  定期提炼
    v
月度编年史 (chronicle/)
    |  进一步精炼
    v
长期记忆 (MEMORY.md)
```

越往上越精炼，越往下越详细。

**如何查看记忆**：

- 直接打开文件查看（它们都是 Markdown 格式）
- 或者问智能体："你记得我们上次做了什么吗？"
- 智能体会自动读取记忆文件并回答

### 4.3 心跳系统（HEARTBEAT.md）

心跳是智能体的 **自动维护机制**，定期执行以下 4 类任务：

| 优先级 | 任务类型 | 具体内容 |
|--------|---------|---------|
| 1（最高） | 安全检查 | 检查 alerts.txt、验证核心文件完整性、检查敏感信息泄露 |
| 2 | 健康检查 | 系统资源、配置文件完整性、备份时效性 |
| 3 | 学习进度 | 学习进度追踪、推进下一个工具学习 |
| 4 | 知识维护 | 清理旧日志、提炼知识到 MEMORY.md、更新技能文件 |

**执行规则**：

- 每次心跳只执行 1-2 项任务，轮换执行，避免过载
- 结果记录在 `memory/heartbeat-check-YYYYMMDDHHMM.md`
- 发现异常时立即记录到 `memory/alerts.txt` 并通知用户

**配套脚本** — `validation/heartbeat.sh` 提供命令行版的健康检查：

```bash
bash validation/heartbeat.sh          # 一次检查
bash validation/heartbeat.sh --fix    # 检查并尝试自动修复
bash validation/heartbeat.sh --json   # JSON 输出（适合接入监控）
```

**如何自定义心跳** — 编辑 `HEARTBEAT.md`：

- 调整检查频率：修改执行规则
- 添加新的检查项：在对应分类下添加
- 修改优先级：调整任务顺序

### 4.4 工具知识库（TOOLS.md）

TOOLS.md 是智能体的 **工具能力清单**：

- **518 个 Kali 工具**按 65+ 个类别追踪
- 每个工具记录：掌握状态、学习笔记、使用经验
- 智能体通过 TOOLS.md 了解自己会什么、还不会什么

**工具状态**：

| 状态 | 含义 |
|------|------|
| 已掌握 | 熟练使用，可作为主力工具 |
| 学习中 | 正在学习，基本功能可用 |
| 待学习 | 尚未开始学习 |

**如何添加新工具** — 在 TOOLS.md 的 Category Index 表格中添加一行：

```markdown
| My Custom Tools | 2 | Learning | Custom Python scripts for recon |
```

### 4.5 质量评分体系（SCORE.sh v2）

这是 v0.1.11 引入、v0.1.16 升级到 v2 的核心子系统，让"技能是否够好"变成客观可量化的指标。

**4 个加权组件**：

| 组件 | 权重 | 评分来源 | 含义 |
|------|------|----------|------|
| SKILL.md | 15% | `##` 标题数量 | 结构深度 |
| payloads.md | 30% | 词数 + 段落数 + 代码块数（取平均） | 攻击载荷全面性 |
| test-cases.md | 30% | 测试用例数 + 字段完整度（取平均） | 测试可执行性 |
| guides/ | 25% | 文件数（40%）+ 平均词数（30%）+ 关键段落（30%） | 深度材料 |

**5 级分层**（v2 引入 Distinguished）：

| 等级 | 分数 | v0.1.39 数量 |
|------|------|--------------|
| Distinguished | 92 - 100 | 33 |
| Excellent | 80 - 91.9 | 78 |
| Strong | 60 - 79.9 | 0 |
| Adequate | 40 - 59.9 | 0 |
| Weak | 0 - 39.9 | 0 |

**运行评分**：

```bash
bash validation/SCORE.sh                # 全量评分 111 个技能
bash validation/SCORE.sh --skill web-sqli  # 单技能评分
```

结果写入 `validation/evidence/quality-scores/<skill>.json`，每个 JSON 包含组件明细分。

**典型用途**：

- 改造完一个技能后跑分，确认提升幅度
- 找出最低分技能，确定补强优先级
- 在 PR 中附上分数变化作为客观证据

详细方法论见 `validation/SCORING-METHODOLOGY.md`。

### 4.6 自动化与编排脚本（validation/）

`validation/` 目录是 kali-claw 的"工具箱"——10+ 个 Bash 脚本覆盖运维、编排、报告全流程：

| 脚本 | 作用 | 常用参数 |
|------|------|----------|
| `heartbeat.sh` | 工作空间健康检查 | `--fix` `--json` |
| `auto-backup.sh` | 备份轮换 | `--restore` `--keep N` |
| `drift-detect.sh` | 配置漂移检测 | `--create-baseline` `--update-baseline` |
| `scenario-runner.sh` | 跨技能场景执行 | `--resume` `--dry-run` |
| `orchestrator.sh` | 端到端渗透测试工作流 | `--target` `--phase` `--resume` |
| `tool-selector.sh` | 目标 → 工具智能映射 | `--target-type` `--phase` `--stealth` |
| `report-generator.sh` | 自动生成渗透测试报告 | `--source` `--format` |
| `SCORE.sh` | 质量评分引擎（见 4.5） | `--skill <name>` |
| `update-skill-standard.py` | SKILL.md 对齐 Agent Skills 标准 | `--dry-run` `--skill <name>` |

**典型端到端示例**（编排脚本）：

```bash
# 自动跑完侦察 → 扫描 → 利用 → 后渗透 → 报告
bash validation/orchestrator.sh --target 10.10.10.10 --phase full

# 中断后续跑
bash validation/orchestrator.sh --target 10.10.10.10 --resume
```

**授权渗透模板** — `validation/engagement-template/` 提供：

- `targets.json.example` — 目标范围配置模板
- `scope-rules.json.example` — 范围规则与安全约束
- `report-template.md` — 标准渗透报告模板

### 4.7 Engagement 工作流

`engagement-manager` 技能 + `validation/engagement-template/` 一起，提供完整的 **授权渗透测试生命周期管理**：

```
1. 范围确认（scope-rules.json）     --> 明确能打什么、不能打什么
2. 目标登记（targets.json）         --> 列出 IP/域名/资产
3. 侦察 + 扫描                       --> recon-osint + network-pentest
4. 漏洞利用                          --> 对应攻击技能（web-sqli / ad-cs-abuse 等）
5. 后渗透                            --> post-exploitation + privilege-escalation
6. 证据收集                          --> pentest-reporting + 截图/日志
7. 报告生成                          --> report-generator.sh
8. 复盘                              --> 写入 chronicle/ + MEMORY.md
```

每一步都会写入 `memory/YYYY-MM-DD.md`，重要的里程碑提炼到 `chronicle/`，长期决策进入 `MEMORY.md`。

---

## 五、使用场景示例

### 5.1 渗透测试全流程

以下是一个完整的渗透测试对话示例，展示 kali-claw 在每个阶段的作用：

**第一阶段：侦察**

```
用户：帮我收集 target.com 的信息，包括子域名、DNS 记录和技术栈

智能体：好的，我来对 target.com 进行全面的侦察。我会使用以下方法：
1. DNS 记录查询（dig）
2. 子域名枚举（sublist3r + assetfinder）
3. Web 技术指纹识别（whatweb）
4. WHOIS 信息查询

执行中...

[结果汇总]
- 主域名: target.com -> 93.184.216.34
- 子域名: 发现 12 个活跃子域名
  - api.target.com (REST API)
  - admin.target.com (登录页面)
  - dev.target.com (开发环境)
- 技术栈: Nginx 1.18, PHP 7.4, MySQL
- DNS: 使用 Cloudflare CDN

建议下一步: 对发现的子域名进行端口扫描
```

**第二阶段：扫描**

```
用户：扫描所有发现的子域名，重点看 admin.target.com

智能体：使用 nmap 对 admin.target.com 进行全端口扫描和服务识别：

nmap -sV -sC -p- admin.target.com

[扫描结果]
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.2
80/tcp   open   http       Nginx 1.18.0
443/tcp  open   ssl/http   Nginx 1.18.0
3306/tcp closed mysql
8080/tcp open   http-proxy PHP-FPM 7.4

发现: 8080 端口运行 PHP-FPM，可能存在未授权访问。
建议: 对 admin.target.com:8080 进行目录扫描和漏洞探测。
```

**第三阶段：漏洞利用**

```
用户：admin.target.com:8080 有一个登录页面，帮我测试一下有没有 SQL 注入

智能体：对登录页面进行 SQL 注入测试。

步骤 1: 识别注入点 -- 测试用户名和密码字段
步骤 2: 使用 sqlmap 进行自动化检测
步骤 3: 尝试 Union-based 和 Blind-based 注入

sqlmap -u "http://admin.target.com:8080/login" \
  --data="username=admin&password=test" \
  --method POST --level 3 --risk 2

[结果]
发现 SQL 注入漏洞！
- 注入点: username 参数
- 类型: Boolean-based blind SQL injection
- 数据库: MySQL 5.7
- 当前用户: root@localhost

安全提醒: 这是授权测试范围内的操作。建议立即记录并报告此漏洞。
```

**第四阶段：后渗透**

```
用户：拿到了数据库访问权限，接下来怎么做？

智能体：获得数据库访问后，建议按以下步骤进行后渗透评估：

1. 信息收集（在数据库内）:
   - 列出所有数据库和表
   - 查找敏感数据（用户表、配置表）
   - 检查数据库用户权限

2. 提权评估:
   - 检查 FILE 权限（可能读写系统文件）
   - 尝试通过 UDF 执行系统命令

3. 持久化评估:
   - 记录所有发现的攻击路径
   - 评估每条路径的检测难度

注意: 所有操作仅用于评估和报告目的。
```

**第五阶段：报告**

```
用户：帮我整理今天的发现，生成一份渗透测试报告

智能体：根据今天的测试活动，生成以下报告结构：

## 渗透测试报告 -- target.com

### 1. 执行摘要
- 测试日期: 2026-05-18
- 目标范围: target.com 及子域名
- 总体风险等级: 高危

### 2. 发现摘要
| # | 漏洞 | 严重程度 | 影响 |
|---|------|---------|------|
| 1 | SQL 注入 (admin.target.com) | 严重 | 数据库完全控制 |
| 2 | 开发环境暴露 (dev.target.com) | 中 | 信息泄露 |
| 3 | 8080 端口未限制访问 | 中 | 攻击面扩大 |

### 3. 详细发现
[每个漏洞的详细描述、复现步骤、修复建议]

### 4. 修复建议（按优先级）
1. 立即修复 SQL 注入 -- 使用参数化查询
2. 关闭 dev 环境的公网访问
3. 限制 8080 端口仅内网访问
```

### 5.2 安全审计

```
用户：帮我审计这个 Web 应用的安全性，URL 是 http://testphp.vulnweb.com

智能体：我来按照 OWASP Top 10 对这个应用进行系统性安全审计。

审计范围:
A01 - Broken Access Control
A02 - Cryptographic Failures
A03 - Injection
A04 - Insecure Design
A05 - Security Misconfiguration
A06 - Vulnerable Components
A07 - Auth Failures
A08 - Data Integrity Failures
A09 - Logging/Monitoring Failures
A10 - SSRF

[逐项检查...]

审计结果:
- A03 Injection: 发现 SQL 注入和 XSS 漏洞
- A05 Security Misconfiguration: 默认配置未修改，错误信息暴露堆栈
- A07 Auth Failures: 登录无速率限制，可暴力破解
- A01 Access Control: 存在 IDOR，可越权访问其他用户数据

总体评分: 高风险
建议优先修复 Injection 和 Access Control 问题。
```

### 5.3 学习与研究

```
用户：我想学习 SQL 注入，从哪里开始？

智能体：我来帮你制定 SQL 注入的学习路径。

第一步: 理论基础
- SQL 注入原理: 用户输入被直接拼接到 SQL 查询中
- 注入类型: Union-based / Boolean-blind / Time-blind / Error-based

第二步: 搭建练习环境
我来帮你用 Docker 启动一个 sqli-labs 靶场：

docker run -d -p 80:80 acgpiano/sqli-labs

第三步: 从最简单的开始
- Less-1: 基于 Union 的字符型注入（入门）
- Less-5: 基于 Boolean 的盲注（进阶）
- Less-15: 基于时间的盲注（高级）

每个关卡我会解释原理、给出提示、然后让你自己尝试。

准备好了吗？我们先从 Less-1 开始。
```

### 5.4 团队协作

**Council 多视角分析** — 让智能体从不同角色分析同一个安全问题：

```
用户：用 council 模式分析一下 admin.target.com 的 SQL 注入漏洞

智能体：启动 Council 多视角分析：

[攻击者视角]
- 可以利用 SQL 注入获取数据库完整控制
- 通过 FILE 权限可能实现 RCE
- 建议测试: 写入 WebShell、读取 /etc/passwd

[防御者视角]
- 根本原因: 未使用参数化查询
- 修复方案: 使用预处理语句 + WAF 规则
- 检测方案: 监控异常 SQL 查询模式

[审计者视角]
- CVSS 评分: 9.8 (Critical)
- 合规影响: 违反 OWASP A03、PCI-DSS 6.5
- 报告建议: 需要书面记录完整攻击链

综合建议: 立即修复，同时检查其他页面是否存在同类问题。
```

### 5.5 现代企业攻击链（v0.1.39 新增能力示例）

v0.1.39 补齐了 PAM、CI/CD、CSPM/CASB、SASE/SSE 4 个现代企业安全栈领域，现在可以推演完整的勒索家族攻击链：

```
用户：用 kali-claw 推演一下 BlackCat 勒索从初始访问到加密的完整攻击链

智能体：基于 Mandiant 2023 + CrowdStrike 2024 报告，BlackCat 的典型路径如下：

阶段 1: 初始访问（sase-sse-attack / email-security-deep）
- 绕过 Zscaler ZIA 出口检查，钓鱼邮件落地
- AiTM 钓鱼（evilginx2）窃取 MFA 凭据

阶段 2: 身份渗透（cloud-identity-attack）
- Entra ID PRT 盗窃 → Conditional Access 绕过
- 通过 ROADtools 拿到合法 refresh token

阶段 3: 凭据中枢（pam-privilege-attack）
- 用窃取的凭据登录 CyberArk PVWA
- 利用 CVE-2025-32564 认证绕过，提权到 Vault Admin
- 从 .cue cred file 还原明文密码 → 拿下所有域管理员账号

阶段 4: 横向移动（ad-cs-abuse / ad-ldap-attack）
- ESC1 滥用 → 申请 Domain Controller 证书
- Pass-the-Hash + Kerberoasting 横向到所有域控

阶段 5: 持久化（ci-cd-supply-chain-attack）
- 在 Jenkins 共享库植入后门
- 修改 GitHub Actions workflow 窃取所有 secrets
- 用依赖混淆植入恶意 npm 包

阶段 6: 防御规避（cspm-casb-attack）
- 篡改 Terraform state 让 Wiz 图谱看不到真实配置
- 用 OPA Rego 大小写陷阱绕过 Kyverno 策略

阶段 7: 数据外发 + 加密部署（storage-san-attack）
- 通过 NetApp NDMP 快照窃取
- 用窃取的凭据登录 Dell EMC Unity 删除备份
- 部署 BlackCat 加密器

每一步对应 kali-claw 中的一个技能域，可以在 skills/<域>/payloads.md 找到具体 TTP 和命令。
```

---

## 六、进阶配置

### 6.1 MCP 工具集成

**MCP（Model Context Protocol）** 是一种让 AI 智能体调用外部工具的标准协议。kali-claw 包含 `mcp-server-patterns` 技能，可以帮你将 Kali 工具包装为 MCP 服务器。

**示例：将 nmap 包装为 MCP 工具**

1. 智能体读取 `skills/mcp-server-patterns/SKILL.md` 了解 MCP 服务器设计模式
2. 按照模式创建 nmap 的 MCP 服务器包装
3. 配置后，智能体可以直接通过 MCP 调用 nmap，而不需要通过终端命令

**适用场景**：

- 需要频繁调用特定工具时
- 需要将工具能力暴露给其他智能体时
- 需要对工具调用进行标准化管理时

### 6.2 自定义技能

按照以下步骤创建新的技能域（**符合 Agent Skills Open Standard**）：

**第一步：创建目录**

```bash
mkdir -p ~/.openclaw/workspace-kali-claw/skills/my-custom-skill/guides
```

**第二步：编写 SKILL.md（含 YAML frontmatter）**

```markdown
---
name: my-custom-skill
description: Brief one-line description for skill matching
compatibility: >= 0.1.39
allowed-tools:
  - Bash
  - Read
  - Write
metadata:
  category: custom
  domain: reconnaissance
  mitre:
    - T1595 Active Scanning
  tools:
    - nmap
    - masscan
---

# my-custom-skill

## Summary
[一句话总结这个技能解决什么问题]

## Description
[详细描述这个技能是什么、做什么]

## Use Cases
- 用例 1: ...
- 用例 2: ...

## Core Tools
- tool1: 用途说明
- tool2: 用途说明

## Methodology
1. 步骤一
2. 步骤二
3. 步骤三

## Practical Steps
[详细可执行步骤]

## Defense Perspective
[蓝队如何检测与防御]

## Orchestration
[与其他技能如何配合]
```

**第三步：编写 payloads.md**

```markdown
# Payloads - my-custom-skill

## Type 1: 场景 A
命令/载荷示例...

## Type 2: 场景 B
命令/载荷示例...
```

**第四步：编写 test-cases.md**

```markdown
# Test Cases - my-custom-skill

## TC-001: 测试场景名称
- **Target**: 测试目标
- **Steps**:
  1. 步骤一
  2. 步骤二
- **Expected**: 预期结果
- **Actual**: [待填写]
- **Status**: [Pass/Fail]
```

**第五步（推荐）：创建 guides/ 目录**

```bash
mkdir -p ~/.openclaw/workspace-kali-claw/skills/my-custom-skill/guides
# 在 guides/ 中放入深度学习材料（建议 1-3 个文件）
```

**第六步：用标准对齐脚本生成 frontmatter（可选）**

```bash
python3 validation/update-skill-standard.py --skill my-custom-skill --dry-run
# 检查无误后去掉 --dry-run 实际写入
```

**第七步：在 IDENTITY.md 添加技能标签**

```markdown
| My Custom Skill | 自定义能力描述 | First Principles |
```

**第八步：在 TOOLS.md 添加相关工具**

```markdown
| My Custom Tools | 3 | Learning | Custom scripts and utilities |
```

**第九步：跑分验证**

```bash
bash validation/SCORE.sh --skill my-custom-skill
# 目标：至少达到 Excellent (80+)，理想是 Distinguished (92+)
```

### 6.3 自定义行为

**修改 12 条黑客法则**（SOUL.md）：

你可以根据需要增删改法则。例如添加一条新法则：

```markdown
### 13. Document Everything
Every finding must be recorded with evidence. If it's not documented, it didn't happen.
```

**调整心跳任务**（HEARTBEAT.md）：

在对应的分类下添加新的检查项：

```markdown
## Security Check
- [ ] Check memory/alerts.txt for new security alerts
- [ ] Verify core files haven't been tampered with
- [ ] 新增：检查 Docker 容器安全状态
```

**修改会话启动流程**（AGENTS.md）：

在 "Every Session" 部分添加新的启动步骤：

```markdown
## Every Session
1. Read SOUL.md
2. Read USER.md
3. Read memory/YYYY-MM-DD.md
4. Read MEMORY.md
5. 新增：Read TOOLS.md（检查工具学习进度）
```

---

## 七、版本演进与里程碑

### 7.1 主要版本回顾

kali-claw 采用"**扩面 ↔ 质量**"交替迭代的节奏，每个版本都有明确主题：

| 阶段 | 版本 | 关键里程碑 |
|------|------|------------|
| 基础建设 | v0.1.1 - v0.1.7 | 45 → 49 技能域，建立分层架构 |
| 全量丰富 | v0.1.8 - v0.1.10 | 49/49 全部 FULL enrichment，集成测试 7/7 PASS |
| **质量评分引入** | v0.1.11 - v0.1.14 | SCORE.sh v1，49/49 Excellent 100% |
| **质量评分 v2** | v0.1.15 - v0.1.17 | Distinguished 等级引入，TEMPLATE.md |
| **领域扩面 1** | v0.1.18 - v0.1.21 | 49 → 70 技能域（exploit-dev / privesc / payload-gen / AV-EDR / DNS / XXE / LFI / CMS / stego / bluetooth / firmware / SCADA / DB / VoIP / anti-forensics / AD-LDAP / web-deserialization / email） |
| **Distinguished 冲刺** | v0.1.22 - v0.1.27 | 5 → 17 Distinguished |
| **领域扩面 2** | v0.1.28 - v0.1.31 | 70 → 91 技能域（darkweb / threat-hunting / blockchain / payment / llm-red-team / honeypot / k8s / secret-mgmt / ai-agent / iot / detection-eng / agentic-pentest / cloud-identity / physical / quantum / email-deep） |
| **100% Excellent+** | v0.1.32 | 91/91 全部 Excellent+，零 Strong |
| **GitHub Trending 扩面** | v0.1.33 - v0.1.35 | 91 → 103（5G / automotive / mobile-deep / cloud-native-vuln / macOS / UAV / game-anticheat / mainframe / ICS-fieldbus / HF/VHF / blockchain-L2 / RTOS） |
| **质量提升 E 计划** | v0.1.36 | 19 → 28 Distinguished（+9） |
| **Wave 7 扩面** | v0.1.37 | 103 → 107（storage-SAN / hypervisor / satellite-LEO / AD CS） |
| **E 计划再发力** | v0.1.38 | 28 → 32 Distinguished，首次破 30，最低分 85.1（质量债务清零） |
| **Wave 8 扩面（当前）** | **v0.1.39** | **107 → 111**（CI/CD 供应链 / PAM / CSPM-CASB / SASE-SSE），首次出现"新技能基线即 Distinguished"（pam-privilege-attack 92.0） |

### 7.2 当前质量快照（v0.1.39）

| 等级 | 数量 | 代表技能 |
|------|------|----------|
| **Distinguished (92+)** | **33** | secret-management-attack (94.6) · social-intelligence (93.8) · sdr-rf-attack (93.6) · article-writing (93.6) · deep-research (93.5) · payload-generation (93.1) · scada-ics-security (93.0) · ad-cs-abuse (93.0) · vulnerability-assessment (93.0) · 5g-telecom-attack (92.7) · embedded-rtos-security (92.7) · agentic-pentest (92.6) · autonomous-loops (92.6) · verification-loop (92.6) · quantum-crypto-attack (92.5) · osint (92.5) · vpn-attack (92.5) · ai-security (92.3) · council (92.3) · network-tunneling-proxy (92.3) · crypto-attacks (92.2) · macos-security (92.2) · username-profiling (92.2) · web-deserialization (92.2) · cloud-security (92.1) · hf-vhf-radio-attack (92.1) · email-security-deep (92.0) · network-pentest (92.0) · security-bounty-hunter (92.0) · pam-privilege-attack (92.0) · security-misconfiguration (92.8) · container-security (92.8) · web-xss (92.0) |
| **Excellent (80-91.9)** | **78** | storage-san-attack (91.5) · dns-attacks (91.1) · kubernetes-attack (90.2) · blockchain-web3 (90.2) · cloud-identity-attack (89.0) · ci-cd-supply-chain-attack (89.2) · cspm-casb-attack (88.5) · sase-sse-attack (88.2) · ... |
| Strong (60-80) | **0** | — |
| Adequate (40-60) | **0** | — |
| Weak (0-40) | **0** | — |

**平均分：88.78** | **111/111 Excellent+（100%）** | **33 Distinguished**

### 7.3 下一版本（v0.1.40）方向

按"扩面 ↔ 质量"交替节奏，v0.1.40 很可能回到 **质量提升路线**，候选方向：

- **A 轨 Distinguished 冲刺** — 还有 7 个技能卡在 89-91.9（storage-san-attack 91.5、dns-attacks 91.1、blockchain-web3 90.2、kubernetes-attack 90.2、darkweb-intel 89.2、av-edr-evasion 89.1、cloud-identity-attack 89.0），每个加 1 个 guide 大多能进 92+
- **底部提升** — 5 个技能卡在 85-86（chronicle 85.1、cloud-native-vuln-research 85.2、email-protocol-attack 85.2、game-anticheat-bypass 85.2、multi-agent-collaboration 85.4），拉到 88+ 让最低分再上一台阶
- **Wave 8 cohort 深化** — 给 ci-cd-supply-chain-attack、cspm-casb-attack、sase-sse-attack 各加第 2 个 guide
- **扩面第 9 波** — 候选方向包括 GitOps 安全、QKD 攻击、Open Banking/PSD2、HSM 攻击、CPS 网络物理系统

---

## 八、常见问题（FAQ）

### Q1: npm install -g openclaw 报权限错误

**症状**：`EACCES: permission denied`

**原因**：npm 全局安装目录需要 root 权限

**解决**：

```bash
# 方案一：使用 sudo
sudo npm install -g openclaw@latest

# 方案二（推荐）：修改 npm 全局路径
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
npm install -g openclaw@latest
```

### Q2: openclaw gateway start 连接失败

**症状**：`Connection refused` 或 `ECONNREFUSED`

**排查步骤**：

```bash
# 1. 检查 Node.js 版本
node --version  # 需要 >= 18

# 2. 检查端口是否被占用
lsof -i :3000  # 或 netstat -tlnp | grep 3000

# 3. 检查防火墙
sudo ufw status
# 如果启用了防火墙，放行端口：
sudo ufw allow 3000

# 4. 尝试指定端口启动
openclaw gateway start --port 8080
```

### Q3: 智能体说找不到 nmap/sqlmap 等工具

**症状**：智能体报错 `command not found: nmap`

**排查步骤**：

```bash
# 1. 确认工具已安装
which nmap
nmap --version

# 2. 如果未安装
sudo apt update && sudo apt install -y nmap

# 3. 如果使用远程 Kali，测试 SSH 连接
ssh user@kali-host "which nmap"
# 如果连接失败，检查 SSH 密钥配置

# 4. 如果使用 Docker，进入容器安装
docker exec -it kali-claw-env bash -c "apt install -y nmap"
```

### Q4: 技能没有被触发

**症状**：智能体没有使用正确的技能来处理任务

**解决方案**：

- 使用更明确的指令，比如 "用 SQL 注入测试这个登录页面" 而不是 "看看这个页面安全吗"
- 在指令中直接提到技能名称，比如 "用 web-sqli 技能测试..."
- 检查 IDENTITY.md 中是否包含对应的技能标签
- 检查 SKILL.md frontmatter 的 `description` 字段是否清晰（这是技能匹配的关键）

### Q5: 记忆丢失了

**症状**：智能体不记得之前的对话内容

**排查**：

```bash
# 1. 检查 memory/ 目录是否有日志文件
ls -la ~/.openclaw/workspace-kali-claw/memory/

# 2. 检查 MEMORY.md 是否存在
cat ~/.openclaw/workspace-kali-claw/MEMORY.md

# 3. 检查文件权限
chmod 644 ~/.openclaw/workspace-kali-claw/memory/*.md
```

**注意**：每次新会话智能体会重新加载记忆文件。如果文件在，记忆就在。

### Q6: 如何重置智能体（清空所有记忆）

```bash
cd ~/.openclaw/workspace-kali-claw/

# 清空每日记忆
rm -f memory/*.md memory/alerts.txt

# 清空编年史
rm -rf chronicle/

# 清空长期记忆
echo "# MEMORY.md - Long-term Distilled Knowledge" > MEMORY.md
```

智能体的人格和技能不受影响，只清除记忆数据。

### Q7: 如何更新到最新版本

```bash
cd ~/.openclaw/workspace-kali-claw/

# 拉取最新代码（会获取新的技能和配置更新）
git pull origin main

# 注意：这不会覆盖你的 USER.md 修改
# 如果有冲突，手动解决即可

# 拉取后跑一次质量评分，确认所有技能到位
bash validation/SCORE.sh
```

### Q8: 可以在非 Kali 系统上用吗

**可以**，但安全工具的执行需要以下方案之一：

- **SSH 远程**：OpenClaw 在 Mac/Windows 上，通过 SSH 连接远程 Kali（推荐）
- **Docker**：在非 Kali 系统上运行 Kali Docker 容器
- **WSL**：Windows 上使用 WSL 安装 Kali

智能体的知识库（技能、方法论、攻击载荷）在任何系统上都能使用。只是执行具体工具时需要 Kali 环境。

### Q9: 如何贡献新技能或改进

1. Fork 仓库，创建特性分支
2. 按"6.2 自定义技能"流程创建技能域
3. 运行 `bash validation/SCORE.sh --skill <你的技能>`，确保达到 Excellent (80+)
4. 提交 PR，附上分数证据和 1-2 个真实场景测试结果

PR 模板参见仓库根目录的 README.md。

### Q10: 如何知道哪些技能最强 / 最需要改进

```bash
# 查看所有技能分数（从高到低）
cat validation/QUALITY-SCORE-TRACKER.md

# 或检查单个技能
cat validation/evidence/quality-scores/<skill-name>.json
```

JSON 中包含 4 个组件的明细分（skill_md / payloads_md / test_cases_md / guides），让你能精确看到短板在哪。

---

## 九、核心文件参考

| 文件 | 作用 | 何时修改 |
|------|------|---------|
| `SOUL.md` | 智能体人格、12 条黑客法则、行为准则 | 自定义人格 / 增删法则 |
| `AGENTS.md` | 工作空间配置、会话启动流程 | 调整智能体名称 / 修改启动流程 |
| `IDENTITY.md` | 技能标签表（111 行）、性格特质 | 添加/删除技能域 |
| `USER.md` | 用户信息、偏好、当前关注点 | 首次配置 / 信息变更 |
| `MEMORY.md` | 长期精炼知识、关键决策 | 一般不手动修改 |
| `TOOLS.md` | 518 工具的学习进度和笔记 | 添加新工具 / 更新进度 |
| `HEARTBEAT.md` | 心跳自动化任务定义 | 调整检查频率和内容 |
| `CHANGELOG.md` | 全部版本变更日志 | 一般不手动修改 |
| `skills/` | 111 个技能域目录 | 添加新技能 / 更新现有技能 |
| `validation/` | 自动化脚本套件（SCORE.sh、orchestrator.sh 等） | 调整评分权重 / 添加新场景 |
| `validation/engagement-template/` | 授权渗透模板（targets/scope/report） | 新增 engagement 类型 |
| `memory/` | 每日记忆日志（YYYY-MM-DD.md） | 一般不手动修改 |
| `chronicle/` | 月度里程碑记录 | 一般不手动修改 |
| `docs/` | 长篇设计文档与规划 | 重大架构变更时 |
| `RELEASE-v0.1.X.md` | 每个版本的发布公告 | 一般不手动修改 |

**首次使用只需修改 4 个文件**：USER.md、SOUL.md、IDENTITY.md、AGENTS.md（见第三章第 4 节）。

其他文件是智能体自动维护的，通常不需要手动修改。

---

_Built with the OpenClaw Agent Framework. 当前版本 v0.1.39（111 技能域、33 Distinguished）。如有问题，请在 GitHub Issues 中反馈。_
