# OpenClaw + kali-claw 完整使用指南

> 面向 v0.1.8 | 从零开始，手把手教你搭建和使用 AI 渗透测试代理

---

## 一、概念理解

### 1.1 OpenClaw 是什么

OpenClaw 是一个 **AI 代理运行框架**，通过 npm 安装，提供以下核心能力：

- **代理管理** — 创建、列表、删除 AI 代理（`openclaw agents add/list/remove`）
- **独立工作空间** — 每个代理拥有独立的文件目录，互不干扰
- **网关服务** — 提供统一的对话入口（`openclaw gateway start`）
- **会话管理** — 自动加载工作空间中的配置和记忆文件
- **心跳轮询** — 定期触发代理执行自动化任务

**类比理解**：如果把 OpenClaw 想象成手机操作系统（比如 iOS），那 kali-claw 就是一个安装在上面的 App。操作系统提供运行环境和管理能力，App 提供具体功能。

### 1.2 kali-claw 是什么

kali-claw 是基于 OpenClaw 框架的 **预构建渗透测试代理工作空间**。它不是一个传统的软件代码仓库，而是一个 **Markdown 格式的知识库 + 配置系统**。

核心组成：

- **49 个安全技能域** — 覆盖 Web 安全、网络渗透、密码攻击、云安全等
- **518 个 Kali Linux 工具知识库** — 从 nmap 到 sqlmap，从 burpsuite 到 metasploit
- **12 条黑客法则** — 定义代理的思维方式（第一性原理、发散思维、最小攻击面等）
- **三层记忆系统** — 每日日志 / 月度编年史 / 长期精炼知识

**与直接使用 ChatGPT/Claude 的区别**：

| 特性 | ChatGPT/Claude | kali-claw |
|------|----------------|-----------|
| 持久记忆 | 无（每次对话从零开始） | 有（文件级记忆系统） |
| 技能体系 | 无 | 49 个领域、结构化技能 |
| 工具执行 | 不能直接执行命令 | 可调用 Kali Linux 安全工具 |
| 人格一致性 | 无 | SOUL.md 定义固定人格 |
| 学习进化 | 无 | 通过记忆和心跳持续学习 |

### 1.3 整体架构

```
用户
  |
  v
OpenClaw Gateway（网关服务）
  |
  v
kali-claw 工作空间
  +-- SOUL.md          <-- 代理人格（是谁、怎么思考）
  +-- USER.md          <-- 用户信息（帮助谁、什么偏好）
  +-- IDENTITY.md      <-- 技能标签（会什么、性格特质）
  +-- AGENTS.md        <-- 工作空间配置 + 会话启动流程
  +-- MEMORY.md        <-- 长期精炼知识
  +-- TOOLS.md         <-- 518 工具学习进度
  +-- HEARTBEAT.md     <-- 心跳自动化任务
  +-- skills/          <-- 49 个技能域
  |   +-- web-sqli/
  |   |   +-- SKILL.md     <-- 技能定义
  |   |   +-- payloads.md  <-- 攻击载荷
  |   |   +-- test-cases.md<-- 测试用例
  |   |   +-- guides/      <-- 深度指南
  |   +-- network-pentest/
  |   +-- osint/
  |   +-- ... (共 49 个)
  +-- memory/          <-- 每日记忆日志
  +-- chronicle/       <-- 月度里程碑
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

---

## 二、环境准备

### 2.1 方案 A：Kali Linux 本机运行（推荐）

**最简单的方案**：直接在 Kali Linux 上安装 OpenClaw，代理可以直接调用所有安全工具。

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
- [ ] 网络连接正常（代理需要联网获取信息）

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

### 3.2 创建专用代理

```bash
openclaw agents add kali-claw --workspace ~/.openclaw/workspace-kali-claw
```

**为什么要创建专用代理（而不是用 main）**：

- **独立工作空间** — kali-claw 的记忆、技能、配置与其他代理完全隔离
- **独立记忆** — 渗透测试知识不会被其他代理的对话覆盖
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
SOUL.md
AGENTS.md
IDENTITY.md
USER.md
MEMORY.md
TOOLS.md
HEARTBEAT.md
skills/
memory/
chronicle/
```

### 3.4 首次配置（4 个文件必须修改）

克隆完成后，**必须修改以下 4 个文件**，让代理知道你是谁、它应该扮演什么角色。

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

IDENTITY.md 中的技能标签表格决定了代理的"能力图谱"。你可以：

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

#### 文件四：AGENTS.md — 更新代理配置块

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

启动后，在网关中发送测试消息验证代理正常：

```
> 你好，请介绍一下你自己
```

代理应该回复包含你修改后的昵称、角色描述以及技能概览。

```
> 你记得我的名字和偏好是什么吗？
```

代理应该能从 USER.md 中读取并正确回答。

---

## 四、核心概念详解

### 4.1 技能系统

kali-claw 拥有 **49 个技能域**，按类型分为以下几大类：

**攻击技能**：

| 技能域 | 说明 |
|--------|------|
| web-sqli | SQL 注入（Union/Blind/Time-based/Double Query） |
| web-xss | 跨站脚本攻击（Reflected/Stored/DOM-based/CSP bypass） |
| web-ssrf | 服务端请求伪造（内网扫描/云元数据/协议走私） |
| web-auth-bypass | 认证绕过（暴力破解/会话攻击/OAuth 缺陷） |
| web-access-control | 访问控制突破（IDOR/权限提升/强制浏览） |
| network-pentest | 网络渗透测试（扫描/利用/横向移动） |
| password-attack | 密码攻击（字典/规则暴力/哈希破解） |
| post-exploitation | 后渗透（持久化/提权/数据窃取） |
| wifi-pentest | WiFi 渗透（WPA 破解/WPS 攻击/Evil Twin） |
| crypto-attacks | 加密攻击（弱算法/证书问题/填充预言） |

**防御与分析技能**：

| 技能域 | 说明 |
|--------|------|
| security-review | OWASP Top 10 安全审计 |
| verification-loop | 多阶段漏洞验证 |
| docker-patterns | Docker 安全测试实验室 |
| digital-forensics | 数字取证 |
| container-security | 容器和 K8s 安全 |
| cloud-security | AWS/Azure/GCP 云安全 |

**知识与研究技能**：

| 技能域 | 说明 |
|--------|------|
| osint | 开源情报收集 |
| recon-osint | 侦察与 OSINT |
| deep-research | 多源情报综合研究 |
| search-first | 先搜索再利用 |
| repo-scan | 源代码安全审计 |
| social-intelligence | 社交平台情报 |

**元技能（协调其他技能）**：

| 技能域 | 说明 |
|--------|------|
| autonomous-loops | 自主执行模式（顺序流水线/监控循环/批量处理） |
| council | 多视角分析（攻击者/防御者/审计者三重视角） |
| multi-agent-collaboration | 多代理协作 |
| ai-fuzzing | AI 辅助漏洞发现 |

**基础设施技能**：

| 技能域 | 说明 |
|--------|------|
| safety-guard | 安全守卫（范围检查/危险命令拦截） |
| terminal-ops | 终端操作（结构化命令执行） |
| chronicle | 编年史记录 |
| continuous-learning | 持续学习 |
| mcp-server-patterns | MCP 服务器集成模式 |

**技能结构** — 每个技能域包含以下文件：

```
skills/web-sqli/
+-- SKILL.md          <-- 技能定义、用例、方法论、工具
+-- payloads.md       <-- 攻击载荷和命令
+-- test-cases.md     <-- 结构化测试用例
+-- guides/           <-- 深度学习材料
```

**如何触发技能** — 不需要手动调用！用自然语言描述任务，代理自动匹配技能：

```
用户：帮我扫描 192.168.1.0/24 网段的开放端口

--> 代理匹配到 network-pentest + terminal-ops 技能
--> 自动选择 nmap 作为工具
--> 执行扫描并分析结果
--> 给出端口/服务/潜在风险的报告
```

**ECC 编排模式**简介 — 复杂任务时，代理会组合多个技能，采用以下 6 种编排模式之一：

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
- 自动创建，代理每次会话都会写入

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
- 或者问代理："你记得我们上次做了什么吗？"
- 代理会自动读取记忆文件并回答

### 4.3 心跳系统（HEARTBEAT.md）

心跳是代理的 **自动维护机制**，定期执行以下 4 类任务：

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

**如何自定义心跳** — 编辑 `HEARTBEAT.md`：

- 调整检查频率：修改执行规则
- 添加新的检查项：在对应分类下添加
- 修改优先级：调整任务顺序

### 4.4 工具知识库（TOOLS.md）

TOOLS.md 是代理的 **工具能力清单**：

- **518 个 Kali 工具**按 65 个类别追踪
- 每个工具记录：掌握状态、学习笔记、使用经验
- 代理通过 TOOLS.md 了解自己会什么、还不会什么

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

---

## 五、使用场景示例

### 5.1 渗透测试全流程

以下是一个完整的渗透测试对话示例，展示 kali-claw 在每个阶段的作用：

**第一阶段：侦察**

```
用户：帮我收集 target.com 的信息，包括子域名、DNS 记录和技术栈

代理：好的，我来对 target.com 进行全面的侦察。我会使用以下方法：
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

代理：使用 nmap 对 admin.target.com 进行全端口扫描和服务识别：

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

代理：对登录页面进行 SQL 注入测试。

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

代理：获得数据库访问后，建议按以下步骤进行后渗透评估：

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

代理：根据今天的测试活动，生成以下报告结构：

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

代理：我来按照 OWASP Top 10 对这个应用进行系统性安全审计。

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

代理：我来帮你制定 SQL 注入的学习路径。

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

**Council 多视角分析** — 让代理从不同角色分析同一个安全问题：

```
用户：用 council 模式分析一下 admin.target.com 的 SQL 注入漏洞

代理：启动 Council 多视角分析：

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

---

## 六、进阶配置

### 6.1 MCP 工具集成

**MCP（Model Context Protocol）** 是一种让 AI 代理调用外部工具的标准协议。kali-claw 包含 `mcp-server-patterns` 技能，可以帮你将 Kali 工具包装为 MCP 服务器。

**示例：将 nmap 包装为 MCP 工具**

1. 代理读取 `skills/mcp-server-patterns/SKILL.md` 了解 MCP 服务器设计模式
2. 按照模式创建 nmap 的 MCP 服务器包装
3. 配置后，代理可以直接通过 MCP 调用 nmap，而不需要通过终端命令

**适用场景**：

- 需要频繁调用特定工具时
- 需要将工具能力暴露给其他代理时
- 需要对工具调用进行标准化管理时

### 6.2 自定义技能

按照以下步骤创建新的技能域：

**第一步：创建目录**

```bash
mkdir -p ~/.openclaw/workspace-kali-claw/skills/my-custom-skill
```

**第二步：编写 SKILL.md**

```markdown
# my-custom-skill

## Description
[描述这个技能是什么、做什么]

## Use Cases
- 用例 1: ...
- 用例 2: ...

## Methodology
1. 步骤一
2. 步骤二
3. 步骤三

## Tools
- tool1: 用途说明
- tool2: 用途说明

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

**第五步（可选）：创建 guides/ 目录**

```bash
mkdir -p ~/.openclaw/workspace-kali-claw/skills/my-custom-skill/guides
# 在 guides/ 中放入深度学习材料
```

**第六步：在 IDENTITY.md 添加技能标签**

```markdown
| My Custom Skill | 自定义能力描述 | First Principles |
```

**第七步：在 TOOLS.md 添加相关工具**

```markdown
| My Custom Tools | 3 | Learning | Custom scripts and utilities |
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

## 七、常见问题（FAQ）

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

### Q3: 代理说找不到 nmap/sqlmap 等工具

**症状**：代理报错 `command not found: nmap`

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

**症状**：代理没有使用正确的技能来处理任务

**解决方案**：

- 使用更明确的指令，比如 "用 SQL 注入测试这个登录页面" 而不是 "看看这个页面安全吗"
- 在指令中直接提到技能名称，比如 "用 web-sqli 技能测试..."
- 检查 IDENTITY.md 中是否包含对应的技能标签

### Q5: 记忆丢失了

**症状**：代理不记得之前的对话内容

**排查**：

```bash
# 1. 检查 memory/ 目录是否有日志文件
ls -la ~/.openclaw/workspace-kali-claw/memory/

# 2. 检查 MEMORY.md 是否存在
cat ~/.openclaw/workspace-kali-claw/MEMORY.md

# 3. 检查文件权限
chmod 644 ~/.openclaw/workspace-kali-claw/memory/*.md
```

**注意**：每次新会话代理会重新加载记忆文件。如果文件在，记忆就在。

### Q6: 如何重置代理（清空所有记忆）

```bash
cd ~/.openclaw/workspace-kali-claw/

# 清空每日记忆
rm -f memory/*.md memory/alerts.txt

# 清空编年史
rm -rf chronicle/

# 清空长期记忆
echo "# MEMORY.md - Long-term Distilled Knowledge" > MEMORY.md
```

代理的人格和技能不受影响，只清除记忆数据。

### Q7: 如何更新到最新版本

```bash
cd ~/.openclaw/workspace-kali-claw/

# 拉取最新代码（会获取新的技能和配置更新）
git pull origin main

# 注意：这不会覆盖你的 USER.md 修改
# 如果有冲突，手动解决即可
```

### Q8: 可以在非 Kali 系统上用吗

**可以**，但安全工具的执行需要以下方案之一：

- **SSH 远程**：OpenClaw 在 Mac/Windows 上，通过 SSH 连接远程 Kali（推荐）
- **Docker**：在非 Kali 系统上运行 Kali Docker 容器
- **WSL**：Windows 上使用 WSL 安装 Kali

代理的知识库（技能、方法论、攻击载荷）在任何系统上都能使用。只是执行具体工具时需要 Kali 环境。

---

## 八、核心文件参考

| 文件 | 作用 | 何时修改 |
|------|------|---------|
| `SOUL.md` | 代理人格、12 条黑客法则、行为准则 | 自定义人格 / 增删法则 |
| `AGENTS.md` | 工作空间配置、会话启动流程 | 调整代理名称 / 修改启动流程 |
| `IDENTITY.md` | 技能标签表、性格特质 | 添加/删除技能域 |
| `USER.md` | 用户信息、偏好、当前关注点 | 首次配置 / 信息变更 |
| `MEMORY.md` | 长期精炼知识、关键决策 | 一般不手动修改 |
| `TOOLS.md` | 518 工具的学习进度和笔记 | 添加新工具 / 更新进度 |
| `HEARTBEAT.md` | 心跳自动化任务定义 | 调整检查频率和内容 |
| `skills/` | 49 个技能域目录 | 添加新技能 / 更新现有技能 |
| `memory/` | 每日记忆日志（YYYY-MM-DD.md） | 一般不手动修改 |
| `chronicle/` | 月度里程碑记录 | 一般不手动修改 |

**首次使用只需修改 4 个文件**：USER.md、SOUL.md、IDENTITY.md、AGENTS.md（见第三章第 4 节）。

其他文件是代理自动维护的，通常不需要手动修改。

---

_Built with the OpenClaw Agent Framework. 如有问题，请在 GitHub Issues 中反馈。_
