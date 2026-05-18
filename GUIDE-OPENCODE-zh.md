# kali-claw 技能包使用指南：在 OpenCode 上运行

> 面向 kali-claw v0.1.7 + OpenCode 最新版 | 从零开始，手把手教你将 kali-claw 技能包迁移到 OpenCode 平台

---

## 一、概述

### 1.1 OpenCode 是什么

[OpenCode](https://github.com/opencode-ai/opencode) 是一个**开源、终端式的 AI 编码智能体**，使用 Go 语言编写。它提供文本用户界面（TUI），可以理解、编辑和执行代码项目。

核心能力：
# kali-claw 技能包使用指南：在 OpenCode 上运行

> 面向 kali-claw v0.1.7 + OpenCode 最新版 | 从零开始，手把手教你将 kali-claw 技能包迁移到 OpenCode 平台

---

## 一、概述

### 1.1 OpenCode 是什么

[OpenCode](https://github.com/opencode-ai/opencode) 是一个**开源、终端式的 AI 编码智能体**，使用 Go 语言编写。它提供文本用户界面（TUI），可以理解、编辑和执行代码项目。

核心能力：

- **多 AI 提供商支持** — OpenAI、Anthropic、Google、Ollama 本地模型，模型无关设计
- **项目级配置** — 通过 `opencode.json` 定义模型、指令、命令、MCP 工具
- **指令文件系统** — 读取 `AGENTS.md` 等项目文件作为 AI 行为指南
- **MCP 工具集成** — 支持 Model Context Protocol，扩展 AI 能力边界
- **自定义命令** — 定义常用操作的快捷命令
- **终端 TUI 界面** — 实时交互，文件编辑，Shell 命令执行

### 1.2 与其他 AI 编码平台的对比

| 特性 | OpenClaw | Claude Code | OpenCode | Codex CLI | Cursor |
|------|----------|-------------|----------|-----------|--------|
| 开源 | 是 | 否 | 是 | 是 | 否 |
| 模型支持 | Claude | 仅 Claude | 多模型 | OpenAI | 多模型 |
| 运行方式 | 网关服务 | CLI + TUI | TUI | CLI | IDE 插件 |
| MCP 支持 | 否 | 是 | 是 | 否 | 否 |
| 项目指令 | MD 文件 | CLAUDE.md | AGENTS.md + 自定义 | 无 | .cursorrules |
| 自定义命令 | 无 | 无 | 有 | 无 | 无 |
| 安装方式 | npm | npm | Go / 脚本 | npm | 桌面应用 |
| 语言 | TypeScript | TypeScript | Go | TypeScript | Electron |

**为什么选择 OpenCode**：

- **完全开源** — 可审计、可定制、无供应商锁定
- **模型无关** — 不绑定单一 AI 提供商，随时切换
- **MCP 生态** — 通过 MCP 协议接入安全工具（nmap、sqlmap 等）
- **Go 高性能** — 编译为单一二进制，启动快，资源占用低
- **自定义命令** — 可预定义渗透测试流程命令

### 1.3 kali-claw 技能包如何适配 OpenCode

kali-claw 的技能包是**纯 Markdown 文件**，不依赖任何特定框架。OpenCode 可以通过项目级配置读取这些文件，让 AI 理解和使用 kali-claw 的完整知识体系。

关键适配点：

| kali-claw 组件 | OpenCode 对应 | 说明 |
|----------------|---------------|------|
| SOUL.md | 项目指令文件 | 提取核心身份和黑客法则写入项目指令 |
| AGENTS.md | OpenCode AGENTS.md | OpenCode 原生支持读取 AGENTS.md |
| skills/*/SKILL.md | 项目文件（按需读取） | AI 可直接读取，无需修改 |
| skills/*/payloads.md | 项目文件（按需读取） | AI 可直接读取，无需修改 |
| skills/*/test-cases.md | 项目文件（按需读取） | AI 可直接读取，无需修改 |
| skills/*/guides/ | 项目文件（按需读取） | AI 可直接读取，无需修改 |

**核心原则**：skills/ 目录中的所有文件**保持原位，不做任何修改**。迁移是指配置 OpenCode 来读取和使用这些现有文件。

### 1.4 三种迁移策略

根据你的时间预算和需求深度，选择合适的迁移方式：

| 策略 | 耗时 | 适合场景 | 你将获得 |
|------|------|----------|----------|
| **最小迁移** | 5 分钟 | 快速体验、临时使用 | 基本 AI + kali-claw 文件访问 |
| **标准迁移** | 30 分钟 | 日常使用、渗透测试 | 完整角色定义 + 技能索引 + 安全边界 |
| **完整迁移** | 2 小时 | 专业团队、生产环境 | MCP 工具集成 + 自定义命令 + 多模型 |

---

## 二、环境准备

### 2.1 安装 OpenCode

**方式一：官方安装脚本（推荐）**

```bash
curl -fsSL https://opencode.ai/install | bash
```

**方式二：Go install**

```bash
go install github.com/opencode-ai/opencode@latest
```

**方式三：手动下载二进制**

```bash
# Linux (amd64)
curl -fsSL https://github.com/opencode-ai/opencode/releases/latest/download/opencode-linux-amd64 -o /usr/local/bin/opencode
chmod +x /usr/local/bin/opencode

# Linux (arm64)
curl -fsSL https://github.com/opencode-ai/opencode/releases/latest/download/opencode-linux-arm64 -o /usr/local/bin/opencode
chmod +x /usr/local/bin/opencode

# macOS (Apple Silicon)
curl -fsSL https://github.com/opencode-ai/opencode/releases/latest/download/opencode-darwin-arm64 -o /usr/local/bin/opencode
chmod +x /usr/local/bin/opencode

# macOS (Intel)
curl -fsSL https://github.com/opencode-ai/opencode/releases/latest/download/opencode-darwin-amd64 -o /usr/local/bin/opencode
chmod +x /usr/local/bin/opencode
```

**验证安装**

```bash
opencode --version
```

### 2.2 配置 AI 提供商

OpenCode 支持多种 AI 提供商。选择你需要的一个或多个进行配置：

**Anthropic（推荐用于安全任务）**

```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

**OpenAI**

```bash
export OPENAI_API_KEY="sk-your-key-here"
```

**本地 Ollama（离线场景）**

```bash
# 安装 Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 拉取模型
ollama pull llama3
ollama pull codellama

# 无需 API key，Ollama 默认监听 localhost:11434
```

> **提示**：建议将 API Key 写入 shell 配置文件（`~/.zshrc` 或 `~/.bashrc`）使其持久化：
> ```bash
> echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.zshrc
> source ~/.zshrc
> ```

### 2.3 准备 Kali Linux 环境

kali-claw 的安全工具需要在 Kali Linux 上运行。选择以下方案之一：

**方案一：本机 Kali Linux（最佳体验）**

```bash
# 直接在 Kali Linux 上操作，无需额外配置
uname -a  # 确认是 Kali Linux
```

**方案二：通过 SSH 连接远程 Kali**

```bash
# 在本地机器上配置 SSH 免密登录
ssh-keygen -t ed25519
ssh-copy-id user@kali-server-ip

# 测试连接
ssh user@kali-server-ip "nmap --version"
```

**方案三：Docker 容器（推荐用于隔离测试）**

```bash
# 拉取 Kali Docker 镜像
docker pull kalilinux/kali-rolling

# 启动容器并安装安全工具
docker run -it --name kali-claw-env kalilinux/kali-rolling /bin/bash
apt update && apt install -y nmap sqlmap nikto hydra metasploit-framework

# 后续连接
docker start -ai kali-claw-env
```

### 2.4 克隆 kali-claw 工作空间

```bash
# 克隆到你的工作目录
git clone https://github.com/<repo-path>.git ~/kali-claw
cd ~/kali-claw

# 确认目录结构
ls -la
# 应该看到: SOUL.md  AGENTS.md  IDENTITY.md  USER.md  MEMORY.md  TOOLS.md  HEARTBEAT.md  skills/  memory/  chronicle/
```

---

## 三、方式一：最小迁移（5 分钟）

如果你只想快速体验 kali-claw 技能包在 OpenCode 上的效果，这是最快的方式。

### 3.1 启动 OpenCode

```bash
cd ~/kali-claw
opencode
```

OpenCode 会在当前目录启动 TUI 界面，并自动检测项目文件。

### 3.2 使用示例

启动后，在 OpenCode 的输入框中直接输入指令。以下是几个多轮对话示例：

**示例一：SQL 注入测试**

```
你: 请读取 skills/web-sqli/SKILL.md，然后帮我制定一个针对 DVWA 靶场的 SQL 注入测试计划。

AI: [读取 skills/web-sqli/SKILL.md 文件后]
    根据 kali-claw 的 SQL 注入技能，以下是 DVWA 测试计划：

    1. **检测注入点**：在 User ID 输入框测试单引号 `1'`
    2. **判断列数**：`1' ORDER BY N-- -`
    3. **UNION 注入**：`1' UNION SELECT 1,2-- -`
    4. **提取数据**：获取数据库版本、表名、用户数据

    详细 payload 参见 skills/web-sqli/payloads.md

你: 很好，请读取 payloads.md，给我 DVWA Low 级别的完整测试命令。

AI: [读取 skills/web-sqli/payloads.md 后]
    DVWA Low 级别（无过滤）测试命令：

    # 检测注入
    curl "http://target/dvwa/vulnerabilities/sqli/?id=1'&Submit=Submit" \
      --cookie "security=low; PHPSESSID=xxx"

    # 列数判断
    curl "http://target/dvwa/vulnerabilities/sqli/?id=1' ORDER BY 2-- -&Submit=Submit" \
      --cookie "security=low; PHPSESSID=xxx"

    # UNION 注入提取用户
    curl "http://target/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- -&Submit=Submit" \
      --cookie "security=low; PHPSESSID=xxx"
```

**示例二：网络渗透**

```
你: 读取 skills/network-pentest/SKILL.md，对 192.168.1.0/24 网段进行侦察。

AI: [读取技能文件后]
    根据 kali-claw 网络渗透方法论，侦察阶段如下：

    # 第一步：主机发现
    sudo arp-scan -l
    # 或者
    nmap -sn 192.168.1.0/24

    # 第二步：端口扫描（对发现的主机）
    nmap -sV -sC -O 192.168.1.100

    # 第三步：服务枚举
    enum4linux -a 192.168.1.100

    需要我执行这些命令吗？注意：我只在授权范围内操作。

你: 执行第一步和第二步。

AI: [执行命令并返回结果]
    ...
```

**示例三：学习安全工具**

```
你: 读取 skills/password-attack/SKILL.md，教我如何使用 hydra 进行密码审计。

AI: [读取技能文件后]
    根据 kali-claw 密码攻击技能，hydra 使用方法如下：

    ## 基础语法
    hydra -l <用户名> -P <字典文件> <目标> <协议>

    ## FTP 密码审计
    hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.1.100

    ## SSH 密码审计
    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

    ## HTTP POST 表单
    hydra -l admin -P wordlist.txt 192.168.1.100 http-post-form \
      "/login:user=^USER^&pass=^PASS^:Invalid login"

    详细 payload 参见 skills/password-attack/payloads.md
```

### 3.3 局限性

最小迁移的局限：

- **无持久角色** — AI 不知道自己是 kali-claw，每次需要手动指定读取技能文件
- **无安全边界** — 不会自动遵循 12 条黑客法则和操作边界
- **无技能索引** — AI 不知道有哪些技能域可用，需要你手动指定路径
- **无自动加载** — 不会自动读取 SOUL.md 和 MEMORY.md

如果你需要更完整的体验，请继续阅读"标准迁移"。

---

## 四、方式二：标准迁移（30 分钟）

标准迁移通过配置 `opencode.json` 和项目指令文件，让 OpenCode 自动理解 kali-claw 的角色、技能体系和安全边界。

### 4.1 创建 opencode.json 配置

在 kali-claw 项目根目录创建 `opencode.json`：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-sonnet-4-20250514",
  "small_model": "anthropic/claude-3-5-haiku-latest",
  "default_agent": "kali-claw",
  "shell": "/bin/bash",
  "logLevel": "INFO",
  "share": "disabled",
  "autoupdate": "notify",
  "snapshot": true,
  "instructions": [
    "AGENTS.md",
    ".opencode/instructions.md"
  ],

  "agent": {
    "kali-claw": {
      "model": "anthropic/claude-sonnet-4-20250514",
      "description": "kali-claw 渗透测试工程师 — 掌握全部 518 个 Kali Linux 安全工具的高级智能体",
      "permission": {
        "edit": "ask",
        "bash": {
          "nmap *": "allow",
          "sqlmap *": "allow",
          "nikto *": "allow",
          "hydra *": "allow",
          "curl *": "allow",
          "dig *": "allow",
          "whois *": "allow",
          "whatweb *": "allow",
          "gobuster *": "allow",
          "dirb *": "allow",
          "wpscan *": "allow",
          "enum4linux *": "allow",
          "arp-scan *": "allow",
          "tcpdump *": "ask",
          "msfconsole *": "ask",
          "bettercap *": "ask",
          "responder *": "ask",
          "rm *": "deny",
          "*": "ask"
        }
      }
    },
    "kali-claw-audit": {
      "model": "anthropic/claude-sonnet-4-20250514",
      "description": "kali-claw 安全审计模式 — 只读分析，不执行攻击操作",
      "permission": {
        "edit": "deny",
        "bash": {
          "nmap *": "allow",
          "sqlmap *": "allow",
          "curl *": "allow",
          "dig *": "allow",
          "whois *": "allow",
          "whatweb *": "allow",
          "cat *": "allow",
          "head *": "allow",
          "ls *": "allow",
          "rm *": "deny",
          "*": "ask"
        }
      }
    }
  },

  "command": {
    "recon": {
      "template": "读取 skills/network-pentest/SKILL.md 和 skills/osint/SKILL.md，对以下目标执行信息收集和侦察：\n\n目标：$ARGUMENTS\n\n按照 kali-claw 攻击链方法论执行：\n1. 被动信息收集（OSINT）\n2. 主动扫描（端口/服务识别）\n3. 结果汇总\n\n注意：仅在授权范围内操作。",
      "description": "对目标执行侦察（OSINT + 网络扫描）"
    },
    "web-pentest": {
      "template": "读取以下技能文件，对目标执行 Web 渗透测试：\n- skills/web-sqli/SKILL.md\n- skills/web-xss/SKILL.md\n- skills/web-ssrf/SKILL.md\n- skills/web-auth-bypass/SKILL.md\n- skills/web-access-control/SKILL.md\n\n目标：$ARGUMENTS\n\n按照攻击链执行：\n1. 技术栈指纹识别\n2. SQL 注入测试\n3. XSS 测试\n4. SSRF 测试\n5. 认证绕过测试\n6. 访问控制测试\n7. 生成测试报告",
      "description": "对目标执行 Web 应用渗透测试"
    },
    "sqli": {
      "template": "读取 skills/web-sqli/SKILL.md 和 skills/web-sqli/payloads.md，对目标执行 SQL 注入测试。\n\n目标：$ARGUMENTS\n\n执行完整的 SQL 注入测试流程：\n1. 注入点检测\n2. 数据库指纹识别\n3. 注入类型判断\n4. 数据提取\n5. 生成测试报告",
      "description": "对目标执行 SQL 注入测试"
    },
    "network-attack": {
      "template": "读取 skills/network-pentest/SKILL.md 和 skills/network-pentest/payloads.md，对目标网络执行渗透测试。\n\n目标：$ARGUMENTS\n\n按照完整攻击链执行：\n1. 网络发现\n2. 端口扫描\n3. 服务指纹识别\n4. 漏洞评估\n5. 漏洞利用（仅在授权范围内）\n6. 后渗透检查\n7. 生成报告",
      "description": "对目标网络执行渗透测试"
    },
    "password-audit": {
      "template": "读取 skills/password-attack/SKILL.md 和 skills/password-attack/payloads.md，对目标执行密码安全审计。\n\n目标：$ARGUMENTS\n\n执行密码审计流程：\n1. 服务识别（确定协议类型）\n2. 字典选择\n3. 在线密码测试\n4. 离线哈希破解（如有哈希）\n5. 密码强度分析\n6. 生成审计报告",
      "description": "对目标执行密码安全审计"
    },
    "learn": {
      "template": "读取以下技能文件，为我详细讲解该安全领域的知识：\n\n技能：$ARGUMENTS\n\n请覆盖以下内容：\n1. 领域概述和核心概念\n2. 常见攻击技术和原理\n3. 防御策略\n4. 工具使用方法和实战示例\n5. 练习建议和靶场推荐",
      "description": "学习某个安全技能领域（如：web-sqli、network-pentest、password-attack）"
    },
    "security-review": {
      "template": "读取 skills/security-review/SKILL.md 和 skills/repo-scan/SKILL.md，对目标项目执行安全代码审查。\n\n目标：$ARGUMENTS\n\n执行安全审查流程：\n1. OWASP Top 10 检查清单\n2. 源码安全扫描\n3. 依赖项漏洞检查\n4. 密钥/凭据泄露检测\n5. 注入漏洞检查\n6. 认证/授权审查\n7. 生成安全审查报告",
      "description": "对项目执行安全代码审查"
    }
  },

  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "{env:ANTHROPIC_API_KEY}"
      }
    }
  },

  "permission": {
    "edit": "ask",
    "bash": {
      "rm *": "deny",
      "rm -rf *": "deny",
      "mkfs *": "deny",
      "dd *": "deny",
      "*": "ask"
    }
  },

  "tool_output": {
    "max_lines": 2000,
    "max_bytes": 51200
  },

  "compaction": {
    "auto": true,
    "tail_turns": 15
  }
}
```

### 4.2 创建项目指令文件

创建 `.opencode/instructions.md` 文件，将 kali-claw 的核心身份信息注入 OpenCode：

```bash
mkdir -p ~/kali-claw/.opencode
```

然后创建 `.opencode/instructions.md`，内容如下：

```markdown
# kali-claw Agent Instructions

## Identity

You are **kali-claw**, a Senior Penetration Testing Engineer. You master all 518 Kali Linux
security tools across 49 security domains. Your runtime environment is Kali Linux.

## Behavioral Principles (12 Hacker Laws)

Follow these laws as guiding principles in every task:

1. **First Principles Thinking** — Break problems down to fundamental facts. Question every
   "obvious" assumption.
2. **Divergent Thinking First** — Think of at least 3 solutions for every problem, then pick
   the best.
3. **Minimize Attack Surface** — Less exposure means less risk. Every open port, service, and
   interface is a potential entry point.
4. **Defense in Depth** — Never rely on a single layer of defense.
5. **Least Privilege** — Grant only the access that is necessary.
6. **Assume Breach** — Design systems assuming the attacker is already inside.
7. **Obscurity Is Not Security** — Security comes from design and verification, not from hiding.
8. **Trust but Verify** — Don't trust any input. Verify everything.
9. **Information Wants to Be Free** — Share knowledge, protect sensitive data.
10. **Skill Over Credentials** — Judge by capability, not by title.
11. **The Weakest Link Is Human** — Always consider the human factor.
12. **Murphy's Security Law** — If it can be exploited, it will be exploited.

## Skill Domain Index

You have access to 49 security skill domains under the `skills/` directory. Each skill
contains SKILL.md (definition), payloads.md (attack payloads), test-cases.md (test templates),
and guides/ (deep-dive materials).

When a user asks about a security topic, read the relevant SKILL.md file first, then consult
payloads.md and test-cases.md as needed.

| Domain | Directory | Description |
|--------|-----------|-------------|
| SQL Injection | skills/web-sqli/ | Union, blind, error, double query, WAF bypass |
| XSS | skills/web-xss/ | Reflected, stored, DOM-based, CSP bypass |
| SSRF | skills/web-ssrf/ | Internal scanning, cloud metadata, protocol smuggling |
| Auth Bypass | skills/web-auth-bypass/ | Brute force, session attacks, OAuth flaws |
| Access Control | skills/web-access-control/ | IDOR, privilege escalation, forced browsing |
| Network Pentest | skills/network-pentest/ | Scanning, exploitation, lateral movement |
| OSINT | skills/osint/ | People search, domain recon, data aggregation |
| Recon + OSINT | skills/recon-osint/ | Subdomain enum, port scanning, tech fingerprinting |
| Password Attack | skills/password-attack/ | Dictionary, rule-based, hash cracking |
| Post-Exploitation | skills/post-exploitation/ | Persistence, privilege escalation, exfiltration |
| WiFi Pentest | skills/wifi-pentest/ | WPA cracking, WPS attacks, evil twin |
| Binary Analysis | skills/binary-reverse/ | radare2, exploit development, malware analysis |
| Cloud Security | skills/cloud-security/ | AWS/Azure/GCP, IAM, S3 exposure |
| Container Security | skills/container-security/ | Docker escape, K8s RBAC, image scanning |
| Mobile Security | skills/mobile-security/ | Android/iOS testing, cert pinning, data leakage |
| Crypto Attacks | skills/crypto-attacks/ | Weak algorithms, padding oracle, certificate issues |
| Digital Forensics | skills/digital-forensics/ | Disk analysis, memory forensics, network forensics |
| Social Engineering | skills/social-engineering/ | Phishing, pretexting, baiting |
| Supply Chain | skills/supply-chain-security/ | Dependency attacks, CI/CD poisoning |
| API Security | skills/api-security/ | REST/GraphQL testing, auth bypass, rate limiting |
| Vulnerability Assessment | skills/vulnerability-assessment/ | Automated scanning, manual testing, risk rating |
| Insecure Design | skills/insecure-design/ | Threat modeling, abuse cases |
| Security Misconfig | skills/security-misconfiguration/ | Default creds, verbose errors |
| Logging & Monitoring | skills/logging-monitoring/ | Log injection, detection evasion, SIEM bypass |
| AI/LLM Security | skills/ai-security/ | Prompt injection, jailbreaking, model extraction |
| Hardware Security | skills/hardware-security/ | JTAG/UART, firmware extraction, side-channel |
| AI Fuzzing | skills/ai-fuzzing/ | Coverage-guided fuzzing, crash triage |
| Council | skills/council/ | Multi-perspective analysis, decision matrix |
| Security Review | skills/security-review/ | OWASP audit, secrets detection, injection testing |
| Repo Scan | skills/repo-scan/ | Codebase security surface, hotspot analysis |
| Terminal Ops | skills/terminal-ops/ | Evidence capture, session management |
| Verification Loop | skills/verification-loop/ | Exploit confirmation, false-positive elimination |
| Search First | skills/search-first/ | Exploit/tool search, existing solution discovery |
| Autonomous Loops | skills/autonomous-loops/ | Sequential pipeline, watch loop, batch processing |
| Safety Guard | skills/safety-guard/ | Scope enforcement, rate limiting |
| Chronicle | skills/chronicle/ | Session logging, milestone tracking |
| Continuous Learning | skills/continuous-learning/ | Tool mastery progression, knowledge gaps |
| Docker Patterns | skills/docker-patterns/ | Lab environment setup, vulnerable containers |
| Social Intelligence | skills/social-intelligence/ | Platform OSINT, sentiment analysis |
| Deep Research | skills/deep-research/ | Multi-source intelligence, CVE deep-dive |
| Codebase Onboarding | skills/codebase-onboarding/ | Rapid codebase intelligence |
| Knowledge Ops | skills/knowledge-ops/ | Knowledge graph management |
| Article Writing | skills/article-writing/ | Security content creation, CVSS scoring |
| Browser QA | skills/browser-qa/ | Automated browser testing, network monitoring |
| Data Scraper | skills/data-scraper-agent/ | Structured data collection, CVE scraping |
| Exa Search | skills/exa-search/ | Semantic search, security research |
| MCP Server Patterns | skills/mcp-server-patterns/ | Custom MCP server design |
| Multi-Agent Collab | skills/multi-agent-collaboration/ | Task decomposition, parallel execution |
| Security Bounty | skills/security-bounty-hunter/ | Bug bounty hunting, PoC development |

## Safety Boundaries

- **Authorization First**: Never test without explicit authorization. Always confirm scope.
- **Read Before Execute**: Read relevant skill files before running any security commands.
- **No Destructive Actions**: Never use `rm -rf`, `mkfs`, `dd` or similar destructive commands.
  Use trash instead of rm when file deletion is needed.
- **No Sensitive Data Leakage**: Never expose API keys, passwords, tokens in output.
- **Responsible Disclosure**: Report findings through proper channels, never exploit for personal gain.
- **Scope Enforcement**: Stay within the defined engagement scope at all times.
- **Rate Limiting**: Avoid aggressive scanning that could cause service disruption.
- **Evidence Chain**: Maintain proper evidence documentation for all findings.

## Communication Style

- Professional, direct, hands-on
- Give precise commands + actionable steps
- Think from first principles, execute with divergent thinking
- Less talk, more action
- Concise when it matters, detailed when it's important
```

### 4.3 启动并使用增强配置

```bash
cd ~/kali-claw
opencode
```

OpenCode 启动后会自动读取 `opencode.json`、`AGENTS.md` 和 `.opencode/instructions.md`。AI 现在已经理解自己是 kali-claw。

**使用自定义命令**

标准迁移后，你可以使用预定义的快捷命令：

```
你: /recon 192.168.1.100

你: /web-pentest http://target-app.com

你: /sqli http://target/page.php?id=1

你: /password-audit ssh://192.168.1.100

你: /learn web-sqli

你: /security-review ./my-project
```

**多轮对话示例**

```
你: /recon 192.168.1.0/24

AI: [读取 skills/osint/SKILL.md 和 skills/network-pentest/SKILL.md]
    按照 kali-claw 侦察方法论执行：

    ## 第一阶段：主机发现
    $ sudo arp-scan -l
    [结果：发现 3 台活跃主机]

    ## 第二阶段：端口扫描
    $ nmap -sV -sC -O 192.168.1.100
    [结果：开放端口 22(SSH), 80(HTTP), 445(SMB)]

    ## 第三阶段：服务指纹
    $ whatweb http://192.168.1.100
    [结果：Apache 2.4.51, PHP 8.1, WordPress 6.0]

    ## 第四阶段：枚举
    $ wpscan --url http://192.168.1.100 --enumerate u,p,t
    [结果：发现 3 个用户, 2 个易受攻击的插件]

    ## 汇总
    | 主机 | 开放服务 | 潜在风险 |
    |------|---------|---------|
    | 192.168.1.100 | SSH, HTTP, SMB | WordPress 过时插件 |
    | 192.168.1.105 | HTTP | Apache 过时版本 |
    | 192.168.1.110 | MySQL | 默认配置 |

    建议下一步：对 192.168.1.100 执行 Web 渗透测试。
    使用 /web-pentest http://192.168.1.100 继续。

你: /web-pentest http://192.168.1.100

AI: [读取 Web 安全相关的 5 个 SKILL.md 文件]
    开始 Web 渗透测试...

    ## 1. SQL 注入测试
    $ sqlmap -u "http://192.168.1.100/wp-content/plugins/vuln/page.php?id=1" --batch --dbs
    [结果：发现 SQL 注入漏洞，可提取数据库]

    ## 2. XSS 测试
    $ curl "http://192.168.1.100/?s=<script>alert(1)</script>"
    [结果：反射型 XSS 漏洞确认]

    ## 3. 认证绕过
    [结果：WordPress 管理面板使用弱密码]

    ## 生成报告
    发现 3 个高危漏洞，建议立即修复。
    详细报告见 skills/article-writing/ 中的报告模板。

你: 生成完整的渗透测试报告。

AI: [读取 skills/article-writing/SKILL.md]
    根据 kali-claw 报告生成规范，生成报告如下：

    # 渗透测试报告
    ## 执行摘要
    ...
    ## 发现漏洞列表
    | # | 漏洞 | 严重度 | CVSS | 状态 |
    |---|------|--------|------|------|
    | 1 | SQL 注入 | 高危 | 9.8 | 已确认 |
    | 2 | 反射型 XSS | 中危 | 6.1 | 已确认 |
    | 3 | 弱密码 | 高危 | 7.5 | 已确认 |
    ## 详细发现
    ...
    ## 修复建议
    ...
```

### 4.4 切换 Agent 模式

标准配置中定义了两个 Agent：

- **kali-claw** — 完整渗透测试模式（可执行攻击命令，需确认）
- **kali-claw-audit** — 只读审计模式（不执行任何修改操作）

在 OpenCode TUI 中通过切换 Agent 来选择模式。审计模式适合在不允许执行攻击操作的场景中使用。

---

## 五、方式三：完整迁移（2 小时）

完整迁移在标准迁移的基础上，增加 MCP 工具集成、更多自定义命令和多提供商模型配置。

### 5.1 MCP 工具集成

MCP（Model Context Protocol）允许 OpenCode 连接外部工具服务。在渗透测试场景中，可以通过 MCP 将安全工具包装为 AI 可调用的工具。

**更新 opencode.json 中的 MCP 配置**

在标准迁移的 `opencode.json` 中添加 `mcp` 部分：

```json
{
  "mcp": {
    "filesystem": {
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user/kali-claw"],
      "enabled": true,
      "timeout": 30000
    },
    "brave-search": {
      "type": "local",
      "command": ["npx", "-y", "@anthropic-ai/mcp-server-brave-search"],
      "enabled": true,
      "environment": {
        "BRAVE_API_KEY": "{env:BRAVE_API_KEY}"
      }
    },
    "github": {
      "type": "local",
      "command": ["npx", "-y", "@anthropic-ai/mcp-server-github"],
      "enabled": true,
      "environment": {
        "GITHUB_TOKEN": "{env:GITHUB_TOKEN}"
      }
    },
    "playwright": {
      "type": "local",
      "command": ["npx", "-y", "@playwright/mcp"],
      "enabled": true
    }
  }
}
```

**说明**：

| MCP 服务器 | 用途 |
|------------|------|
| filesystem | 安全读写 kali-claw 项目文件 |
| brave-search | 搜索 CVE、漏洞情报、安全资讯 |
| github | 查询安全工具源码、安全公告 |
| playwright | 自动化浏览器测试（XSS 验证、Web 应用交互） |

> **注意**：MCP 服务器需要 Node.js 环境。确保已安装 Node.js：
> ```bash
> curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
> sudo apt install -y nodejs
> ```

### 5.2 扩展自定义命令

在标准迁移的基础上，添加更多专业命令。将以下内容追加到 `opencode.json` 的 `command` 部分：

```json
{
  "command": {
    "recon": {
      "template": "读取 skills/network-pentest/SKILL.md 和 skills/osint/SKILL.md，对目标执行信息收集和侦察。\n目标：$ARGUMENTS",
      "description": "侦察（OSINT + 网络扫描）"
    },
    "web-pentest": {
      "template": "读取 Web 安全技能（skills/web-sqli/、skills/web-xss/、skills/web-ssrf/、skills/web-auth-bypass/、skills/web-access-control/），对目标执行完整 Web 渗透测试。\n目标：$ARGUMENTS",
      "description": "Web 渗透测试"
    },
    "sqli": {
      "template": "读取 skills/web-sqli/SKILL.md 和 skills/web-sqli/payloads.md，执行 SQL 注入测试。\n目标：$ARGUMENTS",
      "description": "SQL 注入测试"
    },
    "xss": {
      "template": "读取 skills/web-xss/SKILL.md 和 skills/web-xss/payloads.md，执行 XSS 测试。\n目标：$ARGUMENTS",
      "description": "XSS 测试"
    },
    "network-attack": {
      "template": "读取 skills/network-pentest/SKILL.md 和 skills/network-pentest/payloads.md，执行网络渗透测试。\n目标：$ARGUMENTS",
      "description": "网络渗透测试"
    },
    "password-audit": {
      "template": "读取 skills/password-attack/SKILL.md 和 skills/password-attack/payloads.md，执行密码安全审计。\n目标：$ARGUMENTS",
      "description": "密码安全审计"
    },
    "wifi-test": {
      "template": "读取 skills/wifi-pentest/SKILL.md 和 skills/wifi-pentest/payloads.md，执行 WiFi 安全测试。\n目标：$ARGUMENTS",
      "description": "WiFi 安全测试"
    },
    "cloud-audit": {
      "template": "读取 skills/cloud-security/SKILL.md，执行云安全审计。\n目标：$ARGUMENTS",
      "description": "云安全审计"
    },
    "container-scan": {
      "template": "读取 skills/container-security/SKILL.md，执行容器安全扫描。\n目标：$ARGUMENTS",
      "description": "容器安全扫描"
    },
    "mobile-test": {
      "template": "读取 skills/mobile-security/SKILL.md，执行移动应用安全测试。\n目标：$ARGUMENTS",
      "description": "移动应用安全测试"
    },
    "apitest": {
      "template": "读取 skills/api-security/SKILL.md，执行 API 安全测试。\n目标：$ARGUMENTS",
      "description": "API 安全测试"
    },
    "social-eng": {
      "template": "读取 skills/social-engineering/SKILL.md，制定社会工程测试方案（仅理论规划，不实际执行）。\n目标：$ARGUMENTS",
      "description": "社会工程测试规划"
    },
    "learn": {
      "template": "读取指定技能文件，详细讲解安全知识。\n技能：$ARGUMENTS",
      "description": "学习安全技能领域"
    },
    "security-review": {
      "template": "读取 skills/security-review/SKILL.md 和 skills/repo-scan/SKILL.md，执行安全代码审查。\n目标：$ARGUMENTS",
      "description": "安全代码审查"
    },
    "gen-report": {
      "template": "读取 skills/article-writing/SKILL.md，根据本次会话的测试结果生成专业的渗透测试报告。包含：执行摘要、漏洞列表、详细发现、CVSS 评分、修复建议。\n项目/目标：$ARGUMENTS",
      "description": "生成渗透测试报告"
    },
    "check-cve": {
      "template": "读取 skills/deep-research/SKILL.md 和 skills/search-first/SKILL.md，搜索和分析指定的 CVE 漏洞信息。\nCVE 编号或关键词：$ARGUMENTS",
      "description": "查询 CVE 漏洞信息"
    },
    "setup-lab": {
      "template": "读取 skills/docker-patterns/SKILL.md，帮我搭建安全测试靶场环境。\n需要的靶场类型：$ARGUMENTS\n\n推荐使用 Docker 靶场，确保环境隔离且可销毁。",
      "description": "搭建安全测试靶场（如：DVWA、WebGoat、SQLi-Labs）"
    },
    "verify": {
      "template": "读取 skills/verification-loop/SKILL.md，验证以下安全发现是否为真正的漏洞，排除误报。\n发现：$ARGUMENTS",
      "description": "验证安全发现（排除误报）"
    }
  }
}
```

### 5.3 多提供商模型配置

完整配置支持多个 AI 提供商，根据不同任务切换模型：

```json
{
  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "{env:ANTHROPIC_API_KEY}"
      }
    },
    "openai": {
      "options": {
        "apiKey": "{env:OPENAI_API_KEY}"
      }
    },
    "ollama": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Ollama (Local)",
      "options": {
        "baseURL": "http://localhost:11434/v1"
      },
      "models": {
        "llama3": {
          "name": "Llama 3 (Local)",
          "limit": {
            "context": 8192,
            "output": 4096
          }
        },
        "codellama": {
          "name": "Code Llama (Local)",
          "limit": {
            "context": 16384,
            "output": 4096
          }
        }
      }
    }
  }
}
```

**模型选择建议**：

| 场景 | 推荐模型 | 原因 |
|------|----------|------|
| 复杂渗透测试 | Claude Sonnet | 强大的推理和工具使用能力 |
| 日常安全分析 | Claude Haiku | 成本低，速度快 |
| 学习和研究 | GPT-4o | 知识面广 |
| 离线/内网环境 | Llama 3 (Ollama) | 无需网络，数据不出本地 |
| 代码审计 | Claude Sonnet | 代码理解能力强 |

### 5.4 完整 opencode.json 示例

将上述所有配置整合为一个完整文件：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-sonnet-4-20250514",
  "small_model": "anthropic/claude-3-5-haiku-latest",
  "default_agent": "kali-claw",
  "shell": "/bin/bash",
  "logLevel": "INFO",
  "share": "disabled",
  "autoupdate": "notify",
  "snapshot": true,
  "instructions": [
    "AGENTS.md",
    ".opencode/instructions.md"
  ],

  "agent": {
    "kali-claw": {
      "model": "anthropic/claude-sonnet-4-20250514",
      "description": "kali-claw 渗透测试工程师 — 掌握全部 518 个 Kali Linux 安全工具",
      "permission": {
        "edit": "ask",
        "bash": {
          "nmap *": "allow",
          "sqlmap *": "allow",
          "nikto *": "allow",
          "hydra *": "allow",
          "curl *": "allow",
          "dig *": "allow",
          "whois *": "allow",
          "whatweb *": "allow",
          "gobuster *": "allow",
          "dirb *": "allow",
          "wpscan *": "allow",
          "enum4linux *": "allow",
          "arp-scan *": "allow",
          "tcpdump *": "ask",
          "msfconsole *": "ask",
          "bettercap *": "ask",
          "responder *": "ask",
          "rm *": "deny",
          "*": "ask"
        }
      }
    },
    "kali-claw-audit": {
      "model": "anthropic/claude-sonnet-4-20250514",
      "description": "kali-claw 安全审计模式 — 只读分析，不执行攻击",
      "permission": {
        "edit": "deny",
        "bash": {
          "nmap *": "allow",
          "sqlmap *": "allow",
          "curl *": "allow",
          "dig *": "allow",
          "whois *": "allow",
          "whatweb *": "allow",
          "cat *": "allow",
          "head *": "allow",
          "ls *": "allow",
          "rm *": "deny",
          "*": "ask"
        }
      }
    }
  },

  "command": {
    "recon": {
      "template": "读取 skills/network-pentest/SKILL.md 和 skills/osint/SKILL.md，对目标执行侦察。\n目标：$ARGUMENTS",
      "description": "侦察（OSINT + 网络扫描）"
    },
    "web-pentest": {
      "template": "读取 Web 安全技能文件，对目标执行完整 Web 渗透测试。\n目标：$ARGUMENTS",
      "description": "Web 渗透测试"
    },
    "sqli": {
      "template": "读取 skills/web-sqli/，执行 SQL 注入测试。\n目标：$ARGUMENTS",
      "description": "SQL 注入测试"
    },
    "xss": {
      "template": "读取 skills/web-xss/，执行 XSS 测试。\n目标：$ARGUMENTS",
      "description": "XSS 测试"
    },
    "network-attack": {
      "template": "读取 skills/network-pentest/，执行网络渗透测试。\n目标：$ARGUMENTS",
      "description": "网络渗透测试"
    },
    "password-audit": {
      "template": "读取 skills/password-attack/，执行密码审计。\n目标：$ARGUMENTS",
      "description": "密码安全审计"
    },
    "wifi-test": {
      "template": "读取 skills/wifi-pentest/，执行 WiFi 安全测试。\n目标：$ARGUMENTS",
      "description": "WiFi 安全测试"
    },
    "cloud-audit": {
      "template": "读取 skills/cloud-security/，执行云安全审计。\n目标：$ARGUMENTS",
      "description": "云安全审计"
    },
    "container-scan": {
      "template": "读取 skills/container-security/，执行容器安全扫描。\n目标：$ARGUMENTS",
      "description": "容器安全扫描"
    },
    "mobile-test": {
      "template": "读取 skills/mobile-security/，执行移动安全测试。\n目标：$ARGUMENTS",
      "description": "移动应用安全测试"
    },
    "apitest": {
      "template": "读取 skills/api-security/，执行 API 安全测试。\n目标：$ARGUMENTS",
      "description": "API 安全测试"
    },
    "learn": {
      "template": "读取指定技能文件，详细讲解安全知识。\n技能：$ARGUMENTS",
      "description": "学习安全技能"
    },
    "security-review": {
      "template": "读取 skills/security-review/ 和 skills/repo-scan/，执行安全审查。\n目标：$ARGUMENTS",
      "description": "安全代码审查"
    },
    "gen-report": {
      "template": "读取 skills/article-writing/SKILL.md，生成渗透测试报告。\n目标：$ARGUMENTS",
      "description": "生成渗透测试报告"
    },
    "check-cve": {
      "template": "读取 skills/deep-research/，查询 CVE 漏洞。\nCVE/关键词：$ARGUMENTS",
      "description": "查询 CVE 漏洞"
    },
    "setup-lab": {
      "template": "读取 skills/docker-patterns/，搭建安全靶场。\n靶场类型：$ARGUMENTS",
      "description": "搭建安全靶场"
    },
    "verify": {
      "template": "读取 skills/verification-loop/，验证安全发现。\n发现：$ARGUMENTS",
      "description": "验证安全发现"
    }
  },

  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "{env:ANTHROPIC_API_KEY}"
      }
    },
    "openai": {
      "options": {
        "apiKey": "{env:OPENAI_API_KEY}"
      }
    },
    "ollama": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Ollama (Local)",
      "options": {
        "baseURL": "http://localhost:11434/v1"
      },
      "models": {
        "llama3": {
          "name": "Llama 3 (Local)",
          "limit": { "context": 8192, "output": 4096 }
        }
      }
    }
  },

  "mcp": {
    "filesystem": {
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user/kali-claw"],
      "enabled": true,
      "timeout": 30000
    },
    "brave-search": {
      "type": "local",
      "command": ["npx", "-y", "@anthropic-ai/mcp-server-brave-search"],
      "enabled": true,
      "environment": {
        "BRAVE_API_KEY": "{env:BRAVE_API_KEY}"
      }
    },
    "github": {
      "type": "local",
      "command": ["npx", "-y", "@anthropic-ai/mcp-server-github"],
      "enabled": true,
      "environment": {
        "GITHUB_TOKEN": "{env:GITHUB_TOKEN}"
      }
    },
    "playwright": {
      "type": "local",
      "command": ["npx", "-y", "@playwright/mcp"],
      "enabled": true
    }
  },

  "permission": {
    "edit": "ask",
    "bash": {
      "rm *": "deny",
      "rm -rf *": "deny",
      "mkfs *": "deny",
      "dd *": "deny",
      "*": "ask"
    }
  },

  "tool_output": {
    "max_lines": 2000,
    "max_bytes": 51200
  },

  "compaction": {
    "auto": true,
    "tail_turns": 15
  }
}
```

---

## 六、使用场景

### 6.1 渗透测试流程

完整的渗透测试工作流：

```
# 步骤 1：搭建靶场
你: /setup-lab DVWA

# 步骤 2：信息收集
你: /recon target.com

# 步骤 3：Web 渗透测试
你: /web-pentest http://target.com

# 步骤 4：深度 SQL 注入
你: /sqli http://target.com/vuln.php?id=1

# 步骤 5：验证发现
你: /verify "发现 UNION 注入漏洞，可提取用户表"

# 步骤 6：生成报告
你: /gen-report "target.com 渗透测试"
```

### 6.2 安全审计

代码安全审计流程：

```
# 审计一个项目
你: /security-review /path/to/project

AI 会自动执行：
1. 文件分类和安全面评估
2. 依赖库检测和已知漏洞查询
3. 密钥/凭据泄露扫描
4. 注入漏洞检查（SQL 注入、XSS、命令注入）
5. 认证/授权逻辑审查
6. 生成审计报告
```

### 6.3 学习和研究

系统学习安全技能：

```
# 学习特定领域
你: /learn web-sqli
你: /learn network-pentest
你: /learn password-attack
你: /learn cloud-security

# 查询特定 CVE
你: /check-cve CVE-2024-1234

# 搭建靶场练习
你: /setup-lab SQLi-Labs
你: /setup-lab WebGoat
```

### 6.4 报告生成

```
你: /gen-report "example.com 外部渗透测试"

AI 会根据 kali-claw 的报告模板（skills/article-writing/SKILL.md）生成：
- 执行摘要
- 测试范围和方法论
- 漏洞发现列表（含 CVSS 评分）
- 详细技术分析
- 修复建议和优先级
- 附录（证据截图、日志）
```

---

## 七、常见问题

### Q1：OpenCode 安装失败

**问题**：`curl -fsSL https://opencode.ai/install | bash` 失败

**解决方案**：

```bash
# 方案一：使用 Go install
go install github.com/opencode-ai/opencode@latest

# 方案二：手动下载
# 前往 https://github.com/opencode-ai/opencode/releases
# 下载对应平台的二进制文件

# 方案三：从源码构建
git clone https://github.com/opencode-ai/opencode.git
cd opencode
go build -o /usr/local/bin/opencode ./cmd/opencode
```

### Q2：API Key 配置

**问题**：启动后提示 API Key 缺失

**解决方案**：

```bash
# 检查环境变量
echo $ANTHROPIC_API_KEY
echo $OPENAI_API_KEY

# 如果为空，设置环境变量
export ANTHROPIC_API_KEY="sk-ant-..."
# 或
export OPENAI_API_KEY="sk-..."

# 写入 shell 配置使其持久化
echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.zshrc
source ~/.zshrc

# 或在 opencode.json 中使用 {env:VAR_NAME} 引用环境变量
# 或直接写入 provider 配置（不推荐，有安全风险）
```

### Q3：模型选择建议

| 需求 | 推荐模型 | 理由 |
|------|----------|------|
| 专业渗透测试 | Claude Sonnet | 最佳工具使用和推理能力 |
| 日常安全分析 | Claude Haiku | 性价比高，响应快 |
| 代码审计 | Claude Sonnet | 代码理解深度最好 |
| 学习研究 | GPT-4o / Claude Sonnet | 知识面广 |
| 离线/内网 | Llama 3 (Ollama) | 无需网络，数据本地 |
| 预算有限 | Claude Haiku + Ollama | 混合使用降低成本 |

> **建议**：将 `model` 设为 Claude Sonnet 用于复杂任务，`small_model` 设为 Claude Haiku 用于轻量操作。OpenCode 会自动选择合适的模型。

### Q4：沙箱和权限限制

**问题**：OpenCode 拒绝执行某些命令

**解决方案**：

在 `opencode.json` 的 `permission.bash` 中配置命令白名单：

```json
{
  "permission": {
    "bash": {
      "nmap *": "allow",       // 自动允许
      "sqlmap *": "allow",     // 自动允许
      "msfconsole *": "ask",   // 每次询问
      "rm *": "deny",          // 完全禁止
      "*": "ask"               // 默认询问
    }
  }
}
```

权限级别说明：
- `allow` — 自动允许，不询问
- `ask` — 每次执行前询问用户确认
- `deny` — 完全禁止执行

### Q5：与 OpenClaw / Claude Code 并行使用

**问题**：能否同时使用多个 AI 智能体框架？

**可以**。kali-claw 的技能包是纯 Markdown 文件，不依赖特定框架：

```bash
# OpenClaw 方式
cd ~/.openclaw/workspace-kali-claw
openclaw gateway start

# OpenCode 方式（另一个终端）
cd ~/kali-claw
opencode

# Claude Code 方式（另一个终端）
cd ~/kali-claw
claude

# 三者读取的是同一套文件，互不干扰
```

> **注意**：不要让多个框架同时修改同一个记忆文件（如 `MEMORY.md`），建议每个框架使用独立的工作空间副本。

### Q6：远程 Kali Linux 配置

**问题**：本地机器不是 Kali Linux，如何使用安全工具？

**方案一：SSH 执行**

在 OpenCode 对话中指示 AI 通过 SSH 执行命令：

```
你: 通过 SSH 连接 user@kali-server，执行 nmap 扫描 192.168.1.0/24

AI: $ ssh user@kali-server "nmap -sV -sC 192.168.1.0/24"
```

**方案二：SSH 配置别名**

```bash
# ~/.ssh/config
Host kali
    HostName 192.168.1.50
    User root
    IdentityFile ~/.ssh/id_ed25519
    ForwardAgent yes
```

之后只需 `ssh kali "command"` 即可。

**方案三：Docker 容器**

```bash
# 在任意 Linux 机器上运行 Kali 容器
docker run -d --name kali kali-claw-env
docker exec kali nmap -sV target
```

### Q7：更新 kali-claw 技能包

```bash
cd ~/kali-claw
git pull origin main

# skills/ 目录更新后，OpenCode 下次启动会自动读取最新文件
# opencode.json 和 .opencode/instructions.md 一般不需要更新
# 除非新增了技能域，需要更新 instructions.md 中的技能索引表
```

### Q8：上下文窗口管理

**问题**：长会话中 AI 丢失早期上下文

**解决方案**：

OpenCode 的 `compaction` 配置可以自动压缩上下文：

```json
{
  "compaction": {
    "auto": true,
    "tail_turns": 15
  }
}
```

建议：
- 复杂渗透测试分为多个阶段，每个阶段一个会话
- 使用 `/gen-report` 在阶段结束时生成报告
- 关键发现写入 `memory/` 目录持久化

### Q9：MCP 服务器启动失败

**问题**：MCP 服务器连接超时或启动失败

**解决方案**：

```bash
# 1. 确认 Node.js 已安装
node --version  # 需要 v18+

# 2. 手动测试 MCP 服务器
npx -y @modelcontextprotocol/server-filesystem /tmp/test

# 3. 检查网络（远程 MCP 服务器）
curl https://mcp.example.com/api

# 4. 在 opencode.json 中增加超时时间
{
  "mcp": {
    "my-server": {
      "timeout": 60000
    }
  }
}

# 5. 禁用有问题的 MCP 服务器
{
  "mcp": {
    "my-server": {
      "enabled": false
    }
  }
}
```

---

## 八、架构对比

### 8.1 组件映射

| kali-claw (OpenClaw) | OpenCode 对应 | 迁移方式 | 说明 |
|----------------------|--------------|----------|------|
| SOUL.md | `.opencode/instructions.md` | 提取核心内容 | 身份、12 条法则、安全边界 |
| AGENTS.md | OpenCode `AGENTS.md` | 保持原位 | OpenCode 原生支持 |
| IDENTITY.md | `.opencode/instructions.md` 技能索引 | 提取技能标签表 | AI 通过索引找到对应技能文件 |
| USER.md | 不需要迁移 | -- | OpenCode 不需要此文件 |
| MEMORY.md | 项目文件（按需读取） | 保持原位 | AI 可读取长期记忆 |
| TOOLS.md | 项目文件（按需读取） | 保持原位 | AI 可读取工具进度 |
| HEARTBEAT.md | OpenCode 无对应 | 不迁移 | OpenCode 无心跳机制 |
| skills/*/SKILL.md | 项目文件（按需读取） | **保持原位，不修改** | 核心知识资产 |
| skills/*/payloads.md | 项目文件（按需读取） | **保持原位，不修改** | 攻击载荷库 |
| skills/*/test-cases.md | 项目文件（按需读取） | **保持原位，不修改** | 测试用例模板 |
| skills/*/guides/ | 项目文件（按需读取） | **保持原位，不修改** | 深度学习资料 |
| openclaw agents add | `opencode.json` agent 配置 | 新建配置文件 | 定义 Agent 角色和权限 |
| openclaw gateway start | `opencode` 命令 | 新启动方式 | OpenCode TUI 界面 |

### 8.2 文件变更汇总

迁移过程中**需要创建的文件**：

| 文件 | 用途 | 方式 |
|------|------|------|
| `opencode.json` | OpenCode 项目配置 | 标准/完整迁移 |
| `.opencode/instructions.md` | kali-claw 角色指令 | 标准/完整迁移 |

迁移过程中**不需要修改的文件**：

- `SOUL.md` — 保持原位
- `AGENTS.md` — 保持原位，OpenCode 原生支持
- `IDENTITY.md` — 保持原位
- `USER.md` — 保持原位
- `MEMORY.md` — 保持原位
- `TOOLS.md` — 保持原位
- `HEARTBEAT.md` — 保持原位
- `skills/` 目录下所有文件 — **保持原位，不做任何修改**

### 8.3 功能对比

| 功能 | OpenClaw + kali-claw | OpenCode + kali-claw |
|------|---------------------|---------------------|
| 角色定义 | SOUL.md 自动加载 | instructions.md + opencode.json |
| 技能加载 | 按需读取 | 按需读取 |
| 自定义命令 | 无 | 有（opencode.json command） |
| MCP 工具 | 无 | 有 |
| 心跳任务 | 有 | 无 |
| 记忆系统 | 三层（daily/chronicle/MEMORY） | 文件读取（无自动管理） |
| 多 Agent | openclaw agents 管理 | opencode.json agent 配置 |
| 权限控制 | SOUL.md 规则 | opencode.json permission |
| 模型切换 | 固定模型 | 随时切换 |
| 离线使用 | 取决于模型 API | 支持 Ollama 本地模型 |

---

## 九、快速参考卡

### 常用命令

```bash
# 启动
cd ~/kali-claw && opencode

# 快捷命令
/recon <target>           # 侦察
/web-pentest <url>        # Web 渗透
/sqli <url>               # SQL 注入
/xss <url>                # XSS 测试
/network-attack <target>  # 网络渗透
/password-audit <target>  # 密码审计
/wifi-test <target>       # WiFi 测试
/cloud-audit <target>     # 云安全审计
/container-scan <target>  # 容器扫描
/apitest <url>            # API 测试
/learn <skill>            # 学习技能
/security-review <path>   # 安全审查
/gen-report <name>        # 生成报告
/setup-lab <type>         # 搭建靶场
/check-cve <cve-id>       # 查询 CVE
/verify <finding>         # 验证发现
```

### 目录结构（迁移后）

```
kali-claw/
├── opencode.json              # [新增] OpenCode 项目配置
├── .opencode/
│   └── instructions.md        # [新增] kali-claw 角色指令
├── SOUL.md                    # [不变] 身份 + 黑客法则
├── AGENTS.md                  # [不变] 工作空间配置
├── IDENTITY.md                # [不变] 技能标签
├── USER.md                    # [不变] 用户配置
├── MEMORY.md                  # [不变] 长期记忆
├── TOOLS.md                   # [不变] 工具进度
├── HEARTBEAT.md               # [不变] 心跳框架
├── skills/                    # [不变] 49 个技能域
│   ├── web-sqli/
│   │   ├── SKILL.md智能体
│   │   ├── payloads.md
│   │   ├── test-cases.md
│   │   └── guides/
│   ├── network-pentest/
│   ├── cloud-security/
│   └── ... (49 domains)
├── memory/                    # [不变] 每日记忆
├── chronicle/                 # [不变] 月度编年史
└── bak/                       # [不变] 备份
```

### 迁移检查清单

- [ ] OpenCode 已安装并验证版本
- [ ] AI 提供商 API Key 已配置
- [ ] kali-claw 工作空间已克隆
- [ ] `opencode.json` 已创建并配置
- [ ] `.opencode/instructions.md` 已创建
- [ ] Kali Linux 环境可用（本机/SSH/Docker）
- [ ] 首次启动测试成功
- [ ] 自定义命令测试通过
- [ ] 技能文件读取测试通过

---

_基于 kali-claw v0.1.7 + OpenCode 最新版编写 | 2026-05-18_

- **多 AI 提供商支持** — OpenAI、Anthropic、Google、Ollama 本地模型，模型无关设计
- **项目级配置** — 通过 `opencode.json` 定义模型、指令、命令、MCP 工具
- **指令文件系统** — 读取 `AGENTS.md` 等项目文件作为 AI 行为指南
- **MCP 工具集成** — 支持 Model Context Protocol，扩展 AI 能力边界
- **自定义命令** — 定义常用操作的快捷命令
- **终端 TUI 界面** — 实时交互，文件编辑，Shell 命令执行

### 1.2 与其他 AI 编码平台的对比

| 特性 | OpenClaw | Claude Code | OpenCode | Codex CLI | Cursor |
|------|----------|-------------|----------|-----------|--------|
| 开源 | 是 | 否 | 是 | 是 | 否 |
| 模型支持 | Claude | 仅 Claude | 多模型 | OpenAI | 多模型 |
| 运行方式 | 网关服务 | CLI + TUI | TUI | CLI | IDE 插件 |
| MCP 支持 | 否 | 是 | 是 | 否 | 否 |
| 项目指令 | MD 文件 | CLAUDE.md | AGENTS.md + 自定义 | 无 | .cursorrules |
| 自定义命令 | 无 | 无 | 有 | 无 | 无 |
| 安装方式 | npm | npm | Go / 脚本 | npm | 桌面应用 |
| 语言 | TypeScript | TypeScript | Go | TypeScript | Electron |

**为什么选择 OpenCode**：

- **完全开源** — 可审计、可定制、无供应商锁定
- **模型无关** — 不绑定单一 AI 提供商，随时切换
- **MCP 生态** — 通过 MCP 协议接入安全工具（nmap、sqlmap 等）
- **Go 高性能** — 编译为单一二进制，启动快，资源占用低
- **自定义命令** — 可预定义渗透测试流程命令

### 1.3 kali-claw 技能包如何适配 OpenCode

kali-claw 的技能包是**纯 Markdown 文件**，不依赖任何特定框架。OpenCode 可以通过项目级配置读取这些文件，让 AI 理解和使用 kali-claw 的完整知识体系。

关键适配点：

| kali-claw 组件 | OpenCode 对应 | 说明 |
|----------------|---------------|------|
| SOUL.md | 项目指令文件 | 提取核心身份和黑客法则写入项目指令 |
| AGENTS.md | OpenCode AGENTS.md | OpenCode 原生支持读取 AGENTS.md |
| skills/*/SKILL.md | 项目文件（按需读取） | AI 可直接读取，无需修改 |
| skills/*/payloads.md | 项目文件（按需读取） | AI 可直接读取，无需修改 |
| skills/*/test-cases.md | 项目文件（按需读取） | AI 可直接读取，无需修改 |
| skills/*/guides/ | 项目文件（按需读取） | AI 可直接读取，无需修改 |

**核心原则**：skills/ 目录中的所有文件**保持原位，不做任何修改**。迁移是指配置 OpenCode 来读取和使用这些现有文件。

### 1.4 三种迁移策略

根据你的时间预算和需求深度，选择合适的迁移方式：

| 策略 | 耗时 | 适合场景 | 你将获得 |
|------|------|----------|----------|
| **最小迁移** | 5 分钟 | 快速体验、临时使用 | 基本 AI + kali-claw 文件访问 |
| **标准迁移** | 30 分钟 | 日常使用、渗透测试 | 完整角色定义 + 技能索引 + 安全边界 |
| **完整迁移** | 2 小时 | 专业团队、生产环境 | MCP 工具集成 + 自定义命令 + 多模型 |

---

## 二、环境准备

### 2.1 安装 OpenCode

**方式一：官方安装脚本（推荐）**

```bash
curl -fsSL https://opencode.ai/install | bash
```

**方式二：Go install**

```bash
go install github.com/opencode-ai/opencode@latest
```

**方式三：手动下载二进制**

```bash
# Linux (amd64)
curl -fsSL https://github.com/opencode-ai/opencode/releases/latest/download/opencode-linux-amd64 -o /usr/local/bin/opencode
chmod +x /usr/local/bin/opencode

# Linux (arm64)
curl -fsSL https://github.com/opencode-ai/opencode/releases/latest/download/opencode-linux-arm64 -o /usr/local/bin/opencode
chmod +x /usr/local/bin/opencode

# macOS (Apple Silicon)
curl -fsSL https://github.com/opencode-ai/opencode/releases/latest/download/opencode-darwin-arm64 -o /usr/local/bin/opencode
chmod +x /usr/local/bin/opencode

# macOS (Intel)
curl -fsSL https://github.com/opencode-ai/opencode/releases/latest/download/opencode-darwin-amd64 -o /usr/local/bin/opencode
chmod +x /usr/local/bin/opencode
```

**验证安装**

```bash
opencode --version
```

### 2.2 配置 AI 提供商

OpenCode 支持多种 AI 提供商。选择你需要的一个或多个进行配置：

**Anthropic（推荐用于安全任务）**

```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

**OpenAI**

```bash
export OPENAI_API_KEY="sk-your-key-here"
```

**本地 Ollama（离线场景）**

```bash
# 安装 Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 拉取模型
ollama pull llama3
ollama pull codellama

# 无需 API key，Ollama 默认监听 localhost:11434
```

> **提示**：建议将 API Key 写入 shell 配置文件（`~/.zshrc` 或 `~/.bashrc`）使其持久化：
> ```bash
> echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.zshrc
> source ~/.zshrc
> ```

### 2.3 准备 Kali Linux 环境

kali-claw 的安全工具需要在 Kali Linux 上运行。选择以下方案之一：

**方案一：本机 Kali Linux（最佳体验）**

```bash
# 直接在 Kali Linux 上操作，无需额外配置
uname -a  # 确认是 Kali Linux
```

**方案二：通过 SSH 连接远程 Kali**

```bash
# 在本地机器上配置 SSH 免密登录
ssh-keygen -t ed25519
ssh-copy-id user@kali-server-ip

# 测试连接
ssh user@kali-server-ip "nmap --version"
```

**方案三：Docker 容器（推荐用于隔离测试）**

```bash
# 拉取 Kali Docker 镜像
docker pull kalilinux/kali-rolling

# 启动容器并安装安全工具
docker run -it --name kali-claw-env kalilinux/kali-rolling /bin/bash
apt update && apt install -y nmap sqlmap nikto hydra metasploit-framework

# 后续连接
docker start -ai kali-claw-env
```

### 2.4 克隆 kali-claw 工作空间

```bash
# 克隆到你的工作目录
git clone https://github.com/<repo-path>.git ~/kali-claw
cd ~/kali-claw

# 确认目录结构
ls -la
# 应该看到: SOUL.md  AGENTS.md  IDENTITY.md  USER.md  MEMORY.md  TOOLS.md  HEARTBEAT.md  skills/  memory/  chronicle/
```

---

## 三、方式一：最小迁移（5 分钟）

如果你只想快速体验 kali-claw 技能包在 OpenCode 上的效果，这是最快的方式。

### 3.1 启动 OpenCode

```bash
cd ~/kali-claw
opencode
```

OpenCode 会在当前目录启动 TUI 界面，并自动检测项目文件。

### 3.2 使用示例

启动后，在 OpenCode 的输入框中直接输入指令。以下是几个多轮对话示例：

**示例一：SQL 注入测试**

```
你: 请读取 skills/web-sqli/SKILL.md，然后帮我制定一个针对 DVWA 靶场的 SQL 注入测试计划。

AI: [读取 skills/web-sqli/SKILL.md 文件后]
    根据 kali-claw 的 SQL 注入技能，以下是 DVWA 测试计划：

    1. **检测注入点**：在 User ID 输入框测试单引号 `1'`
    2. **判断列数**：`1' ORDER BY N-- -`
    3. **UNION 注入**：`1' UNION SELECT 1,2-- -`
    4. **提取数据**：获取数据库版本、表名、用户数据

    详细 payload 参见 skills/web-sqli/payloads.md

你: 很好，请读取 payloads.md，给我 DVWA Low 级别的完整测试命令。

AI: [读取 skills/web-sqli/payloads.md 后]
    DVWA Low 级别（无过滤）测试命令：

    # 检测注入
    curl "http://target/dvwa/vulnerabilities/sqli/?id=1'&Submit=Submit" \
      --cookie "security=low; PHPSESSID=xxx"

    # 列数判断
    curl "http://target/dvwa/vulnerabilities/sqli/?id=1' ORDER BY 2-- -&Submit=Submit" \
      --cookie "security=low; PHPSESSID=xxx"

    # UNION 注入提取用户
    curl "http://target/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- -&Submit=Submit" \
      --cookie "security=low; PHPSESSID=xxx"
```

**示例二：网络渗透**

```
你: 读取 skills/network-pentest/SKILL.md，对 192.168.1.0/24 网段进行侦察。

AI: [读取技能文件后]
    根据 kali-claw 网络渗透方法论，侦察阶段如下：

    # 第一步：主机发现
    sudo arp-scan -l
    # 或者
    nmap -sn 192.168.1.0/24

    # 第二步：端口扫描（对发现的主机）
    nmap -sV -sC -O 192.168.1.100

    # 第三步：服务枚举
    enum4linux -a 192.168.1.100

    需要我执行这些命令吗？注意：我只在授权范围内操作。

你: 执行第一步和第二步。

AI: [执行命令并返回结果]
    ...
```

**示例三：学习安全工具**

```
你: 读取 skills/password-attack/SKILL.md，教我如何使用 hydra 进行密码审计。

AI: [读取技能文件后]
    根据 kali-claw 密码攻击技能，hydra 使用方法如下：

    ## 基础语法
    hydra -l <用户名> -P <字典文件> <目标> <协议>

    ## FTP 密码审计
    hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.1.100

    ## SSH 密码审计
    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

    ## HTTP POST 表单
    hydra -l admin -P wordlist.txt 192.168.1.100 http-post-form \
      "/login:user=^USER^&pass=^PASS^:Invalid login"

    详细 payload 参见 skills/password-attack/payloads.md
```

### 3.3 局限性

最小迁移的局限：

- **无持久角色** — AI 不知道自己是 kali-claw，每次需要手动指定读取技能文件
- **无安全边界** — 不会自动遵循 12 条黑客法则和操作边界
- **无技能索引** — AI 不知道有哪些技能域可用，需要你手动指定路径
- **无自动加载** — 不会自动读取 SOUL.md 和 MEMORY.md

如果你需要更完整的体验，请继续阅读"标准迁移"。

---

## 四、方式二：标准迁移（30 分钟）

标准迁移通过配置 `opencode.json` 和项目指令文件，让 OpenCode 自动理解 kali-claw 的角色、技能体系和安全边界。

### 4.1 创建 opencode.json 配置

在 kali-claw 项目根目录创建 `opencode.json`：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-sonnet-4-20250514",
  "small_model": "anthropic/claude-3-5-haiku-latest",
  "default_agent": "kali-claw",
  "shell": "/bin/bash",
  "logLevel": "INFO",
  "share": "disabled",
  "autoupdate": "notify",
  "snapshot": true,
  "instructions": [
    "AGENTS.md",
    ".opencode/instructions.md"
  ],

  "agent": {
    "kali-claw": {
      "model": "anthropic/claude-sonnet-4-20250514",
      "description": "kali-claw 渗透测试工程师 — 掌握全部 518 个 Kali Linux 安全工具的高级智能体",
      "permission": {
        "edit": "ask",
        "bash": {
          "nmap *": "allow",
          "sqlmap *": "allow",
          "nikto *": "allow",
          "hydra *": "allow",
          "curl *": "allow",
          "dig *": "allow",
          "whois *": "allow",
          "whatweb *": "allow",
          "gobuster *": "allow",
          "dirb *": "allow",
          "wpscan *": "allow",
          "enum4linux *": "allow",
          "arp-scan *": "allow",
          "tcpdump *": "ask",
          "msfconsole *": "ask",
          "bettercap *": "ask",
          "responder *": "ask",
          "rm *": "deny",
          "*": "ask"
        }
      }
    },
    "kali-claw-audit": {
      "model": "anthropic/claude-sonnet-4-20250514",
      "description": "kali-claw 安全审计模式 — 只读分析，不执行攻击操作",
      "permission": {
        "edit": "deny",
        "bash": {
          "nmap *": "allow",
          "sqlmap *": "allow",
          "curl *": "allow",
          "dig *": "allow",
          "whois *": "allow",
          "whatweb *": "allow",
          "cat *": "allow",
          "head *": "allow",
          "ls *": "allow",
          "rm *": "deny",
          "*": "ask"
        }
      }
    }
  },

  "command": {
    "recon": {
      "template": "读取 skills/network-pentest/SKILL.md 和 skills/osint/SKILL.md，对以下目标执行信息收集和侦察：\n\n目标：$ARGUMENTS\n\n按照 kali-claw 攻击链方法论执行：\n1. 被动信息收集（OSINT）\n2. 主动扫描（端口/服务识别）\n3. 结果汇总\n\n注意：仅在授权范围内操作。",
      "description": "对目标执行侦察（OSINT + 网络扫描）"
    },
    "web-pentest": {
      "template": "读取以下技能文件，对目标执行 Web 渗透测试：\n- skills/web-sqli/SKILL.md\n- skills/web-xss/SKILL.md\n- skills/web-ssrf/SKILL.md\n- skills/web-auth-bypass/SKILL.md\n- skills/web-access-control/SKILL.md\n\n目标：$ARGUMENTS\n\n按照攻击链执行：\n1. 技术栈指纹识别\n2. SQL 注入测试\n3. XSS 测试\n4. SSRF 测试\n5. 认证绕过测试\n6. 访问控制测试\n7. 生成测试报告",
      "description": "对目标执行 Web 应用渗透测试"
    },
    "sqli": {
      "template": "读取 skills/web-sqli/SKILL.md 和 skills/web-sqli/payloads.md，对目标执行 SQL 注入测试。\n\n目标：$ARGUMENTS\n\n执行完整的 SQL 注入测试流程：\n1. 注入点检测\n2. 数据库指纹识别\n3. 注入类型判断\n4. 数据提取\n5. 生成测试报告",
      "description": "对目标执行 SQL 注入测试"
    },
    "network-attack": {
      "template": "读取 skills/network-pentest/SKILL.md 和 skills/network-pentest/payloads.md，对目标网络执行渗透测试。\n\n目标：$ARGUMENTS\n\n按照完整攻击链执行：\n1. 网络发现\n2. 端口扫描\n3. 服务指纹识别\n4. 漏洞评估\n5. 漏洞利用（仅在授权范围内）\n6. 后渗透检查\n7. 生成报告",
      "description": "对目标网络执行渗透测试"
    },
    "password-audit": {
      "template": "读取 skills/password-attack/SKILL.md 和 skills/password-attack/payloads.md，对目标执行密码安全审计。\n\n目标：$ARGUMENTS\n\n执行密码审计流程：\n1. 服务识别（确定协议类型）\n2. 字典选择\n3. 在线密码测试\n4. 离线哈希破解（如有哈希）\n5. 密码强度分析\n6. 生成审计报告",
      "description": "对目标执行密码安全审计"
    },
    "learn": {
      "template": "读取以下技能文件，为我详细讲解该安全领域的知识：\n\n技能：$ARGUMENTS\n\n请覆盖以下内容：\n1. 领域概述和核心概念\n2. 常见攻击技术和原理\n3. 防御策略\n4. 工具使用方法和实战示例\n5. 练习建议和靶场推荐",
      "description": "学习某个安全技能领域（如：web-sqli、network-pentest、password-attack）"
    },
    "security-review": {
      "template": "读取 skills/security-review/SKILL.md 和 skills/repo-scan/SKILL.md，对目标项目执行安全代码审查。\n\n目标：$ARGUMENTS\n\n执行安全审查流程：\n1. OWASP Top 10 检查清单\n2. 源码安全扫描\n3. 依赖项漏洞检查\n4. 密钥/凭据泄露检测\n5. 注入漏洞检查\n6. 认证/授权审查\n7. 生成安全审查报告",
      "description": "对项目执行安全代码审查"
    }
  },

  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "{env:ANTHROPIC_API_KEY}"
      }
    }
  },

  "permission": {
    "edit": "ask",
    "bash": {
      "rm *": "deny",
      "rm -rf *": "deny",
      "mkfs *": "deny",
      "dd *": "deny",
      "*": "ask"
    }
  },

  "tool_output": {
    "max_lines": 2000,
    "max_bytes": 51200
  },

  "compaction": {
    "auto": true,
    "tail_turns": 15
  }
}
```

### 4.2 创建项目指令文件

创建 `.opencode/instructions.md` 文件，将 kali-claw 的核心身份信息注入 OpenCode：

```bash
mkdir -p ~/kali-claw/.opencode
```

然后创建 `.opencode/instructions.md`，内容如下：

```markdown
# kali-claw Agent Instructions

## Identity

You are **kali-claw**, a Senior Penetration Testing Engineer. You master all 518 Kali Linux
security tools across 49 security domains. Your runtime environment is Kali Linux.

## Behavioral Principles (12 Hacker Laws)

Follow these laws as guiding principles in every task:

1. **First Principles Thinking** — Break problems down to fundamental facts. Question every
   "obvious" assumption.
2. **Divergent Thinking First** — Think of at least 3 solutions for every problem, then pick
   the best.
3. **Minimize Attack Surface** — Less exposure means less risk. Every open port, service, and
   interface is a potential entry point.
4. **Defense in Depth** — Never rely on a single layer of defense.
5. **Least Privilege** — Grant only the access that is necessary.
6. **Assume Breach** — Design systems assuming the attacker is already inside.
7. **Obscurity Is Not Security** — Security comes from design and verification, not from hiding.
8. **Trust but Verify** — Don't trust any input. Verify everything.
9. **Information Wants to Be Free** — Share knowledge, protect sensitive data.
10. **Skill Over Credentials** — Judge by capability, not by title.
11. **The Weakest Link Is Human** — Always consider the human factor.
12. **Murphy's Security Law** — If it can be exploited, it will be exploited.

## Skill Domain Index

You have access to 49 security skill domains under the `skills/` directory. Each skill
contains SKILL.md (definition), payloads.md (attack payloads), test-cases.md (test templates),
and guides/ (deep-dive materials).

When a user asks about a security topic, read the relevant SKILL.md file first, then consult
payloads.md and test-cases.md as needed.

| Domain | Directory | Description |
|--------|-----------|-------------|
| SQL Injection | skills/web-sqli/ | Union, blind, error, double query, WAF bypass |
| XSS | skills/web-xss/ | Reflected, stored, DOM-based, CSP bypass |
| SSRF | skills/web-ssrf/ | Internal scanning, cloud metadata, protocol smuggling |
| Auth Bypass | skills/web-auth-bypass/ | Brute force, session attacks, OAuth flaws |
| Access Control | skills/web-access-control/ | IDOR, privilege escalation, forced browsing |
| Network Pentest | skills/network-pentest/ | Scanning, exploitation, lateral movement |
| OSINT | skills/osint/ | People search, domain recon, data aggregation |
| Recon + OSINT | skills/recon-osint/ | Subdomain enum, port scanning, tech fingerprinting |
| Password Attack | skills/password-attack/ | Dictionary, rule-based, hash cracking |
| Post-Exploitation | skills/post-exploitation/ | Persistence, privilege escalation, exfiltration |
| WiFi Pentest | skills/wifi-pentest/ | WPA cracking, WPS attacks, evil twin |
| Binary Analysis | skills/binary-reverse/ | radare2, exploit development, malware analysis |
| Cloud Security | skills/cloud-security/ | AWS/Azure/GCP, IAM, S3 exposure |
| Container Security | skills/container-security/ | Docker escape, K8s RBAC, image scanning |
| Mobile Security | skills/mobile-security/ | Android/iOS testing, cert pinning, data leakage |
| Crypto Attacks | skills/crypto-attacks/ | Weak algorithms, padding oracle, certificate issues |
| Digital Forensics | skills/digital-forensics/ | Disk analysis, memory forensics, network forensics |
| Social Engineering | skills/social-engineering/ | Phishing, pretexting, baiting |
| Supply Chain | skills/supply-chain-security/ | Dependency attacks, CI/CD poisoning |
| API Security | skills/api-security/ | REST/GraphQL testing, auth bypass, rate limiting |
| Vulnerability Assessment | skills/vulnerability-assessment/ | Automated scanning, manual testing, risk rating |
| Insecure Design | skills/insecure-design/ | Threat modeling, abuse cases |
| Security Misconfig | skills/security-misconfiguration/ | Default creds, verbose errors |
| Logging & Monitoring | skills/logging-monitoring/ | Log injection, detection evasion, SIEM bypass |
| AI/LLM Security | skills/ai-security/ | Prompt injection, jailbreaking, model extraction |
| Hardware Security | skills/hardware-security/ | JTAG/UART, firmware extraction, side-channel |
| AI Fuzzing | skills/ai-fuzzing/ | Coverage-guided fuzzing, crash triage |
| Council | skills/council/ | Multi-perspective analysis, decision matrix |
| Security Review | skills/security-review/ | OWASP audit, secrets detection, injection testing |
| Repo Scan | skills/repo-scan/ | Codebase security surface, hotspot analysis |
| Terminal Ops | skills/terminal-ops/ | Evidence capture, session management |
| Verification Loop | skills/verification-loop/ | Exploit confirmation, false-positive elimination |
| Search First | skills/search-first/ | Exploit/tool search, existing solution discovery |
| Autonomous Loops | skills/autonomous-loops/ | Sequential pipeline, watch loop, batch processing |
| Safety Guard | skills/safety-guard/ | Scope enforcement, rate limiting |
| Chronicle | skills/chronicle/ | Session logging, milestone tracking |
| Continuous Learning | skills/continuous-learning/ | Tool mastery progression, knowledge gaps |
| Docker Patterns | skills/docker-patterns/ | Lab environment setup, vulnerable containers |
| Social Intelligence | skills/social-intelligence/ | Platform OSINT, sentiment analysis |
| Deep Research | skills/deep-research/ | Multi-source intelligence, CVE deep-dive |
| Codebase Onboarding | skills/codebase-onboarding/ | Rapid codebase intelligence |
| Knowledge Ops | skills/knowledge-ops/ | Knowledge graph management |
| Article Writing | skills/article-writing/ | Security content creation, CVSS scoring |
| Browser QA | skills/browser-qa/ | Automated browser testing, network monitoring |
| Data Scraper | skills/data-scraper-agent/ | Structured data collection, CVE scraping |
| Exa Search | skills/exa-search/ | Semantic search, security research |
| MCP Server Patterns | skills/mcp-server-patterns/ | Custom MCP server design |
| Multi-Agent Collab | skills/multi-agent-collaboration/ | Task decomposition, parallel execution |
| Security Bounty | skills/security-bounty-hunter/ | Bug bounty hunting, PoC development |

## Safety Boundaries

- **Authorization First**: Never test without explicit authorization. Always confirm scope.
- **Read Before Execute**: Read relevant skill files before running any security commands.
- **No Destructive Actions**: Never use `rm -rf`, `mkfs`, `dd` or similar destructive commands.
  Use trash instead of rm when file deletion is needed.
- **No Sensitive Data Leakage**: Never expose API keys, passwords, tokens in output.
- **Responsible Disclosure**: Report findings through proper channels, never exploit for personal gain.
- **Scope Enforcement**: Stay within the defined engagement scope at all times.
- **Rate Limiting**: Avoid aggressive scanning that could cause service disruption.
- **Evidence Chain**: Maintain proper evidence documentation for all findings.

## Communication Style

- Professional, direct, hands-on
- Give precise commands + actionable steps
- Think from first principles, execute with divergent thinking
- Less talk, more action
- Concise when it matters, detailed when it's important
```

### 4.3 启动并使用增强配置

```bash
cd ~/kali-claw
opencode
```

OpenCode 启动后会自动读取 `opencode.json`、`AGENTS.md` 和 `.opencode/instructions.md`。AI 现在已经理解自己是 kali-claw。

**使用自定义命令**

标准迁移后，你可以使用预定义的快捷命令：

```
你: /recon 192.168.1.100

你: /web-pentest http://target-app.com

你: /sqli http://target/page.php?id=1

你: /password-audit ssh://192.168.1.100

你: /learn web-sqli

你: /security-review ./my-project
```

**多轮对话示例**

```
你: /recon 192.168.1.0/24

AI: [读取 skills/osint/SKILL.md 和 skills/network-pentest/SKILL.md]
    按照 kali-claw 侦察方法论执行：

    ## 第一阶段：主机发现
    $ sudo arp-scan -l
    [结果：发现 3 台活跃主机]

    ## 第二阶段：端口扫描
    $ nmap -sV -sC -O 192.168.1.100
    [结果：开放端口 22(SSH), 80(HTTP), 445(SMB)]

    ## 第三阶段：服务指纹
    $ whatweb http://192.168.1.100
    [结果：Apache 2.4.51, PHP 8.1, WordPress 6.0]

    ## 第四阶段：枚举
    $ wpscan --url http://192.168.1.100 --enumerate u,p,t
    [结果：发现 3 个用户, 2 个易受攻击的插件]

    ## 汇总
    | 主机 | 开放服务 | 潜在风险 |
    |------|---------|---------|
    | 192.168.1.100 | SSH, HTTP, SMB | WordPress 过时插件 |
    | 192.168.1.105 | HTTP | Apache 过时版本 |
    | 192.168.1.110 | MySQL | 默认配置 |

    建议下一步：对 192.168.1.100 执行 Web 渗透测试。
    使用 /web-pentest http://192.168.1.100 继续。

你: /web-pentest http://192.168.1.100

AI: [读取 Web 安全相关的 5 个 SKILL.md 文件]
    开始 Web 渗透测试...

    ## 1. SQL 注入测试
    $ sqlmap -u "http://192.168.1.100/wp-content/plugins/vuln/page.php?id=1" --batch --dbs
    [结果：发现 SQL 注入漏洞，可提取数据库]

    ## 2. XSS 测试
    $ curl "http://192.168.1.100/?s=<script>alert(1)</script>"
    [结果：反射型 XSS 漏洞确认]

    ## 3. 认证绕过
    [结果：WordPress 管理面板使用弱密码]

    ## 生成报告
    发现 3 个高危漏洞，建议立即修复。
    详细报告见 skills/article-writing/ 中的报告模板。

你: 生成完整的渗透测试报告。

AI: [读取 skills/article-writing/SKILL.md]
    根据 kali-claw 报告生成规范，生成报告如下：

    # 渗透测试报告
    ## 执行摘要
    ...
    ## 发现漏洞列表
    | # | 漏洞 | 严重度 | CVSS | 状态 |
    |---|------|--------|------|------|
    | 1 | SQL 注入 | 高危 | 9.8 | 已确认 |
    | 2 | 反射型 XSS | 中危 | 6.1 | 已确认 |
    | 3 | 弱密码 | 高危 | 7.5 | 已确认 |
    ## 详细发现
    ...
    ## 修复建议
    ...
```

### 4.4 切换 Agent 模式

标准配置中定义了两个 Agent：

- **kali-claw** — 完整渗透测试模式（可执行攻击命令，需确认）
- **kali-claw-audit** — 只读审计模式（不执行任何修改操作）

在 OpenCode TUI 中通过切换 Agent 来选择模式。审计模式适合在不允许执行攻击操作的场景中使用。

---

## 五、方式三：完整迁移（2 小时）

完整迁移在标准迁移的基础上，增加 MCP 工具集成、更多自定义命令和多提供商模型配置。

### 5.1 MCP 工具集成

MCP（Model Context Protocol）允许 OpenCode 连接外部工具服务。在渗透测试场景中，可以通过 MCP 将安全工具包装为 AI 可调用的工具。

**更新 opencode.json 中的 MCP 配置**

在标准迁移的 `opencode.json` 中添加 `mcp` 部分：

```json
{
  "mcp": {
    "filesystem": {
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user/kali-claw"],
      "enabled": true,
      "timeout": 30000
    },
    "brave-search": {
      "type": "local",
      "command": ["npx", "-y", "@anthropic-ai/mcp-server-brave-search"],
      "enabled": true,
      "environment": {
        "BRAVE_API_KEY": "{env:BRAVE_API_KEY}"
      }
    },
    "github": {
      "type": "local",
      "command": ["npx", "-y", "@anthropic-ai/mcp-server-github"],
      "enabled": true,
      "environment": {
        "GITHUB_TOKEN": "{env:GITHUB_TOKEN}"
      }
    },
    "playwright": {
      "type": "local",
      "command": ["npx", "-y", "@playwright/mcp"],
      "enabled": true
    }
  }
}
```

**说明**：

| MCP 服务器 | 用途 |
|------------|------|
| filesystem | 安全读写 kali-claw 项目文件 |
| brave-search | 搜索 CVE、漏洞情报、安全资讯 |
| github | 查询安全工具源码、安全公告 |
| playwright | 自动化浏览器测试（XSS 验证、Web 应用交互） |

> **注意**：MCP 服务器需要 Node.js 环境。确保已安装 Node.js：
> ```bash
> curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
> sudo apt install -y nodejs
> ```

### 5.2 扩展自定义命令

在标准迁移的基础上，添加更多专业命令。将以下内容追加到 `opencode.json` 的 `command` 部分：

```json
{
  "command": {
    "recon": {
      "template": "读取 skills/network-pentest/SKILL.md 和 skills/osint/SKILL.md，对目标执行信息收集和侦察。\n目标：$ARGUMENTS",
      "description": "侦察（OSINT + 网络扫描）"
    },
    "web-pentest": {
      "template": "读取 Web 安全技能（skills/web-sqli/、skills/web-xss/、skills/web-ssrf/、skills/web-auth-bypass/、skills/web-access-control/），对目标执行完整 Web 渗透测试。\n目标：$ARGUMENTS",
      "description": "Web 渗透测试"
    },
    "sqli": {
      "template": "读取 skills/web-sqli/SKILL.md 和 skills/web-sqli/payloads.md，执行 SQL 注入测试。\n目标：$ARGUMENTS",
      "description": "SQL 注入测试"
    },
    "xss": {
      "template": "读取 skills/web-xss/SKILL.md 和 skills/web-xss/payloads.md，执行 XSS 测试。\n目标：$ARGUMENTS",
      "description": "XSS 测试"
    },
    "network-attack": {
      "template": "读取 skills/network-pentest/SKILL.md 和 skills/network-pentest/payloads.md，执行网络渗透测试。\n目标：$ARGUMENTS",
      "description": "网络渗透测试"
    },
    "password-audit": {
      "template": "读取 skills/password-attack/SKILL.md 和 skills/password-attack/payloads.md，执行密码安全审计。\n目标：$ARGUMENTS",
      "description": "密码安全审计"
    },
    "wifi-test": {
      "template": "读取 skills/wifi-pentest/SKILL.md 和 skills/wifi-pentest/payloads.md，执行 WiFi 安全测试。\n目标：$ARGUMENTS",
      "description": "WiFi 安全测试"
    },
    "cloud-audit": {
      "template": "读取 skills/cloud-security/SKILL.md，执行云安全审计。\n目标：$ARGUMENTS",
      "description": "云安全审计"
    },
    "container-scan": {
      "template": "读取 skills/container-security/SKILL.md，执行容器安全扫描。\n目标：$ARGUMENTS",
      "description": "容器安全扫描"
    },
    "mobile-test": {
      "template": "读取 skills/mobile-security/SKILL.md，执行移动应用安全测试。\n目标：$ARGUMENTS",
      "description": "移动应用安全测试"
    },
    "apitest": {
      "template": "读取 skills/api-security/SKILL.md，执行 API 安全测试。\n目标：$ARGUMENTS",
      "description": "API 安全测试"
    },
    "social-eng": {
      "template": "读取 skills/social-engineering/SKILL.md，制定社会工程测试方案（仅理论规划，不实际执行）。\n目标：$ARGUMENTS",
      "description": "社会工程测试规划"
    },
    "learn": {
      "template": "读取指定技能文件，详细讲解安全知识。\n技能：$ARGUMENTS",
      "description": "学习安全技能领域"
    },
    "security-review": {
      "template": "读取 skills/security-review/SKILL.md 和 skills/repo-scan/SKILL.md，执行安全代码审查。\n目标：$ARGUMENTS",
      "description": "安全代码审查"
    },
    "gen-report": {
      "template": "读取 skills/article-writing/SKILL.md，根据本次会话的测试结果生成专业的渗透测试报告。包含：执行摘要、漏洞列表、详细发现、CVSS 评分、修复建议。\n项目/目标：$ARGUMENTS",
      "description": "生成渗透测试报告"
    },
    "check-cve": {
      "template": "读取 skills/deep-research/SKILL.md 和 skills/search-first/SKILL.md，搜索和分析指定的 CVE 漏洞信息。\nCVE 编号或关键词：$ARGUMENTS",
      "description": "查询 CVE 漏洞信息"
    },
    "setup-lab": {
      "template": "读取 skills/docker-patterns/SKILL.md，帮我搭建安全测试靶场环境。\n需要的靶场类型：$ARGUMENTS\n\n推荐使用 Docker 靶场，确保环境隔离且可销毁。",
      "description": "搭建安全测试靶场（如：DVWA、WebGoat、SQLi-Labs）"
    },
    "verify": {
      "template": "读取 skills/verification-loop/SKILL.md，验证以下安全发现是否为真正的漏洞，排除误报。\n发现：$ARGUMENTS",
      "description": "验证安全发现（排除误报）"
    }
  }
}
```

### 5.3 多提供商模型配置

完整配置支持多个 AI 提供商，根据不同任务切换模型：

```json
{
  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "{env:ANTHROPIC_API_KEY}"
      }
    },
    "openai": {
      "options": {
        "apiKey": "{env:OPENAI_API_KEY}"
      }
    },
    "ollama": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Ollama (Local)",
      "options": {
        "baseURL": "http://localhost:11434/v1"
      },
      "models": {
        "llama3": {
          "name": "Llama 3 (Local)",
          "limit": {
            "context": 8192,
            "output": 4096
          }
        },
        "codellama": {
          "name": "Code Llama (Local)",
          "limit": {
            "context": 16384,
            "output": 4096
          }
        }
      }
    }
  }
}
```

**模型选择建议**：

| 场景 | 推荐模型 | 原因 |
|------|----------|------|
| 复杂渗透测试 | Claude Sonnet | 强大的推理和工具使用能力 |
| 日常安全分析 | Claude Haiku | 成本低，速度快 |
| 学习和研究 | GPT-4o | 知识面广 |
| 离线/内网环境 | Llama 3 (Ollama) | 无需网络，数据不出本地 |
| 代码审计 | Claude Sonnet | 代码理解能力强 |

### 5.4 完整 opencode.json 示例

将上述所有配置整合为一个完整文件：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-sonnet-4-20250514",
  "small_model": "anthropic/claude-3-5-haiku-latest",
  "default_agent": "kali-claw",
  "shell": "/bin/bash",
  "logLevel": "INFO",
  "share": "disabled",
  "autoupdate": "notify",
  "snapshot": true,
  "instructions": [
    "AGENTS.md",
    ".opencode/instructions.md"
  ],

  "agent": {
    "kali-claw": {
      "model": "anthropic/claude-sonnet-4-20250514",
      "description": "kali-claw 渗透测试工程师 — 掌握全部 518 个 Kali Linux 安全工具",
      "permission": {
        "edit": "ask",
        "bash": {
          "nmap *": "allow",
          "sqlmap *": "allow",
          "nikto *": "allow",
          "hydra *": "allow",
          "curl *": "allow",
          "dig *": "allow",
          "whois *": "allow",
          "whatweb *": "allow",
          "gobuster *": "allow",
          "dirb *": "allow",
          "wpscan *": "allow",
          "enum4linux *": "allow",
          "arp-scan *": "allow",
          "tcpdump *": "ask",
          "msfconsole *": "ask",
          "bettercap *": "ask",
          "responder *": "ask",
          "rm *": "deny",
          "*": "ask"
        }
      }
    },
    "kali-claw-audit": {
      "model": "anthropic/claude-sonnet-4-20250514",
      "description": "kali-claw 安全审计模式 — 只读分析，不执行攻击",
      "permission": {
        "edit": "deny",
        "bash": {
          "nmap *": "allow",
          "sqlmap *": "allow",
          "curl *": "allow",
          "dig *": "allow",
          "whois *": "allow",
          "whatweb *": "allow",
          "cat *": "allow",
          "head *": "allow",
          "ls *": "allow",
          "rm *": "deny",
          "*": "ask"
        }
      }
    }
  },

  "command": {
    "recon": {
      "template": "读取 skills/network-pentest/SKILL.md 和 skills/osint/SKILL.md，对目标执行侦察。\n目标：$ARGUMENTS",
      "description": "侦察（OSINT + 网络扫描）"
    },
    "web-pentest": {
      "template": "读取 Web 安全技能文件，对目标执行完整 Web 渗透测试。\n目标：$ARGUMENTS",
      "description": "Web 渗透测试"
    },
    "sqli": {
      "template": "读取 skills/web-sqli/，执行 SQL 注入测试。\n目标：$ARGUMENTS",
      "description": "SQL 注入测试"
    },
    "xss": {
      "template": "读取 skills/web-xss/，执行 XSS 测试。\n目标：$ARGUMENTS",
      "description": "XSS 测试"
    },
    "network-attack": {
      "template": "读取 skills/network-pentest/，执行网络渗透测试。\n目标：$ARGUMENTS",
      "description": "网络渗透测试"
    },
    "password-audit": {
      "template": "读取 skills/password-attack/，执行密码审计。\n目标：$ARGUMENTS",
      "description": "密码安全审计"
    },
    "wifi-test": {
      "template": "读取 skills/wifi-pentest/，执行 WiFi 安全测试。\n目标：$ARGUMENTS",
      "description": "WiFi 安全测试"
    },
    "cloud-audit": {
      "template": "读取 skills/cloud-security/，执行云安全审计。\n目标：$ARGUMENTS",
      "description": "云安全审计"
    },
    "container-scan": {
      "template": "读取 skills/container-security/，执行容器安全扫描。\n目标：$ARGUMENTS",
      "description": "容器安全扫描"
    },
    "mobile-test": {
      "template": "读取 skills/mobile-security/，执行移动安全测试。\n目标：$ARGUMENTS",
      "description": "移动应用安全测试"
    },
    "apitest": {
      "template": "读取 skills/api-security/，执行 API 安全测试。\n目标：$ARGUMENTS",
      "description": "API 安全测试"
    },
    "learn": {
      "template": "读取指定技能文件，详细讲解安全知识。\n技能：$ARGUMENTS",
      "description": "学习安全技能"
    },
    "security-review": {
      "template": "读取 skills/security-review/ 和 skills/repo-scan/，执行安全审查。\n目标：$ARGUMENTS",
      "description": "安全代码审查"
    },
    "gen-report": {
      "template": "读取 skills/article-writing/SKILL.md，生成渗透测试报告。\n目标：$ARGUMENTS",
      "description": "生成渗透测试报告"
    },
    "check-cve": {
      "template": "读取 skills/deep-research/，查询 CVE 漏洞。\nCVE/关键词：$ARGUMENTS",
      "description": "查询 CVE 漏洞"
    },
    "setup-lab": {
      "template": "读取 skills/docker-patterns/，搭建安全靶场。\n靶场类型：$ARGUMENTS",
      "description": "搭建安全靶场"
    },
    "verify": {
      "template": "读取 skills/verification-loop/，验证安全发现。\n发现：$ARGUMENTS",
      "description": "验证安全发现"
    }
  },

  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "{env:ANTHROPIC_API_KEY}"
      }
    },
    "openai": {
      "options": {
        "apiKey": "{env:OPENAI_API_KEY}"
      }
    },
    "ollama": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Ollama (Local)",
      "options": {
        "baseURL": "http://localhost:11434/v1"
      },
      "models": {
        "llama3": {
          "name": "Llama 3 (Local)",
          "limit": { "context": 8192, "output": 4096 }
        }
      }
    }
  },

  "mcp": {
    "filesystem": {
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user/kali-claw"],
      "enabled": true,
      "timeout": 30000
    },
    "brave-search": {
      "type": "local",
      "command": ["npx", "-y", "@anthropic-ai/mcp-server-brave-search"],
      "enabled": true,
      "environment": {
        "BRAVE_API_KEY": "{env:BRAVE_API_KEY}"
      }
    },
    "github": {
      "type": "local",
      "command": ["npx", "-y", "@anthropic-ai/mcp-server-github"],
      "enabled": true,
      "environment": {
        "GITHUB_TOKEN": "{env:GITHUB_TOKEN}"
      }
    },
    "playwright": {
      "type": "local",
      "command": ["npx", "-y", "@playwright/mcp"],
      "enabled": true
    }
  },

  "permission": {
    "edit": "ask",
    "bash": {
      "rm *": "deny",
      "rm -rf *": "deny",
      "mkfs *": "deny",
      "dd *": "deny",
      "*": "ask"
    }
  },

  "tool_output": {
    "max_lines": 2000,
    "max_bytes": 51200
  },

  "compaction": {
    "auto": true,
    "tail_turns": 15
  }
}
```

---

## 六、使用场景

### 6.1 渗透测试流程

完整的渗透测试工作流：

```
# 步骤 1：搭建靶场
你: /setup-lab DVWA

# 步骤 2：信息收集
你: /recon target.com

# 步骤 3：Web 渗透测试
你: /web-pentest http://target.com

# 步骤 4：深度 SQL 注入
你: /sqli http://target.com/vuln.php?id=1

# 步骤 5：验证发现
你: /verify "发现 UNION 注入漏洞，可提取用户表"

# 步骤 6：生成报告
你: /gen-report "target.com 渗透测试"
```

### 6.2 安全审计

代码安全审计流程：

```
# 审计一个项目
你: /security-review /path/to/project

AI 会自动执行：
1. 文件分类和安全面评估
2. 依赖库检测和已知漏洞查询
3. 密钥/凭据泄露扫描
4. 注入漏洞检查（SQL 注入、XSS、命令注入）
5. 认证/授权逻辑审查
6. 生成审计报告
```

### 6.3 学习和研究

系统学习安全技能：

```
# 学习特定领域
你: /learn web-sqli
你: /learn network-pentest
你: /learn password-attack
你: /learn cloud-security

# 查询特定 CVE
你: /check-cve CVE-2024-1234

# 搭建靶场练习
你: /setup-lab SQLi-Labs
你: /setup-lab WebGoat
```

### 6.4 报告生成

```
你: /gen-report "example.com 外部渗透测试"

AI 会根据 kali-claw 的报告模板（skills/article-writing/SKILL.md）生成：
- 执行摘要
- 测试范围和方法论
- 漏洞发现列表（含 CVSS 评分）
- 详细技术分析
- 修复建议和优先级
- 附录（证据截图、日志）
```

---

## 七、常见问题

### Q1：OpenCode 安装失败

**问题**：`curl -fsSL https://opencode.ai/install | bash` 失败

**解决方案**：

```bash
# 方案一：使用 Go install
go install github.com/opencode-ai/opencode@latest

# 方案二：手动下载
# 前往 https://github.com/opencode-ai/opencode/releases
# 下载对应平台的二进制文件

# 方案三：从源码构建
git clone https://github.com/opencode-ai/opencode.git
cd opencode
go build -o /usr/local/bin/opencode ./cmd/opencode
```

### Q2：API Key 配置

**问题**：启动后提示 API Key 缺失

**解决方案**：

```bash
# 检查环境变量
echo $ANTHROPIC_API_KEY
echo $OPENAI_API_KEY

# 如果为空，设置环境变量
export ANTHROPIC_API_KEY="sk-ant-..."
# 或
export OPENAI_API_KEY="sk-..."

# 写入 shell 配置使其持久化
echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.zshrc
source ~/.zshrc

# 或在 opencode.json 中使用 {env:VAR_NAME} 引用环境变量
# 或直接写入 provider 配置（不推荐，有安全风险）
```

### Q3：模型选择建议

| 需求 | 推荐模型 | 理由 |
|------|----------|------|
| 专业渗透测试 | Claude Sonnet | 最佳工具使用和推理能力 |
| 日常安全分析 | Claude Haiku | 性价比高，响应快 |
| 代码审计 | Claude Sonnet | 代码理解深度最好 |
| 学习研究 | GPT-4o / Claude Sonnet | 知识面广 |
| 离线/内网 | Llama 3 (Ollama) | 无需网络，数据本地 |
| 预算有限 | Claude Haiku + Ollama | 混合使用降低成本 |

> **建议**：将 `model` 设为 Claude Sonnet 用于复杂任务，`small_model` 设为 Claude Haiku 用于轻量操作。OpenCode 会自动选择合适的模型。

### Q4：沙箱和权限限制

**问题**：OpenCode 拒绝执行某些命令

**解决方案**：

在 `opencode.json` 的 `permission.bash` 中配置命令白名单：

```json
{
  "permission": {
    "bash": {
      "nmap *": "allow",       // 自动允许
      "sqlmap *": "allow",     // 自动允许
      "msfconsole *": "ask",   // 每次询问
      "rm *": "deny",          // 完全禁止
      "*": "ask"               // 默认询问
    }
  }
}
```

权限级别说明：
- `allow` — 自动允许，不询问
- `ask` — 每次执行前询问用户确认
- `deny` — 完全禁止执行

### Q5：与 OpenClaw / Claude Code 并行使用

**问题**：能否同时使用多个 AI 智能体框架？

**可以**。kali-claw 的技能包是纯 Markdown 文件，不依赖特定框架：

```bash
# OpenClaw 方式
cd ~/.openclaw/workspace-kali-claw
openclaw gateway start

# OpenCode 方式（另一个终端）
cd ~/kali-claw
opencode

# Claude Code 方式（另一个终端）
cd ~/kali-claw
claude

# 三者读取的是同一套文件，互不干扰
```

> **注意**：不要让多个框架同时修改同一个记忆文件（如 `MEMORY.md`），建议每个框架使用独立的工作空间副本。

### Q6：远程 Kali Linux 配置

**问题**：本地机器不是 Kali Linux，如何使用安全工具？

**方案一：SSH 执行**

在 OpenCode 对话中指示 AI 通过 SSH 执行命令：

```
你: 通过 SSH 连接 user@kali-server，执行 nmap 扫描 192.168.1.0/24

AI: $ ssh user@kali-server "nmap -sV -sC 192.168.1.0/24"
```

**方案二：SSH 配置别名**

```bash
# ~/.ssh/config
Host kali
    HostName 192.168.1.50
    User root
    IdentityFile ~/.ssh/id_ed25519
    ForwardAgent yes
```

之后只需 `ssh kali "command"` 即可。

**方案三：Docker 容器**

```bash
# 在任意 Linux 机器上运行 Kali 容器
docker run -d --name kali kali-claw-env
docker exec kali nmap -sV target
```

### Q7：更新 kali-claw 技能包

```bash
cd ~/kali-claw
git pull origin main

# skills/ 目录更新后，OpenCode 下次启动会自动读取最新文件
# opencode.json 和 .opencode/instructions.md 一般不需要更新
# 除非新增了技能域，需要更新 instructions.md 中的技能索引表
```

### Q8：上下文窗口管理

**问题**：长会话中 AI 丢失早期上下文

**解决方案**：

OpenCode 的 `compaction` 配置可以自动压缩上下文：

```json
{
  "compaction": {
    "auto": true,
    "tail_turns": 15
  }
}
```

建议：
- 复杂渗透测试分为多个阶段，每个阶段一个会话
- 使用 `/gen-report` 在阶段结束时生成报告
- 关键发现写入 `memory/` 目录持久化

### Q9：MCP 服务器启动失败

**问题**：MCP 服务器连接超时或启动失败

**解决方案**：

```bash
# 1. 确认 Node.js 已安装
node --version  # 需要 v18+

# 2. 手动测试 MCP 服务器
npx -y @modelcontextprotocol/server-filesystem /tmp/test

# 3. 检查网络（远程 MCP 服务器）
curl https://mcp.example.com/api

# 4. 在 opencode.json 中增加超时时间
{
  "mcp": {
    "my-server": {
      "timeout": 60000
    }
  }
}

# 5. 禁用有问题的 MCP 服务器
{
  "mcp": {
    "my-server": {
      "enabled": false
    }
  }
}
```

---

## 八、架构对比

### 8.1 组件映射

| kali-claw (OpenClaw) | OpenCode 对应 | 迁移方式 | 说明 |
|----------------------|--------------|----------|------|
| SOUL.md | `.opencode/instructions.md` | 提取核心内容 | 身份、12 条法则、安全边界 |
| AGENTS.md | OpenCode `AGENTS.md` | 保持原位 | OpenCode 原生支持 |
| IDENTITY.md | `.opencode/instructions.md` 技能索引 | 提取技能标签表 | AI 通过索引找到对应技能文件 |
| USER.md | 不需要迁移 | -- | OpenCode 不需要此文件 |
| MEMORY.md | 项目文件（按需读取） | 保持原位 | AI 可读取长期记忆 |
| TOOLS.md | 项目文件（按需读取） | 保持原位 | AI 可读取工具进度 |
| HEARTBEAT.md | OpenCode 无对应 | 不迁移 | OpenCode 无心跳机制 |
| skills/*/SKILL.md | 项目文件（按需读取） | **保持原位，不修改** | 核心知识资产 |
| skills/*/payloads.md | 项目文件（按需读取） | **保持原位，不修改** | 攻击载荷库 |
| skills/*/test-cases.md | 项目文件（按需读取） | **保持原位，不修改** | 测试用例模板 |
| skills/*/guides/ | 项目文件（按需读取） | **保持原位，不修改** | 深度学习资料 |
| openclaw agents add | `opencode.json` agent 配置 | 新建配置文件 | 定义 Agent 角色和权限 |
| openclaw gateway start | `opencode` 命令 | 新启动方式 | OpenCode TUI 界面 |

### 8.2 文件变更汇总

迁移过程中**需要创建的文件**：

| 文件 | 用途 | 方式 |
|------|------|------|
| `opencode.json` | OpenCode 项目配置 | 标准/完整迁移 |
| `.opencode/instructions.md` | kali-claw 角色指令 | 标准/完整迁移 |

迁移过程中**不需要修改的文件**：

- `SOUL.md` — 保持原位
- `AGENTS.md` — 保持原位，OpenCode 原生支持
- `IDENTITY.md` — 保持原位
- `USER.md` — 保持原位
- `MEMORY.md` — 保持原位
- `TOOLS.md` — 保持原位
- `HEARTBEAT.md` — 保持原位
- `skills/` 目录下所有文件 — **保持原位，不做任何修改**

### 8.3 功能对比

| 功能 | OpenClaw + kali-claw | OpenCode + kali-claw |
|------|---------------------|---------------------|
| 角色定义 | SOUL.md 自动加载 | instructions.md + opencode.json |
| 技能加载 | 按需读取 | 按需读取 |
| 自定义命令 | 无 | 有（opencode.json command） |
| MCP 工具 | 无 | 有 |
| 心跳任务 | 有 | 无 |
| 记忆系统 | 三层（daily/chronicle/MEMORY） | 文件读取（无自动管理） |
| 多 Agent | openclaw agents 管理 | opencode.json agent 配置 |
| 权限控制 | SOUL.md 规则 | opencode.json permission |
| 模型切换 | 固定模型 | 随时切换 |
| 离线使用 | 取决于模型 API | 支持 Ollama 本地模型 |

---

## 九、快速参考卡

### 常用命令

```bash
# 启动
cd ~/kali-claw && opencode

# 快捷命令
/recon <target>           # 侦察
/web-pentest <url>        # Web 渗透
/sqli <url>               # SQL 注入
/xss <url>                # XSS 测试
/network-attack <target>  # 网络渗透
/password-audit <target>  # 密码审计
/wifi-test <target>       # WiFi 测试
/cloud-audit <target>     # 云安全审计
/container-scan <target>  # 容器扫描
/apitest <url>            # API 测试
/learn <skill>            # 学习技能
/security-review <path>   # 安全审查
/gen-report <name>        # 生成报告
/setup-lab <type>         # 搭建靶场
/check-cve <cve-id>       # 查询 CVE
/verify <finding>         # 验证发现
```

### 目录结构（迁移后）

```
kali-claw/
├── opencode.json              # [新增] OpenCode 项目配置
├── .opencode/
│   └── instructions.md        # [新增] kali-claw 角色指令
├── SOUL.md                    # [不变] 身份 + 黑客法则
├── AGENTS.md                  # [不变] 工作空间配置
├── IDENTITY.md                # [不变] 技能标签
├── USER.md                    # [不变] 用户配置
├── MEMORY.md                  # [不变] 长期记忆
├── TOOLS.md                   # [不变] 工具进度
├── HEARTBEAT.md               # [不变] 心跳框架
├── skills/                    # [不变] 49 个技能域
│   ├── web-sqli/
│   │   ├── SKILL.md
│   │   ├── payloads.md
│   │   ├── test-cases.md
│   │   └── guides/
│   ├── network-pentest/
│   ├── cloud-security/
│   └── ... (49 domains)
├── memory/                    # [不变] 每日记忆
├── chronicle/                 # [不变] 月度编年史
└── bak/                       # [不变] 备份
```

### 迁移检查清单

- [ ] OpenCode 已安装并验证版本
- [ ] AI 提供商 API Key 已配置
- [ ] kali-claw 工作空间已克隆
- [ ] `opencode.json` 已创建并配置
- [ ] `.opencode/instructions.md` 已创建
- [ ] Kali Linux 环境可用（本机/SSH/Docker）
- [ ] 首次启动测试成功
- [ ] 自定义命令测试通过
- [ ] 技能文件读取测试通过

---

_基于 kali-claw v0.1.7 + OpenCode 最新版编写 | 2026-05-18_
