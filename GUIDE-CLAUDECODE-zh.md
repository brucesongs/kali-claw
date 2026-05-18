# kali-claw 技能包迁移指南：在 Claude Code 上使用

> 面向 v0.1.7 | 将 kali-claw 安全技能包迁移到 Anthropic 官方 CLI 工具 Claude Code 的完整指南

---

## 一、概述

### 1.1 Claude Code 是什么

Claude Code 是 Anthropic 推出的 **官方命令行工具**，直接在终端中与 Claude 交互。它不是一个聊天机器人的封装，而是 Claude 的 **原生运行时**——Claude Code 本身就是运行环境。

**核心能力**：

- **CLI 接口** — 在终端中直接使用 Claude，支持多轮对话和上下文管理
- **CLAUDE.md 项目指令** — 项目根目录下的 Markdown 文件，定义 Claude 在该项目中的行为规则（类似系统提示词）
- **自定义智能体（Agents）** — 放在 `~/.claude/agents/` 目录下的专业提示文件，可用 Agent 工具调用
- **规则（Rules）** — 放在 `~/.claude/rules/` 下的行为准则，对所有项目或特定项目生效
- **MCP 服务器** — 通过 Model Context Protocol 集成外部工具，让 Claude 直接调用 nmap、sqlmap 等命令
- **记忆系统** — 持久化的会话记忆，存储在 `~/.claude/projects/<project>/memory/` 目录
- **Hooks** — 在工具调用前/后自动执行的 Shell 命令（PreToolUse/PostToolUse/Stop）

**与 OpenClaw 的关键区别**：

| 特性 | OpenClaw | Claude Code |
|------|----------|-------------|
| 运行时 | 独立的 npm 框架 | Claude 原生 CLI，无需额外框架 |
| 技能系统 | Markdown 文件，由框架解析 | Markdown 文件 + 自定义智能体 |
| 工具调用 | 通过终端命令 | 通过 Bash 工具 + MCP 服务器 |
| 记忆持久化 | 文件系统（memory/ 目录） | 文件系统（~/.claude/projects/） |
| 安装依赖 | 需要 Node.js + OpenClaw | 只需要 Claude Code 本身 |

### 1.2 kali-claw 技能包的价值

kali-claw 包含 **49 个安全技能域** 和 **518 个 Kali Linux 工具知识库**，是一套结构化的安全测试知识体系：

- 每个技能域包含：`SKILL.md`（方法论）+ `payloads.md`（攻击载荷）+ `test-cases.md`（测试用例）+ `guides/`（深度指南）
- 根级配置：`SOUL.md`（12 条黑客法则）、`IDENTITY.md`（技能标签）、`TOOLS.md`（518 工具清单）
- 核心优势：**kali-claw 的技能本质上是 Markdown 文件**，可以直接被 Claude Code 读取和使用，无需格式转换

### 1.3 迁移策略总览

迁移不需要"转换格式"，只需要正确地放置和引用。提供三种迁移深度：

| 迁移方式 | 耗时 | 获得能力 | 适合谁 |
|---------|------|---------|--------|
| **最小迁移** | 5 分钟 | 直接在 Claude Code 中引用技能文件 | 想快速体验的用户 |
| **标准迁移** | 30 分钟 | 自定义智能体 + 规则 + 记忆系统 | 日常使用的用户 |
| **完整迁移** | 2 小时 | MCP 工具集成 + Hooks 自动化 + 完整智能体 | 专业渗透测试工程师 |

---

## 二、环境准备

### 2.1 安装 Claude Code

```bash
# macOS / Linux
npm install -g @anthropic-ai/claude-code

# 验证安装
claude --version

# 首次启动（需要 Anthropic 账号）
claude
```

**常见安装问题**：

| 问题 | 解决方案 |
|------|---------|
| 权限不足 (EACCES) | `sudo npm install -g @anthropic-ai/claude-code` |
| npm 镜像超时（国内用户） | `npm config set registry https://registry.npmmirror.com` |
| Node.js 版本过低 | 使用 nvm 安装最新 LTS：`nvm install --lts` |

### 2.2 准备 Kali Linux 环境

选择以下三种方案之一：

**方案 A：Kali Linux 本机（推荐）**

```bash
# 直接在 Kali 上运行 Claude Code
nmap --version  # 验证工具可用
sqlmap --version
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

验证文件结构：

```bash
ls -la
# 应看到：SOUL.md  AGENTS.md  IDENTITY.md  USER.md  MEMORY.md  TOOLS.md  HEARTBEAT.md  skills/  memory/  chronicle/
```

### 2.4 环境检查清单

- [ ] Claude Code 已安装（`claude --version`）
- [ ] Kali Linux 可用（本机 / SSH 远程 / Docker 容器）
- [ ] kali-claw 已克隆到本地
- [ ] 基本 Kali 工具可用（`nmap --version` 验证）
- [ ] 网络连接正常

---

## 三、方式一：最小迁移（5 分钟）

### 3.1 直接打开项目

```bash
cd kali-claw
claude
```

Claude Code 启动时会 **自动读取项目根目录的 `CLAUDE.md`** 作为项目指令。kali-claw 的 `CLAUDE.md` 已经包含项目概述和架构说明，Claude 会理解这是一个安全测试知识库。

### 3.2 开始使用

直接用自然语言对话，让 Claude 读取对应的技能文件：

```
你：阅读 skills/web-sqli/SKILL.md，然后帮我分析一个 SQL 注入漏洞

Claude：[读取 SKILL.md]
      我已了解 SQL 注入技能的方法论。这个技能覆盖以下注入类型：
      - Union-based / Error-based / Boolean-blind / Time-blind
      - Double Query / Stacked Queries / Out-of-band

      请提供你的目标信息，我来按方法论进行分析。
```

```
你：查看 skills/web-sqli/payloads.md，给我一个 UNION 注入的载荷

Claude：[读取 payloads.md]
      基于 payloads.md 中的 UNION Injection 部分，以下是一个标准载荷：

      ' UNION SELECT 1,2,3-- -

      步骤：
      1. 先用 ORDER BY 确定列数：' ORDER BY 5-- -
      2. 找到回显位：' UNION SELECT 1,2,3-- -
      3. 提取数据：' UNION SELECT database(),version(),user()-- -
```

```
你：按照 skills/web-sqli/test-cases.md 的 TC-S001 执行测试

Claude：[读取 test-cases.md]
      按照 TC-S001 GET 参数注入点检测的测试步骤：

      步骤 1: 测试单引号触发 SQL 错误
        ?id=1'

      步骤 2: 字符型注入确认
        ?id=1' AND '1'='1   （页面应正常）
        ?id=1' AND '1'='2   （页面应异常）

      步骤 3: 数值型注入确认
        ?id=1 AND 1=1       （页面应正常）
        ?id=1 AND 1=2       （页面应异常）

      步骤 4: 测试不同闭合方式：' / " / ') / "))

      请提供目标 URL，我来帮你执行。
```

### 3.3 最小迁移的局限

- **每次都要手动引用技能文件路径**（如"阅读 skills/web-sqli/SKILL.md"）
- **没有持久记忆** — 关闭会话后，Claude 不记得之前的分析结果
- **没有自动化智能体** — 无法用 `/web-sqli` 这样的快捷命令触发技能
- **没有工具集成** — 不能直接调用 nmap、sqlmap 等工具

适合：快速体验、临时测试、一次性任务。

---

## 四、方式二：标准迁移（30 分钟）

### 4.1 配置 CLAUDE.md（项目指令）

在 kali-claw 项目的 `CLAUDE.md` 中追加安全智能体的行为指令。以下是需要添加到 CLAUDE.md 末尾的内容：

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

### Skill Index
49 security skill domains are available under skills/:

**Web Security**: web-sqli, web-xss, web-ssrf, web-auth-bypass, web-access-control
**Network**: network-pentest, wifi-pentest, osint, recon-osint
**Exploitation**: post-exploitation, password-attack, crypto-attacks
**Code & Binary**: binary-reverse, repo-scan, security-review, ai-security
**Cloud & Infra**: cloud-security, container-security, supply-chain-security
**Meta Skills**: autonomous-loops, council, multi-agent-collaboration, ai-fuzzing
**Infrastructure**: terminal-ops, safety-guard, chronicle, continuous-learning
**Knowledge**: deep-research, search-first, exa-search, data-scraper-agent

When a security task is requested, automatically identify the relevant skill domain and read its SKILL.md first.

### Safety Boundaries
- Only test targets within explicitly authorized scope
- Use safety-guard principles from skills/safety-guard/SKILL.md
- Log all actions to memory/YYYY-MM-DD.md
- Never store credentials or tokens in memory files
```

### 4.2 创建自定义智能体

将每个安全技能域转换为 Claude Code 自定义智能体。智能体文件放在 `~/.claude/agents/` 目录。

**创建智能体目录**：

```bash
mkdir -p ~/.claude/agents
```

**示例：web-sqli 分析智能体**（`~/.claude/agents/web-sqli-analyzer.md`）：

```markdown
---
name: web-sqli-analyzer
description: SQL injection vulnerability analysis and exploitation specialist. Covers Union/Blind/Time-based/Error-based/Double Query injection detection, exploitation, and defense recommendations.
tools:
  - Bash
  - Read
  - Write
  - Grep
  - Glob
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

**批量创建更多智能体**（可选，按需创建）：

```bash
# 网络扫描智能体
cat > ~/.claude/agents/network-scanner.md << 'AGENT_EOF'
---
name: network-scanner
description: Network penetration testing specialist. Port scanning, service identification, vulnerability detection, and lateral movement planning.
tools:
  - Bash
  - Read
  - Write
  - Grep
---

You are a network penetration testing specialist. Read skills/network-pentest/SKILL.md for methodology. Follow the attack chain: Reconnaissance -> Scanning -> Enumeration -> Vulnerability Assessment -> Exploitation. Use nmap as primary tool. Document all findings.
AGENT_EOF

# 安全审计智能体
cat > ~/.claude/agents/security-auditor.md << 'AGENT_EOF'
---
name: security-auditor
description: OWASP Top 10 security audit specialist. Systematic code review, configuration analysis, and vulnerability assessment.
tools:
  - Bash
  - Read
  - Write
  - Grep
  - Glob
---

You are a security audit specialist. Read skills/security-review/SKILL.md for methodology. Perform OWASP Top 10 audit systematically. Generate structured reports with severity ratings and remediation steps.
AGENT_EOF
```

### 4.3 创建安全规则文件

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

### 4.4 使用自定义智能体

启动 Claude Code 后，可以用以下方式触发智能体：

**方式一：自然语言触发**（Claude 自动匹配）

```
你：帮我检测 http://testsite.com/login 的 SQL 注入漏洞

Claude：[自动识别为 SQL 注入任务，加载 web-sqli-analyzer 智能体]
      读取 skills/web-sqli/SKILL.md 中的方法论...
```

**方式二：明确指定智能体**

```
你：使用 web-sqli-analyzer 智能体分析这个登录表单

Claude：[加载指定智能体，按智能体中的操作流程执行]
```

**方式三：通过 Bash 工具调用**

Claude 在智能体模式下会自动使用 Bash 工具执行安全命令：

```
你：用 sqlmap 测试 http://testsite.com/page?id=1

Claude：执行 sqlmap 命令...
      [通过 Bash 工具运行]
      sqlmap -u "http://testsite.com/page?id=1" --batch --dbs --level 3
```

### 4.5 配置记忆系统

将 kali-claw 的记忆映射到 Claude Code 的记忆系统。

**理解两套记忆系统的对应关系**：

| kali-claw 记忆 | Claude Code 记忆 | 说明 |
|---------------|-----------------|------|
| `memory/YYYY-MM-DD.md` | `~/.claude/projects/<project>/memory/` | 每日会话记录 |
| `MEMORY.md`（根目录） | 项目记忆文件 | 长期精炼知识 |
| `chronicle/YYYY-MM/*.md` | 手动维护 | 月度里程碑 |

**配置项目记忆**：

```bash
# 确定项目记忆路径
# Claude Code 使用项目路径的哈希作为目录名
# 查看实际路径
ls ~/.claude/projects/

# 将 kali-claw 的长期记忆复制到 Claude Code 记忆
PROJECT_MEMORY=~/.claude/projects/$(echo -n "/path/to/kali-claw" | md5sum | cut -d' ' -f1)/memory
mkdir -p "$PROJECT_MEMORY"

# 复制长期记忆
cp MEMORY.md "$PROJECT_MEMORY/long-term-knowledge.md"

# 复制近期每日记忆（可选）
cp memory/2026-05-*.md "$PROJECT_MEMORY/"
```

**记忆系统的使用**：

在会话中，你可以让 Claude 将重要发现写入记忆：

```
你：把这个 SQL 注入漏洞的发现记录到记忆中

Claude：[将发现写入 ~/.claude/projects/.../memory/ 文件]
      已记录到记忆文件中。下次会话时我仍会记得这个发现。
```

---

## 五、方式三：完整迁移（2 小时）

### 5.1 MCP 服务器集成

通过 MCP 服务器，让 Claude Code **直接调用** Kali 安全工具，而不需要手动输入命令。

**安装 MCP SDK**：

```bash
pip install mcp
```

**创建 MCP 服务器目录**：

```bash
mkdir -p ~/kali-mcp-servers
```

**完整的 nmap MCP 服务器示例**（`~/kali-mcp-servers/nmap_server.py`）：

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
            description="Run nmap network scan. Supports common scan types: service detection, version detection, OS detection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range (default: 1-1000)",
                        "default": "1-1000"
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "Scan type: -sV (version), -sC (default scripts), -O (OS detect), -A (aggressive)",
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
            description="Run nmap vulnerability scan using NSE vuln category scripts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target to scan for vulnerabilities"
                    }
                },
                "required": ["target"]
            }
        )
    ]

def validate_target(target: str) -> bool:
    """Basic target validation — reject obviously invalid input."""
    if not target or len(target) > 256:
        return False
    # Block shell metacharacters for safety
    blocked = set(";|&`$(){}[]<>!#~")
    return not any(c in blocked for c in target)

def run_nmap(args: list[str], timeout: int = 300) -> str:
    """Execute nmap and return stdout."""
    try:
        result = subprocess.run(
            ["nmap"] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Error: nmap scan timed out after 300 seconds"
    except FileNotFoundError:
        return "Error: nmap not found. Install with: sudo apt install nmap"

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "nmap_scan":
        target = arguments["target"]
        if not validate_target(target):
            return [TextContent(type="text", text="Error: Invalid target format")]

        ports = arguments.get("ports", "1-1000")
        scan_type = arguments.get("scan_type", "-sV")
        extra = arguments.get("extra_args", "")

        args = scan_type.split() + ["-p", ports]
        if extra:
            args += extra.split()
        args.append(target)

        output = run_nmap(args)
        return [TextContent(type="text", text=output)]

    elif name == "nmap_vuln_scan":
        target = arguments["target"]
        if not validate_target(target):
            return [TextContent(type="text", text="Error: Invalid target format")]

        output = run_nmap(["--script", "vuln", target], timeout=600)
        return [TextContent(type="text", text=output)]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]

if __name__ == "__main__":
    import asyncio
    asyncio.run(server.run())
```

**完整的 sqlmap MCP 服务器示例**（`~/kali-mcp-servers/sqlmap_server.py`）：

```python
#!/usr/bin/env python3
"""sqlmap MCP Server — Wraps sqlmap as an MCP tool for Claude Code."""

import subprocess
import os
import tempfile
from mcp.server import Server
from mcp.types import Tool, TextContent

server = Server("kali-sqlmap")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="sqlmap_detect",
            description="Run sqlmap to detect SQL injection vulnerabilities. Non-destructive detection only.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL (e.g., http://target/page?id=1)"
                    },
                    "data": {
                        "type": "string",
                        "description": "POST data (optional, for POST-based injection)"
                    },
                    "level": {
                        "type": "integer",
                        "description": "Detection level 1-5 (default: 3)",
                        "default": 3
                    },
                    "risk": {
                        "type": "integer",
                        "description": "Risk level 1-3 (default: 2)",
                        "default": 2
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="sqlmap_dbs",
            description="Enumerate databases via detected SQL injection. Requires prior detection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL with confirmed injection"
                    },
                    "batch": {
                        "type": "boolean",
                        "description": "Use default answers (non-interactive mode)",
                        "default": True
                    }
                },
                "required": ["url"]
            }
        )
    ]

def validate_url(url: str) -> bool:
    """Basic URL validation."""
    return url.startswith("http://") or url.startswith("https://")

def run_sqlmap(args: list[str], timeout: int = 300) -> str:
    """Execute sqlmap and return output."""
    try:
        result = subprocess.run(
            ["sqlmap"] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Error: sqlmap timed out"
    except FileNotFoundError:
        return "Error: sqlmap not found. Install with: sudo apt install sqlmap"

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "sqlmap_detect":
        url = arguments["url"]
        if not validate_url(url):
            return [TextContent(type="text", text="Error: Invalid URL format")]

        level = arguments.get("level", 3)
        risk = arguments.get("risk", 2)
        data = arguments.get("data")

        args = ["-u", url, "--batch", f"--level={level}", f"--risk={risk}"]
        if data:
            args.extend(["--data", data])

        output = run_sqlmap(args, timeout=600)
        return [TextContent(type="text", text=output)]

    elif name == "sqlmap_dbs":
        url = arguments["url"]
        if not validate_url(url):
            return [TextContent(type="text", text="Error: Invalid URL format")]

        args = ["-u", url, "--batch", "--dbs"]
        output = run_sqlmap(args, timeout=600)
        return [TextContent(type="text", text=output)]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]

if __name__ == "__main__":
    import asyncio
    asyncio.run(server.run())
```

**配置 MCP 服务器**：

在项目根目录创建 `.mcp.json`：

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

或者全局配置在 `~/.claude.json`：

```json
{
  "mcpServers": {
    "kali-nmap": {
      "command": "python3",
      "args": ["~/kali-mcp-servers/nmap_server.py"]
    },
    "kali-sqlmap": {
      "command": "python3",
      "args": ["~/kali-mcp-servers/sqlmap_server.py"]
    }
  }
}
```

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

远程 MCP 服务器需要在执行 nmap 时通过 SSH 调用：

```python
# remote_nmap_server.py 中的关键修改
import os

KALI_HOST = os.environ.get("KALI_HOST", "user@kali-host")
SSH_KEY = os.environ.get("KALI_SSH_KEY", "~/.ssh/id_ed25519")

def run_nmap_remote(args: list[str], timeout: int = 300) -> str:
    ssh_cmd = ["ssh", "-i", SSH_KEY, KALI_HOST, "nmap"] + args
    result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout + result.stderr
```

### 5.2 配置 Hooks（自动化）

使用 Claude Code Hooks 实现 kali-claw HEARTBEAT 的部分功能。

**范围检查 Hook**（PreToolUse）：

在执行 Bash 命令前自动检查目标是否在授权范围内。

创建 `~/kali-hooks/check-scope.sh`：

```bash
#!/bin/bash
# 检查 Bash 命令是否在授权范围内
# 由 Claude Code PreToolUse Hook 调用

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# 读取授权范围文件
SCOPE_FILE=".scope"
if [ ! -f "$SCOPE_FILE" ]; then
    exit 0  # 没有范围文件则不限制
fi

# 检查命令中是否包含目标
AUTHORIZED_TARGETS=$(grep -v '^#' "$SCOPE_FILE" | grep -v '^$')

# 记录执行日志
echo "[$(date)] Command: $COMMAND" >> .claude-execution.log

exit 0
```

创建项目级范围文件 `.scope`（在 kali-claw 项目根目录）：

```
# Authorized Test Targets
# One target per line, lines starting with # are comments
192.168.1.0/24
testphp.vulnweb.com
*.example.com
```

**在 `~/.claude/settings.json` 中配置 Hooks**：

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
    ]
  }
}
```

### 5.3 迁移后的完整项目结构

```
kali-claw/                           <-- 项目根目录
├── CLAUDE.md                        <-- 项目指令（追加安全智能体模式）
├── SOUL.md                          <-- 12 条黑客法则（保留原样）
├── USER.md                          <-- 用户信息（保留原样）
├── IDENTITY.md                      <-- 技能标签（保留原样）
├── AGENTS.md                        <-- 工作空间配置（保留原样）
├── MEMORY.md                        <-- 长期记忆（保留原样）
├── TOOLS.md                         <-- 工具清单（保留原样）
├── HEARTBEAT.md                     <-- 心跳任务（保留原样）
├── .mcp.json                        <-- MCP 服务器配置（新增）
├── .scope                           <-- 授权范围文件（新增）
├── skills/                          <-- 49 个技能域（保留原样）
│   ├── web-sqli/
│   │   ├── SKILL.md
│   │   ├── payloads.md
│   │   ├── test-cases.md
│   │   └── guides/
│   ├── network-pentest/
│   ├── osint/
│   └── ...
├── memory/                          <-- 每日记忆日志
├── chronicle/                       <-- 月度里程碑
└── bak/                             <-- 备份目录

~/.claude/
├── agents/                          <-- 自定义智能体（从 skills/ 转换）
│   ├── web-sqli-analyzer.md
│   ├── network-scanner.md
│   ├── security-auditor.md
│   └── ...
├── rules/                           <-- 安全规则
│   └── kali-claw-security.md
├── settings.json                    <-- Hooks 配置
└── projects/                        <-- 项目记忆
    └── <project-hash>/
        └── memory/
            ├── long-term-knowledge.md
            └── ...

~/kali-mcp-servers/                  <-- MCP 服务器（新增）
├── nmap_server.py
├── sqlmap_server.py
└── remote_nmap_server.py

~/kali-hooks/                        <-- Hook 脚本（新增）
└── check-scope.sh
```

---

## 六、使用场景

### 6.1 渗透测试完整流程

以下展示在 Claude Code 中执行完整渗透测试的多轮对话：

**第一步：侦察**

```
你：帮我收集 target.com 的信息，包括子域名、DNS 记录和技术栈

Claude：我来对 target.com 进行全面侦察。读取 skills/recon-osint/SKILL.md 获取方法论...

      按照侦察方法论执行：

      1. DNS 记录查询
      [执行] dig target.com ANY +noall +answer
      [结果] A: 93.184.216.34, MX: mail.target.com, NS: ns1.cloudflare.com

      2. 子域名枚举
      [执行] sublist3r -d target.com
      [结果] 发现 12 个活跃子域名
        - api.target.com (REST API)
        - admin.target.com (登录页面)
        - dev.target.com (开发环境)

      3. Web 技术指纹识别
      [执行] whatweb target.com
      [结果] Nginx 1.18, PHP 7.4, MySQL

      建议：对 admin.target.com 进行端口扫描
```

**第二步：扫描**

```
你：扫描 admin.target.com

Claude：[调用 MCP nmap_scan 工具]
      执行 nmap -sV -sC -p- admin.target.com

      端口扫描结果：
      PORT     STATE  SERVICE    VERSION
      22/tcp   open   ssh        OpenSSH 8.2
      80/tcp   open   http       Nginx 1.18.0
      443/tcp  open   ssl/http   Nginx 1.18.0
      8080/tcp open   http-proxy PHP-FPM 7.4

      发现：8080 端口运行 PHP-FPM，可能存在未授权访问。
      建议：对 admin.target.com:8080 进行目录扫描和漏洞探测。
```

**第三步：漏洞利用**

```
你：admin.target.com:8080 有登录页面，测试 SQL 注入

Claude：[加载 web-sqli-analyzer 智能体，读取 SKILL.md]
      按照 SQL 注入方法论执行测试：

      步骤 1: 注入点探测
      [调用 MCP sqlmap_detect 工具]
      目标：http://admin.target.com:8080/login
      POST 数据：username=admin&password=test

      [sqlmap 结果]
      参数 'username' 存在 Boolean-based blind SQL 注入！
      数据库类型：MySQL >= 5.6
      后端 DBMS：MySQL

      步骤 2: 枚举数据库
      [调用 MCP sqlmap_dbs 工具]

      可用数据库：
      [*] information_schema
      [*] mysql
      [*] performance_schema
      [*] target_app

      发现 SQL 注入漏洞！
      - 注入点：username 参数
      - 类型：Boolean-based blind
      - 数据库：MySQL >= 5.6
      - CVSS 评分：9.8（Critical）

      修复建议：使用参数化查询（预处理语句）替代字符串拼接
```

**第四步：后渗透评估**

```
你：拿到了数据库访问，下一步怎么做？

Claude：[读取 skills/post-exploitation/SKILL.md]
      获得数据库访问后，按照后渗透方法论评估影响：

      1. 数据库内信息收集
         - 列出 target_app 数据库的表：users, sessions, configs, api_keys
         - 检查是否有敏感数据暴露

      2. 提权评估
         - 检查 FILE 权限：是否可读写系统文件
         - 尝试 UDF 提权：是否可通过自定义函数执行系统命令

      3. 持久化评估
         - 记录所有攻击路径
         - 评估每条路径的检测难度

      4. 影响评估
         - 数据泄露范围
         - 系统控制级别
         - 横向移动可能性

      注意：所有操作仅用于评估目的。是否继续深入评估？
```

**第五步：报告生成**

```
你：帮我生成渗透测试报告

Claude：[读取 skills/article-writing/SKILL.md]
      生成渗透测试报告：

      ## 渗透测试报告 — target.com

      ### 1. 执行摘要
      - 测试日期：2026-05-18
      - 目标范围：target.com 及子域名
      - 总体风险等级：高危

      ### 2. 发现摘要
      | # | 漏洞 | 严重程度 | 影响 |
      |---|------|---------|------|
      | 1 | SQL 注入 (admin.target.com) | Critical | 数据库完全控制 |
      | 2 | 开发环境暴露 (dev.target.com) | Medium | 信息泄露 |
      | 3 | 8080 端口未限制访问 | Medium | 攻击面扩大 |

      ### 3. 修复建议（按优先级）
      1. 立即使用参数化查询修复 SQL 注入
      2. 关闭 dev 环境的公网访问
      3. 限制 8080 端口仅内网访问

      [已将报告记录到记忆中]
```

### 6.2 安全审计

```
你：使用 security-auditor 智能体对 http://testphp.vulnweb.com 进行 OWASP 审计

Claude：[加载 security-auditor 智能体]
      [读取 skills/security-review/SKILL.md]
      按照 OWASP Top 10 逐项审计：

      A01 - Broken Access Control
      [检查] 发现 IDOR，可越权访问其他用户数据

      A02 - Cryptographic Failures
      [检查] HTTP 未强制跳转 HTTPS

      A03 - Injection
      [检查] 发现 SQL 注入和 XSS 漏洞

      A05 - Security Misconfiguration
      [检查] 默认配置未修改，错误信息暴露堆栈

      A07 - Auth Failures
      [检查] 登录无速率限制，可暴力破解

      总体评分：高风险
      优先修复：A03 Injection + A01 Access Control
```

### 6.3 学习与研究

```
你：我想学习 SQL 注入，从哪里开始？

Claude：[读取 skills/web-sqli/SKILL.md 和 guides/ 目录]
      按照技能方法论制定学习路径：

      第一步：理论基础
      - SQL 注入原理：用户输入被直接拼接到 SQL 查询中
      - 注入类型：Union-based / Boolean-blind / Time-blind / Error-based

      第二步：搭建练习环境
      docker run -d -p 80:80 acgpiano/sqli-labs

      第三步：从简单到复杂
      - Less-1：Union 字符型注入（入门）
      - Less-5：Boolean 盲注（进阶）
      - Less-15：Time 盲注（高级）

      每关我会讲解原理、给出提示。准备好了吗？
```

### 6.4 Council 多视角分析

```
你：用 council 模式分析一下发现的 SQL 注入漏洞

Claude：[读取 skills/council/SKILL.md]
      启动 Council 多视角分析：

      [攻击者视角]
      - 可通过 SQL 注入获取数据库完全控制
      - 通过 FILE 权限可能实现 RCE
      - 建议测试：写入 WebShell、读取 /etc/passwd

      [防御者视角]
      - 根本原因：未使用参数化查询
      - 修复方案：使用预处理语句 + WAF 规则
      - 检测方案：监控异常 SQL 查询模式

      [审计者视角]
      - CVSS 评分：9.8 (Critical)
      - 合规影响：违反 OWASP A03、PCI-DSS 6.5
      - 需要书面记录完整攻击链

      综合建议：立即修复，同时检查其他页面是否存在同类问题。
```

### 6.5 报告生成

```
你：帮我生成一份安全报告，关于今天发现的所有漏洞

Claude：[读取 skills/article-writing/SKILL.md]
      按照 article-writing 技能的方法论生成报告：

      ## 安全评估报告

      ### 元信息
      - 评估日期：2026-05-18
      - 目标：target.com
      - 方法论：OWASP Top 10 + PTES

      ### 发现摘要
      | ID | 标题 | CVSS | 状态 |
      |----|------|------|------|
      | V-001 | SQL Injection | 9.8 | Open |
      | V-002 | XSS (Reflected) | 6.1 | Open |
      | V-003 | IDOR | 5.3 | Open |

      ### 详细发现
      [每个漏洞的：描述、复现步骤、证据、影响分析、修复建议]

      [报告已写入 memory/2026-05-18-report.md]
```

---

## 七、常见问题

### Q1: Claude Code 可以在 Kali Linux 上运行吗？

可以。Kali Linux 基于 Debian，只需要安装 Node.js >= 18：

```bash
# 安装 Node.js
sudo apt update
sudo apt install -y nodejs npm
# 或使用 nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
nvm install --lts

# 安装 Claude Code
npm install -g @anthropic-ai/claude-code
claude --version
```

### Q2: MCP 服务器无法连接

**症状**：Claude Code 提示 MCP 服务器启动失败

**排查步骤**：

```bash
# 1. 检查 Python 和 MCP SDK 是否安装
python3 --version
pip show mcp

# 2. 手动测试 MCP 服务器
python3 ~/kali-mcp-servers/nmap_server.py
# 应该无报错启动

# 3. 检查 .mcp.json 或 ~/.claude.json 中的路径
# 确保使用绝对路径

# 4. 检查权限
chmod +x ~/kali-mcp-servers/*.py
```

### Q3: 自定义智能体不触发

**排查**：

```bash
# 1. 检查智能体文件位置
ls ~/.claude/agents/

# 2. 检查文件格式（必须有 YAML frontmatter）
head -5 ~/.claude/agents/web-sqli-analyzer.md
# 应以 --- 开头，包含 name 和 description 字段

# 3. 检查 description 是否足够描述性
# Claude 根据 description 匹配任务到智能体
```

### Q4: 如何保持 kali-claw 原项目更新

```bash
cd kali-claw
git pull origin main

# 你的自定义智能体和规则不需要改
# 它们引用的是 skills/ 下的文件路径，内容更新后自动生效
```

### Q5: Claude Code 的记忆会丢失吗

不会。Claude Code 的记忆存储在磁盘文件中（`~/.claude/projects/<hash>/memory/`），不会随会话结束而丢失。即使关闭 Claude Code，下次打开同一项目时记忆仍在。

### Q6: 如何使用 Claude Code 的技能系统

Claude Code 支持通过 `/skill-name` 调用已注册技能。要使用 kali-claw 的技能：

1. **通过自定义智能体**：在 `~/.claude/agents/` 中创建的智能体会自动可用
2. **通过直接对话**：描述任务，Claude 自动匹配相关技能文件
3. **通过手动引用**：告诉 Claude 读取特定技能的 `SKILL.md`

### Q7: 能否同时用 OpenClaw 和 Claude Code

可以。两者共用同一个 `skills/` 目录：

- **OpenClaw** 读取 `SOUL.md` + `AGENTS.md` + `skills/` 作为工作空间
- **Claude Code** 读取 `CLAUDE.md` + `~/.claude/agents/` + `skills/` 作为项目

它们不冲突，只是运行时不同。你可以根据场景选择使用哪个。

### Q8: 远程 Kali 怎么配置

有三种方式：

1. **SSH 直连**：Claude Code 通过 Bash 工具执行 `ssh user@kali-host "nmap ..."`
2. **MCP 远程模式**：MCP 服务器通过 SSH 调用远程 Kali 工具（见 5.1 节）
3. **VS Code Remote**：通过 VS Code Remote SSH 连接到 Kali，在远程终端中运行 Claude Code

---

## 八、架构对比与参考

### 8.1 完整映射表

| kali-claw (OpenClaw) | Claude Code | 迁移方式 | 说明 |
|---------------------|------------|---------|------|
| `SOUL.md`（人格） | `CLAUDE.md` | 复制关键内容 | 将 12 条黑客法则和安全规则追加到 CLAUDE.md |
| `USER.md`（用户信息） | `~/.claude/settings` 或 `CLAUDE.md` | 手动配置 | 在 CLAUDE.md 用户部分或 settings 中记录偏好 |
| `AGENTS.md`（会话配置） | `CLAUDE.md` + `~/.claude/rules/` | 提取规则 | 会话启动流程由 CLAUDE.md 自动执行 |
| `skills/*/SKILL.md` | `~/.claude/agents/` | 转换为智能体 | 每个技能域创建一个智能体文件 |
| `skills/*/payloads.md` | 项目文件（智能体引用） | 保持原位 | 智能体中引用路径，Claude 按需读取 |
| `skills/*/test-cases.md` | 项目文件（智能体引用） | 保持原位 | 智能体中引用路径，Claude 按需读取 |
| `skills/*/guides/` | 项目文件 | 保持原位 | 深度学习材料不需要迁移 |
| `MEMORY.md`（长期记忆） | `~/.claude/projects/.../memory/` | 复制 | 复制长期精炼知识到 Claude Code 记忆 |
| `memory/*.md`（每日日志） | `~/.claude/projects/.../memory/` | 复制 | 复制近期日志到 Claude Code 记忆 |
| `chronicle/`（编年史） | 项目文件 | 保持原位 | 月度里程碑记录 |
| `TOOLS.md`（工具清单） | 项目文件 + MCP 服务器 | 部分转换 | 工具知识作为项目文件保留，常用工具包装为 MCP |
| `HEARTBEAT.md`（心跳） | `~/.claude/settings.json` Hooks | 手动配置 | 用 Hooks 实现部分自动化功能 |
| 12 条黑客法则 | `~/.claude/rules/` | 提取为规则 | 创建独立规则文件 |

### 8.2 迁移检查清单

**最小迁移**（5 分钟）：

- [ ] 安装 Claude Code
- [ ] 克隆 kali-claw 项目
- [ ] 在项目目录中运行 `claude`

**标准迁移**（30 分钟）：

- [ ] 追加安全智能体模式到 `CLAUDE.md`
- [ ] 创建 `~/.claude/agents/` 下的自定义智能体
- [ ] 创建 `~/.claude/rules/kali-claw-security.md` 规则文件
- [ ] 配置项目记忆系统

**完整迁移**（2 小时）：

- [ ] 完成标准迁移所有步骤
- [ ] 创建 MCP 服务器（nmap、sqlmap 等）
- [ ] 配置 `.mcp.json`
- [ ] 创建 Hook 脚本
- [ ] 配置 `~/.claude/settings.json` 中的 Hooks
- [ ] 创建 `.scope` 授权范围文件
- [ ] 测试完整流程

### 8.3 性能对比

| 指标 | OpenClaw | Claude Code |
|------|----------|-------------|
| 首次启动 | 需安装框架 + 创建智能体 | 直接 `claude` 启动 |
| 技能加载 | 会话启动时全部加载 | 按需读取（更高效） |
| 工具调用 | 通过终端命令 | 通过 Bash 工具 + MCP |
| 上下文窗口 | 受框架限制 | Claude 原生上下文窗口（200K tokens） |
| 多会话 | 支持多智能体 | 支持多 Tab |
| 更新维护 | 需同步框架和技能 | 只需 `git pull` 更新技能 |

---

_Built with Claude Code. 如有问题，请在 GitHub Issues 中反馈。_
