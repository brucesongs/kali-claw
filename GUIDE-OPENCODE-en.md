# kali-claw Skill Pack Usage Guide: Running on OpenCode

> A comprehensive guide to using kali-claw's 49 security skill domains with OpenCode, an open-source terminal-based AI coding agent.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Environment Setup](#2-environment-setup)
3. [Approach 1: Minimal Migration (5 Minutes)](#3-approach-1-minimal-migration-5-minutes)
4. [Approach 2: Standard Migration (30 Minutes)](#4-approach-2-standard-migration-30-minutes)
5. [Approach 3: Full Migration (2 Hours)](#5-approach-3-full-migration-2-hours)
6. [Usage Scenarios](#6-usage-scenarios)
7. [FAQ](#7-faq)
8. [Architecture Comparison](#8-architecture-comparison)

---

## 1. Overview

### 1.1 What is OpenCode

OpenCode (github.com/opencode-ai/opencode) is an open-source, terminal-based AI coding agent written in Go. It provides a TUI (Terminal User Interface) for interacting with various AI models to help with coding tasks, debugging, and more.

**Key features:**

- **Interactive TUI** -- Built with Bubble Tea for a smooth terminal experience
- **Multiple AI Providers** -- Support for OpenAI, Anthropic, Google Gemini, AWS Bedrock, Groq, Azure OpenAI, GitHub Copilot, OpenRouter, and local models via self-hosted endpoints
- **Project Instructions** -- Reads project-level Markdown files (`OPENCODE.md`, `opencode.md`, `CLAUDE.md`, and others) as context for AI interactions
- **Custom Commands** -- Predefined prompts stored as Markdown files, triggered via keyboard shortcut
- **MCP (Model Context Protocol)** -- Standardized tool integration for extending AI capabilities
- **LSP Integration** -- Language Server Protocol support for code intelligence
- **Session Management** -- Save and manage multiple conversation sessions with persistent SQLite storage
- **Auto Compact** -- Automatically summarizes conversations when approaching context window limits
- **Non-interactive Mode** -- Run single prompts from the command line for scripting and automation
- **Open Source** -- MIT licensed, fully extensible, model-agnostic

**Think of it this way:** OpenCode is the terminal interface that connects you to AI models. kali-claw is the structured security knowledge base that the AI model reads and uses. You do not need to change or convert kali-claw files -- you configure OpenCode to point at them.

### 1.2 How kali-claw Skills Fit with OpenCode

kali-claw contains **49 security skill domains** and a **518 Kali Linux tool knowledge base**. These are stored as structured Markdown files:

- Each skill domain has: `SKILL.md` (methodology) + `payloads.md` (attack payloads) + `test-cases.md` (test templates) + `guides/` (deep-dive materials)
- Root configuration: `SOUL.md` (12 Hacker Laws), `IDENTITY.md` (skill tags), `TOOLS.md` (518 tool inventory)

**Key insight:** kali-claw files are plain Markdown. OpenCode reads Markdown project instructions natively. Migration means configuring OpenCode to read and use these existing files -- not converting, modifying, or merging anything.

### 1.3 Migration Strategies (3 Approaches)

| Approach | Time Required | What You Get | Best For |
|----------|---------------|--------------|----------|
| **1. Minimal** | 5 minutes | Direct skill file access via natural language prompts | Quick evaluation, getting started |
| **2. Standard** | 30 minutes | Project instructions + custom commands + structured skill index | Daily pentest work |
| **3. Full** | 2 hours | MCP tool integration + custom commands + multi-provider models + automation | Professional penetration testers |

**Recommendation:** Start with Approach 1 to validate the setup. Use Approach 2 for daily work. Use Approach 3 when you need full tool automation.

---

## 2. Environment Setup

### 2.1 Install OpenCode

**Option A: Using the install script (Linux and macOS)**

```bash
# Install the latest version
curl -fsSL https://raw.githubusercontent.com/opencode-ai/opencode/refs/heads/main/install | bash

# Install a specific version
curl -fsSL https://raw.githubusercontent.com/opencode-ai/opencode/refs/heads/main/install | VERSION=0.1.0 bash
```

**Option B: Using Homebrew (macOS and Linux)**

```bash
brew install opencode-ai/tap/opencode
```

**Option C: Using Go**

```bash
go install github.com/opencode-ai/opencode@latest
```

**Option D: Using AUR (Arch Linux)**

```bash
yay -S opencode-ai-bin
```

**Verify installation:**

```bash
opencode --version
```

**Troubleshooting:**

| Issue | Solution |
|-------|----------|
| `command not found: opencode` | Ensure `$(go env GOPATH)/bin` is in your `$PATH` |
| Permission denied on macOS | `xattr -d com.apple.quarantine $(which opencode)` |
| Old Go version | OpenCode requires Go 1.24.0+ to build from source |

### 2.2 Prepare Kali Linux

Choose one of three deployment options:

**Option A: Kali Linux native (recommended)**

```bash
# Verify tools are available
nmap --version
sqlmap --version
hydra --version
```

**Option B: Remote Kali via SSH**

```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "kali-claw"

# Copy key to remote Kali
ssh-copy-id user@kali-host

# Verify tool access
ssh user@kali-host "nmap --version && sqlmap --version"
```

**Option C: Docker container**

```bash
# Pull and start Kali container
docker pull kalilinux/kali-rolling
docker run -it --name kali-claw-env kalilinux/kali-rolling /bin/bash

# Inside the container, install security tools
apt update && apt install -y nmap sqlmap nikto hydra metasploit-framework

# Re-enter after exiting
docker start -ai kali-claw-env
```

### 2.3 Clone kali-claw

```bash
# Clone the workspace
git clone https://github.com/brucesongs/kali-claw.git
cd kali-claw
```

**Verify the file structure:**

```bash
ls -la
# You should see: SOUL.md  AGENTS.md  IDENTITY.md  USER.md
#                 MEMORY.md  TOOLS.md  HEARTBEAT.md  skills/  memory/  chronicle/

# Verify skill count
ls skills/ | wc -l
# Expected: 49 (or close, depending on your version)
```

### 2.4 Configure an AI Provider

OpenCode requires at least one AI provider. Set the corresponding environment variable:

```bash
# Anthropic Claude (recommended for security tasks)
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI
export OPENAI_API_KEY="sk-..."

# Google Gemini
export GEMINI_API_KEY="..."

# Groq (fast, low-cost)
export GROQ_API_KEY="..."

# OpenRouter (access to 200+ models)
export OPENROUTER_API_KEY="..."
```

Add these to your `~/.bashrc` or `~/.zshrc` for persistence:

```bash
echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.zshrc
source ~/.zshrc
```

### 2.5 Environment Checklist

Before proceeding, confirm the following:

- [ ] OpenCode installed (`opencode --version` returns a version number)
- [ ] Kali Linux available (native, SSH, or Docker)
- [ ] kali-claw cloned to local directory
- [ ] At least one AI provider API key configured
- [ ] Basic Kali tools work (`nmap --version` returns successfully)

---

## 3. Approach 1: Minimal Migration (5 Minutes)

### 3.1 Launch OpenCode in the kali-claw Directory

```bash
cd kali-claw
opencode
```

OpenCode starts a TUI session. It automatically looks for project instruction files in the current directory. By default, it reads files like `CLAUDE.md`, `OPENCODE.md`, `opencode.md` (case-insensitive).

kali-claw already has a `CLAUDE.md` file that OpenCode will read automatically. This gives the AI model basic context about the project.

**What happens when you start OpenCode:**

1. OpenCode reads project-level configuration (`.opencode.json` if present)
2. OpenCode loads project instructions from `CLAUDE.md` (and other `contextPaths`)
3. The AI model now has context about kali-claw's architecture and purpose
4. You can ask questions about skills, and the model can read skill files on demand

### 3.2 Usage Examples (Multi-turn Dialog)

**Example 1: Query a specific skill**

```
You: Read skills/web-sqli/SKILL.md and summarize the SQL injection methodology

AI: [reads the file using the view tool]

    The SQL Injection skill covers a complete attack chain:

    1. Detection -- Find injection points using single quote tests, numeric tests,
       and closure determination
    2. Fingerprinting -- Determine column count with ORDER BY, identify database
       type using version functions
    3. Exploitation -- UNION, error-based, boolean blind, time blind, double query,
       and stacked queries
    4. Data Extraction -- Enumerate databases, tables, columns, and extract data
    5. Privilege Escalation -- File read/write and OS command execution

    Core tools: sqlmap, Burp Suite, curl, manual injection
```

**Example 2: Get attack payloads**

```
You: Show me the payloads for WAF bypass from skills/web-xss/payloads.md

AI: [reads the file]

    Here are the WAF bypass payloads from the XSS skill:

    ### Tag Attribute Bypass
    <img/src=x onerror=alert(1)>
    <svg/onload=alert(1)>

    ### Encoding Bypass
    <script>alert(String.fromCharCode(88,83,83))</script>

    ### Keyword Obfuscation
    <scr<script>ipt>alert(1)</scr</script>ipt>

    ... (shows full payload collection)
```

**Example 3: Get test case templates**

```
You: What test cases are available for SSRF testing?
     Read skills/web-ssrf/test-cases.md

AI: [reads the file]

    The SSRF test cases cover these categories:

    TC-SSRF-001: Basic URL Parameter SSRF Detection (CRITICAL)
    TC-SSRF-002: Internal Network Scanning via SSRF (CRITICAL)
    TC-SSRF-003: Protocol Scheme Bypass (HIGH)
    TC-SSRF-004: DNS Rebinding Attack (HIGH)
    ...

    Each test case includes prerequisites, steps, and expected results.
```

**Example 4: Plan a penetration test**

```
You: I need to pentest a web application at http://target.example.com.
     What skills should I use and in what order?

AI: Based on the kali-claw skill domains, here is a recommended workflow:

    1. **OSINT** (skills/osint/SKILL.md) -- Gather information about the target
       domain, subdomains, technologies
    2. **Network Pentest** (skills/network-pentest/SKILL.md) -- Scan for open
       ports and running services
    3. **Web Security** (multiple skills):
       - skills/web-sqli/ -- SQL injection testing
       - skills/web-xss/ -- Cross-site scripting testing
       - skills/web-ssrf/ -- Server-side request forgery testing
       - skills/web-auth-bypass/ -- Authentication bypass testing
       - skills/web-access-control/ -- Access control testing
    4. **API Security** (skills/api-security/SKILL.md) -- Test API endpoints
    5. **Report Generation** (skills/article-writing/SKILL.md) -- Compile findings

    Shall I start with OSINT reconnaissance?
```

**Example 5: Execute a command**

```
You: Run an nmap service scan on 192.168.1.0/24

AI: [uses the bash tool]

    $ nmap -sV -sC 192.168.1.0/24

    Starting Nmap 7.95 ( https://nmap.org )
    ...
    Found 3 live hosts:
    - 192.168.1.1   (gateway)    ports: 22, 80, 443
    - 192.168.1.50  (web server) ports: 80, 3306
    - 192.168.1.100 (workstation) ports: 22, 3389

    Shall I run a vulnerability scan on the web server?
```

### 3.3 Limitations of Minimal Migration

| What Works | What Does Not Work |
|------------|-------------------|
| Reading any skill file on demand | Skills are not automatically loaded into context |
| Asking about payloads and test cases | Agent does not follow the 12 Hacker Laws |
| Running commands via bash tool | No session startup sequence (no memory loading) |
| Basic penetration test guidance | No custom commands for common tasks |
| Multi-turn conversations | No MCP tool integration |

**What this means:** The AI model can read any file you ask about, but it does not automatically behave like the kali-claw agent. For a more integrated experience, use Approach 2 or 3.

---

## 4. Approach 2: Standard Migration (30 Minutes)

### 4.1 Create `.opencode.json` Configuration

Create an `.opencode.json` file in the kali-claw project root. This file configures OpenCode to use specific models and settings for security work.

```json
{
  "$schema": "https://raw.githubusercontent.com/opencode-ai/opencode/main/opencode-schema.json",
  "data": {
    "directory": ".opencode"
  },
  "providers": {
    "anthropic": {
      "apiKey": "",
      "disabled": false
    }
  },
  "agents": {
    "coder": {
      "model": "claude-sonnet-4",
      "maxTokens": 8000,
      "reasoningEffort": "high"
    },
    "task": {
      "model": "claude-sonnet-4",
      "maxTokens": 8000,
      "reasoningEffort": "high"
    },
    "title": {
      "model": "claude-3.5-haiku",
      "maxTokens": 80
    }
  },
  "shell": {
    "path": "/bin/bash",
    "args": ["-l"]
  },
  "autoCompact": true,
  "contextPaths": [
    "OPENCODE.md",
    "CLAUDE.md",
    "SOUL.md",
    "USER.md",
    "IDENTITY.md",
    "TOOLS.md",
    "MEMORY.md"
  ]
}
```

**What this configuration does:**

- **providers** -- Configures your AI provider (set API key via environment variable, not in this file)
- **agents** -- Sets the model and token limits for the main coding agent
- **shell** -- Configures the shell used for bash tool execution
- **autoCompact** -- Automatically summarizes long conversations to prevent context overflow
- **contextPaths** -- Additional files that OpenCode reads as project instructions. This is the key setting that makes kali-claw skills accessible. By including `SOUL.md`, `USER.md`, `IDENTITY.md`, and `TOOLS.md`, the AI model loads kali-claw's identity, hacker laws, skill tags, and tool knowledge at session start.

### 4.2 Create Project Instructions File

Create an `OPENCODE.md` file in the kali-claw project root. This is the primary project instruction file that OpenCode reads. It tells the AI model how to behave as a penetration testing agent using the kali-claw skill system.

```markdown
# kali-claw -- OpenCode Project Instructions

## Identity

You are kali-claw, a senior penetration testing engineer and master of all
Kali Linux security tools. You operate under 12 Hacker Laws defined in SOUL.md.

## Session Startup

At the start of every session, read these files to load your full context:

1. SOUL.md -- Your identity and 12 Hacker Laws
2. USER.md -- Who you are helping (the captain)
3. IDENTITY.md -- Your skill tags and personality traits
4. TOOLS.md -- Your 518 Kali Linux tool knowledge base
5. MEMORY.md -- Long-term distilled knowledge

## Skill System

You have 49 security skill domains in the skills/ directory. Each skill has:

- SKILL.md -- Skill definition, use cases, tools, methodology
- payloads.md -- Attack payloads and commands organized by type
- test-cases.md -- Structured test case templates
- guides/ -- Deep-dive learning materials

When the user asks about a security topic, read the relevant skill files
to provide expert-level guidance.

## Skill Index

| Domain | Path | Key Topics |
|--------|------|------------|
| SQL Injection | skills/web-sqli/ | UNION, error-based, blind, double query, WAF bypass |
| XSS | skills/web-xss/ | Reflected, stored, DOM-based, CSP bypass |
| SSRF | skills/web-ssrf/ | Internal scanning, protocol bypass, DNS rebinding |
| Auth Bypass | skills/web-auth-bypass/ | Brute force, session hijacking, OAuth attacks |
| Access Control | skills/web-access-control/ | IDOR, privilege escalation, forced browsing |
| API Security | skills/api-security/ | REST/GraphQL testing, rate limiting, auth |
| Network Pentest | skills/network-pentest/ | nmap, service detection, vulnerability scanning |
| OSINT | skills/osint/ | DNS enumeration, subdomain discovery, recon |
| Recon OSINT | skills/recon-osint/ | Passive recon, data aggregation |
| Password Attack | skills/password-attack/ | Dictionary, brute force, hash cracking |
| Post-Exploitation | skills/post-exploitation/ | Persistence, lateral movement, exfiltration |
| WiFi Pentest | skills/wifi-pentest/ | WPA cracking, WPS attacks, wireless sniffing |
| Binary Reverse | skills/binary-reverse/ | radare2, vulnerability analysis, exploit dev |
| Crypto Attacks | skills/crypto-attacks/ | Cipher analysis, key recovery, protocol attacks |
| Cloud Security | skills/cloud-security/ | AWS/Azure/GCP misconfigurations |
| Container Security | skills/container-security/ | Docker, Kubernetes security testing |
| Mobile Security | skills/mobile-security/ | Android/iOS app testing |
| Digital Forensics | skills/digital-forensics/ | Disk analysis, memory forensics, timeline |
| Social Engineering | skills/social-engineering/ | Phishing, pretexting, awareness |
| Supply Chain Security | skills/supply-chain-security/ | Dependency attacks, CI/CD poisoning |
| Hardware Security | skills/hardware-security/ | JTAG, firmware, side-channel |
| AI/LLM Security | skills/ai-security/ | Prompt injection, model extraction |
| AI Fuzzing | skills/ai-fuzzing/ | Coverage-guided fuzzing, crash triage |
| Insecure Design | skills/insecure-design/ | Threat modeling, design pattern flaws |
| Security Misconfiguration | skills/security-misconfiguration/ | Default configs, information disclosure |
| Vulnerability Assessment | skills/vulnerability-assessment/ | Scanning, prioritization, CVSS |
| Logging Monitoring | skills/logging-monitoring/ | Log analysis, SIEM, detection rules |
| Security Review | skills/security-review/ | OWASP audit, secrets detection, injection testing |
| Repo Scan | skills/repo-scan/ | Codebase security surface, secret scanning |
| Search First | skills/search-first/ | Exploit search, vulnerability intelligence |
| Exa Search | skills/exa-search/ | Semantic search, context-aware queries |
| Deep Research | skills/deep-research/ | Multi-source intelligence synthesis |
| Data Scraper | skills/data-scraper-agent/ | Structured data collection, CVE scraping |
| Browser QA | skills/browser-qa/ | Automated browser testing, network monitoring |
| Terminal Ops | skills/terminal-ops/ | CLI operations, evidence capture, session mgmt |
| Verification Loop | skills/verification-loop/ | Exploit confirmation, false-positive elimination |
| Docker Patterns | skills/docker-patterns/ | Lab setup, vulnerable containers, cleanup |
| Safety Guard | skills/safety-guard/ | Scope enforcement, rate limiting, authorization |
| Autonomous Loops | skills/autonomous-loops/ | Sequential pipeline, watch loop, batch processing |
| Council | skills/council/ | Multi-perspective analysis, attack/defense/audit |
| Chronicle | skills/chronicle/ | Session logging, milestone tracking |
| Continuous Learning | skills/continuous-learning/ | Tool mastery progression, knowledge gaps |
| Knowledge Ops | skills/knowledge-ops/ | Knowledge graph, entity extraction |
| Multi-Agent Collaboration | skills/multi-agent-collaboration/ | Task decomposition, parallel execution |
| MCP Server Patterns | skills/mcp-server-patterns/ | Security tool API wrapping, integration |
| Codebase Onboarding | skills/codebase-onboarding/ | Rapid codebase intelligence |
| Article Writing | skills/article-writing/ | Security content, CVSS scoring, disclosure |
| Social Intelligence | skills/social-intelligence/ | Platform OSINT, sentiment analysis |
| Security Bounty Hunter | skills/security-bounty-hunter/ | Bug bounty methodology, report writing |

## Behavioral Guidelines

Follow the 12 Hacker Laws from SOUL.md:

1. First Principles Thinking
2. Divergent Thinking First
3. Minimize Attack Surface
4. Defense in Depth
5. Least Privilege
6. Assume Breach
7. Obscurity Is Not Security
8. Trust but Verify
9. Information Wants to Be Free
10. Skill Over Credentials
11. The Weakest Link Is Human
12. Murphy's Security Law

## Boundaries

- Never attack systems without explicit authorization
- Never store sensitive data (API keys, tokens, passwords) in memory files
- Proactively redact sensitive information when asked about it
- Keep code local unless the captain explicitly approves remote uploads
- When in doubt, ask before executing external operations

## Communication Style

Professional, direct, hands-on. Give precise commands and actionable steps.
Less talk, more action.
```

### 4.3 Create Custom Commands

OpenCode supports custom commands stored as Markdown files. Create project-level commands for common security tasks.

**Directory structure:**

```bash
mkdir -p .opencode/commands
```

**Command 1: Reconnaissance** (`.opencode/commands/recon.md`)

```markdown
# Reconnaissance on $TARGET

Read skills/recon-osint/SKILL.md and skills/osint/SKILL.md for the full methodology.

Perform reconnaissance on $TARGET:

1. DNS enumeration: dig, whois, host
2. Subdomain discovery: sublist3r, assetfinder, crt.sh
3. Technology detection: whatweb
4. Port scanning: nmap -sV -sC $TARGET

RUN dig $TARGET ANY +noall +answer
RUN whois $TARGET
RUN nmap -sV -sC $TARGET -oN /tmp/recon-$TARGET.txt
```

**Command 2: Web Application Security Audit** (`.opencode/commands/web-audit.md`)

```markdown
# Web Security Audit on $TARGET_URL

Read skills/web-sqli/SKILL.md, skills/web-xss/SKILL.md,
skills/web-ssrf/SKILL.md, and skills/web-auth-bypass/SKILL.md
for the full methodology.

Perform a systematic OWASP Top 10 audit on $TARGET_URL:

Phase 1: Information Gathering
- Identify server, framework, and technologies
- Discover all input points (forms, parameters, headers)

Phase 2: Injection Testing
- SQL Injection on all parameters
- XSS (reflected, stored, DOM-based)
- SSRF on URL-accepting parameters
- Command injection

Phase 3: Authentication and Authorization
- Default credential testing
- Session management analysis
- Access control testing (IDOR, privilege escalation)
- Rate limiting check

Phase 4: Configuration Review
- Security headers check
- Error handling review
- Directory listing check
RUN curl -sI $TARGET_URL
```

**Command 3: SQL Injection Test** (`.opencode/commands/sqli-test.md`)

```markdown
# SQL Injection Testing on $TARGET_URL

Read skills/web-sqli/SKILL.md and skills/web-sqli/payloads.md for
the complete payload collection.

Test $TARGET_URL for SQL injection:

1. Detection: Test all parameters with single quote, numeric, and boolean tests
2. Fingerprinting: Determine column count and database type
3. Exploitation: Test UNION, error-based, boolean blind, time blind
4. WAF bypass: Try encoding, comments, mixed case if basic payloads are blocked
RUN echo "Testing $TARGET_URL for SQLi..."
```

**Command 4: Nmap Scan** (`.opencode/commands/nmap-scan.md`)

```markdown
# Nmap Scan on $TARGET

Read skills/network-pentest/SKILL.md for the scanning methodology.

Run nmap against $TARGET with options:
- Service version detection (-sV)
- Default scripts (-sC)
- OS detection (-O)

RUN nmap -sV -sC -O $TARGET -oN /tmp/nmap-$TARGET.txt
```

**Command 5: Load Skill Context** (`.opencode/commands/load-skill.md`)

```markdown
# Load Skill: $SKILL_NAME

Read the complete skill context for $SKILL_NAME:

READ skills/$SKILL_NAME/SKILL.md
READ skills/$SKILL_NAME/payloads.md
READ skills/$SKILL_NAME/test-cases.md

Provide a summary of the skill including:
- Description and use cases
- Core tools and methodology
- Key payloads
- Available test cases
```

**How to use custom commands:**

1. Press `Ctrl+K` to open the command dialog
2. Select a command (prefixed with `project:`)
3. Enter values for any named arguments (like `$TARGET`)
4. Press Enter to execute

### 4.4 Use Enhanced Configuration

Now launch OpenCode with the enhanced setup:

```bash
cd kali-claw
opencode
```

**What happens now at session start:**

1. OpenCode reads `.opencode.json` for configuration
2. OpenCode loads all files listed in `contextPaths`: `SOUL.md`, `USER.md`, `IDENTITY.md`, `TOOLS.md`, `MEMORY.md`, plus `CLAUDE.md` and `OPENCODE.md`
3. The AI model now has full kali-claw context: personality, hacker laws, skill index, tool knowledge, and long-term memory
4. Custom commands are available via `Ctrl+K`

**Enhanced multi-turn dialog:**

```
You: What vulnerabilities should I test for on a web application?

AI: Based on the kali-claw skill system, here is a systematic approach:

    1. SQL Injection (skills/web-sqli/) -- Test all input parameters
    2. Cross-Site Scripting (skills/web-xss/) -- Test reflection points
    3. SSRF (skills/web-ssrf/) -- Test URL-accepting parameters
    4. Authentication Bypass (skills/web-auth-bypass/) -- Test login mechanisms
    5. Access Control (skills/web-access-control/) -- Test authorization

    Following Hacker Law #8 (Trust but Verify), every input point must be
    tested. Following Hacker Law #2 (Divergent Thinking), consider multiple
    attack vectors for each finding.

    Shall I load the full methodology for any of these?
```

---

## 5. Approach 3: Full Migration (2 Hours)

### 5.1 MCP Tool Integration

MCP (Model Context Protocol) servers let OpenCode call external tools through a standardized interface. For kali-claw, you can create MCP servers that wrap Kali Linux security tools.

**Complete `.opencode.json` with MCP servers:**

```json
{
  "$schema": "https://raw.githubusercontent.com/opencode-ai/opencode/main/opencode-schema.json",
  "data": {
    "directory": ".opencode"
  },
  "providers": {
    "anthropic": {
      "disabled": false
    },
    "openai": {
      "disabled": true
    },
    "groq": {
      "disabled": true
    }
  },
  "agents": {
    "coder": {
      "model": "claude-sonnet-4",
      "maxTokens": 16000,
      "reasoningEffort": "high"
    },
    "task": {
      "model": "claude-sonnet-4",
      "maxTokens": 16000,
      "reasoningEffort": "high"
    },
    "title": {
      "model": "claude-3.5-haiku",
      "maxTokens": 80
    }
  },
  "shell": {
    "path": "/bin/bash",
    "args": ["-l"]
  },
  "mcpServers": {
    "nmap-security-scanner": {
      "type": "stdio",
      "command": "python3",
      "args": [".opencode/mcp/nmap-server.py"],
      "env": []
    },
    "sqlmap-scanner": {
      "type": "stdio",
      "command": "python3",
      "args": [".opencode/mcp/sqlmap-server.py"],
      "env": []
    },
    "security-toolkit": {
      "type": "stdio",
      "command": "python3",
      "args": [".opencode/mcp/security-toolkit-server.py"],
      "env": []
    }
  },
  "autoCompact": true,
  "contextPaths": [
    "OPENCODE.md",
    "CLAUDE.md",
    "SOUL.md",
    "USER.md",
    "IDENTITY.md",
    "TOOLS.md",
    "MEMORY.md"
  ]
}
```

**MCP server example -- nmap wrapper** (`.opencode/mcp/nmap-server.py`):

This is a minimal MCP server that wraps nmap as a standardized tool. It accepts structured input and returns structured output.

```python
#!/usr/bin/env python3
"""
Minimal MCP server wrapping nmap for OpenCode integration.
Install: pip install mcp
"""

import json
import subprocess
import sys
from mcp.server import Server
from mcp.types import Tool, TextContent

server = Server("nmap-security-scanner")


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="nmap_scan",
            description="Run nmap network scanner with specified options",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR range"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "service", "vuln", "stealth", "full"],
                        "description": "Type of scan to perform"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification (e.g. '80,443' or '1-1000')"
                    }
                },
                "required": ["target"]
            }
        )
    ]


@server.call_tool()
async def call_tool(name, arguments):
    if name != "nmap_scan":
        return [TextContent(type="text", text="Unknown tool")]

    target = arguments["target"]
    scan_type = arguments.get("scan_type", "service")
    ports = arguments.get("ports")

    cmd = ["nmap"]
    if scan_type == "quick":
        cmd.extend(["-T4", "-F"])
    elif scan_type == "service":
        cmd.extend(["-sV", "-sC"])
    elif scan_type == "vuln":
        cmd.extend(["-sV", "--script=vuln"])
    elif scan_type == "stealth":
        cmd.extend(["-sS", "-T2"])
    elif scan_type == "full":
        cmd.extend(["-sV", "-sC", "-O", "-A"])

    if ports:
        cmd.extend(["-p", ports])

    cmd.append(target)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        output = result.stdout
        if result.returncode != 0:
            output += f"\nSTDERR: {result.stderr}"
    except subprocess.TimeoutExpired:
        output = "Scan timed out after 300 seconds"
    except FileNotFoundError:
        output = "nmap not found. Install: sudo apt install nmap"

    return [TextContent(type="text", text=output)]


if __name__ == "__main__":
    import asyncio
    asyncio.run(server.run())
```

**How MCP tools appear in OpenCode:**

Once configured, MCP tools are automatically available to the AI alongside built-in tools. The AI can call `nmap_scan` directly without using the bash tool. MCP tools follow the same permission model -- you approve each call.

### 5.2 Custom Commands (Extended Set)

Create additional commands for common security workflows.

**Command: Pentest Full Flow** (`.opencode/commands/pentest.md`)

```markdown
# Full Penetration Test on $TARGET

Follow the kali-claw penetration testing methodology.

Read skills/recon-osint/SKILL.md, skills/network-pentest/SKILL.md,
and skills/post-exploitation/SKILL.md for reference.

Execute the following phases on $TARGET:

## Phase 1: Passive Reconnaissance
- DNS lookup and WHOIS
- Subdomain enumeration
- Technology fingerprinting
- Google dorking for exposed information

## Phase 2: Active Scanning
- Port scanning (all 65535 ports)
- Service version detection
- OS fingerprinting
- Vulnerability scanning

## Phase 3: Web Application Testing
- Directory and file enumeration
- SQL injection testing on all parameters
- XSS testing on all input fields
- SSRF testing on URL parameters
- Authentication and session testing
- Access control testing

## Phase 4: Exploitation (only with authorization)
- Attempt to exploit confirmed vulnerabilities
- Verify impact of each finding
- Document proof-of-concept

## Phase 5: Reporting
- Compile findings with CVSS scores
- Provide remediation recommendations
- Generate executive summary

IMPORTANT: Only test systems you have explicit written authorization to test.
```

**Command: Learn a Tool** (`.opencode/commands/learn-tool.md`)

```markdown
# Learn: $TOOL_NAME

Read the relevant skill files and provide a structured learning path
for $TOOL_NAME.

Check TOOLS.md for the current mastery status of $TOOL_NAME.

Provide:
1. Quick start command with the most common usage
2. Key options and flags explained
3. Practical examples from the skill payloads
4. Test cases for hands-on practice
5. Common pitfalls and tips
```

**Command: Generate Report** (`.opencode/commands/report.md`)

```markdown
# Generate Pentest Report

Read skills/article-writing/SKILL.md for the report template.

Generate a penetration test report including:

1. Executive Summary
2. Scope and Methodology
3. Findings (sorted by severity: Critical > High > Medium > Low > Info)
4. For each finding:
   - Description
   - Affected component
   - Steps to reproduce
   - Evidence (commands, output, screenshots)
   - CVSS score
   - Remediation recommendation
5. Overall Risk Assessment
6. Appendices (tool output, raw data)
```

**Directory structure after full setup:**

```
kali-claw/
  .opencode/
    commands/
      recon.md
      web-audit.md
      sqli-test.md
      nmap-scan.md
      load-skill.md
      pentest.md
      learn-tool.md
      report.md
    mcp/
      nmap-server.py
      sqlmap-server.py
      security-toolkit-server.py
  .opencode.json
  OPENCODE.md
  SOUL.md
  USER.md
  IDENTITY.md
  TOOLS.md
  MEMORY.md
  HEARTBEAT.md
  AGENTS.md
  skills/        (49 skill domains -- unchanged)
  memory/
  chronicle/
```

### 5.3 Model Configuration (Multi-provider)

OpenCode supports multiple AI providers. You can configure different models for different needs.

**High-performance setup (recommended for pentest work):**

```json
{
  "providers": {
    "anthropic": {
      "disabled": false
    }
  },
  "agents": {
    "coder": {
      "model": "claude-sonnet-4",
      "maxTokens": 16000,
      "reasoningEffort": "high"
    },
    "task": {
      "model": "claude-sonnet-4",
      "maxTokens": 16000,
      "reasoningEffort": "high"
    },
    "title": {
      "model": "claude-3.5-haiku",
      "maxTokens": 80
    }
  }
}
```

**Cost-effective setup (using OpenRouter for model variety):**

```json
{
  "providers": {
    "openrouter": {
      "disabled": false
    }
  },
  "agents": {
    "coder": {
      "model": "openrouter.claude-3.7-sonnet",
      "maxTokens": 8000
    },
    "task": {
      "model": "openrouter.gemini-2.5",
      "maxTokens": 8000
    },
    "title": {
      "model": "openrouter.claude-3.5-haiku",
      "maxTokens": 80
    }
  }
}
```

**Offline setup (using local models via Ollama or self-hosted endpoint):**

```json
{
  "agents": {
    "coder": {
      "model": "local.granite-3.3-2b-instruct@q8_0",
      "reasoningEffort": "high"
    }
  }
}
```

Set the local endpoint:

```bash
export LOCAL_ENDPOINT=http://localhost:1235/v1
```

**Available models by provider:**

| Provider | Example Models | Environment Variable |
|----------|---------------|---------------------|
| Anthropic | claude-sonnet-4, claude-4-opus, claude-3.7-sonnet, claude-3.5-haiku | `ANTHROPIC_API_KEY` |
| OpenAI | gpt-4.1, gpt-4o, o3, o4-mini | `OPENAI_API_KEY` |
| Google | gemini-2.5, gemini-2.5-flash, gemini-2.0-flash | `GEMINI_API_KEY` |
| Groq | llama-4-maverick, deepseek-r1-distill | `GROQ_API_KEY` |
| OpenRouter | 200+ models from all providers | `OPENROUTER_API_KEY` |
| GitHub Copilot | gpt-4o, claude-sonnet-4, gemini-2.5-pro | `GITHUB_TOKEN` |
| AWS Bedrock | claude-3.7-sonnet | `AWS_ACCESS_KEY_ID` |
| Azure OpenAI | gpt-4.1, o3, o4-mini | `AZURE_OPENAI_API_KEY` |
| Self-hosted | Any OpenAI-compatible model | `LOCAL_ENDPOINT` |

**Switching models at runtime:** Press `Ctrl+O` to open the model selection dialog and switch between providers and models without editing the configuration file.

### 5.4 Complete Project Configuration

Here is the complete `.opencode.json` for a full kali-claw deployment:

```json
{
  "$schema": "https://raw.githubusercontent.com/opencode-ai/opencode/main/opencode-schema.json",
  "data": {
    "directory": ".opencode"
  },
  "providers": {
    "anthropic": {
      "disabled": false
    },
    "openrouter": {
      "disabled": false
    }
  },
  "agents": {
    "coder": {
      "model": "claude-sonnet-4",
      "maxTokens": 16000,
      "reasoningEffort": "high"
    },
    "task": {
      "model": "claude-sonnet-4",
      "maxTokens": 16000,
      "reasoningEffort": "high"
    },
    "title": {
      "model": "claude-3.5-haiku",
      "maxTokens": 80
    }
  },
  "shell": {
    "path": "/bin/bash",
    "args": ["-l"]
  },
  "mcpServers": {
    "nmap-security-scanner": {
      "type": "stdio",
      "command": "python3",
      "args": [".opencode/mcp/nmap-server.py"],
      "env": []
    },
    "security-toolkit": {
      "type": "stdio",
      "command": "python3",
      "args": [".opencode/mcp/security-toolkit-server.py"],
      "env": []
    }
  },
  "autoCompact": true,
  "contextPaths": [
    "OPENCODE.md",
    "CLAUDE.md",
    "SOUL.md",
    "USER.md",
    "IDENTITY.md",
    "TOOLS.md",
    "MEMORY.md"
  ]
}
```

**Note on archived status:** The OpenCode project has been archived and continues development as [Crush](https://github.com/charmbracelet/crush) by the Charm team. The configuration format and features described in this guide apply to both OpenCode and its successor. When migrating to Crush, the same `.opencode.json` structure and `contextPaths` mechanism work identically.

---

## 6. Usage Scenarios

### 6.1 Complete Penetration Test Flow

A multi-turn dialog showing a full penetration test from reconnaissance to reporting.

**Step 1 -- Reconnaissance:**

```
You: /project:recon target.example.com

AI: [Loads recon skill context, executes commands]

    Starting reconnaissance on target.example.com...

    DNS Records:
    - A     : target.example.com -> 93.184.216.34
    - MX    : mail.target.example.com
    - NS    : ns1.example.com, ns2.example.com

    Subdomains found:
    - www.target.example.com
    - api.target.example.com
    - admin.target.example.com
    - dev.target.example.com (403 Forbidden)

    Technologies: nginx/1.18.0, PHP 8.1, MySQL (inferred)

    4 live subdomains found. Next step: port scanning?
```

**Step 2 -- Scanning:**

```
You: Yes, scan all discovered subdomains

AI: Running nmap service detection on 4 hosts...

    Results:
    www.target.example.com:80    nginx/1.18.0, PHP 8.1
    www.target.example.com:443   TLS 1.2
    api.target.example.com:8080  Node.js Express
    admin.target.example.com:80  Apache Tomcat 9.0.50
    admin.target.example.com:8080 Tomcat manager (401)

    Notable findings:
    1. admin:8080 - Tomcat manager may have default credentials
    2. api:8080 - Node.js API, potential injection points
    3. dev - 403 Forbidden, might be worth investigating

    What would you like to investigate first?
```

**Step 3 -- Web Testing:**

```
You: Check admin.target.example.com for default credentials and test the API

AI: [Loads web-auth-bypass and api-security skills]

    Testing Tomcat manager for default credentials...
    - admin:admin       -> 401
    - tomcat:tomcat     -> 401
    - tomcat:s3cret     -> 200 OK! ACCESS GRANTED

    [!] Default credentials found: tomcat:s3cret
    [!] This allows WAR file deployment = remote code execution

    Testing API endpoint api.target.example.com:8080/api/users?id=1...
    - Single quote test: server error (500)
    - UNION injection: data returned

    [!] SQL injection confirmed on /api/users?id parameter

    How would you like to proceed?
```

**Step 4 -- Reporting:**

```
You: /project:report

AI: [Loads article-writing skill]

    # Penetration Test Report - target.example.com
    ## Date: 2026-05-18

    ### Executive Summary
    2 critical and 1 high-severity vulnerabilities identified.

    ### Findings

    | # | Finding | Severity | CVSS |
    |---|---------|----------|------|
    | 1 | Default Tomcat credentials | Critical | 9.8 |
    | 2 | SQL Injection on /api/users | Critical | 9.1 |
    | 3 | Exposed dev subdomain | Medium | 5.3 |

    ### Recommendations
    1. Change all default credentials immediately
    2. Implement parameterized queries
    3. Restrict access to admin interfaces

    Report saved to memory/2026-05-18.md
```

### 6.2 Security Audit

```
You: /project:web-audit http://testphp.vulnweb.com

AI: [Loads all web security skill contexts]

    Running systematic OWASP Top 10 audit...

    Phase 1: Information Gathering
    - Server: nginx/1.18.0
    - Backend: PHP
    - Forms found: login, search, signup

    Phase 2: Injection Testing
    - SQL Injection: [!] search field vulnerable to UNION-based SQLi
    - XSS: [!] Reflected XSS in search results
    - Command Injection: [OK] Not found

    Phase 3: Authentication
    - Brute force protection: None
    - Session management: Predictable session IDs
    - Access control: IDOR on /user.php?id= parameter

    Phase 4: Configuration
    - Directory listing: Enabled on /uploads/
    - Security headers: Missing X-Frame-Options, CSP

    Summary: 2 Critical, 2 High, 3 Medium findings
```

### 6.3 Learning and Research

```
You: /project:learn-tool sqlmap

AI: [Loads web-sqli skill context and TOOLS.md]

    ## sqlmap Learning Path

    ### Quick Start
    ```bash
    sqlmap -u "http://target/page?id=1" --batch --dbs
    ```

    ### Key Options
    | Option | Purpose |
    |--------|---------|
    | -u URL | Target URL |
    | --dbs | Enumerate databases |
    | --tables | Enumerate tables |
    | --batch | Non-interactive mode |
    | --tamper | WAF bypass scripts |
    | --os-shell | Get OS shell |
    | --level 5 | Aggressive testing |

    ### Practical Examples (from payloads.md)
    1. Basic detection: sqlmap -u "URL?id=1" --batch
    2. With POST data: sqlmap -u "URL" --data="user=admin&pass=test"
    3. WAF bypass: sqlmap -u "URL" --tamper=space2comment
    4. OS shell: sqlmap -u "URL" --os-shell

    ### Test Cases for Practice
    - TC-S001: GET parameter injection detection
    - TC-S003: UNION column count and echo position
    - TC-S009: WAF bypass testing

    Current mastery: Learning (from TOOLS.md)
    Next steps: Practice TC-S001 through TC-S005
```

### 6.4 Report Generation

```
You: Generate a vulnerability report for today's findings on target.example.com

AI: [Loads article-writing and chronicle skills]

    Based on today's session, here are the findings:

    # Security Assessment Report
    ## Target: target.example.com
    ## Date: 2026-05-18
    ## Scope: External infrastructure assessment

    ### Finding 1: Default Tomcat Credentials
    - **Severity**: Critical (CVSS 9.8)
    - **Component**: admin.target.example.com:8080
    - **Description**: Apache Tomcat manager interface uses default
      credentials (tomcat:s3cret)
    - **Impact**: Remote code execution via WAR deployment
    - **Remediation**: Change credentials, restrict access by IP,
      disable manager app in production

    ### Finding 2: SQL Injection
    - **Severity**: Critical (CVSS 9.1)
    - **Component**: api.target.example.com:8080/api/users?id
    - **Description**: UNION-based SQL injection in id parameter
    - **Impact**: Full database access, potential OS command execution
    - **Remediation**: Use parameterized queries, implement WAF

    ### Risk Rating: HIGH
    Two critical findings require immediate remediation.
```

---

## 7. FAQ

### Q1: What is the relationship between OpenCode and Crush?

**Answer:** OpenCode (github.com/opencode-ai/opencode) has been archived and continues as Crush (github.com/charmbracelet/crush), developed by the original author and the Charm team. Both use the same configuration format (`.opencode.json`), the same `contextPaths` mechanism, and the same MCP protocol. The instructions in this guide apply to both. When Crush introduces changes, update the config file accordingly.

### Q2: Do I need to modify files in skills/ to use them with OpenCode?

**Answer:** No. kali-claw skills are plain Markdown files. OpenCode reads Markdown files natively through its project instructions system. Migration means configuring OpenCode to read these files, not converting or modifying them. The skills/ directory remains exactly as it is.

### Q3: Can I use OpenCode without Kali Linux?

**Answer:** Yes, with limitations. Without Kali Linux, you can still use kali-claw for:

- Reading skill files and learning security methodology
- Research and planning
- Report generation
- Code review and security audit guidance

You cannot execute security tools like nmap, sqlmap, or hydra without a Kali Linux environment. Use SSH or Docker (see Section 2.2) to connect to a remote Kali instance.

### Q4: How do contextPaths work?

**Answer:** OpenCode reads files listed in `contextPaths` as project-level instructions at session start. These files are loaded into the AI model's context, giving it knowledge about your project. By listing kali-claw files like `SOUL.md`, `IDENTITY.md`, and `TOOLS.md` in contextPaths, the AI model automatically knows about kali-claw's identity, hacker laws, skill domains, and tool knowledge.

The default contextPaths include `CLAUDE.md`, `OPENCODE.md`, and several case variations. You can add any file path relative to the project root.

### Q5: Can I use a different AI model for security tasks?

**Answer:** Yes. OpenCode supports models from Anthropic, OpenAI, Google, Groq, OpenRouter, GitHub Copilot, AWS Bedrock, Azure OpenAI, and self-hosted endpoints. You can switch models at runtime with `Ctrl+O`.

For security tasks, we recommend Claude Sonnet 4 or Claude 3.7 Sonnet due to their strong reasoning capabilities. For cost-sensitive work, Gemini 2.5 Flash via OpenRouter is a good alternative.

### Q6: How do I add a new custom command?

**Answer:** Create a Markdown file in `.opencode/commands/` (for project-level commands) or `~/.config/opencode/commands/` (for user-level commands). The file name becomes the command ID. Use `$VARIABLE_NAME` placeholders for arguments.

```bash
# Create a new command
echo '# My Custom Command\nRUN echo "Hello $NAME"' > .opencode/commands/hello.md

# The command appears as "project:hello" in the command dialog (Ctrl+K)
```

### Q7: What happens when context gets too long?

**Answer:** OpenCode has an auto-compact feature (enabled by default) that automatically summarizes your conversation when it reaches 95% of the model's context window. This creates a new session with the summary, allowing you to continue without losing context.

You can also manually trigger compaction using the built-in "Compact Session" command via `Ctrl+K`.

### Q8: How do I use OpenCode in non-interactive mode?

**Answer:** Use the `-p` flag to run a single prompt and get the result in the terminal:

```bash
# Quick query
opencode -p "What SQL injection types does kali-claw cover?"

# JSON output for scripting
opencode -p "List all skill domains in kali-claw" -f json

# Quiet mode (no spinner)
opencode -p "Read skills/web-sqli/SKILL.md and list the tools" -q
```

This is useful for automation, scripting, and CI/CD integration.

### Q9: How do MCP servers differ from using the bash tool?

**Answer:** Both approaches let the AI execute commands, but MCP servers offer advantages:

| Feature | Bash Tool | MCP Server |
|---------|-----------|------------|
| Input validation | None (raw commands) | Structured schema validation |
| Output format | Raw text | Structured, parseable |
| Error handling | Basic | Custom error messages |
| Safety | User approval per command | Schema-level constraints |
| Reusability | One-off commands | Reusable across sessions |

For simple tasks, the bash tool is sufficient. For frequent, structured operations like nmap scans, MCP servers provide better safety and consistency.

### Q10: Can I run OpenCode alongside OpenClaw or Claude Code?

**Answer:** Yes. All three tools are independent. They read the same kali-claw files but do not interfere with each other:

- **OpenCode** reads `.opencode.json` and `contextPaths`
- **Claude Code** reads `CLAUDE.md` and uses agents/rules
- **OpenClaw** reads `AGENTS.md` and its gateway system

You can use all three interchangeably on the same kali-claw workspace.

### Q11: How do I update kali-claw skills when new versions are released?

**Answer:** Pull the latest changes from the git repository:

```bash
cd kali-claw
git pull origin main

# If you have local modifications (custom OPENCODE.md, etc.):
git stash
git pull origin main
git stash pop
```

Your `.opencode.json`, `OPENCODE.md`, and custom commands are local files that will not be overwritten by git pull.

---

## 8. Architecture Comparison

### Component Mapping: kali-claw to OpenCode

| kali-claw Component | OpenCode Equivalent | How It Works |
|--------------------|--------------------|--------------|
| `SOUL.md` | `contextPaths` entry | Loaded as project instruction at session start |
| `USER.md` | `contextPaths` entry | Loaded as project instruction at session start |
| `IDENTITY.md` | `contextPaths` entry | Loaded as project instruction at session start |
| `TOOLS.md` | `contextPaths` entry | Loaded as project instruction at session start |
| `MEMORY.md` | `contextPaths` entry | Loaded as project instruction at session start |
| `AGENTS.md` | Part of `OPENCODE.md` | Session startup sequence defined in project instructions |
| `CLAUDE.md` | Default `contextPaths` entry | Automatically loaded by OpenCode |
| `skills/*/SKILL.md` | Read on demand via view tool | AI reads specific skills when needed |
| `skills/*/payloads.md` | Read on demand via view tool | AI reads payloads when user asks |
| `skills/*/test-cases.md` | Read on demand via view tool | AI reads test cases when user asks |
| `skills/*/guides/` | Read on demand via view tool | AI reads guides for deep-dive topics |
| `HEARTBEAT.md` | Not directly supported | Use cron + `opencode -p` for periodic tasks |
| `memory/YYYY-MM-DD.md` | OpenCode session storage | OpenCode stores sessions in SQLite |
| `chronicle/` | Not directly supported | Access manually via view tool |
| Custom ECC orchestration | Custom commands | Predefined prompts with `$VARIABLES` |

### Framework Comparison

| Feature | OpenClaw | Claude Code | OpenCode |
|---------|----------|-------------|----------|
| **Language** | TypeScript/Node.js | TypeScript/Node.js | Go |
| **Install** | `npm install -g openclaw` | `npm install -g @anthropic-ai/claude-code` | `go install` or `brew install` |
| **Config file** | `~/.openclaw/` | `~/.claude/` | `.opencode.json` |
| **Project instructions** | AGENTS.md startup | `CLAUDE.md` | `OPENCODE.md` + `contextPaths` |
| **Custom commands** | ECC patterns | Agents + Rules | `.opencode/commands/` |
| **Tool integration** | Terminal commands | Bash tool + MCP | Bash tool + MCP |
| **Model support** | Single provider | Anthropic only | Multiple providers |
| **Session storage** | Markdown files | `~/.claude/projects/` | SQLite database |
| **Memory system** | File hierarchy | File system | Session storage + auto-compact |
| **TUI** | No (gateway) | Yes (CLI) | Yes (Bubble Tea TUI) |
| **LSP support** | No | No | Yes |
| **Auto compact** | No | Yes | Yes |
| **Non-interactive mode** | No | Yes (`-p` flag) | Yes (`-p` flag) |
| **Open source** | Yes | No | Yes (MIT) |
| **Cost** | Free + API costs | Subscription | Free + API costs |

### Skill Count Reference

kali-claw includes 49 security skill domains organized into six categories:

**Attack Skills (17):**
web-sqli, web-xss, web-ssrf, web-auth-bypass, web-access-control, api-security, network-pentest, password-attack, post-exploitation, wifi-pentest, binary-reverse, crypto-attacks, mobile-security, social-engineering, hardware-security, supply-chain-security, insecure-design

**Defense Skills (8):**
security-review, verification-loop, docker-patterns, safety-guard, security-misconfiguration, vulnerability-assessment, logging-monitoring, container-security

**Knowledge Skills (8):**
osint, recon-osint, deep-research, search-first, repo-scan, exa-search, data-scraper-agent, knowledge-ops

**Meta Skills (6):**
autonomous-loops, multi-agent-collaboration, council, chronicle, continuous-learning, codebase-onboarding

**Infrastructure (6):**
terminal-ops, mcp-server-patterns, browser-qa, article-writing, ai-fuzzing, ai-security

**Specialized (4):**
digital-forensics, cloud-security, security-bounty-hunter, social-intelligence

### Quick Reference: OpenCode Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+K` | Open command dialog (access custom commands) |
| `Ctrl+O` | Switch AI model |
| `Ctrl+N` | New session |
| `Ctrl+A` | Switch session |
| `Ctrl+C` | Quit |
| `Ctrl+L` | View logs |
| `Ctrl+S` | Send message (in editor) |
| `Ctrl+E` | Open external editor |
| `Ctrl+X` | Cancel current operation |
| `i` | Focus editor (when not editing) |
| `Esc` | Close overlay or exit editing |

---

_This guide covers kali-claw v0.1.7 usage with OpenCode. For the latest updates, visit the [kali-claw repository](https://github.com/brucesongs/kali-claw) and the [OpenCode repository](https://github.com/opencode-ai/opencode). Note: OpenCode has been archived and continues as [Crush](https://github.com/charmbracelet/crush) by the Charm team._
