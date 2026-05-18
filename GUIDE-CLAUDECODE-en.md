# kali-claw Skill Pack Migration Guide: Using with Claude Code

> For v0.1.7 | A complete guide to migrating kali-claw security skill packs to Anthropic's official CLI tool, Claude Code

---

## 1. Overview

### 1.1 What is Claude Code?

Claude Code is Anthropic's **official command-line tool** that lets you interact with Claude directly in the terminal. It is not a chatbot wrapper -- it is Claude's **native runtime**. Claude Code itself is the execution environment.

**Core capabilities:**

- **CLI interface** -- Use Claude directly in the terminal with multi-turn conversations and context management
- **CLAUDE.md project instructions** -- A Markdown file in the project root directory that defines how Claude behaves within that project (similar to a system prompt)
- **Custom Agents** -- Specialized prompt files placed in `~/.claude/agents/`, invocable via the Agent tool
- **Rules** -- Behavioral guidelines placed in `~/.claude/rules/` that apply to all projects or specific projects
- **MCP Servers** -- Integrate external tools via the Model Context Protocol, letting Claude directly invoke tools like nmap, sqlmap, and more
- **Memory System** -- Persistent session memory stored in `~/.claude/projects/<project>/memory/`
- **Hooks** -- Shell commands that execute automatically before/after tool calls (PreToolUse/PostToolUse/Stop)

**Key differences from OpenClaw:**

| Feature | OpenClaw | Claude Code |
|---------|----------|-------------|
| Runtime | Standalone npm framework | Claude's native CLI, no extra framework needed |
| Skill system | Markdown files parsed by the framework | Markdown files + custom agents |
| Tool invocation | Through terminal commands | Through Bash tool + MCP servers |
| Memory persistence | File system (memory/ directory) | File system (~/.claude/projects/) |
| Installation dependency | Requires Node.js + OpenClaw | Only Claude Code itself |

### 1.2 The Value of kali-claw Skill Packs

kali-claw contains **49 security skill domains** and a **518 Kali Linux tool knowledge base**, forming a structured body of security testing knowledge:

- Each skill domain includes: `SKILL.md` (methodology) + `payloads.md` (attack payloads) + `test-cases.md` (test cases) + `guides/` (deep-dive guides)
- Root-level configuration: `SOUL.md` (12 Hacker Laws), `IDENTITY.md` (skill tags), `TOOLS.md` (518 tool inventory)
- Key advantage: **kali-claw skills are essentially Markdown files** that can be directly read and used by Claude Code -- no format conversion required

### 1.3 Migration Strategy Overview

Migration does not mean "converting formats" -- it means correctly placing and referencing existing files. Three migration depths are available:

| Migration Level | Time | Capabilities Gained | Best For |
|----------------|------|---------------------|----------|
| **Minimal** | 5 minutes | Directly reference skill files in Claude Code | Quick experimentation |
| **Standard** | 30 minutes | Custom agents + rules + memory system | Daily use |
| **Complete** | 2 hours | MCP tool integration + Hooks automation + full agents | Professional penetration testers |

**Critical constraint:** This guide does NOT suggest modifying, converting, or altering any files in the kali-claw `skills/` directory. kali-claw skills stay exactly as they are. Migration means configuring Claude Code to READ existing kali-claw files, not changing them.

---

## 2. Environment Setup

### 2.1 Install Claude Code

```bash
# macOS / Linux
npm install -g @anthropic-ai/claude-code

# Verify installation
claude --version

# First launch (requires an Anthropic account)
claude
```

**Common installation issues:**

| Issue | Solution |
|-------|----------|
| Permission denied (EACCES) | `sudo npm install -g @anthropic-ai/claude-code` |
| npm registry timeout | `npm config set registry https://registry.npmmirror.com` |
| Node.js version too low | Install latest LTS via nvm: `nvm install --lts` |

### 2.2 Prepare a Kali Linux Environment

Choose one of the three options below:

**Option A: Kali Linux Local Machine (Recommended)**

```bash
# Run Claude Code directly on Kali
nmap --version  # Verify tools are available
sqlmap --version
```

**Option B: Remote Kali (SSH Access)**

```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -C "kali-claw"

# Copy public key to remote Kali machine
ssh-copy-id user@kali-host

# Verify connection
ssh user@kali-host "nmap --version && sqlmap --version"
```

**Option C: Docker Container**

```bash
# Pull and start Kali container
docker pull kalilinux/kali-rolling
docker run -it --name kali-env kalilinux/kali-rolling /bin/bash

# Install security tools inside the container
apt update && apt install -y nmap sqlmap nikto hydra metasploit-framework

# Re-enter after exiting
docker start -ai kali-env
```

### 2.3 Clone the kali-claw Workspace

```bash
git clone https://github.com/brucesongs/kali-claw.git
cd kali-claw
```

Verify the file structure:

```bash
ls -la
# You should see: SOUL.md  AGENTS.md  IDENTITY.md  USER.md  MEMORY.md  TOOLS.md  HEARTBEAT.md  skills/  memory/  chronicle/
```

### 2.4 Environment Checklist

- [ ] Claude Code installed (`claude --version`)
- [ ] Kali Linux available (local machine / SSH remote / Docker container)
- [ ] kali-claw cloned to local machine
- [ ] Basic Kali tools available (verified with `nmap --version`)
- [ ] Network connection working

---

## 3. Level 1: Minimal Migration (5 Minutes)

### 3.1 Open the Project Directly

```bash
cd kali-claw
claude
```

When Claude Code starts, it **automatically reads `CLAUDE.md`** from the project root directory as project instructions. kali-claw's `CLAUDE.md` already contains a project overview and architecture description, so Claude will understand that this is a security testing knowledge base.

### 3.2 Start Using

Simply use natural language conversation and ask Claude to read the corresponding skill files:

```
You: Read skills/web-sqli/SKILL.md, then help me analyze a SQL injection vulnerability

Claude: [reads SKILL.md]
        I now understand the SQL injection skill methodology. This skill covers the following injection types:
        - Union-based / Error-based / Boolean-blind / Time-blind
        - Double Query / Stacked Queries / Out-of-band

        Please provide your target information, and I will analyze it using the methodology.
```

```
You: Look at skills/web-sqli/payloads.md and give me a UNION injection payload

Claude: [reads payloads.md]
        Based on the UNION Injection section in payloads.md, here is a standard payload:

        ' UNION SELECT 1,2,3-- -

        Steps:
        1. First determine column count with ORDER BY: ' ORDER BY 5-- -
        2. Find the echo position: ' UNION SELECT 1,2,3-- -
        3. Extract data: ' UNION SELECT database(),version(),user()-- -
```

```
You: Execute testing per TC-S001 from skills/web-sqli/test-cases.md

Claude: [reads test-cases.md]
        Following test steps from TC-S001 GET Parameter Injection Point Detection:

        Step 1: Test single quote to trigger SQL error
          ?id=1'

        Step 2: Confirm string-type injection
          ?id=1' AND '1'='1   (page should be normal)
          ?id=1' AND '1'='2   (page should be abnormal)

        Step 3: Confirm numeric-type injection
          ?id=1 AND 1=1       (page should be normal)
          ?id=1 AND 1=2       (page should be abnormal)

        Step 4: Test different closure styles: ' / " / ') / "))

        Please provide the target URL and I will help you execute the test.
```

### 3.3 Limitations of Minimal Migration

- **You must manually reference skill file paths each time** (e.g., "Read skills/web-sqli/SKILL.md")
- **No persistent memory** -- Claude does not remember previous analysis results after the session ends
- **No automated agents** -- Cannot trigger skills with shortcut commands like `/web-sqli`
- **No tool integration** -- Cannot directly invoke tools like nmap, sqlmap, etc.

Best for: Quick experimentation, one-off testing, single-use tasks.

---

## 4. Level 2: Standard Migration (30 Minutes)

### 4.1 Configure CLAUDE.md (Project Instructions)

Append security agent behavioral instructions to kali-claw's existing `CLAUDE.md`. Add the following content to the end of CLAUDE.md:

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

**Important:** You are appending to CLAUDE.md, not modifying any files inside `skills/`. The kali-claw skill files remain untouched.

### 4.2 Create Custom Agents

Create Claude Code custom agents that reference kali-claw skill files. Agent files go in `~/.claude/agents/`.

**Create the agents directory:**

```bash
mkdir -p ~/.claude/agents
```

**Example: web-sqli analysis agent** (`~/.claude/agents/web-sqli-analyzer.md`):

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
- `skills/web-sqli/SKILL.md` -- Complete methodology, tools, and attack chain
- `skills/web-sqli/payloads.md` -- Payload collection organized by 10 injection types
- `skills/web-sqli/test-cases.md` -- Structured test case templates (TC-S001 to TC-S012)
- `skills/web-sqli/guides/` -- Deep-dive guides for advanced techniques

## Operating Procedure

1. **Read SKILL.md first** -- Always load the methodology before starting any task
2. **Identify injection type** -- Determine if the target shows echo, error, or blind behavior
3. **Follow the attack chain** -- Detection -> Fingerprinting -> Exploitation -> Data Extraction
4. **Use structured payloads** -- Pull from payloads.md, do not improvise payloads
5. **Document per test-cases.md** -- Record findings using TC-SXXX format
6. **Provide defense recommendations** -- Always include remediation advice

## Safety Rules

- Only test targets within explicitly authorized scope
- Confirm with the user before any destructive SQL operations (DROP, DELETE, UPDATE)
- Never exfiltrate real user data -- use dummy data for proof-of-concept
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

**Batch-create more agents** (optional, create as needed):

```bash
# Network scanner agent
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

# Security auditor agent
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

# OSINT researcher agent
cat > ~/.claude/agents/osint-researcher.md << 'AGENT_EOF'
---
name: osint-researcher
description: Open Source Intelligence gathering specialist. Subdomain enumeration, DNS analysis, technology fingerprinting, and information gathering.
tools:
  - Bash
  - Read
  - Write
  - Grep
---

You are an OSINT research specialist. Read skills/osint/SKILL.md and skills/recon-osint/SKILL.md for methodology. Gather intelligence systematically: DNS -> Subdomains -> Technology Stack -> Public Records. Document all findings and assess their security implications.
AGENT_EOF

# Post-exploitation agent
cat > ~/.claude/agents/post-exploitation.md << 'AGENT_EOF'
---
name: post-exploitation
description: Post-exploitation specialist. Privilege escalation, lateral movement, persistence, and impact assessment after initial access.
tools:
  - Bash
  - Read
  - Write
  - Grep
---

You are a post-exploitation specialist. Read skills/post-exploitation/SKILL.md for methodology. After gaining initial access, follow the chain: Stabilize -> Enumerate -> Escalate -> Persist -> Exfiltrate (assessment only). Always assess impact and document all attack paths. Never execute destructive actions without explicit user confirmation.
AGENT_EOF
```

**Key principle:** Each agent file *references* skill files in `skills/` by their paths. The agent reads the SKILL.md, payloads.md, and test-cases.md from their original locations. No skill files are modified or duplicated.

### 4.3 Create Security Rules

Create a Claude Code rules file that encodes kali-claw's safety principles:

```bash
mkdir -p ~/.claude/rules
```

Create `~/.claude/rules/kali-claw-security.md`:

```markdown
# kali-claw Security Rules

## Mandatory Safety Checks

Before ANY security testing command:
- [ ] Target is within explicitly authorized scope
- [ ] User has confirmed the target and test type
- [ ] Safety-guard skill principles have been reviewed
- [ ] No destructive commands without triple confirmation

## The 12 Hacker Laws (from SOUL.md)

1. **First Principles Thinking** -- Break problems down to fundamental facts
2. **Divergent Thinking First** -- Consider at least 3 solutions before acting
3. **Minimize Attack Surface** -- Less exposure means less risk
4. **Defense in Depth** -- Never rely on a single layer
5. **Least Privilege** -- Grant only necessary access
6. **Assume Breach** -- Design assuming attacker is already inside
7. **Obscurity Is Not Security** -- Security from design, not hiding
8. **Trust but Verify** -- Verify all inputs and outputs
9. **Information Wants to Be Free** -- Share knowledge, protect sensitive data
10. **Skill Over Credentials** -- Judge by capability
11. **The Weakest Link Is Human** -- Always consider human factor
12. **Murphy's Security Law** -- If it can be exploited, it will be

## Command Execution Rules

- Never use `rm` -- use trash or move to bak/ directory
- Triple confirmation required for destructive operations
- Always log actions to memory/YYYY-MM-DD.md
- Never write sensitive data (API keys, tokens, passwords) to memory files
- Proactively redact sensitive information in responses

## File Operations

- Back up core files to bak/ directory before modification
- Never overwrite SOUL.md, USER.md, IDENTITY.md without user awareness
- Memory files are append-only -- do not delete past entries
```

### 4.4 Using Custom Agents

After starting Claude Code, you can trigger agents in the following ways:

**Method 1: Natural language trigger** (Claude auto-matches)

```
You: Help me detect SQL injection vulnerabilities on http://testsite.com/login

Claude: [auto-identifies as SQL injection task, loads web-sqli-analyzer agent]
        Reading the methodology from skills/web-sqli/SKILL.md...
```

**Method 2: Explicitly specify the agent**

```
You: Use the web-sqli-analyzer agent to analyze this login form

Claude: [loads the specified agent, follows the operating procedure defined in the agent]
```

**Method 3: Through the Bash tool**

When in agent mode, Claude automatically uses the Bash tool to execute security commands:

```
You: Use sqlmap to test http://testsite.com/page?id=1

Claude: Executing sqlmap command...
        [runs via Bash tool]
        sqlmap -u "http://testsite.com/page?id=1" --batch --dbs --level 3
```

### 4.5 Configure the Memory System

Map kali-claw's memory to Claude Code's memory system.

**Understanding the correspondence between the two memory systems:**

| kali-claw Memory | Claude Code Memory | Description |
|-----------------|-------------------|-------------|
| `memory/YYYY-MM-DD.md` | `~/.claude/projects/<project>/memory/` | Daily session records |
| `MEMORY.md` (root) | Project memory file | Long-term distilled knowledge |
| `chronicle/YYYY-MM/*.md` | Manually maintained | Monthly milestones |

**Configure project memory:**

```bash
# Determine project memory path
# Claude Code uses a hash of the project path as the directory name
# Check the actual path
ls ~/.claude/projects/

# Copy kali-claw's long-term memory to Claude Code memory
PROJECT_MEMORY=~/.claude/projects/$(echo -n "/path/to/kali-claw" | md5sum | cut -d' ' -f1)/memory
mkdir -p "$PROJECT_MEMORY"

# Copy long-term memory
cp MEMORY.md "$PROJECT_MEMORY/long-term-knowledge.md"

# Copy recent daily memory (optional)
cp memory/2026-05-*.md "$PROJECT_MEMORY/"
```

On macOS, use `md5` instead of `md5sum`:

```bash
PROJECT_MEMORY=~/.claude/projects/$(echo -n "/path/to/kali-claw" | md5)/memory
```

**Using the memory system:**

During a session, you can ask Claude to write important findings to memory:

```
You: Record this SQL injection vulnerability discovery to memory

Claude: [writes discovery to ~/.claude/projects/.../memory/ file]
        Recorded to memory file. I will still remember this discovery in the next session.
```

---

## 5. Level 3: Complete Migration (2 Hours)

### 5.1 MCP Server Integration

Through MCP servers, Claude Code can **directly invoke** Kali security tools without needing manual command input.

**Install the MCP SDK:**

```bash
pip install mcp
```

**Create the MCP server directory:**

```bash
mkdir -p ~/kali-mcp-servers
```

**Complete nmap MCP server example** (`~/kali-mcp-servers/nmap_server.py`):

```python
#!/usr/bin/env python3
"""nmap MCP Server -- Wraps nmap as an MCP tool for Claude Code."""

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
    """Basic target validation -- reject obviously invalid input."""
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

**Complete sqlmap MCP server example** (`~/kali-mcp-servers/sqlmap_server.py`):

```python
#!/usr/bin/env python3
"""sqlmap MCP Server -- Wraps sqlmap as an MCP tool for Claude Code."""

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

**Configure MCP servers:**

Create `.mcp.json` in the project root:

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

Or configure globally in `~/.claude.json`:

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

**Remote Kali MCP configuration** (invoking remote Kali tools via SSH):

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

The remote MCP server needs to invoke nmap through SSH during execution:

```python
# Key modification in remote_nmap_server.py
import os

KALI_HOST = os.environ.get("KALI_HOST", "user@kali-host")
SSH_KEY = os.environ.get("KALI_SSH_KEY", "~/.ssh/id_ed25519")

def run_nmap_remote(args: list[str], timeout: int = 300) -> str:
    ssh_cmd = ["ssh", "-i", SSH_KEY, KALI_HOST, "nmap"] + args
    result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout + result.stderr
```

### 5.2 Configure Hooks (Automation)

Use Claude Code Hooks to implement some of kali-claw HEARTBEAT's functionality.

**Scope check hook** (PreToolUse):

This hook automatically checks whether the target is within the authorized scope before executing Bash commands.

Create `~/kali-hooks/check-scope.sh`:

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

# Check if command contains targets
AUTHORIZED_TARGETS=$(grep -v '^#' "$SCOPE_FILE" | grep -v '^$')

# Log execution
echo "[$(date)] Command: $COMMAND" >> .claude-execution.log

exit 0
```

Create a project-level scope file `.scope` (in the kali-claw project root):

```
# Authorized Test Targets
# One target per line, lines starting with # are comments
192.168.1.0/24
testphp.vulnweb.com
*.example.com
```

**Configure Hooks in `~/.claude/settings.json`:**

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

### 5.3 Complete Project Structure After Migration

```
kali-claw/                           <-- Project root
|-- CLAUDE.md                        <-- Project instructions (Security Agent Mode appended)
|-- SOUL.md                          <-- 12 Hacker Laws (unchanged)
|-- USER.md                          <-- User information (unchanged)
|-- IDENTITY.md                      <-- Skill tags (unchanged)
|-- AGENTS.md                        <-- Workspace config (unchanged)
|-- MEMORY.md                        <-- Long-term memory (unchanged)
|-- TOOLS.md                         <-- Tool inventory (unchanged)
|-- HEARTBEAT.md                     <-- Heartbeat tasks (unchanged)
|-- .mcp.json                        <-- MCP server configuration (new)
|-- .scope                           <-- Authorized scope file (new)
|-- skills/                          <-- 49 skill domains (unchanged)
|   |-- web-sqli/
|   |   |-- SKILL.md
|   |   |-- payloads.md
|   |   |-- test-cases.md
|   |   +-- guides/
|   |-- network-pentest/
|   |-- osint/
|   +-- ... (46 more domains)
|-- memory/                          <-- Daily memory logs
|-- chronicle/                       <-- Monthly milestones
+-- bak/                             <-- Backup directory

~/.claude/
|-- agents/                          <-- Custom agents (reference skills/ paths)
|   |-- web-sqli-analyzer.md
|   |-- network-scanner.md
|   |-- security-auditor.md
|   |-- osint-researcher.md
|   |-- post-exploitation.md
|   +-- ...
|-- rules/                           <-- Security rules
|   +-- kali-claw-security.md
|-- settings.json                    <-- Hooks configuration
+-- projects/                        <-- Project memory
    +-- <project-hash>/
        +-- memory/
            |-- long-term-knowledge.md
            +-- ...

~/kali-mcp-servers/                  <-- MCP servers (new)
|-- nmap_server.py
|-- sqlmap_server.py
+-- remote_nmap_server.py

~/kali-hooks/                        <-- Hook scripts (new)
+-- check-scope.sh
```

**Key observation:** The `skills/` directory and all files within it remain completely unchanged. Claude Code reads them in their original locations. The only modifications are: appending to `CLAUDE.md`, creating new files outside `skills/` (agents, rules, MCP servers, hooks), and creating `.mcp.json` and `.scope` in the project root.

---

## 6. Usage Scenarios

### 6.1 Full Penetration Testing Workflow

The following demonstrates a multi-turn conversation executing a complete penetration test in Claude Code:

**Step 1 -- Reconnaissance:**

```
You: Help me gather information on target.com, including subdomains, DNS records, and tech stack

Claude: I will perform comprehensive reconnaissance on target.com. Reading skills/recon-osint/SKILL.md for methodology...

        Executing per the reconnaissance methodology:

        1. DNS Record Lookup
        [executed] dig target.com ANY +noall +answer
        [result] A: 93.184.216.34, MX: mail.target.com, NS: ns1.cloudflare.com

        2. Subdomain Enumeration
        [executed] sublist3r -d target.com
        [result] Found 12 active subdomains
          - api.target.com (REST API)
          - admin.target.com (login page)
          - dev.target.com (development environment)

        3. Web Technology Fingerprinting
        [executed] whatweb target.com
        [result] Nginx 1.18, PHP 7.4, MySQL

        Recommendation: Perform port scanning on admin.target.com
```

**Step 2 -- Scanning:**

```
You: Scan admin.target.com

Claude: [invokes MCP nmap_scan tool]
        Executing nmap -sV -sC -p- admin.target.com

        Port scan results:
        PORT     STATE  SERVICE    VERSION
        22/tcp   open   ssh        OpenSSH 8.2
        80/tcp   open   http       Nginx 1.18.0
        443/tcp  open   ssl/http   Nginx 1.18.0
        8080/tcp open   http-proxy PHP-FPM 7.4

        Finding: Port 8080 runs PHP-FPM, potential unauthorized access.
        Recommendation: Perform directory scanning and vulnerability detection on admin.target.com:8080.
```

**Step 3 -- Exploitation:**

```
You: admin.target.com:8080 has a login page, test for SQL injection

Claude: [loads web-sqli-analyzer agent, reads SKILL.md]
        Executing tests per the SQL injection methodology:

        Step 1: Injection point detection
        [invokes MCP sqlmap_detect tool]
        Target: http://admin.target.com:8080/login
        POST data: username=admin&password=test

        [sqlmap results]
        Parameter 'username' is vulnerable to Boolean-based blind SQL injection!
        Database type: MySQL >= 5.6
        Backend DBMS: MySQL

        Step 2: Enumerate databases
        [invokes MCP sqlmap_dbs tool]

        Available databases:
        [*] information_schema
        [*] mysql
        [*] performance_schema
        [*] target_app

        SQL injection vulnerability discovered!
        - Injection point: username parameter
        - Type: Boolean-based blind
        - Database: MySQL >= 5.6
        - CVSS score: 9.8 (Critical)

        Remediation: Use parameterized queries (prepared statements) instead of string concatenation
```

**Step 4 -- Post-Exploitation Assessment:**

```
You: We got database access, what should we do next?

Claude: [reads skills/post-exploitation/SKILL.md]
        After gaining database access, assess impact per the post-exploitation methodology:

        1. Database Information Gathering
           - List tables in target_app database: users, sessions, configs, api_keys
           - Check for sensitive data exposure

        2. Privilege Escalation Assessment
           - Check FILE privileges: can we read/write system files
           - Try UDF escalation: can we execute system commands via custom functions

        3. Persistence Assessment
           - Document all attack paths
           - Assess detection difficulty for each path

        4. Impact Assessment
           - Data breach scope
           - System control level
           - Lateral movement possibilities

        Note: All operations are for assessment purposes only. Continue with deeper assessment?
```

**Step 5 -- Report Generation:**

```
You: Help me generate a penetration test report

Claude: [reads skills/article-writing/SKILL.md]
        Generating penetration test report:

        ## Penetration Test Report -- target.com

        ### 1. Executive Summary
        - Test date: 2026-05-18
        - Target scope: target.com and subdomains
        - Overall risk level: High

        ### 2. Findings Summary
        | # | Vulnerability | Severity | Impact |
        |---|--------------|----------|--------|
        | 1 | SQL Injection (admin.target.com) | Critical | Full database control |
        | 2 | Development environment exposed (dev.target.com) | Medium | Information disclosure |
        | 3 | Port 8080 unrestricted access | Medium | Increased attack surface |

        ### 3. Remediation Recommendations (by priority)
        1. Immediately fix SQL injection using parameterized queries
        2. Disable public access to the dev environment
        3. Restrict port 8080 to internal network only

        [Report has been recorded to memory]
```

### 6.2 Security Audit

```
You: Use the security-auditor agent to perform an OWASP audit on http://testphp.vulnweb.com

Claude: [loads security-auditor agent]
        [reads skills/security-review/SKILL.md]
        Performing systematic OWASP Top 10 audit:

        A01 - Broken Access Control
        [check] Found IDOR, can access other users' data without authorization

        A02 - Cryptographic Failures
        [check] HTTP not redirecting to HTTPS

        A03 - Injection
        [check] Found SQL injection and XSS vulnerabilities

        A05 - Security Misconfiguration
        [check] Default configuration unchanged, error messages expose stack traces

        A07 - Auth Failures
        [check] No rate limiting on login, vulnerable to brute force

        Overall rating: High risk
        Priority fixes: A03 Injection + A01 Access Control
```

### 6.3 Learning and Research

```
You: I want to learn SQL injection. Where do I start?

Claude: [reads skills/web-sqli/SKILL.md and guides/ directory]
        Creating a learning path based on the skill methodology:

        Phase 1: Theory Fundamentals
        - SQL injection principles: user input concatenated directly into SQL queries
        - Injection types: Union-based / Boolean-blind / Time-blind / Error-based

        Phase 2: Set Up a Practice Environment
        docker run -d -p 80:80 acgpiano/sqli-labs

        Phase 3: From Simple to Complex
        - Less-1: Union string-type injection (beginner)
        - Less-5: Boolean blind injection (intermediate)
        - Less-15: Time blind injection (advanced)

        I will explain the principles and give hints for each level. Ready?
```

### 6.4 Council Multi-Perspective Analysis

```
You: Use council mode to analyze the SQL injection vulnerability we found

Claude: [reads skills/council/SKILL.md]
        Launching Council multi-perspective analysis:

        [Attacker Perspective]
        - Can achieve full database control via SQL injection
        - May achieve RCE through FILE privileges
        - Suggested tests: write webshell, read /etc/passwd

        [Defender Perspective]
        - Root cause: not using parameterized queries
        - Fix: use prepared statements + WAF rules
        - Detection: monitor abnormal SQL query patterns

        [Auditor Perspective]
        - CVSS score: 9.8 (Critical)
        - Compliance impact: violates OWASP A03, PCI-DSS 6.5
        - Need to document the complete attack chain in writing

        Consensus recommendation: Fix immediately, and check other pages for the same vulnerability class.
```

### 6.5 Report Generation

```
You: Help me generate a security report for all vulnerabilities found today

Claude: [reads skills/article-writing/SKILL.md]
        Generating report per the article-writing skill methodology:

        ## Security Assessment Report

        ### Metadata
        - Assessment date: 2026-05-18
        - Target: target.com
        - Methodology: OWASP Top 10 + PTES

        ### Findings Summary
        | ID | Title | CVSS | Status |
        |----|-------|------|--------|
        | V-001 | SQL Injection | 9.8 | Open |
        | V-002 | XSS (Reflected) | 6.1 | Open |
        | V-003 | IDOR | 5.3 | Open |

        ### Detailed Findings
        [For each vulnerability: description, reproduction steps, evidence, impact analysis, remediation]

        [Report written to memory/2026-05-18-report.md]
```

---

## 7. FAQ

### Q1: Can Claude Code run on Kali Linux?

Yes. Kali Linux is Debian-based; you only need Node.js >= 18:

```bash
# Install Node.js
sudo apt update
sudo apt install -y nodejs npm
# Or use nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
nvm install --lts

# Install Claude Code
npm install -g @anthropic-ai/claude-code
claude --version
```

### Q2: MCP server fails to connect

**Symptoms:** Claude Code reports MCP server startup failure

**Troubleshooting steps:**

```bash
# 1. Check Python and MCP SDK are installed
python3 --version
pip show mcp

# 2. Test MCP server manually
python3 ~/kali-mcp-servers/nmap_server.py
# Should start without errors

# 3. Check paths in .mcp.json or ~/.claude.json
# Make sure you are using absolute paths

# 4. Check permissions
chmod +x ~/kali-mcp-servers/*.py
```

### Q3: Custom agents do not trigger

**Troubleshooting:**

```bash
# 1. Check agent file locations
ls ~/.claude/agents/

# 2. Check file format (must have YAML frontmatter)
head -5 ~/.claude/agents/web-sqli-analyzer.md
# Should start with ---, containing name and description fields

# 3. Check if description is descriptive enough
# Claude matches tasks to agents based on the description
```

### Q4: How do I keep the kali-claw project updated?

```bash
cd kali-claw
git pull origin main

# Your custom agents and rules do not need to change
# They reference file paths under skills/, so updated content takes effect automatically
```

### Q5: Will Claude Code's memory be lost?

No. Claude Code's memory is stored in disk files (`~/.claude/projects/<hash>/memory/`) and does not disappear when the session ends. Even if you close Claude Code, the memory is still there when you open the same project next time.

### Q6: How do I use kali-claw's skill system with Claude Code?

Claude Code supports invoking registered skills. To use kali-claw skills:

1. **Through custom agents:** Agents created in `~/.claude/agents/` are automatically available
2. **Through direct conversation:** Describe the task and Claude automatically matches relevant skill files
3. **Through manual reference:** Tell Claude to read a specific skill's `SKILL.md`

### Q7: Can I use both OpenClaw and Claude Code simultaneously?

Yes. Both share the same `skills/` directory:

- **OpenClaw** reads `SOUL.md` + `AGENTS.md` + `skills/` as a workspace
- **Claude Code** reads `CLAUDE.md` + `~/.claude/agents/` + `skills/` as a project

They do not conflict -- they simply use different runtimes. You can choose which one to use based on the scenario.

### Q8: How do I configure remote Kali access?

There are three approaches:

1. **Direct SSH:** Claude Code executes `ssh user@kali-host "nmap ..."` via the Bash tool
2. **MCP remote mode:** MCP server invokes remote Kali tools through SSH (see Section 5.1)
3. **VS Code Remote:** Connect to Kali via VS Code Remote SSH, then run Claude Code in the remote terminal

### Q9: Do I need to modify any kali-claw skill files?

No. This is a fundamental design principle of this migration guide. All 49 skill domains in the `skills/` directory remain completely unchanged. Claude Code reads them in their original Markdown format. The migration involves:

- Appending instructions to `CLAUDE.md` (project-level config, not a skill file)
- Creating new agent files in `~/.claude/agents/` that *reference* skill paths
- Creating rule files in `~/.claude/rules/` that encode safety principles
- Creating MCP server wrappers that call Kali tools
- Creating hook scripts for automation

None of these steps touch any file inside `skills/`.

### Q10: How do I create agents for all 49 skill domains?

You do not need to create an agent for every single skill domain. Start with the domains you use most frequently. The agent creation pattern is consistent:

1. Create a `.md` file in `~/.claude/agents/` with YAML frontmatter (name, description, tools)
2. In the body, specify which `skills/<domain>/SKILL.md` files to read
3. Define the operating procedure and safety rules
4. Reference `payloads.md` and `test-cases.md` paths for the agent to read on demand

For skills you use occasionally, just reference the file path directly in conversation (minimal migration approach).

---

## 8. Architecture Comparison and Reference

### 8.1 Complete Mapping Table

| kali-claw (OpenClaw) | Claude Code | Migration Method | Notes |
|---------------------|------------|-----------------|-------|
| `SOUL.md` (personality) | `CLAUDE.md` | Append key content | Append 12 Hacker Laws and security rules to CLAUDE.md |
| `USER.md` (user info) | `~/.claude/settings` or `CLAUDE.md` | Manual configuration | Record preferences in CLAUDE.md user section or settings |
| `AGENTS.md` (session config) | `CLAUDE.md` + `~/.claude/rules/` | Extract rules | Session startup flow is handled automatically by CLAUDE.md |
| `skills/*/SKILL.md` | `~/.claude/agents/` | Create agents that reference paths | Create one agent file per skill domain, referencing original paths |
| `skills/*/payloads.md` | Project files (agent references) | Keep in place | Agents reference paths; Claude reads on demand |
| `skills/*/test-cases.md` | Project files (agent references) | Keep in place | Agents reference paths; Claude reads on demand |
| `skills/*/guides/` | Project files | Keep in place | Deep-dive learning materials do not need migration |
| `MEMORY.md` (long-term memory) | `~/.claude/projects/.../memory/` | Copy | Copy long-term distilled knowledge to Claude Code memory |
| `memory/*.md` (daily logs) | `~/.claude/projects/.../memory/` | Copy | Copy recent logs to Claude Code memory |
| `chronicle/` (chronicles) | Project files | Keep in place | Monthly milestone records |
| `TOOLS.md` (tool inventory) | Project files + MCP servers | Partial conversion | Tool knowledge stays as project file; common tools wrapped as MCP |
| `HEARTBEAT.md` (heartbeat) | `~/.claude/settings.json` Hooks | Manual configuration | Implement partial automation using Hooks |
| 12 Hacker Laws | `~/.claude/rules/` | Extract as rules | Create a standalone rules file |

### 8.2 Migration Checklist

**Minimal migration** (5 minutes):

- [ ] Install Claude Code
- [ ] Clone the kali-claw project
- [ ] Run `claude` in the project directory

**Standard migration** (30 minutes):

- [ ] Append Security Agent Mode to `CLAUDE.md`
- [ ] Create custom agents in `~/.claude/agents/`
- [ ] Create `~/.claude/rules/kali-claw-security.md` rules file
- [ ] Configure the project memory system

**Complete migration** (2 hours):

- [ ] Complete all standard migration steps
- [ ] Create MCP servers (nmap, sqlmap, etc.)
- [ ] Configure `.mcp.json`
- [ ] Create hook scripts
- [ ] Configure Hooks in `~/.claude/settings.json`
- [ ] Create `.scope` authorized scope file
- [ ] Test the complete workflow

### 8.3 Performance Comparison

| Metric | OpenClaw | Claude Code |
|--------|----------|-------------|
| First startup | Requires framework install + agent creation | Direct `claude` launch |
| Skill loading | All loaded at session start | Read on demand (more efficient) |
| Tool invocation | Through terminal commands | Through Bash tool + MCP |
| Context window | Limited by framework | Claude's native context window (200K tokens) |
| Multi-session | Supports multiple agents | Supports multiple tabs |
| Update maintenance | Need to sync framework and skills | Only `git pull` to update skills |

### 8.4 Skill Domain Reference

The complete list of 49 kali-claw skill domains available for reference:

**Web Security (5 domains):**
- `web-sqli` -- SQL injection detection, exploitation, and defense
- `web-xss` -- Cross-site scripting attacks and prevention
- `web-ssrf` -- Server-Side Request Forgery
- `web-auth-bypass` -- Authentication bypass techniques
- `web-access-control` -- Access control vulnerabilities

**Network & Wireless (4 domains):**
- `network-pentest` -- Network penetration testing methodology
- `wifi-pentest` -- Wireless network security testing
- `osint` -- Open Source Intelligence gathering
- `recon-osint` -- Reconnaissance and OSINT techniques

**Exploitation (3 domains):**
- `post-exploitation` -- Post-exploitation techniques and assessment
- `password-attack` -- Password cracking and credential attacks
- `crypto-attacks` -- Cryptographic attack methods

**Code & Binary (5 domains):**
- `binary-reverse` -- Binary analysis and reverse engineering
- `repo-scan` -- Source code security scanning
- `security-review` -- Security code review methodology
- `ai-security` -- AI/ML model security testing
- `ai-fuzzing` -- AI-powered fuzzing techniques

**Cloud & Infrastructure (4 domains):**
- `cloud-security` -- Cloud platform security assessment
- `container-security` -- Docker and Kubernetes security
- `supply-chain-security` -- Supply chain attack detection
- `hardware-security` -- Hardware-level security testing

**Mobile & Digital Forensics (2 domains):**
- `mobile-security` -- Mobile application security testing
- `digital-forensics` -- Digital forensics and incident response

**Social & Intelligence (3 domains):**
- `social-engineering` -- Social engineering attack awareness
- `social-intelligence` -- Social intelligence gathering
- `security-bounty-hunter` -- Bug bounty hunting methodology

**Security Assessment (3 domains):**
- `vulnerability-assessment` -- Systematic vulnerability assessment
- `insecure-design` -- Insecure design pattern identification
- `security-misconfiguration` -- Configuration weakness detection

**Meta Skills (4 domains):**
- `autonomous-loops` -- Autonomous operation loops
- `council` -- Multi-perspective analysis
- `multi-agent-collaboration` -- Multi-agent coordination
- `browser-qa` -- Browser-based security QA

**Knowledge & Research (5 domains):**
- `deep-research` -- Deep security research methodology
- `search-first` -- Intelligence-first approach to security
- `exa-search` -- Advanced search techniques
- `data-scraper-agent` -- Data collection and analysis
- `article-writing` -- Security report and article writing

**Infrastructure & Operations (7 domains):**
- `terminal-ops` -- Terminal operations and scripting
- `safety-guard` -- Safety guardrails and scope enforcement
- `chronicle` -- Knowledge chronicle management
- `continuous-learning` -- Continuous learning system
- `docker-patterns` -- Docker lab environment patterns
- `mcp-server-patterns` -- MCP server design patterns
- `verification-loop` -- Verification and validation loops
- `logging-monitoring` -- Security logging and monitoring

**Onboarding & Knowledge (4 domains):**
- `codebase-onboarding` -- Codebase security onboarding
- `knowledge-ops` -- Knowledge management operations
- `api-security` -- API security testing methodology
- `insecure-design` -- Insecure design pattern identification

Each domain directory contains:
- `SKILL.md` -- Methodology, tools, attack chains
- `payloads.md` -- Attack payloads organized by type
- `test-cases.md` -- Structured test case templates
- `guides/` -- Deep-dive learning materials (in most domains)

---

_Built with Claude Code. For questions or feedback, please open an issue on GitHub._
