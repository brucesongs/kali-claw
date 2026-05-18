# kali-claw Skill Pack Migration Guide: Using with Claude Code

> A comprehensive guide to migrating your kali-claw penetration testing workspace from OpenClaw to Claude Code -- Anthropic's official CLI runtime.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Environment Setup](#2-environment-setup)
3. [Approach 1: Minimal Migration (5 Minutes)](#3-approach-1-minimal-migration-5-minutes)
4. [Approach 2: Standard Migration (30 Minutes)](#4-approach-2-standard-migration-30-minutes)
5. [Approach 3: Full Migration (2 Hours)](#5-approach-3-full-migration-2-hours)
6. [Usage Scenarios](#6-usage-scenarios)
7. [FAQ](#7-faq)
8. [Architecture Comparison and Reference](#8-architecture-comparison-and-reference)

---

## 1. Overview

### 1.1 What is Claude Code

Claude Code is Anthropic's official CLI tool for using Claude directly in your terminal. It provides a native, framework-free way to interact with Claude as a coding and reasoning assistant.

**Key features relevant to kali-claw:**

- **CLAUDE.md files** -- Project-level instruction files that Claude reads automatically at session start (acts as a system prompt for your project)
- **Custom agents** -- Specialized agent prompts stored in `~/.claude/agents/` that can be invoked with the Agent tool
- **Rules** -- Behavioral guidelines stored in `~/.claude/rules/` that apply across all sessions
- **MCP servers** -- Tool integration via Model Context Protocol, allowing Claude to call external tools directly
- **Memory system** -- Persistent notes stored in `~/.claude/projects/<project>/memory/` that survive across sessions
- **Hooks** -- Shell commands triggered by PreToolUse/PostToolUse/Stop events for automation

**How it differs from OpenClaw:**

| Aspect | OpenClaw | Claude Code |
|--------|----------|-------------|
| Runtime | Third-party npm framework | Claude's native CLI -- no separate framework |
| Agent definition | Workspace directory with SOUL.md | CLAUDE.md + custom agent files |
| Tool access | Gateway routes | MCP servers + Bash tool |
| Memory | Manual memory/ directory | Built-in persistent memory system |
| Installation | `npm install -g openclaw` | `npm install -g @anthropic-ai/claude-code` |

**Why choose Claude Code for kali-claw:**

1. **No framework install needed** -- Claude Code IS the runtime. No OpenClaw gateway, no separate service to manage.
2. **Skills become native agents** -- Each kali-claw skill domain maps to a Claude Code custom agent, invocable with the Agent tool.
3. **MCP wraps Kali tools directly** -- nmap, sqlmap, and other tools become first-class callable functions.
4. **Memory persists automatically** -- Claude Code's memory system replaces kali-claw's manual memory hierarchy.
5. **Cross-platform** -- Works on macOS, Windows, and Linux. Access Kali remotely via SSH when not running on Kali directly.

### 1.2 Value of the kali-claw Skill Pack

The kali-claw workspace provides a ready-made knowledge base that supercharges Claude Code for security work:

- **49 security skill domains** -- From OSINT and web exploitation to cloud security and AI fuzzing
- **518 Kali Linux tool references** -- Mastery tracking, command examples, and usage notes
- **Thousands of lines of attack payloads** -- Organized by category in `payloads.md` files
- **Structured test case templates** -- `test-cases.md` files with TC-SXXX format for repeatable testing
- **12 Hacker Laws** -- Behavioral guidelines derived from real-world security philosophy

**The key insight:** kali-claw skills are just Markdown files. Migration to Claude Code does not require format conversion -- it requires proper placement and referencing within Claude Code's native structure.

### 1.3 Migration Strategy

There are three levels of migration, depending on how much Claude Code integration you want:

```
Minimal (5 min)           Standard (30 min)          Full (2 hours)
    |                          |                          |
    v                          v                          v
Open project         + CLAUDE.md config          + MCP servers
in Claude Code       + Custom agents              + Memory import
                     + Rule files                 + Hooks automation
                     + Memory setup
```

**Approach 1 -- Minimal Migration (5 minutes):**
Open the kali-claw project directly in Claude Code. Claude reads CLAUDE.md and can access all skill files via the Read tool. No configuration needed. You reference skill files manually.

**Approach 2 -- Standard Migration (30 minutes):**
Configure CLAUDE.md with kali-claw behavioral instructions. Convert key skill domains into Claude Code custom agents. Set up rule files for security guidelines. Configure the memory system.

**Approach 3 -- Full Migration (2 hours):**
Everything in Standard, plus MCP servers wrapping Kali tools, Hooks for automated safety checks, and full memory import from kali-claw's existing memory files.

**Recommendation:** Start with Approach 1 to verify everything works, then upgrade to Approach 2 or 3 based on your needs.

---

## 2. Environment Setup

### 2.1 Install Claude Code

```bash
# macOS / Linux
npm install -g @anthropic-ai/claude-code

# Verify installation
claude --version
```

**Prerequisites:**

- Node.js >= 18 (check with `node --version`)
- An Anthropic API key or Claude Pro/Max subscription
- Git (for cloning the repository)

**Troubleshooting:**

- **Permission error:** Use `sudo npm install -g @anthropic-ai/claude-code` on Linux
- **Node.js too old:** Install via nvm: `curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash && nvm install --lts`
- **npm not found:** Install Node.js first from https://nodejs.org/

### 2.2 Prepare Kali Linux Environment

You need access to a Kali Linux environment for security tool execution. Choose one of the following options:

**Option A: Kali Linux native (recommended for security work)**

```bash
# On Kali Linux, verify tool availability
nmap --version
sqlmap --version
nikto -Version
```

**Option B: Remote Kali via SSH**

Run Claude Code on your regular machine (macOS, Windows, Linux) and execute security tools on a remote Kali machine via SSH.

```bash
# Set up SSH key authentication
ssh-keygen -t ed25519 -C "kali-claw"
ssh-copy-id user@kali-host

# Verify connectivity and tool availability
ssh user@kali-host "nmap --version"
ssh user@kali-host "sqlmap --version"
```

When using remote Kali, Claude Code will prefix commands with `ssh user@kali-host`.

**Option C: Docker container**

```bash
# Pull and run Kali Linux in Docker
docker pull kalilinux/kali-rolling
docker run -it --name kali-claw-env kalilinux/kali-rolling /bin/bash

# Inside the container, install security tools
apt update && apt install -y nmap sqlmap nikto hydra metasploit-framework
```

### 2.3 Clone kali-claw

```bash
# Clone the repository (English version)
git clone https://github.com/brucesongs/kali-claw.git kali-claw-en
cd kali-claw-en

# Verify the clone
ls -la
# You should see: SOUL.md, AGENTS.md, USER.md, IDENTITY.md,
# HEARTBEAT.md, TOOLS.md, skills/, memory/, chronicle/, etc.
```

### 2.4 Environment Checklist

Before proceeding, confirm the following:

- [ ] Claude Code installed (`claude --version` succeeds)
- [ ] kali-claw repository cloned
- [ ] Kali Linux accessible (local, SSH, or Docker)
- [ ] Basic Kali tools work (`nmap --version` returns successfully)

---

## 3. Approach 1: Minimal Migration (5 Minutes)

### 3.1 Open the Project Directly

```bash
cd /path/to/kali-claw-en
claude
```

Claude Code starts and automatically reads `CLAUDE.md` as project-level instructions. This gives Claude basic context about the kali-claw workspace: what it is, how skills are organized, and the file naming conventions.

### 3.2 Start Using

No configuration needed. Just talk to Claude and reference skill files directly. Claude can read any file in the project using the Read tool.

**Dialog example -- SQL injection analysis:**

```
You: Read skills/web-sqli/SKILL.md, then help me analyze a SQL injection
     vulnerability on http://testsite.com/page?id=1

Claude: [Reads skills/web-sqli/SKILL.md]
        Based on the SQL injection methodology, let's start with detection:

        Step 1: Test for injection point
        The id parameter might be vulnerable. Let's test:
        - Normal: http://testsite.com/page?id=1
        - With quote: http://testsite.com/page?id=1'

        Would you like me to run curl commands to test this?
```

**Dialog example -- Payload lookup:**

```
You: Check skills/web-sqli/payloads.md for a UNION injection payload
     targeting MySQL with 5 columns

Claude: [Reads skills/web-sqli/payloads.md]
        Here is the appropriate UNION injection payload:

        ' UNION SELECT 1,2,3,4,5-- -

        Variations for different scenarios:
        - With string closure: ' UNION SELECT 1,2,3,4,5-- -
        - With integer injection: UNION SELECT 1,2,3,4,5-- -
        - With comment bypass: '/*!UNION*/ /*!SELECT*/ 1,2,3,4,5-- -
```

**Dialog example -- Test case execution:**

```
You: Follow skills/web-sqli/test-cases.md TC-S001 to test the target

Claude: [Reads skills/web-sqli/test-cases.md]
        Executing test case TC-S001: SQL Injection Detection

        Preconditions: Target URL with parameter-based input
        Target: http://testsite.com/page?id=1

        Step 1: Single quote test
        Step 2: Numeric boolean test (AND 1=1 vs AND 1=2)
        Step 3: Comment character test (-- -, #, /*)
        Step 4: Determine closure method

        Shall I begin executing these steps?
```

### 3.3 Limitations of Minimal Migration

The minimal approach works but has drawbacks:

- **Manual referencing** -- You must specify file paths like `skills/web-sqli/SKILL.md` each time
- **No persistent memory** -- Claude forgets context when the session closes (unless you explicitly save to Claude Code memory)
- **No automated agents** -- Skills are not available as invocable agents; you must describe what you want
- **No tool integration** -- Kali tools are not callable as MCP functions; you must use Bash commands manually

**When to use this approach:** Quick testing, evaluating whether kali-claw skills are useful for your workflow, or one-off security tasks.

---

## 4. Approach 2: Standard Migration (30 Minutes)

### 4.1 Configure CLAUDE.md (Project Instructions)

Edit the kali-claw project's `CLAUDE.md` to include kali-claw's behavioral guidelines and skill index. This makes Claude automatically adopt the penetration testing agent persona.

Replace (or extend) the existing `CLAUDE.md` with the following content:

```markdown
# CLAUDE.md

## Project Overview

kali-claw is an AI-powered penetration testing workspace with 49 security skill
domains and 518 Kali Linux tool references. This workspace is a structured
Markdown knowledge base, not a traditional software project.

## Agent Role

You are a senior penetration testing engineer -- a security specialist with
deep knowledge of Kali Linux tools and offensive/defensive security methodology.

## 12 Hacker Laws

Follow these principles in every task:

1. **First Principles Thinking** -- Break problems down to fundamental facts.
   Question every assumption.
2. **Divergent Thinking First** -- Consider at least 3 solutions before choosing.
3. **Minimize Attack Surface** -- Less exposure means less risk.
4. **Defense in Depth** -- Never rely on a single layer of defense.
5. **Least Privilege** -- Grant only necessary access.
6. **Assume Breach** -- Design assuming the attacker is already inside.
7. **Obscurity Is Not Security** -- Security comes from design, not hiding.
8. **Trust but Verify** -- Verify all inputs and outputs.
9. **Information Wants to Be Free** -- Share knowledge, protect sensitive data.
10. **Skill Over Credentials** -- Judge by capability, not title.
11. **The Weakest Link Is Human** -- Always consider the human factor.
12. **Murphy's Security Law** -- If it can be exploited, it will be.

## Skill Index

49 security skill domains are available under skills/. Each domain contains:
- SKILL.md -- Methodology, tools, and use cases
- payloads.md -- Attack payloads organized by category
- test-cases.md -- Structured test case templates (TC-SXXX format)
- guides/ -- Deep-dive learning materials

### Attack Skills
- skills/web-sqli/ -- SQL injection (UNION, Error, Blind, Double Query, WAF bypass)
- skills/web-xss/ -- Cross-site scripting (Reflected, Stored, DOM-based)
- skills/web-ssrf/ -- Server-Side Request Forgery
- skills/web-auth-bypass/ -- Authentication bypass techniques
- skills/web-access-control/ -- Access control testing
- skills/network-pentest/ -- Network penetration testing (nmap, MITM, sniffing)
- skills/password-attack/ -- Dictionary attacks, brute force, hash cracking
- skills/post-exploitation/ -- Persistence, lateral movement, privilege escalation
- skills/wifi-pentest/ -- WiFi cracking, WPS attacks, wireless sniffing
- skills/api-security/ -- REST/GraphQL API security testing
- skills/crypto-attacks/ -- Cryptographic vulnerability exploitation
- skills/binary-reverse/ -- Binary analysis and exploit development
- skills/hardware-security/ -- JTAG/UART, firmware extraction, side-channel

### Defense Skills
- skills/security-review/ -- OWASP audit, secrets detection, injection testing
- skills/verification-loop/ -- Exploit confirmation, false-positive elimination
- skills/docker-patterns/ -- Lab environments, vulnerable containers
- skills/safety-guard/ -- Scope enforcement, rate limiting
- skills/logging-monitoring/ -- Security logging and monitoring
- skills/security-misconfiguration/ -- Configuration security assessment
- skills/vulnerability-assessment/ -- Systematic vulnerability scanning

### Knowledge Skills
- skills/osint/ -- Open source intelligence gathering
- skills/recon-osint/ -- DNS enumeration, subdomain discovery
- skills/deep-research/ -- Multi-source intelligence synthesis
- skills/search-first/ -- Exploit and vulnerability search
- skills/exa-search/ -- Semantic web search for security research
- skills/repo-scan/ -- Codebase security surface classification
- skills/data-scraper-agent/ -- Structured data collection, CVE scraping

### Meta Skills
- skills/autonomous-loops/ -- Sequential pipeline, watch loop, batch processing
- skills/multi-agent-collaboration/ -- Task decomposition, parallel execution
- skills/council/ -- Multi-perspective analysis (attacker/defender/auditor)
- skills/chronicle/ -- Session logging, milestone tracking
- skills/continuous-learning/ -- Tool mastery progression

### Infrastructure
- skills/terminal-ops/ -- Command-line pentest operations
- skills/knowledge-ops/ -- Knowledge graph management
- skills/codebase-onboarding/ -- Rapid codebase intelligence
- skills/article-writing/ -- Security content and report creation
- skills/browser-qa/ -- Automated browser testing
- skills/mcp-server-patterns/ -- Security tool MCP server design
- skills/ai-fuzzing/ -- Coverage-guided fuzzing, automated vuln discovery
- skills/ai-security/ -- LLM security, prompt injection, adversarial inputs
- skills/supply-chain-security/ -- Dependency security, CI/CD pipeline attacks
- skills/container-security/ -- Container and Kubernetes security
- skills/cloud-security/ -- AWS/Azure/GCP security assessment
- skills/mobile-security/ -- Android/iOS security testing
- skills/digital-forensics/ -- Disk, memory, and network forensics
- skills/social-engineering/ -- Phishing, pretexting, security awareness
- skills/social-intelligence/ -- Social platform OSINT, sentiment analysis
- skills/insecure-design/ -- Security design flaw identification

## Security Boundaries

- Only test systems you have explicit authorization to test
- Never store real credentials or API keys in project files
- Log all security-relevant actions to memory/
- Verify scope before executing any attack commands
- Report vulnerabilities through responsible disclosure channels

## File Reference

- SOUL.md -- Agent identity and behavioral guidelines
- USER.md -- User profile and interaction preferences
- IDENTITY.md -- Skill tags table and personality traits
- MEMORY.md -- Long-term distilled knowledge
- TOOLS.md -- 518 Kali tool inventory and learning progress
- HEARTBEAT.md -- Automated health check definitions
```

### 4.2 Create Custom Agents

The most powerful migration step: convert each security skill domain into a Claude Code custom agent. Custom agents are Markdown files in `~/.claude/agents/` that Claude can invoke automatically based on task descriptions.

**Agent file format:**

```
~/.claude/agents/<agent-name>.md
```

Each agent file contains a YAML frontmatter block (name, description, tools) followed by Markdown instructions.

**Example -- web-sqli-analyzer agent:**

Create the file `~/.claude/agents/web-sqli-analyzer.md`:

```markdown
---
name: web-sqli-analyzer
description: SQL injection vulnerability detection, analysis, and exploitation specialist. Covers UNION, Error-based, Blind, Double Query, Stacked Queries, and WAF bypass techniques for MySQL, PostgreSQL, MSSQL, and Oracle.
tools:
  - Bash
  - Read
  - Write
  - Grep
  - Glob
---

You are a SQL injection security specialist. Your job is to detect, analyze,
and exploit SQL injection vulnerabilities following the kali-claw methodology.

## Knowledge Base

Read these files for reference material:
- skills/web-sqli/SKILL.md -- Full methodology, tools, and attack chain
- skills/web-sqli/payloads.md -- Payloads organized by injection type
- skills/web-sqli/test-cases.md -- Structured test cases (TC-S001 through TC-S012)
- skills/web-sqli/guides/ -- Deep-dive guides (double query, cross-database)

## Methodology

Always follow this attack chain:

1. **Detection** -- Test for injection points using single quotes, numeric
   boolean tests, and comment characters. Determine closure method.
2. **Fingerprinting** -- Determine column count (ORDER BY), identify database
   type (@@version, version()), confirm injection type (echo/error/blind).
3. **Exploitation** -- Choose technique based on type:
   - Echo: UNION-based injection
   - Error: extractvalue(), updatexml(), floor()+rand()+group by
   - Boolean blind: Length comparison and binary search
   - Time blind: SLEEP()/BENCHMARK() with conditional logic
   - Double query: Subquery with error-based data extraction
4. **Data Extraction** -- Enumerate databases, tables, columns, and data.
5. **Post-exploitation** -- File read/write if privileges allow.

## Instructions

1. Always read skills/web-sqli/SKILL.md first to load the full methodology.
2. For payload construction, read skills/web-sqli/payloads.md and select
   the appropriate category.
3. For structured testing, follow test cases from skills/web-sqli/test-cases.md.
4. Document all findings with severity ratings and remediation steps.
5. For cross-database targets, read skills/web-sqli/sqli-cross-db-guide.md.
6. For double query techniques, read skills/web-sqli/sqli-double-query-guide.md.

## Output Format

For each finding, provide:
- Injection point URL/parameter
- Injection type classification
- Payload used
- Data extracted (if any)
- Severity (Critical/High/Medium/Low)
- Remediation recommendation

## Safety

- Only test targets you have explicit authorization to test.
- Never modify or delete data in the target database without permission.
- Log all commands and results for the audit trail.
```

**Example -- network-scanner agent:**

Create the file `~/.claude/agents/network-scanner.md`:

```markdown
---
name: network-scanner
description: Network penetration testing specialist covering reconnaissance, port scanning, service fingerprinting, vulnerability assessment, MITM attacks, and traffic analysis using nmap, tcpdump, bettercap, and other network tools.
tools:
  - Bash
  - Read
  - Write
  - Grep
  - Glob
---

You are a network penetration testing specialist. Follow the kali-claw
methodology for network security assessment.

## Knowledge Base

Read these files for reference:
- skills/network-pentest/SKILL.md -- Full methodology and tool reference
- skills/network-pentest/payloads.md -- Network attack payloads by category
- skills/network-pentest/test-cases.md -- Structured test cases

## Methodology

Follow this attack chain:

1. **Host Discovery** -- Identify live hosts on the target network.
   Tools: arp-scan, nmap -sn, fping
2. **Port Scanning** -- Enumerate open ports and services.
   Tools: nmap -sV -sC -p-
3. **Service Fingerprinting** -- Identify service versions and OS.
   Tools: nmap -O -sV, banner grabbing
4. **Vulnerability Assessment** -- Identify known vulnerabilities.
   Tools: nmap --script vuln, nikto
5. **MITM Testing** -- Test for ARP spoofing, DNS spoofing resistance.
   Tools: bettercap, arpspoof, mitmproxy
6. **Traffic Analysis** -- Capture and analyze network traffic.
   Tools: tcpdump, tshark

## Instructions

1. Always read skills/network-pentest/SKILL.md first.
2. Use payloads from skills/network-pentest/payloads.md.
3. Follow test cases from skills/network-pentest/test-cases.md.
4. Document all findings with network diagrams where applicable.

## Safety

- Only scan networks you have authorization to test.
- Be mindful of scan intensity -- use rate limiting on production networks.
- Log all scan activities for audit compliance.
```

**Creating additional agents:**

Follow the same pattern for other skill domains. Key agents to create:

| Agent File | Skill Domain | Description |
|-----------|-------------|-------------|
| `web-sqli-analyzer.md` | web-sqli | SQL injection specialist |
| `web-xss-analyzer.md` | web-xss | Cross-site scripting specialist |
| `network-scanner.md` | network-pentest | Network penetration testing |
| `osint-researcher.md` | osint + recon-osint | Open source intelligence |
| `security-auditor.md` | security-review | OWASP audit specialist |
| `password-cracker.md` | password-attack | Password attack specialist |
| `post-exploit.md` | post-exploitation | Post-exploitation operations |
| `api-tester.md` | api-security | API security testing |
| `cloud-auditor.md` | cloud-security | Cloud security assessment |

Create the agents directory and add agent files:

```bash
# Create the agents directory
mkdir -p ~/.claude/agents

# Create agent files (example for web-sqli)
cat > ~/.claude/agents/web-sqli-analyzer.md << 'AGENT_EOF'
[paste the agent content above]
AGENT_EOF
```

### 4.3 Create Rule Files

Convert kali-claw security guidelines into Claude Code rule files. Rules apply to all sessions and cannot be overridden by the agent.

**Create security rules:**

Create the file `~/.claude/rules/kali-claw-security.md`:

```markdown
# kali-claw Security Rules

## Scope Enforcement

- Before executing ANY security tool command, verify the target is within
  the authorized scope.
- If no scope has been defined for the current session, ask the user to
  define it before proceeding with any active security testing.

## Data Protection

- Never store real credentials, API keys, or tokens in project files.
- Redact sensitive data (passwords, hashes, PII) in reports unless
  explicitly requested.
- Use environment variables or secret managers for any authentication
  material needed during testing.

## Responsible Testing

- Only execute attack commands against targets you have explicit written
  authorization to test.
- Prefer non-destructive testing techniques unless destructive testing
  is specifically authorized.
- Maintain an audit log of all security-related commands executed.

## Reporting

- Document all findings with severity ratings (Critical/High/Medium/Low).
- Provide remediation recommendations for every finding.
- Follow responsible disclosure timelines for any vulnerabilities discovered.
```

### 4.4 Configure the Memory System

Map kali-claw's memory hierarchy to Claude Code's persistent memory.

**Understanding the mapping:**

| kali-claw Memory | Claude Code Memory | Location |
|-----------------|-------------------|----------|
| `memory/YYYY-MM-DD.md` | Session notes | `~/.claude/projects/<project>/memory/` |
| `MEMORY.md` (root) | Long-term notes | `~/.claude/projects/<project>/memory/MEMORY.md` |
| `chronicle/YYYY-MM/*.md` | Persistent summaries | `~/.claude/projects/<project>/memory/chronicle/` |

**Import existing memory:**

```bash
# Find the Claude Code project memory directory
# The path is based on your project's absolute path
PROJECT_DIR=$(pwd | tr '/' '-')
MEMORY_DIR="$HOME/.claude/projects/$PROJECT_DIR/memory"

# Create the memory directory
mkdir -p "$MEMORY_DIR"

# Copy kali-claw's long-term memory
cp MEMORY.md "$MEMORY_DIR/MEMORY.md"

# Copy daily logs (optional -- copy recent ones)
cp memory/*.md "$MEMORY_DIR/" 2>/dev/null

# Copy chronicles (optional)
mkdir -p "$MEMORY_DIR/chronicle"
cp -r chronicle/* "$MEMORY_DIR/chronicle/" 2>/dev/null
```

**Using memory in sessions:**

Claude Code's memory persists automatically. To save important findings during a session:

```
You: Save this finding to memory: Found SQL injection in /api/users endpoint,
     UNION-based, 5 columns, MySQL 8.0 backend.

Claude: [Writes to memory file]
        Finding saved. This will persist across sessions.
```

To recall memory in a new session:

```
You: What SQL injection findings do we have from previous sessions?

Claude: [Reads memory files]
        From previous sessions:
        - SQL injection in /api/users (UNION-based, MySQL 8.0)
        - ...
```

### 4.5 Using Custom Agents in Sessions

Once agents are configured, start a session and invoke them naturally:

```bash
cd /path/to/kali-claw-en
claude
```

**Automatic agent invocation:**

```
You: Scan 192.168.1.0/24 for open ports and services

Claude: [Automatically invokes network-scanner agent]
        [Reads skills/network-pentest/SKILL.md]
        [Reads skills/network-pentest/payloads.md]

        Starting network scan on 192.168.1.0/24...

        $ nmap -sV -sC 192.168.1.0/24

        Results:
        192.168.1.1   (gateway)    ports: 22, 80, 443
        192.168.1.50  (web server) ports: 80, 3306
        192.168.1.100 (workstation) ports: 22, 3389

        Shall I run a vulnerability scan on the web server?
```

**Explicit agent invocation:**

```
You: Use the web-sqli-analyzer agent to test http://testsite.com/page?id=1

Claude: [Invokes web-sqli-analyzer agent]
        [Reads skills/web-sqli/SKILL.md]
        [Reads skills/web-sqli/payloads.md]

        Starting SQL injection analysis on the target...
```

### 4.6 Standard Migration Checklist

- [ ] CLAUDE.md updated with kali-claw agent role and skill index
- [ ] Agent files created in `~/.claude/agents/`
- [ ] Security rules created in `~/.claude/rules/`
- [ ] Memory directory configured and existing memory imported
- [ ] Tested by starting a session and invoking a custom agent

---

## 5. Approach 3: Full Migration (2 Hours)

### 5.1 MCP Server Integration

MCP (Model Context Protocol) servers allow Claude Code to call Kali security tools as native functions. Instead of running `nmap` via Bash and parsing raw output, Claude calls `nmap_scan` with structured parameters and receives structured results.

**Example -- nmap MCP server (Python):**

Create the file `/path/to/kali-mcp-servers/nmap_server.py`:

```python
#!/usr/bin/env python3
"""nmap MCP server for Claude Code integration."""

import subprocess
import json
import re

from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("kali-nmap")


def validate_target(target: str) -> bool:
    """Validate that the target is a legitimate IP or hostname."""
    if ";" in target or "|" in target or "&" in target:
        return False
    if ".." in target:
        return False
    return True


def parse_nmap_output(output: str) -> dict:
    """Parse nmap output into structured JSON."""
    hosts = []
    current_host = None

    for line in output.split("\n"):
        host_match = re.match(
            r"Nmap scan report for (?:.+?\()?([\d.]+)(?:\))?", line
        )
        if host_match:
            if current_host:
                hosts.append(current_host)
            current_host = {
                "ip": host_match.group(1),
                "ports": [],
                "status": "up",
            }
            continue

        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(.*)", line
        )
        if port_match and current_host:
            current_host["ports"].append(
                {
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4).strip(),
                }
            )

    if current_host:
        hosts.append(current_host)

    return {"hosts": hosts, "total_hosts": len(hosts)}


@server.list_tools()
async def list_tools():
    return [
        {
            "name": "nmap_scan",
            "description": (
                "Run nmap network scan on a target. Supports host discovery, "
                "port scanning, service detection, and OS fingerprinting. "
                "Use ONLY on targets you have authorization to scan."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target IP, hostname, or CIDR range "
                            "(e.g., '192.168.1.1' or '192.168.1.0/24')"
                        ),
                    },
                    "ports": {
                        "type": "string",
                        "description": (
                            "Port range to scan (default: '1-1000')"
                        ),
                        "default": "1-1000",
                    },
                    "scan_type": {
                        "type": "string",
                        "description": (
                            "Scan type: '-sV' (service), '-sC' (default scripts), "
                            "'-O' (OS detect), '-sV -sC -O' (full)"
                        ),
                        "default": "-sV",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 300)",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        },
        {
            "name": "nmap_vuln_scan",
            "description": (
                "Run nmap vulnerability scan using the vuln script category. "
                "Scans for known vulnerabilities in discovered services. "
                "Use ONLY on targets you have authorization to scan."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname",
                    },
                    "ports": {
                        "type": "string",
                        "description": (
                            "Specific ports to scan (default: all common)"
                        ),
                        "default": "",
                    },
                },
                "required": ["target"],
            },
        },
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "nmap_scan":
        target = arguments.get("target", "")
        ports = arguments.get("ports", "1-1000")
        scan_type = arguments.get("scan_type", "-sV")
        timeout = arguments.get("timeout", 300)

        if not validate_target(target):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {"error": "Invalid target format"}
                        ),
                    }
                ]
            }

        cmd = ["nmap", scan_type, "-p", ports, target]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            parsed = parse_nmap_output(result.stdout)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(parsed, indent=2),
                    }
                ]
            }
        except subprocess.TimeoutExpired:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {"error": f"Scan timed out after {timeout}s"}
                        ),
                    }
                ]
            }
        except FileNotFoundError:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {"error": "nmap not found. Install: apt install nmap"}
                        ),
                    }
                ]
            }

    elif name == "nmap_vuln_scan":
        target = arguments.get("target", "")
        ports = arguments.get("ports", "")

        if not validate_target(target):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {"error": "Invalid target format"}
                        ),
                    }
                ]
            }

        cmd = ["nmap", "--script", "vuln", target]
        if ports:
            cmd.extend(["-p", ports])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            parsed = parse_nmap_output(result.stdout)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(parsed, indent=2),
                    }
                ]
            }
        except subprocess.TimeoutExpired:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {"error": "Vuln scan timed out after 600s"}
                        ),
                    }
                ]
            }


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

**Configure MCP servers in Claude Code:**

Create or edit the project-level `.mcp.json` file in the kali-claw root directory:

```json
{
  "mcpServers": {
    "kali-nmap": {
      "command": "python3",
      "args": ["/path/to/kali-mcp-servers/nmap_server.py"]
    },
    "kali-sqlmap": {
      "command": "python3",
      "args": ["/path/to/kali-mcp-servers/sqlmap_server.py"]
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
      "args": ["/absolute/path/to/kali-mcp-servers/nmap_server.py"]
    }
  }
}
```

**Using MCP tools in sessions:**

Once configured, Claude can call these tools directly:

```
You: Scan 192.168.1.0/24 for open ports and services

Claude: [Calls nmap_scan MCP tool with target="192.168.1.0/24",
         scan_type="-sV -sC", ports="1-65535"]

        Found 3 hosts:
        - 192.168.1.1   open ports: 22/tcp (ssh), 80/tcp (http nginx)
        - 192.168.1.50  open ports: 80/tcp (http apache), 3306/tcp (mysql)
        - 192.168.1.100 open ports: 22/tcp (ssh), 3389/tcp (ms-wbt-server)
```

**MCP server setup checklist:**

```bash
# 1. Install the MCP Python package
pip install mcp

# 2. Create the MCP servers directory
mkdir -p /path/to/kali-mcp-servers

# 3. Create MCP server scripts (see example above)

# 4. Make scripts executable
chmod +x /path/to/kali-mcp-servers/*.py

# 5. Test a server independently
echo '{"jsonrpc":"2.0","method":"initialize","id":1}' | \
  python3 /path/to/kali-mcp-servers/nmap_server.py

# 6. Add to .mcp.json in the project root
# 7. Restart Claude Code to pick up the new MCP servers
```

### 5.2 Configure Hooks (Automation)

Claude Code Hooks are shell commands that run before or after tool calls. Use them to implement automated safety checks, similar to kali-claw's HEARTBEAT.md system.

**Example -- scope check hook:**

Create the file `/path/to/kali-hooks/check-scope.sh`:

```bash
#!/bin/bash
# PreToolUse hook: verify that security commands target authorized scope

TOOL_NAME="$1"
INPUT="$2"

# Only check Bash tool calls that contain security tools
if [ "$TOOL_NAME" != "Bash" ]; then
    exit 0
fi

# List of security tools that require scope verification
SECURITY_TOOLS="nmap|sqlmap|nikto|hydra|metasploit|msfconsole|burpsuite|dirb|gobuster|nuclei|wpscan"

# Check if the command contains a security tool
if echo "$INPUT" | grep -qE "$SECURITY_TOOLS"; then
    # Check if scope file exists and target is in scope
    SCOPE_FILE="/path/to/kali-claw-en/memory/scope.txt"

    if [ ! -f "$SCOPE_FILE" ]; then
        echo "WARNING: No scope file found. Create memory/scope.txt with authorized targets."
        exit 0  # Allow but warn
    fi

    echo "Security tool detected. Scope file exists. Proceeding."
fi

exit 0
```

**Example -- logging hook:**

Create the file `/path/to/kali-hooks/log-command.sh`:

```bash
#!/bin/bash
# PostToolUse hook: log all security-related commands

TOOL_NAME="$1"
INPUT="$2"
OUTPUT="$3"

LOG_FILE="/path/to/kali-claw-en/memory/command-log-$(date +%Y-%m-%d).md"

if [ "$TOOL_NAME" = "Bash" ]; then
    # Only log commands that contain security tools
    SECURITY_TOOLS="nmap|sqlmap|nikto|hydra|nuclei|curl|dig|whois"
    if echo "$INPUT" | grep -qE "$SECURITY_TOOLS"; then
        echo "## $(date '+%H:%M:%S')" >> "$LOG_FILE"
        echo "Command: $INPUT" >> "$LOG_FILE"
        echo "Output preview: $(echo "$OUTPUT" | head -5)" >> "$LOG_FILE"
        echo "" >> "$LOG_FILE"
    fi
fi

exit 0
```

**Configure hooks in `~/.claude/settings.json`:**

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "command": "/path/to/kali-hooks/check-scope.sh"
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "command": "/path/to/kali-hooks/log-command.sh"
      }
    ]
  }
}
```

**Make hooks executable:**

```bash
chmod +x /path/to/kali-hooks/*.sh
```

### 5.3 Complete Project Structure

After a full migration, the project structure looks like this:

```
kali-claw-en/                         # Git repository (unchanged)
+-- CLAUDE.md                         # Project instructions (from SOUL.md + AGENTS.md)
+-- .mcp.json                         # MCP server configuration
+-- skills/                           # Original skill files (kept as-is)
|    +-- web-sqli/
|    |    +-- SKILL.md
|    |    +-- payloads.md
|    |    +-- test-cases.md
|    |    +-- guides/
|    +-- network-pentest/
|    +-- osint/
|    +-- ... (46 more domains)
+-- memory/                           # Daily logs (unchanged)
+-- chronicle/                        # Monthly milestones (unchanged)
+-- SOUL.md                           # Original (kept as reference)
+-- USER.md                           # Original (kept as reference)
+-- AGENTS.md                         # Original (kept as reference)
+-- IDENTITY.md                       # Original (kept as reference)
+-- MEMORY.md                         # Original (kept as reference)
+-- TOOLS.md                          # Original (unchanged)
+-- HEARTBEAT.md                      # Original (kept as reference)

~/.claude/
+-- agents/                           # Custom agents (converted from skills/)
|    +-- web-sqli-analyzer.md
|    +-- web-xss-analyzer.md
|    +-- network-scanner.md
|    +-- osint-researcher.md
|    +-- security-auditor.md
|    +-- password-cracker.md
|    +-- post-exploit.md
|    +-- api-tester.md
|    +-- cloud-auditor.md
|    +-- ... (more agent files)
+-- rules/                            # Security rules
|    +-- kali-claw-security.md
+-- settings.json                     # Hooks configuration
+-- projects/                         # Project-specific memory
|    +-- <project-hash>/
|         +-- memory/
|              +-- MEMORY.md          # Imported long-term memory
|              +-- chronicle/         # Imported chronicles

/path/to/kali-mcp-servers/           # MCP server scripts
+-- nmap_server.py
+-- sqlmap_server.py
+-- ... (more MCP servers)

/path/to/kali-hooks/                  # Hook scripts
+-- check-scope.sh
+-- log-command.sh
```

**Key point:** The original kali-claw files (`SOUL.md`, `AGENTS.md`, `skills/`, etc.) remain in the repository. They serve as reference material that agents read at runtime. Claude Code's configuration (`~/.claude/`) references these files.

### 5.4 Full Migration Checklist

- [ ] All Standard Migration steps completed
- [ ] MCP Python package installed (`pip install mcp`)
- [ ] nmap MCP server created and tested
- [ ] Additional MCP servers created as needed
- [ ] `.mcp.json` configured in project root
- [ ] Hook scripts created and made executable
- [ ] Hooks configured in `~/.claude/settings.json`
- [ ] End-to-end test: open project, invoke agent, call MCP tool, verify logging

---

## 6. Usage Scenarios

### 6.1 Complete Penetration Test Flow

A multi-turn dialog showing how to execute a full penetration test using Claude Code with kali-claw skills:

**Step 1 -- Define scope:**

```
You: I need to perform a penetration test on target.com. This is an authorized
     engagement with scope covering *.target.com web applications and
     93.184.216.0/24 network infrastructure.

Claude: Scope acknowledged. Let me load the relevant skills.

        [Reads skills/recon-osint/SKILL.md]
        [Reads skills/network-pentest/SKILL.md]

        I'll follow a structured methodology:
        1. OSINT reconnaissance on target.com
        2. Network scan of 93.184.216.0/24
        3. Web application testing on discovered hosts
        4. Vulnerability exploitation
        5. Post-exploitation assessment
        6. Report generation

        Starting with Phase 1: OSINT reconnaissance.
```

**Step 2 -- Reconnaissance:**

```
Claude: [Invokes osint-researcher agent]
        [Reads skills/osint/SKILL.md and skills/recon-osint/SKILL.md]

        Phase 1: OSINT Reconnaissance

        DNS Records:
        - A     : target.com -> 93.184.216.34
        - MX    : mail.target.com
        - NS    : ns1.target.com, ns2.target.com

        Subdomains (via crt.sh + dnsenum):
        - www.target.com (93.184.216.34)
        - api.target.com (93.184.216.35)
        - admin.target.com (93.184.216.36)
        - dev.target.com (93.184.216.37) -- returns 403

        Technologies:
        - nginx/1.18.0, PHP 8.1, MySQL (inferred)

        Proceeding to Phase 2: Network scanning.
```

**Step 3 -- Network scanning (using MCP):**

```
Claude: [Calls nmap_scan MCP tool]
        target: 93.184.216.0/24, scan_type: -sV -sC

        Network Scan Results:

        Host: 93.184.216.34 (www.target.com)
          80/tcp  open  http    nginx/1.18.0
          443/tcp open  https   TLS 1.2

        Host: 93.184.216.35 (api.target.com)
          8080/tcp open  http    Node.js Express
          5432/tcp filtered postgresql

        Host: 93.184.216.36 (admin.target.com)
          80/tcp   open  http    Apache Tomcat 9.0.50
          8080/tcp open  http    Tomcat Manager (401)

        Notable findings:
        1. Tomcat Manager on admin.target.com:8080 -- may have default creds
        2. PostgreSQL port filtered but responding on api.target.com
        3. dev.target.com:80 returning 403 -- worth investigating
```

**Step 4 -- Web application testing:**

```
You: Test the web applications for vulnerabilities

Claude: [Invokes web-sqli-analyzer + web-xss-analyzer + security-auditor agents]
        [Reads skills/web-sqli/SKILL.md, skills/web-xss/SKILL.md]

        Testing web applications...

        www.target.com:
        - No SQL injection in search parameter
        - Reflected XSS in error page (parameter: q) -- Medium
        - Missing security headers (CSP, X-Frame-Options) -- Low

        api.target.com:8080:
        - SQL injection in /api/users?id= parameter -- Critical
          Type: UNION-based, 5 columns, MySQL 8.0
          Payload: ' UNION SELECT 1,2,3,4,5-- -
          Data extracted: database() = 'production_db'
        - No rate limiting on API endpoints -- High
        - CORS allows all origins (*) -- Medium

        admin.target.com:8080:
        - Tomcat Manager default credentials: tomcat:s3cret -- Critical
        - WAR file deployment enabled (RCE possible) -- Critical
```

**Step 5 -- Post-exploitation:**

```
You: I got a shell through Tomcat. What's next?

Claude: [Invokes post-exploit agent]
        [Reads skills/post-exploitation/SKILL.md]

        Post-exploitation checklist:

        1. Stabilize shell:
           $ python3 -c 'import pty; pty.spawn("/bin/bash")'
           $ export TERM=xterm

        2. Gather system info:
           $ whoami && id
           $ hostname && uname -a

        3. Privilege escalation vectors:
           $ sudo -l
           $ find / -perm -4000 -type f 2>/dev/null
           $ cat /etc/crontab

        4. Network pivot enumeration:
           $ ss -tulpn
           $ cat /etc/hosts
           $ arp -a

        Safety reminder: This is an authorized engagement.
        Document every action for the final report.
```

**Step 6 -- Report generation:**

```
You: Generate the final penetration test report

Claude: [Invokes article-writing agent]
        [Reads skills/article-writing/SKILL.md]

        Generating comprehensive report...

        Report saved to memory/2026-05-18-pentest-target-com.md

        Executive Summary:
        - 3 Critical findings
        - 2 High findings
        - 3 Medium findings
        - 1 Low finding

        Critical findings require immediate remediation.
        Full report includes CVSS scores, proof of concept,
        and remediation steps for each finding.
```

### 6.2 Security Audit

Using custom agents for an OWASP Top 10 audit:

```
You: Perform an OWASP Top 10 security audit on http://testphp.vulnweb.com

Claude: [Invokes security-auditor agent]
        [Reads skills/security-review/SKILL.md]
        [Reads skills/web-sqli/payloads.md, skills/web-xss/payloads.md]

        Running systematic OWASP Top 10 audit...

        A01 - Broken Access Control:
        - IDOR on /user.php?id= -- can access other users' data
        - Admin panel accessible without authentication at /admin/

        A02 - Cryptographic Failures:
        - Login form submits over HTTP (not HTTPS)
        - Password stored as MD5 hash (weak, should use bcrypt)

        A03 - Injection:
        - SQL Injection on search parameter (UNION-based)
        - Reflected XSS in search results (no output encoding)

        A04 - Insecure Design:
        - No rate limiting on login endpoint
        - Password reset token sent via URL (not one-time)

        A05 - Security Misconfiguration:
        - Directory listing enabled on /uploads/
        - Error messages expose PHP version and stack traces
        - Default PHP installation with debug mode on

        A07 - Authentication Failures:
        - No brute force protection
        - Session tokens are predictable

        Summary: 2 Critical, 3 High, 4 Medium findings
        Full report with remediation recommendations available.
```

### 6.3 Learning and Research

Using kali-claw's guides and skill files for security tool learning:

```
You: I want to learn SQL injection from scratch. Guide me through it.

Claude: [Reads skills/web-sqli/SKILL.md]
        [Reads skills/web-sqli/payloads.md]
        [Reads skills/docker-patterns/SKILL.md]

        Here is your structured learning path:

        Phase 1: Theory (1-2 days)
        Read skills/web-sqli/SKILL.md for the complete methodology:
        - 5 SQLi types: UNION, Error, Boolean-blind, Time-blind, Double Query
        - Attack chain: Detection -> Fingerprinting -> Exploitation -> Extraction

        Phase 2: Lab Setup (today)
        Spin up a practice environment:
        $ docker run -d -p 8080:80 acunetix/vulnerable-web-app
        Or dedicated SQLi labs:
        $ docker run -d -p 8080:80 sqli/sqli-labs

        Phase 3: Hands-On Practice (3-5 days)
        Use payloads from skills/web-sqli/payloads.md:
        - Level 1: UNION-based injection
        - Level 2: Error-based (extractvalue/updatexml)
        - Level 3: Boolean-blind injection
        - Level 4: Time-blind injection
        - Level 5: WAF bypass techniques

        Phase 4: Structured Testing (2-3 days)
        Follow test cases in skills/web-sqli/test-cases.md (TC-S001 through TC-S012)

        Phase 5: Advanced Techniques
        - Double Query: skills/web-sqli/sqli-double-query-guide.md
        - Cross-database: skills/web-sqli/sqli-cross-db-guide.md

        Shall I set up the Docker lab now?
```

### 6.4 Report Generation

Using the article-writing skill for security reports:

```
You: Write a vulnerability disclosure report for the SQL injection finding
     on api.target.com. Include CVSS scoring.

Claude: [Reads skills/article-writing/SKILL.md]
        [Reads relevant memory files]

        Generating vulnerability disclosure report...

        # SQL Injection Vulnerability - api.target.com

        ## Vulnerability Summary
        - **Type**: UNION-based SQL Injection (CWE-89)
        - **Severity**: Critical (CVSS 3.1: 9.8)
        - **Attack Vector**: Network
        - **User Interaction**: None required
        - **Scope**: Changed
        - **Endpoint**: /api/users?id=

        ## Description
        The id parameter in the /api/users endpoint is vulnerable to
        UNION-based SQL injection. An attacker can extract the entire
        database contents including user credentials, session tokens,
        and application configuration.

        ## Proof of Concept
        Request: GET /api/users?id=1' UNION SELECT 1,2,3,4,5-- -
        Response: Returns combined data from users table and
                  information_schema.schemata

        ## Impact
        - Complete database disclosure
        - Potential credential compromise
        - Possible file read/write on database server

        ## Remediation
        1. Use parameterized queries (prepared statements)
        2. Implement input validation and whitelist allowed characters
        3. Apply least-privilege principle to database accounts
        4. Deploy WAF rules to detect SQL injection patterns

        ## Timeline
        - 2026-05-18: Vulnerability discovered
        - 2026-05-18: Vendor notified
        - [Pending]: Vendor acknowledgment
        - [Pending]: Fix deployed
```

---

## 7. FAQ

### Q1: Can Claude Code run directly on Kali Linux?

**Yes.** Claude Code runs on any system with Node.js >= 18. Install it on Kali Linux just like any other platform:

```bash
npm install -g @anthropic-ai/claude-code
claude
```

This is the simplest setup because all Kali security tools are available locally.

### Q2: MCP server won't connect. How do I troubleshoot?

**Common causes and fixes:**

```bash
# 1. Verify the MCP Python package is installed
pip show mcp
# If missing: pip install mcp

# 2. Test the server standalone
echo '{"jsonrpc":"2.0","method":"initialize","id":1}' | \
  python3 /path/to/nmap_server.py

# 3. Check file permissions
ls -la /path/to/kali-mcp-servers/*.py
# Should be executable: chmod +x /path/to/kali-mcp-servers/*.py

# 4. Verify Python path
which python3
# Use absolute path in .mcp.json configuration

# 5. Check Claude Code MCP logs
# MCP errors appear in Claude Code's output on startup
```

### Q3: Custom agents are not triggering. What's wrong?

**Check these items:**

1. Agent files must be in `~/.claude/agents/` (not in the project directory)
2. File must have a YAML frontmatter with `name` and `description`
3. The description must be relevant to the task you are describing
4. File extension must be `.md`
5. No syntax errors in the YAML frontmatter

```bash
# Verify agent files exist
ls ~/.claude/agents/

# Verify file format
head -10 ~/.claude/agents/web-sqli-analyzer.md
# Should start with: ---
#                      name: web-sqli-analyzer
#                      description: ...
```

### Q4: How do I keep kali-claw updated?

```bash
cd /path/to/kali-claw-en
git pull origin main

# If you have local modifications:
git stash
git pull origin main
git stash pop
```

Your custom agents in `~/.claude/agents/` and rules in `~/.claude/rules/` reference skill files by relative path. They do not need to be updated when kali-claw skills are updated -- they always read the latest version at runtime.

### Q5: Will Claude Code memory be lost between sessions?

**No.** Claude Code's memory files are stored on disk in `~/.claude/projects/<project>/memory/`. They persist across sessions and survive Claude Code restarts.

You can also write important findings directly to the kali-claw `memory/` directory, which is tracked by Git and can be committed for long-term preservation.

### Q6: Can I use both OpenClaw and Claude Code with the same kali-claw workspace?

**Yes.** The kali-claw workspace is just Markdown files. Both OpenClaw and Claude Code can read the same `skills/` directory. However, the configuration files differ:

- **OpenClaw** uses `SOUL.md`, `AGENTS.md`, `HEARTBEAT.md` directly
- **Claude Code** uses `CLAUDE.md`, `~/.claude/agents/`, `~/.claude/rules/`

The skill files (`SKILL.md`, `payloads.md`, `test-cases.md`, `guides/`) are shared between both runtimes without modification.

### Q7: How do I configure remote Kali access for Claude Code?

Claude Code can execute commands on remote Kali via SSH. There are three approaches:

**Approach A -- SSH prefix in commands:**

Claude uses `ssh user@host "command"` to run tools remotely:

```
You: Scan 192.168.1.0/24

Claude: $ ssh pentester@kali-server "nmap -sV 192.168.1.0/24"
```

**Approach B -- MCP server with SSH:**

The MCP server script uses SSH internally:

```python
# In the MCP server, replace local subprocess calls with SSH
cmd = ["ssh", "user@kali-server", "nmap", "-sV", target]
result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
```

**Approach C -- SSH tunnel:**

```bash
# Create an SSH tunnel to the Kali machine
ssh -L 8080:localhost:8080 user@kali-server -N -f

# Claude Code connects to localhost:8080 which tunnels to Kali
```

### Q8: How do I use Claude Code's skill system with kali-claw?

Claude Code has a skill system that can invoke registered skills via `/skill-name`. kali-claw skills can be registered as Claude Code skills by creating skill files in the appropriate format. However, the most natural integration is through custom agents (described in Section 4.2), which are automatically matched to tasks based on their descriptions.

To explicitly invoke an agent:

```
You: /web-sqli-analyzer

# Or describe the task and let Claude match the agent:
You: Analyze this URL for SQL injection: http://target.com/page?id=1
```

### Q9: The nmap/sqlmap commands are not found. What do I do?

If you are running Claude Code on a non-Kali system, security tools are not available locally. Use one of these solutions:

```bash
# Option 1: Install individual tools
# macOS (via Homebrew)
brew install nmap sqlmap nikto

# Ubuntu/Debian
sudo apt install nmap sqlmap nikto

# Option 2: Use Docker
docker run -it kalilinux/kali-rolling bash -c \
  "apt update && apt install -y nmap sqlmap && nmap -sV <target>"

# Option 3: Use remote Kali (see Q7 above)
ssh user@kali-host "nmap -sV <target>"
```

### Q10: How do I create a new skill domain in Claude Code?

Follow the same process as in the OpenClaw version, then create a corresponding agent:

```bash
# 1. Create the skill directory in the kali-claw repo
mkdir -p skills/my-new-skill/guides

# 2. Write SKILL.md, payloads.md, test-cases.md
# (Follow the pattern in existing skills)

# 3. Create a corresponding Claude Code agent
cat > ~/.claude/agents/my-new-skill.md << 'EOF'
---
name: my-new-skill
description: Description of what this skill does
tools:
  - Bash
  - Read
  - Write
---
Instructions for the agent...
Read skills/my-new-skill/SKILL.md for methodology.
EOF

# 4. Update IDENTITY.md with the new skill tag
# 5. Update TOOLS.md with related tools
```

---

## 8. Architecture Comparison and Reference

### Complete Mapping Table

| kali-claw (OpenClaw) | Claude Code Equivalent | Migration Method |
|---------------------|----------------------|-----------------|
| `SOUL.md` (identity + laws) | `CLAUDE.md` project instructions | Copy key content into CLAUDE.md |
| `USER.md` (user profile) | `~/.claude/settings` or `CLAUDE.md` user section | Manual configuration |
| `AGENTS.md` (session config) | `CLAUDE.md` + `~/.claude/rules/` | Extract session flow into rules |
| `skills/*/SKILL.md` | `~/.claude/agents/*.md` | Convert to agent files with frontmatter |
| `skills/*/payloads.md` | Project files (referenced by agents) | Keep in place, agents read at runtime |
| `skills/*/test-cases.md` | Project files (referenced by agents) | Keep in place, agents read at runtime |
| `skills/*/guides/` | Project files | Keep in place, no changes needed |
| `MEMORY.md` (long-term) | `~/.claude/projects/<proj>/memory/` | Copy content to memory directory |
| `memory/*.md` (daily logs) | `~/.claude/projects/<proj>/memory/` | Copy recent logs |
| `chronicle/` (monthly) | `~/.claude/projects/<proj>/memory/chronicle/` | Copy to memory subdirectory |
| `TOOLS.md` (tool inventory) | Project files + MCP servers | Keep as reference, convert key tools to MCP |
| `HEARTBEAT.md` (health checks) | `~/.claude/settings.json` hooks | Convert to PreToolUse/PostToolUse hooks |
| 12 Hacker Laws | `~/.claude/rules/` + `CLAUDE.md` | Extract as rule files |
| ECC orchestration patterns | Custom agent instructions | Embed in agent Markdown files |

### Feature Parity Matrix

| Feature | OpenClaw | Claude Code | Notes |
|---------|----------|-------------|-------|
| Persistent memory | Manual files | Built-in system | Claude Code memory is automatic |
| Skill invocation | Auto-matched by gateway | Auto-matched by agent description | Both use natural language matching |
| Tool execution | Gateway routes | Bash tool + MCP servers | MCP provides structured I/O |
| Behavioral rules | SOUL.md | CLAUDE.md + rules/ | Same content, different location |
| Automated tasks | HEARTBEAT.md polling | Hooks (PreToolUse/PostToolUse) | Hooks are event-driven, not polled |
| Session startup | AGENTS.md sequence | CLAUDE.md auto-read | Both load context at session start |
| Multi-agent | Council skill | Parallel agent invocation | Claude Code agents are independent |

### Migration Effort by Component

| Component | Effort | Priority | Notes |
|-----------|--------|----------|-------|
| CLAUDE.md configuration | 15 min | High | Foundation for everything else |
| 3-5 key agent files | 30 min | High | Covers most common security tasks |
| Security rules | 10 min | Medium | Important for safety |
| Memory import | 5 min | Medium | Preserves existing knowledge |
| 1-2 MCP servers | 60 min | Low | Nice-to-have for structured tool I/O |
| Hook scripts | 30 min | Low | Optional automation |
| Remaining agent files | 60 min | Low | Add as needed over time |

---

_This guide covers kali-claw v0.1.7 migration to Claude Code. For the latest updates, visit the [kali-claw repository](https://github.com/brucesongs/kali-claw). For the OpenClaw version of this guide, see [GUIDE-OPENCLAW-en.md](./GUIDE-OPENCLAW-en.md)._
