# OpenClaw + kali-claw: Complete Usage Guide

> A beginner-friendly guide to setting up and using the OpenClaw framework with the kali-claw penetration testing agent workspace.

---

## Table of Contents

1. [Understanding the Concepts](#1-understanding-the-concepts)
2. [Environment Setup](#2-environment-setup)
3. [Installation and Initialization](#3-installation-and-initialization)
4. [Core Concepts](#4-core-concepts)
5. [Usage Scenarios](#5-usage-scenarios)
6. [Advanced Configuration](#6-advanced-configuration)
7. [FAQ](#7-faq)
8. [Core File Reference](#8-core-file-reference)

---

## 1. Understanding the Concepts

### 1.1 What is OpenClaw?

OpenClaw is an AI agent runtime framework installed via npm. It provides the infrastructure for running AI agents with persistent workspaces, memory, and tool access.

**Key features:**
- **Agent management** -- `openclaw agents add/list/remove` to create and manage isolated agents
- **Isolated workspaces** -- Each agent gets its own directory for configuration, memory, and skills
- **Gateway** -- A service that connects you to your agents via chat interfaces
- **Session management** -- Agents load their identity and memory at the start of every session
- **Heartbeat polling** -- Automated periodic tasks for health checks, learning, and maintenance

**Think of it this way:** OpenClaw is the phone operating system. kali-claw is an app that runs on it. OpenClaw handles the infrastructure (routing, sessions, memory). kali-claw provides the security domain expertise (skills, payloads, tools).

### 1.2 What is kali-claw?

kali-claw is a pre-built penetration testing agent workspace for the OpenClaw framework. It is NOT a traditional software code repository -- it is a **Markdown knowledge base + configuration system**.

**What it includes:**
- **49 security skill domains** -- from OSINT and web exploitation to cloud security and AI fuzzing
- **518 Kali Linux tool knowledge base** -- mastery tracking, learning notes, usage experience
- **12 Hacker Laws** -- behavioral guidelines derived from real-world security philosophy
- **Layered memory system** -- daily logs, monthly chronicles, and long-term distilled knowledge

**How it differs from using ChatGPT or Claude directly:**
- ChatGPT/Claude have no persistent memory across sessions
- kali-claw maintains a structured memory system that grows over time
- kali-claw has 49 curated skill domains with attack payloads, test cases, and learning guides
- kali-claw can actually execute Kali Linux security tools in your environment
- kali-claw follows the 12 Hacker Laws in every interaction, not generic AI behavior

### 1.3 Architecture Overview

```
User --> OpenClaw Gateway --> kali-claw Workspace
                                  |
                                  +-- SOUL.md       (personality + 12 Hacker Laws)
                                  +-- USER.md       (user profile and preferences)
                                  +-- IDENTITY.md   (skill tags + personality traits)
                                  +-- skills/       (49 skill domains)
                                  |    +-- web-sqli/
                                  |    |    +-- SKILL.md
                                  |    |    +-- payloads.md
                                  |    |    +-- test-cases.md
                                  |    |    +-- guides/
                                  |    +-- network-pentest/
                                  |    +-- ... (47 more domains)
                                  +-- memory/       (daily memory logs)
                                  +-- chronicle/    (monthly milestones)
                                  +-- TOOLS.md      (518 tool knowledge base)
                                  +-- HEARTBEAT.md  (automated task framework)
                                  +-- MEMORY.md     (long-term distilled knowledge)
```

**Session startup flow:**

Every time you start a new session, the agent automatically:
1. Reads `SOUL.md` -- loads its identity and the 12 Hacker Laws
2. Reads `USER.md` -- learns who it is helping
3. Reads today's and yesterday's memory logs -- gets recent context
4. Reads `MEMORY.md` -- loads long-term distilled knowledge
5. Ready -- the agent now has full context and can assist you

---

## 2. Environment Setup

### 2.1 Option A: Running on Kali Linux Directly (Recommended)

The simplest setup. Install everything on a Kali Linux machine.

**System requirements:** Kali Linux 2025.x (ARM64 and x86_64 both supported).

**Install Node.js:**

```bash
# Option 1: Using apt
sudo apt update
sudo apt install -y nodejs npm

# Option 2: Using nvm (recommended for latest LTS)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
source ~/.bashrc
nvm install --lts
```

**Verify:**

```bash
node --version    # Needs >= 18
npm --version
```

### 2.2 Option B: Remote Kali via SSH

Run OpenClaw on your regular machine (Mac, Windows, or Linux) and have kali-claw execute security tools remotely on a Kali Linux machine via SSH.

**SSH key setup:**

```bash
# Generate an SSH key pair
ssh-keygen -t ed25519 -C "kali-claw"

# Copy the public key to your Kali machine
ssh-copy-id user@kali-host

# Verify the connection and tool availability
ssh user@kali-host "nmap --version"
ssh user@kali-host "sqlmap --version"
```

**Best for:** Mac or Windows users who do not want to run a Kali VM locally, or teams with a shared Kali server.

### 2.3 Option C: Docker Container

Run Kali Linux in a Docker container and connect to it.

```bash
# Pull the official Kali image
docker pull kalilinux/kali-rolling

# Create and start a container
docker run -it --name kali-claw-env kalilinux/kali-rolling /bin/bash

# Inside the container, install security tools
apt update && apt install -y nmap sqlmap nikto hydra burpsuite metasploit-framework
```

The kali-claw workspace stays on your host machine. The agent connects to the container via volume mount or SSH.

**Best for:** Isolated, disposable testing environments. Easy to reset.

### 2.4 Environment Checklist

Before proceeding to installation, confirm the following:

- [ ] Node.js >= 18 installed (`node --version`)
- [ ] OpenClaw installed (`npm list -g openclaw`)
- [ ] Kali Linux available (local machine, SSH, or Docker)
- [ ] Basic Kali tools work (`nmap --version` returns successfully)

---

## 3. Installation and Initialization

### 3.1 Install OpenClaw

```bash
npm install -g openclaw@latest
```

**Verify:**

```bash
openclaw --version
```

**Troubleshooting:**
- **Permission error** on Linux/Mac: use `sudo npm install -g openclaw@latest`
- **Slow download**: configure an npm mirror with `npm config set registry https://registry.npmmirror.com`

### 3.2 Create a Dedicated Agent

```bash
openclaw agents add kali-claw --workspace ~/.openclaw/workspace-kali-claw
```

**Why create a dedicated agent instead of using `main`?**
- Isolated workspace -- kali-claw's memory and config do not mix with other agents
- Isolated memory -- daily logs, chronicles, and long-term knowledge are separate
- Isolated configuration -- SOUL.md, USER.md, and AGENTS.md are agent-specific
- Separate permission and routing management

### 3.3 Clone the kali-claw Workspace

```bash
# Navigate to the workspace directory created by OpenClaw
cd ~/.openclaw/workspace-kali-claw/

# Clone the kali-claw repository into this directory
# Note the trailing dot (.) -- this clones into the current directory
git clone https://github.com/brucesongs/kali-claw.git .
```

**Verify the clone:**

```bash
ls -la
# You should see: SOUL.md, AGENTS.md, USER.md, IDENTITY.md,
# HEARTBEAT.md, TOOLS.md, skills/, memory/, chronicle/, etc.
```

### 3.4 First-Time Configuration (4 Files You MUST Modify)

These four files contain the agent's identity and your preferences. You need to customize them before first use.

#### FILE 1: `USER.md` -- Fill in Your Information

This file tells the agent who you are and how you like to communicate.

**Before (default):**

```markdown
## Basic Info

- **Name**: kali-claw
- **Title**: Captain
- **Timezone**: Asia/Shanghai (CST)
- **Language Preference**: Chinese primary, technical terms in English

## Key Interests

- Ethical Hacking
- Penetration Testing
- Network Security
```

**After (example -- customize to your own information):**

```markdown
## Basic Info

- **Name**: Alex
- **Title**: Captain
- **Timezone**: America/New_York (EST)
- **Language Preference**: English primary, technical terms in English

## Key Interests

- Web Application Security
- Bug Bounty Hunting
- CTF Competitions
- Network Penetration Testing

## Current Focus

- Learning nmap and burpsuite for bug bounty
- Practicing on HackTheBox and TryHackMe
- Building a personal security lab with Docker

## Preferences & Style

- **Technical Communication**: Give commands and steps directly, no fluff
- **Learning Style**: Hands-on practice first, theory second
- **Problem Solving**: Try to solve independently first, then discuss
```

#### FILE 2: `SOUL.md` -- Change Nickname and Role

This file defines the agent's personality. At minimum, change the nickname and role.

**Before (default):**

```markdown
## Identity

- **Nickname**: kali-claw
- **Role**: Senior Penetration Testing Engineer -- Master of all Kali Linux security tools
```

**After (example):**

```markdown
## Identity

- **Nickname**: my-pentest-agent
- **Role**: Junior Security Analyst -- Learning penetration testing fundamentals
```

Leave the 12 Hacker Laws and Core Truths sections unchanged -- they are universally applicable.

#### FILE 3: `IDENTITY.md` -- Adjust Skill Tags

This file contains a table of skill domains. Remove rows for skills you do not need, or add custom ones.

**Before (default -- 28 skill rows):**

```markdown
| Domain | Core Capabilities | Related Laws |
|--------|-------------------|--------------|
| Reconnaissance | OSINT, DNS enumeration, ... | ... |
| Web Security | SQL injection, XSS, ... | ... |
| ... (28 rows total) |
```

**After (example -- focus only on Web security):**

```markdown
| Domain | Core Capabilities | Related Laws |
|--------|-------------------|--------------|
| Web Security | SQL injection, XSS, SSRF, auth bypass, access control | Trust but Verify, Minimize Attack Surface |
| API Security | REST/GraphQL API testing, authentication bypass, rate limiting | Trust but Verify, Minimize Attack Surface |
| Reconnaissance | OSINT, DNS enumeration, port scanning, subdomain discovery | First Principles, Divergent Thinking |
| Terminal Ops | Command-line pentest operations, evidence capture, session management | First Principles, Assume Breach |
| Docker Patterns | Lab environment setup, vulnerable container management | Assume Breach, Defense in Depth |
| Search First | Vulnerability intelligence, exploit search, evaluation | Information Wants to Be Free, First Principles |
```

#### FILE 4: `AGENTS.md` -- Update the Agent Config Block

This file defines the workspace configuration and session startup sequence.

**Before (default):**

```markdown
## Agent Config

- **Agent Name**: kali-claw
- **Runtime Environment**: Kali Linux
- **Role**: Penetration Testing Engineer
- **Specialty**: Security tools + penetration testing + vulnerability research
- **Work Mode**: 24/7 Continuous
```

**After (example):**

```markdown
## Agent Config

- **Agent Name**: my-pentest-agent
- **Runtime Environment**: Kali Linux (remote SSH at 192.168.1.100)
- **Role**: Security Learning Assistant
- **Specialty**: Web application security + learning penetration testing fundamentals
- **Work Mode**: On-demand (active during study sessions)
```

### 3.5 Start and Verify

```bash
openclaw gateway start
```

**Verify everything works:**

Send a test message through the gateway to confirm the agent responds:

```
You: hello, what skills do you have?
```

The agent should respond with a summary of its capabilities, reflecting your customized configuration.

---

## 4. Core Concepts

### 4.1 Skill System

kali-claw includes **49 skill domains** organized into five categories:

| Category | Example Domains | Purpose |
|----------|----------------|---------|
| **Attack Skills** | web-sqli, web-xss, web-ssrf, network-pentest, password-attack, post-exploitation, wifi-pentest | Offensive security techniques |
| **Defense Skills** | security-review, verification-loop, docker-patterns, safety-guard | Defensive security and safety |
| **Knowledge Skills** | osint, deep-research, search-first, repo-scan, exa-search | Intelligence gathering and research |
| **Meta Skills** | autonomous-loops, multi-agent-collaboration, council, chronicle | Orchestration and coordination |
| **Infrastructure** | safety-guard, continuous-learning, terminal-ops, mcp-server-patterns | Agent operations and tooling |

**Skill structure** -- each domain follows a consistent pattern:

```
skills/web-sqli/
  +-- SKILL.md          # Skill definition, use cases, tools, methodology
  +-- payloads.md       # Attack payloads and commands organized by type
  +-- test-cases.md     # Structured test case templates
  +-- guides/           # Deep-dive learning materials
```

**How skills are triggered:**

You do NOT need to manually invoke skills. Simply describe your task in natural language, and the agent automatically matches the relevant skills based on your request.

Example dialog:

```
You: Scan 192.168.1.0/24 for open ports and running services

Agent: [triggers network-pentest + terminal-ops skills]
       Running nmap scan on 192.168.1.0/24...

       $ nmap -sV -sC 192.168.1.0/24

       Found 3 live hosts:
       - 192.168.1.1   (gateway)    ports: 22, 80, 443
       - 192.168.1.50  (web server) ports: 80, 3306
       - 192.168.1.100 (workstation) ports: 22, 3389

       Shall I run a vulnerability scan on the web server?
```

**ECC Orchestration patterns** -- kali-claw supports 6 patterns for multi-step operations:

| Pattern | Use Case | Example |
|---------|----------|---------|
| Sequential Pipeline | Step-by-step pentest flow | Recon -> Scan -> Exploit -> Report |
| Watch Loop | Monitoring a target for changes | Watching for new subdomains |
| Batch Processing | Processing multiple targets | Scanning a list of 100 URLs |
| Learning Cycle | Tool mastery progression | Learn nmap -> practice -> review |
| Meta-Skill | Combining multiple skills | Council analysis across domains |
| Cross-cutting Interceptor | Safety enforcement | Safety-guard checking every command |

### 4.2 Memory System

kali-claw uses a **three-layer memory architecture**:

```
Layer 1: memory/YYYY-MM-DD.md
          Daily raw logs (what was done, what was found, commands run)
                    |
                    | auto-distill
                    v
Layer 2: chronicle/YYYY-MM/*.md
          Monthly milestones (key decisions, breakthroughs, tool mastery)
                    |
                    | auto-distill
                    v
Layer 3: MEMORY.md (root)
          Long-term distilled knowledge (key decisions, tool preferences, lessons learned)
```

**How it works:**
- Every session, the agent writes daily activity to `memory/YYYY-MM-DD.md`
- Periodically, important events are distilled into `chronicle/YYYY-MM/*.md`
- The most important, persistent knowledge ends up in `MEMORY.md`
- On each new session, the agent reads recent daily logs + MEMORY.md for full context

**How to check memory:**
- Open the files directly in any text editor
- Or ask the agent: "What did we work on last time?"
- Or ask: "What do you know about [topic]?"

### 4.3 Heartbeat System (HEARTBEAT.md)

The heartbeat system runs automated periodic tasks to keep the agent healthy and learning.

**4 task categories (in priority order):**

| Priority | Category | Tasks |
|----------|----------|-------|
| 1 (highest) | Security Check | Check alerts, verify file integrity, detect sensitive data leaks |
| 2 | Health Check | Check system resources, verify config file integrity, confirm backups |
| 3 | Learning Progress | Track tool learning, advance to next tool, update skill files |
| 4 | Knowledge Maintenance | Clean old logs, distill lessons, update skill files |

**Key behaviors:**
- Only 1-2 items execute per heartbeat cycle (lightweight execution)
- Tasks rotate across heartbeats to avoid overloading
- Results are logged to `memory/heartbeat-check-YYYYMMDDHHMM.md`
- Anomalies are recorded in `memory/alerts.txt` and the user is notified

**How to customize:** Edit `HEARTBEAT.md` to add, remove, or modify heartbeat tasks.

### 4.4 Tool Knowledge Base (TOOLS.md)

TOOLS.md tracks the agent's knowledge of **518 Kali Linux tools** across 65 categories.

**What each tool entry records:**
- Mastery status (Mastered / Learning / Not started)
- Learning notes and usage experience
- Links to relevant memory files and guides

**How to add new tools:** Add a new row to the Category Index table in TOOLS.md:

```markdown
| Your Category | Tool Count | Status | Learning Notes |
|---------------|------------|--------|----------------|
| Custom Tools  | 2          | Learning | Custom scripts in /opt/tools/ |
```

---

## 5. Usage Scenarios

### 5.1 Penetration Testing

A complete multi-turn dialog showing a full penetration test workflow:

**Step 1 -- Reconnaissance:**

```
You: Help me gather information on target.com

Agent: [triggers recon-osint + osint skills]

       Starting OSINT reconnaissance on target.com...

       DNS Records:
       - A     : target.com -> 93.184.216.34
       - MX    : mail.target.com
       - NS    : ns1.target.com, ns2.target.com

       Subdomains found (via crt.sh + sublist3r):
       - www.target.com
       - api.target.com
       - admin.target.com
       - dev.target.com (403 Forbidden)

       Technologies detected (whatweb):
       - nginx/1.18.0
       - PHP 8.1
       - MySQL (inferred)

       Found 4 live subdomains. Shall I proceed with port scanning?
```

**Step 2 -- Scanning:**

```
You: Yes, scan all discovered subdomains for open ports and services

Agent: [triggers network-pentest + terminal-ops skills]

       Scanning 4 hosts with nmap service detection...

       Results:
       www.target.com:80    - nginx/1.18.0, PHP 8.1
       www.target.com:443   - TLS 1.2, cert valid
       api.target.com:8080  - Node.js Express
       api.target.com:5432  - PostgreSQL (filtered)
       admin.target.com:80  - Apache Tomcat 9.0.50
       admin.target.com:8080- Apache Tomcat management interface (401)

       Notable findings:
       1. admin.target.com:8080 - Tomcat manager may have default credentials
       2. api.target.com:8080 - Node.js API, potential injection points
       3. dev.target.com still returning 403 - might be worth investigating

       What would you like to investigate first?
```

**Step 3 -- Exploitation:**

```
You: Check admin.target.com:8080 for default credentials and test the API for injection

Agent: [triggers web-auth-bypass + api-security + web-sqli skills]

       Testing Tomcat manager for default credentials...

       Attempting common username/password combinations...
       - admin:admin       -> 401 Unauthorized
       - tomcat:tomcat     -> 401 Unauthorized
       - admin:password    -> 401 Unauthorized
       - tomcat:s3cret     -> 200 OK! ACCESS GRANTED

       [!] Default credentials found: tomcat:s3cret
       [!] This allows WAR file deployment = remote code execution

       Testing API endpoint api.target.com:8080/api/users?id=1...
       - Normal request: returns user data
       - Adding single quote: server error (500)
       - Testing UNION-based injection: data returned

       [!] SQL injection confirmed on /api/users?id parameter
       [!] Database: PostgreSQL, 3 tables found (users, sessions, config)

       How would you like to proceed?
```

**Step 4 -- Post-Exploitation:**

```
You: I got a shell through Tomcat. What should I do next?

Agent: [triggers post-exploitation + safety-guard skills]

       Post-exploitation checklist for your new shell:

       1. **Stabilize the shell** (important for reliable operations):
          $ python3 -c 'import pty; pty.spawn("/bin/bash")'
          $ export TERM=xterm

       2. **Gather system information:**
          $ whoami && id
          $ hostname && uname -a
          $ cat /etc/os-release

       3. **Check privilege escalation vectors:**
          $ sudo -l
          $ find / -perm -4000 -type f 2>/dev/null
          $ cat /etc/crontab

       4. **Enumerate network connections:**
          $ ss -tulpn
          $ cat /etc/hosts

       IMPORTANT REMINDER: This is a learning exercise. Only perform these
       actions on systems you have explicit authorization to test.

       Shall I walk you through each step?
```

**Step 5 -- Reporting:**

```
You: Help me summarize today's findings into a report

Agent: [triggers article-writing + chronicle skills]

       # Penetration Test Report - target.com
       ## Date: 2026-05-18
       ## Scope: External infrastructure assessment

       ### Executive Summary
       3 critical and 2 high-severity vulnerabilities identified...

       ### Findings

       | # | Finding | Severity | CVSS |
       |---|---------|----------|------|
       | 1 | Default Tomcat credentials | Critical | 9.8 |
       | 2 | SQL Injection on /api/users | Critical | 9.1 |
       | 3 | Exposed PostgreSQL port | High | 7.5 |
       | 4 | Dev subdomain accessible | Medium | 5.3 |
       | 5 | TLS 1.0 still enabled | Low | 3.7 |

       ### Recommendations
       1. Change all default credentials immediately
       2. Implement parameterized queries for all SQL operations
       ...

       Report saved to memory/2026-05-18.md
```

### 5.2 Security Audit

```
You: Audit this web application for security issues: http://testphp.vulnweb.com

Agent: [triggers security-review + verification-loop skills]

       Running systematic OWASP Top 10 audit...

       Phase 1: Information Gathering
       - Server: nginx/1.18.0
       - Backend: PHP
       - Forms found: login, search, signup

       Phase 2: Injection Testing
       - SQL Injection: Testing all input fields...
         [!] search field vulnerable to UNION-based SQLi
       - XSS: Testing reflection points...
         [!] Reflected XSS in search results (no output encoding)
       - Command Injection: Testing for OS command execution...
         [OK] No command injection found

       Phase 3: Authentication and Authorization
       - Brute force protection: None detected
       - Session management: Predictable session IDs
       - Access control: IDOR on /user.php?id= parameter

       Phase 4: Configuration Review
       - Directory listing: Enabled on /uploads/
       - Error messages: Expose PHP version and stack traces
       - Security headers: Missing X-Frame-Options, CSP

       Summary: 2 Critical, 2 High, 3 Medium findings
       Full report with remediation steps available.
```

### 5.3 Learning and Research

```
You: I want to learn SQL injection. Where do I start?

Agent: [triggers search-first + web-sqli + docker-patterns skills]

       Here is a structured learning path for SQL injection:

       ## Phase 1: Understand the Fundamentals (1-2 days)
       1. Read skills/web-sqli/SKILL.md for the full methodology
       2. Understand the 5 SQLi types: Union, Boolean-blind, Time-blind,
          Error-based, Out-of-band

       ## Phase 2: Set Up a Practice Lab (today)
       I can spin up a Docker-based practice environment for you:

       $ docker run -d -p 80:80 acunetix/vulnerable-web-app

       Or use the dedicated SQLi labs:

       $ docker run -d -p 8080:80 sqli/sqli-labs

       ## Phase 3: Hands-On Practice (3-5 days)
       Start with skills/web-sqli/payloads.md -- it has payloads
       organized by difficulty:
       - Level 1: Union-based (simplest)
       - Level 2: Error-based
       - Level 3: Boolean-blind
       - Level 4: Time-blind
       - Level 5: WAF bypass techniques

       ## Phase 4: Test Cases (2-3 days)
       Use skills/web-sqli/test-cases.md to practice structured testing
       against real targets.

       Shall I set up the Docker lab right now?
```

### 5.4 Team Collaboration

**Multi-agent collaboration:** Use the `council` skill to get multi-perspective analysis:

```
You: Analyze the security of this authentication implementation from multiple angles

Agent: [triggers council + security-review skills]

       Running council analysis with 3 perspectives:

       ## Attacker Perspective
       - Session tokens are predictable (timestamp-based)
       - No rate limiting on login endpoint (brute force possible)
       - Password reset token sent via email (interception risk)

       ## Defender Perspective
       - Recommend switching to cryptographically random session tokens
       - Implement rate limiting: 5 attempts per 15 minutes
       - Add TOTP-based 2FA for sensitive operations
       - Log all authentication events for monitoring

       ## Auditor Perspective
       - Non-compliant with NIST SP 800-63B (no password complexity)
       - Missing audit trail for failed login attempts
       - Password storage uses SHA-256 (should use bcrypt/argon2)
       - Session timeout set to 30 days (too long)

       ## Consensus Recommendations
       Priority 1: Fix session token generation (critical)
       Priority 2: Implement rate limiting (high)
       Priority 3: Upgrade password hashing (high)
       Priority 4: Add 2FA (medium)
```

---

## 6. Advanced Configuration

### 6.1 MCP Tool Integration

MCP (Model Context Protocol) allows kali-claw to expose Kali Linux tools as standardized, callable services.

The `mcp-server-patterns` skill provides templates for wrapping security tools as MCP servers.

**Example: wrapping nmap as an MCP tool:**

1. Create a wrapper script that accepts structured input and returns structured output
2. Register it as an MCP server in the OpenClaw configuration
3. kali-claw can now call nmap through a standardized interface with proper input validation and output parsing

This enables better tool integration, logging, and safety guards around tool execution.

### 6.2 Custom Skills

Follow these steps to create a new skill domain:

**Step 1: Create the directory**

```bash
mkdir -p skills/my-custom-skill/guides
```

**Step 2: Write `SKILL.md`**

```markdown
# My Custom Skill

## Description
Brief description of what this skill does.

## Use Cases
- Use case 1
- Use case 2

## Tools
- tool1
- tool2

## Methodology
1. Step one
2. Step two
3. Step three

## Orchestration
Which ECC pattern(s) this skill uses and how.
```

**Step 3: Write `payloads.md`**

```markdown
# Attack Payloads - My Custom Skill

## Type 1: Category Name

### Payload 1
Description and usage:
\`\`\`bash
command --option value
\`\`\`

### Payload 2
...
```

**Step 4: Write `test-cases.md`**

```markdown
# Test Cases - My Custom Skill

## TC-001: Test Case Title

- **Target**: What is being tested
- **Preconditions**: What must be true before testing
- **Steps**:
  1. Step one
  2. Step two
- **Expected Result**: What should happen
- **Actual Result**: (filled during testing)
- **Status**: Pass / Fail
```

**Step 5: Add skill tag in `IDENTITY.md`**

Add a new row to the Skill Tags table:

```markdown
| My Custom Skill | description of capabilities | Related Laws |
```

**Step 6: Add related tools in `TOOLS.md`**

Add tools used by your new skill to the Category Index table.

### 6.3 Custom Behaviors

**Modify the 12 Hacker Laws in SOUL.md:**

The laws are universal, but you can adjust emphasis or add domain-specific rules. For example, for a compliance-focused agent, add a 13th law:

```markdown
### 13. Compliance by Design
Every action must be traceable, auditable, and compliant with applicable regulations.
```

**Adjust heartbeat tasks in HEARTBEAT.md:**

Add custom monitoring tasks relevant to your use case. For example:

```markdown
## Custom Monitoring

- [ ] Check if any Docker containers have been running for > 24 hours
- [ ] Verify that no test targets are still accessible
```

**Modify session startup flow in AGENTS.md:**

Add or remove steps from the "Every Session" section. For example, if you want the agent to always check a specific dashboard on startup:

```markdown
## Every Session

1. Read SOUL.md
2. Read USER.md
3. Read memory/YYYY-MM-DD.md
4. Read MEMORY.md
5. Check https://your-dashboard.com/api/status for active engagements
```

---

## 7. FAQ

### Q1: `npm install -g openclaw` gives a permission error

**Problem:** `EACCES: permission denied` when installing globally.

**Cause:** npm tries to write to a system directory that requires elevated privileges.

**Solution:**

```bash
# Option 1: Use sudo (quick fix)
sudo npm install -g openclaw@latest

# Option 2: Configure npm to use a user-writable directory (recommended)
mkdir -p ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
npm install -g openclaw@latest
```

### Q2: `openclaw gateway start` fails to connect

**Problem:** Gateway does not start or connection is refused.

**Cause:** Port conflict, firewall blocking, or incompatible Node.js version.

**Solution:**

```bash
# Check Node.js version (needs >= 18)
node --version

# Check if the port is already in use
lsof -i :3000    # or whatever port OpenClaw uses

# Check firewall rules
sudo ufw status   # Linux
# Or on Mac: System Preferences > Network > Firewall
```

### Q3: Agent says it cannot find nmap, sqlmap, or other tools

**Problem:** The agent reports tools are not available.

**Cause:** Tools are not installed on the Kali system, not in PATH, or SSH connection to the remote Kali machine has failed.

**Solution:**

```bash
# If running on Kali directly
sudo apt update && sudo apt install -y nmap sqlmap nikto hydra

# If using remote SSH
ssh user@kali-host "which nmap"
ssh user@kali-host "nmap --version"

# If using Docker
docker exec -it kali-claw-env which nmap
docker exec -it kali-claw-env apt install -y nmap
```

### Q4: Skills are not being triggered

**Problem:** The agent does not seem to be using the right skills.

**Cause:** Task description may be too vague, or skill descriptions do not match the request.

**Solution:**
- Be more explicit: instead of "check this website", say "scan this website for SQL injection vulnerabilities"
- Reference skill names directly: "Use the web-sqli skill to test the login form"
- Check that the relevant skill exists in `skills/` and has proper descriptions in `SKILL.md`

### Q5: Memory seems lost after a session

**Problem:** The agent does not remember previous conversations.

**Cause:** Daily memory files may be missing, or MEMORY.md may not exist.

**Solution:**

```bash
# Check that memory files exist
ls -la memory/

# Verify MEMORY.md exists
ls -la MEMORY.md

# If MEMORY.md is missing, the agent will still read daily logs
# but will lack long-term distilled knowledge
```

### Q6: How do I reset the agent completely?

**Problem:** You want to start with a clean slate.

**Solution:**

```bash
# Delete all memory (this is irreversible!)
rm -f memory/*.md memory/alerts.txt
rm -rf chronicle/

# MEMORY.md will be regenerated as the agent learns
# You can also clear it manually:
> MEMORY.md
```

### Q7: How do I update to the latest version?

**Problem:** You want the newest skills and configurations.

**Solution:**

```bash
cd ~/.openclaw/workspace-kali-claw/
git pull origin main

# If you have local modifications that conflict:
git stash
git pull origin main
git stash pop

# Note: your customizations to SOUL.md, USER.md, IDENTITY.md,
# and AGENTS.md will be preserved if committed to a local branch
```

### Q8: Can I use kali-claw on a non-Kali system?

**Problem:** You do not have Kali Linux installed.

**Solution:** Yes, but with limitations.

- **Without Kali Linux:** kali-claw can still help with research, learning, planning, and report writing. It just cannot execute security tools like nmap, sqlmap, etc.
- **With remote Kali:** Set up SSH access (see Section 2.2) to a Kali machine.
- **With Docker:** Run a Kali container (see Section 2.3) on any system with Docker installed.

---

## 8. Core File Reference

| File | Purpose | When to Modify |
|------|---------|---------------|
| `SOUL.md` | Agent personality, 12 Hacker Laws, behavioral guidelines, boundaries | Customizing personality, adding new laws |
| `AGENTS.md` | Workspace config, session startup sequence, memory system rules | Adjusting session flow, changing agent name/role |
| `IDENTITY.md` | Skill tags table, personality traits, creature type | Adding/removing skill domains, changing agent identity |
| `USER.md` | Captain profile, preferences, interests, current focus | New user first-time setup, updating preferences |
| `MEMORY.md` | Long-term distilled knowledge and key decisions | Generally do NOT edit manually -- let the agent manage it |
| `TOOLS.md` | 518 tool inventory, learning progress, learning strategy | Adding new tools, updating mastery status |
| `HEARTBEAT.md` | Automated heartbeat tasks: health, learning, security, maintenance | Adjusting check frequency, adding custom monitoring |
| `skills/` | 49 skill domains with payloads, test cases, and guides | Adding new skills, updating existing payloads |
| `memory/` | Daily memory logs (`YYYY-MM-DD.md`) | Generally do NOT edit manually -- let the agent manage it |
| `chronicle/` | Monthly milestone tracking (`YYYY-MM/*.md`) | Generally do NOT edit manually -- let the agent manage it |

---

_This guide covers OpenClaw + kali-claw v0.1.7. For the latest updates, visit the [kali-claw repository](https://github.com/brucesongs/kali-claw)._
