# OpenClaw + kali-claw: Complete Usage Guide

> A beginner-friendly guide to setting up and using the OpenClaw framework with the kali-claw penetration testing agent workspace.
>
> **Target version: v0.1.39** — 111 skill domains, 33 Distinguished, 100% Excellent+.

---

## Table of Contents

1. [Understanding the Concepts](#1-understanding-the-concepts)
2. [Environment Setup](#2-environment-setup)
3. [Installation and Initialization](#3-installation-and-initialization)
4. [Core Concepts](#4-core-concepts)
5. [Usage Scenarios](#5-usage-scenarios)
6. [Advanced Configuration](#6-advanced-configuration)
7. [Version History and Milestones](#7-version-history-and-milestones)
8. [FAQ](#8-faq)
9. [Core File Reference](#9-core-file-reference)

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

kali-claw is a pre-built penetration testing agent workspace for the OpenClaw framework. It is NOT a traditional software code repository -- it is a **Markdown knowledge base + configuration system + automation scripts**.

**What it includes:**
- **111 security skill domains** -- from OSINT and web exploitation to cloud + identity, modern enterprise stack (PAM / CI-CD / CSPM-CASB / SASE-SSE), AI/LLM security, SCADA/ICS, blockchain/Web3, mobile/IoT, quantum/post-quantum, radio/satellite, and more
- **518 Kali Linux tool knowledge base** -- mastery tracking, learning notes, usage experience
- **12 Hacker Laws** -- behavioral guidelines derived from real-world security philosophy
- **Layered memory system** -- daily logs, monthly chronicles, and long-term distilled knowledge
- **Agent Skills Open Standard compliance** -- all SKILL.md files use the Anthropic 2025 YAML frontmatter standard (`name`, `description`, `compatibility`, `allowed-tools`, `metadata`)
- **Quality scoring system (SCORE.sh v2)** -- 7 metrics × 4 components × 5 tiers (Distinguished / Excellent / Strong / Adequate / Weak)
- **Automation and orchestration** -- 10+ scripts in `validation/` covering heartbeat, backup, drift detection, scenario runner, end-to-end orchestration, report generation

**How it differs from using ChatGPT or Claude directly:**

| Feature | ChatGPT / Claude | kali-claw |
|---------|------------------|-----------|
| Persistent memory | None (start from zero every chat) | Three-layer file-based memory |
| Skill system | None | 111 structured skill domains |
| Tool execution | Cannot run commands | Can call all 518 Kali Linux tools |
| Personality consistency | None | SOUL.md defines fixed persona + 12 laws |
| Learning evolution | None | Grows through memory + heartbeat |
| Payload library | None | Multi-MB payloads.md per skill |
| Detection rule mapping | None | Defender perspective + Sigma/SPL/KQL rules |
| Real-world incident case studies | None | SolarWinds / Capital One / 3CX / xz-utils deep dives |

### 1.3 Architecture Overview

```
User --> OpenClaw Gateway --> kali-claw Workspace
                                  |
                                  +-- SOUL.md              (personality + 12 Hacker Laws)
                                  +-- USER.md              (user profile and preferences)
                                  +-- IDENTITY.md          (111 skill tag rows)
                                  +-- AGENTS.md            (workspace config + session flow)
                                  +-- MEMORY.md            (long-term distilled knowledge)
                                  +-- TOOLS.md             (518 tool knowledge base)
                                  +-- HEARTBEAT.md         (automated task framework)
                                  +-- CHANGELOG.md         (v0.1.1 -> v0.1.39 history)
                                  +-- skills/              (111 skill domains)
                                  |    +-- web-sqli/
                                  |    |    +-- SKILL.md     (YAML frontmatter)
                                  |    |    +-- payloads.md
                                  |    |    +-- test-cases.md
                                  |    |    +-- guides/
                                  |    +-- ci-cd-supply-chain-attack/
                                  |    +-- pam-privilege-attack/
                                  |    +-- cspm-casb-attack/
                                  |    +-- sase-sse-attack/
                                  |    +-- ad-cs-abuse/
                                  |    +-- cloud-identity-attack/
                                  |    +-- ... (111 total)
                                  +-- validation/          (automation and orchestration)
                                  |    +-- SCORE.sh              (quality scoring engine)
                                  |    +-- heartbeat.sh           (workspace health check)
                                  |    +-- orchestrator.sh        (end-to-end pentest orchestration)
                                  |    +-- scenario-runner.sh     (cross-skill scenarios)
                                  |    +-- tool-selector.sh       (target -> tool mapping)
                                  |    +-- report-generator.sh    (automated reporting)
                                  |    +-- update-skill-standard.py (SKILL.md standard alignment)
                                  |    +-- engagement-template/   (authorized pentest templates)
                                  |    +-- evidence/              (scoring + scenario evidence)
                                  +-- memory/              (daily memory logs)
                                  +-- chronicle/           (monthly milestones)
                                  +-- docs/                (long-form design docs)
                                  +-- bak/                 (backups)
```

**Session startup flow:**

Every time you start a new session, the agent automatically:
1. Reads `SOUL.md` -- loads its identity and the 12 Hacker Laws
2. Reads `USER.md` -- learns who it is helping
3. Reads today's and yesterday's memory logs -- gets recent context
4. Reads `MEMORY.md` -- loads long-term distilled knowledge
5. Ready -- the agent now has full context and can assist you

### 1.4 Quality Tier System (introduced v0.1.16, current state v0.1.39)

kali-claw ships with an **objective, quantifiable** skill quality scoring system. Every skill domain receives a 0-100 score, mapped to 5 tiers:

| Tier | Score Range | v0.1.39 Count | Meaning |
|------|-------------|---------------|---------|
| **Distinguished** | 92.0 - 100 | **33** | Best-in-class depth, reference implementation |
| **Excellent** | 80.0 - 91.9 | **78** | Comprehensive coverage, only minor depth gaps |
| Strong | 60.0 - 79.9 | 0 | Good coverage |
| Adequate | 40.0 - 59.9 | 0 | Components present but shallow |
| Weak | 0 - 39.9 | 0 | Missing critical components |

**Current state (v0.1.39):**
- 111/111 skills at Excellent or above (**100%**)
- Average score: **88.78**
- Min / Max: 85.1 / 94.6
- Distinguished ratio: 33/111 ≈ **30%**

Scoring details live in `validation/SCORING-METHODOLOGY.md`. Per-skill JSON evidence is in `validation/evidence/quality-scores/`.

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
```

You should see:

```
SOUL.md           CHANGELOG.md      MEMORY.md
AGENTS.md         CLAUDE.md         TOOLS.md
IDENTITY.md       HEARTBEAT.md      README.md
USER.md           LICENSE           VERSION
skills/           validation/       memory/
chronicle/        docs/             bak/
GUIDE-OPENCLAW-zh.md   GUIDE-OPENCLAW-en.md
RELEASE-v0.1.X.md (one release note per version)
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

This file contains a table of skill domains (111 rows in v0.1.39). Remove rows for skills you do not need, or add custom ones.

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

### 3.6 Run Quality Scoring (Optional but Recommended)

After cloning, run the scoring script once to confirm all skills are intact:

```bash
bash validation/SCORE.sh
```

This generates JSON score files for all 111 skill domains in `validation/evidence/quality-scores/`. If you plan to modify skills, these scores help you locate weak spots.

---

## 4. Core Concepts

### 4.1 Skill System

kali-claw includes **111 skill domains** organized into 8 broad categories:

**Web and API Attacks**

| Domain | Description |
|--------|-------------|
| web-sqli / web-xss / web-ssrf | The classic web trio (incl. CSP bypass, cloud-metadata SSRF) |
| web-auth-bypass / web-access-control | Auth bypass, IDOR, OAuth/JWT attacks |
| web-xxe / web-deserialization / file-inclusion | XML External Entity, Java/PHP/.NET deserialization, LFI/RFI |
| cms-framework-attack | WordPress/Joomla/Drupal pentesting |
| api-security | REST/GraphQL, rate limiting, parameter tampering |
| email-security-deep | AiTM phishing, gateway bypass (Proofpoint/Mimecast), CVE-2024-21413 |
| browser-qa | Playwright/Puppeteer automated browser security testing |

**Network and Infrastructure**

| Domain | Description |
|--------|-------------|
| network-pentest / recon-osint | Scanning, exploitation, lateral movement, subdomain enumeration |
| network-sniffing-mitm / network-tunneling-proxy | Traffic hijacking, SSH/DNS/ICMP tunneling, SOCKS proxy chains |
| dns-attacks | DNS rebinding, SAD DNS, DoH/DoT/DoQ tunneling, subdomain takeover |
| vpn-attack / sase-sse-attack | Traditional VPN + modern edge (Zscaler / Netskope / Cloudflare One / Cisco Umbrella) |
| email-protocol-attack | SMTP enumeration, SPF/DKIM/DMARC bypass |
| voip-sip-attack | SIP eavesdropping, VLAN hopping |

**Identity and Enterprise Stack**

| Domain | Description |
|--------|-------------|
| ad-ldap-attack | AD/LDAP/Kerberos (AS-REP Roasting, Kerberoasting, DCSync, PtH) |
| ad-cs-abuse | AD CS ESC1-ESC15, PetitPotam, Certifried (CVE-2022-26923) |
| cloud-identity-attack | Entra ID / Okta / Auth0, PRT theft, Golden SAML |
| pam-privilege-attack | 8 PAM vendors: CyberArk / BeyondTrust / Delinea / ManageEngine / WALLIX ... |
| ci-cd-supply-chain-attack | Jenkins, GitLab CI, GitHub Actions, Argo CD, xz-utils / SolarWinds / 3CX case studies |
| cspm-casb-attack | Wiz / Prisma Cloud / Netskope, OPA/Kyverno policy bypass |

**Cloud and Container**

| Domain | Description |
|--------|-------------|
| cloud-security | AWS/Azure/GCP, IAM, S3 exposure, metadata attacks |
| container-security / kubernetes-attack | Docker escape, K8s RBAC, Pod Escape, runc CVE-2024-21626 |
| cloud-native-vuln-research | CVE methodology, PoC reproduction, nuclei templates |
| secret-management-attack | gitleaks/semgrep/trufflehog, Vault/CI-CD/registry exploitation |

**Cryptography and Emerging Tech**

| Domain | Description |
|--------|-------------|
| crypto-attacks | Weak algorithms, Padding Oracle, TLS issues, post-quantum migration, KyberSlash |
| quantum-crypto-attack | NIST PQC, hybrid TLS, QKD/BB84, SM2/3/4 Chinese national crypto |
| blockchain-web3 | Smart-contract audit, DeFi reentrancy, cross-chain bridges, MEV, ERC-777 |
| llm-red-team / ai-security / ai-agent-security | LLM jailbreaks (GCG/AutoDAN/Crescendo), MCP poisoning, RAG poisoning |
| agentic-pentest | PentestGPT, HexStrike, multi-agent team coordination |

**Mobile / IoT / Embedded / Hardware**

| Domain | Description |
|--------|-------------|
| mobile-security / mobile-app-instrumentation | iOS/Android, SSL Pinning bypass, Frida/Objection/r2frida |
| iot-pentest | MQTT, CoAP, AMQP, IoT cloud backends |
| firmware-reverse / hardware-security | Firmware extraction, JTAG/UART, side-channel |
| embedded-rtos-security | VxWorks / QNX / FreeRTOS / ThreadX / Zephyr |
| bluetooth-rfid-nfc | BLE GATT, MIFARE, NFC cloning |

**Critical Infrastructure and Physical**

| Domain | Description |
|--------|-------------|
| scada-ics-security / ics-fieldbus-attack | Modbus, S7comm, EtherNet/IP, OPC UA, Profibus, DNP3, IEC 61850 |
| storage-san-attack | iSCSI/FC/NFSv4/SMB3/S3, NetApp/Dell EMC/QNAP/Synology/TrueNAS |
| hypervisor-introspection | VMware ESXi / Hyper-V / KVM / Xen, LibVMI / DRAKVUF, VENOM |
| satellite-leo-security | Starlink / Iridium / Viasat KA-SAT, DVB-S2 / VSAT, AcidRain |
| sdr-rf-attack / hf-vhf-radio-attack | ADS-B, AIS, ACARS, POCSAG, APRS |
| 5g-telecom-attack | PFCP, GTP, IMSI catchers, O-RAN |
| automotive-vehicle-security | CAN/UDS, key fobs, EV charging |
| uav-drone-security | MAVLink, PX4, GPS spoofing, DroneID |
| physical-security-testing | Lock bypass, RFID cloning, USB weapons (Ducky/Bunny) |
| mainframe-security | z/OS / RACF / CICS / DB2 / JES2 |
| game-anticheat-bypass | EAC / BattlEye / Vanguard / BYOVD |

**Defense / Forensics / Meta-capabilities**

| Domain | Description |
|--------|-------------|
| digital-forensics / anti-forensics | Disk/memory/network forensics, anti-forensics |
| threat-hunting / detection-engineering | Hypothesis-driven hunting, Sigma/YARA, ATT&CK detection engineering |
| deception-honeypot | SSH/Web/ICS/AI honeypots, honeytokens |
| pentest-reporting / article-writing | Dradis/Faraday, CVSS scoring, CVE disclosure |
| engagement-manager | Authorized pentest lifecycle, scope management, evidence chain |
| security-review / repo-scan | OWASP Top 10, source audit, dependency scanning |
| security-bounty-hunter | Bug bounty, PoC development, responsible disclosure |
| codebase-onboarding / knowledge-ops | Rapid codebase intelligence, knowledge graph management |
| exa-search / deep-research / data-scraper-agent | Multi-source intelligence, CVE scraping, semantic search |
| autonomous-loops / multi-agent-collaboration / council | Autonomous orchestration, multi-perspective analysis (attack/defense/audit) |
| safety-guard / terminal-ops / search-first / verification-loop | Safety enforcement, terminal operations, research-before-exploit, multi-phase verification |
| docker-patterns / continuous-learning / chronicle / tool-mastery / mcp-server-patterns | Labs, continuous learning, chronicles, tool mastery, MCP integration |

**Skill structure** -- each domain follows the Agent Skills Open Standard pattern:

```
skills/web-sqli/
  +-- SKILL.md          # Skill definition with YAML frontmatter
  +-- payloads.md       # Attack payloads and commands organized by type
  +-- test-cases.md     # Structured test case templates
  +-- guides/           # Deep-dive learning materials (multiple files)
```

**Progressive disclosure** -- the core design of the Agent Skills Open Standard:

- **Stage 1 (Advertise)** -- YAML frontmatter + `## Summary` -- loaded during skill scanning
- **Stage 2 (Quick Reference)** -- `## Core Tools` + `## Methodology` -- loaded on skill activation
- **Stage 3 (Detailed)** -- `## Practical Steps` + `## Defense Perspective` -- loaded on task execution

This staged loading saves tokens when the skill is not needed, while preserving depth when it is.

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

**Companion script** -- `validation/heartbeat.sh` provides a CLI health check:

```bash
bash validation/heartbeat.sh           # One-shot check
bash validation/heartbeat.sh --fix     # Check and attempt auto-fix
bash validation/heartbeat.sh --json    # JSON output (for monitoring integration)
```

**How to customize:** Edit `HEARTBEAT.md` to add, remove, or modify heartbeat tasks.

### 4.4 Tool Knowledge Base (TOOLS.md)

TOOLS.md tracks the agent's knowledge of **518 Kali Linux tools** across 65+ categories.

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

### 4.5 Quality Scoring System (SCORE.sh v2)

Introduced in v0.1.11, upgraded to v2 in v0.1.16. This subsystem makes "is this skill good enough" an objective, quantifiable metric.

**4 weighted components:**

| Component | Weight | Source | Meaning |
|-----------|--------|--------|---------|
| SKILL.md | 15% | `##` heading count | Structural depth |
| payloads.md | 30% | Avg of word count, section count, code block count | Payload comprehensiveness |
| test-cases.md | 30% | Avg of test case count, field completeness | Test executability |
| guides/ | 25% | File count (40%) + avg word count (30%) + key section presence (30%) | Depth material |

**5 tiers (v2 introduced Distinguished):**

| Tier | Score | v0.1.39 Count |
|------|-------|---------------|
| Distinguished | 92 - 100 | 33 |
| Excellent | 80 - 91.9 | 78 |
| Strong | 60 - 79.9 | 0 |
| Adequate | 40 - 59.9 | 0 |
| Weak | 0 - 39.9 | 0 |

**Running the score:**

```bash
bash validation/SCORE.sh                    # Score all 111 skills
bash validation/SCORE.sh --skill web-sqli   # Score a single skill
```

Results are written to `validation/evidence/quality-scores/<skill>.json`. Each JSON contains the component-level breakdown.

**Typical uses:**
- After improving a skill, score it to confirm the lift
- Find the lowest-scoring skills to prioritize improvements
- Include score deltas in PRs as objective evidence

See `validation/SCORING-METHODOLOGY.md` for the full methodology.

### 4.6 Automation and Orchestration Scripts (validation/)

The `validation/` directory is kali-claw's toolbox -- 10+ Bash scripts covering ops, orchestration, and reporting:

| Script | Purpose | Common Flags |
|--------|---------|--------------|
| `heartbeat.sh` | Workspace health check | `--fix` `--json` |
| `auto-backup.sh` | Backup rotation | `--restore` `--keep N` |
| `drift-detect.sh` | Config drift detection | `--create-baseline` `--update-baseline` |
| `scenario-runner.sh` | Cross-skill scenario execution | `--resume` `--dry-run` |
| `orchestrator.sh` | End-to-end pentest workflow | `--target` `--phase` `--resume` |
| `tool-selector.sh` | Target -> tool smart mapping | `--target-type` `--phase` `--stealth` |
| `report-generator.sh` | Automated pentest report generation | `--source` `--format` |
| `SCORE.sh` | Quality scoring engine (see 4.5) | `--skill <name>` |
| `update-skill-standard.py` | Align SKILL.md with the Agent Skills Standard | `--dry-run` `--skill <name>` |

**End-to-end example (orchestrator):**

```bash
# Auto-run recon -> scan -> exploit -> post-exploit -> report
bash validation/orchestrator.sh --target 10.10.10.10 --phase full

# Resume an interrupted run
bash validation/orchestrator.sh --target 10.10.10.10 --resume
```

**Authorized engagement templates** -- `validation/engagement-template/` provides:

- `targets.json.example` -- Target scope template
- `scope-rules.json.example` -- Scope rules and safety constraints
- `report-template.md` -- Standard pentest report template

### 4.7 Engagement Workflow

The `engagement-manager` skill plus `validation/engagement-template/` provide full **authorized pentest lifecycle management**:

```
1. Scope confirmation (scope-rules.json)   --> Define what is in/out of scope
2. Target registration (targets.json)       --> List IPs/domains/assets
3. Recon + Scan                             --> recon-osint + network-pentest
4. Exploitation                             --> Corresponding attack skill (web-sqli / ad-cs-abuse ...)
5. Post-exploitation                        --> post-exploitation + privilege-escalation
6. Evidence collection                      --> pentest-reporting + screenshots/logs
7. Report generation                        --> report-generator.sh
8. Retrospective                            --> Write to chronicle/ + MEMORY.md
```

Each step is logged to `memory/YYYY-MM-DD.md`. Important milestones are distilled into `chronicle/`, and long-term decisions land in `MEMORY.md`.

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

### 5.5 Modern Enterprise Attack Chain (new in v0.1.39)

v0.1.39 completed the modern enterprise security stack with PAM, CI/CD, CSPM/CASB, and SASE/SSE. The agent can now walk through a full ransomware-family kill chain:

```
You: Use kali-claw to walk me through the BlackCat ransomware kill chain end-to-end

Agent: Based on Mandiant 2023 + CrowdStrike 2024 reports, BlackCat's typical path:

Stage 1: Initial access (sase-sse-attack / email-security-deep)
- Bypass Zscaler ZIA egress inspection, deliver phishing email
- AiTM phishing (evilginx2) harvests MFA credentials

Stage 2: Identity penetration (cloud-identity-attack)
- Entra ID PRT theft -> Conditional Access bypass
- Use ROADtools to obtain a legitimate refresh token

Stage 3: Credential hub (pam-privilege-attack)
- Log in to CyberArk PVWA with stolen creds
- Exploit CVE-2025-32564 auth bypass, escalate to Vault Admin
- Recover plaintext passwords from .cue cred files -> all domain admin accounts

Stage 4: Lateral movement (ad-cs-abuse / ad-ldap-attack)
- ESC1 abuse -> request Domain Controller certificate
- Pass-the-Hash + Kerberoasting laterally to all DCs

Stage 5: Persistence (ci-cd-supply-chain-attack)
- Plant backdoor in Jenkins shared library
- Modify GitHub Actions workflow to exfiltrate all secrets
- Use dependency confusion to plant malicious npm packages

Stage 6: Defense evasion (cspm-casb-attack)
- Tamper Terraform state so Wiz graph hides real config
- Use OPA Rego case-sensitivity trap to bypass Kyverno policy

Stage 7: Data exfiltration + encryption deployment (storage-san-attack)
- Steal via NetApp NDMP snapshots
- Use stolen creds to log in to Dell EMC Unity and delete backups
- Deploy BlackCat encryptor

Each stage maps to a kali-claw skill domain. Specific TTPs and commands live in skills/<domain>/payloads.md.
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

Follow these steps to create a new skill domain (**Agent Skills Open Standard compliant**):

**Step 1: Create the directory**

```bash
mkdir -p skills/my-custom-skill/guides
```

**Step 2: Write `SKILL.md` (with YAML frontmatter)**

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

# My Custom Skill

## Summary
One-line summary of the problem this skill solves.

## Description
Detailed description of what this skill does.

## Use Cases
- Use case 1
- Use case 2

## Core Tools
- tool1
- tool2

## Methodology
1. Step one
2. Step two
3. Step three

## Practical Steps
Detailed executable steps.

## Defense Perspective
How defenders detect and mitigate.

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

**Step 5 (recommended): Create `guides/` directory**

```bash
mkdir -p skills/my-custom-skill/guides
# Add 1-3 deep-dive learning guides inside
```

**Step 6 (optional): Use the standard-alignment script**

```bash
python3 validation/update-skill-standard.py --skill my-custom-skill --dry-run
# Inspect, then drop --dry-run to write
```

**Step 7: Add a skill tag in `IDENTITY.md`**

```markdown
| My Custom Skill | description of capabilities | Related Laws |
```

**Step 8: Add related tools in `TOOLS.md`**

Add tools used by your new skill to the Category Index table.

**Step 9: Score and verify**

```bash
bash validation/SCORE.sh --skill my-custom-skill
# Target: at least Excellent (80+), ideally Distinguished (92+)
```

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

Add or remove steps from the "Every Session" section. For example:

```markdown
## Every Session

1. Read SOUL.md
2. Read USER.md
3. Read memory/YYYY-MM-DD.md
4. Read MEMORY.md
5. Check https://your-dashboard.com/api/status for active engagements
```

---

## 7. Version History and Milestones

### 7.1 Major Version Timeline

kali-claw follows an alternating "**expansion <-> quality**" rhythm, each version has a clear theme:

| Phase | Versions | Key Milestone |
|-------|----------|---------------|
| Foundation | v0.1.1 - v0.1.7 | 45 -> 49 skill domains, layered architecture established |
| Full Enrichment | v0.1.8 - v0.1.10 | 49/49 FULL enrichment, 7/7 integration tests PASS |
| **Quality scoring introduced** | v0.1.11 - v0.1.14 | SCORE.sh v1, 49/49 Excellent 100% |
| **Scoring v2** | v0.1.15 - v0.1.17 | Distinguished tier introduced, TEMPLATE.md |
| **Expansion wave 1** | v0.1.18 - v0.1.21 | 49 -> 70 skill domains (exploit-dev / privesc / payload-gen / AV-EDR / DNS / XXE / LFI / CMS / stego / bluetooth / firmware / SCADA / DB / VoIP / anti-forensics / AD-LDAP / web-deserialization / email) |
| **Distinguished sprint** | v0.1.22 - v0.1.27 | 5 -> 17 Distinguished |
| **Expansion wave 2** | v0.1.28 - v0.1.31 | 70 -> 91 skill domains (darkweb / threat-hunting / blockchain / payment / llm-red-team / honeypot / k8s / secret-mgmt / ai-agent / iot / detection-eng / agentic-pentest / cloud-identity / physical / quantum / email-deep) |
| **100% Excellent+** | v0.1.32 | 91/91 Excellent+, zero Strong remaining |
| **GitHub-trending expansion** | v0.1.33 - v0.1.35 | 91 -> 103 (5G / automotive / mobile-deep / cloud-native-vuln / macOS / UAV / game-anticheat / mainframe / ICS-fieldbus / HF/VHF / blockchain-L2 / RTOS) |
| **E-plan quality lift** | v0.1.36 | 19 -> 28 Distinguished (+9) |
| **Wave 7 expansion** | v0.1.37 | 103 -> 107 (storage-SAN / hypervisor / satellite-LEO / AD CS) |
| **E-plan again** | v0.1.38 | 28 -> 32 Distinguished, first time breaking 30, min score 85.1 (quality debt cleared) |
| **Wave 8 expansion (current)** | **v0.1.39** | **107 -> 111** (CI/CD supply chain / PAM / CSPM-CASB / SASE-SSE). First time a new skill entered Distinguished on baseline (pam-privilege-attack 92.0) |

### 7.2 Current Quality Snapshot (v0.1.39)

| Tier | Count | Representative Skills |
|------|-------|----------------------|
| **Distinguished (92+)** | **33** | secret-management-attack (94.6) · social-intelligence (93.8) · sdr-rf-attack (93.6) · article-writing (93.6) · deep-research (93.5) · payload-generation (93.1) · scada-ics-security (93.0) · ad-cs-abuse (93.0) · vulnerability-assessment (93.0) · 5g-telecom-attack (92.7) · embedded-rtos-security (92.7) · agentic-pentest (92.6) · autonomous-loops (92.6) · verification-loop (92.6) · quantum-crypto-attack (92.5) · osint (92.5) · vpn-attack (92.5) · ai-security (92.3) · council (92.3) · network-tunneling-proxy (92.3) · crypto-attacks (92.2) · macos-security (92.2) · username-profiling (92.2) · web-deserialization (92.2) · cloud-security (92.1) · hf-vhf-radio-attack (92.1) · email-security-deep (92.0) · network-pentest (92.0) · security-bounty-hunter (92.0) · pam-privilege-attack (92.0) · security-misconfiguration (92.8) · container-security (92.8) · web-xss (92.0) |
| **Excellent (80-91.9)** | **78** | storage-san-attack (91.5) · dns-attacks (91.1) · kubernetes-attack (90.2) · blockchain-web3 (90.2) · cloud-identity-attack (89.0) · ci-cd-supply-chain-attack (89.2) · cspm-casb-attack (88.5) · sase-sse-attack (88.2) · ... |
| Strong (60-80) | **0** | -- |
| Adequate (40-60) | **0** | -- |
| Weak (0-40) | **0** | -- |

**Average: 88.78** | **111/111 Excellent+ (100%)** | **33 Distinguished**

### 7.3 What's Coming in v0.1.40

Following the alternating expansion/quality rhythm, v0.1.40 will likely return to the **quality-lift track**. Candidates:

- **A-track Distinguished sprint** -- 7 skills are stuck at 89-91.9 (storage-san-attack 91.5, dns-attacks 91.1, blockchain-web3 90.2, kubernetes-attack 90.2, darkweb-intel 89.2, av-edr-evasion 89.1, cloud-identity-attack 89.0). Adding one more guide to each would push most of them past 92+
- **Bottom lift** -- 5 skills are stuck at 85-86 (chronicle 85.1, cloud-native-vuln-research 85.2, email-protocol-attack 85.2, game-anticheat-bypass 85.2, multi-agent-collaboration 85.4). Lifting them to 88+ raises the floor again
- **Wave 8 cohort deepening** -- Add a second guide each for ci-cd-supply-chain-attack, cspm-casb-attack, and sase-sse-attack
- **Wave 9 expansion** -- Candidates include GitOps security, QKD attacks, Open Banking/PSD2, HSM attacks, CPS cyber-physical systems

---

## 8. FAQ

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
- Verify the `description` field in the YAML frontmatter -- this is the primary signal for skill matching

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

# After pulling, run quality scoring once to confirm all skills are intact
bash validation/SCORE.sh
```

### Q8: Can I use kali-claw on a non-Kali system?

**Problem:** You do not have Kali Linux installed.

**Solution:** Yes, but with limitations.

- **Without Kali Linux:** kali-claw can still help with research, learning, planning, and report writing. It just cannot execute security tools like nmap, sqlmap, etc.
- **With remote Kali:** Set up SSH access (see Section 2.2) to a Kali machine.
- **With Docker:** Run a Kali container (see Section 2.3) on any system with Docker installed.

### Q9: How do I contribute a new skill or improvement?

1. Fork the repo and create a feature branch
2. Follow the "6.2 Custom Skills" workflow to create the skill domain
3. Run `bash validation/SCORE.sh --skill <your-skill>` and confirm it reaches Excellent (80+)
4. Open a PR with score evidence and 1-2 real-world scenario test results

See the root README.md for the PR template.

### Q10: How do I know which skills are strongest / most in need of improvement?

```bash
# View all skill scores (high to low)
cat validation/QUALITY-SCORE-TRACKER.md

# Or inspect a single skill
cat validation/evidence/quality-scores/<skill-name>.json
```

The JSON includes the 4-component breakdown (skill_md / payloads_md / test_cases_md / guides), so you can pinpoint exactly where the weak spot is.

---

## 9. Core File Reference

| File | Purpose | When to Modify |
|------|---------|---------------|
| `SOUL.md` | Agent personality, 12 Hacker Laws, behavioral guidelines, boundaries | Customizing personality, adding new laws |
| `AGENTS.md` | Workspace config, session startup sequence, memory system rules | Adjusting session flow, changing agent name/role |
| `IDENTITY.md` | Skill tags table (111 rows), personality traits, creature type | Adding/removing skill domains, changing agent identity |
| `USER.md` | Captain profile, preferences, interests, current focus | New user first-time setup, updating preferences |
| `MEMORY.md` | Long-term distilled knowledge and key decisions | Generally do NOT edit manually -- let the agent manage it |
| `TOOLS.md` | 518 tool inventory, learning progress, learning strategy | Adding new tools, updating mastery status |
| `HEARTBEAT.md` | Automated heartbeat tasks: health, learning, security, maintenance | Adjusting check frequency, adding custom monitoring |
| `CHANGELOG.md` | Full version change log | Generally do NOT edit manually |
| `skills/` | 111 skill domains with payloads, test cases, and guides | Adding new skills, updating existing payloads |
| `validation/` | Automation script suite (SCORE.sh, orchestrator.sh, ...) | Adjusting scoring weights, adding new scenarios |
| `validation/engagement-template/` | Authorized pentest templates (targets/scope/report) | Adding new engagement types |
| `memory/` | Daily memory logs (`YYYY-MM-DD.md`) | Generally do NOT edit manually |
| `chronicle/` | Monthly milestone tracking (`YYYY-MM/*.md`) | Generally do NOT edit manually |
| `docs/` | Long-form design docs and plans | Major architectural changes |
| `RELEASE-v0.1.X.md` | Per-version release notes | Generally do NOT edit manually |

**For first-time use, you only need to modify 4 files**: USER.md, SOUL.md, IDENTITY.md, AGENTS.md (see Section 3.4).

All other files are maintained automatically by the agent and usually do not need manual editing.

---

_This guide covers OpenClaw + kali-claw **v0.1.39** (111 skill domains, 33 Distinguished, 100% Excellent+). For the latest updates, visit the [kali-claw repository](https://github.com/brucesongs/kali-claw)._
