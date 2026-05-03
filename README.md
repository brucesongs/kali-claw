# kali-claw

> An AI-powered penetration testing agent built on Kali Linux, mastering all 518 security tools through continuous self-directed learning.

**kali-claw** is a self-evolving security agent from the [OpenClaw](https://github.com/openclaw/openclaw.git) project. It operates 24/7 on Kali Linux, systematically learning and practicing penetration testing across 31 security domains. It thinks like a hacker — first principles, divergent thinking, assume breach — and acts like a senior engineer: direct, hands-on, results-driven.

---

## Features

- **31 Security Skill Domains** — From OSINT and web exploitation to cloud security and digital forensics, each with structured payloads, test cases, and learning guides
- **12 Hacker Laws** — Core behavioral guidelines derived from real-world security philosophy
- **Layered Memory System** — Daily logs + distilled long-term memory + monthly chronicles for persistent knowledge across sessions
- **Heartbeat Task Framework** — Automated health checks, security scans, learning progress tracking, and knowledge maintenance
- **Fully Reusable** — Copy the workspace, change 4 files, and you have a new security agent

---

## Quick Start

### Prerequisites

- [OpenClaw](https://github.com/openclaw/openclaw.git) installed and configured
- **Recommended**: Kali Linux environment — either install OpenClaw directly on Kali Linux, or provide SSH access from your OpenClaw host to a Kali Linux machine so kali-claw can execute security tools remotely

### 1. Install OpenClaw

```bash
npm install -g openclaw@latest
```

See the [official documentation](https://docs.openclaw.ai/) for detailed installation and configuration options.

### 2. Create a dedicated agent

It is **not recommended** to use the `main` agent directly. Create a dedicated agent for this workspace:

```bash
openclaw agents add kali-claw --workspace ~/.openclaw/workspace-kali-claw
```

This creates an isolated agent with its own workspace, auth, and routing. See [`openclaw agents`](https://docs.openclaw.ai/cli/agents) for full options including `--model`, `--bind`, and `--non-interactive`.

### 3. Clone this repository into the workspace

```bash
cd ~/.openclaw/workspace-kali-claw/
git clone https://github.com/<repo-path>.git .
```

The agent will automatically read `SOUL.md`, `AGENTS.md`, `USER.md`, and `MEMORY.md` on startup to initialize its identity and context.

### 4. Start the agent

```bash
openclaw gateway start
```

Then interact with kali-claw:

```
> Scan target 192.168.1.100 with nmap for open ports and services
> Teach me how SQL injection works with hands-on examples
> Run an OSINT reconnaissance on example.com
```

---

## How It Works

### Architecture

```
kali-claw/
├── SOUL.md              # Identity + 12 Hacker Laws (the agent's personality)
├── AGENTS.md            # Workspace config + session startup sequence
├── IDENTITY.md          # Skill tags + personality traits
├── USER.md              # Captain (user) profile
├── MEMORY.md            # Long-term distilled knowledge
├── TOOLS.md             # Tool quick reference + learning progress
├── HEARTBEAT.md         # Periodic heartbeat task framework
├── skills/              # 31 security skill domains
│   ├── api-security/
│   │   ├── SKILL.md         # Skill definition + use cases
│   │   ├── payloads.md      # Attack payloads
│   │   ├── test-cases.md    # Structured test cases
│   │   └── guides/          # Deep-dive learning guides
│   ├── web-sqli/
│   ├── web-xss/
│   ├── cloud-security/
│   └── ... (31 domains total)
├── memory/              # Daily memory logs (YYYY-MM-DD.md)
├── chronicle/           # Monthly chronicle of major events
├── bak/                 # Automatic backups
└── README.md            # This file
```

### Session Lifecycle

Every time the agent starts a new session:

1. **Read SOUL.md** — Load identity and hacker laws
2. **Read USER.md** — Understand who it's helping
3. **Read recent memory** — Get context from today and yesterday
4. **Read MEMORY.md** — Load long-term distilled knowledge

The agent wakes up fresh each session but carries continuity through its file-based memory system.

### Memory System

| Layer | File | Purpose |
|-------|------|---------|
| Daily | `memory/YYYY-MM-DD.md` | Raw activity logs for the day |
| Long-term | `MEMORY.md` | Distilled knowledge, key decisions, lessons learned |
| Chronicle | `chronicle/YYYY-MM/*.md` | Monthly record of major events |

Knowledge flows upward: daily logs are regularly distilled into MEMORY.md, and major milestones are recorded in the chronicle.

---

## Security Skills

31 domains organized by the OWASP and MITRE frameworks:

| Domain | Description | Key Topics |
|--------|-------------|------------|
| `api-security` | API security testing | REST/GraphQL testing, auth bypass, rate limiting |
| `binary-reverse` | Binary analysis & reverse engineering | radare2, exploit development, malware analysis |
| `cloud-security` | Cloud platform security | AWS/Azure/GCP, IAM, S3 exposure, metadata attacks |
| `container-security` | Container & K8s security | Docker escape, K8s RBAC, image scanning |
| `crypto-attacks` | Cryptographic vulnerability testing | Weak algorithms, certificate issues, padding oracle |
| `digital-forensics` | Digital forensics | Disk analysis, memory forensics, network forensics |
| `insecure-design` | Insecure design detection | Threat modeling, abuse cases, design patterns |
| `logging-monitoring` | Logging & monitoring security | Log injection, detection evasion, SIEM bypass |
| `mobile-security` | Mobile application security | Android/iOS testing, certificate pinning, data leakage |
| `network-pentest` | Network penetration testing | Scanning, exploitation, lateral movement |
| `osint` | Open source intelligence | People search, domain recon, data aggregation |
| `password-attack` | Password attack techniques | Dictionary attacks, hash cracking, rule-based brute force |
| `post-exploitation` | Post-exploitation operations | Persistence, privilege escalation, data exfiltration |
| `recon-osint` | Reconnaissance & OSINT | Subdomain enum, port scanning, technology fingerprinting |
| `security-misconfiguration` | Security misconfiguration detection | Default creds, verbose errors, directory listing |
| `social-engineering` | Social engineering | Phishing, pretexting, baiting techniques |
| `supply-chain-security` | Software supply chain security | Dependency attacks, CI/CD poisoning, integrity verification |
| `vulnerability-assessment` | Vulnerability assessment | Automated scanning, manual testing, risk rating |
| `web-access-control` | Broken access control | IDOR, privilege escalation, forced browsing |
| `web-auth-bypass` | Authentication bypass | Brute force, session attacks, OAuth flaws |
| `web-sqli` | SQL injection | Union-based, blind, time-based, double query |
| `web-ssrf` | Server-Side Request Forgery | Internal scanning, cloud metadata, protocol smuggling |
| `web-xss` | Cross-Site Scripting | Reflected, stored, DOM-based, CSP bypass |
| `wifi-pentest` | WiFi penetration testing | WPA cracking, WPS attacks, evil twin |
| `chronicle` | Chronicle system | Event logging, milestone tracking |
| `deep-research` | Multi-source intelligence research | CVE deep-dive, threat actor profiling, attack technique investigation, cited reports |
| `security-bounty-hunter` | Bug bounty vulnerability hunting | Exploitable vulnerability discovery, PoC development, responsible disclosure reporting |
| `terminal-ops` | Evidence-first terminal operations | Structured command execution, evidence chain protocol, verified state tracking |
| `search-first` | Research before exploit | Exploit/tool search workflow, existing solution discovery, decision matrix |
| `security-review` | Comprehensive security review | OWASP Top 10 checklist, source code audit, configuration review, dependency scanning |
| `repo-scan` | Cross-stack source code audit | File classification, library detection, module verdicts, security hotspot analysis |

Each skill contains:
- **SKILL.md** — Description, use cases, tools, and workflow
- **payloads.md** — Curated attack payloads and testing commands
- **test-cases.md** — Structured test cases with steps and expected results
- **guides/** — Deep-dive learning guides with hands-on exercises

---

## The 12 Hacker Laws

These laws define how kali-claw thinks and acts:

1. **First Principles Thinking** — Reason from fundamental facts, not tools or assumptions
2. **Divergent Thinking First** — Always consider 3+ approaches before choosing
3. **Minimize Attack Surface** — Less exposure = less risk
4. **Defense in Depth** — Never rely on a single security layer
5. **Least Privilege** — Grant only necessary access
6. **Assume Breach** — Design as if the attacker is already inside
7. **Obscurity Is Not Security** — Security through design, not hiding
8. **Trust but Verify** — Validate all inputs unconditionally
9. **Information Wants to Be Free** — Share knowledge, protect sensitive data
10. **Skill Over Credentials** — Judge by capability, not title
11. **The Weakest Link Is Human** — Always consider the human factor
12. **Murphy's Security Law** — If it can be exploited, it will be

---

## Creating a New Agent

To create a different security agent based on this workspace:

### 1. Copy the workspace

```bash
cp -r kali-claw/ <new-agent-name>/
cd <new-agent-name>/
```

### 2. Modify these 4 files

| File | What to Change |
|------|----------------|
| `AGENTS.md` | "Agent Config" block: name, environment, role, specialty |
| `IDENTITY.md` | Name, role description, skill tags, personality traits |
| `SOUL.md` | Nickname and role description in "Identity" section |
| `USER.md` | Captain information |

### 3. Clean up historical data

```bash
rm -f memory/*.md memory/alerts.txt
rm -rf chronicle/
```

### 4. Keep unchanged

The following are universal and reusable as-is:
- **Hacker Laws** in `SOUL.md` — applies to all security agents
- **Heartbeat framework** in `HEARTBEAT.md`
- **All 31 skills** in `skills/`
- **All guides** in `skills/*/guides/`

### Example: Web Security Agent

```
AGENTS.md:
  Agent Name: web-hunter
  Role: Web Security Researcher
  Specialty: Web penetration testing + vulnerability discovery

IDENTITY.md:
  Name: web-hunter
  Skill tags: Keep Web Security rows, simplify others

SOUL.md:
  Nickname: web-hunter
  Keep hacker laws unchanged
```

### Example: Cloud Security Agent

```
AGENTS.md:
  Agent Name: cloud-sentinel
  Role: Cloud Security Auditor
  Specialty: AWS/Azure/GCP security + Container security

IDENTITY.md:
  Name: cloud-sentinel
  Skill tags: Focus on cloud security and container security

TOOLS.md:
  Core tools: pacu, scoutsuite, kubeaudit, trivy
```

---

## Core Files Reference

| File | Purpose |
|------|---------|
| `SOUL.md` | Agent identity, hacker laws, behavioral rules, boundaries |
| `AGENTS.md` | Workspace config, session startup sequence, memory system |
| `IDENTITY.md` | Skill tags table, personality traits |
| `USER.md` | Captain profile, preferences, current focus |
| `MEMORY.md` | Long-term distilled knowledge and key decisions |
| `TOOLS.md` | Tool inventory, learning progress, learning strategy |
| `HEARTBEAT.md` | Automated heartbeat: health, learning, security, maintenance |

---

## Project Info

| | |
|---|---|
| **Project** | OpenClaw Security Research |
| **Version** | 0.1.1 |
| **Runtime** | Kali Linux 2025-2 (aarch64) |
| **Tools** | 518 Kali security tools (100% coverage) |
| **Skill Domains** | 31 |
| **Created** | 2026-03-14 |
| **License** | MIT |

---

_Built with the OpenClaw Agent Framework._
