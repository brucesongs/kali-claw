# kali-claw

> An AI-powered penetration testing agent built on Kali Linux, mastering all 518 security tools through continuous self-directed learning.

**kali-claw** is a self-evolving security agent from the [OpenClaw](https://github.com/openclaw/openclaw.git) project. It operates 24/7 on Kali Linux, systematically learning and practicing penetration testing across 74 security domains. It thinks like a hacker — first principles, divergent thinking, assume breach — and acts like a senior engineer: direct, hands-on, results-driven.

---

## Features

- **74 Security Skill Domains** — From OSINT and web exploitation to cloud security, AI/LLM security, exploit development, hardware/embedded systems, Bluetooth/RFID/NFC, SCADA/ICS, firmware reverse engineering, VoIP/SIP, database attacks, Active Directory/LDAP attacks, and anti-forensics, each with structured payloads, test cases, and learning guides
- **12 Hacker Laws** — Core behavioral guidelines derived from real-world security philosophy
- **Layered Memory System** — Daily logs + distilled long-term memory + monthly chronicles for persistent knowledge across sessions
- **Heartbeat Task Framework** — Automated health checks, security scans, learning progress tracking, and knowledge maintenance
- **Fully Reusable** — Copy the workspace, change 4 files, and you have a new security agent

---

## Guides

### Usage Guide

| Language | File |
|----------|------|
| 中文 | [GUIDE-OPENCLAW-zh.md](GUIDE-OPENCLAW-zh.md) |
| English | [GUIDE-OPENCLAW-en.md](GUIDE-OPENCLAW-en.md) |

### Migration Guides

kali-claw is a portable skill package — you can use it with multiple AI agent platforms:

| Platform | 中文 | English |
|----------|------|---------|
| Hermes Agent | [GUIDE-HERMES-zh.md](GUIDE-HERMES-zh.md) | [GUIDE-HERMES-en.md](GUIDE-HERMES-en.md) |
| Claude Code | [GUIDE-CLAUDECODE-zh.md](GUIDE-CLAUDECODE-zh.md) | [GUIDE-CLAUDECODE-en.md](GUIDE-CLAUDECODE-en.md) |
| OpenAI Codex CLI | [GUIDE-CODEX-zh.md](GUIDE-CODEX-zh.md) | [GUIDE-CODEX-en.md](GUIDE-CODEX-en.md) |
| OpenCode | [GUIDE-OPENCODE-zh.md](GUIDE-OPENCODE-zh.md) | [GUIDE-OPENCODE-en.md](GUIDE-OPENCODE-en.md) |

> New to OpenClaw? Start with the usage guide — it covers everything from installation to your first penetration test.

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
├── skills/              # 74 security skill domains
│   ├── api-security/
│   │   ├── SKILL.md         # Skill definition + use cases
│   │   ├── payloads.md      # Attack payloads
│   │   ├── test-cases.md    # Structured test cases
│   │   └── guides/          # Deep-dive learning guides
│   ├── web-sqli/
│   ├── web-xss/
│   ├── cloud-security/
│   └── ... (74 domains total)
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

37 domains organized by the OWASP and MITRE frameworks + 12 additional domains (knowledge operations, AI/LLM, hardware, multi-agent, MCP, bounty hunting, etc.) + 23 expanded domains (exploit development, privilege escalation, payload generation, AV/EDR evasion, DNS attacks, web XXE, file inclusion, CMS attack, steganography, network sniffing & MITM, Bluetooth/RFID/NFC, network tunneling & proxy, firmware reverse, SCADA/ICS security, database attack, VoIP/SIP attack, anti-forensics, pentest reporting, engagement manager, tool mastery, AD/LDAP attack, web deserialization, email protocol attack):

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
| `social-intelligence` | Social platform intelligence | Reddit/HN/X/YouTube OSINT, community sentiment, target profiling, dark web monitoring |
| `supply-chain-security` | Software supply chain security | Dependency attacks, CI/CD poisoning, integrity verification |
| `vulnerability-assessment` | Vulnerability assessment | Automated scanning, manual testing, risk rating |
| `web-access-control` | Broken access control | IDOR, privilege escalation, forced browsing |
| `web-auth-bypass` | Authentication bypass | Brute force, session attacks, OAuth flaws |
| `web-sqli` | SQL injection | Union-based, blind, time-based, double query |
| `web-ssrf` | Server-Side Request Forgery | Internal scanning, cloud metadata, protocol smuggling |
| `web-xss` | Cross-Site Scripting | Reflected, stored, DOM-based, CSP bypass |
| `wifi-pentest` | WiFi penetration testing | WPA cracking, WPS attacks, evil twin |
| `chronicle` | Chronicle system | Event logging, milestone tracking |
| `deep-research` | Multi-source intelligence research | CVE deep-dive, threat actor profiling, attack technique investigation, continuous monitoring, intelligence correlation, cited reports |
| `security-bounty-hunter` | Bug bounty vulnerability hunting | Exploitable vulnerability discovery, PoC development, responsible disclosure reporting |
| `terminal-ops` | Evidence-first terminal operations | Structured command execution, evidence chain protocol, verified state tracking |
| `search-first` | Research before exploit | Exploit/tool search workflow, existing solution discovery, decision matrix |
| `security-review` | Comprehensive security review | OWASP Top 10 checklist, source code audit, configuration review, dependency scanning |
| `repo-scan` | Cross-stack source code audit | File classification, library detection, module verdicts, security hotspot analysis |
| `verification-loop` | Multi-phase finding verification | Exploit confirmation, false positive elimination, independent reproduction, evidence documentation |
| **`codebase-onboarding`** | **Rapid codebase intelligence** | **3 scope modes (Targeted/Exploratory/Comprehensive), language tier matrix, confidence scoring, architecture pattern recognition, 100M+ LOC strategy** |
| **`knowledge-ops`** | **Knowledge graph management** | **Entity extraction, cross-session aggregation, confidence tracking, graph visualization, pattern intelligence** |
| **`article-writing`** | **Security content creation** | **Pentest reports, CVE disclosures, blog posts, CVSS scoring, sanitization, evidence documentation** |
| **`browser-qa`** | **Automated browser testing** | **Playwright/Puppeteer, network monitoring, cookie analysis, CSRF detection, XSS payload injection** |
| **`data-scraper-agent`** | **Structured data collection** | **CVE scraping, exploit DB search, threat intel feeds, GitHub advisories, HTML parsing** |
| **`exa-search`** | **Semantic security research** | **Context-aware queries, date filtering, domain filtering, full-text extraction, API integration** |
| **`ai-fuzzing`** | **AI-assisted vulnerability discovery** | **Coverage-guided fuzzing, AFL++/libFuzzer/Honggfuzz, crash triage, Web API fuzzing, protocol fuzzing** |
| **`council`** | **Multi-perspective security analysis** | **Attack/defense/audit viewpoints, decision matrix, risk assessment, consensus building** |
| `autonomous-loops` | Safe autonomous execution patterns | Sequential pipeline, watch loop, batch processing, learning cycle, scope locks |
| `continuous-learning` | Engagement knowledge extraction | Pattern detection, confidence scoring, cross-reference linking, memory layering |
| `docker-patterns` | Docker security testing labs | Vulnerable app labs, network labs, attack chain labs, disposable testing |
| `safety-guard` | Safety enforcement layer | Scope checking, dangerous command interception, incident response, engagement rules |
| `bluetooth-rfid-nfc` | Bluetooth/BLE/RFID/NFC attacks | Device discovery, BLE GATT exploitation, MIFARE cracking, NFC cloning |
| `network-tunneling-proxy` | Network tunneling & proxying | SSH/HTTP tunneling, DNS/ICMP covert tunnels, SOCKS proxy chains, pivoting |
| `firmware-reverse` | Firmware reverse engineering | Extraction, filesystem analysis, QEMU emulation, backdoor detection |
| `scada-ics-security` | SCADA/ICS security assessment | Modbus, S7comm, EtherNet/IP, OPC UA, PLC enumeration, honeypots |
| `database-attack` | Database server attacks | Oracle TNS, Redis/MongoDB unauth, brute-force, stored procedures |
| `voip-sip-attack` | VoIP/SIP protocol attacks | SIP enumeration, eavesdropping, VLAN hopping, DoS |
| `anti-forensics` | Anti-forensic techniques | Secure deletion, log tampering, timestamp manipulation, steganographic hiding |
| `pentest-reporting` | Pentest reporting & evidence | Dradis, Faraday, screenshot capture, password analysis, evidence management |
| `ad-ldap-attack` | Enterprise | Active Directory/LDAP/Kerberos attacks, domain reconnaissance, Kerberos exploitation (AS-REP Roasting, Kerberoasting, Golden/Silver Tickets), DCSync, Pass-the-Hash, lateral movement, domain dominance | impacket-suite, bloodhound, ldapsearch, enum4linux, enum4linux-ng, kerberoast, crackmapexec, ldeep, ldapdomaindump, rpcclient |
| `web-deserialization` | Web Attack | Java/PHP/.NET deserialization, ysoserial, phpggc, gadget chains, blind detection, RCE | ysoserial, phpggc, marshalsec, ysoserial.net, gadgetprobe |
| `email-protocol-attack` | Network | SMTP enumeration, email forgery, SPF/DKIM/DMARC bypass, IMAP/Exchange attacks | smtp-user-enum, swaks, sendemail, nailgun, smtpmap, mutt, openssl |

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
- **All 74 skills** in `skills/`
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

## Roadmap

### Completed

| Version | Date | Milestone | Key Changes |
|---------|------|-----------|-------------|
| v0.1.3 | 2026-05-14 | Foundation | Tier 1 skills (`codebase-onboarding`, `knowledge-ops`) |
| v0.1.4 | 2026-05-14 | Expansion | Tier 2 skills (`article-writing`, `browser-qa`, `data-scraper-agent`, `exa-search`) |
| v0.1.5 | 2026-05-14 | Frontier Domains | Added AI Fuzzing + Council; three-perspective framework (Attack/Defense/Audit) |
| v0.1.6 | 2026-05-14 | Infrastructure Ops | 10 infrastructure skills enriched (FULL/PARTIAL/MINIMAL strategy) |
| v0.1.7 | 2026-05-16 | 49 Domains | Added AI Security, Hardware Security, Multi-Agent Collaboration, MCP Server Patterns (45→49) |
| v0.1.8 | 2026-05-22 | Full Enrichment | All 49 skills at FULL enrichment (SKILL.md + payloads + test-cases + guides) |
| v0.1.9 | 2026-05-22 | Validation Infra | Practice validation: 49 test cases, execution playbook, 5-level status system |
| v0.1.10 | 2026-05-22 | Integration Tests | 7 cross-skill integration scenarios, all PASS (recon→exploit→verify→report pipelines) |
| v0.1.11 | 2026-05-23 | Quality Scoring | Automated SCORE.sh (7 metrics, 4 components); baseline: 22 Weak, 25 Adequate, 2 Strong |
| v0.1.12 | 2026-05-25 | First Improvement | 16 guides added; Weak 22→9, Strong 2→20, Excellent 0→2; avg 40.5→50.5 |
| v0.1.13 | 2026-05-29 | Zero Weak | All 49 skills Adequate or above; avg 59.4, median 59.2 |
| v0.1.14 | 2026-05-30 | **100% Excellent** | **49/49 Excellent, avg 84.0, min 80.0, max 90.3**; CI quality gate; 10 integration tests |
| v0.1.15 | 2026-05-31 | **Solid Excellent** | **avg 88.6, min 85.3, max 99.7**; 18 SKILL.md expanded, 20 TC added, 26 payloads to 50+ blocks |
| v0.1.16 | 2026-06-02 | **Infrastructure + Scoring v2** | Scoring v2 (guide quality, score caps, Distinguished tier); core files synced to 49 domains; 5 cross-skill attack chain scenarios; TEMPLATE.md |
| v0.1.17 | 2026-06-03 | **Bottom Reinforcement + Distinguished Sprint + Automation** | 45 new guides; 15 key sections fixed; avg 87.5, min 84.3; cloud-security 91.2 (near Distinguished); 7 automation scripts; 2 new skill domains (engagement-manager, tool-mastery); decision trees; multi-agent collaboration |
| v0.1.18 | 2026-06-04 | **10 New Skill Domains** | 10 new skills (exploit-dev, privilege-escalation, payload-gen, av-edr-evasion, dns-attacks, web-xxe, file-inclusion, cms-attack, network-sniffing-mitm, steganography); 72 new tool references; 51→61 domains |
| v0.1.19 | 2026-06-09 | **8 New Blank-Coverage Domains** | 8 new skills (bluetooth-rfid-nfc, network-tunneling-proxy, firmware-reverse, scada-ics-security, database-attack, voip-sip-attack, anti-forensics, pentest-reporting); 70 new tool references; 61→69 domains |
| v0.1.20 | 2026-06-10 | **+1 domain (ad-ldap-attack), 70/70 Excellent (100%)** | +1 domain (ad-ldap-attack), 70/70 Excellent (100%), avg 86.5 |
| v0.1.21 | 2026-06-10 | **+2 domains (web-deserialization, email-protocol-attack), first Distinguished (network-pentest 92.0), avg 86.9** | +2 domains (web-deserialization, email-protocol-attack), first Distinguished (network-pentest 92.0), avg 86.9 |
| v0.1.22 | 2026-06-10 | **+2 domains (sdr-rf-attack, vpn-attack), 2 Distinguished, avg 87.0** | +2 domains (sdr-rf-attack, vpn-attack); Distinguished sprint: cloud-security 92.1; 72→74 domains |
| v0.1.23 | 2026-06-10 | **5 Distinguished milestone, guide quality sprint** | article-writing 93.6, vulnerability-assessment 93.0, autonomous-loops 92.6; 12 guides expanded; avg 87.0 |
| v0.1.24 | 2026-06-10 | **8 Distinguished milestone, Distinguished sprint + bottom lift** | +3 Distinguished (osint 92.5, social-intelligence 93.8, verification-loop 92.6); 5 bottom skills lifted; avg 87.3 |
| v0.1.25 | 2026-06-10 | **11 Distinguished milestone, Distinguished sprint + bottom lift** | +3 Distinguished (security-misconfiguration 92.8, security-bounty-hunter 92.0, web-xss 92.0); 3 bottom skills lifted (+6 avg); avg 87.7 |

### Current Quality Snapshot (v0.1.25, scoring v2)

| Tier | Count | Skills |
|------|-------|--------|
| Distinguished (92+) | **11** | social-intelligence (93.8), article-writing (93.6), vulnerability-assessment (93.0), security-misconfiguration (92.8), autonomous-loops (92.6), verification-loop (92.6), osint (92.5), cloud-security (92.1), network-pentest (92.0), security-bounty-hunter (92.0), web-xss (92.0) |
| Excellent (80-91.9) | **63** | All remaining skill domains |
| Strong (60-80) | 0 | — |
| Adequate (40-60) | 0 | — |
| Weak (0-40) | 0 | — |

**Average score: 87.7** | **74/74 Excellent or above** | **11 Distinguished**

### Future Exploration

| Topic | Description |
|-------|-------------|
| Cross-skill advanced scenarios | Multi-skill composite attack chain testing |
| Live pentest validation | Execute full attack chains on authorized targets, produce real pentest reports |
| AI-driven exploit dev | AI-driven exploit development and payload customization |

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
| **Version** | 0.1.21 |
| **Runtime** | Kali Linux 2025-2 (aarch64) |
| **Tools** | 518 Kali security tools (100% coverage) |
| **Skill Domains** | 72 |
| **Created** | 2026-03-14 |
| **License** | MIT |

---

_Built with the OpenClaw Agent Framework._
