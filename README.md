# kali-claw

> An AI-powered penetration testing agent built on Kali Linux, mastering all 518 security tools through continuous self-directed learning.

**kali-claw** is a self-evolving security agent from the [OpenClaw](https://github.com/openclaw/openclaw.git) project. It operates 24/7 on Kali Linux, systematically learning and practicing penetration testing across **137 security domains**. It thinks like a hacker — first principles, divergent thinking, assume breach — and acts like a senior engineer: direct, hands-on, results-driven.

> **Current Version**: **v0.2.4** (2026-08-08) — **Phase 2 Track 1 Minor Release**（139 SKILLs，新增 EU AI Act 合规 + AI Agent 供应链攻击 2 个 P0 SKILL；skill-lint 0 errors / 0 warnings）。详见 [RELEASE-v0.2.4.md](RELEASE-v0.2.4.md)。

---

## Features

- **137 Security Skill Domains** — From OSINT and web exploitation to cloud security + cloud-identity (Entra ID/Okta/Auth0), AI/LLM security (LLM red team + AI agent security + agentic pentest), exploit development, hardware/embedded systems, Bluetooth/RFID/NFC, SCADA/ICS, firmware reverse engineering, VoIP/SIP, database attacks, Active Directory/LDAP attacks, anti-forensics, username-based OSINT dossier generation (Maigret), dark-web intelligence, threat hunting + defensive deception (honeypots) + detection engineering, blockchain/Web3 security, payment security (PCI-DSS), Kubernetes red team, secret-management attack (SAST/secrets), IoT application-layer pentest, physical security testing (locks/badges/USB weapons), quantum/post-quantum/national crypto attacks, deep phishing infrastructure (AiTM/gateway bypass), 5G telecom attack (PFCP/GTP/IMSI catchers/O-RAN), automotive vehicle security (CAN/UDS/key fobs/EV charging), mobile app instrumentation (Frida/Objection/r2frida), cloud-native vulnerability research (CVE methodology/PoC reproduction/nuclei templates), macOS security (SIP/TCC/ESF/Keychain/Apple Silicon), UAV/drone security (MAVLink/PX4/GPS spoofing/DroneID), game anti-cheat bypass (EAC/BattlEye/Vanguard/BYOVD), mainframe security (z/OS/RACF/CICS/DB2/JES2), ICS fieldbus attack (Profibus/DNP3/IEC 61850/IEC 60870-5/EtherCAT/PROFINET), HF/VHF radio attack (ADS-B/AIS/ACARS/POCSAG/APRS), blockchain L2 attack (Lightning Network/Optimism/Arbitrum/zkSync/cross-chain bridges), embedded RTOS security (VxWorks/QNX/FreeRTOS/ThreadX/Zephyr), storage/SAN attack (iSCSI/FC/NFSv4/SMB3/S3/NetApp/Dell EMC/QNAP), hypervisor introspection (VMware ESXi/Hyper-V/KVM/Xen/LibVMI/DRAKVUF/VENOM), satellite/LEO security (Starlink/Iridium/Viasat KA-SAT/DVB-S2/VSAT), AD CS abuse (ESC1-ESC15/PetitPotam/Certifried/Certipy), CI/CD supply chain attack (Jenkins/GitLab CI/GitHub Actions/xz-utils/SolarWinds), PAM privilege attack (CyberArk/BeyondTrust/Delinea/ManageEngine), CSPM/CASB attack (Wiz/Prisma Cloud/Netskope/OPA/Kyverno policy bypass), and SASE/SSE attack (Zscaler ZIA/ZPA, Netskope, Cloudflare One, Cisco Umbrella), each with structured payloads, test cases, and learning guides
- **Defense Triple Coverage** — **All 137 SKILLs** include Defense Perspective (table format) + Detection Methods (with SIEM rules: Sigma/Splunk SPL/Sysmon/Falco) + Defense Evasion Techniques — **100% coverage**
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
├── skills/              # 137 security skill domains (v0.2.0.2)
│   ├── api-security/
│   │   ├── SKILL.md         # Skill definition + Defense Triple (Defense Perspective + Detection Methods + Defense Evasion)
│   │   ├── payloads.md      # Attack payloads
│   │   ├── test-cases.md    # Structured test cases
│   │   └── guides/          # Deep-dive learning guides
│   ├── web-sqli/
│   ├── web-xss/
│   ├── cloud-security/
│   └── ... (137 domains total)
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
| `username-profiling` | OSINT | Maigret single-username dossier, cross-platform account discovery (3,000+ sites), recursive pivot, identity graph | maigret, sherlock, whatsmyname, holehe, blackbird |
| `darkweb-intel` | OSINT | Tor/onion hidden-service enumeration, dark-net marketplace intelligence, leak-site monitoring, actor attribution | tor, ahmia, onionsearch, darkdump, intelx, shodan (onion), hunchly |
| `threat-hunting` | Defense | Hypothesis-driven hunts, SIEM/EDR telemetry pivoting, ATT&CK detection engineering, purple-team validation | splunk, elk, sentinel, zeek, veliciraptor, yara, sigma, mitre-attack |
| `blockchain-web3` | Blockchain | Smart-contract auditing, DeFi exploit chains, wallet/key management, bridge/oracle attacks | slither, mythril, echidna, foundry, ganache, securify, solidity-coverage |
| `payment-security` | Financial | PCI-DSS assessment, card-data flow, 3DS/SAML SSO, fraud detection, webhook signing | burpsuite, pwntools, openssl, gitleaks, testssl, token-explorer |
| `llm-red-team` | AI Red Team | LLM/generative AI red team: prompt injection, jailbreaking, model extraction, RAG poisoning, agent tool abuse | promptfoo, garak, PyRIT, PurpleLlama, AI-Infra-Guard, llm-guard |
| `deception-honeypot` | Defense | Defensive deception: SSH/web/ICS/AI honeypots, honeytokens, canary deployment, IOC extraction | T-Pot, Cowrie, OpenCanary, HFish, Beelzebub, Conpot, canarytokens |
| `kubernetes-attack` | Cloud-Native | K8s red team: RBAC abuse, pod escape, SA token theft, etcd attacks, EKS/GKE/AKS pivot | kubectl, CDK, peirates, kube-hunter, kubescape, stratus-red-team, k8s-goat |
| `secret-management-attack` | AppSec | Secrets/SAST: gitleaks, semgrep, trufflehog, infisical, Vault/CI-CD/registry exploitation | gitleaks, semgrep, trufflehog, infisical, bearer, DeepAudit, apkleaks, cariddi |
| `ai-agent-security` | AI Emerging | Offensive AI agent testing: MCP tool poisoning, indirect prompt injection, RAG poisoning, agent sandbox escape | HexStrike AI, AI-Infra-Guard, mcp-scan, MCP Inspector, garak, picklescan |
| `iot-pentest` | IoT | IoT application-layer: MQTT broker abuse, CoAP attacks, AMQP, cloud IoT backends, mobile companion | mosquitto, MQTT-Pwn, IoT-Goat, EMQX, coap-client, chip-tool, Shodan |
| `detection-engineering` | Defense | Detection-as-code: Sigma rules, YARA signatures, SPL/KQL/EQL, ATT&CK mapping, FP tuning | SigmaHQ, Yara-Rules, Loki, yarGen, hayabusa, SigmaCLI, zircollo |
| `agentic-pentest` | AI Meta | LLM-driven autonomous pentest: PentestGPT, HexStrike, Viper, multi-agent team coordination, HITL | PentestGPT, HexStrike AI, Viper, PentestAgent, AI-Infra-Guard, AutoPWN |
| `cloud-identity-attack` | Enterprise Cloud | Azure AD/Entra ID, Okta, Auth0, Ping federation abuse, OAuth token theft, SAML forgery, CA bypass, MFA fatigue | ROADtools, AADInternals, MicroBurst, MFASweep, TokenTactics, AzureHound, okta-cli |
| `physical-security-testing` | Physical | Lock bypass (pin/tubular/wafer), RFID/NFC badge cloning, USB weapons (Ducky/Bunny), drop boxes, on-site ops | Proxmark3, ESP-RFID-Tool, Walrus, LAN Turtle, USB Rubber Ducky, Bash Bunny, Packet Squirrel |
| `quantum-crypto-attack` | Cryptography | Post-quantum migration risks, NIST PQC, hybrid TLS, QKD/BB84, SM2/SM3/SM4 国密, lattice side-channel | liboqs, OQS-OpenSSL, GmSSL, cloudflare/circl, hashsigs-solidity, Qiskit |
| `email-security-deep` | AppSec | AiTM phishing infra (evilginx2/modlishka), gateway bypass (Proofpoint/Mimecast/Cisco ESA), MFA bypass, email bombing | evilginx2, evilgophish, modlishka, gophish, King-Phisher, espoofer |

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
- **All 91 skills** in `skills/`
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
| v0.1.26 | 2026-06-11 | **15 Distinguished milestone, Distinguished sprint + bottom lift** | +4 Distinguished (payload-generation 93.1, vpn-attack 92.5, network-tunneling-proxy 92.3, web-deserialization 92.2); avg 88.0 |
| v0.1.27 | 2026-06-11 | **17 Distinguished milestone, Distinguished sprint + bottom lift** | +2 Distinguished (scada-ics-security 93.0, council 92.3); 3 bottom skills lifted; avg 88.2 |
| v0.1.28 | 2026-06-16 | **Domain expansion: +4 new skill domains (75→79)** | +4 domains (darkweb-intel, threat-hunting, blockchain-web3, payment-security); first defensive skill (threat-hunting); first financial skill (payment-security); first blockchain skill (blockchain-web3); 75→79 domains |
| v0.1.29 | 2026-06-17 | **GitHub-trending expansion: +4 new skill domains (79→83)** | +4 domains (llm-red-team, deception-honeypot, kubernetes-attack, secret-management-attack); driven by GitHub open-source analysis (150k+ cumulative stars); 8 new skills scored (v0.1.28 + v0.1.29); 79→83 domains |
| v0.1.30 | 2026-06-17 | **GitHub-trending expansion wave 2: +4 new skill domains (83→87)** | +4 domains (ai-agent-security, iot-pentest, detection-engineering, agentic-pentest); ai-emerging + iot + defense + ai-meta categories all entered; 4 new skills scored; 83→87 domains |
| v0.1.31 | 2026-06-17 | **GitHub-trending expansion wave 3: +4 new skill domains (87→91)** | +4 domains (cloud-identity-attack, physical-security-testing, quantum-crypto-attack, email-security-deep); fills identity/physical/quantum/phishing-infra gaps; 91 total |
| v0.1.32 | 2026-06-21 | **100% Excellent+ milestone (zero new skills, pure quality lift)** | Lifted last 2 Strong-tier skills (username-profiling 77.7→91.6, quantum-crypto-attack 79.7→90.8); added 2nd guide file to all 12 v0.1.28-v0.1.30 cohort skills (+10,180 lines); 91/91 Excellent+ achieved; average 87.51→88.19 |
| v0.1.33 | 2026-06-22 | **GitHub-trending expansion wave 4: +4 new skill domains (91→95)** | +4 domains (5g-telecom-attack, automotive-vehicle-security, mobile-app-instrumentation, cloud-native-vuln-research); 2 new categories (telecom, automotive); mobile-deep extends mobile; cloud-native extends; 3/4 baselined Excellent, 1 borderline Strong (automotive 79.0); 95 total |
| v0.1.34 | 2026-06-21 | **GitHub-trending expansion wave 5 + automotive lift (95→99, 100% Excellent+ restored)** | +4 domains (macos-security, uav-drone-security, game-anticheat-bypass, mainframe-security); 4 new categories (macos, aerial, game-security, mainframe); automotive-vehicle-security lifted 79.0→88.7; 4/4 new skills baselined Excellent; **99/99 Excellent+ (100%)**; 0 Strong remaining; 99 total |
| v0.1.35 | 2026-06-24 | **GitHub-trending expansion wave 6: +4 deep-dive skill domains (99→103)** | +4 domains (ics-fieldbus-attack, hf-vhf-radio-attack, blockchain-l2-attack, embedded-rtos-security); 4 new categories (fieldbus, lowfreq-radio, blockchain-l2, rtos); deepens existing SCADA/SDR/blockchain/firmware coverage rather than entering new verticals; 4/4 new skills baselined Excellent; **103/103 Excellent+ (100%)** maintained; cohort avg 88.4 (vs v0.1.34 cohort 85.4); 103 total |
| v0.1.36 | 2026-06-25 | **E plan: Distinguished sprint + bottom lift (no new skills, +9 Distinguished)** | 9 skills lifted: 8 reached Distinguished (secret-management-attack 90.4→94.6, deep-research 90.6→93.5, 5g-telecom-attack 82.5→92.7, embedded-rtos-security 88.8→92.7, agentic-pentest 90.0→92.6, quantum-crypto-attack 90.8→92.5, macos-security 82.7→92.2, username-profiling 91.6→92.2, hf-vhf-radio-attack 89.3→92.1); email-security-deep 81.0→91.3 (Excellent+ but 0.7 below Distinguished); **Distinguished 19→28** (+9, exceeds 25+ target); avg 87.98→88.45; min 81.0→83.8; 9 new 2nd/3rd guide files; ~7,000 new lines |
| v0.1.37 | 2026-06-27 | **GitHub-trending expansion wave 7: +4 skill domains (103→107)** | +4 domains (storage-san-attack, hypervisor-introspection, satellite-leo-security, ad-cs-abuse); 4 new categories (storage, virtualization, satellite, enterprise-cloud AD CS); covers enterprise storage infrastructure + hypervisor internals + satellite/LEO comms + AD CS privilege escalation; 4/4 new skills baselined Excellent (ad-cs-abuse 91.0 near-Distinguished, storage-san-attack 89.5, hypervisor-introspection 87.4, satellite-leo-security 86.8); **107/107 Excellent+ (100%)** maintained; cohort avg 88.7 (highest of all waves); 107 total |
| v0.1.38 | 2026-06-27 | **E plan again: Distinguished sprint + bottom lift (+4 Distinguished, 28→32)** | 10 skills lifted: 4 reached Distinguished (email-security-deep 91.3→92.0, ad-cs-abuse 91.0→93.0, ai-security 89.3→92.3, crypto-attacks 89.0→92.2); 2 near-miss A-track (storage-san-attack 89.5→91.5, kubernetes-attack 89.5→90.2); 4 C-track bottom-lifted (cloud-identity-attack 83.8→89.0, mobile-app-instrumentation 84.5→87.3, dns-attacks 84.6→91.1, blockchain-web3 84.6→90.2); **Distinguished 28→32**; avg 88.46→88.75; min 83.8→85.1 (no skills below 85 anymore); 11 new guide files, ~13,500 new lines |
| v0.1.39 | 2026-06-27 | **GitHub-trending expansion wave 8: +4 skill domains (107→111)** | +4 domains (ci-cd-supply-chain-attack, pam-privilege-attack, cspm-casb-attack, sase-sse-attack); 4 new categories (supply-chain, privileged-access, cloud-posture, sase-sse); covers modern enterprise stack (CI/CD pipelines + PAM vendors + CSPM/CASB + SASE/SSE); 3/4 new skills baselined Excellent + 1 Distinguished on baseline (pam-privilege-attack 92.0); **111/111 Excellent+ (100%)** maintained; cohort avg 89.5 (highest of all 8 waves); 111 total |
| v0.1.40-v0.1.45 | 2026-06-28 ~ 2026-07-05 | **Wave 9-12 expansion (111→127)** | +16 domains across 4 waves: Wave 9-10 (+9 domains: red-team-infrastructure, threat-intel-platform-attack, malware-analysis-advanced, data-exfiltration-attack, reverse-engineering-advanced, patch-to-poc-pipeline, etc.); Wave 11 (+5 domains: data-exfil, red-team-infra, threat-intel, malware-RE, advanced-RE); Wave 12 (+7 domains including patch-to-poc-pipeline 16/16=100% on CyberGym validation) |
| v0.1.46-v0.1.47.1 | 2026-07-08 ~ 2026-07-10 | **CyberGym evaluation + 3 new exploitation SKILLs** | Released 3 new SKILLs (command-injection-advanced, concurrency-exploitation, protocol-state-exploitation) targeting 0% bug classes; full CyberGym evaluation: 635/1508 instances, 1 PASS; infrastructure improvements (closed-book isolation, auto permission mode, mirror fallback) |
| v0.2.0.1 | 2026-07-16 | **Strategic pivot: SKILL library focus** | Established kali-claw as dedicated SKILL library maintainer; new xAgent project will transform SKILLs into deliverable agents. See [RELEASE-v0.2.0.1.md](RELEASE-v0.2.0.1.md) |
| v0.2.0.2 | 2026-07-19 | **Phase 1 Day 1-2: 8 P0/P1 SKILLs upgraded** | Phase 1 Task 1.2 第一阶段启动: 3 P0 (network-pentest, post-exploitation, web-xss) + 5 P1 (web-sqli, web-ssrf, web-auth-bypass, api-security, password-attack) all bumped to v0.2.0.2 with complete Defense Triple |
| v0.2.0.3 | 2026-07-21 | **Phase 1 Day 3: 12/15 SKILLs (80%)** | +4 P1 SKILLs (privilege-escalation, social-engineering, osint, cloud-security) with comprehensive Detection Methods (Sigma/Splunk/Sysmon rules) and Defense Evasion sections |
| v0.2.0.4 | 2026-07-24 | **Phase 1 Task 1.2 Phase 1 完成 (15/15 = 100%)** 🎉 | Final 3 P1 SKILLs (container-security, binary-reverse, exploit-development) standardized. **All 15 high-priority SKILLs at v0.2.0.2 with full Defense Triple**. See [RELEASE-v0.2.0.4.md](RELEASE-v0.2.0.4.md) |
| v0.2.0.5 | 2026-07-26 | **Phase 2 Batch 1-2 + 文档基线** | 20 SKILLs standardized; repository cleanup (3.7 GB → 19 MB); all core docs aligned |
| v0.2.0.6 | 2026-07-27 | **Phase 2 半程 (50%)** | Batch 3-5 completed (30 SKILLs); cumulative 65/130 |
| v0.2.0.7 | 2026-07-28 | **Phase 2 全部完成 (130/130 = 100%)** 🎊 | Batch 6-10 completed (55 SKILLs); **all 130 SKILLs at v0.2.0.2** |
| v0.2.0.8 | 2026-07-29 | **Task 1.3 完成 (7 新 SKILL)** | 7 strategic new SKILLs: ai-safety-redteam-advanced, identity-provider-attack, data-loss-prevention-bypass, edge-computing-security, quantum-cryptography-transition, hardware-side-channel-advanced, 5g-6g-telecom-attack-advanced. SKILL total: 130 → **137** |
| **v0.2.1** | **2026-07-30** | **Phase 1 全部完成 — Stable Release** 🎯 | Task 1.4 (6 docs) + Task 1.5 (5 scripts) completed. **137/137 SKILLs at v0.2.0.2, 100% Defense Triple**. See [RELEASE-v0.2.1.md](RELEASE-v0.2.1.md) |
| v0.2.2 | 2026-08-05 | **Defense Perspective 标准化** 🛡️ | Phase 2 Track 1 月度审查：linter 升级（严格 H3 检测 + `defense_triple_required` 字段），45 H2→H3 层级修复，4 个字面打字错误修复，2 个攻击类补写 Defense Triple，1 个翻译残留清零。See [RELEASE-v0.2.2.md](RELEASE-v0.2.2.md) |
| **v0.2.3** | **2026-08-05** | **MISSING_SECTION 清零** 🧹 | Phase 2 Track 1 增量补丁：linter 智能化（模板适用性豁免 + Methodology≥50 启发式），56 → 0 warnings。5 个攻击类 SKILL 补 Core Tools / Practical Steps。**skill-lint 0 errors / 0 warnings**. See [RELEASE-v0.2.3.md](RELEASE-v0.2.3.md) |
| v0.2.3.1 | 2026-08-06 | **Q3 工具基线更新** 🔄 | 6 MAJOR 升级（hashcat/ghidra/frida/docker/openssl/radare2）+ Trivy CVE-2026-33634 供应链事件警告；新增 `KALI_TOOLS_BASELINE_2026_08.md`. See [RELEASE-v0.2.3.1.md](RELEASE-v0.2.3.1.md) |
| v0.2.3.2 | 2026-08-06 | **Defense Perspective 抽样审查** 🔍 | 6 个高频攻击类 SKILL 内容质量审查；平均 4.2/5；2 P1 + 3 P2 + 3 P3 findings（0 P0）. See [RELEASE-v0.2.3.2.md](RELEASE-v0.2.3.2.md) |
| v0.2.3.3 | 2026-08-06 | **新 SKILL 候选评估** 🎯 | 5 候选方向评估；2 P0（EU AI Act 合规 + AI Agent 供应链）+ 2 P1 + 1 P2；不创建（留待 v0.2.4）. See [RELEASE-v0.2.3.3.md](RELEASE-v0.2.3.3.md) |
| **v0.2.4** | **2026-08-08** | **Minor Release：3 阶段累积发布** 🚀 | 阶段 A（MAJOR 工具修复，21 文件）+ 阶段 B（P1/P2 findings 落地，4 文件）+ 阶段 C（2 个新 P0 SKILL：`eu-ai-act-compliance-redteam` + `ai-agent-supply-chain-attack`，8 文件）。SKILL 137 → **139**. See [RELEASE-v0.2.4.md](RELEASE-v0.2.4.md) |

### Current Quality Snapshot (v0.2.3 — Phase 2 Track 1 月度审查完成) 🛡️

| Metric | Value |
|--------|-------|
| **Total SKILLs** | **137** (130 baseline + 7 new strategic) |
| **At v0.2.0.2** | **137/137 (100%)** 🎊 |
| **Defense Triple** | **137/137 (100%)** 🎊 |
| **Translation residue** | **0** |
| **Test cases** | **1761** |
| **Documentation files** | **6** (Handbook, Quick Reference, Index, Matrix, Tools Lifecycle, Maintenance) |
| **Automation scripts** | **5** (skill-lint, validate-payloads, validate-testcases, SCORE.sh, update-skill-standard) |
| **CI/CD** | **GitHub Actions** (lint + score dual job) |

**Phase 1 全部完成**: 5 大任务 (Task 1.1-1.5) 全部交付 ✅

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
| **Version** | **v0.2.4** (Phase 2 Track 1 Minor — 139 SKILLs) |
| **Runtime** | Kali Linux 2025-2 (aarch64) |
| **Tools** | 518 Kali security tools (100% coverage) |
| **Skill Domains** | **137** (all at v0.2.0.2 with full Defense Triple — 100% coverage) |
| **Created** | 2026-03-14 |
| **License** | MIT |

### Release Documents

| Version | Date | Description |
|---------|------|-------------|
| **[v0.2.1](RELEASE-v0.2.1.md)** | **2026-07-30** | **Phase 1 全部完成 — Stable Release 🎯** |
| [v0.2.0.8](RELEASE-v0.2.0.8.md) | 2026-07-29 | Task 1.3 完成 (7 新 SKILL, 总 137) |
| [v0.2.0.7](RELEASE-v0.2.0.7.md) | 2026-07-28 | Phase 2 全部完成 (130/130) |
| [v0.2.0.6](RELEASE-v0.2.0.6.md) | 2026-07-27 | Phase 2 半程 (50%) |
| [v0.2.0.5](RELEASE-v0.2.0.5.md) | 2026-07-26 | Phase 2 Batch 1-2 + 文档基线 |
| [v0.2.0.4](RELEASE-v0.2.0.4.md) | 2026-07-24 | Phase 1 Task 1.2 第一阶段完成 (15/15 SKILLs = 100%) — 里程碑版本 |
| [v0.2.0.3](RELEASE-v0.2.0.3.md) | 2026-07-21 | Phase 1 Day 3 完成 (12/15 = 80%) |
| [v0.2.0.2](RELEASE-v0.2.0.2.md) | 2026-07-19 | Phase 1 Day 1-2 完成 (8 SKILLs) |
| [v0.2.0.1](RELEASE-v0.2.0.1.md) | 2026-07-16 | 战略定位：SKILL 库维护者 |
| [v0.1.47.1-analysis](RELEASE-v0.1.47.1-analysis.md) | 2026-07-10 | CyberGym 完整评估分析 |
| [v0.1.47](RELEASE-v0.1.47.md) | 2026-07-08 | +3 exploitation SKILLs |
| [v0.1.46](RELEASE-v0.1.46.md) | 2026-07-08 | Closed-book CyberGym 校准 |

---

_Built with the OpenClaw Agent Framework._
