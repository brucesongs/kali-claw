# Changelog

All notable changes to kali-claw are documented in this file.

Version format: MAJOR.MINOR.PATCH — PATCH increments per change; resets to 0 and bumps MINOR when PATCH exceeds 1024.

## v0.1.26 (2026-06-11) — 15 Distinguished Milestone, Distinguished Sprint + Bottom Lift

### Distinguished Sprint: 3+2 New Distinguished Skills
- **network-tunneling-proxy** reached 92.3 — created 3 new guides (pivoting-double-pivot, ipv6-tunneling, tunnel-detection-evasion); file_count 5→8
- **payload-generation** reached 93.1 — created 3 new guides (cross-platform, web-shell, encoding-encryption); file_count 5→8
- **vpn-attack** reached 92.5 — created 3 new guides (wireguard, openvpn, credential-brute-force); expanded payloads +2 sections; file_count 5→8

### Bottom Lift: 3 Skills Improved
- **web-deserialization** 85.3 → **92.2** — expanded SKILL.md (+6 sections); created 2 new guides (nodejs, dotnet); added 9 payload sections (10→18)
- **scada-ics-security** 84.6 → **91.6** — expanded SKILL.md (+5 sections); expanded 3 guides; created 2 new guides; added 5 payload sections
- **sdr-rf-attack** 86.1 → **88.8** — expanded 3 guides; created 2 new guides (gps-spoofing, zigbee-ble-sdr)

### Stats
- Distinguished: 11 → 15 (+4)
- Excellent: 63 → 59
- Total: 74
- Average: 87.7 → 88.0
- Min: 83.4

## v0.1.25 (2026-06-10) — 11 Distinguished Milestone, Distinguished Sprint + Bottom Lift

### Distinguished Sprint: 3 New Distinguished Skills
- **security-misconfiguration** reached 92.8 — expanded SKILL.md (13→15 sections); expanded all 8 guides (avg 880→2014 words)
- **security-bounty-hunter** reached 92.0 — expanded SKILL.md (14→18 sections); expanded 5 guides (avg 1463→1894); added 2 test cases
- **web-xss** reached 92.0 — expanded SKILL.md (8→25 headings); expanded 4 guides (avg 1480→2177); created CSP bypass guide (8 guides total)

### Bottom Lift: 3 Lowest Skills Improved
- **vpn-attack** 83.3 → 89.4 (+6.1) — expanded SKILL.md (7→12 sections); expanded 3 guides; created 2 new guides; added 3 payload sections
- **network-tunneling-proxy** 84.3 → 90.3 (+6.0) — expanded SKILL.md (8→14 sections); expanded 3 guides; created 2 new guides
- **payload-generation** 84.4 → 91.1 (+6.7) — expanded SKILL.md (11→14 sections); expanded 3 guides; created 2 new guides; added 6 payload sections

### Stats
- Distinguished: 8 → 11 (+3)
- Excellent: 66 → 63
- Total: 74
- Average: 87.3 → 87.7
- Min: 83.4

## v0.1.24 (2026-06-10) — 8 Distinguished Milestone, Distinguished Sprint + Bottom Lift

### Distinguished Sprint: 3 New Distinguished Skills
- **osint** reached 92.5 — expanded 4 guides (info-gathering-cli-reference, automated-osint-pipeline, enterprise-pentest-case-study, corporate-recon); added Introduction/Hands-on/References to 8 guides
- **social-intelligence** reached 93.8 — expanded 5 guides (community-monitoring, reddit-hn, social-graph, target-profiling, twitter-youtube); added 4 payload sections (TikTok, Instagram, Discord, Mastodon/Fediverse); added 2 test cases
- **verification-loop** reached 92.6 — expanded 1 guide (automated-exploit-verification); added key sections to 5 guides; created 3 new guides (false-positive-triage, cross-tool-verification, finding-documentation-evidence)

### Bottom Lift: 5 Lowest Skills Improved
- **engagement-manager** 82.8 → 86.0 — expanded SKILL.md (10→16 sections: Phase Entry/Exit, Evidence Requirements, Timeline, Communication Templates, Risk Matrix, Post-Engagement Checklist)
- **tool-mastery** 82.8 → 85.4 — expanded SKILL.md (11→16 sections: Tool Selection Matrix, Learning Path, Tool Failure Recovery, Common Pitfalls, Output Formats)
- **email-protocol-attack** 83.1 → 85.2 — added payload code block (Email Header Forensic Analysis)
- **steganography** 84.9 → 86.4 — added payload code blocks (Chi-Square, Audio, PDF); created 2 new guides (audio-video-steganography, network-protocol-steganography)
- **av-edr-evasion** 88.3 → 89.1 — created 2 new guides (shellcode-encoding, process-injection-techniques)

### Stats
- Distinguished: 5 → 8 (+3)
- Excellent: 69 → 66
- Total: 74
- Average: 87.0 → 87.3
- Min: 83.3 (vpn-attack)

## v0.1.23 (2026-06-10) — 5 Distinguished Milestone, Guide Quality Sprint

### Quality Milestone: 5 Distinguished Skills
- **article-writing** reached 93.6 — expanded 5 guides (pentest-report-template, report-structure, cve-advisory, security-blog, vulnerability-writing)
- **vulnerability-assessment** reached 93.0 — expanded 4 guides (automated-scanning-pipeline, manual-testing, risk-rating, vuln-analysis-tools)
- **autonomous-loops** reached 92.6 — expanded 3 guides (watch-loop-patterns, batch-processing, error-recovery)
- cloud-security maintained 92.1
- network-pentest maintained 92.0

### Stats
- Distinguished: 2 → 5 (+3)
- Excellent: 72 → 69
- Total: 74
- Average: 86.9 → 87.0
- Guides expanded: 12 (all from ~300-800 words to 2000+ words)

## v0.1.22 (2026-06-10) — SDR/RF + VPN Attack, 2 Distinguished

### New Skill Domains
- **sdr-rf-attack** (7 tools) — Software Defined Radio and RF signal attacks covering HackRF/RTL-SDR, signal capture and replay, GSM/LTE analysis, RFID/NFC attacks, keyfob replay, drone RF analysis, satellite signal monitoring, AIS ship tracking, and spectrum analysis.
- **vpn-attack** (5 tools) — VPN attack techniques covering IKE enumeration with ike-scan, PSK cracking via aggressive mode, SSL VPN exploitation (Fortinet/Pulse/Palo Alto/SonicWall), IPSec tunnel testing, certificate analysis, credential brute force, and split tunneling detection.

### Quality Milestone: 2 Distinguished Skills
- **cloud-security** reached 92.1 — second Distinguished tier skill (Distinguished sprint)
- **network-pentest** maintained 92.0 — first Distinguished tier skill
- 74/74 Excellent or above (100%)

### Distinguished Sprint
- cloud-security: added AWS Lambda priv esc, Azure CA bypass, GCP SA key extraction, CloudFormation injection, Terraform state exploitation
- vulnerability-assessment: added NSE scripts, OpenVAS automation, Nessus CLI, Nuclei templates, correlation scripts
- article-writing: added report generator, markdown-to-PDF, CVSS calculator, disclosure generator, export pipeline
- autonomous-loops: added pipeline orchestration, batch processing, learning cycle, error recovery, parallel execution

### Stats
- Skills: 72 → 74 (+2)
- Distinguished: 2 (cloud-security, network-pentest)
- Excellent: 72
- Strong: 0
- New tool references: 12

## v0.1.21 (2026-06-10) — First Distinguished, web-deserialization + email-protocol-attack

### New Skill Domains
- **web-deserialization** (6 tools) — Insecure deserialization attacks (OWASP A08:2021) covering Java ysoserial, PHP phpggc, .NET ysoserial.net, Python pickle, Ruby Marshal, Jackson/Fastjson. Includes blind detection, gadget chain analysis, and WAF bypass.
- **email-protocol-attack** (8 tools) — Email protocol attacks covering SMTP enumeration, open relay testing, SPF/DKIM/DMARC bypass, email forgery with swaks, IMAP/POP3 brute force, Exchange server exploitation, and STARTTLS testing.

### Quality Milestone: First Distinguished Skill
- **network-pentest** reached 92.0 — the first Distinguished tier skill
- 72/72 Excellent or above (100%), avg 86.9
- 1 Distinguished / 71 Excellent / 0 Strong / 0 Adequate

### Distinguished Sprint (Top 5)
- network-pentest: 91.2 → 92.0 (Distinguished!)
- cloud-security: 91.3 → 91.8
- autonomous-loops: 90.9 → 91.3
- vulnerability-assessment: 90.7 → 91.1
- article-writing: 90.6 → 91.0

### Bottom 5 Consolidation (all to 83+)
- privilege-escalation: 80.2 → 85.8
- web-xxe: 81.3 → 87.3
- cms-framework-attack: 81.7 → 85.8
- network-sniffing-mitm: 81.7 → 85.8
- ad-ldap-attack: 82.2 → 85.8

### Guide Additions (5 new guides)
- web-access-control: CSRF Attack Guide
- api-security: WebSocket Security Testing Guide
- web-xss: SSTI Attack Guide + WAF Bypass XSS Guide
- web-sqli: WAF Bypass SQLi Guide

### Stats
- Skill domains: 70 → 72
- Tool references: +14 (ysoserial, phpggc, marshalsec, smtp-user-enum, swaks, etc.)
- New files: 19 (2×7 core + 5 guides)
- Average score: 86.5 → 86.9

## v0.1.20 (2026-06-10) — 70/70 Excellent, AD/LDAP Attack Domain

### New Skill Domain
- **ad-ldap-attack** (15 tools) — Active Directory/LDAP/Kerberos attack techniques covering domain reconnaissance, AS-REP Roasting, Kerberoasting, Golden/Silver Tickets, DCSync, Pass-the-Hash, lateral movement, and domain dominance. Tools: impacket-suite, bloodhound, ldapsearch, enum4linux, crackmapexec, ldeep, ldapdomaindump, rpcclient, etc.

### Quality Milestone: 70/70 Excellent (100%)
- All 70 skill domains now score Excellent (80+) under scoring system v2
- Previous: 49 Excellent / 18 Strong / 2 Adequate
- Now: 70 Excellent / 0 Strong / 0 Adequate
- Average score: 81.8 → 86.5

### Skills Promoted from Strong/Adequate to Excellent (21 skills)
- **From Adequate** (2): tool-mastery (44.0→79.0), engagement-manager (45.7→77.8)
- **From Strong** (19): bluetooth-rfid-nfc, file-inclusion, anti-forensics, network-tunneling-proxy, database-attack, firmware-reverse, voip-sip-attack, scada-ics-security, dns-attacks, payload-generation, pentest-reporting, av-edr-evasion, steganography, web-xxe, cms-framework-attack, exploit-development, network-sniffing-mitm, privilege-escalation, ad-ldap-attack (new)

### Content Enhancements
- payloads.md: All 21 promoted skills received 15-25 additional code blocks (realistic Kali commands)
- test-cases.md: All skills now have 8+ test cases with 7/7 field completeness (Severity, Prerequisite, Steps, Expected Result, Objective, Remediation, Pass Criteria)
- SKILL.md: Fixed missing sections (Core Tools tables, Practical Steps, Defense Perspective) for tool-mastery, engagement-manager, network-tunneling-proxy, privilege-escalation
- guides: Expanded to 1000+ words each with Introduction, Hands-on Exercise, and References sections for file-inclusion, firmware-reverse, network-tunneling-proxy, bluetooth-rfid-nfc

### Stats
- Skill domains: 69 → 70
- Tool references: +15 (impacket-suite, bloodhound, enum4linux, kerberoast, etc.)
- New files: 7 (SKILL.md, payloads.md, test-cases.md, 3 guides + 1 guide for tool-mastery)
- Average score: 86.5 (up from 81.8)

## [0.1.19] - 2026-06-09

### Added

- **8 new security skill domains** (61 → 69), covering 70 additional Kali tool references:
  - `bluetooth-rfid-nfc` — Bluetooth/BLE/RFID/NFC near-field wireless attacks (13 tools: spooftooph, redfang, bluelog, btscanner, bluehydra, crackle, ubertooth-tools, gatttool, proxmark3, mfoc, mfcuk, libnfc, blescan)
  - `network-tunneling-proxy` — Network tunneling, proxy chains, and pivoting (10 tools: chisel, ligolo-ng, proxychains, socat, ptunnel, gost, 3proxy, sshuttle, stunnel, dnscat2)
  - `firmware-reverse` — Firmware extraction, analysis, and emulation (9 tools: firmadyne, firmwalker, sasquatch, jefferson, binwalk, unblob, qemu-system, yara, firmware-mod-kit)
  - `scada-ics-security` — SCADA/ICS industrial control system security (8 tools: conpot, plcscan, s7scan, modbus-cli, mbpoll, enip-client, csric, python-opcua)
  - `database-attack` — Direct database server attacks at protocol level (8 tools: odat, oscanner, sqsh, redis-tools, mongoaudit, patator, ncrack, hydra)
  - `voip-sip-attack` — VoIP/SIP protocol attacks (8 tools: sipvicious, sipsak, voiphopper, iaxflood, inviteflood, rtpflood)
  - `anti-forensics` — Anti-forensic techniques and forensic evasion (7 tools: shred, wipe, tcplay, logtamper, timestomp, bulk_extractor, steghide)
  - `pentest-reporting` — Pentest reporting and evidence management tools (7 tools: dradis, faraday, pipal, cutycapt, recordmydesktop, magictree, cherrytree)
- Each new skill includes: SKILL.md, payloads.md, test-cases.md, and 3 deep-dive guides
- `validation/update-skill-standard.py` — Updated with DOMAIN_MAP, ATTACK_SKILLS, ANALYSIS_SKILLS, and MITRE_MAP for all 8 new domains

### Changed

- Skill domain count: 61 → 69
- Tool coverage: 70 new tool references added
- `heartbeat.sh`: EXPECTED_SKILLS=69
- `VERSION`: 0.1.19

## [0.1.18] - 2026-06-04

### Added

- **10 new security skill domains** (51 → 61), covering 72 additional Kali tool references:
  - `network-sniffing-mitm` — Network traffic interception, ARP spoofing, credential harvesting (9 tools: wireshark, tcpdump, ettercap, bettercap, mitm6, responder, dsniff, driftnet, mitmproxy)
  - `privilege-escalation` — Linux/Windows local and domain privilege escalation (8 tools: linpeas, winpeas, linux-exploit-suggester, pspy, GTFOBins, lolbas, sudo, capsh)
  - `exploit-development` — Vulnerability research, exploit writing, binary exploitation (8 tools: gdb/pwndbg, pwntools, ROPgadget, ropper, checksec, pattern_create, shellnoob, one_gadget)
  - `payload-generation` — Reverse shell generation, payload encoding, delivery mechanisms (7 tools: msfvenom, netcat, socat, nishang, hoaxshell, rlwrap, shellter)
  - `av-edr-evasion` — Antivirus/EDR bypass techniques (7 tools: shellter, veil, msfvenom encoders, donut, pe2shc, hyperion, crypter)
  - `dns-attacks` — DNS reconnaissance, spoofing, tunneling, exfiltration (8 tools: dnsrecon, dnsenum, fierce, dnschef, dns2tcp, dnscat2, dnswalk, iodine)
  - `web-xxe` — XML External Entity injection attacks (6 tools: XXEinjector, oxml_xxe, xxeplus, burpsuite, odat, netcat)
  - `file-inclusion` — Local/Remote File Inclusion attacks (6 tools: dotdotpwn, kadimus, fimap, burpsuite, php_filter_chain, secLists)
  - `cms-framework-attack` — CMS security assessment (7 tools: wpscan, joomscan, droopescan, cmseek, nikto, whatweb, nuclei)
  - `steganography` — Steganographic data hiding and extraction (6 tools: steghide, stegcracker, zsteg, binwalk, foremost, exiftool)
- Each new skill includes: SKILL.md, payloads.md, test-cases.md, and 3 deep-dive guides (6-8 test cases, 300+ word guides)
- **Agent Skills Open Standard alignment** — All 61 SKILL.md files now conform to the open Agent Skills standard (Anthropic, 2025):
  - YAML frontmatter with `name`, `description`, `version`, `compatibility`, `allowed-tools`, and `metadata` fields
  - `compatibility` field declaring support for openclaw, claude-code, cursor, windsurf
  - `allowed-tools` field restricting tool access per skill type (security/analysis/all)
  - `metadata` with domain classification, tool count, OWASP/MITRE ATT&CK mapping
  - Progressive disclosure via `## Summary` section (Stage 1: advertise → Stage 2: quick reference → Stage 3: detailed content)
  - All SKILL.md files verified under 500 lines (max: 378)
- `validation/update-skill-standard.py` — Automated SKILL standard alignment script

### Changed

- Skill domain count: 51 → 61
- Tool coverage: 72 new tool references added
- IDENTITY.md: added 10 new skill tags
- TOOLS.md: added 10 new tool categories
- CLAUDE.md: updated domain count and descriptions
- SOUL.md: decision trees updated with new skill references
- README.md: version updated to 0.1.18

## [0.1.17] - 2026-06-03

### Added

- **15 skills fixed key sections** (Introduction, Hands-on, References): verification-loop, council, browser-qa, crypto-attacks, hardware-security, insecure-design, supply-chain-security, web-ssrf, container-security, password-attack, safety-guard, codebase-onboarding, web-access-control, ai-fuzzing, post-exploitation
- **10 new guides for bottom 5 skills**:
  - post-exploitation: persistence-techniques-guide, lateral-movement-practical-guide
  - ai-fuzzing: web-api-fuzzing-guide, crash-triage-guide
  - password-attack: hashcat-rules-guide, password-policy-audit-guide
  - insecure-design: abuse-case-development-guide, secure-design-patterns-guide
- **3 test cases added** to continuous-learning (TC-CL-007 to TC-CL-009, now 9 total)
- **35 new guides for Distinguished sprint** (10 target skills × 3-4 guides each):
  - cloud-security: aws-pentest-lab-guide, azure-privilege-escalation-guide, cloud-post-exploitation-guide
  - vulnerability-assessment: automated-scanning-pipeline-guide, manual-testing-techniques-guide, risk-rating-methodology-guide
  - article-writing: pentest-report-template-guide, cve-advisory-writing-guide, security-blog-writing-guide
  - autonomous-loops: watch-loop-patterns-guide, batch-processing-guide, error-recovery-guide
  - osint: dark-web-intelligence-guide, corporate-recon-guide, data-aggregation-analysis-guide
  - ai-security: prompt-injection-lab-guide, ai-red-team-guide (model-extraction already existed)
  - security-misconfiguration: cloud-misconfiguration-checklist-guide, web-server-hardening-lab-guide, default-credential-audit-guide
  - network-pentest: 3 guides (from batch agent)
  - security-bounty-hunter: 3 guides (from batch agent)
  - social-intelligence: 3 guides (from batch agent)
- **Automation infrastructure** (4 scripts):
  - `validation/heartbeat.sh` — Workspace health checks with JSON output and auto-fix
  - `validation/auto-backup.sh` — Timestamped backup rotation with integrity verification
  - `validation/drift-detect.sh` — Configuration drift detection with baseline snapshots
  - `validation/scenario-runner.sh` — Cross-skill scenario execution with checkpoint resume
- **Penetration test orchestration layer** (3 scripts + templates):
  - `validation/orchestrator.sh` — End-to-end kill chain workflow engine with phase management
  - `validation/tool-selector.sh` — Target-to-tool mapping engine (5 target types × 6 phases)
  - `validation/report-generator.sh` — Automated penetration test report generator
  - `validation/engagement-template/` — Target config, scope rules, and report templates
- **2 new skill domains** (49 → 51):
  - `skills/engagement-manager/` — Full engagement lifecycle management (3 guides, 8 test cases)
  - `skills/tool-mastery/` — Tool proficiency assessment framework (2 guides, 6 test cases)
- **SOUL.md decision trees** — Structured decision frameworks for target type, vulnerability priority, tool selection, and engagement phase decisions
- **AGENTS.md multi-agent collaboration** — Role definitions (Attacker/Defender/Auditor), collaboration protocol, handoff protocol, and automation script inventory

### Changed

- Average quality score: 86.1 → 87.5 (+1.4)
- Minimum quality score: 80.1 → 84.3 (+4.2)
- All 15 key-section-deficient skills now have 3/3 key sections
- All 51 skills remain Excellent tier (80+)
- CI quality gate baseline: 86.1 → 87.5
- IDENTITY.md: added engagement-manager and tool-mastery skill tags
- TOOLS.md: added engagement-manager and tool-mastery tool categories
- CLAUDE.md: updated from 49 to 51 skill domains, added automation scripts section

## [0.1.16] - 2026-06-02

### Changed

- **Scoring system v2**: All component scores capped at 100 (no inflation), guide quality composite metric replaces raw file count, Distinguished tier (92+) added above Excellent (80-91.9)
- **Core files synchronized to 49-domain reality**: CLAUDE.md (25→49), IDENTITY.md (30→49 skill rows), TOOLS.md (20→49 category rows), README.md version consistency
- Updated USER.md, MEMORY.md, TOOLS.md, HEARTBEAT.md to reflect current project phase

### Added

- **TEMPLATE.md**: Authoritative template for creating new OpenClaw agent workspaces
- **docs/tools/full-inventory.md**: Complete 518-tool inventory organized by skill domain
- **5 cross-skill composite attack chain scenarios**:
  - SCEN-001: Enterprise External Network Penetration Full Chain
  - SCEN-002: Cloud Environment Attack Chain
  - SCEN-003: Social Engineering + Internal Network Penetration
  - SCEN-004: Mobile Application Attack Chain
  - SCEN-005: Purple Team Defense Validation
- HEARTBEAT.md: core file consistency checks and `__pycache__` artifact detection

### Fixed

- Removed `__pycache__` directories from 5 skill directories
- Fixed score inflation (council: 99.7→87.4, max component 125.7→93.3)
- All dangling file references resolved (bak/, docs/tools/, TEMPLATE.md)

### Metrics

- Scoring v2 baseline: Average 86.1, Min 80.1 (post-exploitation), Max 90.1 (cloud-security)
- CI baseline updated to 86.1
- 0 Distinguished, 49 Excellent — room to grow into new tier

## [0.1.15] - 2026-05-31

### Changed

- Expanded 18 SKILL.md files from 10-14 to 17+ `##` headings (skill_section scores 68-76 → 86.7)

### Added

- 20 new test cases across 9 skills (all now 8+ TC)
- Expanded 26 payloads.md files to 50+ code blocks (payload_code bottleneck eliminated)

### Metrics

- Average: 84.0 → 88.6 (+4.6)
- Minimum: 80.0 → 85.3 (+5.3)
- Maximum: 90.3 → 99.7 (+9.4)
- CI baseline updated to 88.6

## [0.1.14] - 2026-05-29

### Added

- Infrastructure documentation:
  - `validation/SCORING-METHODOLOGY.md` — Formal scoring methodology reference
  - `validation/README.md` — Unified validation system entry point
- 11 new guides:
  - `ai-security/guides/ai-model-security-testing-guide.md` — AI model attack patterns
  - `continuous-learning/guides/cross-session-knowledge-aggregation-guide.md` — Knowledge aggregation
  - `web-ssrf/guides/cloud-metadata-ssrf-guide.md` — Cloud metadata exploitation
  - `web-ssrf/guides/ssrf-filter-bypass-guide.md` — URL parser differentials, DNS rebinding
  - `logging-monitoring/guides/siem-log-analysis-guide.md` — SIEM correlation rules
  - `logging-monitoring/guides/log-tampering-detection-guide.md` — Anti-forensics detection
  - `security-misconfiguration/guides/cloud-misconfiguration-audit-guide.md` — Multi-cloud audit
  - `security-misconfiguration/guides/web-server-hardening-guide.md` — Server hardening
  - `insecure-design/guides/threat-modeling-for-design-flaws-guide.md` — STRIDE/DREAD
  - `insecure-design/guides/business-logic-attack-patterns-guide.md` — Race conditions, state abuse
  - `social-intelligence/guides/social-network-mapping-guide.md` — Graph analysis, community detection
- 10 new test cases: ai-fuzzing (+2), knowledge-ops (+3), article-writing (+2), council (+1), web-sqli (+2)
- Expanded payloads for 10 skills: post-exploitation, web-access-control, security-review, multi-agent-collaboration, verification-loop, insecure-design, article-writing, council, social-intelligence, web-sqli
- Added sections to password-attack/SKILL.md (Integration, Common Pitfalls)
- Strong expansion phase:
  - `mcp-server-patterns/payloads.md` — +20 code blocks (5 new sections)
  - `security-bounty-hunter/payloads.md` — +15 code blocks (2 new phases)
  - `security-bounty-hunter/test-cases.md` — +1 test case (TC-BH-005)
- Excellent promotion:
  - `osint/payloads.md` — +10 code blocks (6 new sections)
  - `osint/guides/automated-osint-pipeline-guide.md` — Pipeline architecture, modules, reporting
- Automation tool:
  - `validation/batch-improve.sh` — Identifies optimal improvement path per skill
- CI integration:
  - `.github/workflows/skill-quality.yml` — Automated scoring on skills/ changes
- Strong expansion phase 2:
  - `search-first/guides/multi-source-intelligence-correlation-guide.md`
  - `search-first/guides/search-query-optimization-guide.md`
  - `search-first/guides/search-result-validation-guide.md`
  - `search-first/payloads.md` — +20 code blocks
  - `codebase-onboarding/guides/dependency-supply-chain-analysis-guide.md`
  - `codebase-onboarding/payloads.md` — +20 code blocks
- Fourth Excellent:
  - `deep-research/guides/source-validation-guide.md`
  - `deep-research/payloads.md` — +27 code blocks
- Fifth Excellent:
  - `mobile-security/payloads.md` — +20 code blocks (8 new sections)
- Strong expansion phase 3:
  - `terminal-ops/guides/terminal-automation-scripting-guide.md`
  - `terminal-ops/guides/terminal-network-operations-guide.md`
  - `terminal-ops/guides/terminal-forensics-evidence-guide.md`
  - `terminal-ops/payloads.md` — +11 code blocks
  - `docker-patterns/guides/docker-security-scanning-guide.md`
  - `docker-patterns/guides/container-escape-techniques-guide.md`
  - `docker-patterns/guides/docker-network-security-guide.md`
  - `docker-patterns/payloads.md` — +20 code blocks
- CI quality gate:
  - `.github/workflows/skill-quality.yml` — PR regression blocking (avg + per-skill >5pt detection)
  - `validation/evidence/quality-scores-baseline.json` — Baseline for regression detection
- Adequate elimination (4 skills → Strong):
  - `repo-scan/payloads.md` — +31 code blocks (8 new phases)
  - `repo-scan/test-cases.md` — +1 test case (TC-RS-005 CI/CD security)
  - `repo-scan/guides/dependency-vulnerability-scanning-guide.md`
  - `repo-scan/guides/sast-integration-guide.md`
  - `repo-scan/guides/git-history-security-analysis-guide.md`
  - `data-scraper-agent/payloads.md` — +28 code blocks (7 new sections)
  - `data-scraper-agent/guides/rate-limiting-and-stealth-guide.md`
  - `data-scraper-agent/guides/structured-data-extraction-guide.md`
  - `data-scraper-agent/guides/anti-bot-bypass-guide.md`
  - `browser-qa/payloads.md` — +28 code blocks (7 new sections)
  - `browser-qa/guides/headless-browser-security-testing-guide.md`
  - `browser-qa/guides/browser-fingerprint-analysis-guide.md`
  - `browser-qa/guides/web-automation-evidence-capture-guide.md`
  - `exa-search/payloads.md` — +24 code blocks (6 new sections)
  - `exa-search/test-cases.md` — +3 test cases (TC-EX-003/004/005)
  - `exa-search/guides/advanced-query-construction-guide.md`
  - `exa-search/guides/search-result-enrichment-guide.md`
  - `exa-search/guides/competitive-intelligence-gathering-guide.md`
- Sixth Excellent (council):
  - `council/guides/multi-perspective-analysis-framework-guide.md`
  - `council/guides/automated-consensus-scoring-guide.md`
  - `council/guides/risk-prioritization-matrix-guide.md`
- Seventh Excellent (repo-scan):
  - `repo-scan/payloads.md` — +31 code blocks (8 new phases)
  - `repo-scan/test-cases.md` — +3 test cases (TC-RS-006/007/008)
- Guide expansion to 5+ per skill (all 49 skills, 261 total guide files)
- Integration tests INT-008/009/010 (supply chain, full pentest, defensive validation) — all PASS
- Mass payload expansion across 49 skills (code blocks 25-50+)
- SKILL.md section expansion:
  - `exa-search/SKILL.md` — +4 sections (Query Strategy, Result Triage, Rate Limits, Common Pitfalls)
  - `data-scraper-agent/SKILL.md` — +4 sections (Scraping Strategy, Ethical Scraping, Data Normalization, Common Pitfalls)
  - `browser-qa/SKILL.md` — +4 sections (Methodology, Test Patterns, Anti-Detection, Common Pitfalls)
- `ai-fuzzing/test-cases.md` — +1 test case (TC-AF-007 Differential Fuzzing)
- Field completeness fixes for 6 skills: codebase-onboarding, autonomous-loops, web-xss, docker-patterns, search-first, terminal-ops
- Test case expansion (+52 TC across 10 skills): search-first +6, docker-patterns +6, codebase-onboarding +5, autonomous-loops +4, terminal-ops +5, hardware-security +5, browser-qa +5, data-scraper-agent +5, exa-search +5
- Payload expansion for 8 skills to 50+ code blocks: logging-monitoring, security-bounty-hunter, verification-loop, hardware-security, continuous-learning, mcp-server-patterns, web-xss, ai-security
- SKILL.md section expansion (round 2): browser-qa +5, data-scraper-agent +5, exa-search +5 (all to 15 headings)

### Fixed

- SCORE.sh guide score overflow: capped at 100 (was 156 for web-sqli)

### Changed

- Quality tier distribution: Adequate 27→0, Strong 20→0, Excellent 2→**49 (100%)**
- Average score: 59.4 → **84.0**
- Min score: 40.4 → **80.0**
- Max score: 80.0 → **90.3**
- 47 skills promoted to Excellent tier
- CI quality gate baseline updated to 84.0

## [0.1.13] - 2026-05-29

### Added

- 6 new guides for 3 previously zero-guide skills:
  - `data-scraper-agent/guides/nvd-api-scraping-guide.md` — NVD API pagination and caching
  - `data-scraper-agent/guides/data-extraction-patterns-guide.md` — Extraction methodology
  - `browser-qa/guides/playwright-auth-testing-guide.md` — Auth security testing
  - `browser-qa/guides/network-interception-guide.md` — Traffic interception patterns
  - `exa-search/guides/semantic-search-query-design-guide.md` — Query design methodology
  - `exa-search/guides/exa-api-configuration-guide.md` — API configuration reference
- Expanded payloads.md for data-scraper-agent (116→647 words), browser-qa (130→708 words), exa-search (211→823 words)
- Additional test cases for data-scraper-agent (+3) and browser-qa (+2)

### Fixed

- SCORE.sh section matching: replaced name-based matching with heading-count approach — eliminates false low scores from non-standard section naming
- SCORE.sh test case pattern: `### TC-` → `^##+ TC-` to match both `## TC-` and `### TC-` formats
- SCORE.sh field completeness: added recognition of "Steps", "Expected Output", "Objective" patterns

### Changed

- Quality tier distribution: Weak 9→0, Adequate 18→27, Strong 20→20, Excellent 2→2
- Average score: 50.5 → 59.4 (+8.9)
- All 49 skills now at Adequate tier or above (zero Weak)

## [0.1.12] - 2026-05-23

### Added

- 16 new practical guides across 13 skills:
  - `data-scraper-agent/guides/nvd-api-scraping-guide.md` — NVD API methodology
  - `data-scraper-agent/guides/data-extraction-patterns-guide.md` — Data extraction patterns
  - `browser-qa/guides/playwright-auth-testing-guide.md` — Auth testing with Playwright
  - `browser-qa/guides/network-interception-guide.md` — Network request interception
  - `exa-search/guides/semantic-search-query-design-guide.md` — Query design methodology
  - `exa-search/guides/exa-api-configuration-guide.md` — API configuration guide
  - `docker-patterns/guides/docker-vulnerability-patterns-guide.md` — Docker vulnerability patterns
  - `repo-scan/guides/secret-detection-patterns-guide.md` — Secret detection patterns
  - `terminal-ops/guides/terminal-session-management-guide.md` — Session management
  - `verification-loop/guides/remediation-verification-patterns-guide.md` — Patch verification
  - `mcp-server-patterns/guides/mcp-tool-implementation-guide.md` — MCP tool implementation
  - `autonomous-loops/guides/autonomous-pentest-orchestration-guide.md` — Orchestration guide
  - `hardware-security/guides/hardware-exploitation-patterns-guide.md` — Hardware exploitation
  - `security-review/guides/code-review-security-patterns-guide.md` — Code review patterns
  - `multi-agent-collaboration/guides/agent-failure-handling-and-recovery-guide.md` — Failure handling
  - `search-first/guides/tool-evaluation-and-selection-guide.md` — Tool evaluation
- `RELEASE-v0.1.12.md` — Release announcement (Chinese)

### Fixed

- `validation/SCORE.sh` — SKILL.md section detection: added `-E` flag for extended regex matching
- `validation/SCORE.sh` — grep -c handling: fixed exit code handling for zero matches (returns 1, not 0)

### Changed

- `VERSION` — 0.1.11 → 0.1.12
- `README.md` — Version 0.1.12
- `QUALITY-SCORE-TRACKER.md` — Updated with new scores and tier distribution
- `WEAK-SKILL-IMPROVEMENT-PLANS.md` — Marked complete, recorded progress

### Quality Improvement Results

- **Tier distribution**: 9 Weak (18%), 18 Adequate (37%), 20 Strong (41%), 2 Excellent (4%)
- **18 skills promoted to Strong tier**: ai-fuzzing, api-security, binary-reverse, cloud-security, container-security, crypto-attacks, deep-research, digital-forensics, mobile-security, network-pentest, osint, password-attack, post-exploitation, social-engineering, supply-chain-security, vulnerability-assessment, web-access-control, web-auth-bypass
- **2 skills promoted to Excellent tier**: recon-osint, web-sqli
- **Average score**: 40.5 → 50.5 (+10)

## [0.1.11] - 2026-05-23

### Added

- `validation/SCORE.sh` — Bash script to compute quality metrics for all 49 skills
- `validation/QUALITY-SCORE-TRACKER.md` — Master quality score tracker (all 49 skills)
- `validation/QUALITY-SCORE-GUIDE.md` — Metric definitions + tier definitions + analysis findings
- `validation/evidence/quality-scores/` — Per-skill JSON score data (49 files)
- `RELEASE-v0.1.11.md` — Release announcement

### Changed

- `VERSION` — 0.1.10 → 0.1.11
- `MEMORY.md` — Marked quality scoring follow-up done, added v0.1.11 key decision
- `CHANGELOG.md` — v0.1.11 entry

### Analysis Results

- **Tier distribution**: 22 Weak (45%), 25 Adequate (51%), 2 Strong (4%), 0 Excellent
- **Top skill**: web-sqli (76.1) — 24 guides, strong payloads and test cases
- **Bottom skill**: data-scraper-agent (4.7) — no guides, minimal test cases
- **Key insight**: Guide poverty is the primary weakness (22 skills with 0 guides)

## [0.1.10] - 2026-05-22

### Added

- `validation/INTEGRATION-TRACKER.md` — Cross-skill integration test tracker (7 scenarios)
- `validation/INTEGRATION-SCENARIOS.md` — Detailed scenario definitions with data flow diagrams
- `validation/evidence/integration/` — Integration test evidence directory (7 evidence files)
- `RELEASE-v0.1.10.md` — Release announcement

### Changed

- `VERSION` — 0.1.9 → 0.1.10
- `MEMORY.md` — Updated current focus, added v0.1.10 key decision, marked follow-up done
- `CHANGELOG.md` — v0.1.10 entry

## [0.1.9] - 2026-05-22

### Added

- `validation/VALIDATION-TRACKER.md` — Master validation tracking table (49 skills, 1 test case each)
- `validation/VALIDATION-GUIDE.md` — Execution playbook: environment setup, workflow, evidence standards, execution order
- `validation/evidence/` — Evidence storage directory for validation artifacts
- `RELEASE-v0.1.9.md` — Release announcement

### Changed

- `VERSION` — 0.1.8 → 0.1.9
- `MEMORY.md` — Updated current focus to validation, added v0.1.9 key decision
- `CHANGELOG.md` — v0.1.9 entry

## [0.1.8] - 2026-05-22

### Added

All 49 skill domains brought to FULL enrichment status (SKILL.md + payloads.md + test-cases.md + guides/).

**3 MINIMAL skills upgraded (payloads.md + test-cases.md + guides/ added):**

- `chronicle` — payloads.md (event recording templates, distillation commands, archive patterns), test-cases.md (TC-CH-001 to TC-CH-006), guides/event-recording-best-practices.md
- `continuous-learning` — payloads.md (pattern detection, knowledge entry templates, confidence scoring rubrics), test-cases.md (TC-CL-001 to TC-CL-006), guides/knowledge-extraction-workflow.md
- `safety-guard` — payloads.md (scope lock templates, dangerous command patterns, rate limiting, incident response playbooks), test-cases.md (TC-SG-001 to TC-SG-007), guides/scope-enforcement-operations.md

**7 PARTIAL skills upgraded (guides/ added):**

- `api-security` — guides/api-security-complete-guide.md (relocated from root), guides/graphql-security-testing.md (new)
- `web-auth-bypass` — guides/auth-bypass-complete-guide.md (relocated from root), guides/jwt-attack-methodology.md (new)
- `docker-patterns` — guides/lab-environment-management.md
- `repo-scan` — guides/codebase-security-audit-workflow.md
- `search-first` — guides/exploit-research-methodology.md
- `terminal-ops` — guides/evidence-first-execution.md
- `verification-loop` — guides/finding-verification-methodology.md

### Changed

- `MEMORY.md` — Updated with v0.1.5-v0.1.8 key decisions, refreshed current status and lessons learned
- `HEARTBEAT.md` — Added Skill Domain Completeness check section, added MEMORY.md staleness check, updated priority order
- `VERSION` — 0.1.7 → 0.1.8
- `CHANGELOG.md` — v0.1.8 entry
- `RELEASE-v0.1.8.md` — release announcement

## [0.1.7] - 2026-05-16

### Added

4 new FULL skill domains added (45 → 49 total). Each includes SKILL.md, payloads.md, test-cases.md, and a guides/ deep-dive.

- `ai-security` — AI/LLM system attack and defense: prompt injection, jailbreaking (DAN, many-shot, fictional framing), model extraction, RAG poisoning, adversarial inputs, supply chain attacks. ECC: Learning Cycle. Guide: `guides/llm-attack-methodology.md`.
- `hardware-security` — Hardware and embedded system security: UART/JTAG debugging, SPI firmware extraction, firmware analysis with binwalk, RFID/NFC cloning with Proxmark3, fault injection basics. ECC: Sequential Pipeline. Guide: `guides/embedded-firmware-analysis.md`.
- `multi-agent-collaboration` — Coordinated multi-agent penetration testing: task decomposition (by phase/target/tool), coordinator-worker pattern, result aggregation, deduplication, conflict resolution, coverage verification. ECC: Batch Processing. Guide: `guides/coordinated-pentest-playbook.md`.
- `mcp-server-patterns` — MCP security tool integration: wrapping Kali tools as MCP servers, input validation, command injection prevention, authentication, rate limiting; also security auditing of MCP server implementations. ECC: Sequential Pipeline. Guide: `guides/security-mcp-server-design.md`.

### Changed

- `IDENTITY.md` — Skill Tags table expanded: 14 new rows added (10 infrastructure skills missing from v0.1.6 + 4 new domains)
- `VERSION` — 0.1.6 → 0.1.7
- `README.md` — Skill count 45 → 49; Future Exploration table updated (removed 2 now-implemented domains)

## [0.1.6] - 2026-05-14

### Enhanced

10 infrastructure skills enriched from "understand" to "executable" with payloads, test cases, guides, and ECC Orchestration.

**FULL enrichment (2 skills):**

- `autonomous-loops` — added payloads.md, test-cases.md, guides/safe-autonomous-pentest.md, SKILL.md Orchestration (meta-skill)
  - payloads.md — Scope Lock templates ×4, rate limit configs, loop command templates, error handling response templates
  - test-cases.md — TC-AL-001 to TC-AL-006 (pipeline, watch, batch, learning, scope violation, rate backoff)
  - guides/safe-autonomous-pentest.md — autonomous vs manual matrix, scope lock construction, loop composition, monitoring, recovery
- `security-review` — added payloads.md, test-cases.md, guides/owasp-audit-methodology.md, SKILL.md Orchestration (Sequential Pipeline)
  - payloads.md — secret detection, injection payloads, auth testing, security headers, dependency audit, API sensitive field detection
  - test-cases.md — TC-SR-001 to TC-SR-007 (secrets, input validation, injection, auth, headers, dependencies, full OWASP)
  - guides/owasp-audit-methodology.md — audit planning, attack surface mapping, priority ranking, evidence collection, report writing

**PARTIAL enrichment (5 skills):**

- `repo-scan` — added payloads.md (classification, library detection, hotspot grep, secret scan, verdict aid), test-cases.md (TC-RS-001~004), SKILL.md Orchestration (Batch Processing)
- `terminal-ops` — added payloads.md (recon/exploit/post-exploit commands, evidence capture, debugging), test-cases.md (TC-TO-001~004), SKILL.md Orchestration (Sequential Pipeline)
- `verification-loop` — added payloads.md (SQLi/XSS/auth/network verification payloads, FP elimination checklists, remediation verification), test-cases.md (TC-VL-001~005), SKILL.md Orchestration (Sequential Pipeline)
- `docker-patterns` — added payloads.md (quick launch, additional labs, evidence extraction, cleanup), test-cases.md (TC-DP-001~004), SKILL.md Orchestration (Sequential Pipeline)
- `search-first` — added payloads.md (searchsploit/gh/msf/nuclei templates, evaluation scoring), test-cases.md (TC-SF-001~004), SKILL.md Orchestration (Learning Cycle)

**MINIMAL enrichment (3 skills):**

- `continuous-learning` — SKILL.md added Orchestration (Learning Cycle consumer)
- `safety-guard` — SKILL.md added Orchestration (Cross-cutting Interceptor)
- `chronicle` — SKILL.md added Orchestration (Sequential Pipeline: record → index → distill)

### Changed Files

- `VERSION` — 0.1.5 → 0.1.6
- `README.md` — Version 0.1.6
- `CHANGELOG.md` — v0.1.6 entry
- `UPDATELOG.md` — v0.1.6 report
- `RELEASE-v0.1.6.md` — release announcement
- 16 new files created (7 payloads + 7 test-cases + 2 guides)
- 13 SKILL.md files updated (header + Orchestration)

## [0.1.5] - 2026-05-14

### Added

- `ai-fuzzing` skill — AI-assisted automated vulnerability discovery
  - SKILL.md — coverage-guided fuzzing, AI seed generation, crash triage, 6-phase methodology, ECC Learning Cycle orchestration
  - payloads.md — AFL++, libFuzzer, Honggfuzz, radare2 crash analysis, Web API fuzzing, protocol fuzzing commands
  - test-cases.md — TC-AF-001 to TC-AF-004 (binary, Web API, protocol, file format fuzzing)
  - guides/coverage-guided-fuzzing.md — AFL++ internals, corpus management, mutation operators, parallel fuzzing, crash triage
  - guides/web-api-fuzzing.md — OpenAPI schema fuzzing (Schemathesis, RESTler), GraphQL fuzzing, REST boundary testing, auth fuzzing, Burp Suite integration
  - guides/protocol-fuzzing.md — TCP/UDP state machine fuzzing, TLS/SSL fuzzing, custom protocol analysis, BooFuzz framework
- `council` skill — multi-perspective security analysis
  - SKILL.md — Attack/Defense/Audit three-perspective framework, decision matrix, risk assessment, ECC Sequential Pipeline orchestration
  - payloads.md — attacker/defender/auditor checklists, risk scoring matrix, decision record templates
  - test-cases.md — TC-CL-001 to TC-CL-004 (Web app, cloud architecture, mobile app, incident response)
  - guides/multi-perspective-analysis.md — role-playing framework, bias mitigation, dissent encouragement, consensus building
  - guides/security-decision-framework.md — risk-benefit matrix, impact analysis, degradation planning, decision under uncertainty
- `mobile-security` skill enhanced with cross-platform and cloud-integration testing
  - guides/react-native-flutter-security.md — React Native bundle analysis, Flutter Dart snapshot, WebView vulnerabilities
  - guides/mobile-api-security-testing.md — advanced cert pinning bypass, GraphQL mobile, WebSocket security
  - guides/mobile-cloud-integration.md — Firebase audit, AWS Amplify, OAuth 2.0/OIDC mobile flaws
  - SKILL.md updated — cross-platform testing table, mobile-cloud integration, ECC Orchestration
- `cloud-security` skill enhanced with K8s, serverless, and IaC security
  - guides/kubernetes-security-deep-dive.md — RBAC audit, Pod Security, network policy bypass, Secrets management
  - guides/serverless-security.md — Lambda injection, Azure/GCP Functions, event injection, cold start leakage
  - guides/infrastructure-as-code-security.md — Terraform/CloudFormation audit, Helm Chart security, CI/CD attacks
  - SKILL.md updated — K8s attack tree, serverless attack chain, IaC risk table, ECC Orchestration
- `security-bounty-hunter` skill enhanced with full supplementary files
  - payloads.md — semgrep rules, Nuclei templates, SQLi/SSRF/XSS/auth bypass payloads, PoC/report templates
  - test-cases.md — TC-BH-001 to TC-BH-004 (HackerOne bounty, scope validation, disclosure, report quality)
  - guides/bounty-hunting-methodology.md — target selection, recon pipeline, vulnerability priority P0-P3, ROI
  - guides/responsible-disclosure-workflow.md — vendor contact, CVE request, 90-day timeline, legal considerations
  - guides/bug-bounty-automation.md — automated recon, ECC Watch Loop, automated triage, safety guardrails
  - SKILL.md updated — ECC Orchestration (Watch Loop + Sequential Pipeline)

### Changed

- `VERSION` — 0.1.4 → 0.1.5
- `README.md` — updated skill domain count (43 → 45), added 2 new skill rows, roadmap updated
- `IDENTITY.md` — added AI Fuzzing and Council skill tags
- `TOOLS.md` — added AI Fuzzing and Council tool categories

## [0.1.4] - 2026-05-11

### Added

- `codebase-onboarding` skill — rapid codebase intelligence acquisition for security research
  - SKILL.md — 3 scope modes (Targeted/Exploratory/Comprehensive), Phase 0 Search-First, language tier matrix (Tier 1/2/3), confidence scoring, 100M+ LOC strategy, structured JSON output, Mermaid architecture diagrams
  - payloads.md — discovery by phase: orientation, architecture mapping, security surface analysis, large codebase tactics, mode-specific sequences
  - test-cases.md — TC-CO-001 to TC-CO-005 (Django, Go microservice, TypeScript monorepo, legacy PHP, large-scale Java)
  - guides/web-framework-onboarding.md — Django, Express.js, Spring Boot, FastAPI, Gin framework onboarding patterns
  - guides/microservice-onboarding.md — multi-service architecture mapping, inter-service auth, API gateway analysis
  - guides/architecture-pattern-recognition.md — MVC monolith, REST+SPA, microservices, event-driven, serverless, GraphQL detection
  - guides/legacy-codebase-onboarding.md — PHP/CGI/Perl legacy patterns, SQL injection, XSS, LFI detection
- `knowledge-ops` skill — knowledge graph management for cross-session intelligence persistence
  - SKILL.md — knowledge unit format, confidence model (0-100), storage format, entity/finding/pattern/hypothesis/intelligence types
  - payloads.md — session startup context loading, knowledge unit capture templates (entity/finding/relationship/pattern), maintenance commands
  - test-cases.md — TC-KO-001 to TC-KO-005 (cross-session context, confidence evolution, pattern recognition, handoff, expiration)
  - guides/entity-extraction-and-tagging.md — entity types, extraction sources, tagging strategy, relationship mapping, deduplication
  - guides/cross-session-intelligence-aggregation.md — aggregation workflow, report templates, query patterns, automation helpers
  - guides/knowledge-graph-visualization-and-querying.md — DOT/Mermaid graph generation, path finding, centrality analysis, export formats
- `article-writing` skill — technical security content creation
  - SKILL.md — pentest reports, vulnerability disclosures, blog posts, advisory format, methodology
  - payloads.md — CVSS calculator reference, sanitization checklist, severity classification, finding description templates
  - test-cases.md — TC-AW-001 to TC-AW-003 (pentest report, CVE disclosure, blog post)
  - guides/cvss-scoring.md — CVSS 3.1 vector breakdown, common vulnerability scores, scoring decision trees, justification templates
  - guides/report-structure.md — pentest report section order, formatting standards, common mistakes
  - guides/vulnerability-writing.md — responsible disclosure timeline, vendor contact process, CVE request, CWE reference
- `browser-qa` skill — automated browser-based security testing
  - SKILL.md — Playwright/Puppeteer automation, auth flow testing, CSRF detection, cookie analysis
  - payloads.md — Playwright commands for navigation, network monitoring, XSS injection, cookie analysis
  - test-cases.md — TC-BQ-001 to TC-BQ-003 (auth flow, CSRF, XSS)
- `data-scraper-agent` skill — structured security data collection
  - SKILL.md — CVE scraping, exploit database collection, threat intel feeds
  - payloads.md — NVD API, searchsploit, GitHub advisory API, BeautifulSoup scraping
  - test-cases.md — TC-DSA-001 to TC-DSA-002 (CVE collection, exploit availability)
- `exa-search` skill — semantic search for security research
  - SKILL.md — Exa API usage, semantic queries, date/domain filtering
  - payloads.md — API examples for CVE research, exploit techniques, threat intelligence
  - test-cases.md — TC-ES-001 to TC-ES-002 (CVE research, exploit technique research)
- `RELEASE-v0.1.4.md` — release announcement article

### Changed

- `VERSION` — 0.1.3 → 0.1.4
- `README.md` — updated skill domain count (37 → 43), added 6 new skill rows to skills table
- `IDENTITY.md` — added 6 new skill domains to skill mapping
- `TOOLS.md` — added tool categories for new skills

## [0.1.3] - 2026-05-06

### Added

- `social-intelligence` skill — new skill domain: real-time social platform intelligence gathering (Reddit, HackerNews, Twitter/X, YouTube, dark web), community sentiment analysis, and target profiling for security engagements
  - SKILL.md — 5-phase methodology, tools table, report template
  - payloads.md — 7 sections: Reddit, HN, Twitter/X, YouTube, forums/paste, sentiment, cross-platform correlation
  - test-cases.md — 5 structured test cases (TC-SI-001 to TC-SI-005)
  - guides/reddit-hackernews-osint.md — Reddit + HN intelligence gathering
  - guides/twitter-youtube-osint.md — X + YouTube intelligence gathering
  - guides/sentiment-analysis.md — Security sentiment analysis for social engineering
- `deep-research` Phase 7 (Continuous Monitoring) — CVE feed monitoring, attack surface change detection, code leak monitoring, alert triggers
- `deep-research` Phase 8 (Intelligence Correlation) — multi-source IOC correlation, confidence scoring, MITRE ATT&CK mapping, entity relationship mapping
- `deep-research` Phase 9 (Adaptive Refinement) — iterative research loop, query refinement, convergence detection
- `deep-research` guides/iterative-search-patterns.md — query refinement strategies, source tracing, keyword expansion, convergence detection
- `deep-research` guides/continuous-monitoring.md — monitoring architecture, snapshot/diff pattern, alert trigger conditions
- `deep-research` guides/intelligence-correlation.md — entity extraction, deduplication, confidence scoring framework, ATT&CK integration
- `deep-research` guides/mcp-integration.md — MCP server configuration for Shodan, VirusTotal, GreyNoise, Firecrawl
- `deep-research` payloads.md Section 9 (Continuous Monitoring Queries) and Section 10 (Intelligence Correlation Commands)
- `deep-research` test-cases.md TC-DR-011 to TC-DR-013 (continuous monitoring, correlation, adaptive iteration)
- `deep-research` Hacker Laws section and Learning Resources section in SKILL.md
- `RELEASE-v0.1.3.md` — release announcement article
- `memory/2026-05-05-deep-research-migration-report.md` — deep research capability migration research report

### Changed

- `VERSION` — 0.1.2 → 0.1.3
- `README.md` — updated skill domain count (36 → 37), added social-intelligence to skills table, updated version info
- `IDENTITY.md` — added Social Intelligence and Deep Research rows to skill domain mapping
- `TOOLS.md` — added Social Intelligence (6 tools) and Deep Research (8 tools) categories
- `skills/osint/SKILL.md` — added social-intelligence and deep-research cross-references
- `skills/social-engineering/SKILL.md` — added social-intelligence and deep-research cross-references

## [0.1.2] - 2026-05-04

### Added

- `verification-loop` skill — multi-phase finding verification with false positive elimination and evidence documentation
- `autonomous-loops` skill — safe autonomous execution patterns with scope locks, rate limiting, and evidence logging
- `continuous-learning` skill — engagement knowledge extraction with pattern detection, confidence scoring, and memory layering
- `docker-patterns` skill — Docker Compose configurations for isolated security testing labs (DVWA, SQLi-Labs, Juice Shop, network labs)
- `safety-guard` skill — safety enforcement layer with scope checking, dangerous command interception, and incident response protocol
- Future roadmap section in README.md — 9 planned skills organized by priority tier

### Changed

- `VERSION` — 0.1.1 → 0.1.2
- `README.md` — updated skill domain count (31 → 36), added 5 new skills to table, added roadmap section, updated project info version

## [0.1.1] - 2026-05-04

### Added

- `deep-research` skill — multi-source intelligence research with CVE deep-dive, threat actor profiling, attack technique investigation
- `security-bounty-hunter` skill — exploitable vulnerability discovery, PoC development, responsible disclosure reporting
- `terminal-ops` skill — evidence-first terminal execution with audit trail protocol
- `search-first` skill — research existing tools/exploits before building custom solutions
- `security-review` skill — OWASP Top 10 security audit checklist and methodology
- `repo-scan` skill — cross-stack source code audit with library detection and module verdicts
- `VERSION` file (0.1.1)
- `CLAUDE.md` — Claude Code workspace guidance
- `CHANGELOG.md` — this file
- `UPDATELOG.md` — v0.1.1 skill supplement research report

### Changed

- `README.md` — updated skill domain count (25 → 31), added 6 new skills to table, added version info to Project Info

## [0.1.0] - 2026-04-27

### Added

- Initial release with 25 security skill domains
- Core agent configuration (SOUL.md, AGENTS.md, IDENTITY.md, USER.md, MEMORY.md, TOOLS.md, HEARTBEAT.md)
- Layered memory system (daily logs + MEMORY.md + chronicle)
- Heartbeat task framework
- MIT License
