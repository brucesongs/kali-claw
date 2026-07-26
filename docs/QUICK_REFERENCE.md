# kali-claw SKILL 速查表

> **版本**: v0.2.0.8 | **生成日期**: 2026-07-26 | **SKILL 总数**: 137

按渗透测试场景分类的快速参考。每个场景列出对应的 SKILL。

---

## Web 应用渗透测试

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `api-security` | API Security Testing covers security assessment across three major API architect... | ✓ | ✓ | ✓ |
| `cms-framework-attack` | Targeted security assessment of Content Management Systems (WordPress, Joomla, D... | ✓ | ✓ | ✓ |
| `command-injection-advanced` | Advanced injection attacks beyond SQL - covering OS command injection, LDAP inje... | ✓ | ✓ | ✓ |
| `file-inclusion` | Local File Inclusion (LFI) and Remote File Inclusion (RFI) attack techniques cov... | ✓ | ✓ | ✓ |
| `web-access-control` | Broken Access Control (OWASP Top 10 2025 - A01) attacks and defense — covering c... | ✓ | ✓ | ✓ |
| `web-auth-bypass` | Authentication Bypass refers to attackers exploiting design flaws or implementat... | ✓ | ✓ | ✓ |
| `web-deserialization` | Deserialization vulnerabilities arise when an application reconstructs objects f... | ✓ | ✓ | ✓ |
| `web-sqli` | SQL injection attacks and defense - covering all major SQLi types including erro... | ✓ | ✓ | ✓ |
| `web-ssrf` | Server-Side Request Forgery (SSRF) attacks including basic, blind, and advanced ... | ✓ | ✓ | ✓ |
| `web-xss` | XSS (Cross-Site Scripting) is an attack that injects malicious scripts into trus... | ✓ | ✓ | ✓ |
| `web-xxe` | XML External Entity (XXE) injection exploits vulnerable XML parsers to read loca... | ✓ | ✓ | ✓ |

## 网络渗透测试

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `dns-attacks` | DNS Attacks exploit the Domain Name System protocol for reconnaissance, spoofing... | ✓ | ✓ | ✓ |
| `network-pentest` | Network penetration testing covering the full attack chain from reconnaissance, ... | ✓ | ✓ | ✓ |
| `network-sniffing-mitm` | Network Sniffing and MITM attacks focus on intercepting, analyzing, and manipula... | ✓ | ✓ | ✓ |
| `network-tunneling-proxy` | Network tunneling encapsulates one protocol inside another to bypass firewalls, ... | ✓ | ✓ | ✓ |
| `voip-sip-attack` | Voice over IP (VoIP) systems use the Session Initiation Protocol (SIP) for call ... | ✓ | ✓ | ✓ |
| `vpn-attack` | Virtual Private Networks (VPNs) are a critical component of enterprise network s... | ✓ | ✓ | ✓ |

## 云安全评估

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `cloud-identity-attack` | Cloud identity provider attacks covering Azure AD/Entra ID, Okta, Auth0, Ping, A... | ✓ | ✓ | ✓ |
| `cloud-native-vuln-research` | CVE research methodology, PoC reproduction, patch gap analysis, and exploit chai... | ✓ | ✓ | ✓ |
| `cloud-security` | Cloud security covers security assessment for major cloud platforms including AW... | ✓ | ✓ | ✓ |
| `container-security` | Container security covers the complete lifecycle from image building, registry m... | ✓ | ✓ | ✓ |
| `cspm-casb-attack` | CSPM/CASB/CNAPP platform bypass and abuse — rule suppression exploitation, IaC s... | ✓ | ✓ | ✓ |
| `docker-patterns` | Setting up a practice lab for penetration testing techniques - Creating isolated... | ✗ | ✓ | ✓ |
| `gitops-security` | Attacks against GitOps control planes (Argo CD, FluxCD, Jenkins X, Tekton, Fleet... | ✓ | ✓ | ✓ |
| `kubernetes-attack` | Kubernetes cluster attack and red team covering RBAC abuse, pod escape (privileg... | ✓ | ✓ | ✓ |
| `sase-sse-attack` | Secure Access Service Edge (SASE) and Security Service Edge (SSE) platform compr... | ✓ | ✓ | ✓ |

## 移动安全测试

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `mobile-app-instrumentation` | Dynamic instrumentation of iOS/Android apps via Frida, Objection, r2frida, and I... | ✓ | ✓ | ✓ |
| `mobile-security` | Mobile security covers the complete attack/defense chain of Android/iOS applicat... | ✓ | ✓ | ✓ |

## 硬件 / IoT 渗透

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `bluetooth-rfid-nfc` | Near-field wireless penetration testing skills covering Bluetooth Classic device... | ✓ | ✓ | ✓ |
| `embedded-rtos-security` | RTOS penetration testing — VxWorks WDB debug agent (Urgent/11), QNX microkernel,... | ✓ | ✓ | ✓ |
| `firmware-reverse` | Firmware reverse engineering covers the full pipeline from raw firmware image ac... | ✓ | ✓ | ✓ |
| `hardware-security` | Hardware and embedded system security testing covering physical interface exploi... | ✗ | ✓ | ✓ |
| `hardware-side-channel-advanced` | Advanced hardware side-channel attacks covering power analysis (SPA/DPA), electr... | ✓ | ✓ | ✓ |
| `hsm-attack` | Hardware Security Module attacks — physical (side-channel, fault injection, deca... | ✓ | ✓ | ✓ |
| `iot-pentest` | IoT application-layer penetration testing covering MQTT broker abuse, CoAP serve... | ✓ | ✓ | ✓ |

## OSINT / 情报收集

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `darkweb-intel` | Dark web intelligence gathering — Tor/onion service reconnaissance, marketplace ... | ✓ | ✓ | ✓ |
| `osint` | A specialized skill for intelligence gathering using publicly available sources. | ✓ | ✓ | ✓ |
| `recon-osint` | The most critical first step in penetration testing. Information gathering deter... | ✓ | ✓ | ✓ |
| `social-intelligence` | Real-time intelligence gathering from social platforms and community discussions... | ✓ | ✓ | ✓ |
| `threat-intel-platform-attack` | Attacking threat intelligence platforms (MISP, OpenCTI, Anomali ThreatStream, Th... | ✓ | ✓ | ✓ |
| `username-profiling` | Build a complete dossier on a person using only a username. | ✓ | ✓ | ✓ |

## 权限提升 / 后渗透

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `ad-cs-abuse` | Active Directory Certificate Services (AD CS) abuse — ESC1-ESC15 attack patterns... | ✓ | ✓ | ✓ |
| `ad-ldap-attack` | Active Directory is the backbone of enterprise identity and access management, m... | ✓ | ✓ | ✓ |
| `pam-privilege-attack` | Privileged Access Management (PAM) vendor abuse — CyberArk PVWA/PSM/EPV/AIM/CFE,... | ✓ | ✓ | ✓ |
| `post-exploitation` | Post-exploitation covers the complete attack chain after obtaining initial acces... | ✓ | ✓ | ✓ |
| `privilege-escalation` | Privilege escalation is the process of elevating access from a low-privileged us... | ✓ | ✓ | ✓ |

## 社会工程

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `email-protocol-attack` | Email protocol attacks targeting mail infrastructure at the protocol level. | ✓ | ✓ | ✓ |
| `email-security-deep` | Phishing infrastructure and email gateway bypass covering AiTM MFA interception ... | ✓ | ✓ | ✓ |
| `social-engineering` | Social engineering is the art of exploiting human psychological weaknesses rathe... | ✓ | ✓ | ✓ |

## 凭证攻击

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `identity-provider-attack` | Identity Provider (IdP) attack patterns covering OAuth 2.0/OIDC, SAML, JWT, toke... | ✓ | ✓ | ✓ |
| `password-attack` | Password attacks encompass the complete attack chain from hash extraction, hash ... | ✓ | ✓ | ✓ |
| `secret-management-attack` | Secret discovery, SAST code audit, and secrets-management platform attack coveri... | ✓ | ✓ | ✓ |

## AV / EDR 规避

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `anti-forensics` | Anti-forensics is the offensive counterpart to digital forensics. | ✓ | ✓ | ✓ |
| `av-edr-evasion` | AV/EDR evasion covers techniques for bypassing antivirus (AV) and Endpoint Detec... | ✓ | ✓ | ✓ |
| `malware-analysis-advanced` | Advanced malware analysis covering unpacking (UPX, VMProtect, Themida, Enigma, c... | ✓ | ✓ | ✓ |

## 二进制分析 / 漏洞利用

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `binary-reverse` | Binary reverse engineering covers the complete chain from static analysis, dynam... | ✓ | ✓ | ✓ |
| `concurrency-exploitation` | Concurrency exploitation covers race condition vulnerabilities including TOCTOU,... | ✗ | ✓ | ✓ |
| `exploit-development` | Exploit development covers the full chain from vulnerability discovery through c... | ✓ | ✓ | ✓ |
| `patch-to-poc-pipeline` | The end-to-end patch-diff vulnerability reproduction workflow — patch analysis (... | ✓ | ✓ | ✓ |
| `payload-generation` | Payload generation covers the creation, encoding, and delivery of shellcode and ... | ✓ | ✓ | ✓ |
| `protocol-state-exploitation` | Protocol state exploitation targets vulnerabilities in network protocol state ma... | ✓ | ✓ | ✓ |
| `reverse-engineering-advanced` | Advanced reverse engineering covering symbolic execution (angr, KLEE, manticore)... | ✓ | ✓ | ✓ |

## AI / LLM 安全

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `agentic-pentest` | LLM-driven autonomous penetration testing framework operations covering PentestG... | ✓ | ✓ | ✓ |
| `ai-agent-framework-attack` | AI agent framework attack surface — orchestration-layer compromise of LangChain ... | ✓ | ✓ | ✓ |
| `ai-agent-security` | Offensive security testing of AI agent systems covering MCP server attacks, tool... | ✓ | ✓ | ✓ |
| `ai-fuzzing` | AI-assisted fuzzing for automated vulnerability discovery. Coverage-guided fuzzi... | ✓ | ✓ | ✓ |
| `ai-safety-redteam-advanced` | Advanced AI safety red team operations covering OWASP LLM Top 10 (2025), prompt ... | ✓ | ✓ | ✓ |
| `ai-security` | Semantic-layer attack testing against AI systems and LLM-integrated applications... | ✓ | ✓ | ✓ |
| `llm-red-team` | LLM and generative AI red team testing covering prompt injection, jailbreaking (... | ✓ | ✓ | ✓ |

## 区块链 / Web3

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `blockchain-l2-attack` | Layer-2 blockchain attack — Lightning Network (BOLT, HTLC), Optimistic Rollups (... | ✓ | ✓ | ✓ |
| `blockchain-web3` | Blockchain & Web3 security — Solidity/Vyper smart contract auditing, DeFi attack... | ✓ | ✓ | ✓ |

## ICS / SCADA / CPS

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `cps-attack` | Cyber-Physical Systems (CPS) attacks — PLCs (Siemens S7, Rockwell ControlLogix, ... | ✓ | ✓ | ✓ |
| `ics-fieldbus-attack` | Industrial fieldbus protocol penetration testing beyond Modbus — Profibus/PROFIN... | ✓ | ✓ | ✓ |
| `scada-ics-security` | SCADA/ICS security assessment covering industrial control system protocols inclu... | ✓ | ✓ | ✓ |

## 电信 / 5G

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `5g-6g-telecom-attack-advanced` | Advanced 5G/6G telecom attacks covering 5G Core (SBA) exploitation, IMSI catcher... | ✓ | ✓ | ✓ |
| `5g-telecom-attack` | 5G core (AMF/SMF/UPF), RAN, signaling (PFCP/GTP/Diameter/SS7), IMSI catchers, O-... | ✓ | ✓ | ✓ |

## 汽车 / 车辆

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `automotive-vehicle-security` | CAN/CAN-FD bus analysis, UDS diagnostics, IVI pentest, OBD-II exploitation, key ... | ✓ | ✓ | ✓ |

## 卫星 / 航空

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `hf-vhf-radio-attack` | Licensed HF/VHF/UHF radio attack — ADS-B 1090 MHz, AIS, ACARS, VDL Mode 2, POCSA... | ✓ | ✓ | ✓ |
| `satellite-leo-security` | Satellite and LEO communication security — Starlink, Kuiper, OneWeb, Iridium, In... | ✓ | ✓ | ✓ |
| `sdr-rf-attack` | Software Defined Radio and RF signal attacks encompass a broad range of offensiv... | ✓ | ✓ | ✓ |
| `uav-drone-security` | UAV/drone security testing — PX4/ArduPilot autopilot attacks, MAVLink protocol f... | ✓ | ✓ | ✓ |

## 数据保护 / 外泄

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `data-exfiltration-attack` | Attacks for exfiltrating data from compromised networks and bypassing DLP/egress... | ✓ | ✓ | ✓ |
| `data-loss-prevention-bypass` | DLP bypass techniques covering steganography (LSB, audio, video), DNS tunneling,... | ✓ | ✓ | ✓ |
| `data-platform-attack` | Attacks against cloud data platforms and analytics pipelines — Snowflake, Databr... | ✓ | ✓ | ✓ |
| `database-attack` | Direct attacks against database servers at the protocol level — distinct from we... | ✓ | ✓ | ✓ |
| `steganography` | Steganography is the practice of concealing data within non-secret carrier files... | ✓ | ✓ | ✓ |
| `storage-san-attack` | Storage/SAN/NAS/Object storage penetration testing — iSCSI, Fibre Channel, NFSv3... | ✓ | ✓ | ✓ |

## 密码学 / 量子

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `crypto-attacks` | Cryptographic Attacks target implementation flaws and algorithm weaknesses in en... | ✓ | ✓ | ✓ |
| `post-quantum-migration-attack` | Attacks against cryptographic systems during the PQC migration period. Covers Ha... | ✓ | ✓ | ✓ |
| `quantum-crypto-attack` | Post-quantum and modern national cryptography attack surface testing covering NI... | ✓ | ✓ | ✓ |
| `quantum-cryptography-transition` | Post-Quantum Cryptography (PQC) transition security covering NIST standards (ML-... | ✓ | ✓ | ✓ |

## 边缘计算 / CDN

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `edge-computing-attack` | Attacks against edge computing platforms — Cloudflare Workers (V8 isolate), Fast... | ✓ | ✓ | ✓ |
| `edge-computing-security` | Edge computing security testing covering CDN bypass, Cloudflare Workers abuse, A... | ✓ | ✓ | ✓ |

## 供应链 / CI/CD

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `ci-cd-supply-chain-attack` | CI/CD pipeline and software supply chain compromise covering Jenkins (script con... | ✓ | ✓ | ✓ |
| `repo-scan` | Cross-stack source code asset audit that classifies every file, detects embedded... | ✓ | ✓ | ✓ |
| `supply-chain-security` | Software supply chain security covering the entire lifecycle from code developme... | ✓ | ✓ | ✓ |

## 取证 / 检测

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `chronicle` | A system for recording, indexing, and distilling knowledge from agent lifecycle ... | ✗ | ✓ | ✓ |
| `deception-honeypot` | Defensive deception and honeypot deployment covering SSH/Telnet (Cowrie), web (O... | ✓ | ✓ | ✓ |
| `detection-engineering` | Detection-as-code engineering covering Sigma rule authoring, YARA signature deve... | ✓ | ✓ | ✓ |
| `digital-forensics` | Digital forensics covers the complete workflow of disk forensics, memory forensi... | ✓ | ✓ | ✓ |
| `logging-monitoring` | Security logging and monitoring deficiencies (OWASP A09:2021) refer to applicati... | ✓ | ✓ | ✓ |
| `threat-hunting` | Proactive threat hunting — MITRE ATT&CK-mapped hunt hypotheses, Sigma detection ... | ✓ | ✓ | ✓ |

## 报告 / 流程

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `engagement-manager` | End-to-end penetration test project management skill. Orchestrates the full enga... | ✓ | ✓ | ✓ |
| `pentest-reporting` | Initialize Dradis for collaborative report authoring and Faraday for vulnerabili... | ✓ | ✓ | ✓ |
| `security-review` | Comprehensive security checklist and review patterns for analyzing applications,... | ✓ | ✓ | ✓ |
| `verification-loop` | After discovering a potential vulnerability or exploit - Before submitting any f... | ✗ | ✓ | ✓ |
| `vulnerability-assessment` | Vulnerability assessment is the process of systematically identifying and quanti... | ✓ | ✓ | ✓ |

## 智能体 / MCP

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `autonomous-loops` | Performing repetitive enumeration across many targets - Running batch vulnerabil... | ✗ | ✓ | ✓ |
| `continuous-learning` | After completing a penetration test engagement - When encountering a novel attac... | ✗ | ✓ | ✓ |
| `council` | Council provides a structured framework for analyzing security questions from mu... | ✓ | ✓ | ✓ |
| `mcp-server-patterns` | Building and security-testing MCP (Model Context Protocol) servers for Kali Linu... | ✗ | ✓ | ✓ |
| `multi-agent-collaboration` | Coordinating multiple specialized agents to conduct complex penetration testing ... | ✗ | ✓ | ✓ |
| `multi-agent-runtime-engineering` | Runtime engineering discipline for agent systems — structured JSON memory schema... | ✓ | ✓ | ✓ |

## 金融 / 支付

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `open-banking-attack` | Open Banking / PSD2 / Open Finance attacks — FAPI (Financial-grade API), OpenID ... | ✓ | ✓ | ✓ |
| `payment-security` | Payment systems security — PCI-DSS compliance testing, payment API security (Str... | ✓ | ✓ | ✓ |

## 游戏安全

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `game-anticheat-bypass` | Security research on game anti-cheat systems (EAC/BattlEye/Vanguard/Ricochet) — ... | ✓ | ✓ | ✓ |

## Red Team

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `physical-security-testing` | Physical penetration testing covering mechanical lock bypass (pin-tubular/wafer)... | ✓ | ✓ | ✓ |
| `red-team-infrastructure` | Building, deploying, and operating stealthy C2 infrastructure for red team engag... | ✓ | ✓ | ✓ |

## 其他

| SKILL | 描述 | Defense Triple |
|-------|------|----------------|
| `article-writing` | Transform technical findings into clear, structured written content: penetration... | ✗ | ✓ | ✓ |
| `browser-qa` | Automated browser-based security testing using Playwright and browser devtools. ... | ✗ | ✓ | ✓ |
| `codebase-onboarding` | Rapidly acquire a mental model of any unfamiliar codebase — from a 500-line scri... | ✗ | ✓ | ✓ |
| `confidential-computing-attack` | Attacks against Trusted Execution Environments (TEEs) and confidential computing... | ✓ | ✓ | ✓ |
| `data-scraper-agent` | Automated data collection from structured sources: CVE databases, threat intelli... | ✗ | ✓ | ✓ |
| `deep-research` | Multi-source intelligence gathering through systematic web research — producing ... | ✓ | ✓ | ✓ |
| `exa-search` | Semantic search using Exa API for security research queries. Unlike keyword-base... | ✗ | ✓ | ✓ |
| `hypervisor-introspection` | Hypervisor introspection (VMI) and virtualization escape attacks — VMware ESXi, ... | ✓ | ✓ | ✓ |
| `insecure-design` | Insecure Design (OWASP A06:2025) focuses on security flaws in system architectur... | ✓ | ✓ | ✓ |
| `knowledge-ops` | Build and maintain structured, persistent knowledge graphs across sessions. Know... | ✗ | ✓ | ✓ |
| `macos-security` | macOS red team and security assessment — SIP/TCC bypass, Endpoint Security frame... | ✓ | ✓ | ✓ |
| `mainframe-security` | IBM z/OS, RACF (Resource Access Control Facility), CICS, DB2, JES2, TSO/ISPF pen... | ✓ | ✓ | ✓ |
| `safety-guard` | Before executing ANY potentially destructive or irreversible command - When a co... | ✗ | ✓ | ✓ |
| `search-first` | Systematizes the \"search for existing tools, exploits, and techniques before wr... | ✗ | ✓ | ✓ |
| `security-bounty-hunter` | Hunt for exploitable, bounty-worthy security issues in target systems. Focuses o... | ✓ | ✓ | ✓ |
| `security-misconfiguration` | Security misconfiguration detection (OWASP A02:2025) covering default credential... | ✓ | ✓ | ✓ |
| `terminal-ops` | Evidence-first execution workflow for running security commands, inspecting syst... | ✓ | ✓ | ✓ |
| `tool-mastery` | Verification and assessment of practical proficiency with Kali Linux security to... | ✓ | ✓ | ✓ |
