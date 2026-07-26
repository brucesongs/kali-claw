# kali-claw SKILL 使用手册

> **版本**: v0.2.0.8 | **生成日期**: 2026-07-26 | **SKILL 总数**: 137

---

## 目录

- [uncategorized](#uncategorized) (137 个 SKILL)

---

## uncategorized

### 5g-6g-telecom-attack-advanced

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Advanced 5G/6G telecom attacks covering 5G Core (SBA) exploitation, IMSI catcher evolution (5G Stingray), SIP/Diameter protocol attacks, Open RAN vulnerabilities, network slicing abuse, and early 6G research vectors (THz comms, AI-native air interface).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, SKILL.md, test-cases.md

---

### 5g-telecom-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> 5G core (AMF/SMF/UPF), RAN, signaling (PFCP/GTP/Diameter/SS7), IMSI catchers, O-RAN security, roaming abuse, SMS interception, and telecom infrastructure red team operations.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/5g-telecom-attack-deep-dive.md, guides/5g-telecom-attack-playbook.md, SKILL.md, test-cases.md

---

### ad-cs-abuse

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Active Directory Certificate Services (AD CS) abuse — ESC1-ESC15 attack patterns, PKINIT, PetitPotam to AD CS to Domain Admin chains, CVE-2022-26923 (Certifried), Shadow Credentials, Golden Certificate, certificate template ACL abuse, NTLM relay to web enrollment.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/ad-cs-abuse-detection-and-hardening.md, guides/ad-cs-abuse-playbook.md, SKILL.md, test-cases.md

---

### ad-ldap-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Active Directory is the backbone of enterprise identity and access management, making it a primary target during internal network penetration tests.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/ad-lateral-movement-guide.md, guides/ad-recon-enumeration-guide.md, guides/kerberos-attack-guide.md, SKILL.md

---

### agentic-pentest

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> LLM-driven autonomous penetration testing framework operations covering PentestGPT, HexStrike AI, Viper, PentestAgent, AI-Infra-Guard, AutoPWN, and custom agent harness patterns — including reasoning chain orchestration, tool delegation, context window management, output validation, multi-agent pent...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/agent-orchestration-patterns-playbook.md, guides/agentic-pentest-deep-dive.md, guides/agentic-pentest-playbook.md, SKILL.md

---

### ai-agent-framework-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> AI agent framework attack surface — orchestration-layer compromise of LangChain (Python/JS), LangGraph, CrewAI, Microsoft AutoGen, OpenAI Assistants API v2, Anthropic Claude Agent SDK, LlamaIndex, Microsoft Semantic Kernel, Google ADK, SmolAgents, and MCP-integrated agent runtimes. Covers tool poiso...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/ai-agent-framework-attack-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### ai-agent-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Offensive security testing of AI agent systems covering MCP server attacks, tool poisoning, indirect prompt injection against agents, RAG knowledge base poisoning, agent sandbox escape, multi-agent compromise chains, and autonomous agent hijacking — using MCP security testers, HexStrike AI, AI-Infra...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/ai-agent-security-playbook.md, guides/mcp-server-red-team-playbook.md, SKILL.md, test-cases.md

---

### ai-fuzzing

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> AI-assisted fuzzing for automated vulnerability discovery. Coverage-guided fuzzing engines, AI-driven seed generation, intelligent mutation strategies, and systematic crash triage.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/coverage-guided-fuzzing.md, guides/crash-triage-automation-guide.md, guides/crash-triage-guide.md, guides/grammar-based-fuzzing-guide.md

---

### ai-safety-redteam-advanced

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Advanced AI safety red team operations covering OWASP LLM Top 10 (2025), prompt injection (direct/indirect/multi-turn), jailbreak techniques (DAN, cognitive hacking, persona-based), data poisoning detection, model inversion attacks, adversarial examples (evasion), model extraction, and AI supply cha...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/owasp-llm-top10-complete-guide.md, SKILL.md, test-cases.md

---

### ai-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Semantic-layer attack testing against AI systems and LLM-integrated applications.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/adversarial-ml-testing-guide.md, guides/ai-model-security-testing-guide.md, guides/ai-red-team-guide.md, guides/ai-security-jailbreak-research.md

---

### anti-forensics

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Anti-forensics is the offensive counterpart to digital forensics.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/crypto-hide-data-destruction.md, guides/filesystem-anti-forensics.md, guides/log-tamper-timestamp.md, SKILL.md

---

### api-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> API Security Testing covers security assessment across three major API architectures: REST, GraphQL, and gRPC, focusing on the OWASP API Security Top 10 core risks: Broken Authentication, Broken Object Level Authorization (BOLA), Excessive Data Exposure, Rate Limiting Bypass.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, api-security-guide.md, guides/api-authentication-bypass-guide.md, guides/api-rate-limiting-bypass-guide.md, guides/api-security-complete-guide.md

---

### article-writing

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Transform technical findings into clear, structured written content: penetration test reports, vulnerability disclosures, security blog posts, and technical documentation.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cve-advisory-writing-guide.md, guides/cvss-scoring.md, guides/penetration-test-report-guide.md, guides/pentest-report-template-guide.md

---

### automotive-vehicle-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> CAN/CAN-FD bus analysis, UDS diagnostics, IVI pentest, OBD-II exploitation, key fob replay/relay attacks, GNSS spoofing, EV charging station (ISO 15118), and connected vehicle red team operations.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/automotive-ecu-firmware-and-uds-deep-dive.md, guides/automotive-security-testing-tools-guide.md, guides/automotive-vehicle-security-playbook.md, guides/can-bus-reverse-engineering-guide.md

---

### autonomous-loops

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Performing repetitive enumeration across many targets - Running batch vulnerability scans on multiple hosts - Monitoring for changes in target environment - Executing attack chains that require iterative steps - User says \"loop\", \"automate\", \"batch\", \"repeat.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/autonomous-decision-making-guide.md, guides/autonomous-pentest-orchestration-guide.md, guides/batch-processing-guide.md, guides/error-recovery-guide.md

---

### av-edr-evasion

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> AV/EDR evasion covers techniques for bypassing antivirus (AV) and Endpoint Detection/Response (EDR) solutions during payload delivery, execution, and post-exploitation.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/av-edr-evasion-edr-rules-evasion-deep.md, guides/av-edr-evasion-kernel-bypass-deep.md, guides/av-edr-evasion-living-off-the-land-deep.md, guides/av-edr-evasion-real-world-incident-case-studies.md

---

### binary-reverse

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Binary reverse engineering covers the complete chain from static analysis, dynamic debugging, to vulnerability discovery, exploit development, and malware analysis.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/2026-03-21-reverse-engineering-tools.md, guides/Binary_Analysis_Reverse_Engineering_Story.md, guides/anti-reversing-bypass-guide.md, guides/reverse-engineering-cli-reference.md

---

### blockchain-l2-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Layer-2 blockchain attack — Lightning Network (BOLT, HTLC), Optimistic Rollups (Optimism/Arbitrum/Boba/Base), ZK Rollups (zkSync/StarkNet/Polygon zkEVM/Scroll/Linea), Polygon PoS, Gnosis sidechain, cross-chain bridges (Wormhole/Nomad/Ronin/Poly Network/Multichain/Horizon), state channels, ERC-4337 a...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/blockchain-l2-attack-playbook.md, SKILL.md, test-cases.md

---

### blockchain-web3

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Blockchain & Web3 security — Solidity/Vyper smart contract auditing, DeFi attack vectors (flash loans, MEV, oracle manipulation), bridge attacks, wallet security, with tooling from Slither/Mythril/Foundry.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/blockchain-web3-bridge-oracle-exploit-deep.md, guides/blockchain-web3-defi-reentrancy-deep.md, guides/blockchain-web3-real-world-incident-case-studies.md, guides/defi-exploit-testing-playbook.md

---

### bluetooth-rfid-nfc

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Near-field wireless penetration testing skills covering Bluetooth Classic device enumeration and exploitation, BLE GATT service attacks against IoT devices, RFID card cloning (MIFARE Classic/DESFire), NFC tag manipulation, and contactless payment probing.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/ble-gatt-attack.md, guides/bluetooth-device-recon.md, guides/rfid-nfc-clone.md, SKILL.md

---

### browser-qa

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Automated browser-based security testing using Playwright and browser devtools. Interact with web applications as a user would — click, type, navigate — while monitoring network traffic, JavaScript execution, and DOM changes for security issues.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/browser-fingerprint-analysis-guide.md, guides/headless-browser-security-testing-guide.md, guides/network-interception-guide.md, guides/playwright-auth-testing-guide.md

---

### chronicle

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> A system for recording, indexing, and distilling knowledge from agent lifecycle events. Through a three-layer document system (overview -> detailed records -> knowledge distillation), raw conversation events are transformed into reusable experience.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, .DS_Store, chronicle-template.py, guides/cross-session-continuity-guide.md, guides/event-recording-best-practices.md

---

### ci-cd-supply-chain-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> CI/CD pipeline and software supply chain compromise covering Jenkins (script console, Jenkinsfile injection, shared library abuse, CVE-2024-23897 args4j), GitLab CI/CD (runner abuse, .gitlab-ci.yml injection, self-hosted runner takeover, CVE-2022-1162, OmniAuth CVE-2024-9653), GitHub Actions (self-h...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/ci-cd-supply-chain-attack-playbook.md, guides/ci-cd-supply-chain-dependency-confusion-deep.md, guides/ci-cd-supply-chain-github-actions-deep.md, guides/ci-cd-supply-chain-real-world-incident-case-studies.md

---

### cloud-identity-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Cloud identity provider attacks covering Azure AD/Entra ID, Okta, Auth0, Ping, AWS IAM Identity Center, and Google Workspace — including OAuth 2.0 token theft, OIDC redirect abuse, SAML response forgery, conditional access bypass, MFA fatigue, federation compromise (AD FS, Ping), app registration ab...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cloud-identity-attack-device-code-phishing-deep.md, guides/cloud-identity-attack-entra-id-deep.md, guides/cloud-identity-attack-federation-abuse-deep.md, guides/cloud-identity-attack-okta-auth0-deep.md

---

### cloud-native-vuln-research

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> CVE research methodology, PoC reproduction, patch gap analysis, and exploit chain composition across container/k8s/cloud-native surfaces; SBOM-driven vuln management and nuclei template authoring.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cloud-native-vuln-research-playbook.md, SKILL.md, test-cases.md

---

### cloud-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Cloud security covers security assessment for major cloud platforms including AWS, Azure, and GCP, with core focus on IAM misconfiguration detection, storage bucket exposure scanning, metadata service attacks, container escape, and Kubernetes RBAC auditing.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, .DS_Store, guides/aws-pentest-lab-guide.md, guides/azure-privilege-escalation-guide.md, guides/cloud-post-exploitation-guide.md

---

### cms-framework-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Targeted security assessment of Content Management Systems (WordPress, Joomla, Drupal) using specialized scanners and exploit techniques.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cms-identification-enumeration-guide.md, guides/joomla-drupal-cms-attack-guide.md, guides/wordpress-pentest-guide.md, SKILL.md

---

### codebase-onboarding

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Rapidly acquire a mental model of any unfamiliar codebase — from a 500-line script to a 100M+ line monorepo. This skill transforms raw code into structured intelligence: architecture maps, entry points, data flows, security surfaces, and onboarding confidence scores.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/architecture-pattern-recognition.md, guides/dependency-supply-chain-analysis-guide.md, guides/legacy-codebase-onboarding.md, guides/microservice-onboarding.md

---

### command-injection-advanced

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Advanced injection attacks beyond SQL - covering OS command injection, LDAP injection, NoSQL injection, template injection (SSTI), XPath injection, and comprehensive filter bypass techniques.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/blind-injection-techniques.md, guides/command-injection-filter-bypass.md, guides/ldap-nosql-injection-guide.md, guides/ssti-exploitation-guide.md

---

### concurrency-exploitation

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Concurrency exploitation covers race condition vulnerabilities including TOCTOU, signal handler races, thread synchronization bypasses, and timing attacks.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/race-window-amplification.md, guides/signal-handler-race-exploitation.md, guides/threadsanitizer-guide.md, guides/toctou-exploitation-guide.md

---

### confidential-computing-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Attacks against Trusted Execution Environments (TEEs) and confidential computing platforms — Intel SGX (Foreshadow/SGAxe/LVI/ÆPIC Leak), Intel TDX, AMD SEV/SEV-ES/SEV-SNP (CrossLine/BadRAM), Azure CCF, Marblerun, and Gramine/Occlum libos enclaves. Covers side-channel leakage, attestation forgery, AB...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/confidential-computing-attack-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### container-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Container security covers the complete lifecycle from image building, registry management, runtime protection, to orchestration platform (Kubernetes) security.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/2026-03-21-container-security-tools.md, guides/container-escape-techniques-guide.md, guides/container-network-segmentation-guide.md, guides/container-runtime-security-guide.md

---

### continuous-learning

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> After completing a penetration test engagement - When encountering a novel attack technique or defense - After a tool produces unexpected results - When identifying recurring patterns across targets - User says \"learn\", \"remember this\", \"pattern.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/adaptive-learning-strategies-guide.md, guides/cross-domain-knowledge-transfer-guide.md, guides/cross-session-knowledge-aggregation-guide.md, guides/knowledge-decay-detection-guide.md

---

### council

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Council provides a structured framework for analyzing security questions from multiple adversarial and defensive perspectives simultaneously.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/automated-consensus-scoring-guide.md, guides/council-consensus-building-guide.md, guides/multi-agent-escalation-guide.md, guides/multi-perspective-analysis-framework-guide.md

---

### cps-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Cyber-Physical Systems (CPS) attacks — PLCs (Siemens S7, Rockwell ControlLogix, Schneider Modicon, Mitsubishi MELSEC), ICS protocols (Modbus, DNP3, Profinet, EtherNet/IP, IEC 61850, OPC UA), HMIs, SCADA historians, OT-to-IT pivot, SIS bypass. Distinct from scada-ics-security (broader ICS overview) —...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cps-attack-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### crypto-attacks

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Cryptographic Attacks target implementation flaws and algorithm weaknesses in encryption systems, covering OWASP A04: Cryptographic Failures.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/crypto-attacks-pqc-migration-side-channel.md, guides/crypto_failures_scanner.py, guides/cryptographic_failures_complete_guide.md, guides/hash-length-extension-guide.md

---

### cspm-casb-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> CSPM/CASB/CNAPP platform bypass and abuse — rule suppression exploitation, IaC state manipulation, CASB proxy evasion, SaaS shadow discovery, Wiz/Prisma/Lacework/Defender coverage gap identification, and tag-tampering attacks against cloud posture management tools.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cspm-casb-attack-playbook.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md, SKILL.md

---

### darkweb-intel

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Dark web intelligence gathering — Tor/onion service reconnaissance, marketplace monitoring, breach data markets, threat actor profiling, with strict OPSEC for investigators.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/dark-web-investigation-playbook.md, guides/darkweb-intel-forum-attribution-deep.md, guides/darkweb-intel-i2p-freenet-monitoring-deep.md, guides/darkweb-intel-leak-site-investigation-deep.md

---

### data-exfiltration-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Attacks for exfiltrating data from compromised networks and bypassing DLP/egress controls. Covers DNS tunneling, ICMP/HTTPS tunneling, protocol smuggling, steganographic exfil, cloud-native exfil (S3/OpenSearch/BigQuery), and DLP bypass. Use when testing egress monitoring, validating DLP controls, o...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/data-exfiltration-attack-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### data-loss-prevention-bypass

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> DLP bypass techniques covering steganography (LSB, audio, video), DNS tunneling, ICMP tunneling, cloud sync abuse (Dropbox, OneDrive), WebSocket/HTTP3 exfil, AI-augmented exfil (semantic chunking), and modern DLP evasion patterns.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, SKILL.md, test-cases.md

---

### data-platform-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Attacks against cloud data platforms and analytics pipelines — Snowflake, Databricks, BigQuery, Redshift, dbt, Apache Airflow, and lakehouse architectures. Covers identity-based breaches (no perimeter), warehouse SQL injection at scale, IAM privilege escalation, secrets in DAGs, notebook code inject...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/data-platform-attack-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### data-scraper-agent

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Automated data collection from structured sources: CVE databases, threat intelligence feeds, exploit databases, and security advisories. Transform unstructured web data into structured knowledge units.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/anti-bot-bypass-guide.md, guides/data-extraction-patterns-guide.md, guides/nvd-api-scraping-guide.md, guides/rate-limiting-and-stealth-guide.md

---

### database-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Direct attacks against database servers at the protocol level — distinct from web-based SQL injection (covered by web-sqli). This skill targets database listeners, authentication mechanisms, stored procedures, and protocol-level misconfigurations.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/database-bruteforce.md, guides/database-lateral-movement-guide.md, guides/nosql-attack-guide.md, guides/oracle-database-attack.md

---

### deception-honeypot

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Defensive deception and honeypot deployment covering SSH/Telnet (Cowrie), web (OpenCanary), enterprise (HFish), ICS/SCADA (Conpot), all-in-one (T-Pot), AI-driven deception (Beelzebub), Thinkst Canarytokens (DNS, HTTP, file, AWS API key, SQL), Dionaea multi-protocol honeypot, notification pipelines (...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/canary-deployment-playbook.md, guides/deception-honeypot-playbook.md, SKILL.md, test-cases.md

---

### deep-research

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Multi-source intelligence gathering through systematic web research — producing thorough, cited reports from diverse sources.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/continuous-monitoring.md, guides/intelligence-correlation.md, guides/iterative-search-patterns.md, guides/mcp-integration.md

---

### detection-engineering

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Detection-as-code engineering covering Sigma rule authoring, YARA signature development, Splunk SPL / Kusto KQL / Elastic EQL queries, MITRE ATT&CK mapping, detection CI/CD pipelines, false-positive tuning, and rule testing against EVTX-ATTACK-SAMPLES — using SigmaHQ, Yara-Rules, Loki, yarGen, hayab...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/detection-engineering-playbook.md, guides/soc-playbook-mapping-to-nist-csf-2-0.md, SKILL.md, test-cases.md

---

### digital-forensics

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Digital forensics covers the complete workflow of disk forensics, memory forensics, network forensics, file recovery/carving, and chain of custody.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/2026-03-21-digital-forensics-tools.md, guides/digital-forensics-cli-reference.md, guides/disk-image-analysis-guide.md, guides/memory-forensics-volatility-guide.md

---

### dns-attacks

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> DNS Attacks exploit the Domain Name System protocol for reconnaissance, spoofing, tunneling, and data exfiltration. DNS is a foundational infrastructure service that is frequently misconfigured, poorly monitored, and trusted by default -- making it an ideal attack vector.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/dns-attacks-real-world-incident-case-studies.md, guides/dns-attacks-rebinding-tunneling-modern.md, guides/dns-enumeration-reconnaissance-guide.md, guides/dns-modern-attack-surfaces-deep.md

---

### docker-patterns

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Setting up a practice lab for penetration testing techniques - Creating isolated environments for exploit development and testing - Building vulnerable application targets for training - Testing tools against known-vulnerable configurations - User says \"lab\", \"docker lab.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/container-escape-techniques-guide.md, guides/docker-network-security-guide.md, guides/docker-security-scanning-guide.md, guides/docker-vulnerability-patterns-guide.md

---

### edge-computing-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Attacks against edge computing platforms — Cloudflare Workers (V8 isolate), Fastly Compute@Edge (WASM/Wasmtime), AWS Lambda@Edge and CloudFront Functions, Akamai EdgeWorkers, Vercel Edge Functions, and Deno Deploy. Covers V8 isolate escape, WASM sandbox bypass, request smuggling at the edge, edge KV...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/edge-computing-attack-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### edge-computing-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Edge computing security testing covering CDN bypass, Cloudflare Workers abuse, AWS Lambda@Edge attacks, cache poisoning, origin IP discovery, WAF bypass, and edge function injection.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, SKILL.md, test-cases.md

---

### email-protocol-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Email protocol attacks targeting mail infrastructure at the protocol level.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/email-forgery-spf-dkim-dmarc-guide.md, guides/imap-exchange-attack-guide.md, guides/smtp-enumeration-relay-guide.md, SKILL.md

---

### email-security-deep

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Phishing infrastructure and email gateway bypass covering AiTM MFA interception (evilginx2/modlishka/evilgophish), campaign platforms (gophish/King-Phisher), enterprise gateway evasion (Proofpoint/Mimecast/Cisco ESA/Microsoft Defender for Office), email bombing/DoS, sender reputation engineering, an...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/email-security-deep-deep-dive.md, guides/email-security-deep-evasion-deep.md, guides/email-security-deep-playbook.md, SKILL.md

---

### embedded-rtos-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> RTOS penetration testing — VxWorks WDB debug agent (Urgent/11), QNX microkernel, FreeRTOS+TCP CVEs, ThreadX/Azure RTOS, Zephyr, Mbed OS, TI-RTOS, MicroC/OS, NuttX, RIOT, Contiki

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/embedded-rtos-security-deep-dive.md, guides/embedded-rtos-security-playbook.md, guides/freertos-tcp-vulnerability-research.md, SKILL.md

---

### engagement-manager

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> End-to-end penetration test project management skill. Orchestrates the full engagement lifecycle from scoping through reporting, managing skill composition, evidence chains, and phase transitions.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/engagement-lifecycle-guide.md, guides/evidence-chain-guide.md, guides/scope-management-guide.md, SKILL.md

---

### exa-search

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Semantic search using Exa API for security research queries. Unlike keyword-based search, Exa understands context and retrieves high-quality, relevant results for technical research.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/advanced-query-construction-guide.md, guides/competitive-intelligence-gathering-guide.md, guides/exa-api-configuration-guide.md, guides/search-result-enrichment-guide.md

---

### exploit-development

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Exploit development covers the full chain from vulnerability discovery through crash analysis to working exploit code, spanning buffer overflows, ROP chains, format string bugs, and shellcode injection across x86 and ARM architectures.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/buffer-overflow-to-rop-chain-guide.md, guides/heap-exploitation-guide.md, guides/kernel-exploit-guide.md, guides/pwntools-exploit-development-guide.md

---

### file-inclusion

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Local File Inclusion (LFI) and Remote File Inclusion (RFI) attack techniques covering path traversal, PHP wrapper abuse, log poisoning, session file inclusion, and remote payload hosting for code execution.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/lfi-to-rce-exploitation-guide.md, guides/path-traversal-bypass-guide.md, guides/rfi-remote-code-execution-guide.md, SKILL.md

---

### firmware-reverse

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Firmware reverse engineering covers the full pipeline from raw firmware image acquisition through filesystem extraction, static and dynamic analysis, full-system emulation, and vulnerability/backdoor detection.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/firmadyne-emulation.md, guides/firmware-extraction-filesystem.md, guides/firmware-vuln-backdoor.md, SKILL.md

---

### game-anticheat-bypass

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Security research on game anti-cheat systems (EAC/BattlEye/Vanguard/Ricochet) — kernel-mode driver architecture, BYOVD attacks, memory access interception, integrity check evasion, and defense-side anti-cheat engineering.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/game-anticheat-bypass-playbook.md, SKILL.md, test-cases.md

---

### gitops-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Attacks against GitOps control planes (Argo CD, FluxCD, Jenkins X, Tekton, Fleet, Rancher) — repo impersonation, manifest tampering, RBAC bypass, sync-wave abuse, secret management compromise (Sealed Secrets / SOPS / External Secrets / Vault), cluster privilege escalation via Application/CRDs, and p...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/gitops-security-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### hardware-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Hardware and embedded system security testing covering physical interface exploitation, firmware extraction and analysis, side-channel attacks, RFID/NFC cloning, and fault injection.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/embedded-firmware-analysis.md, guides/firmware-extraction-analysis-guide.md, guides/hardware-exploitation-patterns-guide.md, guides/jtag-swd-debugging-guide.md

---

### hardware-side-channel-advanced

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Advanced hardware side-channel attacks covering power analysis (SPA/DPA), electromagnetic emanation, timing attacks, cache-timing attacks (Spectre/Meltdown variants), glitching (voltage/clock), optical fault injection, and countermeasure evaluation.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, SKILL.md, test-cases.md

---

### hf-vhf-radio-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Licensed HF/VHF/UHF radio attack — ADS-B 1090 MHz, AIS, ACARS, VDL Mode 2, POCSAG/FLEX pagers, APRS, NDB, ATC/maritime VHF, DSC, weather fax, MLAT

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/hf-vhf-radio-attack-deep-dive.md, guides/hf-vhf-radio-attack-playbook.md, SKILL.md, test-cases.md

---

### hsm-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Hardware Security Module attacks — physical (side-channel, fault injection, decapping) and logical (PKCS#11 API abuse, key extraction, M-of-N quorum bypass, RDP, firmware exploitation). Covers Thales Luna (SafeNet), Utimaco SecurityServer, nCipher nShield, YubiHSM, AWS CloudHSM, Azure Dedicated HSM,...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/hsm-attack-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### hypervisor-introspection

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Hypervisor introspection (VMI) and virtualization escape attacks — VMware ESXi, Hyper-V, KVM/QEMU, Xen, Proxmox, VirtualBox, LibVMI, DRAKVUF, VENOM CVE-2015-3456, hardware-assisted VT-x/EPT/AMD-V

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/hypervisor-introspection-playbook.md, SKILL.md, test-cases.md

---

### ics-fieldbus-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Industrial fieldbus protocol penetration testing beyond Modbus — Profibus/PROFINET, EtherCAT, DNP3, IEC 61850 (GOOSE/SV/MMS), IEC 60870-5-101/104, Foundation Fieldbus, HART, CC-Link, BACnet deep dive. Covers power utility, process automation, building automation, and automotive fieldbus attack surfa...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/ics-fieldbus-attack-playbook.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md, SKILL.md

---

### identity-provider-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Identity Provider (IdP) attack patterns covering OAuth 2.0/OIDC, SAML, JWT, token theft/replay, MFA fatigue, service principal abuse (Azure AD/Entra ID), Okta, Auth0, Keycloak, and modern identity-based attacks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, SKILL.md, test-cases.md

---

### insecure-design

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Insecure Design (OWASP A06:2025) focuses on security flaws in system architecture and design phases, rather than code implementation-level bugs.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/abuse-case-development-guide.md, guides/business-logic-attack-patterns-guide.md, guides/insecure_design_complete_guide.md, guides/race-condition-exploitation-guide.md

---

### iot-pentest

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> IoT application-layer penetration testing covering MQTT broker abuse, CoAP server attacks, AMQP exploitation, OT/cloud IoT gateways (AWS IoT, Azure IoT Hub), device management platforms, mobile companion apps, embedded web services, and proprietary IoT protocol reverse engineering using mosquitto, M...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/iot-pentest-playbook.md, guides/radio-and-firmware-iot-testing-playbook.md, SKILL.md, test-cases.md

---

### knowledge-ops

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Build and maintain structured, persistent knowledge graphs across sessions. Knowledge-ops transforms ephemeral session findings into reusable intelligence — connecting entities, tracking confidence over time, and enabling recall across engagements.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cross-session-intelligence-aggregation.md, guides/entity-extraction-and-tagging.md, guides/information-retrieval-optimization-guide.md, guides/knowledge-graph-construction-guide.md

---

### kubernetes-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Kubernetes cluster attack and red team covering RBAC abuse, pod escape (privileged pods, hostPath, capabilities, hostPID/hostIPC, container runtime sockets, kernel CVEs), kubelet API abuse (10250/10255), etcd direct access, service account token theft (legacy and projected), RBAC privilege escalatio...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/k8s-escape-and-lateral-movement-playbook.md, guides/kubernetes-attack-detection-evasion-deep.md, guides/kubernetes-attack-playbook.md, guides/kubernetes-attack-rbac-privilege-escalation-deep.md

---

### llm-red-team

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> LLM and generative AI red team testing covering prompt injection, jailbreaking (DAN, many-shot, Crescendo, PAIR/TAP, GCG suffix, persona modulation, prefix injection, payload smuggling), model extraction, RAG poisoning, agentic tool abuse, and safety policy bypass using promptfoo, garak, PyRIT, Purp...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/llm-jailbreak-arsenal-playbook.md, guides/llm-red-team-playbook.md, SKILL.md, test-cases.md

---

### logging-monitoring

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Security logging and monitoring deficiencies (OWASP A09:2021) refer to applications failing to properly record security events or lacking effective monitoring, resulting in attacks going undetected, malicious activities being untraceable.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/alert-fatigue-reduction-guide.md, guides/forensic-logging-requirements-guide.md, guides/log-tampering-detection-guide.md, guides/logging_monitoring_complete_guide.md

---

### macos-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> macOS red team and security assessment — SIP/TCC bypass, Endpoint Security framework, Apple Silicon/T2/M-series attacks, Mach-O analysis, Keychain extraction, MDM bypass, LaunchAgents/Daemons persistence, and macOS-native malware analysis.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/macos-security-deep-dive.md, guides/macos-security-playbook.md, SKILL.md, test-cases.md

---

### mainframe-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> IBM z/OS, RACF (Resource Access Control Facility), CICS, DB2, JES2, TSO/ISPF penetration testing; APF library abuse, dataset access control, SNA/Appc attacks, and legacy mainframe security assessment for financial/government environments.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/lab-driven-walkthrough.md, guides/mainframe-security-playbook.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md

---

### malware-analysis-advanced

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Advanced malware analysis covering unpacking (UPX, VMProtect, Themida, Enigma, custom packers), sandbox-evasion detection (anti-VM, anti-debug, anti-analysis), rootkit analysis (user-mode, kernel-mode, bootkits, UEFI), YARA rule authoring and optimization, and IDA Pro / Ghidra / Binary Ninja workflo...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/malware-analysis-advanced-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### mcp-server-patterns

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Building and security-testing MCP (Model Context Protocol) servers for Kali Linux security tools.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/mcp-protocol-debugging-guide.md, guides/mcp-server-deployment-guide.md, guides/mcp-tool-implementation-guide.md, guides/mcp-tool-security-patterns-guide.md

---

### mobile-app-instrumentation

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Dynamic instrumentation of iOS/Android apps via Frida, Objection, r2frida, and Introspy; runtime SSL pinning bypass, jailbreak/root detection bypass, native library hooking, and runtime secrets extraction.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/mobile-app-instrumentation-ios-android-deep.md, guides/mobile-app-instrumentation-playbook.md, SKILL.md, test-cases.md

---

### mobile-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Mobile security covers the complete attack/defense chain of Android/iOS application security testing, APK/IPA reverse engineering, runtime manipulation, certificate pinning bypass, and mobile data protection.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, .DS_Store, guides/integrity_failures_complete_guide.md, guides/mobile-api-security-testing.md, guides/mobile-cloud-integration.md

---

### multi-agent-collaboration

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Coordinating multiple specialized agents to conduct complex penetration testing engagements through task decomposition, parallel execution, result aggregation, and conflict resolution.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/agent-communication-protocols-guide.md, guides/agent-failure-handling-and-recovery-guide.md, guides/conflict-resolution-consensus-guide.md, guides/coordinated-pentest-playbook.md

---

### multi-agent-runtime-engineering

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Runtime engineering discipline for agent systems — structured JSON memory schemas, memory-driven convergence rules, shared-memory multi-agent coordination via POSIX flock + atomic write + version vector, anti-pattern prevention, and topology selection. Solidifies the engineering patterns of SCEN-007...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/multi-agent-runtime-engineering-playbook.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md, SKILL.md

---

### network-pentest

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Network penetration testing covering the full attack chain from reconnaissance, port scanning, and service fingerprinting through vulnerability assessment, exploitation, traffic sniffing, and MITM attacks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/2026-03-22-reporting-tools.md, guides/2026-03-22-sniffing-spoofing-tools.md, guides/2026-03-22-system-services-tools.md, guides/FINAL_LEARNING_REPORT.md

---

### network-sniffing-mitm

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Network Sniffing and MITM attacks focus on intercepting, analyzing, and manipulating network traffic between two communicating parties.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/ettercap-bettercap-mitm-attack-guide.md, guides/responder-mitm6-credential-harvesting-guide.md, guides/wireshark-tshark-protocol-analysis-guide.md, SKILL.md

---

### network-tunneling-proxy

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Network tunneling encapsulates one protocol inside another to bypass firewalls, evade detection, and route traffic through restricted networks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/dns-icmp-covert-tunnel-deep-dive.md, guides/dns-icmp-covert-tunnel.md, guides/ipv6-tunneling-guide.md, guides/pivoting-double-pivot-guide.md

---

### open-banking-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Open Banking / PSD2 / Open Finance attacks — FAPI (Financial-grade API), OpenID Connect for Financial APIs, OAuth2 PKCE, Strong Customer Authentication (SCA) bypass, AIS/PIS/CBPII API abuse, payment redirection, consent manipulation. Covers UK Open Banking, US FDX, Brazil Open Finance, India Account...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/open-banking-attack-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### osint

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> A specialized skill for intelligence gathering using publicly available sources.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/2026-03-21-information-gathering-tools.md, guides/OSINT-Enterprise-Pentest-Case-Study.md, guides/OSINT_TOOLS_GUIDE.md, guides/automated-osint-pipeline-guide.md

---

### pam-privilege-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Privileged Access Management (PAM) vendor abuse — CyberArk PVWA/PSM/EPV/AIM/CFE, BeyondTrust PRA/Password Safe/Identity Security Insights, Delinea Secret Server/Privilege Manager, One Identity Safeguard, ManageEngine Password Manager Pro, WALLIX Bastion, Devolutions Server, Xton Core. Covers PVWA au...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/pam-privilege-attack-playbook.md, SKILL.md, test-cases.md

---

### password-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Password attacks encompass the complete attack chain from hash extraction, hash type identification, dictionary attacks, rule-based attacks, and bruteforcing to online service brute forcing.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/2026-03-21-password-attack-tools.md, guides/credential-stuffing-automation-guide.md, guides/hash-identification-cracking-guide.md, guides/hashcat-rules-guide.md

---

### patch-to-poc-pipeline

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> The end-to-end patch-diff vulnerability reproduction workflow — patch analysis (read diff, identify protective pattern, hypothesize bug class), source or binary-only code path walking (Ghidra + BinDiff), PoC generation (manual craft OR AFL++/libFuzzer harness with ASan/UBSan), CyberGym-style differe...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/patch-to-poc-pipeline-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### payload-generation

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Payload generation covers the creation, encoding, and delivery of shellcode and executable payloads for initial access and command-and-control (C2) communication.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cross-platform-payload-guide.md, guides/msfvenom-payload-generation-guide.md, guides/payload-delivery-evasion-guide.md, guides/payload-delivery-techniques-guide.md

---

### payment-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Payment systems security — PCI-DSS compliance testing, payment API security (Stripe/Adyen/PayPal), EMV chip/PIN, 3-D Secure, mobile wallets (Apple Pay/Google Pay), and fraud system assessment.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/p2pe-hardware-assessment-playbook.md, guides/payment-pentest-playbook.md, SKILL.md, test-cases.md

---

### pentest-reporting

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Initialize Dradis for collaborative report authoring and Faraday for vulnerability correlation before testing begins.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/dradis-faraday-reporting.md, guides/evidence-collection.md, guides/password-audit-reporting.md, SKILL.md

---

### physical-security-testing

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Physical penetration testing covering mechanical lock bypass (pin-tubular/wafer), RFID/NFC badge cloning (Proxmark3/ESP-RFID-Tool/Walrus), HID iCLASS/Mifare duplication, drop box deployment (LAN Turtle/Packet Squirrel), USB weapons (Rubber Ducky/Bash Bunny), hidden camera placement, and on-site enga...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/physical-security-testing-playbook.md, SKILL.md, test-cases.md

---

### post-exploitation

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Post-exploitation covers the complete attack chain after obtaining initial access: privilege escalation, persistence, lateral movement, data collection and exfiltration, and covering tracks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/2026-03-21-post-exploitation-tools.md, guides/data-exfiltration-guide.md, guides/lateral-movement-practical-guide.md, guides/lateral-movement-techniques-guide.md

---

### post-quantum-migration-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Attacks against cryptographic systems during the PQC migration period. Covers Harvest-Now-Decrypt-Later (SNDL/HNDL), hybrid PQC downgrade abuse, KEM combiner flaws, mixed-protocol failures, NIST PQC standard implementations (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+), and QKD infrastructure a...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/post-quantum-migration-attack-playbook.md, guides/real-world-incident-case-studies.md, SKILL.md, test-cases.md

---

### privilege-escalation

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Privilege escalation is the process of elevating access from a low-privileged user context (standard user, service account, or limited shell) to root on Linux or SYSTEM/Administrator on Windows.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/kernel-exploit-safety-guide.md, guides/linux-privilege-escalation-enumeration-guide.md, guides/windows-privilege-escalation-attack-guide.md, SKILL.md

---

### protocol-state-exploitation

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Protocol state exploitation targets vulnerabilities in network protocol state machines including SSH/TLS/HTTP2/DNS, covering illegal state transitions, stateful fuzzing, and protocol-level race conditions.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/http2-rapid-reset-guide.md, guides/scapy-packet-crafting.md, guides/ssh-protocol-state-exploitation.md, guides/stateful-protocol-fuzzing.md

---

### quantum-crypto-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Post-quantum and modern national cryptography attack surface testing covering NIST PQC candidates (ML-KEM/ML-DSA/SLH-DSA), hybrid TLS analysis, QKD/BB84 protocol attacks, Chinese national crypto (SM2/SM3/SM4/SM9) implementation flaws, lattice/hashing signature probing, and quantum-vulnerable RSA/ECC...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/pqc-migration-assessment-playbook.md, guides/quantum-crypto-attack-deep-dive.md, guides/quantum-crypto-attack-playbook.md, SKILL.md

---

### quantum-cryptography-transition

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Post-Quantum Cryptography (PQC) transition security covering NIST standards (ML-KEM, ML-DSA, SLH-DSA), hybrid TLS weaknesses, Quantum Key Distribution (QKD) attacks, HNDL (Harvest Now, Decrypt Later), and migration vulnerability windows.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, SKILL.md, test-cases.md

---

### recon-osint

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> The most critical first step in penetration testing. Information gathering determines the precision and efficiency of subsequent attacks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/2026-03-21-information-gathering-tools.md, guides/WPScan_Learning_Guide.md, guides/ffuf-advanced-guide.md, guides/gobuster-advanced-guide.md

---

### red-team-infrastructure

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Building, deploying, and operating stealthy C2 infrastructure for red team engagements. Covers Mythic, Havoc, Sliver, Covenant, PoshC2, Brute Ratel, and Cobalt Strike; redirector chains (Nginx mTLS, Cloudflare workers, CDN domain fronting); dead-drop resolvers; infrastructure OPSEC (compartmentalize...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/real-world-incident-case-studies.md, guides/red-team-infrastructure-playbook.md, SKILL.md, test-cases.md

---

### repo-scan

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Cross-stack source code asset audit that classifies every file, detects embedded third-party libraries, and delivers actionable verdicts per module.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/codebase-security-audit-workflow.md, guides/dependency-vulnerability-scanning-guide.md, guides/git-history-security-analysis-guide.md, guides/sast-integration-guide.md

---

### reverse-engineering-advanced

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Advanced reverse engineering covering symbolic execution (angr, KLEE, manticore), decompiler confusion (Hex-Rays, Ghidra deobfuscation), binary diffing (BinDiff, Diaphora, Kam1n0), firmware RE workflow (binwalk, FACT, EMBA), and obfuscated code analysis (LLVM obfuscation, OLLVM, Tigress). Distinct f...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/real-world-incident-case-studies.md, guides/reverse-engineering-advanced-playbook.md, SKILL.md, test-cases.md

---

### safety-guard

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Before executing ANY potentially destructive or irreversible command - When a command targets production or critical infrastructure - When operating under a defined rules of engagement (ROE) - When a loop or automated sequence is about to start - User says \"safe?

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/error-handling-security-guide.md, guides/input-sanitization-patterns-guide.md, guides/rate-limiting-implementation-guide.md, guides/scope-enforcement-operations.md

---

### sase-sse-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Secure Access Service Edge (SASE) and Security Service Edge (SSE) platform compromise covering Zscaler (ZIA/ZPA/ZDX/Client Connector), Netskope (Security Cloud, SWG, CASB, Private Access), Palo Alto Prisma Access, Cisco Umbrella, CATO Networks SASE, Cloudflare One (WARP, Gateway, Access), and Micros...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/netskope-security-cloud-bypass-guide.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md, guides/sase-sse-attack-playbook.md

---

### satellite-leo-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Satellite and LEO communication security — Starlink, Kuiper, OneWeb, Iridium, Inmarsat, Viasat KA-SAT, HughesNet, DVB-S/S2, VSAT (iDirect/Hughes), GNSS receiver attacks, AcidRain wiper (Viasat 2022)

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/satellite-leo-security-playbook.md, SKILL.md, test-cases.md

---

### scada-ics-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> SCADA/ICS security assessment covering industrial control system protocols including Modbus TCP, S7comm (Siemens), DNP3, EtherNet/IP (CIP), OPC UA, BACnet, and GOOSE.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/ics-honeypot-detection-guide.md, guides/ics-incident-response-guide.md, guides/ics-network-assessment.md, guides/ics-protocol-recon.md

---

### sdr-rf-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Software Defined Radio and RF signal attacks encompass a broad range of offensive techniques targeting wireless communication systems.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/gps-spoofing-guide.md, guides/gsm-lte-basestation-attack-guide.md, guides/rf-fingerprinting-device-identification-guide.md, guides/rfid-nfc-deep-dive-guide.md

---

### search-first

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Systematizes the \"search for existing tools, exploits, and techniques before writing custom ones\" workflow.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/exploit-research-methodology.md, guides/multi-source-intelligence-correlation-guide.md, guides/search-query-optimization-guide.md, guides/search-result-validation-guide.md

---

### secret-management-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Secret discovery, SAST code audit, and secrets-management platform attack covering gitleaks, semgrep, trufflehog, infisical, bearer, DeepAudit, apkleaks, and cariddi — including HashiCorp Vault exploitation (auth methods, secrets engines, policies, response-wrap hijacking, SSRF), AWS KMS key policy ...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md, guides/secret-management-attack-playbook.md, guides/vault-and-cloud-kms-attack-playbook.md, SKILL.md

---

### security-bounty-hunter

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Hunt for exploitable, bounty-worthy security issues in target systems. Focuses on remotely reachable vulnerabilities that qualify for real reports and responsible disclosure, not broad best-practices reviews or theoretical findings.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/attack-surface-discovery-guide.md, guides/bounty-hunting-methodology.md, guides/bug-bounty-automation.md, guides/bug-bounty-report-writing-guide.md

---

### security-misconfiguration

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Security misconfiguration detection (OWASP A02:2025) covering default credentials, unnecessary services, verbose errors, missing security headers, and directory listing exposures across deployed systems.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cloud-misconfiguration-audit-guide.md, guides/cloud-misconfiguration-checklist-guide.md, guides/debug-endpoint-discovery-guide.md, guides/default-credential-audit-guide.md

---

### security-review

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Comprehensive security checklist and review patterns for analyzing applications, configurations, and infrastructure. This skill provides structured review methodology to identify vulnerabilities across OWASP Top 10 categories during penetration testing.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/code-review-security-patterns-guide.md, guides/dependency-audit-guide.md, guides/owasp-audit-methodology.md, guides/sast-tool-comparison-guide.md

---

### social-engineering

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Social engineering is the art of exploiting human psychological weaknesses rather than technical vulnerabilities to execute attacks. Attack vectors encompass Phishing, Pretexting, Baiting, Tailgating, Vishing, and other techniques.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/2026-03-21-social-engineering-tools.md, guides/phishing-campaign-design-guide.md, guides/pretexting-techniques-guide.md, guides/social-engineering-cli-reference.md

---

### social-intelligence

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Real-time intelligence gathering from social platforms and community discussions — capturing what people are saying, sharing, and leaking right now.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/community-monitoring-guide.md, guides/osint-automation-pipeline-guide.md, guides/reddit-hackernews-osint.md, guides/sentiment-analysis.md

---

### steganography

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Steganography is the practice of concealing data within non-secret carrier files such as images, audio, video, and documents. Unlike encryption, which makes data unreadable but visibly present, steganography hides the very existence of the hidden data.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/audio-video-steganography-guide.md, guides/ctf-steganography-challenge-guide.md, guides/network-protocol-steganography-guide.md, guides/steganography-techniques-detection-guide.md

---

### storage-san-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Storage/SAN/NAS/Object storage penetration testing — iSCSI, Fibre Channel, NFSv3/v4, SMB3, S3-compatible APIs, NetApp ONTAP, Dell EMC, Pure Storage, QNAP, Synology, TrueNAS, NDMP backup tape pilfering, and ransomware patterns targeting storage appliances. Distinct from database-attack (which targets...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/storage-san-attack-playbook.md, guides/storage-san-attack-real-world-incident-case-studies.md, guides/storage-san-attack-vendor-deep.md, SKILL.md

---

### supply-chain-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Software supply chain security covering the entire lifecycle from code development to deployment: dependency vulnerabilities (known-vulnerable third-party packages), malicious packages (injection and typosquatting.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/build-pipeline-security-guide.md, guides/dependency-confusion-attack-guide.md, guides/package-integrity-verification-guide.md, guides/software-bill-of-materials-guide.md

---

### terminal-ops

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Evidence-first execution workflow for running security commands, inspecting system state, debugging tool failures, and making verified changes. This skill enforces a disciplined approach: inspect before acting, keep changes narrow, and report exact execution state.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/evidence-first-execution.md, guides/terminal-automation-scripting-guide.md, guides/terminal-forensics-evidence-guide.md, guides/terminal-network-operations-guide.md

---

### threat-hunting

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Proactive threat hunting — MITRE ATT&CK-mapped hunt hypotheses, Sigma detection engineering, SIEM query authoring (Splunk SPL, KQL, Lucene), and SOC workflow integration.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/hunt-hypothesis-playbook.md, guides/sigma-rule-development-playbook.md, SKILL.md, test-cases.md

---

### threat-intel-platform-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Attacking threat intelligence platforms (MISP, OpenCTI, Anomali ThreatStream, ThreatQuotient, ThreatConnect, IBM Threat Intel, Palo Alto AutoFocus, Mandiant Advantage). Covers platform CVEs (MISP CVE-2022-29527, OpenCTI vulnerabilities), API abuse, sharing-group trust abuse, false-positive IOC injec...

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/real-world-incident-case-studies.md, guides/threat-intel-platform-attack-playbook.md, SKILL.md, test-cases.md

---

### tool-mastery

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Verification and assessment of practical proficiency with Kali Linux security tools. Covers tool classification, proficiency levels, verification methods, and combination strategies across the 518-tool Kali arsenal.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/tool-combination-guide.md, guides/tool-proficiency-framework-guide.md, guides/tool-selection-by-phase-guide.md, SKILL.md

---

### uav-drone-security

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> UAV/drone security testing — PX4/ArduPilot autopilot attacks, MAVLink protocol fuzzing, RF link hijacking (2.4GHz control / 5.8GHz video), GPS spoofing/jamming, DroneSploit framework, DJI hardware reversing, and counter-UAS methodologies.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/uav-drone-security-playbook.md, SKILL.md, test-cases.md

---

### username-profiling

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Build a complete dossier on a person using only a username.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/maigret-username-dossier.md, guides/maigret-username-workshop.md, guides/username-profiling-deep-dive.md, SKILL.md

---

### verification-loop

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> After discovering a potential vulnerability or exploit - Before submitting any finding to a report or bounty platform - When verifying that a remediation or patch is effective - When cross-checking automated scanner results - User says \"verify\", \"confirm\", \"validate.

**Defense Triple**: Defense Perspective ✗ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/automated-exploit-verification-guide.md, guides/continuous-security-validation-guide.md, guides/cross-tool-verification-guide.md, guides/false-positive-triage-guide.md

---

### voip-sip-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Voice over IP (VoIP) systems use the Session Initiation Protocol (SIP) for call signaling, the Real-time Transport Protocol (RTP) for media streaming, and the Inter-Asterisk eXchange protocol (IAX2) for alternative VoIP communication.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/sip-device-recon.md, guides/voip-denial-of-service.md, guides/voip-eavesdropping-spoofing.md, SKILL.md

---

### vpn-attack

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Virtual Private Networks (VPNs) are a critical component of enterprise network security, providing encrypted tunnels for remote access and site-to-site connectivity.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/ipsec-vpn-enumeration-fingerprinting-guide.md, guides/openvpn-attack-guide.md, guides/ssl-vpn-exploitation-deep-dive-guide.md, guides/ssl-vpn-exploitation-guide.md

---

### vulnerability-assessment

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Vulnerability assessment is the process of systematically identifying and quantifying security weaknesses in information systems through automated scanning, CVE analysis, and risk scoring.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/2026-03-22-vulnerability-analysis-tools.md, guides/2026-03-22-web-app-analysis-advanced.md, guides/2026-03-22-web-application-analysis-tools.md, guides/automated-scanning-pipeline-guide.md

---

### web-access-control

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Broken Access Control (OWASP Top 10 2025 - A01) attacks and defense — covering core attack surfaces including IDOR (Insecure Direct Object Reference), vertical/horizontal privilege escalation, path traversal, and permission bypass.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, access-control-guide.md, guides/access_control_scanner.py, guides/broken_access_control_complete_guide.md, guides/broken_access_control_payloads.md

---

### web-auth-bypass

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Authentication Bypass refers to attackers exploiting design flaws or implementation vulnerabilities in authentication mechanisms to bypass the normal authentication process and gain unauthorized access.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/auth-bypass-complete-guide.md, guides/jwt-attack-methodology.md, guides/mfa-bypass-techniques-guide.md, guides/oauth-vulnerability-testing-guide.md

---

### web-deserialization

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Deserialization vulnerabilities arise when an application reconstructs objects from byte streams (Java), serialized strings (PHP), Base64 blobs (.NET), or pickle data (Python) supplied by the client.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/cross-platform-deserialization-guide.md, guides/dotnet-deserialization-guide.md, guides/java-deserialization-ysoserial-guide.md, guides/nodejs-deserialization-guide.md

---

### web-sqli

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> SQL injection attacks and defense - covering all major SQLi types including error-based, union-based, blind (boolean/time), double query (error-based), stacked queries, and out-of-band injection.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, sqli-cross-db-guide.md, sqli-double-query-guide.md, guides/bug_bounty_sqli_scanner.py, guides/comprehensive_double_query_test.py

---

### web-ssrf

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> Server-Side Request Forgery (SSRF) attacks including basic, blind, and advanced bypass techniques, internal port scanning, cloud metadata extraction (AWS/GCP/Azure), protocol smuggling (gopher://, dict://, file://), and chained RCE exploitation.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/blind-ssrf-detection-guide.md, guides/cloud-metadata-ssrf-guide.md, guides/ssrf-filter-bypass-guide.md, guides/ssrf-post-exploitation-guide.md

---

### web-xss

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> XSS (Cross-Site Scripting) is an attack that injects malicious scripts into trusted websites.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/csp-bypass-techniques-guide.md, guides/dom-xss-source-sink-analysis-guide.md, guides/ssti-attack-guide.md, guides/waf-bypass-xss-guide.md

---

### web-xxe

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> XML External Entity (XXE) injection exploits vulnerable XML parsers to read local files, initiate SSRF attacks, exfiltrate data through out-of-band channels, and cause denial of service.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/blind-xxe-exfiltration-guide.md, guides/oxml-xxe-social-engineering-guide.md, guides/xxe-attack-techniques-guide.md, SKILL.md

---

### wifi-pentest

**版本**: 0.2.0.2 | **域**: uncategorized | **MITRE**: N/A

> WiFi security assessment skills: covering wireless network reconnaissance, WPA/WPA2 handshake capture and offline cracking, WPS PIN brute forcing, Evil Twin attacks, wireless sniffing, and deauthentication attacks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件**: payloads.md, guides/CRACK_MONITOR.md, guides/evil-twin-attack-guide.md, guides/wifi-cracking-complete-learning.md, guides/wifi-cracking-course.md

---
