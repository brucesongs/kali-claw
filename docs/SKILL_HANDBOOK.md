# kali-claw SKILL 使用手册

> **版本**: 0.3.6 | **生成日期**: 2026-11-09 | **SKILL 总数**: 139 / **域数**: 83
> 本文件由 `validation/gen-skill-handbook.py` 自动生成（以 skills/ frontmatter 为权威源），请勿手工编辑。

---

## 目录

- [ad-cs-abuse](#ad-cs-abuse) (1 个 SKILL)
- [aerial](#aerial) (1 个 SKILL)
- [agent-runtime](#agent-runtime) (1 个 SKILL)
- [ai](#ai) (2 个 SKILL)
- [ai-agent-framework-attack](#ai-agent-framework-attack) (1 个 SKILL)
- [ai-compliance](#ai-compliance) (1 个 SKILL)
- [ai-emerging](#ai-emerging) (1 个 SKILL)
- [ai-meta](#ai-meta) (1 个 SKILL)
- [ai-red-team](#ai-red-team) (1 个 SKILL)
- [ai-safety](#ai-safety) (1 个 SKILL)
- [ai-supply-chain](#ai-supply-chain) (1 个 SKILL)
- [analysis](#analysis) (1 个 SKILL)
- [appsec](#appsec) (3 个 SKILL)
- [assessment](#assessment) (4 个 SKILL)
- [automotive](#automotive) (1 个 SKILL)
- [binary-analysis](#binary-analysis) (1 个 SKILL)
- [blockchain](#blockchain) (1 个 SKILL)
- [blockchain-l2-attack](#blockchain-l2-attack) (1 个 SKILL)
- [cloud](#cloud) (3 个 SKILL)
- [cloud-native](#cloud-native) (2 个 SKILL)
- [confidential-computing](#confidential-computing) (1 个 SKILL)
- [credential-access](#credential-access) (1 个 SKILL)
- [crypto](#crypto) (1 个 SKILL)
- [cryptography](#cryptography) (2 个 SKILL)
- [data-exfiltration](#data-exfiltration) (1 个 SKILL)
- [data-platform](#data-platform) (1 个 SKILL)
- [data-protection](#data-protection) (1 个 SKILL)
- [database](#database) (1 个 SKILL)
- [defense](#defense) (6 个 SKILL)
- [design](#design) (1 个 SKILL)
- [edge](#edge) (1 个 SKILL)
- [edge-computing](#edge-computing) (1 个 SKILL)
- [embedded-rtos-security](#embedded-rtos-security) (1 个 SKILL)
- [enterprise](#enterprise) (1 个 SKILL)
- [enterprise-cloud](#enterprise-cloud) (1 个 SKILL)
- [exploitation](#exploitation) (5 个 SKILL)
- [financial](#financial) (1 个 SKILL)
- [fintech-banking](#fintech-banking) (1 个 SKILL)
- [firmware](#firmware) (1 个 SKILL)
- [forensics](#forensics) (3 个 SKILL)
- [game-security](#game-security) (1 个 SKILL)
- [gitops](#gitops) (1 个 SKILL)
- [hardware](#hardware) (2 个 SKILL)
- [hardware-security](#hardware-security) (1 个 SKILL)
- [hf-vhf-radio-attack](#hf-vhf-radio-attack) (1 个 SKILL)
- [hypervisor-introspection](#hypervisor-introspection) (1 个 SKILL)
- [ics](#ics) (1 个 SKILL)
- [ics-fieldbus-attack](#ics-fieldbus-attack) (1 个 SKILL)
- [identity](#identity) (1 个 SKILL)
- [industrial-control-systems](#industrial-control-systems) (1 个 SKILL)
- [infrastructure](#infrastructure) (4 个 SKILL)
- [iot](#iot) (1 个 SKILL)
- [knowledge](#knowledge) (6 个 SKILL)
- [macos](#macos) (1 个 SKILL)
- [mainframe](#mainframe) (1 个 SKILL)
- [malware-analysis](#malware-analysis) (1 个 SKILL)
- [management](#management) (1 个 SKILL)
- [mobile](#mobile) (1 个 SKILL)
- [mobile-deep](#mobile-deep) (1 个 SKILL)
- [network-attack](#network-attack) (6 个 SKILL)
- [network-security](#network-security) (1 个 SKILL)
- [osint](#osint) (5 个 SKILL)
- [pam-privilege-attack](#pam-privilege-attack) (1 个 SKILL)
- [physical](#physical) (1 个 SKILL)
- [post-exploitation](#post-exploitation) (2 个 SKILL)
- [post-quantum-cryptography](#post-quantum-cryptography) (1 个 SKILL)
- [red-team-infrastructure](#red-team-infrastructure) (1 个 SKILL)
- [reporting](#reporting) (1 个 SKILL)
- [research](#research) (3 个 SKILL)
- [reverse-engineering](#reverse-engineering) (1 个 SKILL)
- [satellite-leo-security](#satellite-leo-security) (1 个 SKILL)
- [security](#security) (2 个 SKILL)
- [social](#social) (1 个 SKILL)
- [storage-san-attack](#storage-san-attack) (1 个 SKILL)
- [supply-chain](#supply-chain) (1 个 SKILL)
- [telecom](#telecom) (2 个 SKILL)
- [testing](#testing) (1 个 SKILL)
- [threat-intel-platforms](#threat-intel-platforms) (1 个 SKILL)
- [voip](#voip) (1 个 SKILL)
- [vuln-research](#vuln-research) (1 个 SKILL)
- [web-attack](#web-attack) (11 个 SKILL)
- [wireless](#wireless) (1 个 SKILL)
- [workflow](#workflow) (3 个 SKILL)

---

## ad-cs-abuse

### ad-cs-abuse

**版本**: 0.2.0.2 | **域**: ad-cs-abuse | **MITRE**: T1552-Unsecured Credentials | reviewed 2026-07-24

> Active Directory Certificate Services (AD CS) abuse — ESC1-ESC15 attack patterns, PKINIT, PetitPotam to AD CS to Domain Admin chains, CVE-2022-26923 (Certifried), Shadow Credentials, Golden Certificate, certificate template ACL abuse, NTLM relay to web enrollment.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/ad-cs-abuse-detection-and-hardening.md, guides/ad-cs-abuse-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## aerial

### uav-drone-security

**版本**: 0.2.0.2 | **域**: aerial | **MITRE**: TA0040-Detection, T1557-Adversary-in-the-Middle, TA0001-Initial Access | reviewed 2026-07-26

> UAV/drone security testing — PX4/ArduPilot autopilot attacks, MAVLink protocol fuzzing, RF link hijacking (2.4GHz control / 5.8GHz video), GPS spoofing/jamming, DroneSploit framework, DJI hardware reversing, and counter-UAS methodologies.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/uav-drone-security-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## agent-runtime

### multi-agent-runtime-engineering

**版本**: 0.2.0.2 | **域**: agent-runtime | **MITRE**: N/A — meta-skill (runtime engineering, not a specific ATT&CK technique) | reviewed 2026-07-26

> Runtime engineering discipline for agent systems — structured JSON memory schemas, memory-driven convergence rules, shared-memory multi-agent coordination via POSIX flock + atomic write + version vector, anti-pattern prevention, and topology selection. Solidifies the engineering patterns of SCEN-007 (shared-memory multi-agent exploit dev) and SCEN-MEMORY-SCHEMA (structured memory foundation) into a reusable knowledge base. Inspired by MopMonk Agent three-layer harness (Chinese press nickname *扫地僧* — CyberGym 73.1%, China #1) — proving that harness engineering beats base-model parameter scaling.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (8): SKILL.md, guides/multi-agent-runtime-engineering-playbook.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment-zh.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## ai

### ai-fuzzing

**版本**: 0.2.0.2 | **域**: ai | **MITRE**: T1190-Exploit Public-Facing Application, T1203-Exploitation for Client Execution, T1068-Exploitation for Privilege Escalation, T1610-Deploy Container | reviewed 2026-09-04

> AI-assisted fuzzing for automated vulnerability discovery. Coverage-guided fuzzing engines, AI-driven seed generation, intelligent mutation strategies, and systematic crash triage.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/coverage-guided-fuzzing.md, guides/crash-triage-automation-guide.md, guides/crash-triage-guide.md, guides/grammar-based-fuzzing-guide.md, guides/protocol-fuzzing.md, guides/usage-and-assessment.md, guides/web-api-fuzzing-guide.md, guides/web-api-fuzzing.md, payloads.md, test-cases.md

---

### ai-security

**版本**: 0.2.0.2 | **域**: ai | **MITRE**: T1190-Exploit Public-Facing Application, T1059-Command and Scripting Interpreter, T1566-Phishing, T1589-Gather Victim Identity Information | reviewed 2026-08-19

> Semantic-layer attack testing against AI systems and LLM-integrated applications.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/adversarial-ml-testing-guide.md, guides/ai-model-security-testing-guide.md, guides/ai-red-team-guide.md, guides/ai-security-jailbreak-research.md, guides/llm-attack-methodology.md, guides/model-extraction-attack-guide.md, guides/prompt-injection-defense-guide.md, guides/prompt-injection-lab-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## ai-agent-framework-attack

### ai-agent-framework-attack

**版本**: 0.2.0.2 | **域**: ai-agent-framework-attack | **MITRE**: T1195-Supply Chain Compromise | reviewed 2026-07-24

> AI agent framework attack surface — orchestration-layer compromise of LangChain (Python/JS), LangGraph, CrewAI, Microsoft AutoGen, OpenAI Assistants API v2, Anthropic Claude Agent SDK, LlamaIndex, Microsoft Semantic Kernel, Google ADK, SmolAgents, and MCP-integrated agent runtimes. Covers tool poisoning (Simon Willison 2025 research), indirect prompt injection via untrusted tool outputs, tool rug-pull attacks (npm/PyPI dependency confusion in agent toolkits), LangChain SSRF via RequestsTool / SqlQueryTool / PythonREPLTool (CVE-2024-21514 area, CVE-2024-43480 area), CrewAI tool RCE via decorators (CVE-2024-10231 area), AutoGen code executor escape (Docker/code execution services), OpenAI Assistants API code_interpreter abuse, Claude Agent SDK MCP injection, LangGraph state injection via checkpoint poisoning, LlamaIndex query engine injection, MCP server poisoning (Anthropic/rug-pull.com research Nov 2024), tool description injection, agent memory poisoning, Retrieval-Augmented Generation (RAG) corpus poisoning, agent-in-the-middle attacks, shadow tools, and recent APT actor abuse of agentic AI systems (UNC5812, STAC-0050).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/ai-agent-framework-attack-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## ai-compliance

### eu-ai-act-compliance-redteam

**版本**: 0.2.0.2 | **域**: ai-compliance | **MITRE**: EUAI-Article-9, TA0040-Impact | **OWASP**: N/A — regulatory framework, not vulnerability class | reviewed 2026-09-04

> EU AI Act (Regulation (EU) 2024/1689) compliance-focused red team testing for high-risk AI systems — Article 9 adversarial testing, Annex III classification, Annex IV technical documentation, conformity assessment, and Notified Body audit preparation. Enforceable since 2 August 2026 with fines up to €35M or 7% global turnover.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/eu-ai-act-article-9-deep-dive.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## ai-emerging

### ai-agent-security

**版本**: 0.2.0.2 | **域**: ai-emerging | **MITRE**: Emerging (no canonical MITRE mapping); overlaps with T1059-Automated Command Execution, T1566-Phishing via prompt injection, T1190-Exploit Public-Facing App via tool abuse | reviewed 2026-07-26

> Offensive security testing of AI agent systems covering MCP server attacks, tool poisoning, indirect prompt injection against agents, RAG knowledge base poisoning, agent sandbox escape, multi-agent compromise chains, and autonomous agent hijacking — using MCP security testers, HexStrike AI, AI-Infra-Guard, custom agent harness probes, and prompt injection toolkits.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/ai-agent-security-playbook.md, guides/mcp-server-red-team-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## ai-meta

### agentic-pentest

**版本**: 0.2.0.2 | **域**: ai-meta | **MITRE**: Meta-skill (no direct MITRE mapping); orchestrates coverage across all ATT&CK tactics via framework delegation | reviewed 2026-07-26

> LLM-driven autonomous penetration testing framework operations covering PentestGPT, HexStrike AI, Viper, PentestAgent, AI-Infra-Guard, AutoPWN, and custom agent harness patterns — including reasoning chain orchestration, tool delegation, context window management, output validation, multi-agent pentest team coordination, and human-in-the-loop checkpoints.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/agent-orchestration-patterns-playbook.md, guides/agentic-pentest-deep-dive.md, guides/agentic-pentest-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## ai-red-team

### llm-red-team

**版本**: 0.2.0.2 | **域**: ai-red-team | **MITRE**: LLM-ATT&CK (promptfoo/garak taxonomy), maps to OWASP LLM Top 10 (LLM01-LLM10) and TA0043-Reconnaissance | reviewed 2026-09-04

> LLM and generative AI red team testing covering prompt injection, jailbreaking (DAN, many-shot, Crescendo, PAIR/TAP, GCG suffix, persona modulation, prefix injection, payload smuggling), model extraction, RAG poisoning, agentic tool abuse, and safety policy bypass using promptfoo, garak, PyRIT, PurpleLlama, AI-Infra-Guard and llm-guard — plus Constitutional AI, Llama Guard, NeMo Guardrails, and Azure AI Content Filter evasion.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/llm-jailbreak-arsenal-playbook.md, guides/llm-red-team-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## ai-safety

### ai-safety-redteam-advanced

**版本**: 0.2.0.2 | **域**: ai-safety | **MITRE**: Emerging (LLM-specific); overlaps T1059-Automated Command Execution, T1566-Phishing via prompt injection, T1190-Exploit Public-Facing App via LLM abuse | reviewed 2026-07-26

> Advanced AI safety red team operations covering OWASP LLM Top 10 (2025), prompt injection (direct/indirect/multi-turn), jailbreak techniques (DAN, cognitive hacking, persona-based), data poisoning detection, model inversion attacks, adversarial examples (evasion), model extraction, and AI supply chain attacks against LLM-integrated applications, agent frameworks, and RAG systems.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/owasp-llm-top10-complete-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## ai-supply-chain

### ai-agent-supply-chain-attack

**版本**: 0.2.0.2 | **域**: ai-supply-chain | **MITRE**: T1195-Supply Chain Compromise, T1195.002-Compromise Software Supply Chain | **OWASP**: A08:2021-Software and Data Integrity Failures | reviewed 2026-08-09

> AI/ML supply chain attacks — model poisoning, Pickle RCE, Hugging Face / Ollama registry compromise, LangChain plugin backdoors, OpenClaw / ClawHub ecosystem threats. Distinguishes from ci-cd-supply-chain-attack by focusing on model weights, training data, and serialization formats. Anchored by the 2026-07 Hugging Face incident (the 'Chernobyl moment' of software supply chain security).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/hugging-face-2026-07-incident-case-study.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## analysis

### council

**版本**: 0.2.0.2 | **域**: analysis | **MITRE**: T1595-Active Scanning, T1592-Gather Victim Host Info, T1590-Gather Victim Network Info, T1078-Valid Accounts | reviewed 2026-09-04

> Council provides a structured framework for analyzing security questions from multiple adversarial and defensive perspectives simultaneously.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/automated-consensus-scoring-guide.md, guides/council-consensus-building-guide.md, guides/multi-agent-escalation-guide.md, guides/multi-perspective-analysis-framework-guide.md, guides/multi-perspective-analysis.md, guides/risk-prioritization-matrix-guide.md, guides/security-decision-framework.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## appsec

### ci-cd-supply-chain-attack

**版本**: 0.2.0.2 | **域**: appsec | **MITRE**: T1195-Supply Chain Compromise, T1195.001-Compromise Software Dependencies, T1195.002-Compromise Software Supply Chain, T1195.003-Hardware Compromise, T1199-Trusted Relationship, T1078-Valid Accounts | reviewed 2026-07-26

> CI/CD pipeline and software supply chain compromise covering Jenkins (script console, Jenkinsfile injection, shared library abuse, CVE-2024-23897 args4j), GitLab CI/CD (runner abuse, .gitlab-ci.yml injection, self-hosted runner takeover, CVE-2022-1162, OmniAuth CVE-2024-9653), GitHub Actions (self-hosted runner abuse, pull_request_target trap, workflow injection via issue/PR title, secrets exfiltration via cache/artifact, GITHUB_TOKEN scope), CircleCI (context theft, OIDC abuse), Argo CD (CVE-2022-24348, default app creds), Flux CD (GitRepository CRD abuse), Tekton, Buildkite, Drone CI, software supply chain attacks (dependency confusion, typosquatting, brandjacking, malicious npm/PyPI packages, SBOM/SLSA, Sigstore/cosign, in-toto, S2C2F), notable incidents (SolarWinds SUNBURST, 3CX, Codecov, xz-utils CVE-2024-3094, event-stream, ua-parser-js), and detection/defense tooling (StepSecurity Harden-Runner, OpenSSF Scorecard, Socket, Sonatype Nexus, Snyk, Anchore Syft/Grype, KICS, Checkov, semgrep).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/ci-cd-supply-chain-attack-playbook.md, guides/ci-cd-supply-chain-dependency-confusion-deep.md, guides/ci-cd-supply-chain-github-actions-deep.md, guides/ci-cd-supply-chain-real-world-incident-case-studies.md, guides/ci-cd-supply-chain-sbom-provenance-deep.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### email-security-deep

**版本**: 0.2.0.2 | **域**: appsec | **MITRE**: T1566-Phishing (Spearfish, Service Spearfish, Spearfish Attachment), T1114-Email Collection, T1059-Automated Command Execution via payload | reviewed 2026-07-26

> Phishing infrastructure and email gateway bypass covering AiTM MFA interception (evilginx2/modlishka/evilgophish), campaign platforms (gophish/King-Phisher), enterprise gateway evasion (Proofpoint/Mimecast/Cisco ESA/Microsoft Defender for Office), email bombing/DoS, sender reputation engineering, and full-stack campaign operations including landing pages, payload staging, and post-click telemetry — complementary to email-protocol-attack which handles protocol-level forgery.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/email-security-deep-deep-dive.md, guides/email-security-deep-evasion-deep.md, guides/email-security-deep-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### secret-management-attack

**版本**: 0.2.0.2 | **域**: appsec | **MITRE**: T1552-Unsecured Credentials, T1552.001-Credentials In Files, T1552.004-Private Keys, T1552.007-Container and Cloud | reviewed 2026-07-26

> Secret discovery, SAST code audit, and secrets-management platform attack covering gitleaks, semgrep, trufflehog, infisical, bearer, DeepAudit, apkleaks, and cariddi — including HashiCorp Vault exploitation (auth methods, secrets engines, policies, response-wrap hijacking, SSRF), AWS KMS key policy abuse, GCP KMS IAM escalation, Azure Key Vault access policy review, BYOK/HYOK attacks, Kyverno/external-secrets/secrets-store-csi-driver misconfig hunting, hardcoded credential discovery, secret rotation abuse, and CI/CD pipeline secret theft.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md, guides/secret-management-attack-playbook.md, guides/usage-and-assessment.md, guides/vault-and-cloud-kms-attack-playbook.md, payloads.md, test-cases.md

---

## assessment

### repo-scan

**版本**: 0.2.0.2 | **域**: assessment | **MITRE**: T1595.002-Vulnerability Scanning, T1195.002-Compromise Software Supply Chain, T1552.001-Credentials In Files, T1083-File and Directory Discovery | reviewed 2026-09-04

> Cross-stack source code asset audit that classifies every file, detects embedded third-party libraries, and delivers actionable verdicts per module.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/codebase-security-audit-workflow.md, guides/dependency-vulnerability-scanning-guide.md, guides/git-history-security-analysis-guide.md, guides/sast-integration-guide.md, guides/secret-detection-patterns-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### security-bounty-hunter

**版本**: 0.2.0.2 | **域**: assessment | **MITRE**: T1190-Exploit Public-Facing Application, T1595.002-Vulnerability Scanning, T1210-Exploitation of Remote Services, T1203-Exploitation for Client Execution | reviewed 2026-09-04

> Hunt for exploitable, bounty-worthy security issues in target systems. Focuses on remotely reachable vulnerabilities that qualify for real reports and responsible disclosure, not broad best-practices reviews or theoretical findings.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/attack-surface-discovery-guide.md, guides/bounty-hunting-methodology.md, guides/bug-bounty-automation.md, guides/bug-bounty-report-writing-guide.md, guides/poc-development-guide.md, guides/report-writing-bounty-guide.md, guides/responsible-disclosure-workflow.md, guides/scope-recon-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### security-review

**版本**: 0.2.0.2 | **域**: assessment | **MITRE**: T1190-Exploit Public-Facing Application, T1059-Command and Scripting Interpreter, T1562.001-Impair Defenses: Disable Tools, T1070-Indicator Removal | reviewed 2026-09-04

> Comprehensive security checklist and review patterns for analyzing applications, configurations, and infrastructure. This skill provides structured review methodology to identify vulnerabilities across OWASP Top 10 categories during penetration testing.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/code-review-security-patterns-guide.md, guides/dependency-audit-guide.md, guides/owasp-audit-methodology.md, guides/sast-tool-comparison-guide.md, guides/secure-code-review-checklist-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### vulnerability-assessment

**版本**: 0.2.0.2 | **域**: assessment | **MITRE**: T1046-Network Service Scanning, T1595-Active Scanning, T1592-Gather Victim Host Info, T1087-Account Discovery, T1613-Container and Resource Discovery | reviewed 2026-08-17

> Vulnerability assessment is the process of systematically identifying and quantifying security weaknesses in information systems through automated scanning, CVE analysis, and risk scoring.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/2026-03-22-vulnerability-analysis-tools.md, guides/2026-03-22-web-app-analysis-advanced.md, guides/2026-03-22-web-application-analysis-tools.md, guides/automated-scanning-pipeline-guide.md, guides/manual-testing-techniques-guide.md, guides/risk-rating-methodology-guide.md, guides/usage-and-assessment.md, guides/vulnerability-prioritization-guide.md, guides/vulnerability-scanning-network-protocol-cli-reference.md, payloads.md, test-cases.md

---

## automotive

### automotive-vehicle-security

**版本**: 0.2.0.2 | **域**: automotive | **MITRE**: TA0001-Initial Access, TA0040-Detection, T1557-Adversary-in-the-Middle | reviewed 2026-08-16

> CAN/CAN-FD bus analysis, UDS diagnostics, IVI pentest, OBD-II exploitation, key fob replay/relay attacks, GNSS spoofing, EV charging station (ISO 15118), and connected vehicle red team operations.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (14): SKILL.md, guides/automotive-ecu-firmware-and-uds-deep-dive.md, guides/automotive-security-testing-tools-guide.md, guides/automotive-vehicle-security-playbook.md, guides/can-bus-reverse-engineering-guide.md, guides/coordinated-disclosure-and-cvd-guide.md, guides/lab-setup-and-development-mule-guide.md, guides/practical-validation-2026-08-15.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment-zh.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## binary-analysis

### binary-reverse

**版本**: 0.2.0.2 | **域**: binary-analysis | **MITRE**: T1027-Obfuscated Files or Information, T1027.002-Software Packing, T1027.007-Dynamic API Resolution, T1027.011-Fileless Storage | reviewed 2026-09-04

> Binary reverse engineering covers the complete chain from static analysis, dynamic debugging, to vulnerability discovery, exploit development, and malware analysis.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/2026-03-21-reverse-engineering-tools.md, guides/Binary_Analysis_Reverse_Engineering_Story.md, guides/anti-reversing-bypass-guide.md, guides/reverse-engineering-cli-reference.md, guides/usage-and-assessment.md, guides/vulnerability-discovery-binary-guide.md, payloads.md, test-cases.md

---

## blockchain

### blockchain-web3

**版本**: 0.2.0.2 | **域**: blockchain | **MITRE**: N/A (application-layer; maps loosely to TA0001-Initial Access via compromise) | reviewed 2026-08-16

> Blockchain & Web3 security — Solidity/Vyper smart contract auditing, DeFi attack vectors (flash loans, MEV, oracle manipulation), bridge attacks, wallet security, with tooling from Slither/Mythril/Foundry.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/blockchain-web3-bridge-oracle-exploit-deep.md, guides/blockchain-web3-defi-reentrancy-deep.md, guides/blockchain-web3-real-world-incident-case-studies.md, guides/defi-exploit-testing-playbook.md, guides/practical-validation-2026-08-13.md, guides/smart-contract-audit-playbook.md, guides/usage-and-assessment-zh.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## blockchain-l2-attack

### blockchain-l2-attack

**版本**: 0.2.0.2 | **域**: blockchain-l2-attack | **MITRE**: TA0006-Credential Access | reviewed 2026-08-17

> Layer-2 blockchain attack — Lightning Network (BOLT, HTLC), Optimistic Rollups (Optimism/Arbitrum/Boba/Base), ZK Rollups (zkSync/StarkNet/Polygon zkEVM/Scroll/Linea), Polygon PoS, Gnosis sidechain, cross-chain bridges (Wormhole/Nomad/Ronin/Poly Network/Multichain/Horizon), state channels, ERC-4337 account abstraction, and DA layers (Celestia/EigenDA/Avail).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/blockchain-l2-attack-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## cloud

### cloud-security

**版本**: 0.2.0.2 | **域**: cloud | **MITRE**: TA0008-Lateral Movement | reviewed 2026-08-19

> Cloud security covers security assessment for major cloud platforms including AWS, Azure, and GCP, with core focus on IAM misconfiguration detection, storage bucket exposure scanning, metadata service attacks, container escape, and Kubernetes RBAC auditing.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/aws-pentest-lab-guide.md, guides/azure-privilege-escalation-guide.md, guides/cloud-post-exploitation-guide.md, guides/cloud-privilege-escalation-guide.md, guides/cloud_security_complete_guide.md, guides/infrastructure-as-code-security.md, guides/kubernetes-security-deep-dive.md, guides/serverless-security.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### container-security

**版本**: 0.2.0.2 | **域**: cloud | **MITRE**: TA0008-Lateral Movement | reviewed 2026-09-04

> Container security covers the complete lifecycle from image building, registry management, runtime protection, to orchestration platform (Kubernetes) security.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/2026-03-21-container-security-tools.md, guides/container-escape-techniques-guide.md, guides/container-network-segmentation-guide.md, guides/container-runtime-security-guide.md, guides/container-security-cli-reference.md, guides/container-supply-chain-attack-guide.md, guides/docker-breakout-escape-guide.md, guides/kubernetes-attack-surface-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### cspm-casb-attack

**版本**: 0.2.0.2 | **域**: cloud | **MITRE**: T1068-Exploitation for Privilege Escalation, T1565-Adversary-Inhibited-Response-System, T1611-Escape to Host | reviewed 2026-07-26

> CSPM/CASB/CNAPP platform bypass and abuse — rule suppression exploitation, IaC state manipulation, CASB proxy evasion, SaaS shadow discovery, Wiz/Prisma/Lacework/Defender coverage gap identification, and tag-tampering attacks against cloud posture management tools.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/cspm-casb-attack-playbook.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## cloud-native

### cloud-native-vuln-research

**版本**: 0.2.0.2 | **域**: cloud-native | **MITRE**: T1068-Exploitation for Privilege Escalation, T1210-Exploitation of Remote Services, T1190-Exploit Public-Facing App | reviewed 2026-07-26

> CVE research methodology, PoC reproduction, patch gap analysis, and exploit chain composition across container/k8s/cloud-native surfaces; SBOM-driven vuln management and nuclei template authoring.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/cloud-native-vuln-research-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### kubernetes-attack

**版本**: 0.2.0.2 | **域**: cloud-native | **MITRE**: TA0008-Lateral Movement (containers), maps to MITRE ATT&CK for Containers | reviewed 2026-07-26

> Kubernetes cluster attack and red team covering RBAC abuse, pod escape (privileged pods, hostPath, capabilities, hostPID/hostIPC, container runtime sockets, kernel CVEs), kubelet API abuse (10250/10255), etcd direct access, service account token theft (legacy and projected), RBAC privilege escalation chains, cloud-managed K8s (EKS/GKE/AKS) pivoting, and kubectl plugin ecosystem (peirates, CDK, kube-hunter, BOtB, kubeletctl, kubescape, stratus-red-team, kubernetes-goat).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/k8s-escape-and-lateral-movement-playbook.md, guides/kubernetes-attack-detection-evasion-deep.md, guides/kubernetes-attack-playbook.md, guides/kubernetes-attack-rbac-privilege-escalation-deep.md, guides/kubernetes-attack-real-world-incident-case-studies.md, guides/kubernetes-attack-runtime-escape.md, guides/kubernetes-attack-supply-chain-deep.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## confidential-computing

### confidential-computing-attack

**版本**: 0.2.0.2 | **域**: confidential-computing | **MITRE**: T1046-Network Service Discovery, T1602-Data from Configuration Repository | reviewed 2026-07-26

> Attacks against Trusted Execution Environments (TEEs) and confidential computing platforms — Intel SGX (Foreshadow/SGAxe/LVI/ÆPIC Leak), Intel TDX, AMD SEV/SEV-ES/SEV-SNP (CrossLine/BadRAM), Azure CCF, Marblerun, and Gramine/Occlum libos enclaves. Covers side-channel leakage, attestation forgery, ABI misuse, host-to-enclave breakout, enclave-to-host escape, and recovery of sealed secrets. Distinct from hardware-security (broad hardware attacks) and firmware-reverse (UEFI/BIOS).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/confidential-computing-attack-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## credential-access

### password-attack

**版本**: 0.2.0.2 | **域**: credential-access | **MITRE**: TA0006-Credential Access | reviewed 2026-07-19

> Password attacks encompass the complete attack chain from hash extraction, hash type identification, dictionary attacks, rule-based attacks, and bruteforcing to online service brute forcing.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/2026-03-21-password-attack-tools.md, guides/credential-stuffing-automation-guide.md, guides/hash-identification-cracking-guide.md, guides/hashcat-rules-guide.md, guides/password-attack-cli-reference.md, guides/password-policy-audit-guide.md, guides/password-spray-techniques-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## crypto

### pqc-implementation-attack

**版本**: 0.2.0.2 | **域**: crypto | **MITRE**: T1600-Weaken Encryption, T1600.001-Reduce Key Space, T1110.002-Password Cracking, T1486-Data Encrypted for Impact, T1040-Network Sniffing | **OWASP**: N/A — cryptographic implementation class (A02:2021 Cryptographic Failures adjacent) | reviewed 2026-09-04

> Post-quantum cryptography implementation-layer attacks — ML-KEM/Kyber side channels (KyberSlash-class timing, single-trace power/EM, template and deep-learning SCA), fault injection on decapsulation, RNG/keygen weaknesses in liboqs/oqs-provider/PQClean/pqm4, hybrid KEM combiner implementation flaws, and Kyber ransomware sample triage with implementation-defect recovery paths.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/kyber-ransomware-retrospective.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## cryptography

### crypto-attacks

**版本**: 0.2.0.2 | **域**: cryptography | **MITRE**: T1110.002-Password Cracking, T1552.001-Credentials In Files, T1600.001-Weaken Encryption: Reduce Key Space, T1557-Adversary-in-the-Middle | **OWASP**: A04:2021-Cryptographic Failures | reviewed 2026-09-04

> Cryptographic Attacks target implementation flaws and algorithm weaknesses in encryption systems, covering OWASP A04: Cryptographic Failures.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/crypto-attacks-pqc-migration-side-channel.md, guides/crypto_failures_scanner.py, guides/cryptographic_failures_complete_guide.md, guides/hash-length-extension-guide.md, guides/padding-oracle-attack-guide.md, guides/tls-ssl-misconfiguration-guide.md, guides/usage-and-assessment.md, guides/weak-random-number-exploitation-guide.md, payloads.md, test-cases.md

---

### quantum-crypto-attack

**版本**: 0.2.0.2 | **域**: cryptography | **MITRE**: T1040-Network Sniffing (crypto layer), T1573-Encrypted Channel (PQC analysis), forward-looking (no canonical MITRE mapping yet) | reviewed 2026-08-17

> Post-quantum and modern national cryptography attack surface testing covering NIST PQC candidates (ML-KEM/ML-DSA/SLH-DSA), hybrid TLS analysis, QKD/BB84 protocol attacks, Chinese national crypto (SM2/SM3/SM4/SM9) implementation flaws, lattice/hashing signature probing, and quantum-vulnerable RSA/ECC asset discovery using liboqs, GmSSL, cloudflare/circl, OQS-OpenSSL, and PQCrypto-Break.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/pqc-migration-assessment-playbook.md, guides/quantum-crypto-attack-deep-dive.md, guides/quantum-crypto-attack-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## data-exfiltration

### data-exfiltration-attack

**版本**: 0.2.0.2 | **域**: data-exfiltration | **MITRE**: TA0010-Exfiltration, TA0011-Command and Control, T1041, T1048, T1048.002, T1053, T1071, T1071.001, T1071.004, T1090, T1104, T1132, T1567, T1567.002, T1571, T1572, T1573 | reviewed 2026-07-26

> Attacks for exfiltrating data from compromised networks and bypassing DLP/egress controls. Covers DNS tunneling, ICMP/HTTPS tunneling, protocol smuggling, steganographic exfil, cloud-native exfil (S3/OpenSearch/BigQuery), and DLP bypass. Use when testing egress monitoring, validating DLP controls, or simulating APT exfiltration campaigns.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/data-exfiltration-attack-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## data-platform

### data-platform-attack

**版本**: 0.2.0.2 | **域**: data-platform | **MITRE**: TA0006-Credential Access, T1078-Valid Accounts, T1213-Data from Information Repositories | reviewed 2026-07-26

> Attacks against cloud data platforms and analytics pipelines — Snowflake, Databricks, BigQuery, Redshift, dbt, Apache Airflow, and lakehouse architectures. Covers identity-based breaches (no perimeter), warehouse SQL injection at scale, IAM privilege escalation, secrets in DAGs, notebook code injection, and cross-tenant data exfiltration. Distinct from database-attack (protocol-level RDBMS) and cloud-security (broader CSP control plane).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/data-platform-attack-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## data-protection

### data-loss-prevention-bypass

**版本**: 0.2.0.2 | **域**: data-protection | **MITRE**: TA0010-Exfiltration, T1048-Exfiltration Over Alternative Protocol | reviewed 2026-09-04

> DLP bypass techniques covering steganography (LSB, audio, video), DNS tunneling, ICMP tunneling, cloud sync abuse (Dropbox, OneDrive), WebSocket/HTTP3 exfil, AI-augmented exfil (semantic chunking), and modern DLP evasion patterns.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (4): SKILL.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## database

### database-attack

**版本**: 0.2.0.2 | **域**: database | **MITRE**: TA0006-Credential Access | reviewed 2026-09-04

> Direct attacks against database servers at the protocol level — distinct from web-based SQL injection (covered by web-sqli). This skill targets database listeners, authentication mechanisms, stored procedures, and protocol-level misconfigurations.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/database-bruteforce.md, guides/database-lateral-movement-guide.md, guides/nosql-attack-guide.md, guides/oracle-database-attack.md, guides/redis-mongodb-unauth.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## defense

### deception-honeypot

**版本**: 0.2.0.2 | **域**: defense | **MITRE**: TA0040-Detection (deception), maps to MITRE Engage framework | reviewed 2026-08-19

> Defensive deception and honeypot deployment covering SSH/Telnet (Cowrie), web (OpenCanary), enterprise (HFish), ICS/SCADA (Conpot), all-in-one (T-Pot), AI-driven deception (Beelzebub), Thinkst Canarytokens (DNS, HTTP, file, AWS API key, SQL), Dionaea multi-protocol honeypot, notification pipelines (Slack/Teams webhooks), false positive tuning, and attacker engagement — including lure design, deployment OPSEC, IOC extraction, and attacker attribution.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/canary-deployment-playbook.md, guides/deception-honeypot-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### detection-engineering

**版本**: 0.2.0.2 | **域**: defense | **MITRE**: TA0040-Detection (detection engineering discipline); provides coverage across all ATT&CK techniques via Sigma rule taxonomy | reviewed 2026-07-26

> Detection-as-code engineering covering Sigma rule authoring, YARA signature development, Splunk SPL / Kusto KQL / Elastic EQL queries, MITRE ATT&CK mapping, detection CI/CD pipelines, false-positive tuning, and rule testing against EVTX-ATTACK-SAMPLES — using SigmaHQ, Yara-Rules, Loki, yarGen, hayabusa, SigmaCLI, and zircollo.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/detection-engineering-playbook.md, guides/soc-playbook-mapping-to-nist-csf-2-0.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### logging-monitoring

**版本**: 0.2.0.2 | **域**: defense | **MITRE**: T1070-Indicator Removal, T1562-Impair Defenses, T1027-Obfuscated Files or Information, T1059-Command and Scripting Interpreter | **OWASP**: A09:2021-Logging Failures | reviewed 2026-07-26

> Security logging and monitoring deficiencies (OWASP A09:2021) refer to applications failing to properly record security events or lacking effective monitoring, resulting in attacks going undetected, malicious activities being untraceable.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/alert-fatigue-reduction-guide.md, guides/forensic-logging-requirements-guide.md, guides/log-tampering-detection-guide.md, guides/logging_monitoring_complete_guide.md, guides/siem-log-analysis-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### safety-guard

**版本**: 0.2.0.2 | **域**: defense | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Before executing ANY potentially destructive or irreversible command - When a command targets production or critical infrastructure - When operating under a defined rules of engagement (ROE) - When a loop or automated sequence is about to start - User says "safe?

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/error-handling-security-guide.md, guides/input-sanitization-patterns-guide.md, guides/rate-limiting-implementation-guide.md, guides/scope-enforcement-operations.md, guides/security-headers-configuration-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### security-misconfiguration

**版本**: 0.2.0.2 | **域**: defense | **MITRE**: T1190-Exploit Public-Facing Application, T1210-Exploitation of Remote Services, T1078.004-Valid Accounts: Cloud Accounts, T1552.001-Credentials In Files | **OWASP**: A02:2025-Misconfiguration | reviewed 2026-09-04

> Security misconfiguration detection (OWASP A02:2025) covering default credentials, unnecessary services, verbose errors, missing security headers, and directory listing exposures across deployed systems.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/cloud-misconfiguration-audit-guide.md, guides/cloud-misconfiguration-checklist-guide.md, guides/debug-endpoint-discovery-guide.md, guides/default-credential-audit-guide.md, guides/default-credential-scanning-guide.md, guides/security_misconfiguration_complete_guide.md, guides/usage-and-assessment.md, guides/web-server-hardening-guide.md, guides/web-server-hardening-lab-guide.md, payloads.md, test-cases.md

---

### threat-hunting

**版本**: 0.2.0.2 | **域**: defense | **MITRE**: TA0040-Detection | reviewed 2026-07-26

> Proactive threat hunting — MITRE ATT&CK-mapped hunt hypotheses, Sigma detection engineering, SIEM query authoring (Splunk SPL, KQL, Lucene), and SOC workflow integration.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/hunt-hypothesis-playbook.md, guides/sigma-rule-development-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## design

### insecure-design

**版本**: 0.2.0.2 | **域**: design | **MITRE**: T1190-Exploit Public-Facing Application, T1078-Valid Accounts, T1059-Command and Scripting Interpreter, T1562.001-Impair Defenses Disable Tools | **OWASP**: A06:2025-Insecure Design | reviewed 2026-07-26

> Insecure Design (OWASP A06:2025) focuses on security flaws in system architecture and design phases, rather than code implementation-level bugs.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/abuse-case-development-guide.md, guides/business-logic-attack-patterns-guide.md, guides/insecure_design_complete_guide.md, guides/race-condition-exploitation-guide.md, guides/secure-design-patterns-guide.md, guides/state-machine-abuse-guide.md, guides/threat-modeling-for-design-flaws-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## edge

### edge-computing-security

**版本**: 0.2.0.2 | **域**: edge | **MITRE**: TA0001-Initial Access, T1190-Exploit Public-Facing App | reviewed 2026-07-26

> Edge computing security testing covering CDN bypass, Cloudflare Workers abuse, AWS Lambda@Edge attacks, cache poisoning, origin IP discovery, WAF bypass, and edge function injection.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (4): SKILL.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## edge-computing

### edge-computing-attack

**版本**: 0.2.0.2 | **域**: edge-computing | **MITRE**: T1190-Exploit Public-Facing Application, T1552.007-Container and Cloud Instance Credentials API | reviewed 2026-07-26

> Attacks against edge computing platforms — Cloudflare Workers (V8 isolate), Fastly Compute@Edge (WASM/Wasmtime), AWS Lambda@Edge and CloudFront Functions, Akamai EdgeWorkers, Vercel Edge Functions, and Deno Deploy. Covers V8 isolate escape, WASM sandbox bypass, request smuggling at the edge, edge KV store abuse, secret leakage via edge logs, and bypass of origin WAF via edge script injection. Distinct from cloud-security (broader CSP control plane), container-security (Linux namespaces), and web-ssrf (origin-side issues).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/edge-computing-attack-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## embedded-rtos-security

### embedded-rtos-security

**版本**: 0.2.0.2 | **域**: embedded-rtos-security | **MITRE**: T1548-Abuse Elevation Control Mechanism | reviewed 2026-08-16

> RTOS penetration testing — VxWorks WDB debug agent (Urgent/11), QNX microkernel, FreeRTOS+TCP CVEs, ThreadX/Azure RTOS, Zephyr, Mbed OS, TI-RTOS, MicroC/OS, NuttX, RIOT, Contiki

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/embedded-rtos-security-deep-dive.md, guides/embedded-rtos-security-playbook.md, guides/freertos-tcp-vulnerability-research.md, guides/practical-validation-2026-08-16.md, guides/usage-and-assessment-zh.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## enterprise

### ad-ldap-attack

**版本**: 0.2.0.2 | **域**: enterprise | **MITRE**: TA0006-Credential Access | reviewed 2026-07-24

> Active Directory is the backbone of enterprise identity and access management, making it a primary target during internal network penetration tests.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/ad-lateral-movement-guide.md, guides/ad-recon-enumeration-guide.md, guides/kerberos-attack-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## enterprise-cloud

### cloud-identity-attack

**版本**: 0.2.0.2 | **域**: enterprise-cloud | **MITRE**: T1078-Valid Accounts (cloud), T1550-Use Alternate Authentication Material (token reuse), T1606-Forge Web Credentials | reviewed 2026-07-26

> Cloud identity provider attacks covering Azure AD/Entra ID, Okta, Auth0, Ping, AWS IAM Identity Center, and Google Workspace — including OAuth 2.0 token theft, OIDC redirect abuse, SAML response forgery, conditional access bypass, MFA fatigue, federation compromise (AD FS, Ping), app registration abuse, and JIT access exploitation using ROADtools, AADInternals, MicroBurst, MFASweep, TokenTactics, and Okta API probing tools.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/cloud-identity-attack-device-code-phishing-deep.md, guides/cloud-identity-attack-entra-id-deep.md, guides/cloud-identity-attack-federation-abuse-deep.md, guides/cloud-identity-attack-okta-auth0-deep.md, guides/cloud-identity-attack-playbook.md, guides/cloud-identity-attack-privilege-escalation-deep.md, guides/cloud-identity-attack-real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## exploitation

### av-edr-evasion

**版本**: 0.2.0.2 | **域**: exploitation | **MITRE**: TA0005-Defense Evasion | reviewed 2026-07-26

> AV/EDR evasion covers techniques for bypassing antivirus (AV) and Endpoint Detection/Response (EDR) solutions during payload delivery, execution, and post-exploitation.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (13): SKILL.md, guides/av-edr-evasion-edr-rules-evasion-deep.md, guides/av-edr-evasion-kernel-bypass-deep.md, guides/av-edr-evasion-living-off-the-land-deep.md, guides/av-edr-evasion-real-world-incident-case-studies.md, guides/edr-detection-evasion-guide.md, guides/in-memory-execution-dotnet-guide.md, guides/payload-obfuscation-av-bypass-guide.md, guides/process-injection-techniques-guide.md, guides/shellcode-encoding-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### concurrency-exploitation

**版本**: 0.2.0.2 | **域**: exploitation | **MITRE**: TA0003-Execution | reviewed 2026-09-04

> Concurrency exploitation covers race condition vulnerabilities including TOCTOU, signal handler races, thread synchronization bypasses, and timing attacks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (8): SKILL.md, guides/race-window-amplification.md, guides/signal-handler-race-exploitation.md, guides/threadsanitizer-guide.md, guides/toctou-exploitation-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### exploit-development

**版本**: 0.2.0.2 | **域**: exploitation | **MITRE**: TA0002-Execution | reviewed 2026-09-04

> Exploit development covers the full chain from vulnerability discovery through crash analysis to working exploit code, spanning buffer overflows, ROP chains, format string bugs, and shellcode injection across x86 and ARM architectures.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/buffer-overflow-to-rop-chain-guide.md, guides/heap-exploitation-guide.md, guides/kernel-exploit-guide.md, guides/pwntools-exploit-development-guide.md, guides/shellcode-writing-encoding-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### payload-generation

**版本**: 0.2.0.2 | **域**: exploitation | **MITRE**: TA0007-Command and Control | reviewed 2026-07-26

> Payload generation covers the creation, encoding, and delivery of shellcode and executable payloads for initial access and command-and-control (C2) communication.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/cross-platform-payload-guide.md, guides/msfvenom-payload-generation-guide.md, guides/payload-delivery-evasion-guide.md, guides/payload-delivery-techniques-guide.md, guides/payload-encoding-encryption-guide.md, guides/payload-testing-validation-guide.md, guides/reverse-shell-complete-guide.md, guides/usage-and-assessment.md, guides/web-shell-generation-guide.md, payloads.md, test-cases.md

---

### protocol-state-exploitation

**版本**: 0.2.0.2 | **域**: exploitation | **MITRE**: TA0011-Command and Control | reviewed 2026-09-04

> Protocol state exploitation targets vulnerabilities in network protocol state machines including SSH/TLS/HTTP2/DNS, covering illegal state transitions, stateful fuzzing, and protocol-level race conditions.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (8): SKILL.md, guides/http2-rapid-reset-guide.md, guides/scapy-packet-crafting.md, guides/ssh-protocol-state-exploitation.md, guides/stateful-protocol-fuzzing.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## financial

### payment-security

**版本**: 0.2.0.2 | **域**: financial | **MITRE**: T1566-Phishing (credential harvesting) + domain-specific | reviewed 2026-07-26

> Payment systems security — PCI-DSS compliance testing, payment API security (Stripe/Adyen/PayPal), EMV chip/PIN, 3-D Secure, mobile wallets (Apple Pay/Google Pay), and fraud system assessment.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/p2pe-hardware-assessment-playbook.md, guides/payment-pentest-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## fintech-banking

### open-banking-attack

**版本**: 0.2.0.2 | **域**: fintech-banking | **MITRE**: TA0001-Initial Access, TA0006-Credential Access, TA0009-Collection, T1552-Unsecured Credentials, T1550-Use Alternate Authentication Material, T1185-Man in the Browser | reviewed 2026-07-26

> Open Banking / PSD2 / Open Finance attacks — FAPI (Financial-grade API), OpenID Connect for Financial APIs, OAuth2 PKCE, Strong Customer Authentication (SCA) bypass, AIS/PIS/CBPII API abuse, payment redirection, consent manipulation. Covers UK Open Banking, US FDX, Brazil Open Finance, India Account Aggregator, Singapore MAS APIX, Australia CDR. Includes 2024-2025 incidents (Token Hijacking, IdOR on AIS endpoints, PIS redirect manipulation).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/open-banking-attack-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## firmware

### firmware-reverse

**版本**: 0.2.0.2 | **域**: firmware | **MITRE**: TA0002-Execution | reviewed 2026-09-04

> Firmware reverse engineering covers the full pipeline from raw firmware image acquisition through filesystem extraction, static and dynamic analysis, full-system emulation, and vulnerability/backdoor detection.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/firmadyne-emulation.md, guides/firmware-extraction-filesystem.md, guides/firmware-vuln-backdoor.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## forensics

### anti-forensics

**版本**: 0.2.0.2 | **域**: forensics | **MITRE**: TA0005-Defense Evasion | reviewed 2026-09-04

> Anti-forensics is the offensive counterpart to digital forensics.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/crypto-hide-data-destruction.md, guides/filesystem-anti-forensics.md, guides/log-tamper-timestamp.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### digital-forensics

**版本**: 0.2.0.2 | **域**: forensics | **MITRE**: T1070.006-Timestomp, T1562-Impair Defenses, T1547.001-Registry Run Keys / Startup Folder, T1055-Process Injection | reviewed 2026-09-04

> Digital forensics covers the complete workflow of disk forensics, memory forensics, network forensics, file recovery/carving, and chain of custody.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/2026-03-21-digital-forensics-tools.md, guides/digital-forensics-cli-reference.md, guides/disk-image-analysis-guide.md, guides/memory-forensics-volatility-guide.md, guides/network-forensics-pcap-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### steganography

**版本**: 0.2.0.2 | **域**: forensics | **MITRE**: T1001.002-Data Obfuscation Steganography, T1027-Obfuscated Files or Information, T1560-Archive Collected Data, T1105-Ingress Tool Transfer | reviewed 2026-07-26

> Steganography is the practice of concealing data within non-secret carrier files such as images, audio, video, and documents. Unlike encryption, which makes data unreadable but visibly present, steganography hides the very existence of the hidden data.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/audio-video-steganography-guide.md, guides/ctf-steganography-challenge-guide.md, guides/network-protocol-steganography-guide.md, guides/steganography-techniques-detection-guide.md, guides/steghide-stegcracker-practical-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## game-security

### game-anticheat-bypass

**版本**: 0.2.0.2 | **域**: game-security | **MITRE**: TA0005-Defense Evasion, T1068-Exploitation for Privilege Escalation, T1547-Boot or Logon Autostart | reviewed 2026-07-26

> Security research on game anti-cheat systems (EAC/BattlEye/Vanguard/Ricochet) — kernel-mode driver architecture, BYOVD attacks, memory access interception, integrity check evasion, and defense-side anti-cheat engineering.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/game-anticheat-bypass-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## gitops

### gitops-security

**版本**: 0.2.0.2 | **域**: gitops | **MITRE**: TA0001-Initial Access, TA0003-Persistence, TA0004-Privilege Escalation, TA0005-Defense Evasion, TA0006-Credential Access, TA0009-Collection, T1190-Exploit Public-Facing Application, T1611-Escape to Host, T1525-Implant Internal Image, T1609-Container and Resource Discovery, T1613-Container and Resource Discovery, T1610-Deploy Container, T1611-Escape to Host | reviewed 2026-08-17

> Attacks against GitOps control planes (Argo CD, FluxCD, Jenkins X, Tekton, Fleet, Rancher) — repo impersonation, manifest tampering, RBAC bypass, sync-wave abuse, secret management compromise (Sealed Secrets / SOPS / External Secrets / Vault), cluster privilege escalation via Application/CRDs, and post-exploitation persistence through CRD backdoors. Covers 2024-2025 Argo CD CVEs (CVE-2022-24348, CVE-2024-21626, CVE-2024-32564), FluxCD CVE-2024-37286, and the Akuukam/Code Catalyst supply chain incidents.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/gitops-security-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## hardware

### hardware-security

**版本**: 0.2.0.2 | **域**: hardware | **MITRE**: T1200-Hardware Additions, T1195.002-Compromise Software Supply Chain, T1040-Network Sniffing, T1068-Exploitation for Privilege Escalation | reviewed 2026-07-26

> Hardware and embedded system security testing covering physical interface exploitation, firmware extraction and analysis, side-channel attacks, RFID/NFC cloning, and fault injection.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/embedded-firmware-analysis.md, guides/firmware-extraction-analysis-guide.md, guides/hardware-exploitation-patterns-guide.md, guides/jtag-swd-debugging-guide.md, guides/side-channel-attack-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### hardware-side-channel-advanced

**版本**: 0.2.0.2 | **域**: hardware | **MITRE**: T1041-Physical Attacks; emerging hardware-specific | reviewed 2026-09-04

> Advanced hardware side-channel attacks covering power analysis (SPA/DPA), electromagnetic emanation, timing attacks, cache-timing attacks (Spectre/Meltdown variants), glitching (voltage/clock), optical fault injection, and countermeasure evaluation.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (4): SKILL.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## hardware-security

### hsm-attack

**版本**: 0.2.0.2 | **域**: hardware-security | **MITRE**: TA0006-Credential Access, TA0010-Exfiltration, T1552-Unsecured Credentials, T1552.007 Container and Cloud Instance Credentials API, T1041-Exfiltration Over C2 Channel | reviewed 2026-07-26

> Hardware Security Module attacks — physical (side-channel, fault injection, decapping) and logical (PKCS#11 API abuse, key extraction, M-of-N quorum bypass, RDP, firmware exploitation). Covers Thales Luna (SafeNet), Utimaco SecurityServer, nCipher nShield, YubiHSM, AWS CloudHSM, Azure Dedicated HSM, Google Cloud HSM. Includes 2024-2025 CVEs (CVE-2024-47787 Thales Luna, CVE-2024-45294 Utimaco), HSM-as-a-Service tenant isolation attacks, and quorum-spoofing scenarios. Distinct from crypto-attacks (algorithm-level) and pam-privilege-attack (credential management).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/hsm-attack-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## hf-vhf-radio-attack

### hf-vhf-radio-attack

**版本**: 0.2.0.2 | **域**: hf-vhf-radio-attack | **MITRE**: T1557-Adversary-in-the-Middle | reviewed 2026-07-26

> Licensed HF/VHF/UHF radio attack — ADS-B 1090 MHz, AIS, ACARS, VDL Mode 2, POCSAG/FLEX pagers, APRS, NDB, ATC/maritime VHF, DSC, weather fax, MLAT

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/hf-vhf-radio-attack-deep-dive.md, guides/hf-vhf-radio-attack-playbook.md, guides/usage-and-assessment-zh.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## hypervisor-introspection

### hypervisor-introspection

**版本**: 0.2.0.2 | **域**: hypervisor-introspection | **MITRE**: T1068-Exploitation for Privilege Escalation | reviewed 2026-07-26

> Hypervisor introspection (VMI) and virtualization escape attacks — VMware ESXi, Hyper-V, KVM/QEMU, Xen, Proxmox, VirtualBox, LibVMI, DRAKVUF, VENOM CVE-2015-3456, hardware-assisted VT-x/EPT/AMD-V

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/hypervisor-introspection-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## ics

### scada-ics-security

**版本**: 0.2.0.2 | **域**: ics | **MITRE**: TA0100-ICS Attack | reviewed 2026-07-26

> SCADA/ICS security assessment covering industrial control system protocols including Modbus TCP, S7comm (Siemens), DNP3, EtherNet/IP (CIP), OPC UA, BACnet, and GOOSE.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/ics-honeypot-detection-guide.md, guides/ics-incident-response-guide.md, guides/ics-network-assessment.md, guides/ics-protocol-recon.md, guides/modbus-s7comm-attack.md, guides/purdue-model-attack-paths-guide.md, guides/scada-network-monitoring-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## ics-fieldbus-attack

### ics-fieldbus-attack

**版本**: 0.2.0.2 | **域**: ics-fieldbus-attack | **MITRE**: T0817-Program Logic Controller Software | reviewed 2026-08-12

> Industrial fieldbus protocol penetration testing beyond Modbus — Profibus/PROFINET, EtherCAT, DNP3, IEC 61850 (GOOSE/SV/MMS), IEC 60870-5-101/104, Foundation Fieldbus, HART, CC-Link, BACnet deep dive. Covers power utility, process automation, building automation, and automotive fieldbus attack surfaces.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (13): SKILL.md, guides/ics-fieldbus-attack-playbook.md, guides/practical-validation-2026-08-10-zh.md, guides/practical-validation-2026-08-10.md, guides/practical-validation-grficsv3-2026-08-10-zh.md, guides/practical-validation-grficsv3-2026-08-10.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment-zh.md, guides/usage-and-assessment.md, guides/validation-walkthrough-zh.md, payloads.md, test-cases.md

---

## identity

### identity-provider-attack

**版本**: 0.2.0.2 | **域**: identity | **MITRE**: TA0006-Credential Access, T1556-Modify Authentication Process | reviewed 2026-07-26

> Identity Provider (IdP) attack patterns covering OAuth 2.0/OIDC, SAML, JWT, token theft/replay, MFA fatigue, service principal abuse (Azure AD/Entra ID), Okta, Auth0, Keycloak, and modern identity-based attacks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (4): SKILL.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## industrial-control-systems

### cps-attack

**版本**: 0.2.0.2 | **域**: industrial-control-systems | **MITRE**: TA0040-Impact, TA0008-Lateral Movement, TA0009-Collection, T0817-Drive-by Compromise, T0859-Valid Accounts, T0886-Exploitation of Remote Services, T0890-Exploitation for Privilege Escalation, T0808-Activate Firmware, T0884-Connection Proxy, T0858-Change Operating Mode | reviewed 2026-07-26

> Cyber-Physical Systems (CPS) attacks — PLCs (Siemens S7, Rockwell ControlLogix, Schneider Modicon, Mitsubishi MELSEC), ICS protocols (Modbus, DNP3, Profinet, EtherNet/IP, IEC 61850, OPC UA), HMIs, SCADA historians, OT-to-IT pivot, SIS bypass. Distinct from scada-ics-security (broader ICS overview) — this skill goes deep on protocol-level PLC exploitation, packet replay/injection, and field-device firmware attacks. Covers 2024-2025 incidents (Unitronics PLC attack, Pipedream/Incontroller, multi-vendor PLC CVEs).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/cps-attack-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## infrastructure

### autonomous-loops

**版本**: 0.2.0.2 | **域**: infrastructure | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Performing repetitive enumeration across many targets - Running batch vulnerability scans on multiple hosts - Monitoring for changes in target environment - Executing attack chains that require iterative steps - User says "loop", "automate", "batch", "repeat.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (12): SKILL.md, guides/autonomous-decision-making-guide.md, guides/autonomous-pentest-orchestration-guide.md, guides/batch-processing-guide.md, guides/error-recovery-guide.md, guides/feedback-loop-design-guide.md, guides/resource-bounded-execution-guide.md, guides/safe-autonomous-pentest.md, guides/usage-and-assessment.md, guides/watch-loop-patterns-guide.md, payloads.md, test-cases.md

---

### docker-patterns

**版本**: 0.2.0.2 | **域**: infrastructure | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Setting up a practice lab for penetration testing techniques - Creating isolated environments for exploit development and testing - Building vulnerable application targets for training - Testing tools against known-vulnerable configurations - User says "lab", "docker lab.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/container-escape-techniques-guide.md, guides/docker-network-security-guide.md, guides/docker-security-scanning-guide.md, guides/docker-vulnerability-patterns-guide.md, guides/lab-environment-management.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### mcp-server-patterns

**版本**: 0.2.0.2 | **域**: infrastructure | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Building and security-testing MCP (Model Context Protocol) servers for Kali Linux security tools.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/mcp-protocol-debugging-guide.md, guides/mcp-server-deployment-guide.md, guides/mcp-tool-implementation-guide.md, guides/mcp-tool-security-patterns-guide.md, guides/security-mcp-server-design.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### multi-agent-collaboration

**版本**: 0.2.0.2 | **域**: infrastructure | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Coordinating multiple specialized agents to conduct complex penetration testing engagements through task decomposition, parallel execution, result aggregation, and conflict resolution.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/agent-communication-protocols-guide.md, guides/agent-failure-handling-and-recovery-guide.md, guides/conflict-resolution-consensus-guide.md, guides/coordinated-pentest-playbook.md, guides/task-decomposition-delegation-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## iot

### iot-pentest

**版本**: 0.2.0.2 | **域**: iot | **MITRE**: TA0007-Discovery (IoT device recon), T1021-Remote Services (MQTT/CoAP), T1190-Exploit Public-Facing App | reviewed 2026-07-26

> IoT application-layer penetration testing covering MQTT broker abuse, CoAP server attacks, AMQP exploitation, OT/cloud IoT gateways (AWS IoT, Azure IoT Hub), device management platforms, mobile companion apps, embedded web services, and proprietary IoT protocol reverse engineering using mosquitto, MQTT-Pwn, IoT-Goat, EMQX, CoAP testing tools, and IoT-Goat lab environments.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/iot-pentest-playbook.md, guides/radio-and-firmware-iot-testing-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## knowledge

### article-writing

**版本**: 0.2.0.2 | **域**: knowledge | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Transform technical findings into clear, structured written content: penetration test reports, vulnerability disclosures, security blog posts, and technical documentation.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (12): SKILL.md, guides/cve-advisory-writing-guide.md, guides/cvss-scoring.md, guides/penetration-test-report-guide.md, guides/pentest-report-template-guide.md, guides/report-structure.md, guides/security-advisory-writing-guide.md, guides/security-blog-writing-guide.md, guides/usage-and-assessment.md, guides/vulnerability-writing.md, payloads.md, test-cases.md

---

### chronicle

**版本**: 0.2.0.2 | **域**: knowledge | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-09-04

> A system for recording, indexing, and distilling knowledge from agent lifecycle events. Through a three-layer document system (overview -> detailed records -> knowledge distillation), raw conversation events are transformed into reusable experience.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (10): SKILL.md, chronicle-template.py, guides/cross-session-continuity-guide.md, guides/event-recording-best-practices.md, guides/event-timeline-construction-guide.md, guides/knowledge-distillation-guide.md, guides/milestone-tracking-methodology-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### codebase-onboarding

**版本**: 0.2.0.2 | **域**: knowledge | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Rapidly acquire a mental model of any unfamiliar codebase — from a 500-line script to a 100M+ line monorepo. This skill transforms raw code into structured intelligence: architecture maps, entry points, data flows, security surfaces, and onboarding confidence scores.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/architecture-pattern-recognition.md, guides/dependency-supply-chain-analysis-guide.md, guides/legacy-codebase-onboarding.md, guides/microservice-onboarding.md, guides/usage-and-assessment.md, guides/web-framework-onboarding.md, payloads.md, test-cases.md

---

### continuous-learning

**版本**: 0.2.0.2 | **域**: knowledge | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-09-04

> After completing a penetration test engagement - When encountering a novel attack technique or defense - After a tool produces unexpected results - When identifying recurring patterns across targets - User says "learn", "remember this", "pattern.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/adaptive-learning-strategies-guide.md, guides/cross-domain-knowledge-transfer-guide.md, guides/cross-session-knowledge-aggregation-guide.md, guides/knowledge-decay-detection-guide.md, guides/knowledge-extraction-workflow.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### knowledge-ops

**版本**: 0.2.0.2 | **域**: knowledge | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Build and maintain structured, persistent knowledge graphs across sessions. Knowledge-ops transforms ephemeral session findings into reusable intelligence — connecting entities, tracking confidence over time, and enabling recall across engagements.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/cross-session-intelligence-aggregation.md, guides/entity-extraction-and-tagging.md, guides/information-retrieval-optimization-guide.md, guides/knowledge-graph-construction-guide.md, guides/knowledge-graph-visualization-and-querying.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### tool-mastery

**版本**: 0.2.0.2 | **域**: knowledge | **MITRE**: T1046-Network Service Scanning, T1190-Exploit Public-Facing Application, T1110-Brute Force, T1003-OS Credential Dumping | reviewed 2026-09-04

> Verification and assessment of practical proficiency with Kali Linux security tools. Covers tool classification, proficiency levels, verification methods, and combination strategies across the 518-tool Kali arsenal.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/tool-combination-guide.md, guides/tool-proficiency-framework-guide.md, guides/tool-selection-by-phase-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## macos

### macos-security

**版本**: 0.2.0.2 | **域**: macos | **MITRE**: TA0005-Defense Evasion, T1547-Boot or Logon Autostart, T1555-Credentials from Password Stores | reviewed 2026-07-26

> macOS red team and security assessment — SIP/TCC bypass, Endpoint Security framework, Apple Silicon/T2/M-series attacks, Mach-O analysis, Keychain extraction, MDM bypass, LaunchAgents/Daemons persistence, and macOS-native malware analysis.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/macos-security-deep-dive.md, guides/macos-security-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## mainframe

### mainframe-security

**版本**: 0.2.0.2 | **域**: mainframe | **MITRE**: TA0006-Credential Access, T1078-Valid Accounts, T1003-OS Credential Dumping | reviewed 2026-07-26

> IBM z/OS, RACF (Resource Access Control Facility), CICS, DB2, JES2, TSO/ISPF penetration testing; APF library abuse, dataset access control, SNA/Appc attacks, and legacy mainframe security assessment for financial/government environments.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (8): SKILL.md, guides/lab-driven-walkthrough.md, guides/mainframe-security-playbook.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## malware-analysis

### malware-analysis-advanced

**版本**: 0.2.0.2 | **域**: malware-analysis | **MITRE**: TA0005-Defense Evasion, TA0010-Exfiltration, T1027-Obfuscated Files, T1497-Virtualization/Sandbox Evasion, T1562-Impair Defenses, T1014-Hidden Processes, T1547-Boot/Logon Autostart | reviewed 2026-07-26

> Advanced malware analysis covering unpacking (UPX, VMProtect, Themida, Enigma, custom packers), sandbox-evasion detection (anti-VM, anti-debug, anti-analysis), rootkit analysis (user-mode, kernel-mode, bootkits, UEFI), YARA rule authoring and optimization, and IDA Pro / Ghidra / Binary Ninja workflows. Distinct from foundational `binary-reverse` — focuses on dynamic unpacking, evasion triage, rootkit techniques, and analyst workflow automation. Use when analyzing modern packed malware (Emotet, TrickBot, Conti, LockBit, BlackCat/ALPHV, REvil), authoring detection rules, or building automated malware triage pipelines.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/malware-analysis-advanced-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## management

### engagement-manager

**版本**: 0.2.0.2 | **域**: management | **MITRE**: T1595-Active Scanning, T1592-Gather Victim Host Info, T1590-Gather Victim Network Info, T1589-Gather Victim Identity Information | reviewed 2026-09-04

> End-to-end penetration test project management skill. Orchestrates the full engagement lifecycle from scoping through reporting, managing skill composition, evidence chains, and phase transitions.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/engagement-lifecycle-guide.md, guides/evidence-chain-guide.md, guides/scope-management-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## mobile

### mobile-security

**版本**: 0.2.0.2 | **域**: mobile | **MITRE**: T1203-Exploitation for Client Execution, T1204.002-User Execution: Malicious File, T1518.001-Software Discovery: Security Software, T1552.001-Credentials In Files | reviewed 2026-09-04

> Mobile security covers the complete attack/defense chain of Android/iOS application security testing, APK/IPA reverse engineering, runtime manipulation, certificate pinning bypass, and mobile data protection.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/integrity_failures_complete_guide.md, guides/mobile-api-security-testing.md, guides/mobile-cloud-integration.md, guides/mobile_security_complete_guide.md, guides/react-native-flutter-security.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## mobile-deep

### mobile-app-instrumentation

**版本**: 0.2.0.2 | **域**: mobile-deep | **MITRE**: T1623-Mobile Adware, T1518-Software Discovery, T1406-Defacement, T1627.001-Adversary-in-the-Mobile-Device, T1437-Application Layer Protocol | reviewed 2026-07-26

> Dynamic instrumentation of iOS/Android apps via Frida, Objection, r2frida, and Introspy; runtime SSL pinning bypass, jailbreak/root detection bypass, native library hooking, and runtime secrets extraction.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/mobile-app-instrumentation-ios-android-deep.md, guides/mobile-app-instrumentation-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## network-attack

### dns-attacks

**版本**: 0.2.0.2 | **域**: network-attack | **MITRE**: TA0011-Command and Control | reviewed 2026-08-17

> DNS Attacks exploit the Domain Name System protocol for reconnaissance, spoofing, tunneling, and data exfiltration. DNS is a foundational infrastructure service that is frequently misconfigured, poorly monitored, and trusted by default -- making it an ideal attack vector.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/dns-attacks-real-world-incident-case-studies.md, guides/dns-attacks-rebinding-tunneling-modern.md, guides/dns-enumeration-reconnaissance-guide.md, guides/dns-modern-attack-surfaces-deep.md, guides/dns-rebinding-attack-guide.md, guides/dns-spoofing-cache-poisoning-guide.md, guides/dns-tunnel-exfiltration-guide.md, guides/dns-tunneling-exfiltration-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### email-protocol-attack

**版本**: 0.2.0.2 | **域**: network-attack | **MITRE**: T1114-Email Collection | reviewed 2026-07-26

> Email protocol attacks targeting mail infrastructure at the protocol level.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/email-forgery-spf-dkim-dmarc-guide.md, guides/imap-exchange-attack-guide.md, guides/smtp-enumeration-relay-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### network-pentest

**版本**: 0.2.0.2 | **域**: network-attack | **MITRE**: TA0046-Initial Access | reviewed 2026-09-04

> Network penetration testing covering the full attack chain from reconnaissance, port scanning, and service fingerprinting through vulnerability assessment, exploitation, traffic sniffing, and MITM attacks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (13): SKILL.md, guides/2026-03-22-reporting-tools.md, guides/2026-03-22-sniffing-spoofing-tools.md, guides/2026-03-22-system-services-tools.md, guides/FINAL_LEARNING_REPORT.md, guides/comprehensive_pentest_demo.sh, guides/lateral-movement-techniques-guide.md, guides/network-pivot-guide.md, guides/pivoting-tunneling-guide.md, guides/usage-and-assessment.md, guides/wireless-network-attack-guide.md, payloads.md, test-cases.md

---

### network-sniffing-mitm

**版本**: 0.2.0.2 | **域**: network-attack | **MITRE**: TA0006-Credential Access | reviewed 2026-07-26

> Network Sniffing and MITM attacks focus on intercepting, analyzing, and manipulating network traffic between two communicating parties.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/ettercap-bettercap-mitm-attack-guide.md, guides/responder-mitm6-credential-harvesting-guide.md, guides/usage-and-assessment.md, guides/wireshark-tshark-protocol-analysis-guide.md, payloads.md, test-cases.md

---

### network-tunneling-proxy

**版本**: 0.2.0.2 | **域**: network-attack | **MITRE**: TA0008-Lateral Movement | reviewed 2026-07-26

> Network tunneling encapsulates one protocol inside another to bypass firewalls, evade detection, and route traffic through restricted networks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/dns-icmp-covert-tunnel-deep-dive.md, guides/dns-icmp-covert-tunnel.md, guides/ipv6-tunneling-guide.md, guides/pivoting-double-pivot-guide.md, guides/proxy-chain-evasion-guide.md, guides/socks-proxy-chain-traffic.md, guides/ssh-http-tunneling-pivoting.md, guides/tunnel-detection-evasion-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### wifi-pentest

**版本**: 0.2.0.2 | **域**: network-attack | **MITRE**: TA0046-Initial Access | reviewed 2026-09-04

> WiFi security assessment skills: covering wireless network reconnaissance, WPA/WPA2 handshake capture and offline cracking, WPS PIN brute forcing, Evil Twin attacks, wireless sniffing, and deauthentication attacks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/CRACK_MONITOR.md, guides/evil-twin-attack-guide.md, guides/usage-and-assessment.md, guides/wifi-cracking-complete-learning.md, guides/wifi-cracking-course.md, guides/wifi-resume-guide.md, payloads.md, test-cases.md

---

## network-security

### sase-sse-attack

**版本**: 0.2.0.2 | **域**: network-security | **MITRE**: T1557-Adversary-in-the-Middle, T1027-Obfuscated Files or Information, T1078-Valid Accounts, T1550-Use Alternate Authentication Material, T1572-Protocol Tunneling, T1573-Encrypted Channel | reviewed 2026-08-17

> Secure Access Service Edge (SASE) and Security Service Edge (SSE) platform compromise covering Zscaler (ZIA/ZPA/ZDX/Client Connector), Netskope (Security Cloud, SWG, CASB, Private Access), Palo Alto Prisma Access, Cisco Umbrella, CATO Networks SASE, Cloudflare One (WARP, Gateway, Access), and Microsoft Entra Global Secure Access — including client connector reverse engineering, TLS inspection bypass via certificate pinning and ESNI/ECH, split-tunnel race conditions, BYOD vs managed device bypass, stolen SSO token replay through SSE proxy, anonymizer proxy evasion (Shadowsocks/V2Ray/Obfs4/Trojan), and detection avoidance using Wireshark, Frida, mitmproxy, JA3/JA4 fingerprint spoofing.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/netskope-security-cloud-bypass-guide.md, guides/quick-reference-card.md, guides/real-world-incident-case-studies.md, guides/sase-sse-attack-playbook.md, guides/sase-sse-detection-avoidance-guide.md, guides/sase-sse-tls-inspection-evasion-guide.md, guides/usage-and-assessment.md, guides/zscaler-zia-zpa-bypass-guide.md, guides/ztna-client-connector-reverse-guide.md, payloads.md, test-cases.md

---

## osint

### darkweb-intel

**版本**: 0.2.0.2 | **域**: osint | **MITRE**: TA0043-Reconnaissance | reviewed 2026-07-26

> Dark web intelligence gathering — Tor/onion service reconnaissance, marketplace monitoring, breach data markets, threat actor profiling, with strict OPSEC for investigators.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/dark-web-investigation-playbook.md, guides/darkweb-intel-forum-attribution-deep.md, guides/darkweb-intel-i2p-freenet-monitoring-deep.md, guides/darkweb-intel-leak-site-investigation-deep.md, guides/darkweb-intel-monero-tracing-deep.md, guides/darkweb-intel-real-world-incident-case-studies.md, guides/tor-onion-crawl-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### osint

**版本**: 0.2.0.2 | **域**: osint | **MITRE**: TA0043-Reconnaissance | reviewed 2026-09-04

> A specialized skill for intelligence gathering using publicly available sources.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/2026-03-21-information-gathering-tools.md, guides/OSINT-Enterprise-Pentest-Case-Study.md, guides/OSINT_TOOLS_GUIDE.md, guides/automated-osint-pipeline-guide.md, guides/corporate-recon-guide.md, guides/dark-web-intelligence-guide.md, guides/data-aggregation-analysis-guide.md, guides/information-gathering-cli-reference.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### recon-osint

**版本**: 0.2.0.2 | **域**: osint | **MITRE**: TA0043-Reconnaissance | reviewed 2026-09-04

> The most critical first step in penetration testing. Information gathering determines the precision and efficiency of subsequent attacks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (15): SKILL.md, guides/2026-03-21-information-gathering-tools.md, guides/WPScan_Learning_Guide.md, guides/ffuf-advanced-guide.md, guides/gobuster-advanced-guide.md, guides/gobuster-ffuf-quick-reference.md, guides/information-gathering-cli-reference.md, guides/maltego.md, guides/osint-tools-check-20260328.md, guides/photon.md, guides/recon-ng.md, guides/usage-and-assessment.md, guides/wpscan-advanced-guide.md, payloads.md, test-cases.md

---

### social-intelligence

**版本**: 0.2.0.2 | **域**: osint | **MITRE**: TA0043-Reconnaissance | reviewed 2026-08-19

> Real-time intelligence gathering from social platforms and community discussions — capturing what people are saying, sharing, and leaking right now.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/community-monitoring-guide.md, guides/osint-automation-pipeline-guide.md, guides/reddit-hackernews-osint.md, guides/sentiment-analysis.md, guides/social-graph-analysis-guide.md, guides/social-network-mapping-guide.md, guides/target-profiling-guide.md, guides/twitter-youtube-osint.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### username-profiling

**版本**: 0.2.0.2 | **域**: osint | **MITRE**: TA0043-Reconnaissance | reviewed 2026-09-04

> Build a complete dossier on a person using only a username.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/maigret-username-dossier.md, guides/maigret-username-workshop.md, guides/usage-and-assessment.md, guides/username-profiling-deep-dive.md, payloads.md, test-cases.md

---

## pam-privilege-attack

### pam-privilege-attack

**版本**: 0.2.0.2 | **域**: pam-privilege-attack | **MITRE**: T1552-Unsecured Credentials | reviewed 2026-08-16

> Privileged Access Management (PAM) vendor abuse — CyberArk PVWA/PSM/EPV/AIM/CFE, BeyondTrust PRA/Password Safe/Identity Security Insights, Delinea Secret Server/Privilege Manager, One Identity Safeguard, ManageEngine Password Manager Pro, WALLIX Bastion, Devolutions Server, Xton Core. Covers PVWA auth bypass (CVE-2025-32564 area), CyberArk safe enumeration via WebSocket, credential file (.cue) theft and decryption, PSM session hijacking, AIM/CCP provider abuse, master key escrow analysis, BeyondTrust SAML account injection (CVE-2022-2451), Password Safe API abuse, session recording tampering, Delinea OAuth token theft, DPAPI-protected agent config extraction, distributed engine lateral movement, One Identity Safeguard SSL pinning bypass, ManageEngine PMP API key enumeration, PostgreSQL backend extraction (CVE-2022-28226 area), pass-the-hash in PAM contexts, golden ticket interaction with PAM credential rotation, and modern ransomware operator TTPs targeting PAM (BlackCat/ALPHV, LockBit, Royal/BlackSuit).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/pam-privilege-attack-playbook.md, guides/practical-validation-2026-08-15.md, guides/usage-and-assessment-zh.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## physical

### physical-security-testing

**版本**: 0.2.0.2 | **域**: physical | **MITRE**: TA0001-Initial Access (physical), T1192-Hardware Additions, T1366-Physical Security Bypass | reviewed 2026-07-26

> Physical penetration testing covering mechanical lock bypass (pin-tubular/wafer), RFID/NFC badge cloning (Proxmark3/ESP-RFID-Tool/Walrus), HID iCLASS/Mifare duplication, drop box deployment (LAN Turtle/Packet Squirrel), USB weapons (Rubber Ducky/Bash Bunny), hidden camera placement, and on-site engagement operations including tailgating pretext preparation and physical-docs legal templates.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/physical-security-testing-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## post-exploitation

### post-exploitation

**版本**: 0.2.0.2 | **域**: post-exploitation | **MITRE**: TA0005-Defense Evasion | reviewed 2026-07-19

> Post-exploitation covers the complete attack chain after obtaining initial access: privilege escalation, persistence, lateral movement, data collection and exfiltration, and covering tracks.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, guides/2026-03-21-post-exploitation-tools.md, guides/data-exfiltration-guide.md, guides/lateral-movement-practical-guide.md, guides/lateral-movement-techniques-guide.md, guides/persistence-mechanisms-guide.md, guides/persistence-techniques-guide.md, guides/post-exploitation-cli-reference.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### privilege-escalation

**版本**: 0.2.0.2 | **域**: post-exploitation | **MITRE**: TA0004-Privilege Escalation | reviewed 2026-07-21

> Privilege escalation is the process of elevating access from a low-privileged user context (standard user, service account, or limited shell) to root on Linux or SYSTEM/Administrator on Windows.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/kernel-exploit-safety-guide.md, guides/linux-privilege-escalation-enumeration-guide.md, guides/usage-and-assessment.md, guides/windows-privilege-escalation-attack-guide.md, payloads.md, test-cases.md

---

## post-quantum-cryptography

### post-quantum-migration-attack

**版本**: 0.2.0.2 | **域**: post-quantum-cryptography | **MITRE**: TA0006-Credential Access, TA0010-Exfiltration, TA0040-Impact, T1552, T1041, T1565, T1020 | reviewed 2026-09-04

> Attacks against cryptographic systems during the PQC migration period. Covers Harvest-Now-Decrypt-Later (SNDL/HNDL), hybrid PQC downgrade abuse, KEM combiner flaws, mixed-protocol failures, NIST PQC standard implementations (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+), and QKD infrastructure attacks. Use when reviewing cryptographic agility, hybrid deployments, or preparing for quantum threat readiness.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/post-quantum-migration-attack-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## red-team-infrastructure

### red-team-infrastructure

**版本**: 0.2.0.2 | **域**: red-team-infrastructure | **MITRE**: TA0011-Command and Control, T1001, T1008, T1090, T1104, T1132, T1568, T1571, T1572, T1573 | reviewed 2026-07-26

> Building, deploying, and operating stealthy C2 infrastructure for red team engagements. Covers Mythic, Havoc, Sliver, Covenant, PoshC2, Brute Ratel, and Cobalt Strike; redirector chains (Nginx mTLS, Cloudflare workers, CDN domain fronting); dead-drop resolvers; infrastructure OPSEC (compartmentalized servers, auto-rotated certs, decoupled domains); AMIS/GoDaddy API for automated rotation. Use when deploying dedicated adversary emulation infrastructure, planning redirector chains, or testing OPSEC resilience of red team operators.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/real-world-incident-case-studies.md, guides/red-team-infrastructure-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## reporting

### pentest-reporting

**版本**: 0.2.0.2 | **域**: reporting | **MITRE**: T1190-Exploit Public-Facing Application, T1059.004-Unix Shell, T1078-Valid Accounts, T1562.001-Impair Defenses: Disable Tools | reviewed 2026-09-04

> Initialize Dradis for collaborative report authoring and Faraday for vulnerability correlation before testing begins.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/dradis-faraday-reporting.md, guides/evidence-collection.md, guides/password-audit-reporting.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## research

### data-scraper-agent

**版本**: 0.2.0.2 | **域**: research | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Automated data collection from structured sources: CVE databases, threat intelligence feeds, exploit databases, and security advisories. Transform unstructured web data into structured knowledge units.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/anti-bot-bypass-guide.md, guides/data-extraction-patterns-guide.md, guides/nvd-api-scraping-guide.md, guides/rate-limiting-and-stealth-guide.md, guides/structured-data-extraction-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### deep-research

**版本**: 0.2.0.2 | **域**: research | **MITRE**: T1592-Gather Victim Host Info, T1593-Search Open Websites/Domains, T1590-Gather Victim Network Info, T1589-Gather Victim Identity Information | reviewed 2026-08-19

> Multi-source intelligence gathering through systematic web research — producing thorough, cited reports from diverse sources.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (10): SKILL.md, guides/continuous-monitoring.md, guides/intelligence-correlation.md, guides/iterative-search-patterns.md, guides/mcp-integration.md, guides/multi-source-synthesis-guide.md, guides/source-validation-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### exa-search

**版本**: 0.2.0.2 | **域**: research | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Semantic search using Exa API for security research queries. Unlike keyword-based search, Exa understands context and retrieves high-quality, relevant results for technical research.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/advanced-query-construction-guide.md, guides/competitive-intelligence-gathering-guide.md, guides/exa-api-configuration-guide.md, guides/search-result-enrichment-guide.md, guides/semantic-search-query-design-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## reverse-engineering

### reverse-engineering-advanced

**版本**: 0.2.0.2 | **域**: reverse-engineering | **MITRE**: TA0005-Defense Evasion, T1027-Obfuscated Files, T1027.002-Binary Padding, T1027.010-Command Obfuscation, T1140-Deobfuscate/Decode | reviewed 2026-08-17

> Advanced reverse engineering covering symbolic execution (angr, KLEE, manticore), decompiler confusion (Hex-Rays, Ghidra deobfuscation), binary diffing (BinDiff, Diaphora, Kam1n0), firmware RE workflow (binwalk, FACT, EMBA), and obfuscated code analysis (LLVM obfuscation, OLLVM, Tigress). Distinct from foundational `binary-reverse` — focuses on advanced program analysis, automated RE techniques, and firmware / obfuscation workflows. Use when analyzing obfuscated or packed binaries, automating RE pipelines, analyzing firmware, or studying APT-grade obfuscation (Equation Group, Pegasus).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/real-world-incident-case-studies.md, guides/reverse-engineering-advanced-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## satellite-leo-security

### satellite-leo-security

**版本**: 0.2.0.2 | **域**: satellite-leo-security | **MITRE**: T1557-Adversary-in-the-Middle | reviewed 2026-07-26

> Satellite and LEO communication security — Starlink, Kuiper, OneWeb, Iridium, Inmarsat, Viasat KA-SAT, HughesNet, DVB-S/S2, VSAT (iDirect/Hughes), GNSS receiver attacks, AcidRain wiper (Viasat 2022)

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (5): SKILL.md, guides/satellite-leo-security-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## security

### sdr-rf-attack

**版本**: 0.2.0.2 | **域**: security | **MITRE**: T1557-Adversary-in-the-Middle, T1040-Network Sniffing, T1200-Hardware Additions, T1095-Non-Application Layer Protocol | reviewed 2026-07-26

> Software Defined Radio and RF signal attacks encompass a broad range of offensive techniques targeting wireless communication systems.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (13): SKILL.md, guides/gps-spoofing-guide.md, guides/gsm-lte-basestation-attack-guide.md, guides/rf-fingerprinting-device-identification-guide.md, guides/rfid-nfc-deep-dive-guide.md, guides/rfid-rf-replay-attack-guide.md, guides/satellite-signal-analysis-guide.md, guides/sdr-signal-capture-analysis-guide.md, guides/sub-ghz-iot-attack-guide.md, guides/usage-and-assessment.md, guides/zigbee-ble-sdr-guide.md, payloads.md, test-cases.md

---

### vpn-attack

**版本**: 0.2.0.2 | **域**: security | **MITRE**: T1133-External Remote Services, T1190-Exploit Public-Facing Application, T1078-Valid Accounts, T1046-Network Service Scanning | reviewed 2026-07-26

> Virtual Private Networks (VPNs) are a critical component of enterprise network security, providing encrypted tunnels for remote access and site-to-site connectivity.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/ipsec-vpn-enumeration-fingerprinting-guide.md, guides/openvpn-attack-guide.md, guides/ssl-vpn-exploitation-deep-dive-guide.md, guides/ssl-vpn-exploitation-guide.md, guides/usage-and-assessment.md, guides/vpn-credential-brute-force-guide.md, guides/vpn-credential-tunnel-attack-guide.md, guides/vpn-pivoting-lateral-guide.md, guides/wireguard-attack-guide.md, payloads.md, test-cases.md

---

## social

### social-engineering

**版本**: 0.2.0.2 | **域**: social | **MITRE**: TA0043-Reconnaissance | reviewed 2026-07-21

> Social engineering is the art of exploiting human psychological weaknesses rather than technical vulnerabilities to execute attacks. Attack vectors encompass Phishing, Pretexting, Baiting, Tailgating, Vishing, and other techniques.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/2026-03-21-social-engineering-tools.md, guides/phishing-campaign-design-guide.md, guides/pretexting-techniques-guide.md, guides/social-engineering-cli-reference.md, guides/social-engineering-defense-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## storage-san-attack

### storage-san-attack

**版本**: 0.2.0.2 | **域**: storage-san-attack | **MITRE**: ['T1552-Unsecured Credentials', 'T1021-Remote Services', 'T1486-Data Encrypted for Impact', 'T1530-Data from Cloud Storage Object', 'T1213-Data from Information Repositories'] | reviewed 2026-07-26

> Storage/SAN/NAS/Object storage penetration testing — iSCSI, Fibre Channel, NFSv3/v4, SMB3, S3-compatible APIs, NetApp ONTAP, Dell EMC, Pure Storage, QNAP, Synology, TrueNAS, NDMP backup tape pilfering, and ransomware patterns targeting storage appliances. Distinct from database-attack (which targets RDBMS/NoSQL query protocols) and cloud-native-vuln-research (which focuses on CVE research rather than storage fabric and appliance pentest).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/storage-san-attack-playbook.md, guides/storage-san-attack-real-world-incident-case-studies.md, guides/storage-san-attack-vendor-deep.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## supply-chain

### supply-chain-security

**版本**: 0.2.0.2 | **域**: supply-chain | **MITRE**: T1195-Supply Chain Compromise, T1195.001-Compromise Software Dependencies and Development Tools, T1195.002-Compromise Software Supply Chain, T1199-Trusted Relationship | **OWASP**: A08:2021-Software Integrity | reviewed 2026-09-04

> Software supply chain security covering the entire lifecycle from code development to deployment: dependency vulnerabilities (known-vulnerable third-party packages), malicious packages (injection and typosquatting.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (10): SKILL.md, guides/build-pipeline-security-guide.md, guides/dependency-confusion-attack-guide.md, guides/package-integrity-verification-guide.md, guides/software-bill-of-materials-guide.md, guides/software_supply_chain_complete_guide.md, guides/supply_chain_scanner.py, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## telecom

### 5g-6g-telecom-attack-advanced

**版本**: 0.2.0.2 | **域**: telecom | **MITRE**: TA0001-Initial Access, T1557-Adversary-in-the-Middle | reviewed 2026-09-04

> Advanced 5G/6G telecom attacks covering 5G Core (SBA) exploitation, IMSI catcher evolution (5G Stingray), SIP/Diameter protocol attacks, Open RAN vulnerabilities, network slicing abuse, and early 6G research vectors (THz comms, AI-native air interface).

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (4): SKILL.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### 5g-telecom-attack

**版本**: 0.2.0.2 | **域**: telecom | **MITRE**: TA0001-Initial Access, T1557-Adversary-in-the-Middle, T1565-Exfiltration | reviewed 2026-07-26

> 5G core (AMF/SMF/UPF), RAN, signaling (PFCP/GTP/Diameter/SS7), IMSI catchers, O-RAN security, roaming abuse, SMS interception, and telecom infrastructure red team operations.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/5g-telecom-attack-deep-dive.md, guides/5g-telecom-attack-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## testing

### browser-qa

**版本**: 0.2.0.2 | **域**: testing | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Automated browser-based security testing using Playwright and browser devtools. Interact with web applications as a user would — click, type, navigate — while monitoring network traffic, JavaScript execution, and DOM changes for security issues.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/browser-fingerprint-analysis-guide.md, guides/headless-browser-security-testing-guide.md, guides/network-interception-guide.md, guides/playwright-auth-testing-guide.md, guides/usage-and-assessment.md, guides/web-automation-evidence-capture-guide.md, payloads.md, test-cases.md

---

## threat-intel-platforms

### threat-intel-platform-attack

**版本**: 0.2.0.2 | **域**: threat-intel-platforms | **MITRE**: TA0001-Initial Access, TA0006-Credential Access, T1078-Valid Accounts, T1190-Exploit Public-Facing App, T1552-Unsecured Credentials, T1566-Phishing | reviewed 2026-07-26

> Attacking threat intelligence platforms (MISP, OpenCTI, Anomali ThreatStream, ThreatQuotient, ThreatConnect, IBM Threat Intel, Palo Alto AutoFocus, Mandiant Advantage). Covers platform CVEs (MISP CVE-2022-29527, OpenCTI vulnerabilities), API abuse, sharing-group trust abuse, false-positive IOC injection, STIX/TAXII feed manipulation, and supply-chain attacks via poisoned TI feeds. Use when testing threat-intel platform security, validating IOC sharing trust models, or simulating APT feed-poisoning campaigns.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/real-world-incident-case-studies.md, guides/threat-intel-platform-attack-playbook.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## voip

### voip-sip-attack

**版本**: 0.2.0.2 | **域**: voip | **MITRE**: TA0046-Initial Access | reviewed 2026-09-04

> Voice over IP (VoIP) systems use the Session Initiation Protocol (SIP) for call signaling, the Real-time Transport Protocol (RTP) for media streaming, and the Inter-Asterisk eXchange protocol (IAX2) for alternative VoIP communication.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/sip-device-recon.md, guides/usage-and-assessment.md, guides/voip-denial-of-service.md, guides/voip-eavesdropping-spoofing.md, payloads.md, test-cases.md

---

## vuln-research

### patch-to-poc-pipeline

**版本**: 0.2.0.2 | **域**: vuln-research | **MITRE**: TA0040-Detection; CWE-787 Out-of-Bounds Write, CWE-125 OOB Read, CWE-190 Integer Overflow, CWE-416 Use-After-Free, CWE-119 Buffer Overflow, CWE-94 Code Injection, CWE-89 SQLi, CWE-22 Path Traversal | reviewed 2026-08-17

> The end-to-end patch-diff vulnerability reproduction workflow — patch analysis (read diff, identify protective pattern, hypothesize bug class), source or binary-only code path walking (Ghidra + BinDiff), PoC generation (manual craft OR AFL++/libFuzzer harness with ASan/UBSan), CyberGym-style differential verification (vuln crashes, patched clean) as the deterministic stop condition, and YARA + Sigma detection rule authoring tested against both versions. Covers 2024-2026 CVEs (libwebp, xz-utils, runc, glibc Looney Tuner, regreSSHion, MOVEit, Jenkins, Confluence, TeamCity, OFBiz). Solidifies validation/scenarios/SCEN-008.md into a reusable knowledge base and wires in Schema 3 reproduction memory for memory-driven convergence.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (6): SKILL.md, guides/patch-to-poc-pipeline-playbook.md, guides/real-world-incident-case-studies.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## web-attack

### api-security

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: T1190-Exploit Public-Facing Application, T1528-Steal Application Access Token, T1539-Steal Web Session Cookie, T1552.001-Credentials In Files | **OWASP**: API Security Top 10 | reviewed 2026-09-04

> API Security Testing covers security assessment across three major API architectures: REST, GraphQL, and gRPC, focusing on the OWASP API Security Top 10 core risks: Broken Authentication, Broken Object Level Authorization (BOLA), Excessive Data Exposure, Rate Limiting Bypass.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (11): SKILL.md, api-security-guide.md, guides/api-authentication-bypass-guide.md, guides/api-rate-limiting-bypass-guide.md, guides/api-security-complete-guide.md, guides/graphql-security-testing-guide.md, guides/graphql-security-testing.md, guides/usage-and-assessment.md, guides/websocket-security-guide.md, payloads.md, test-cases.md

---

### cms-framework-attack

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: T1190-Exploit Public-Facing Application, T1195.002-Compromise Software Supply Chain, T1505.003-Web Shell, T1078-Valid Accounts | reviewed 2026-09-04

> Targeted security assessment of Content Management Systems (WordPress, Joomla, Drupal) using specialized scanners and exploit techniques.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/cms-identification-enumeration-guide.md, guides/joomla-drupal-cms-attack-guide.md, guides/usage-and-assessment.md, guides/wordpress-pentest-guide.md, payloads.md, test-cases.md

---

### command-injection-advanced

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: TA0002-Execution | **OWASP**: A03:2021-Injection | reviewed 2026-09-04

> Advanced injection attacks beyond SQL - covering OS command injection, LDAP injection, NoSQL injection, template injection (SSTI), XPath injection, and comprehensive filter bypass techniques.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (8): SKILL.md, guides/blind-injection-techniques.md, guides/command-injection-filter-bypass.md, guides/ldap-nosql-injection-guide.md, guides/ssti-exploitation-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### file-inclusion

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: T1190-Exploit Public-Facing Application, T1105-Ingress Tool Transfer, T1210-Exploitation of Remote Services, T1505.003-Web Shell | **OWASP**: A01:2021-Broken Access Control | reviewed 2026-09-04

> Local File Inclusion (LFI) and Remote File Inclusion (RFI) attack techniques covering path traversal, PHP wrapper abuse, log poisoning, session file inclusion, and remote payload hosting for code execution.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/lfi-to-rce-exploitation-guide.md, guides/path-traversal-bypass-guide.md, guides/rfi-remote-code-execution-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### web-access-control

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: T1190-Exploit Public-Facing Application, T1078-Valid Accounts, T1098-Account Manipulation, T1539-Steal Web Session Cookie | **OWASP**: A01:2021-Broken Access Control | reviewed 2026-09-04

> Broken Access Control (OWASP Top 10 2025 - A01) attacks and defense — covering core attack surfaces including IDOR (Insecure Direct Object Reference), vertical/horizontal privilege escalation, path traversal, and permission bypass.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, access-control-guide.md, guides/access_control_scanner.py, guides/broken_access_control_complete_guide.md, guides/broken_access_control_payloads.md, guides/csrf-attack-guide.md, guides/idor-exploitation-guide.md, guides/multi-tenancy-isolation-testing-guide.md, guides/privilege-escalation-web-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### web-auth-bypass

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: T1078-Valid Accounts, T1110.003-Password Spraying, T1552.001-Credentials In Files, T1187-Forced Authentication | **OWASP**: A07:2021-Identification | reviewed 2026-09-04

> Authentication Bypass refers to attackers exploiting design flaws or implementation vulnerabilities in authentication mechanisms to bypass the normal authentication process and gain unauthorized access.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (10): SKILL.md, auth-bypass-guide.md, guides/auth-bypass-complete-guide.md, guides/jwt-attack-methodology.md, guides/mfa-bypass-techniques-guide.md, guides/oauth-vulnerability-testing-guide.md, guides/session-management-attacks-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### web-deserialization

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: T1190-Exploit Public-Facing App | **OWASP**: A08:2021-Software Integrity Failures | reviewed 2026-07-26

> Deserialization vulnerabilities arise when an application reconstructs objects from byte streams (Java), serialized strings (PHP), Base64 blobs (.NET), or pickle data (Python) supplied by the client.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/cross-platform-deserialization-guide.md, guides/dotnet-deserialization-guide.md, guides/java-deserialization-ysoserial-guide.md, guides/nodejs-deserialization-guide.md, guides/php-deserialization-phpggc-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### web-sqli

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: T1190-Exploit Public-Facing App | **OWASP**: A03:2021-Injection | reviewed 2026-07-19

> SQL injection attacks and defense - covering all major SQLi types including error-based, union-based, blind (boolean/time), double query (error-based), stacked queries, and out-of-band injection.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (31): SKILL.md, guides/bug_bounty_sqli_scanner.py, guides/comprehensive_double_query_test.py, guides/cross_database_sqli_guide.md, guides/ctf_sqli_practice_guide.md, guides/ctf_sqli_solver.py, guides/double_query_complete_guide.md, guides/double_query_correct_test.py, guides/double_query_lab.md, guides/double_query_learning_complete.md, guides/double_query_simplified_test.py, guides/double_query_study_findings.md, guides/double_query_test.py, guides/master_double_query_final.py, guides/portswigger_learning_notes.md, guides/portswigger_sqli_auto.py, guides/portswigger_sqli_labs.md, guides/real_world_sqli_case_studies.md, guides/sqli-labs-auto.sh, guides/sqli-labs-batch-notes.md, guides/sqli-labs-batch-test.sh, guides/sqli-labs-full-roadmap.md, guides/sqli-labs-milestone-20.md, guides/sqli-labs-milestone-30.md, guides/sqli-labs-progress.md, guides/usage-and-assessment.md, guides/waf-bypass-sqli-guide.md, payloads.md, sqli-cross-db-guide.md, sqli-double-query-guide.md, test-cases.md

---

### web-ssrf

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: T1190-Exploit Public-Facing App | **OWASP**: A10:2021-SSRF | reviewed 2026-07-19

> Server-Side Request Forgery (SSRF) attacks including basic, blind, and advanced bypass techniques, internal port scanning, cloud metadata extraction (AWS/GCP/Azure), protocol smuggling (gopher://, dict://, file://), and chained RCE exploitation.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (10): SKILL.md, guides/blind-ssrf-detection-guide.md, guides/cloud-metadata-ssrf-guide.md, guides/ssrf-filter-bypass-guide.md, guides/ssrf-post-exploitation-guide.md, guides/ssrf-to-rce-escalation-guide.md, guides/ssrf_complete_guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### web-xss

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: T1189-Drive-by Compromise | **OWASP**: A03:2021-Injection | reviewed 2026-07-19

> XSS (Cross-Site Scripting) is an attack that injects malicious scripts into trusted websites.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (12): SKILL.md, guides/csp-bypass-techniques-guide.md, guides/dom-xss-source-sink-analysis-guide.md, guides/ssti-attack-guide.md, guides/usage-and-assessment.md, guides/waf-bypass-xss-guide.md, guides/web-application-security-cli-reference.md, guides/web_security_advanced_plan.md, guides/xss-filter-evasion-guide.md, guides/xss-to-rce-escalation-guide.md, payloads.md, test-cases.md

---

### web-xxe

**版本**: 0.2.0.2 | **域**: web-attack | **MITRE**: T1190-Exploit Public-Facing Application, T1005-Data from Local System, T1105-Ingress Tool Transfer, T1210-Exploitation of Remote Services | **OWASP**: A05:2021-Security Misconfiguration | reviewed 2026-07-26

> XML External Entity (XXE) injection exploits vulnerable XML parsers to read local files, initiate SSRF attacks, exfiltrate data through out-of-band channels, and cause denial of service.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/blind-xxe-exfiltration-guide.md, guides/oxml-xxe-social-engineering-guide.md, guides/usage-and-assessment.md, guides/xxe-attack-techniques-guide.md, payloads.md, test-cases.md

---

## wireless

### bluetooth-rfid-nfc

**版本**: 0.2.0.2 | **域**: wireless | **MITRE**: TA0046-Initial Access | reviewed 2026-07-26

> Near-field wireless penetration testing skills covering Bluetooth Classic device enumeration and exploitation, BLE GATT service attacks against IoT devices, RFID card cloning (MIFARE Classic/DESFire), NFC tag manipulation, and contactless payment probing.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (7): SKILL.md, guides/ble-gatt-attack.md, guides/bluetooth-device-recon.md, guides/rfid-nfc-clone.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

## workflow

### search-first

**版本**: 0.2.0.2 | **域**: workflow | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> Systematizes the "search for existing tools, exploits, and techniques before writing custom ones" workflow.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (9): SKILL.md, guides/exploit-research-methodology.md, guides/multi-source-intelligence-correlation-guide.md, guides/search-query-optimization-guide.md, guides/search-result-validation-guide.md, guides/tool-evaluation-and-selection-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### terminal-ops

**版本**: 0.2.0.2 | **域**: workflow | **MITRE**: T1059-Command and Scripting Interpreter, T1059.004-Unix Shell, T1021.004-Remote Services: SSH, T1518-Software Discovery | reviewed 2026-09-04

> Evidence-first execution workflow for running security commands, inspecting system state, debugging tool failures, and making verified changes. This skill enforces a disciplined approach: inspect before acting, keep changes narrow, and report exact execution state.

**Defense Triple**: Defense Perspective ✓ | Detection Methods ✓ | Defense Evasion ✓

**文件** (9): SKILL.md, guides/evidence-first-execution.md, guides/terminal-automation-scripting-guide.md, guides/terminal-forensics-evidence-guide.md, guides/terminal-network-operations-guide.md, guides/terminal-session-management-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---

### verification-loop

**版本**: 0.2.0.2 | **域**: workflow | **MITRE**: N/A (non-attack meta skill) | reviewed 2026-07-26

> After discovering a potential vulnerability or exploit - Before submitting any finding to a report or bounty platform - When verifying that a remediation or patch is effective - When cross-checking automated scanner results - User says "verify", "confirm", "validate.

**Defense Triple**: exempt (defense_triple_required: false)

**文件** (12): SKILL.md, guides/automated-exploit-verification-guide.md, guides/continuous-security-validation-guide.md, guides/cross-tool-verification-guide.md, guides/false-positive-triage-guide.md, guides/finding-documentation-evidence-guide.md, guides/finding-verification-methodology.md, guides/regression-testing-security-guide.md, guides/remediation-verification-patterns-guide.md, guides/usage-and-assessment.md, payloads.md, test-cases.md

---
