# Changelog

All notable changes to kali-claw are documented in this file.

Version format: MAJOR.MINOR.PATCH — PATCH increments per change; resets to 0 and bumps MINOR when PATCH exceeds 1024.

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
