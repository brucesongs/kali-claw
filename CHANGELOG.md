# Changelog

All notable changes to kali-claw are documented in this file.

Version format: MAJOR.MINOR.PATCH — PATCH increments per change; resets to 0 and bumps MINOR when PATCH exceeds 1024.

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
