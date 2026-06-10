---
name: engagement-manager
description: "End-to-end penetration test project management skill. Orchestrates the full engagement lifecycle from scoping through reporting, managing skill composition, evidence chains, and phase transitions."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
  - Agent
metadata:
  domain: management
  tool_count: 0
  guide_count: 3
---




# Engagement Manager

## Summary

Orchestrates the full engagement lifecycle from scoping through reporting, managing skill composition, evidence chains, and phase transitions.

**Domain**: management

## Description

Engagement Manager is the orchestration skill that manages the full penetration testing lifecycle from initial scoping through final report delivery. It coordinates skill composition across 69 security domains, manages the kill chain phase progression (recon, scan, enum, vuln, exploit, post-exp), maintains evidence chain integrity, and ensures data handoffs between phases are complete and structured. The skill handles scope boundary enforcement, critical finding notification protocols, multi-target coordination, checkpoint-based pause/resume, and standardized report generation. It serves as the command center that activates specialized skills based on target type and manages the overall engagement state.

## Use Cases

- Manage a complete penetration test engagement from kickoff to report delivery
- Automatically select and sequence skills based on target type
- Track kill chain phase progress and data handoffs between phases
- Maintain evidence chain integrity across multi-skill attack scenarios
- Generate standardized reports from collected evidence

## Core Tools

| Tool | Category | Purpose | Key Command |
|------|----------|---------|-------------|
| orchestrator.sh | Engagement Orchestration | End-to-end penetration test workflow execution | `orchestrator.sh --target web --phase all` |
| tool-selector.sh | Tool Selection | Target-to-tool mapping by attack phase and type | `tool-selector.sh --target-type web --phase recon` |
| report-generator.sh | Reporting | Automated report generation from collected evidence | `report-generator.sh --source evidence/ --format html` |
| drift-detect.sh | Quality Assurance | Configuration drift detection and baseline management | `drift-detect.sh --create-baseline` |

## Methodology

1. **Scope & Plan** — Define target, scope rules, and skill chain based on target type
2. **Execute Kill Chain** — Progress through recon → scan → enum → vuln → exploit → post-exp with data handoff
3. **Evidence Collection** — Capture structured evidence at each phase with timestamps
4. **Cross-Phase Validation** — Verify findings from one phase inform the next
5. **Report Generation** — Compile findings into standardized report with severity ratings

## Skill Composition

| Target Type | Skills Activated |
|-------------|-----------------|
| web | web-xss, web-sqli, web-auth-bypass, web-access-control, web-ssrf |
| cloud | cloud-security, container-security, api-security, supply-chain-security |
| network | network-pentest, password-attack, post-exploitation |
| mobile | mobile-security, binary-reverse |
| api | api-security, web-auth-bypass, web-access-control |

## Key Decisions

- IF target has web services → activate web-xss + web-sqli + web-auth-bypass
- IF target is cloud-hosted → activate cloud-security + container-security
- IF engagement duration < 8 hours → prioritize high-value attack paths
- IF critical finding confirmed → pause, notify client within 4 hours
- IF scope boundary hit → stop, document, request scope expansion

## Practical Steps

1. **Initialize engagement** — Create workspace directory structure, load target configuration (targets.json), define scope rules, and verify tool availability
2. **Determine skill composition** — Map target type to appropriate security skills using the Skill Composition table
3. **Execute kill chain phases** — Progress sequentially through recon, scan, enum, vuln, exploit, and post-exp phases, capturing structured evidence at each step
4. **Manage data handoffs** — Ensure output from each phase feeds correctly into the next phase through standardized file formats
5. **Enforce scope boundaries** — Continuously verify all targets and techniques remain within approved scope; halt and document any scope violations
6. **Handle critical findings** — When critical vulnerabilities are discovered, follow the 4-hour notification protocol and document in evidence
7. **Track engagement state** — Update checkpoint.json after each phase completion to enable pause/resume capability
8. **Generate report** — Compile all evidence into a standardized report with executive summary, technical findings, CVSS scores, and remediation priorities
9. **Perform quality assurance** — Validate evidence completeness, verify findings have all required fields, check report for placeholder text

## Defense Perspective

Understanding the engagement lifecycle from a defensive perspective helps organizations prepare for and respond to penetration tests effectively:

- **Engagement indicators**: Defenders should receive advance notice of authorized testing windows and source IP ranges to distinguish legitimate tests from actual attacks.
- **Detection during testing**: Security teams should monitor for engagement artifacts — nmap scans, brute-force attempts, exploitation payloads — and verify these align with authorized testing schedules.
- **Scope enforcement verification**: Blue teams should independently verify that testing stays within approved scope by monitoring network traffic and log entries for activity against out-of-scope systems.
- **Evidence handling**: Organizations should retain copies of all penetration test evidence for their own records and ensure the engagement team follows proper data handling procedures.
- **Post-engagement review**: After testing concludes, defenders should conduct a lessons-learned session to identify detection gaps, response time improvements, and architectural weaknesses revealed by the test.

## Quality Criteria

- All phases produce structured evidence files with timestamps
- Data handoffs between phases are documented and verified
- Findings include severity, CVSS score, PoC, impact, and remediation
- Report follows standard penetration test template with all required sections
- Evidence chain is complete, timestamped, and integrity-verified with checksums
- Critical findings are notified within the agreed-upon timeframe
- Scope boundaries are enforced with zero violations
