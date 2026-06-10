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

Orchestrates the full engagement lifecycle from scoping through reporting, managing skill composition, evidence chains, phase transitions, and stakeholder communication. Serves as the command center that coordinates specialized security skills, enforces scope boundaries, tracks progress across kill chain phases, and ensures deliverables meet professional standards.

**Domain**: management

## Description

Engagement Manager is the orchestration skill that manages the full penetration testing lifecycle from initial scoping through final report delivery. It coordinates skill composition across 69 security domains, manages the kill chain phase progression (recon, scan, enum, vuln, exploit, post-exp), maintains evidence chain integrity, and ensures data handoffs between phases are complete and structured. The skill handles scope boundary enforcement, critical finding notification protocols, multi-target coordination, checkpoint-based pause/resume, and standardized report generation. It serves as the command center that activates specialized skills based on target type and manages the overall engagement state.

The engagement lifecycle follows a strict progression: Rules of Engagement (RoE) review and scope definition, target enumeration and attack surface mapping, systematic vulnerability discovery, controlled exploitation with evidence capture, post-exploitation assessment, and comprehensive reporting with remediation guidance. Each phase has entry criteria, exit criteria, and required evidence artifacts. The Engagement Manager ensures no phase is skipped, all data handoffs are validated, and findings are traceable from initial detection through final report inclusion.

Critical finding management is a key responsibility. When a high-severity vulnerability is confirmed (e.g., remote code execution, credential compromise, data exposure), the Engagement Manager triggers the notification protocol within the agreed timeframe (typically 4 hours), documents the finding with full evidence, and coordinates with the client for emergency remediation without disrupting the broader engagement. Multi-target engagements require careful parallel coordination — different skills may be active simultaneously against different targets, and the Engagement Manager must track all active threads, maintain separate evidence chains per target, and prevent scope confusion.

## Use Cases

- Manage a complete penetration test engagement from kickoff to report delivery with full phase tracking
- Automatically select and sequence skills based on target type using the skill composition matrix
- Track kill chain phase progress and data handoffs between phases with checkpoint validation
- Maintain evidence chain integrity across multi-skill attack scenarios with checksums and timestamps
- Generate standardized reports from collected evidence with executive summary and technical findings
- Coordinate multi-target engagements with parallel skill activation and separate evidence chains
- Enforce scope boundaries with zero violations; halt and document any scope boundary encounters
- Handle critical finding notification within the agreed-upon timeframe while maintaining engagement continuity
- Support engagement pause/resume with checkpoint-based state management for multi-day assessments
- Conduct post-engagement quality assurance: evidence completeness, finding validation, report accuracy

## Core Tools

| Tool | Category | Purpose | Key Command |
|------|----------|---------|-------------|
| orchestrator.sh | Engagement Orchestration | End-to-end penetration test workflow execution | `orchestrator.sh --target web --phase all` |
| tool-selector.sh | Tool Selection | Target-to-tool mapping by attack phase and type | `tool-selector.sh --target-type web --phase recon` |
| report-generator.sh | Reporting | Automated report generation from collected evidence | `report-generator.sh --source evidence/ --format html` |
| drift-detect.sh | Quality Assurance | Configuration drift detection and baseline management | `drift-detect.sh --create-baseline` |

## Methodology

1. **Scope & Plan** — Define target, scope rules, and skill chain based on target type. Review Rules of Engagement, identify in-scope and out-of-scope assets, establish communication channels and notification thresholds.
2. **Execute Kill Chain** — Progress through recon, scan, enum, vuln, exploit, and post-exp phases with structured data handoff between each phase. Each phase has defined entry/exit criteria and required output artifacts.
3. **Evidence Collection** — Capture structured evidence at each phase with timestamps, checksums, and tool command documentation. All evidence files follow a consistent naming convention and directory structure.
4. **Cross-Phase Validation** — Verify findings from one phase inform the next. Reconnaissance results feed scanning targets, scan results drive enumeration focus, enumeration output identifies vulnerabilities for exploitation.
5. **Critical Finding Management** — When high-severity findings are confirmed, trigger notification protocol within agreed timeframe, document with full evidence chain, and coordinate emergency remediation.
6. **Report Generation** — Compile findings into standardized report with executive summary, technical findings, CVSS scores, remediation priorities, and evidence references.

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

- **Engagement indicators**: Defenders should receive advance notice of authorized testing windows and source IP ranges to distinguish legitimate tests from actual attacks. A well-defined notification process prevents unnecessary incident response mobilization during authorized testing.
- **Detection during testing**: Security teams should monitor for engagement artifacts — nmap scans, brute-force attempts, exploitation payloads — and verify these align with authorized testing schedules. This also tests the blue team's detection capabilities in real time.
- **Scope enforcement verification**: Blue teams should independently verify that testing stays within approved scope by monitoring network traffic and log entries for activity against out-of-scope systems. Scope violations by testers indicate either a process failure or a genuine attack masquerading as authorized testing.
- **Evidence handling**: Organizations should retain copies of all penetration test evidence for their own records and ensure the engagement team follows proper data handling procedures. Evidence should be encrypted at rest and securely destroyed after the retention period expires.
- **Post-engagement review**: After testing concludes, defenders should conduct a lessons-learned session to identify detection gaps, response time improvements, and architectural weaknesses revealed by the test. This review should produce actionable items with owners and deadlines.
- **Purple team coordination**: Engagement managers can structure purple team exercises where offensive actions are communicated to defenders in near-real-time, enabling calibration of detection rules and response procedures against actual attack techniques.
- **Remediation tracking**: Post-engagement, the findings report becomes a remediation backlog. Organizations should track remediation progress, re-test critical findings, and update security controls based on lessons learned.

## Phase Entry/Exit Criteria

| Phase | Entry Criteria | Exit Criteria | Required Artifacts |
|-------|---------------|---------------|-------------------|
| Recon | RoE reviewed, targets.json loaded | All in-scope assets enumerated | recon-results.json, attack-surface.md |
| Scan | Recon complete, target list validated | All ports/services identified | scan-results.xml, service-map.json |
| Enum | Scan complete, services catalogued | All enumerated users/shares/configs | enum-results.json, credential-stash.json |
| Vuln | Enum complete, attack surface mapped | All vulnerabilities classified | vuln-results.json, risk-matrix.md |
| Exploit | Vuln confirmed, PoC validated | Exploitation complete with evidence | exploit-evidence.json, screenshots/ |
| Post-Exp | Exploitation successful | Post-exploitation objectives met | post-exp-results.json, lateral-map.json |
| Report | All phases complete | Report reviewed and delivered | final-report.pdf, evidence-archive.tar.gz |

## Evidence Requirements

Every finding must include these evidence artifacts for the engagement report to meet professional standards:

| Evidence Type | Required For | Format | Naming Convention |
|---------------|-------------|--------|-------------------|
| Screenshot | All web findings | PNG with annotations | `F-NNN-description.png` |
| HTTP Request/Response | Web vulnerabilities | Raw text or HAR | `F-NNN-http-exchange.txt` |
| Tool Output | All automated findings | Raw with context | `F-NNN-tool-output.txt` |
| Console Log | Terminal-based findings | Copy of session output | `F-NNN-console.log` |
| Packet Capture | Network-level findings | PCAP with filter | `F-NNN-capture.pcap` |
| Video Recording | Multi-step exploits | MP4/GIF | `F-NNN-demo.mp4` |

## Engagement Timeline Template

```
Day 1: Kickoff, RoE review, recon phase (passive + active)
Day 2: Port scanning, service enumeration, vulnerability scanning
Day 3: Manual testing, exploitation of confirmed vulnerabilities
Day 4: Post-exploitation, lateral movement, privilege escalation
Day 5: Evidence consolidation, report drafting, quality assurance
Day 6: Report review, client walkthrough, remediation planning
```

Adjust timeline based on scope: single-target web app (2-3 days), multi-target enterprise (10-15 days), continuous assessment (ongoing).

## Communication Templates

| Trigger | Template | Recipient | Timeframe |
|---------|----------|-----------|-----------|
| Engagement kickoff | kickoff-notification.md | Client SOC, IT lead | 24h before start |
| Critical finding | critical-finding-alert.md | Client security team | Within 4 hours |
| Scope clarification | scope-change-request.md | Client sponsor | Before proceeding |
| Daily status | daily-status-update.md | Client stakeholders | End of business day |
| Engagement complete | wrap-up-notification.md | Client SOC, IT lead | Within 24h of completion |
| Report delivery | report-delivery-notice.md | Client sponsor, security team | Per contract schedule |

## Risk Assessment Matrix

| Risk Level | CVSS Range | Response Time | Client Notification |
|------------|-----------|---------------|-------------------|
| Critical | 9.0-10.0 | Immediate | Phone call within 2 hours |
| High | 7.0-8.9 | Within 24 hours | Email within 4 hours |
| Medium | 4.0-6.9 | Within engagement | Included in daily status |
| Low | 0.1-3.9 | In report | Included in final report |
| Informational | 0.0 | In report | Included in final report |

## Post-Engagement Checklist

- [ ] All evidence files organized and integrity-verified (SHA256 checksums)
- [ ] All findings have severity, CVSS score, PoC, impact, and remediation
- [ ] Critical findings were notified within agreed timeframe
- [ ] Scope boundaries verified — no unauthorized testing occurred
- [ ] Temporary files, credentials, and test data cleaned up
- [ ] Report follows template with executive summary and technical findings
- [ ] Raw tool outputs archived for re-test reference
- [ ] Client debrief scheduled for report walkthrough
- [ ] Remediation priorities communicated with timeline recommendations
- [ ] Engagement retrospective conducted — lessons learned documented

## Quality Criteria

- All phases produce structured evidence files with timestamps
- Data handoffs between phases are documented and verified
- Findings include severity, CVSS score, PoC, impact, and remediation
- Report follows standard penetration test template with all required sections
- Evidence chain is complete, timestamped, and integrity-verified with checksums
- Critical findings are notified within the agreed-upon timeframe
- Scope boundaries are enforced with zero violations
