# Engagement Manager — Test Cases

## TC-EM-001: Full Web Engagement Lifecycle

**Severity**: CRITICAL

**Objective**: Execute a complete web application penetration test engagement from scoping through report delivery, verifying all kill chain phases produce structured evidence.

**Prerequisites**: Target config file (targets.json) with web target defined. Engagement workspace initialized. All required tools available.

**Test Steps**:
1. Load target config and identify target type as "web"
2. Verify skill chain: recon-osint, network-pentest, web-xss, web-sqli, web-auth-bypass, post-exploitation
3. Execute reconnaissance phase: subdomain enumeration, technology fingerprinting, email harvesting
4. Execute scanning phase: full port scan, service identification, vulnerability scanning with nuclei
5. Execute enumeration phase: directory brute-forcing, API endpoint discovery, parameter discovery
6. Execute vulnerability discovery: SQL injection testing, XSS scanning, authentication testing
7. Execute exploitation: credential brute force, session hijacking, confirmed exploitation of found vulns
8. Execute post-exploitation: privilege escalation checks, lateral movement assessment
9. Generate final report with executive summary, technical findings, and remediation priorities

**Expected Result**: Complete evidence chain across all phases with timestamps. Structured report generated with accurate severity ratings. All findings include CVSS scores, proof of concept, impact, and remediation. Checkpoint.json reflects all phases complete.

**Remediation**: If a phase fails, use `--resume` to restart from the failed phase. Check tool availability and network connectivity. Review scope-rules.json for overly restrictive exclusions. Update skill chain if target type was misclassified.

**Pass Criteria**: All 6 kill chain phases complete with non-empty evidence files. Report contains executive summary, scope, methodology, findings table, and remediation sections. At least one finding documented with full required fields (ID, severity, CVSS, PoC, impact, remediation). Evidence checksums verify integrity.

---

## TC-EM-002: Cloud Target Skill Composition

**Severity**: HIGH

**Objective**: Verify correct skill activation and tool selection for cloud-type targets, including cloud-specific reconnaissance and vulnerability assessment.

**Prerequisites**: Target config with type "cloud". Cloud assessment tools installed (cloudlist, s3scanner, scoutSuite, cloudsploit, pacu, pmapper).

**Test Steps**:
1. Load cloud target config from targets.json
2. Verify activated skills include cloud-security, container-security, api-security, supply-chain-security
3. Verify recon phase uses cloud-specific tools (cloudlist, s3scanner, subfinder)
4. Verify enumeration phase includes cloud resource enumeration (scoutSuite, pmapper)
5. Verify vulnerability phase includes cloud-specific misconfiguration checks
6. Execute each phase and verify evidence capture in structured format
7. Verify data handoff between cloud-specific phases is correct

**Expected Result**: Cloud-specific skills and tools selected automatically based on target type. Evidence files generated for each phase with cloud-specific findings. No web-oriented tools incorrectly selected for pure cloud targets.

**Remediation**: If wrong skills are activated, review the Skill Composition mapping table in SKILL.md. If cloud tools are missing, install via pip or apt depending on the tool. Update tool-selector.sh cloud profile if tool recommendations are incorrect.

**Pass Criteria**: Skill composition matches the expected cloud skill chain. At least 3 cloud-specific tools executed. Evidence directory contains cloud-specific findings (S3 buckets, IAM policies, security groups). Report reflects cloud-specific attack surfaces.

---

## TC-EM-003: Engagement Resume After Interruption

**Severity**: HIGH

**Objective**: Verify checkpoint-based resume functionality works correctly, allowing an interrupted engagement to continue from the last completed phase without duplicating work.

**Prerequisites**: Partial engagement with checkpoint.json file showing phases 1-3 completed. All tools available.

**Test Steps**:
1. Start engagement with `bash validation/orchestrator.sh -t targets.json -o engagement/`
2. Complete phases 1 (recon), 2 (scan), 3 (enum) normally
3. Verify checkpoint.json updated after each phase: `cat engagement/state/checkpoint.json`
4. Simulate interruption (stop execution, close terminal)
5. Resume engagement: `bash validation/orchestrator.sh -t targets.json --resume`
6. Verify phases 1-3 are detected as completed from checkpoint.json
7. Verify execution continues from phase 4 (vuln) without re-running previous phases
8. Complete remaining phases and verify final report

**Expected Result**: No duplicate work performed on resumed phases. All phases eventually completed. Single complete report generated from combined evidence. Checkpoint.json accurately tracks progress throughout.

**Remediation**: If resume re-runs completed phases, check checkpoint.json for corruption or missing phase entries. If checkpoint is missing, manually create it based on existing evidence files. Use `--phase` flag to specify exact resume point.

**Pass Criteria**: Resumed engagement skips all completed phases (verified by timestamp analysis). No duplicate evidence files created for completed phases. Final report includes findings from all phases (pre and post interruption). Engagement completes successfully.

---

## TC-EM-004: Scope Boundary Enforcement

**Severity**: CRITICAL

**Objective**: Verify that out-of-scope targets are never tested, and that scope violations are detected, logged, and prevented during all engagement phases.

**Prerequisites**: Target config with scope definitions and exclusions list. Scope rules JSON with boundary definitions.

**Test Steps**:
1. Load config with scope: `["10.0.0.0/24"]` and exclusions: `["10.0.0.1", "10.0.0.100"]`
2. Execute reconnaissance phase against all scope targets
3. Verify excluded IPs are not present in any evidence file: `grep -r "10.0.0.1\|10.0.0.100" engagement/evidence/`
4. Execute scanning phase
5. Verify no scan traffic targets excluded IPs (check nmap output for excluded addresses)
6. Execute exploitation phase
7. Verify no exploitation attempts against excluded targets
8. Check engagement logs for scope violation warnings: `grep -i "scope" engagement/logs/*.log`
9. Attempt to manually add an out-of-scope target and verify it is rejected

**Expected Result**: Excluded targets completely untouched. No evidence files contain data about excluded targets. Scope violations logged as warnings if attempted. Engagement completes successfully within approved scope.

**Remediation**: If scope violations occur, immediately stop the engagement and document the violation. Review scope-rules.json for correctness. Update the orchestrator scope enforcement logic. Notify the client of any accidental scope contact per the rules of engagement.

**Pass Criteria**: Zero evidence files contain references to excluded targets. Scope violation detection triggers warnings for manual out-of-scope attempts. All completed phases tested only approved targets. Scope verification log contains no critical violations.

---

## TC-EM-005: Critical Finding Notification Protocol

**Severity**: CRITICAL

**Objective**: Verify critical findings trigger the immediate notification protocol within 4 hours, and that all documentation requirements are met.

**Prerequisites**: Engagement in progress with at least scan and enumeration phases completed. Notification protocol defined in rules of engagement.

**Test Steps**:
1. Execute vulnerability discovery phase against target
2. Simulate critical finding (e.g., unauthenticated RCE, SQL injection with database access)
3. Verify finding is logged with severity CRITICAL in evidence file
4. Verify finding contains all required fields: ID, severity, CVSS, PoC, impact, remediation, timestamp
5. Verify notification flag is set in engagement state: `cat engagement/state/checkpoint.json`
6. Generate critical finding notification document
7. Verify notification document is timestamped and contains client-facing summary
8. Verify report highlights critical finding in executive summary with appropriate prominence

**Expected Result**: Critical finding documented with all required fields. Notification generated and timestamped within 4-hour window. Engagement state reflects critical finding count. Report executive summary prominently features critical finding.

**Remediation**: If notification is not generated automatically, manually create the critical notification template and send to client contact. Review the notification trigger logic in the orchestrator. Update engagement state to reflect the critical finding. Ensure all team members are aware of the critical finding.

**Pass Criteria**: Critical finding logged with complete documentation (all 9 required fields). Notification generated within 4 hours of discovery. Notification document includes client-facing summary and immediate recommendations. Engagement state shows critical_findings count updated. Report executive summary references critical finding.

---

## TC-EM-006: Multi-Target Engagement Coordination

**Severity**: HIGH

**Objective**: Manage engagement with multiple targets of different types (web + network), verifying separate evidence chains and unified reporting.

**Prerequisites**: Target config with both web and network targets defined. Separate skill chains for each target type.

**Test Steps**:
1. Load multi-target configuration from targets_multi.json
2. Verify separate evidence directories created per target: `ls engagement/evidence/`
3. Execute web attack chain for web targets (web skill composition)
4. Execute network attack chain for network targets (network skill composition)
5. Verify evidence isolation — no cross-contamination between target evidence
6. Verify data handoffs work independently for each target chain
7. Generate unified report covering all targets
8. Verify report separates findings by target with per-target severity summaries

**Expected Result**: Separate evidence chains per target with no cross-contamination. Each target uses appropriate skill composition. Unified final report includes all targets with clear separation. Per-target findings tables with individual severity counts.

**Remediation**: If evidence directories are not separated, manually create target-specific subdirectories and reorganize evidence. If skill composition is wrong for a target, manually specify the correct skill chain using the Skill Composition table. Update targets.json to include explicit target types.

**Pass Criteria**: Each target has its own evidence subdirectory with non-empty files. Skill chains match target types correctly. Unified report contains findings from all targets. Report includes per-target finding counts and severity breakdowns. No evidence cross-contamination between targets.

---

## TC-EM-007: Evidence Chain Integrity Verification

**Severity**: HIGH

**Objective**: Verify evidence files maintain proper timestamps, cross-references, and integrity checksums throughout the engagement lifecycle.

**Prerequisites**: Engagement in progress with at least 2 completed phases. Evidence files in engagement/evidence/ directory.

**Test Steps**:
1. Check evidence files in engagement/evidence/ for proper directory structure
2. Verify each evidence file has timestamp metadata or creation date
3. Verify data handoff files exist between phases (recon output feeds into scan input)
4. Verify no evidence files are empty: `find engagement/evidence/ -type f -empty`
5. Generate evidence checksums: `cd engagement/evidence && find . -type f -exec sha256sum {} \; > ../state/checksums.txt`
6. Verify checkpoint.json tracks completed phases with timestamps
7. Simulate evidence modification and verify integrity check detects the change
8. Verify finding documents reference correct evidence file paths

**Expected Result**: Complete evidence chain with timestamps and cross-references. All data handoff files present and non-empty. Checksums verify evidence integrity. Any modification to evidence files is detectable.

**Remediation**: If evidence files are missing timestamps, reconstruct from file creation dates using `stat` command. If handoff files are missing, regenerate from phase evidence. If checksum verification fails, investigate whether evidence was accidentally modified or corrupted. Never modify raw evidence — create corrected copies.

**Pass Criteria**: All evidence files have timestamps (file creation or embedded metadata). Data handoff files exist between all consecutive phases. No empty evidence files. SHA-256 checksums generated for all evidence. Integrity check passes for unmodified evidence. Integrity check detects any modification.

---

## TC-EM-008: Report Generation from Evidence

**Severity**: MEDIUM

**Objective**: Generate accurate, complete penetration test report from collected evidence, verifying all required sections and finding accuracy.

**Prerequisites**: Completed engagement with evidence files across all phases. Report generator script available.

**Test Steps**:
1. Run report generator: `bash validation/report-generator.sh -s engagement/ -o engagement/reports/final_report.md`
2. Verify report contains executive summary section
3. Verify findings table matches evidence files (count and severity)
4. Verify severity counts are accurate by cross-checking with evidence directory
5. Verify report includes scope section matching the approved scope document
6. Verify report includes methodology section listing tools and phases executed
7. Verify report includes remediation priorities organized by severity
8. Generate HTML format and verify rendering: `--format html`
9. Generate JSON format and validate structure: `--format json | python3 -m json.tool`

**Expected Result**: Complete report reflecting all findings from evidence. All required sections present. Severity counts match evidence. Multiple output formats valid and renderable.

**Remediation**: If report is missing sections, check that evidence files follow the expected naming convention. If finding counts are wrong, verify evidence files have proper severity field formatting. If HTML rendering fails, check markdown-to-HTML converter and CSS template. If JSON is invalid, check for special characters in finding descriptions.

**Pass Criteria**: Report contains all required sections (executive summary, scope, methodology, findings, remediation). Finding count matches evidence file count. Severity distribution is accurate. HTML report renders correctly in a browser. JSON output validates without errors. No placeholder text remains in the report.

---

## TC-EM-009: Engagement Quality Assurance Review

**Severity**: MEDIUM

**Objective**: Perform comprehensive quality assurance review of a completed engagement, verifying evidence completeness, finding quality, scope compliance, and report accuracy.

**Prerequisites**: Completed engagement with all phases finished and report generated.

**Test Steps**:
1. Run evidence validation: check all evidence files are non-empty and properly named
2. Run findings quality check: verify every finding has all 9 required fields (ID, severity, CVSS, asset, phase, status, PoC, impact, remediation)
3. Run scope compliance check: verify no out-of-scope targets appear in any evidence file
4. Run report quality check: verify all required sections exist and contain substantive content
5. Verify evidence timestamps are in chronological order across phases
6. Verify no placeholder text remains in report: `grep -n "\[.*\]" report.md`
7. Verify evidence checksums are consistent with original generation
8. Run drift detection: `bash validation/drift-detect.sh`

**Expected Result**: All evidence files valid and complete. All findings have required fields. No scope violations. Report passes all quality checks. No placeholders or incomplete sections.

**Remediation**: If evidence files are missing or empty, document the gap and attempt recovery from logs. If findings are incomplete, supplement with additional analysis. If scope violations are found, document and notify client per rules of engagement. If report has placeholders, complete them before delivery.

**Pass Criteria**: 100% of evidence files pass validation. 100% of findings have all required fields. Zero scope violations detected. Report has zero placeholder text. Evidence checksums match original values. Drift detection shows no configuration changes. QA review documented and archived.
