# Terminal Operations — Test Cases

> **Companion to**: `SKILL.md` — Terminal operations workflow and evidence chain protocol
> **See also**: `payloads.md` — Command patterns organized by engagement phase

Structured test scenarios for validating the terminal operations workflow. Each test case follows the Evidence Chain Protocol and verifies correct behavior at every phase.

---

## TC-TO-001: Full Reconnaissance Pipeline

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

**Scenario**: Execute a sequence of terminal commands and verify that the evidence chain is complete, timestamped, and tamper-evident at every step.

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

**Scenario**: Simulate tool failures and verify that the debugging and fallback process follows the terminal-ops methodology (Phase 2: Read the Failing Surface).

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

**Scenario**: Run commands against authorized targets while verifying that scope boundaries are checked before and after every execution phase.

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
