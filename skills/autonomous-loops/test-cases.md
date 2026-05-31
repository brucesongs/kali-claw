# Autonomous Loops — Test Cases

> Structured test scenarios for validating autonomous loop patterns. Each test case covers a specific loop pattern, its safety mechanisms, and expected behavior under normal and failure conditions. Companion to `SKILL.md` and `payloads.md`.

---

## Index

- [TC-AL-001: Sequential Pipeline — Subnet Port Scan](#tc-al-001-sequential-pipeline--subnet-port-scan)
- [TC-AL-002: Watch Loop — Service Monitor](#tc-al-002-watch-loop--service-monitor)
- [TC-AL-003: Batch Processing — Mass Vulnerability Scan](#tc-al-003-batch-processing--mass-vulnerability-scan)
- [TC-AL-004: Learning Cycle — Adaptive SQL Injection](#tc-al-004-learning-cycle--adaptive-sql-injection)
- [TC-AL-005: Scope Violation Detection](#tc-al-005-scope-violation-detection)
- [TC-AL-006: Rate Limit Backoff](#tc-al-006-rate-limit-backoff)
- [TC-AL-007: Adaptive Payload Mutation Loop](#tc-al-007-adaptive-payload-mutation-loop)
- [TC-AL-008: Distributed Credential Testing Loop](#tc-al-008-distributed-credential-testing-loop)
- [TC-AL-009: Network Service Fingerprinting Loop](#tc-al-009-network-service-fingerprinting-loop)
- [TC-AL-010: Evidence Collection Watchdog Loop](#tc-al-010-evidence-collection-watchdog-loop)

---

## TC-AL-001: Sequential Pipeline — Subnet Port Scan

### Scenario

A penetration tester needs to enumerate open ports across an authorized /24 subnet (192.168.1.0/24). The operation must proceed sequentially — one host at a time — with scope lock enforcement, rate limiting, and complete evidence logging.

**Severity**: HIGH

**Objective**: Validate that the Sequential Pipeline pattern correctly enumerates hosts one-at-a-time with scope lock enforcement, rate limiting between hosts, and complete evidence logging for every iteration.

**Remediation**: If scope validation fails for any host, ensure the pipeline logs the violation and skips the host without halting. If rate limiting gaps are observed, increase the inter-host delay. If evidence files are missing for any scanned host, verify the output directory permissions and disk space.

**Pass Criteria**:
- [ ] All hosts outside 192.168.1.0/24 are skipped and logged as scope violations
- [ ] Only one host is scanned at any given time (no concurrent execution)
- [ ] Minimum 2-second gap observed between consecutive host scans
- [ ] Every host scan produces a logged evidence entry with timestamp, target, result, and output path
- [ ] Unreachable hosts are logged and skipped without halting the pipeline
- [ ] Operation stops at 120 minutes even if targets remain

### Pre-conditions

1. Scope lock is defined: allowed targets = 192.168.1.0/24, allowed operations = nmap SYN scan + banner grab
2. Target subnet is reachable from the testing machine
3. Evidence output directory exists and is writable
4. nmap is installed and available in PATH
5. Operator has been notified of operation start

### Test Steps

1. Define scope lock with operation ID, target range, allowed operations, time limit (120 min), and abort conditions
2. Initialize evidence log with operation header (pattern, scope, start time)
3. Execute host discovery: `nmap -sn 192.168.1.0/24` to build target list
4. Validate each discovered host against scope lock CIDR range
5. For each in-scope host, execute: `nmap -sV -T4 -p- --version-intensity 5` with output saved to evidence directory
6. Apply 2-second rate limit delay between hosts
7. Log iteration-level evidence entry (target, action, result, duration) after each host
8. On target unreachable: log error, skip host, continue to next
9. On completion: write operation summary (total hosts, findings, errors, duration)

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Scope enforcement | All hosts outside 192.168.1.0/24 are skipped and logged |
| Sequential execution | Only one host is scanned at any given time |
| Rate limiting | Minimum 2-second gap between consecutive host scans |
| Evidence logging | Every host scan produces a logged entry with timestamp, target, result, and output path |
| Error handling | Unreachable hosts are logged and skipped; pipeline does not stop |
| Completion | Operation summary includes total scanned, skipped, errored, and duration |
| Time limit | Operation stops at 120 minutes even if targets remain |

### Post-conditions

- Evidence directory contains one file per scanned host
- Pipeline log file exists with all iteration entries
- No out-of-scope hosts were scanned
- Operator received start, progress (every 50 hosts), and completion notifications

---

## TC-AL-002: Watch Loop — Service Monitor

### Scenario

A penetration tester needs to monitor a target server (192.168.1.100) for service state changes across ports 22, 80, 443, 3306, and 8080. The watch loop must detect when services go up or down, log all observations, and alert on state changes.

**Severity**: MEDIUM

**Objective**: Validate that the Watch Loop pattern correctly captures baseline port states, detects state changes within one polling cycle, logs all observations, and alerts the operator on every trigger event.

**Remediation**: If false positives are observed, increase the polling interval or add a confirmation check (two consecutive state changes before alerting). If state changes are missed, verify the TCP connect timeout is shorter than the polling interval. If observation logs grow too large, implement log rotation after a configurable size threshold.

**Pass Criteria**:
- [ ] Initial state of all 5 ports recorded as baseline before monitoring starts
- [ ] Minimum 5 seconds between observation cycles
- [ ] Any port state change detected within 1 polling cycle
- [ ] Every cycle logged, even when no changes detected
- [ ] Loop stops after 720 iterations (approximately 1 hour)
- [ ] No false positive state changes when services remain constant

### Pre-conditions

1. Scope lock is defined: allowed targets = 192.168.1.100 on specified ports, allowed operations = TCP connect + HTTP HEAD
2. Target is reachable at the start of monitoring
3. Baseline port states have been captured
4. Polling interval set to 5 seconds
5. Maximum iterations set to 720 (1 hour of monitoring)

### Test Steps

1. Define scope lock with operation ID, target, ports, polling interval (5s), and max iterations (720)
2. Capture baseline: check each port and record initial state (open/closed)
3. Save baseline to evidence file
4. Begin watch loop iteration 1 through max:
   a. For each monitored port, perform TCP connect check with 3-second timeout
   b. Compare current state to baseline state
   c. If state changed: log trigger event, update baseline, notify operator
   d. Log observation cycle (even when no change detected)
   e. Wait polling interval (5 seconds)
5. On max iterations reached: log completion, write operation summary

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Baseline capture | Initial state of all 5 ports recorded before monitoring starts |
| Polling interval | Minimum 5 seconds between observation cycles, never less |
| Change detection | Any port state change (open to closed or closed to open) is detected within 1 polling cycle |
| Trigger logging | Trigger events include timestamp, port, previous state, new state |
| Observation logging | Every cycle is logged, even when no changes detected |
| Iteration limit | Loop stops after 720 iterations (approximately 1 hour) |
| False positive rate | No state changes reported when service states remain constant |

### Post-conditions

- Evidence log contains all observation entries
- Any state changes have corresponding trigger event entries
- Baseline file reflects the most recent known state
- Operator was notified of every trigger event

---

## TC-AL-003: Batch Processing — Mass Vulnerability Scan

### Scenario

A penetration tester needs to run vulnerability scans across 50 pre-authorized hosts. The batch processing pattern must execute with controlled concurrency (max 5 simultaneous), rate limiting between batches, and comprehensive result logging.

**Severity**: HIGH

**Objective**: Validate that the Batch Processing pattern correctly manages concurrency (max 5 simultaneous scans), enforces batch delays, isolates individual target failures, and produces comprehensive per-target and aggregate evidence.

**Remediation**: If concurrency exceeds the configured maximum, verify the batch splitting logic groups targets correctly. If batch delays are inconsistent, check for race conditions in the batch completion detection. If a single target failure crashes the entire batch, ensure error isolation wraps each target scan in an individual try-catch block.

**Pass Criteria**:
- [ ] Never more than 5 simultaneous scan operations at any point
- [ ] Minimum 3-second gap between batch completions and next batch start
- [ ] All IPs verified against authorized range before scanning begins
- [ ] A single target failure does not prevent other targets in the same batch from completing
- [ ] Operator notified after every 10 hosts completed
- [ ] Each target produces a separate evidence file; batch summary exists for each batch

### Pre-conditions

1. Scope lock is defined: allowed targets = targets.txt (50 verified hosts), allowed operations = nmap vuln scripts + nikto
2. Target list file exists with exactly 50 valid IP addresses
3. All targets have been pre-verified as in-scope
4. Evidence output directory exists
5. nmap and nikto are installed and operational

### Test Steps

1. Define scope lock with operation ID, target file reference, concurrency (5), and batch delay (3s)
2. Validate target list: confirm all IPs are within authorized scope
3. Split targets into batches of 5
4. For each batch:
   a. Launch 5 parallel nmap vuln scans
   b. Wait for all batch scans to complete
   c. Log results for each target in batch (status, findings, duration)
   d. Apply 3-second delay before next batch
   e. Notify operator every 10 hosts completed
5. On individual target error: log error, continue with remaining targets in batch
6. On batch completion: aggregate results, write operation summary

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Concurrency | Never more than 5 simultaneous scan operations |
| Batch delay | Minimum 3-second gap between batch completions and next batch start |
| Scope validation | All IPs verified against authorized range before scanning |
| Error isolation | A single target failure does not prevent other targets in the same batch from completing |
| Progress tracking | Operator notified after every 10 hosts (at 10, 20, 30, 40, 50) |
| Evidence | Each target produces a separate evidence file; batch summary exists for each batch |
| Total time | 50 hosts / 5 per batch = 10 batches; at 3s batch delay, overhead is approximately 30s minimum |

### Post-conditions

- Evidence directory contains 50 individual target result files
- Batch processing log shows all 10 batches completed
- Aggregate vulnerability summary identifies all findings across targets
- No target was scanned outside the authorized scope

---

## TC-AL-004: Learning Cycle — Adaptive SQL Injection

### Scenario

A penetration tester is testing a web application's search parameter for SQL injection vulnerabilities. The learning cycle must iteratively refine SQLi payloads based on server responses, with confidence tracking and WAF detection.

**Severity**: CRITICAL

**Objective**: Validate that the Learning Cycle pattern correctly refines payloads based on server response analysis, tracks confidence levels per iteration, detects WAF interference, and aborts when confidence drops below the configured threshold.

**Remediation**: If the learning cycle fails to converge on a successful payload, increase the maximum iteration count or broaden the initial payload diversity. If WAF detection triggers false aborts, refine the detection rules to distinguish between rate limiting (HTTP 429) and true WAF blocking (HTTP 403 with specific headers). If confidence tracking is inaccurate, recalibrate the confidence scoring weights for each response indicator.

**Pass Criteria**:
- [ ] Each refinement cycle produces payloads informed by previous response analysis
- [ ] Confidence percentage logged at every iteration
- [ ] Loop aborts immediately on HTTP 403, 429, or connection reset (WAF detection)
- [ ] Target URL never changes — only payloads are refined
- [ ] Loop stops at 50 iterations maximum
- [ ] Loop stops if confidence drops below 10% after 10 attempts
- [ ] Every payload attempt and response logged with analysis

### Pre-conditions

1. Scope lock is defined: allowed target = single URL endpoint, allowed operations = HTTP GET/POST with SQLi payloads
2. Target web application is accessible and responsive
3. Base payload list is prepared (initial SQLi payloads)
4. Maximum iterations set to 50
5. Confidence threshold set to 10% (abort if below after 10 attempts)
6. WAF detection rules defined (HTTP 403, 429, or connection reset)

### Test Steps

1. Define scope lock with operation ID, single target URL, max iterations (50), abort conditions
2. Initialize evidence log and confidence tracker
3. Execute base payload list:
   a. Send payload via HTTP request to target
   b. Record response: HTTP status code, body length, error messages
   c. Analyze response for SQL error indicators (syntax error, database name, column count)
   d. Log iteration evidence: payload, response, analysis, confidence level
   e. Check WAF detection rules — if triggered, ABORT immediately
4. If base payloads yield partial results, refine:
   a. Based on response analysis, generate refined payloads (e.g., UNION-based if error-based shows column count)
   b. Continue with refined payloads up to iteration limit
5. On confidence below 10% after 10 iterations: log abort reason, stop learning cycle
6. On success (injection confirmed): log successful payload, stop cycle
7. Write operation summary with confidence curve and findings

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Payload refinement | Each refinement cycle produces payloads informed by previous response analysis |
| Confidence tracking | Confidence percentage logged at every iteration |
| WAF detection | Loop aborts immediately on HTTP 403, 429, or connection reset |
| Scope containment | Target URL never changes — only payloads are refined |
| Iteration limit | Loop stops at 50 iterations maximum |
| Confidence abort | Loop stops if confidence drops below 10% after 10 attempts |
| Evidence trail | Every payload attempt and response logged with analysis |

### Post-conditions

- Evidence log contains entries for every iteration with payload, response, and analysis
- If SQL injection found: successful payload documented with reproduction steps
- If aborted: abort reason clearly logged (WAF, confidence, max iterations)
- No payloads were sent to endpoints outside the scope lock

---

## TC-AL-005: Scope Violation Detection

### Scenario

Negative test case. Verify that scope lock enforcement correctly catches and blocks attempts to operate outside defined boundaries. The loop must detect scope violations and stop immediately without executing any out-of-scope operations.

**Severity**: CRITICAL

**Objective**: Validate that scope lock enforcement correctly rejects out-of-scope targets before any operation executes, logs all violation attempts, and continues processing in-scope targets without interruption.

**Remediation**: If scope violations slip through, tighten the CIDR validation logic to handle edge cases (e.g., broadcast addresses, network addresses). If the pipeline halts on scope violations instead of continuing, restructure the scope check to skip-and-log rather than abort. Ensure scope validation occurs before any network traffic is generated.

**Pass Criteria**:
- [ ] In-scope target (192.168.1.100) is scanned successfully
- [ ] Out-of-scope targets (192.168.2.1 and 10.0.0.1) are blocked before any operation
- [ ] Each scope violation is logged with target, reason, and timestamp
- [ ] No network traffic is sent to out-of-scope targets
- [ ] Pipeline continues processing remaining in-scope targets after violations
- [ ] Evidence log clearly distinguishes executed vs. blocked targets

### Pre-conditions

1. Scope lock is defined: allowed targets = 192.168.1.100 only, allowed operations = port scan only
2. Target list intentionally contains out-of-scope addresses (192.168.2.0/24, 10.0.0.1)
3. Loop is configured as Sequential Pipeline with scope validation enabled
4. Evidence logging is active

### Test Steps

1. Define restrictive scope lock: single host 192.168.1.100, port scan only
2. Begin Sequential Pipeline with mixed target list (in-scope + out-of-scope)
3. Process first target (192.168.1.100 — in scope):
   a. Verify scope check passes
   b. Execute scan, log results
4. Process second target (192.168.2.1 — out of scope):
   a. Verify scope check FAILS
   b. Log scope violation attempt
   c. Skip target (do NOT execute any operation)
5. Process third target (10.0.0.1 — out of scope):
   a. Verify scope check FAILS
   b. Log scope violation attempt
   c. Skip target
6. Verify evidence log shows all violations logged
7. Verify no out-of-scope operation was actually executed

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| In-scope execution | 192.168.1.100 is scanned successfully |
| Out-of-scope blocking | 192.168.2.1 and 10.0.0.1 are blocked before any operation |
| Violation logging | Each scope violation is logged with target, reason, and timestamp |
| No phantom operations | No network traffic is sent to out-of-scope targets |
| Pipeline continuation | Pipeline continues processing remaining in-scope targets after violations |
| Evidence integrity | Evidence log clearly distinguishes executed vs. blocked targets |

### Post-conditions

- Evidence log shows exactly 1 successful scan and 2 scope violation entries
- No evidence of any network operation against 192.168.2.1 or 10.0.0.1
- Operator was notified of scope violation attempts

---

## TC-AL-006: Rate Limit Backoff

### Scenario

Verify that rate limiting and backoff behavior work correctly when a target indicates throttling (HTTP 429). The loop must increase delays, retry once, and stop if the target continues to throttle.

**Severity**: HIGH

**Objective**: Validate that the exponential backoff mechanism correctly increases delays on HTTP 429 responses, retries exactly once per rate limit event, respects the maximum delay cap, and does not aggressively hammer a throttled target.

**Remediation**: If backoff delays exceed the configured maximum, verify the cap logic applies `min(current_delay * multiplier, max_delay)`. If more than one retry occurs per rate limit event, audit the retry counter increment logic. If the delay does not reset after a successful retry, ensure the reset action is triggered on HTTP 200 responses.

**Pass Criteria**:
- [ ] HTTP 429 triggers delay increase from 2s to 4s (exponential backoff)
- [ ] Exactly one retry attempt after rate limit detection
- [ ] If retry returns 200, delay resets to base 2s
- [ ] If retry returns 429, target is marked rate-limited with no further attempts
- [ ] Backoff delay never exceeds 60 seconds
- [ ] Every rate limit event and backoff action is logged
- [ ] Never sends more than 1 retry after a rate limit event

### Pre-conditions

1. Scope lock is defined for a single web target
2. Target is configured to return HTTP 429 after sustained requests (simulated)
3. Base delay is set to 2 seconds, backoff multiplier is 2x, max delay is 60 seconds
4. Learning Cycle or Batch Processing pattern configured
5. Maximum retries on rate limit: 1

### Test Steps

1. Configure rate limit parameters: base_delay=2s, multiplier=2x, max_delay=60s, max_retries=1
2. Begin loop executing HTTP requests to target
3. On normal responses (HTTP 200): continue at base rate, log iteration
4. On first HTTP 429 response:
   a. Log rate limit detection with current delay
   b. Apply backoff: delay = current_delay * multiplier (2s to 4s)
   c. Retry ONCE with new delay
5. If retry succeeds (HTTP 200): reset delay to base, continue loop
6. If retry also returns HTTP 429:
   a. Log persistent rate limit
   b. Mark target as rate-limited
   c. Do NOT retry again
   d. Continue to next target or abort if single-target operation
7. Verify backoff curve: 2s to 4s to 8s to 16s to 32s to 60s (capped)
8. Verify max delay cap is respected (never exceeds 60s)

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Backoff activation | HTTP 429 triggers delay increase from 2s to 4s |
| Single retry | Exactly one retry attempt after rate limit detection |
| Retry success | If retry returns 200, delay resets to base 2s |
| Retry failure | If retry returns 429, target is marked rate-limited, no further attempts |
| Delay cap | Backoff delay never exceeds 60 seconds |
| Logging | Every rate limit event and backoff action is logged |
| No aggressive retry | Never sends more than 1 retry after a rate limit event |

### Post-conditions

- Evidence log contains rate limit detection entries with delay progression
- Backoff curve is documented: 2s, 4s, 8s, etc. up to 60s cap
- No more than 1 retry was attempted per rate limit event
- Target was not aggressively hammered after throttling began

---

## TC-AL-007: Adaptive Payload Mutation Loop

### Scenario

A penetration tester is testing a web application's file upload endpoint for bypass opportunities. The adaptive mutation loop must generate, submit, and evaluate payload variations based on server response patterns, iteratively refining the approach.

**Severity**: HIGH

**Objective**: Validate that the adaptive payload mutation loop correctly generates payload variations, evaluates server responses to determine success or filtering, and refines subsequent payloads based on accumulated response intelligence.

**Remediation**: If the mutation loop exhausts all variations without success, expand the mutation dictionary with additional encoding techniques. If the loop generates too many requests too quickly, add a minimum inter-request delay. If WAF detection triggers, switch to a lower-noise mutation strategy.

**Pass Criteria**:
- [ ] Each mutation cycle produces payloads derived from previous response analysis
- [ ] Server response pattern tracked across all iterations (blocked, filtered, accepted, error)
- [ ] WAF or filter fingerprinting documented based on response differences
- [ ] Loop stops at maximum iterations or on successful bypass
- [ ] Every payload and response logged with mutation generation number

### Pre-conditions

1. Scope lock is defined: allowed target = file upload endpoint, allowed operations = HTTP POST with multipart payloads
2. Target upload endpoint is accessible and responsive
3. Base payload list prepared (file extension variations, content-type variations)
4. Maximum iterations set to 100
5. Response pattern database initialized (empty)

### Test Steps

1. Define scope lock with operation ID, target endpoint, max iterations (100), abort conditions
2. Initialize mutation engine with base payloads and response database
3. Execute base payload list:
   a. Submit payload via HTTP POST to upload endpoint
   b. Record response: HTTP status, body content, headers, response time
   c. Classify response: accepted, blocked, filtered, error, unexpected
   d. Store response pattern in database
4. Generate mutations based on response analysis:
   a. If extension blocked: try double extensions (.php.jpg), null bytes (.php%00.jpg)
   b. If content-type filtered: try multipart boundary manipulation
   c. If magic bytes checked: prepend valid file header to payload
   d. If filename sanitized: try path traversal in filename (../../../shell.php)
5. On successful upload: verify file is accessible and executable, stop loop
6. On max iterations: write mutation report with all attempted payloads and response patterns
7. On WAF detection (HTTP 403/429): log and reduce request rate or abort

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Mutation intelligence | Each generation uses data from all previous responses |
| Response classification | All responses categorized (accepted/blocked/filtered/error) |
| WAF fingerprint | Filter behavior documented from response pattern analysis |
| Iteration limit | Loop stops at 100 iterations maximum |
| Evidence | Every payload attempt, response, and mutation generation logged |
| Success detection | Successful upload verified with file accessibility check |

### Post-conditions

- Evidence log contains all payload submissions with response data
- Mutation generation report shows evolutionary path from base to final payloads
- If successful: bypass payload documented with full reproduction steps
- If unsuccessful: filter capabilities fully documented for engagement report

---

## TC-AL-008: Distributed Credential Testing Loop

### Scenario

A penetration tester needs to test a list of credential pairs against an SSH service. The loop must distribute work across multiple parallel workers with global rate limiting, credential-level tracking, and immediate stop on successful authentication.

**Severity**: CRITICAL

**Objective**: Validate that the distributed credential testing loop correctly manages parallel workers, enforces global rate limits across all workers, tracks each credential pair's result, and stops immediately upon finding valid credentials.

**Remediation**: If rate limiting is uneven across workers, implement a shared rate limiter with a global counter. If workers continue testing after valid credentials are found, add a shared stop flag that all workers check before each attempt. If evidence is incomplete for any worker, ensure each worker writes to its own log file before aggregation.

**Pass Criteria**:
- [ ] Maximum 3 parallel workers active at any time
- [ ] Global rate limit of 1 attempt per 2 seconds across all workers
- [ ] Each credential pair tested exactly once (no duplication)
- [ ] Loop stops within 5 seconds of finding valid credentials
- [ ] All workers write to individual log files before aggregation

### Pre-conditions

1. Scope lock is defined: allowed target = single SSH server, allowed operations = SSH authentication attempts
2. Credential list prepared and validated (format: username:password)
3. SSH service is reachable and responsive
4. Maximum workers set to 3
5. Global rate limit set to 1 attempt per 2 seconds
6. Evidence output directory exists

### Test Steps

1. Define scope lock with operation ID, target SSH server, max workers (3), rate limit (1/2s)
2. Load credential list and validate format
3. Split credentials across 3 workers (round-robin distribution)
4. Initialize shared rate limiter with global counter
5. Begin distributed testing:
   a. Each worker checks shared stop flag before each attempt
   b. Worker acquires rate limit token (wait if needed)
   c. Worker attempts SSH connection with credential pair
   d. Result logged: success/failure/timeout/error
   e. On success: set shared stop flag, log valid credentials, notify operator
   f. On failure: release credential, continue to next
6. On stop flag set: all workers finish current attempt and terminate
7. Aggregate worker logs into single evidence file
8. Write operation summary (total tested, valid found, duration)

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Parallel execution | Exactly 3 workers running simultaneously |
| Global rate limit | No more than 1 attempt per 2-second window across all workers |
| Credential tracking | Each pair tested exactly once, no duplicates |
| Immediate stop | All workers terminate within 5 seconds of valid credential discovery |
| Evidence | Per-worker logs aggregated into complete evidence file |
| Notification | Operator notified immediately on valid credential discovery |

### Post-conditions

- Evidence log contains every credential attempt with result
- Valid credentials (if found) highlighted in operation summary
- No credential pair was tested more than once
- All workers terminated cleanly (no orphan processes)

---

## TC-AL-009: Network Service Fingerprinting Loop

### Scenario

A penetration tester needs to fingerprint all discovered services across a /24 subnet. The loop must enumerate each host, probe each open port with multiple fingerprinting tools, and aggregate results with confidence scoring.

**Severity**: MEDIUM

**Objective**: Validate that the network service fingerprinting loop correctly enumerates hosts, probes each service with multiple tools, aggregates results with confidence scoring, and produces a comprehensive service inventory.

**Remediation**: If fingerprinting results are inconsistent across tools, use the majority consensus and flag disagreements for manual review. If specific ports are not responding to probes, try alternative probe types (TCP NULL, FIN, Xmas scans). If confidence scores are below 50%, schedule targeted manual analysis for those services.

**Pass Criteria**:
- [ ] All live hosts enumerated before service probing begins
- [ ] Each open port probed with at least 2 fingerprinting methods
- [ ] Confidence score calculated for each service identification
- [ ] Aggregated service inventory produced with no duplicates
- [ ] Total loop time within 2x estimated minimum

### Pre-conditions

1. Scope lock is defined: allowed targets = authorized /24 subnet, allowed operations = port scan + service probe
2. Target subnet is reachable
3. nmap, whatweb, and nikto installed and available
4. Previous host discovery results available (live hosts list)
5. Maximum concurrent probes set to 5

### Test Steps

1. Define scope lock with operation ID, target subnet, max concurrent probes (5)
2. Load live hosts list from previous discovery phase
3. For each live host:
   a. Run nmap service version detection (-sV) on all open ports
   b. For HTTP/HTTPS ports: run whatweb fingerprinting
   c. For HTTP/HTTPS ports: run nikto scan on top 5 hosts only
   d. Aggregate all fingerprint results per port
   e. Calculate confidence score based on tool agreement
4. Merge results across all hosts into service inventory
5. Sort by confidence (high to low) and flag low-confidence entries
6. Write service inventory to evidence directory

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Host coverage | All live hosts from discovery list processed |
| Fingerprinting depth | At least 2 methods per port (nmap + tool-specific) |
| Confidence scoring | Score calculated for every identified service |
| Inventory quality | No duplicate entries, sorted by confidence |
| Evidence | Complete service inventory exported to evidence directory |
| Performance | Loop completes within 2x estimated minimum time |

### Post-conditions

- Service inventory contains all identified services with confidence scores
- Low-confidence entries flagged for manual review
- Evidence directory contains per-host results and aggregated inventory
- No out-of-scope hosts were probed

---

## TC-AL-010: Evidence Collection Watchdog Loop

### Scenario

A long-running engagement requires continuous monitoring of evidence collection to ensure no evidence files are modified, deleted, or corrupted during the engagement. The watchdog loop must periodically verify evidence integrity.

**Severity**: HIGH

**Objective**: Validate that the evidence collection watchdog loop correctly monitors all evidence files, detects any modification or deletion, alerts the operator immediately on integrity violations, and maintains a tamper-evident audit trail.

**Remediation**: If integrity violations are detected, immediately investigate the cause (disk corruption, accidental overwrite, or malicious tampering). Restore files from backup if available. If no backup exists, document the loss and its impact on the engagement. Implement GPG-signed evidence chains for future engagements.

**Pass Criteria**:
- [ ] Baseline hashes captured for all evidence files at loop start
- [ ] Integrity check runs every 60 seconds (configurable)
- [ ] Any file modification detected within one check cycle
- [ ] Operator alerted immediately on integrity violation
- [ ] Audit trail of all checks logged with timestamps and results

### Pre-conditions

1. Evidence directory populated with at least 10 files from prior engagement phases
2. Baseline hash file exists (SHA-256 for all evidence files)
3. Watchdog interval set to 60 seconds
4. Maximum runtime set to engagement duration (e.g., 8 hours)
5. Alert mechanism configured (terminal notification)

### Test Steps

1. Load baseline hash file and verify all files exist
2. Initialize watchdog loop:
   a. Read current hash of each evidence file
   b. Compare to baseline hash
   c. If any hash differs: log violation, alert operator, record before/after hashes
   d. If any file is missing: log deletion, alert operator
   e. If all hashes match: log clean check cycle
   f. Wait watchdog interval (60 seconds)
3. On violation detection:
   a. Log file path, expected hash, actual hash, timestamp
   b. Alert operator with terminal notification
   c. Update baseline with current state (if operator confirms acceptable change)
   d. Continue monitoring
4. On max runtime: write final integrity report, stop loop
5. Generate integrity audit trail from all check cycles

### Expected Outcomes

| Criterion | Expected Result |
|-----------|-----------------|
| Baseline capture | All evidence files hashed at loop start |
| Check frequency | Integrity verified every 60 seconds |
| Violation detection | Any file change detected within 1 check cycle |
| Alert timing | Operator notified within 5 seconds of violation |
| Audit trail | Complete log of all checks (clean and violation) |
| False positive rate | No violations reported when files are unchanged |

### Post-conditions

- Audit trail contains entries for every check cycle (clean and violations)
- Any violations include file path, hash comparison, and timestamp
- Final integrity report summarizes all checks performed
- No evidence files were modified by the watchdog loop itself
