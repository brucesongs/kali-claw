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

---

## TC-AL-001: Sequential Pipeline — Subnet Port Scan

### Scenario

A penetration tester needs to enumerate open ports across an authorized /24 subnet (192.168.1.0/24). The operation must proceed sequentially — one host at a time — with scope lock enforcement, rate limiting, and complete evidence logging.

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
