# Remediation Verification Patterns Guide

> Skill: verification-loop | Type: practical
> Created: 2026-05-23 | Estimated Study Time: 40 minutes

## Overview

Learn to verify that security remediations, patches, and fixes are effective. Covers pre-patch baseline, post-patch confirmation, regression testing, and evidence documentation for remediation verification.

## Prerequisites

- Basic verification-loop methodology
- Terminal-ops evidence protocol
- Understanding of vulnerability types

## 1. Remediation Verification Framework

### Six-Phase Process for Remediations

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  1. Pre-    │───→│  2. Apply   │───→│  3. Post-   │
│  Patch      │    │  Remediation│    │  Patch      │
│  Baseline   │    │             │    │  Check      │
└─────────────┘    └─────────────┘    └─────────────┘
                                            │
┌─────────────┐    ┌─────────────┐    ┌─────┴───────┐
│  6. Evidence │←──│  5. Variant  │←──│  4. Re-      │
│  Report     │    │  Testing    │    │  Exploit     │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Phase 1: Pre-Patch Baseline

Document the vulnerability state before remediation:

```markdown
## Pre-Patch Baseline
- **Finding ID:** VULN-2024-001
- **Type:** SQL Injection
- **Endpoint:** /api/users
- **Payload:** ' OR 1=1--
- **Baseline Evidence:**
  - [x] Vulnerability confirmed with original payload
  - [x] Baseline screenshot captured
  - [x] Original request/response logged
  - [x] System state recorded (version, config)
```

```bash
# Capture baseline evidence
echo "=== PRE-PATCH BASELINE: $(date) ==="

# Confirm vulnerability exists
curl -X POST "http://target/api/users" \
  -d "username=test' OR 1=1--&password=test" \
  -v > pre-patch-evidence.log

# Capture system state
echo "=== SYSTEM STATE ===" >> pre-patch-evidence.log
cat /etc/os-release >> pre-patch-evidence.log
rpm -qa | grep -i app-name >> pre-patch-evidence.log
```

### Phase 2: Apply Remediation

Document the exact remediation applied:

```markdown
## Remediation Applied
- **Date:** 2024-05-23 14:30 UTC
- **Method:** [Patch / Config Change / Code Fix / WAF Rule]
- **Change Description:**
  - Added input validation for username field
  - Implemented parameterized queries
  - Updated library version X.Y.Z → X.Y.Z+1
- **Applied By:** [Name / Automation]
- **Rollback Plan:** [How to revert if needed]
```

```bash
# Apply remediation
echo "=== REMEDIATION APPLIED: $(date) ==="

# Example: Apply patch
yum update -y app-security-patch-1.2.3

# Example: Change config
sed -i 's/validate_input=false/validate_input=true/' /etc/app/config.ini
systemctl restart app

# Example: Add WAF rule
curl -X POST "http://waf/api/rules" \
  -H "Content-Type: application/json" \
  -d '{"rule_id": "sqli-block-001", "action": "block"}'
```

### Phase 3: Post-Patch Check

Verify the system is operational after remediation:

```bash
# Verify system is running
echo "=== POST-PATCH SYSTEM CHECK: $(date) ==="
systemctl status app

# Verify basic functionality
curl -s http://target/api/health
# Expected: {"status": "healthy"}

# Check service version
rpm -qa | grep -i app-name
```

```markdown
## Post-Patch System Check
- [x] Service running: YES
- [x] Health check passing: YES
- [x] Version updated: v1.2.3 → v1.2.4
- [x] No errors in logs
- [x] Normal functionality verified
```

### Phase 4: Re-Exploit Attempt

Try the ORIGINAL exploit that confirmed the vulnerability:

```bash
# Try original payload
echo "=== RE-EXPLOIT ATTEMPT: $(date) ==="
curl -X POST "http://target/api/users" \
  -d "username=test' OR 1=1--&password=test" \
  -v > post-patch-exploit.log

# Check if vulnerable
grep -i "error\|unauthorized\|invalid" post-patch-exploit.log
# Expected: Error response, not user data
```

**Result Matrix:**

| Expected Response | Actual Response | Verdict |
|------------------|-----------------|---------|
| Error/401        | Error/401       | PATCHED |
| Error/401        | User data       | NOT PATCHED |
| Error/401        | No response     | INCONCLUSIVE |

### Phase 5: Variant Testing

Try alternative exploits to test for partial fixes:

```bash
# Test different SQLi payloads
payloads=(
    "' UNION SELECT NULL,NULL--"
    "admin'--"
    "' OR '1'='1"
    "1' AND SLEEP(5)--"
)

echo "=== VARIANT TESTING: $(date) ==="
for payload in "${payloads[@]}"; do
    echo "Testing: $payload"
    curl -X POST "http://target/api/users" \
      -d "username=$payload&password=test" \
      -s -o /dev/null -w "Status: %{http_code}\n"
done
```

### Phase 6: Evidence Report

Compile final verification report:

```markdown
## Remediation Verification Report

### Summary
- **Finding ID:** VULN-2024-001
- **Type:** SQL Injection
- **Verdict:** PATCHED / PARTIALLY PATCHED / NOT PATCHED
- **Confidence:** High
- **Date:** 2024-05-23

### Verification Timeline
1. **14:00 UTC** — Pre-patch baseline captured
2. **14:30 UTC** — Remediation applied (patch v1.2.4)
3. **14:35 UTC** — Post-patch system check passed
4. **14:36 UTC** — Original exploit blocked (401)
5. **14:40 UTC** — Variant payloads blocked (all)
6. **14:45 UTC** — Regression testing complete

### Evidence
- Pre-patch exploit log: `pre-patch-evidence.log`
- Post-patch exploit log: `post-patch-exploit.log`
- System state comparison: `state-diff.txt`
- Screenshot comparison: `before-after.png`

### Regression Test Results
- [x] Normal user login works
- [x] User registration works
- [x] API health check passing
- [x] No performance degradation

### Recommendation
**Approve for production deployment** - All exploit attempts blocked, functionality intact.
```

## 2. Web Vulnerability Verification

### SQL Injection Remediation

```bash
# Pre-patch: Confirm vulnerability
curl -X POST "http://target/api/login" \
  -d "user=admin' OR 1=1--&pass=any" \
  -s | grep -i "welcome\|token"
# Expected: Found (vulnerable)

# Post-patch: Verify fix
curl -X POST "http://target/api/login" \
  -d "user=admin' OR 1=1--&pass=any" \
  -s | grep -i "error\|invalid\|unauthorized"
# Expected: Found (patched)

# Variant: Test blind SQLi
curl -X POST "http://target/api/login" \
  -d "user=admin' AND SLEEP(5)--&pass=any" \
  --max-time 3
# Expected: Timeout (patched) or fast response (vulnerable)
```

### XSS Remediation

```bash
# Pre-patch: Confirm XSS
curl "http://target/search?q=<script>alert(1)</script>" \
  -s | grep -o '<script>alert(1)</script>'
# Expected: Found (vulnerable)

# Post-patch: Verify fix
curl "http://target/search?q=<script>alert(1)</script>" \
  -s | grep -o '<script>alert(1)</script>'
# Expected: Not found (patched)

# Variant: Test other XSS vectors
xss_payloads=(
    "<img src=x onerror=alert(1)>"
    "<svg onload=alert(1)>"
    "javascript:alert(1)"
)

for payload in "${xss_payloads[@]}"; do
    curl "http://target/search?q=$(urlencode "$payload")" \
      -s | grep -q "$payload" && echo "VULN: $payload" || echo "OK: $payload"
done
```

### CSRF Remediation

```bash
# Pre-patch: Confirm missing CSRF
curl -X POST "http://target/api/settings" \
  -d "email=attacker@evil.com" \
  -H "Cookie: session=valid-session" \
  -v 2>&1 | grep -i "csrf\|token"
# Expected: Not found (vulnerable)

# Post-patch: Verify token required
curl -X POST "http://target/api/settings" \
  -d "email=attacker@evil.com" \
  -H "Cookie: session=valid-session" \
  -v 2>&1 | grep -i "csrf\|token\|missing"
# Expected: "CSRF token missing" (patched)

# Valid request with token
curl -X POST "http://target/api/settings" \
  -d "email=attacker@evil.com&csrf_token=valid-token" \
  -H "Cookie: session=valid-session" \
  -v 2>&1 | grep -i "200\|success"
```

## 3. Network Vulnerability Verification

### Open Port Remediation

```bash
# Pre-patch: Confirm open port
nmap -p 22,80,443,3306 target | grep -E "22/tcp|80/tcp|443/tcp|3306/tcp"
# Expected: 3306/tcp open (vulnerable)

# Post-patch: Verify port closed
nmap -p 22,80,443,3306 target | grep -E "22/tcp|80/tcp|443/tcp|3306/tcp"
# Expected: 3306/tcp closed (patched)

# Alternative: Verify with nc
nc -zv target 3306 2>&1
# Expected: Connection refused (patched)
```

### Weak Cipher Remediation

```bash
# Pre-patch: Confirm weak ciphers
nmap --script ssl-enum-ciphers -p 443 target | grep -i "weak\|export\|anon"
# Expected: Found (vulnerable)

# Post-patch: Verify strong ciphers only
nmap --script ssl-enum-ciphers -p 443 target | grep -i "weak\|export\|anon"
# Expected: Not found (patched)

# Test with OpenSSL
openssl s_client -connect target:443 -cipher EXP:LOW 2>&1 | grep -i "handshake"
# Expected: No cipher match (patched)
```

## 4. Configuration-Based Remediation

### WAF Rule Verification

```bash
# Pre-patch: Confirm WAF missing or bypassed
curl -X POST "http://target/api" \
  -H "X-Forwarded-For: evil.com" \
  -d "payload=<script>alert(1)</script>"
# Expected: 200 OK (vulnerable)

# Post-patch: Verify WAF blocks
curl -X POST "http://target/api" \
  -H "X-Forwarded-For: evil.com" \
  -d "payload=<script>alert(1)</script>"
# Expected: 403 Forbidden (patched)

# Verify legitimate traffic still works
curl -X POST "http://target/api" \
  -d "payload=valid data"
# Expected: 200 OK (functionality preserved)
```

### File Permission Remediation

```bash
# Pre-patch: Check permissions
ls -la /etc/app/config.ini
# Expected: -rw-rw-r-- (world-readable, vulnerable)

# Post-patch: Verify fixed
ls -la /etc/app/config.ini
# Expected: -rw-r----- (group-only, patched)

# Verify app can still read
sudo -u appuser cat /etc/app/config.ini
# Expected: Success (functionality preserved)

# Verify others cannot
sudo -u nobody cat /etc/app/config.ini
# Expected: Permission denied (patched)
```

## 5. Regression Testing

### Functional Regression

```bash
# Test normal user workflow
echo "=== REGRESSION TESTS ==="

# Test 1: User login
curl -X POST "http://target/api/login" \
  -d "user=admin&pass=correct-password" \
  -s | grep -q "success" && echo "PASS: Login" || echo "FAIL: Login"

# Test 2: User registration
curl -X POST "http://target/api/register" \
  -d "user=newuser&pass=valid-password" \
  -s | grep -q "created" && echo "PASS: Register" || echo "FAIL: Register"

# Test 3: Data retrieval
curl -H "Authorization: Bearer valid-token" \
  "http://target/api/data" \
  -s | grep -q "expected-data" && echo "PASS: Data retrieval" || echo "FAIL: Data retrieval"
```

### Performance Regression

```bash
# Baseline performance
echo "=== PERFORMANCE BASELINE ==="
time curl -s http://target/api/heavy-operation > /dev/null

# Post-patch performance
echo "=== PERFORMANCE POST-PATCH ==="
time curl -s http://target/api/heavy-operation > /dev/null

# Compare results - should be within 10% of baseline
```

## Quick Reference

```bash
# Pre-patch baseline
curl -X POST "http://target/api" -d "payload=exploit" > pre.log

# Apply remediation
systemctl restart app

# Post-patch check
curl -X POST "http://target/api" -d "payload=exploit" > post.log

# Compare results
diff pre.log post.log

# Variant testing
for p in "${payloads[@]}"; do
    curl -X POST "http://target/api" -d "payload=$p"
done

# Regression test
curl -H "Auth: token" "http://target/api/data"
```

## Integration with Other Skills

- **verification-loop**: Core methodology
- **terminal-ops**: Evidence logging during verification
- **security-review**: Post-remediation review
- **web-sqli**: SQLi-specific verification patterns
- **web-xss**: XSS-specific verification patterns
- **network-pentest**: Network remediation verification