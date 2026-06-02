# Watch Loop Patterns Guide

## Introduction

Watch loops are continuously running autonomous cycles that monitor targets for changes, detect anomalies, and trigger automated responses. Unlike one-shot scans, watch loops maintain persistent awareness of a target's security posture. This guide covers design patterns for building reliable, efficient watch loops.

## Practical Steps

### 1. Polling vs Event-Driven Patterns

**Polling Pattern** (simple, universal):
```python
import time
import requests

def watch_loop(target, interval=300, check_fn=None):
    """Poll target at regular intervals."""
    baseline = check_fn(target)
    while True:
        time.sleep(interval)
        current = check_fn(target)
        diff = compare(baseline, current)
        if diff.has_changes():
            handle_change(diff)
            baseline = current
```

**Event-Driven Pattern** (efficient, requires hook):
```python
import webhooks

@webhooks.handler("deployment")
def on_deploy(event):
    """Trigger scan when new deployment detected."""
    target = event["target"]
    run_security_scan(target)
    compare_with_baseline(target)
```

### 2. Change Detection Strategies

**DNS Watch:**
```bash
#!/bin/bash
# Monitor DNS records for changes
DOMAIN="target.com"
BASELINE="dns_baseline.txt"

dig +short "$DOMAIN" A | sort > current.txt
if ! diff -q "$BASELINE" current.txt > /dev/null 2>&1; then
    echo "DNS change detected for $DOMAIN"
    diff "$BASELINE" current.txt
    notify_slack "DNS change: $DOMAIN"
    mv current.txt "$BASELINE"
fi
```

**Certificate Watch:**
```bash
#!/bin/bash
# Monitor TLS certificate changes (possible MITM indicator)
DOMAIN="target.com"
CERT_FILE="cert_baseline.pem"

echo | openssl s_client -connect "$DOMAIN":443 2>/dev/null | \
  openssl x509 -noout -fingerprint -sha256 > current_cert.txt

if ! diff -q "$CERT_FILE" current_cert.txt > /dev/null 2>&1; then
    echo "Certificate change detected for $DOMAIN"
    notify_slack "TLS cert changed: $DOMAIN"
    mv current_cert "$CERT_FILE"
fi
```

**HTTP Header Watch:**
```python
SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
]

def check_headers(url):
    resp = requests.head(url, timeout=10)
    present = {h.lower(): resp.headers.get(h) for h in SECURITY_HEADERS}
    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    return {"present": present, "missing": missing}
```

### 3. Alerting and Escalation

```python
SEVERITY_MAP = {
    "dns_change": "high",
    "cert_change": "critical",
    "header_missing": "medium",
    "new_port_open": "high",
    "content_change": "low",
}

def handle_change(diff):
    for change in diff.changes:
        severity = SEVERITY_MAP.get(change.type, "info")
        if severity in ("critical", "high"):
            send_alert(change, severity)
        log_change(change, severity)
```

### 4. Loop Reliability

- **Exponential backoff** on failures — don't spam a down target
- **State persistence** — save baseline to disk, survive restarts
- **Watchdog timer** — detect if the loop itself has stalled
- **Graceful degradation** — continue if one check fails, don't halt the loop

## References

- [OWASP Monitoring Guidelines](https://owasp.org/www-community/controls/Monitoring)
- [SANS — Continuous Monitoring](https://www.sans.org/white-papers/)
- [NIST SP 800-137 — Information Security Continuous Monitoring](https://csrc.nist.gov/publications/detail/sp/800-137/final)
