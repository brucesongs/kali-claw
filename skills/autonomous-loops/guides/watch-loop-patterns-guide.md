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

### 4. Port Change Monitoring

Tracking open ports over time reveals unauthorized services, firewall misconfigurations, and lateral movement indicators. A port watch loop should compare current scan results against a known-good baseline and flag any new services immediately.

```bash
#!/bin/bash
# Port change monitoring with Nmap diff
TARGET="192.168.1.0/24"
BASELINE="ports_baseline.xml"
CURRENT="ports_current.xml"

nmap -sS -O -oX "$CURRENT" "$TARGET" --max-retries 2

if [ -f "$BASELINE" ]; then
    ndiff "$BASELINE" "$CURRENT" > port_diff.txt
    if grep -q "add\|remove" port_diff.txt; then
        echo "Port changes detected!"
        cat port_diff.txt
        notify_slack "Port change on $TARGET: $(cat port_diff.txt)"
    fi
fi

mv "$CURRENT" "$BASELINE"
```

For high-frequency monitoring, use a lightweight approach with `masscan` for initial sweep followed by targeted `nmap` service detection on changed ports:

```python
import subprocess
import xml.etree.ElementTree as ET

def port_watch(target, baseline_ports):
    """Quick port sweep with full scan on changes."""
    # Fast sweep
    result = subprocess.run(
        ["masscan", target, "-p1-65535", "--rate=1000", "-oJ", "-"],
        capture_output=True, text=True, timeout=120
    )
    current_ports = parse_masscan_json(result.stdout)

    new_open = current_ports - baseline_ports
    new_closed = baseline_ports - current_ports

    if new_open or new_closed:
        # Run detailed service scan on changed ports
        changed = new_open | new_closed
        detailed = run_nmap_service_scan(target, sorted(changed))
        return {"new_open": new_open, "new_closed": new_closed, "details": detailed}

    return {"new_open": set(), "new_closed": set(), "details": None}
```

### 5. HTTP Body and Content Monitoring

Beyond headers, the actual response body content carries critical signals: changed form fields, new JavaScript includes, modified API endpoints, and injected scripts. Content monitoring requires intelligent comparison that filters out dynamic noise like timestamps, CSRF tokens, and session identifiers.

```python
import hashlib
import re
from bs4 import BeautifulSoup

def extract_stable_content(html):
    """Remove dynamic elements before hashing for comparison."""
    soup = BeautifulSoup(html, "html.parser")

    # Remove script tags (often contain dynamic nonces, timestamps)
    for tag in soup.find_all("script"):
        tag.decompose()

    # Remove inline styles with dynamic values
    for tag in soup.find_all(style=True):
        del tag["style"]

    # Remove common dynamic attributes
    dynamic_attrs = ["csrf-token", "nonce", "data-timestamp"]
    for attr in dynamic_attrs:
        for tag in soup.find_all(attrs={attr: True}):
            del tag[attr]

    # Normalize whitespace for stable comparison
    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\d{10,}", "TIMESTAMP", text)  # mask unix timestamps
    text = re.sub(r"[a-f0-9]{32,}", "HASH", text)  # mask hashes
    return text

def content_hash(url):
    """Produce a stable hash of page content."""
    resp = requests.get(url, timeout=15)
    stable = extract_stable_content(resp.text)
    return hashlib.sha256(stable.encode()).hexdigest()

def content_watch(url, baseline_hash):
    """Detect meaningful content changes."""
    current_hash = content_hash(url)
    if current_hash != baseline_hash:
        # Fetch both versions for diff
        diff = compute_content_diff(url, baseline_hash)
        return {"changed": True, "hash": current_hash, "diff_summary": diff}
    return {"changed": False, "hash": current_hash}
```

For tracking specific page elements such as login forms, hidden fields, and JavaScript source URLs, use CSS-selector-based extraction:

```python
SELECTORS_TO_WATCH = [
    "form[action]",
    "input[type=hidden]",
    "script[src]",
    "link[rel=stylesheet][href]",
    "a[href*='logout']",
    "meta[name='csrf']",
]

def extract_tracked_elements(url):
    """Extract specific elements for structural comparison."""
    resp = requests.get(url, timeout=15)
    soup = BeautifulSoup(resp.text, "html.parser")
    elements = {}
    for selector in SELECTORS_TO_WATCH:
        found = soup.select(selector)
        elements[selector] = [str(el) for el in found]
    return elements
```

### 6. SSL/TLS Configuration Drift Monitoring

TLS misconfigurations are a frequent source of vulnerabilities. A TLS watch loop tracks cipher suite changes, protocol version support, certificate chain alterations, and HSTS policy drift. This is especially critical when monitoring CDN configurations or load balancer terminations that may silently downgrade security.

```python
import ssl
import socket
from datetime import datetime

def tls_fingerprint(hostname, port=443):
    """Capture complete TLS configuration state."""
    context = ssl.create_default_context()
    # Check all protocol versions
    protocols_supported = []
    for proto_name, proto_const in [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto_const
            ctx.maximum_version = proto_const
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocols_supported.append(proto_name)
        except (ssl.SSLError, OSError):
            pass

    # Get certificate details
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert(binary_form=False)
            cipher = ssock.cipher()
            protocol = ssock.version()

    return {
        "protocols": sorted(protocols_supported),
        "cipher": cipher[0] if cipher else None,
        "protocol_used": protocol,
        "cert_subject": dict(x[0] for x in cert["subject"]),
        "cert_issuer": dict(x[0] for x in cert["issuer"]),
        "cert_expires": cert["notAfter"],
        "san": cert.get("subjectAltName", []),
        "days_until_expiry": (
            datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            - datetime.utcnow()
        ).days,
    }

def tls_drift_check(hostname, baseline):
    """Compare current TLS config against baseline."""
    current = tls_fingerprint(hostname)
    drift = {}

    # Check for protocol downgrade
    if set(current["protocols"]) != set(baseline["protocols"]):
        drift["protocol_change"] = {
            "was": baseline["protocols"],
            "now": current["protocols"],
        }

    # Check cipher changes
    if current["cipher"] != baseline["cipher"]:
        drift["cipher_change"] = {"was": baseline["cipher"], "now": current["cipher"]}

    # Check certificate replacement
    if current["cert_expires"] != baseline["cert_expires"]:
        drift["cert_replaced"] = True

    # Expiry warning
    if current["days_until_expiry"] < 30:
        drift["expiry_warning"] = f"{current['days_until_expiry']} days remaining"

    return drift
```

### 7. Web Application Fingerprint Tracking

Web applications change through deployments, CMS updates, plugin upgrades, and theme modifications. Fingerprint tracking detects version changes that may introduce vulnerabilities before the change is publicly announced.

```python
FINGERPRINT_SIGNALS = [
    "/wp-login.php",          # WordPress indicator
    "/administrator/",        # Joomla indicator
    "/misc/drupal.js",        # Drupal indicator
    "/server-info",           # Apache status
    "/elmah.axd",             # ELMAH error log
    "/swagger-ui.html",       # Swagger API docs
    "/.env",                  # Exposed env file
    "/graphql",               # GraphQL endpoint
]

def fingerprint_app(base_url):
    """Enumerate application signals and version hints."""
    signals = {}
    session = requests.Session()

    for path in FINGERPRINT_SIGNALS:
        try:
            resp = session.get(f"{base_url}{path}", timeout=5, allow_redirects=False)
            signals[path] = {
                "status": resp.status_code,
                "content_length": len(resp.content),
                "server": resp.headers.get("Server", ""),
                "x_powered_by": resp.headers.get("X-Powered-By", ""),
            }
        except requests.RequestException:
            signals[path] = {"status": "error"}

    # Extract version hints from meta generators
    resp = session.get(base_url, timeout=10)
    soup = BeautifulSoup(resp.text, "html.parser")
    generators = [m.get("content", "") for m in soup.find_all("meta", attrs={"name": "generator"})]
    signals["generators"] = generators

    # Hash static assets for version detection
    static_hashes = {}
    for script in soup.find_all("script", src=True):
        src = script["src"]
        try:
            content = session.get(f"{base_url}{src}", timeout=5).text
            static_hashes[src] = hashlib.md5(content.encode()).hexdigest()[:12]
        except requests.RequestException:
            pass

    signals["asset_hashes"] = static_hashes
    return signals
```

### 8. Subnet Monitoring

Subnet-level watch loops track new hosts appearing on a network, detect rogue devices, and monitor ARP tables for poisoning attacks. This is critical for internal network security assessments.

```bash
#!/bin/bash
# Subnet monitoring with arp-scan
SUBNET="192.168.1.0/24"
BASELINE_HOSTS="hosts_baseline.txt"

arp-scan --interface=eth0 "$SUBNET" | grep -E "^[0-9]" | awk '{print $1, $2, $3}' | sort > current_hosts.txt

if [ -f "$BASELINE_HOSTS" ]; then
    NEW_HOSTS=$(comm -13 "$BASELINE_HOSTS" current_hosts.txt)
    GONE_HOSTS=$(comm -23 "$BASELINE_HOSTS" current_hosts.txt)

    if [ -n "$NEW_HOSTS" ]; then
        echo "New hosts detected:"
        echo "$NEW_HOSTS"
        notify_slack "New hosts on $SUBNET: $NEW_HOSTS"
    fi

    if [ -n "$GONE_HOSTS" ]; then
        echo "Hosts disappeared:"
        echo "$GONE_HOSTS"
    fi
fi

mv current_hosts.txt "$BASELINE_HOSTS"
```

### 9. Log Aggregation Patterns

When running multiple watch loops across several targets, centralized log aggregation becomes essential. Use structured logging with consistent schemas to enable post-hoc analysis and correlation.

```python
import json
import logging
import socket
from datetime import datetime, timezone

class StructuredWatchLogger(logging.Handler):
    """Structured JSON logger for watch loop events."""

    def __init__(self, log_file="watch_loop.jsonl"):
        super().__init__()
        self._log_file = log_file
        self.hostname = socket.gethostname()

    def emit(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": self.hostname,
            "level": record.levelname,
            "loop_id": getattr(record, "loop_id", "unknown"),
            "target": getattr(record, "target", "unknown"),
            "change_type": getattr(record, "change_type", None),
            "severity": getattr(record, "severity", "info"),
            "message": record.getMessage(),
            "details": getattr(record, "details", {}),
        }
        with open(self._log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

# Usage: correlate events across loops
def find_correlated_events(log_file, time_window_seconds=300):
    """Find events across different loops that happened near the same time."""
    events = []
    with open(log_file) as f:
        for line in f:
            events.append(json.loads(line))

    # Group by time proximity
    events.sort(key=lambda e: e["timestamp"])
    correlated = []
    for i, event in enumerate(events):
        cluster = [event]
        t = datetime.fromisoformat(event["timestamp"])
        for j in range(i + 1, len(events)):
            t2 = datetime.fromisoformat(events[j]["timestamp"])
            if (t2 - t).total_seconds() <= time_window_seconds:
                cluster.append(events[j])
            else:
                break
        if len(cluster) > 1:
            correlated.append(cluster)

    return correlated
```

### 10. Dashboard Integration

Watch loop output can feed security dashboards for real-time visibility. Use a lightweight metrics emitter that integrates with Grafana, Prometheus, or custom dashboards.

```python
import requests
from collections import Counter

class MetricsEmitter:
    """Emit watch loop metrics to Prometheus pushgateway."""

    def __init__(self, pushgateway_url="http://localhost:9091"):
        self._url = pushgateway_url

    def emit(self, metric_name, value, labels=None):
        labels_str = ",".join(f'{k}="{v}"' for k, v in (labels or {}).items())
        payload = f'# TYPE {metric_name} gauge\n{metric_name}{{{labels_str}}} {value}\n'
        try:
            requests.post(
                f"{self._url}/metrics/job/watch_loop",
                data=payload,
                timeout=5,
            )
        except requests.RequestException:
            pass  # metrics are best-effort

    def emit_scan_summary(self, scan_results):
        """Push scan result metrics."""
        statuses = Counter(r.get("status", "unknown") for r in scan_results)
        for status, count in statuses.items():
            self.emit("watch_scan_results", count, {"status": status})
        self.emit("watch_scan_total", len(scan_results))
        errors = sum(1 for r in scan_results if "error" in r)
        self.emit("watch_scan_errors", errors)
```

### 11. State Persistence Strategies

Watch loops must survive restarts, crashes, and redeployments. The state persistence strategy determines how much historical data is retained and how quickly the loop can resume after an interruption.

```python
import json
import os
from datetime import datetime, timezone

class WatchState:
    """File-based state persistence with atomic writes."""

    def __init__(self, state_dir="watch_state"):
        self._dir = state_dir
        os.makedirs(state_dir, exist_ok=True)

    def _path(self, target):
        safe_name = target.replace("/", "_").replace(":", "_")
        return os.path.join(self._dir, f"{safe_name}.json")

    def save(self, target, state):
        """Atomic write: write to temp file then rename."""
        path = self._path(target)
        tmp_path = path + ".tmp"
        state["last_updated"] = datetime.now(timezone.utc).isoformat()
        with open(tmp_path, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp_path, path)  # atomic on POSIX

    def load(self, target):
        """Load state, return None if not found."""
        path = self._path(target)
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return None

    def list_targets(self):
        """List all tracked targets."""
        return [f[:-5].replace("_", ":") for f in os.listdir(self._dir)
                if f.endswith(".json")]

    def prune(self, max_age_days=30):
        """Remove state files older than max_age_days."""
        cutoff = datetime.now(timezone.utc).timestamp() - (max_age_days * 86400)
        for filename in os.listdir(self._dir):
            path = os.path.join(self._dir, filename)
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
```

### 12. Alert Fatigue Prevention

Excessive alerts lead to desensitization and missed critical events. Implement suppression, deduplication, throttling, and severity escalation to keep the alert stream actionable.

```python
from collections import defaultdict
from datetime import datetime, timedelta

class AlertSuppressor:
    """Prevent alert fatigue with dedup, throttling, and escalation."""

    def __init__(self, cooldown_minutes=60, repeat_threshold=3):
        self._cooldown = timedelta(minutes=cooldown_minutes)
        self._repeat_threshold = repeat_threshold
        self._recent_alerts = defaultdict(list)  # key -> [timestamps]
        self._escalated = set()

    def should_alert(self, alert_key, severity):
        """Determine if an alert should be sent."""
        now = datetime.utcnow()
        recent = self._recent_alerts[alert_key]

        # Remove expired entries
        recent[:] = [t for t in recent if now - t < self._cooldown]

        if not recent:
            # First occurrence within cooldown window
            self._recent_alerts[alert_key].append(now)
            return True

        # Within cooldown — suppress unless threshold exceeded
        if len(recent) >= self._repeat_threshold:
            if alert_key not in self._escalated:
                self._escalated.add(alert_key)
                # Escalate: promote severity and force alert
                return True
            return False  # already escalated, suppress duplicates

        self._recent_alerts[alert_key].append(now)
        return False  # not enough repeats to break suppression

    def format_alert(self, change, severity):
        """Format alert with context and actionable guidance."""
        return {
            "severity": severity,
            "change_type": change.get("type"),
            "target": change.get("target"),
            "detail": change.get("detail", ""),
            "action_required": self._action_for(severity),
            "timestamp": datetime.utcnow().isoformat(),
        }

    @staticmethod
    def _action_for(severity):
        actions = {
            "critical": "IMMEDIATE: Investigate potential compromise",
            "high": "URGENT: Review within 1 hour",
            "medium": "Review within 24 hours",
            "low": "Log for next review cycle",
        }
        return actions.get(severity, "Review at convenience")
```

### 13. Multi-Target Watch Loops with Priority Queues

When monitoring many targets, not all deserve equal attention. Priority queues ensure critical assets are checked first and more frequently, while lower-priority targets are monitored at reduced cadence.

```python
import heapq
import time
from dataclasses import dataclass, field
from typing import Any

@dataclass(order=True)
class WatchTask:
    next_check: float  # Unix timestamp of next scheduled check
    priority: int = field(compare=True)  # lower = higher priority
    target: Any = field(compare=False)
    check_fn: Any = field(compare=False)
    interval: int = field(compare=False)  # seconds between checks

class PriorityWatchScheduler:
    """Schedule watch tasks with priority-based execution."""

    def __init__(self):
        self._queue = []

    def add_target(self, target, check_fn, interval, priority=5):
        """Add a target. Priority 1=critical, 10=low."""
        task = WatchTask(
            next_check=time.monotonic(),
            priority=priority,
            target=target,
            check_fn=check_fn,
            interval=interval,
        )
        heapq.heappush(self._queue, task)

    def run(self, max_iterations=None):
        """Execute watch tasks in priority order."""
        iteration = 0
        while max_iterations is None or iteration < max_iterations:
            if not self._queue:
                break

            task = heapq.heappop(self._queue)
            now = time.monotonic()

            # Wait until scheduled time
            if task.next_check > now:
                time.sleep(task.next_check - now)

            # Execute check
            try:
                result = task.check_fn(task.target)
                handle_result(task.target, result)
            except Exception as e:
                log_error(task.target, e)

            # Reschedule with same interval and priority
            task.next_check = time.monotonic() + task.interval
            heapq.heappush(self._queue, task)
            iteration += 1

# Priority guidelines
PRIORITY_LEVELS = {
    1: {"description": "Critical infrastructure", "interval": 60},      # every minute
    2: {"description": "Production web servers", "interval": 300},     # every 5 min
    3: {"description": "API endpoints", "interval": 600},              # every 10 min
    5: {"description": "Internal services", "interval": 1800},        # every 30 min
    7: {"description": "Development/staging", "interval": 3600},      # hourly
    10: {"description": "Low-value targets", "interval": 21600},      # every 6 hours
}
```

### 14. Loop Reliability

- **Exponential backoff** on failures — don't spam a down target
- **State persistence** — save baseline to disk, survive restarts
- **Watchdog timer** — detect if the loop itself has stalled
- **Graceful degradation** — continue if one check fails, don't halt the loop

## References

- [OWASP Monitoring Guidelines](https://owasp.org/www-community/controls/Monitoring)
- [SANS — Continuous Monitoring](https://www.sans.org/white-papers/)
- [NIST SP 800-137 — Information Security Continuous Monitoring](https://csrc.nist.gov/publications/detail/sp/800-137/final)
- [Prometheus Pushgateway](https://github.com/prometheus/pushgateway)
- [Nmap NDiff](https://nmap.org/book/ndiff-man.html)
- [SSL Labs Best Practices](https://ssl-config.mozilla.org/)
