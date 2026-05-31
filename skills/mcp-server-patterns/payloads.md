# MCP Server Patterns — Payloads

## 1. MCP Server Scaffold (Python SDK)

Minimal working MCP server. Install with: `pip install mcp`

```python
#!/usr/bin/env python3
"""Minimal secure MCP server scaffold for wrapping Kali Linux tools."""

import asyncio
import json
import logging
import os
import shlex
import subprocess
from typing import Any

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

# Configure server-side logging (never exposed to callers)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[logging.FileHandler("/var/log/mcp-security-server.log")],
)
log = logging.getLogger("mcp-security-server")

# Load secrets from environment at startup — fail fast if missing
API_KEY = os.environ.get("MCP_API_KEY")
if not API_KEY:
    raise RuntimeError("MCP_API_KEY environment variable is required")

app = Server("security-tools-server")


@app.list_tools()
async def list_tools() -> ListToolsResult:
    """Advertise available tools to the AI client."""
    return ListToolsResult(tools=[
        Tool(
            name="run_nmap",
            description=(
                "Run an nmap port scan against a single authorized IP address. "
                "Returns open ports, service versions, and OS detection results as JSON."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IPv4 address (must be in authorized scope)",
                        "pattern": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification (e.g. '80,443', '1-1024', 'top100')",
                        "default": "top100",
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["syn", "connect", "udp", "version"],
                        "description": "Scan technique to use",
                        "default": "connect",
                    },
                },
                "required": ["target"],
            },
        ),
    ])


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    """Dispatch tool calls to handlers with error isolation."""
    try:
        if name == "run_nmap":
            result = await handle_nmap(arguments)
        else:
            result = {"error": "unknown_tool", "tool": name}
    except Exception as exc:
        log.error("Tool execution failed: tool=%s error=%s", name, exc, exc_info=True)
        result = {"error": "tool_execution_failed", "detail": str(exc)[:120]}

    return CallToolResult(content=[TextContent(type="text", text=json.dumps(result))])


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(server_name="security-tools-server", server_version="1.0.0"),
        )


if __name__ == "__main__":
    asyncio.run(main())
```

---

## 2. Security Tool Wrapping Templates

### 2a. nmap Wrapper (Full Implementation)

```python
import ipaddress
import json
import re
import subprocess
from typing import Any

# Authorized target ranges — must be explicitly configured per engagement
AUTHORIZED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
]

SCAN_TYPE_FLAGS = {
    "syn":     ["-sS"],
    "connect": ["-sT"],
    "udp":     ["-sU"],
    "version": ["-sV"],
}

PORT_PATTERN = re.compile(r"^(top\d+|\d+(-\d+)?(,\d+(-\d+)?)*)$")


def validate_ip(target: str) -> ipaddress.IPv4Address:
    """Parse and validate target IP. Raise ValueError if invalid or out of scope."""
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        raise ValueError(f"Invalid IP address: {target!r}")

    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 addresses are supported")

    in_scope = any(addr in net for net in AUTHORIZED_RANGES)
    if not in_scope:
        raise ValueError(f"Target {target} is not in authorized scope")

    return addr


def validate_ports(ports: str) -> str:
    """Validate port specification format."""
    if ports == "top100":
        return "--top-ports=100"
    if not PORT_PATTERN.match(ports):
        raise ValueError(f"Invalid port specification: {ports!r}")
    return f"-p{ports}"


async def handle_nmap(arguments: dict[str, Any]) -> dict:
    target = arguments.get("target", "")
    ports = arguments.get("ports", "top100")
    scan_type = arguments.get("scan_type", "connect")

    # Validate all inputs before touching subprocess
    validated_ip = validate_ip(target)
    port_flag = validate_ports(ports)

    if scan_type not in SCAN_TYPE_FLAGS:
        raise ValueError(f"Invalid scan_type: {scan_type!r}")

    scan_flags = SCAN_TYPE_FLAGS[scan_type]

    # Build argument list — NO shell=True, NO string formatting with user input
    cmd = ["nmap", "-oX", "-", port_flag] + scan_flags + [str(validated_ip)]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,   # hard timeout — no unbounded execution
    )

    if proc.returncode != 0:
        raise RuntimeError(f"nmap returned exit code {proc.returncode}")

    return {
        "target": str(validated_ip),
        "scan_type": scan_type,
        "ports_requested": ports,
        "raw_xml": proc.stdout,   # caller parses XML; could be pre-parsed here
        "stderr_summary": proc.stderr[:500] if proc.stderr else "",
    }
```

### 2b. nikto Wrapper

```python
import re
import subprocess
from urllib.parse import urlparse
from typing import Any

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_NIKTO_TUNING = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "a", "b", "c", "x"}


def validate_url(url: str) -> str:
    """Validate URL scheme and format. Return normalized URL."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"URL scheme must be http or https, got: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError("URL must include a hostname")
    # Reject URLs with embedded credentials
    if parsed.username or parsed.password:
        raise ValueError("URL must not contain embedded credentials")
    return url


async def handle_nikto(arguments: dict[str, Any]) -> dict:
    url = arguments.get("url", "")
    tuning = arguments.get("tuning", "x")  # default: all tests except DoS

    validated_url = validate_url(url)

    # Validate tuning string — each char must be in allowed set
    if not all(c in ALLOWED_NIKTO_TUNING for c in tuning):
        raise ValueError(f"Invalid tuning value: {tuning!r}")

    cmd = ["nikto", "-h", validated_url, "-Format", "json", "-Tuning", tuning, "-nointeractive"]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )

    # nikto exits non-zero even on success if findings exist — check output instead
    try:
        findings = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        findings = {"raw_output": proc.stdout[:2000]}

    return {
        "target_url": validated_url,
        "tuning": tuning,
        "findings": findings,
        "exit_code": proc.returncode,
    }
```

### 2c. Generic Safe Command Tool Pattern

```python
import shlex
import subprocess
from typing import Any

# ALLOWLIST of permitted commands and their permitted flags
COMMAND_ALLOWLIST = {
    "whatweb": {"--log-json", "-a", "--quiet"},
    "gobuster": {"dir", "dns", "-u", "-w", "-t", "-o"},
}

DISALLOWED_CHARS = set(";|&`$><\n\r\x00")


def sanitize_string_arg(value: str, label: str) -> str:
    """Reject any string containing shell metacharacters."""
    found = DISALLOWED_CHARS & set(value)
    if found:
        raise ValueError(f"{label} contains disallowed characters: {found!r}")
    return value


async def handle_generic_tool(tool_name: str, flags: list[str], target: str) -> dict:
    if tool_name not in COMMAND_ALLOWLIST:
        raise ValueError(f"Tool not in allowlist: {tool_name!r}")

    allowed_flags = COMMAND_ALLOWLIST[tool_name]
    for flag in flags:
        if flag not in allowed_flags:
            raise ValueError(f"Flag not permitted: {flag!r}")

    sanitize_string_arg(target, "target")

    # Build command as list — never use shell=True
    cmd = [tool_name] + flags + [target]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
    )

    return {
        "tool": tool_name,
        "target": target,
        "stdout": proc.stdout[:5000],
        "exit_code": proc.returncode,
    }
```

---

## 3. Input Validation Patterns

```python
import ipaddress
import re
import os
from urllib.parse import urlparse

# --- IP / CIDR Validation ---
def validate_ip_or_cidr(value: str) -> str:
    """Accept single IP or CIDR notation. Reject everything else."""
    try:
        # Try as network first (raises if host bits are set without strict=False)
        network = ipaddress.ip_network(value, strict=False)
        return str(network)
    except ValueError:
        raise ValueError(f"Invalid IP or CIDR: {value!r}")


# --- URL Validation ---
ALLOWED_URL_SCHEMES = {"http", "https"}

def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        raise ValueError(f"Disallowed URL scheme: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError("URL missing hostname")
    return url


# --- Port Range Validation ---
def validate_port(port: int) -> int:
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"Port must be integer 1-65535, got: {port!r}")
    return port

def validate_port_range(start: int, end: int) -> tuple[int, int]:
    validate_port(start)
    validate_port(end)
    if start > end:
        raise ValueError(f"Port range start {start} > end {end}")
    return start, end


# --- File Path Allowlist ---
ALLOWED_WORDLIST_DIR = "/usr/share/wordlists"

def validate_wordlist_path(path: str) -> str:
    """Ensure path resolves inside the allowed directory."""
    real = os.path.realpath(path)
    allowed_real = os.path.realpath(ALLOWED_WORDLIST_DIR)
    if not real.startswith(allowed_real + os.sep):
        raise ValueError(f"Path outside allowed directory: {path!r}")
    if not os.path.isfile(real):
        raise ValueError(f"Wordlist file not found: {path!r}")
    return real


# --- Target Scope Enforcement ---
AUTHORIZED_RANGES = [
    ipaddress.ip_network("10.10.10.0/24"),   # lab network
]

def assert_in_scope(target_ip: str) -> None:
    addr = ipaddress.ip_address(target_ip)
    if not any(addr in net for net in AUTHORIZED_RANGES):
        raise ValueError(f"Target {target_ip} is outside authorized engagement scope")
```

---

## 4. Authentication Middleware

```python
import os
import logging
from functools import wraps
from typing import Callable, Any

log = logging.getLogger("mcp-auth")

# Load API key at module import time — fail fast if missing
_EXPECTED_KEY = os.environ.get("MCP_API_KEY")
if not _EXPECTED_KEY:
    raise RuntimeError("MCP_API_KEY must be set in environment before starting server")


def require_api_key(handler: Callable) -> Callable:
    """Decorator: validate X-API-Key header before executing handler."""
    @wraps(handler)
    async def wrapper(request: Any, *args, **kwargs):
        provided_key = request.headers.get("X-API-Key", "")

        # Constant-time comparison to prevent timing attacks
        import hmac
        if not hmac.compare_digest(provided_key.encode(), _EXPECTED_KEY.encode()):
            log.warning("Auth failure from %s", request.client.host)
            return {"error": "unauthorized"}   # no detail about why

        log.info("Auth success from %s", request.client.host)
        return await handler(request, *args, **kwargs)

    return wrapper


# HTTP/SSE transport — FastAPI-style middleware example
from fastapi import Request, Response

async def api_key_middleware(request: Request, call_next) -> Response:
    provided_key = request.headers.get("X-API-Key", "")
    import hmac
    if not hmac.compare_digest(provided_key.encode(), _EXPECTED_KEY.encode()):
        log.warning("Unauthorized request from %s for %s", request.client.host, request.url.path)
        return Response(
            content='{"error": "unauthorized"}',
            status_code=401,
            media_type="application/json",
        )
    return await call_next(request)
```

---

## 5. Rate Limiting Configuration

```python
import time
import logging
from collections import defaultdict
from threading import Lock
from typing import Optional

log = logging.getLogger("mcp-ratelimit")

# Configuration constants
PER_CLIENT_MAX_REQUESTS = 10
PER_CLIENT_WINDOW_SECONDS = 60
GLOBAL_MAX_REQUESTS = 100
GLOBAL_WINDOW_SECONDS = 60


class RateLimiter:
    def __init__(self):
        self._client_windows: dict[str, list[float]] = defaultdict(list)
        self._global_window: list[float] = []
        self._lock = Lock()

    def check(self, client_id: str) -> Optional[int]:
        """
        Return None if request is allowed.
        Return retry_after seconds if rate limited.
        """
        now = time.monotonic()
        with self._lock:
            # Prune expired timestamps
            cutoff_client = now - PER_CLIENT_WINDOW_SECONDS
            cutoff_global = now - GLOBAL_WINDOW_SECONDS
            self._client_windows[client_id] = [
                t for t in self._client_windows[client_id] if t > cutoff_client
            ]
            self._global_window = [t for t in self._global_window if t > cutoff_global]

            # Check global limit first
            if len(self._global_window) >= GLOBAL_MAX_REQUESTS:
                oldest = self._global_window[0]
                retry_after = int(GLOBAL_WINDOW_SECONDS - (now - oldest)) + 1
                log.warning("Global rate limit hit by client=%s", client_id)
                return retry_after

            # Check per-client limit
            if len(self._client_windows[client_id]) >= PER_CLIENT_MAX_REQUESTS:
                oldest = self._client_windows[client_id][0]
                retry_after = int(PER_CLIENT_WINDOW_SECONDS - (now - oldest)) + 1
                log.warning("Per-client rate limit hit: client=%s", client_id)
                return retry_after

            # Allow and record
            self._client_windows[client_id].append(now)
            self._global_window.append(now)
            return None


_limiter = RateLimiter()


def check_rate_limit(client_id: str) -> Optional[dict]:
    """Return None if allowed, or an error dict with retry_after if throttled."""
    retry_after = _limiter.check(client_id)
    if retry_after is not None:
        return {
            "error": "rate_limit_exceeded",
            "retry_after": retry_after,
            "message": f"Too many requests. Retry after {retry_after} seconds.",
        }
    return None
```

---

## 6. Structured Output Templates

```json
// Scan Results Schema
{
  "scan_id": "string (UUID)",
  "target": "string (IP or hostname)",
  "timestamp": "string (ISO 8601)",
  "scan_type": "string",
  "status": "string (completed | failed | timeout)",
  "hosts": [
    {
      "ip": "string",
      "hostname": "string | null",
      "status": "string (up | down)",
      "ports": [
        {
          "port": "integer",
          "protocol": "string (tcp | udp)",
          "state": "string (open | closed | filtered)",
          "service": "string | null",
          "version": "string | null"
        }
      ],
      "os_guess": "string | null"
    }
  ],
  "error": "string | null"
}
```

```json
// Vulnerability Finding Schema
{
  "finding_id": "string",
  "severity": "string (critical | high | medium | low | info)",
  "title": "string",
  "target": "string",
  "endpoint": "string | null",
  "cwe": "string | null (e.g. CWE-89)",
  "description": "string",
  "evidence": "string",
  "remediation": "string",
  "references": ["string (URL)"]
}
```

```json
// Host Enumeration Schema
{
  "enumeration_id": "string",
  "scope": "string (CIDR)",
  "timestamp": "string (ISO 8601)",
  "live_hosts": [
    {
      "ip": "string",
      "hostname": "string | null",
      "mac": "string | null",
      "vendor": "string | null",
      "response_time_ms": "number"
    }
  ],
  "total_scanned": "integer",
  "total_live": "integer"
}
```

---

## 7. MCP Security Testing Commands

### Schema Validation Bypass Tests

```bash
# Send wrong type for integer field (expect: 400 or validation error, not execution)
curl -s -X POST http://localhost:8080/tools/run_nmap \
  -H "X-API-Key: $MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": 12345, "ports": "80"}'

# Send missing required field
curl -s -X POST http://localhost:8080/tools/run_nmap \
  -H "X-API-Key: $MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ports": "80"}'

# Send extra undeclared field
curl -s -X POST http://localhost:8080/tools/run_nmap \
  -H "X-API-Key: $MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "ports": "80", "extra_field": "injected"}'
```

### Injection Attempt Tests

```bash
# Semicolon injection in IP field (expect: rejected before execution)
curl -s -X POST http://localhost:8080/tools/run_nmap \
  -H "X-API-Key: $MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1; id"}'

# Command substitution injection
curl -s -X POST http://localhost:8080/tools/run_nmap \
  -H "X-API-Key: $MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "$(whoami)"}'

# Path traversal via port field
curl -s -X POST http://localhost:8080/tools/run_nikto \
  -H "X-API-Key: $MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.1/../../../../etc/passwd"}'
```

### Auth Bypass Tests

```bash
# Missing API key header (expect: 401)
curl -s -X POST http://localhost:8080/tools/run_nmap \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'

# Empty API key (expect: 401)
curl -s -X POST http://localhost:8080/tools/run_nmap \
  -H "X-API-Key: " \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'

# Wrong API key (expect: 401)
curl -s -X POST http://localhost:8080/tools/run_nmap \
  -H "X-API-Key: wrongkey" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
```

### Rate Limit Testing (Python)

```python
import time
import httpx

MCP_URL = "http://localhost:8080/tools/run_nmap"
API_KEY = "your-test-key"
PAYLOAD = {"target": "192.168.1.1", "ports": "80"}

results = []
for i in range(20):
    resp = httpx.post(
        MCP_URL,
        json=PAYLOAD,
        headers={"X-API-Key": API_KEY},
        timeout=5,
    )
    results.append((i, resp.status_code, resp.json()))
    print(f"Request {i+1}: status={resp.status_code}")

# Expect first N requests to succeed (200), subsequent to get 429
rate_limited = [r for r in results if r[1] == 429]
print(f"Rate limited after {results.index(rate_limited[0])+1} requests" if rate_limited else "WARNING: Rate limiting not triggered")
```

### Error Message Information Disclosure Tests

```bash
# Trigger failure with unreachable target — inspect error response
curl -s -X POST http://localhost:8080/tools/run_nmap \
  -H "X-API-Key: $MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.254", "ports": "99999"}' | jq .

# Check response does NOT contain: /home/, /root/, Traceback, File ", line
# If it does: HIGH severity information disclosure finding
```

---

## 10. MCP Client Implementation Patterns

### Python Client with Retry Logic

```python
import httpx
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential

class MCPClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def call_tool(self, tool_name, params):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/tools/{tool_name}",
                headers=self.headers,
                json=params,
                timeout=30.0
            )
            resp.raise_for_status()
            return resp.json()
```

### Streaming Response Handler

```python
async def stream_tool_output(client, tool_name, params):
    async with httpx.AsyncClient() as http:
        async with http.stream("POST", f"{client.base_url}/tools/{tool_name}",
                               headers=client.headers, json=params) as response:
            async for chunk in response.aiter_lines():
                if chunk.strip():
                    data = json.loads(chunk)
                    yield data
```

### Connection Pool Management

```python
from contextlib import asynccontextmanager

class MCPConnectionPool:
    def __init__(self, servers):
        self.servers = servers
        self.pools = {}

    @asynccontextmanager
    async def get_connection(self, server_name):
        if server_name not in self.pools:
            self.pools[server_name] = httpx.AsyncClient(
                base_url=self.servers[server_name]["url"],
                headers={"X-API-Key": self.servers[server_name]["key"]},
                limits=httpx.Limits(max_connections=10)
            )
        yield self.pools[server_name]

    async def close_all(self):
        for pool in self.pools.values():
            await pool.aclose()
```

---

## 11. Multi-Server Orchestration

### Server Registry Pattern

```python
class ServerRegistry:
    def __init__(self):
        self.servers = {}
        self.capabilities = {}

    def register(self, name, url, api_key, tools):
        self.servers[name] = {"url": url, "api_key": api_key}
        for tool in tools:
            self.capabilities[tool] = name

    def route(self, tool_name):
        server = self.capabilities.get(tool_name)
        if not server:
            raise ValueError(f"No server registered for tool: {tool_name}")
        return self.servers[server]
```

### Parallel Tool Execution

```python
async def parallel_execute(registry, tool_calls):
    tasks = []
    for call in tool_calls:
        server = registry.route(call["tool"])
        client = MCPClient(server["url"], server["api_key"])
        tasks.append(client.call_tool(call["tool"], call["params"]))
    return await asyncio.gather(*tasks, return_exceptions=True)
```

### Pipeline Pattern (Sequential with Data Passing)

```python
async def pipeline_execute(registry, steps):
    context = {}
    for step in steps:
        server = registry.route(step["tool"])
        client = MCPClient(server["url"], server["api_key"])
        params = {**step["params"], **{k: context[v] for k, v in step.get("input_map", {}).items()}}
        result = await client.call_tool(step["tool"], params)
        if step.get("output_key"):
            context[step["output_key"]] = result
    return context
```

---

## 12. Health Check and Monitoring

### Server Health Endpoint

```python
@app.route("/health")
async def health_check():
    checks = {
        "status": "healthy",
        "uptime_seconds": time.time() - START_TIME,
        "tools_registered": len(TOOL_REGISTRY),
        "active_connections": CONNECTION_COUNTER,
        "last_request_at": LAST_REQUEST_TIME,
    }
    for tool_name, tool_fn in TOOL_REGISTRY.items():
        try:
            checks[f"tool_{tool_name}"] = "available"
        except Exception as e:
            checks[f"tool_{tool_name}"] = f"error: {e}"
            checks["status"] = "degraded"
    return json.dumps(checks)
```

### Prometheus Metrics Export

```python
from prometheus_client import Counter, Histogram, generate_latest

REQUEST_COUNT = Counter("mcp_requests_total", "Total requests", ["tool", "status"])
REQUEST_LATENCY = Histogram("mcp_request_duration_seconds", "Request latency", ["tool"])

@app.middleware("http")
async def metrics_middleware(request, call_next):
    tool = request.url.path.split("/")[-1]
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    REQUEST_COUNT.labels(tool=tool, status=response.status_code).inc()
    REQUEST_LATENCY.labels(tool=tool).observe(duration)
    return response

@app.route("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### Automated Health Monitor Script

```bash
#!/bin/bash
SERVERS=("http://localhost:8080" "http://localhost:8081" "http://localhost:8082")

for server in "${SERVERS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$server/health" --max-time 5)
    if [ "$status" != "200" ]; then
        echo "ALERT: $server is DOWN (HTTP $status)"
    else
        echo "OK: $server is healthy"
    fi
done
```

---

## 13. Configuration and Deployment

### Docker Compose Multi-Server Setup

```yaml
version: "3.8"
services:
  mcp-nmap:
    build: ./servers/nmap
    ports: ["8080:8080"]
    environment:
      - MCP_API_KEY=${MCP_API_KEY}
      - ALLOWED_TARGETS=10.0.0.0/8,192.168.0.0/16
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: "1.0"

  mcp-sqlmap:
    build: ./servers/sqlmap
    ports: ["8081:8080"]
    environment:
      - MCP_API_KEY=${MCP_API_KEY}
      - MAX_CONCURRENT=3

  mcp-gateway:
    build: ./gateway
    ports: ["443:443"]
    depends_on: [mcp-nmap, mcp-sqlmap]
    environment:
      - UPSTREAM_SERVERS=mcp-nmap:8080,mcp-sqlmap:8080
```

### Environment Configuration Schema

```python
from pydantic import BaseModel, Field

class MCPServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = Field(default=8080, ge=1024, le=65535)
    api_key: str = Field(min_length=32)
    allowed_targets: list[str] = []
    max_concurrent_requests: int = Field(default=5, ge=1, le=50)
    request_timeout_seconds: int = Field(default=30, ge=5, le=300)
    rate_limit_per_minute: int = Field(default=60, ge=1)
    log_level: str = "INFO"
    tls_cert_path: str | None = None
    tls_key_path: str | None = None
```

### Nginx Reverse Proxy Configuration

```nginx
upstream mcp_servers {
    server 127.0.0.1:8080 weight=5;
    server 127.0.0.1:8081 weight=3;
    server 127.0.0.1:8082 weight=2;
}

server {
    listen 443 ssl;
    server_name mcp.internal;
    ssl_certificate /etc/ssl/mcp.crt;
    ssl_certificate_key /etc/ssl/mcp.key;

    location /tools/ {
        proxy_pass http://mcp_servers;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 60s;
        limit_req zone=mcp_rate burst=10 nodelay;
    }

    location /health {
        proxy_pass http://mcp_servers;
        access_log off;
    }
}
```

---

## 14. Logging and Audit Trail

### Structured Audit Logger

```python
import json
import logging
from datetime import datetime

class AuditLogger:
    def __init__(self, log_file="audit.jsonl"):
        self.logger = logging.getLogger("mcp_audit")
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log_request(self, tool, params, user, result_status):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": tool,
            "params": {k: v for k, v in params.items() if k != "api_key"},
            "user": user,
            "status": result_status,
        }
        self.logger.info(json.dumps(entry))
```

### Log Rotation Configuration

```bash
# /etc/logrotate.d/mcp-server
/var/log/mcp/*.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 mcp mcp
    postrotate
        systemctl reload mcp-server
    endscripts
}
```

---

## 15. Server Lifecycle

### Graceful Startup with Dependency Checks

```python
#!/usr/bin/env python3
"""MCP server startup with health checks and graceful initialization."""
import asyncio
import logging
import os
import signal
import sys

log = logging.getLogger("mcp-server")

class MCPServer:
    def __init__(self):
        self.shutdown_event = asyncio.Event()
        self.tool_registry = {}

    async def check_dependencies(self):
        """Verify all required services are available before starting."""
        checks = {
            "REDIS": os.environ.get("REDIS_URL", "redis://localhost:6379"),
            "DATABASE": os.environ.get("DATABASE_URL", "postgresql://localhost/mcp"),
        }
        for name, url in checks.items():
            try:
                if name == "REDIS":
                    import redis
                    r = redis.from_url(url)
                    r.ping()
                elif name == "DATABASE":
                    import psycopg2
                    conn = psycopg2.connect(url)
                    conn.close()
                log.info("Dependency OK: %s", name)
            except Exception as e:
                log.error("Dependency FAIL: %s - %s", name, e)
                return False
        return True

    async def start(self):
        log.info("Running dependency checks...")
        if not await self.check_dependencies():
            log.error("Dependency checks failed. Aborting startup.")
            sys.exit(1)

        log.info("Registering signal handlers...")
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self.shutdown_event.set)

        log.info("MCP server started successfully")
        await self.shutdown_event.wait()
        log.info("Shutdown signal received, cleaning up...")

    def register_tool(self, name, handler, schema):
        self.tool_registry[name] = {"handler": handler, "schema": schema}

if __name__ == "__main__":
    server = MCPServer()
    asyncio.run(server.start())
```

### Graceful Shutdown Handler

```python
import asyncio
import logging

log = logging.getLogger("mcp-shutdown")

async def graceful_shutdown(server, timeout=30):
    """Drain in-flight requests and clean up resources."""
    log.info("Starting graceful shutdown (timeout=%ds)", timeout)

    # Stop accepting new connections
    server.close()
    await server.wait_closed()
    log.info("Stopped accepting new connections")

    # Wait for in-flight requests to complete
    try:
        await asyncio.wait_for(
            asyncio.gather(*asyncio.all_tasks(), return_exceptions=True),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        log.warning("Shutdown timeout reached, forcing exit")

    # Clean up resources
    await cleanup_database_connections()
    await cleanup_cache()
    log.info("Graceful shutdown complete")
```

---

## 16. Tool Registration Patterns

### Dynamic Tool Registry

```python
from typing import Any, Callable
from dataclasses import dataclass, field

@dataclass
class ToolDefinition:
    name: str
    description: str
    handler: Callable
    input_schema: dict
    requires_auth: bool = True
    rate_limit: int = 60
    timeout_seconds: int = 30
    tags: list[str] = field(default_factory=list)

class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition):
        if definition.name in self._tools:
            raise ValueError(f"Tool already registered: {definition.name}")
        self._tools[definition.name] = definition

    def get(self, name: str) -> ToolDefinition:
        if name not in self._tools:
            raise KeyError(f"Tool not found: {name}")
        return self._tools[name]

    def list_all(self) -> list[dict]:
        return [
            {"name": t.name, "description": t.description, "tags": t.tags}
            for t in self._tools.values()
        ]

    def list_by_tag(self, tag: str) -> list[ToolDefinition]:
        return [t for t in self._tools.values() if tag in t.tags]

# Usage
registry = ToolRegistry()
registry.register(ToolDefinition(
    name="run_nmap",
    description="Execute nmap scan",
    handler=handle_nmap,
    input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
    tags=["network", "scanner"],
))
```

---

## 17. Error Handling Patterns

### Structured Error Responses

```python
from enum import Enum
from dataclasses import dataclass
import json

class ErrorCode(Enum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    AUTH_FAILED = "AUTH_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    TIMEOUT = "TIMEOUT"
    SCOPE_DENIED = "SCOPE_DENIED"

@dataclass
class MCPError:
    code: ErrorCode
    message: str
    detail: str = ""
    retry_after: int | None = None

    def to_response(self):
        response = {
            "error": self.code.value,
            "message": self.message,
        }
        if self.detail:
            response["detail"] = self.detail[:200]
        if self.retry_after is not None:
            response["retry_after"] = self.retry_after
        return json.dumps(response)

# Usage in tool handler
async def call_tool(name: str, arguments: dict):
    try:
        tool = registry.get(name)
    except KeyError:
        return MCPError(ErrorCode.TOOL_NOT_FOUND, f"Unknown tool: {name}").to_response()

    try:
        validated = validate_input(tool.input_schema, arguments)
    except ValueError as e:
        return MCPError(ErrorCode.VALIDATION_ERROR, str(e)).to_response()
```

### Error Recovery Middleware

```python
import asyncio
import logging

log = logging.getLogger("mcp-errors")

async def error_recovery_middleware(tool_name, arguments, handler):
    """Wrap tool execution with retry and fallback logic."""
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            return await handler(arguments)
        except asyncio.TimeoutError:
            log.warning("Tool %s timed out (attempt %d/%d)", tool_name, attempt + 1, max_retries + 1)
            if attempt == max_retries:
                return {"error": "timeout", "tool": tool_name, "attempts": attempt + 1}
        except ConnectionError as e:
            log.warning("Connection error in %s: %s", tool_name, e)
            if attempt < max_retries:
                await asyncio.sleep(2 ** attempt)
            else:
                return {"error": "connection_failed", "tool": tool_name}
        except Exception as e:
            log.error("Unexpected error in %s: %s", tool_name, e, exc_info=True)
            return {"error": "execution_failed", "tool": tool_name, "detail": str(e)[:120]}
```

---

## 18. Transport Protocols

### SSE (Server-Sent Events) Transport

```python
import asyncio
import json
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

app = FastAPI()

@app.get("/sse")
async def sse_endpoint(request: Request):
    """SSE transport for streaming MCP responses."""
    async def event_generator():
        while True:
            if await request.is_disconnected():
                break
            # Check for pending tool results
            result = await get_next_result(request)
            if result:
                data = json.dumps(result)
                yield f"data: {data}\n\n"
            await asyncio.sleep(0.1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
```

### WebSocket Transport

```python
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import json

app = FastAPI()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            raw = await websocket.receive_text()
            message = json.loads(raw)
            tool_name = message.get("tool")
            arguments = message.get("arguments", {})

            result = await call_tool(tool_name, arguments)
            await websocket.send_text(json.dumps(result))
    except WebSocketDisconnect:
        pass
```

---

## 19. Authentication Patterns

### JWT Authentication

```python
import jwt
import os
import time
from functools import wraps

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 3600

def create_token(user_id: str, scopes: list[str]) -> str:
    payload = {
        "sub": user_id,
        "scopes": scopes,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRY_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

def require_scope(scope: str):
    def decorator(handler):
        @wraps(handler)
        async def wrapper(request, *args, **kwargs):
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            payload = verify_token(token)
            if scope not in payload.get("scopes", []):
                raise PermissionError(f"Missing required scope: {scope}")
            return await handler(request, *args, **kwargs)
        return wrapper
    return decorator
```

### OAuth2 Client Credentials

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        return payload
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
```

---

## 20. Rate Limiting Advanced

### Token Bucket Rate Limiter

```python
import time
import threading
from collections import defaultdict

class TokenBucketLimiter:
    def __init__(self, rate: float, capacity: int):
        self.rate = rate          # Tokens per second
        self.capacity = capacity  # Max tokens
        self._buckets: dict[str, dict] = defaultdict(
            lambda: {"tokens": capacity, "last_refill": time.monotonic()}
        )
        self._lock = threading.Lock()

    def allow(self, client_id: str) -> bool:
        with self._lock:
            now = time.monotonic()
            bucket = self._buckets[client_id]
            elapsed = now - bucket["last_refill"]
            bucket["tokens"] = min(
                self.capacity,
                bucket["tokens"] + elapsed * self.rate,
            )
            bucket["last_refill"] = now

            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                return True
            return False

# Usage: 10 requests per second, burst of 20
limiter = TokenBucketLimiter(rate=10, capacity=20)
```

### Sliding Window Rate Limiter

```python
import time
from collections import defaultdict

class SlidingWindowLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._windows: dict[str, list[float]] = defaultdict(list)

    def check(self, client_id: str) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - self.window_seconds
        self._windows[client_id] = [
            t for t in self._windows[client_id] if t > cutoff
        ]
        if len(self._windows[client_id]) >= self.max_requests:
            oldest = self._windows[client_id][0]
            retry_after = int(oldest + self.window_seconds - now) + 1
            return False, retry_after
        self._windows[client_id].append(now)
        return True, 0
```

---

## 21. MCP Protocol Testing

### Protocol Compliance Tests

```python
#!/usr/bin/env python3
"""Test MCP server protocol compliance."""
import json
import httpx
import asyncio

async def test_protocol_compliance(base_url, api_key):
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    results = []

    async with httpx.AsyncClient(base_url=base_url, headers=headers, timeout=10) as client:
        # Test 1: List tools endpoint
        resp = await client.get("/tools")
        results.append({
            "test": "list_tools",
            "status": resp.status_code,
            "valid_json": True,
        })

        # Test 2: Call non-existent tool
        resp = await client.post("/tools/nonexistent", json={})
        results.append({
            "test": "unknown_tool_error",
            "status": resp.status_code,
            "returns_error": "error" in resp.text.lower(),
        })

        # Test 3: Missing required parameter
        resp = await client.post("/tools/run_nmap", json={})
        results.append({
            "test": "missing_param_validation",
            "status": resp.status_code,
            "validates_input": resp.status_code in (400, 422),
        })

        # Test 4: Invalid JSON body
        resp = await client.post("/tools/run_nmap", content="not json", headers={"Content-Type": "application/json"})
        results.append({
            "test": "invalid_json_handling",
            "status": resp.status_code,
            "graceful_error": resp.status_code in (400, 422),
        })

        # Test 5: Health endpoint
        resp = await client.get("/health")
        results.append({
            "test": "health_endpoint",
            "status": resp.status_code,
        })

    return results

asyncio.run(test_protocol_compliance("http://localhost:8080", "test-key"))
```

### Concurrent Request Testing

```python
#!/usr/bin/env python3
"""Test MCP server behavior under concurrent load."""
import asyncio
import httpx
import time

async def concurrent_test(url, api_key, num_requests=50):
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    payload = {"target": "192.168.1.1", "ports": "80"}

    start = time.time()
    async with httpx.AsyncClient(timeout=30) as client:
        tasks = [
            client.post(f"{url}/tools/run_nmap", json=payload, headers=headers)
            for _ in range(num_requests)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    duration = time.time() - start
    successes = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code == 200)
    errors = sum(1 for r in responses if isinstance(r, Exception))
    rate_limited = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code == 429)

    print(f"Concurrent test: {num_requests} requests in {duration:.1f}s")
    print(f"  Successes: {successes}")
    print(f"  Rate limited: {rate_limited}")
    print(f"  Errors: {errors}")

asyncio.run(concurrent_test("http://localhost:8080", "test-key"))
```

---

## 22. MCP Server Security Hardening

### TLS Configuration

```python
import ssl
import os

def create_tls_context():
    """Create a hardened TLS context for MCP server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(
        certfile=os.environ["TLS_CERT_PATH"],
        keyfile=os.environ["TLS_KEY_PATH"],
    )
    # Hardened cipher suite
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    )
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    return ctx
```

### Input Schema Validation

```python
import jsonschema
from typing import Any

def validate_tool_input(schema: dict, arguments: dict[str, Any]) -> dict[str, Any]:
    """Validate tool input against JSON schema. Raise on invalid."""
    try:
        jsonschema.validate(instance=arguments, schema=schema)
    except jsonschema.ValidationError as e:
        raise ValueError(f"Input validation failed: {e.message}")

    # Additional safety checks beyond schema
    for key, value in arguments.items():
        if isinstance(value, str):
            # Reject shell metacharacters
            dangerous = set(";|&`$><\n\r\x00")
            found = dangerous & set(value)
            if found:
                raise ValueError(f"Field {key!r} contains dangerous characters: {found}")

    return arguments
```

### Request Size Limiting Middleware

```python
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()
MAX_REQUEST_SIZE = 1_000_000  # 1MB

@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_SIZE:
        raise HTTPException(status_code=413, detail="Request too large")
    return await call_next(request)
```

---

## 23. MCP Server Testing Automation

### End-to-End Integration Test

```python
#!/usr/bin/env python3
"""Full end-to-end integration test for MCP server."""
import asyncio
import httpx
import json

async def e2e_test(base_url, api_key):
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    async with httpx.AsyncClient(base_url=base_url, headers=headers, timeout=30) as client:
        # Step 1: Health check
        resp = await client.get("/health")
        assert resp.status_code == 200, f"Health check failed: {resp.status_code}"

        # Step 2: List available tools
        resp = await client.get("/tools")
        tools = resp.json().get("tools", [])
        assert len(tools) > 0, "No tools registered"
        print(f"[OK] {len(tools)} tools registered")

        # Step 3: Test a tool call with valid input
        resp = await client.post("/tools/run_nmap", json={
            "target": "192.168.1.1", "ports": "80", "scan_type": "connect",
        })
        assert resp.status_code == 200, f"Tool call failed: {resp.status_code}"

        print("[PASS] All e2e tests passed")

asyncio.run(e2e_test("http://localhost:8080", "test-key"))
```

### Fuzz Testing for MCP Endpoints

```python
#!/usr/bin/env python3
"""Fuzz test MCP server endpoints with random inputs."""
import httpx
import random
import string
import asyncio

def random_string(length=20):
    return "".join(random.choices(string.printable, k=length))

async def fuzz_endpoint(url, api_key, iterations=100):
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    errors = []

    async with httpx.AsyncClient(timeout=10) as client:
        for i in range(iterations):
            payload = {
                "target": random_string(),
                "ports": random.choice(["80", "abc", "99999", "", random_string(5)]),
            }
            try:
                resp = await client.post(f"{url}/tools/run_nmap", json=payload, headers=headers)
                if resp.status_code == 500:
                    errors.append({"payload": payload, "body": resp.text[:200]})
            except Exception as e:
                errors.append({"payload": payload, "error": str(e)})

    print(f"Fuzzed {iterations} requests, {len(errors)} server errors")

asyncio.run(fuzz_endpoint("http://localhost:8080", "test-key"))
```

---

## 24. MCP Server Metrics and Observability

### Tool Usage Metrics

```python
from collections import defaultdict
from datetime import datetime

class ToolMetrics:
    def __init__(self):
        self._calls = defaultdict(list)
        self._errors = defaultdict(int)

    def record_call(self, tool_name, duration_ms, success=True):
        self._calls[tool_name].append({
            "timestamp": datetime.utcnow().isoformat(),
            "duration_ms": duration_ms,
            "success": success,
        })
        if not success:
            self._errors[tool_name] += 1

    def get_summary(self):
        summary = {}
        for tool, calls in self._calls.items():
            durations = [c["duration_ms"] for c in calls]
            summary[tool] = {
                "total_calls": len(calls),
                "errors": self._errors.get(tool, 0),
                "avg_duration_ms": sum(durations) / len(durations) if durations else 0,
                "p95_duration_ms": sorted(durations)[int(len(durations) * 0.95)] if durations else 0,
            }
        return summary
```

### Health Check with Dependency Verification

```python
async def deep_health_check():
    """Comprehensive health check including all dependencies."""
    checks = {}

    # Check database connectivity
    try:
        import psycopg2
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        conn.close()
        checks["database"] = "healthy"
    except Exception as e:
        checks["database"] = f"unhealthy: {str(e)[:50]}"

    # Check Redis connectivity
    try:
        import redis
        r = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost"))
        r.ping()
        checks["redis"] = "healthy"
    except Exception as e:
        checks["redis"] = f"unhealthy: {str(e)[:50]}"

    # Check tool binaries
    for tool in ["nmap", "nikto", "sqlmap"]:
        import shutil
        checks[f"tool_{tool}"] = "available" if shutil.which(tool) else "missing"

    overall = "healthy" if all(v == "healthy" or v == "available" for v in checks.values()) else "degraded"
    return {"status": overall, "checks": checks}
```

---

## 25. MCP Server Versioning and Compatibility

### API Version Header Handler

```python
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()
SUPPORTED_VERSIONS = ["1.0", "1.1", "2.0"]

@app.middleware("http")
async def version_middleware(request: Request, call_next):
    version = request.headers.get("X-MCP-Version", "1.0")
    if version not in SUPPORTED_VERSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported API version: {version}. Supported: {SUPPORTED_VERSIONS}",
        )
    request.state.api_version = version
    response = await call_next(request)
    response.headers["X-MCP-Version"] = version
    return response
```

### Backward Compatibility Layer

```python
def adapt_request(payload, from_version, to_version="2.0"):
    """Transform request payload between API versions."""
    adapted = dict(payload)

    if from_version == "1.0" and to_version == "2.0":
        # v1.0 used "ip" field, v2.0 uses "target"
        if "ip" in adapted and "target" not in adapted:
            adapted["target"] = adapted.pop("ip")
        # v1.0 used "type", v2.0 uses "scan_type"
        if "type" in adapted and "scan_type" not in adapted:
            adapted["scan_type"] = adapted.pop("type")

    return adapted
```
