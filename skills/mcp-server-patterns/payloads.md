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
