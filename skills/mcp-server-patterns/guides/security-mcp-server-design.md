# Security MCP Server Design Guide

## 1. Tool Selection Criteria

### Which Tools Benefit Most from MCP Wrapping

Not every Kali tool deserves an MCP wrapper. Prioritize tools that meet most of these criteria:

**High-value wrapping candidates:**

| Criterion | Explanation |
|-----------|-------------|
| Structured output | Tool already produces JSON, XML, or parseable output (nmap XML, nikto JSON, gobuster's `-o json`) — parsing is straightforward |
| Frequent invocation | Tools called many times per session benefit from a stable API instead of ad-hoc shell construction each time |
| Parameter complexity | Tools with many flags and combinations benefit from a schema that enforces valid parameter sets (sqlmap, nuclei) |
| Dangerous without guardrails | Tools that can cause real damage if misused (sqlmap, hydra) benefit from scope enforcement and flag allowlisting built into the wrapper |
| Cross-session reuse | Tools used across multiple agent sessions (nmap, whatweb, amass) benefit from a persistent shared API |

**Recommended first wrappers** for a security agent:

- `nmap` — structured XML output, frequent use, scope validation critical
- `nikto` — JSON output mode, web scanning, well-defined parameters
- `gobuster` / `ffuf` — directory/subdomain fuzzing, allowlistable wordlist paths
- `whatweb` — JSON output, passive recon, safe to expose broadly
- `wapiti` — web vulnerability scanner, structured JSON reports

### Tools That Should NOT Be Wrapped

Some tools are too dangerous or too interactive to expose through an MCP API:

| Tool | Reason Not to Wrap |
|------|-------------------|
| `metasploit` (`msfconsole`) | Interactive REPL; exploit execution requires multi-turn state; RCE blast radius is too high for an API surface |
| `sqlmap` with `--os-shell` flag | OS shell access via API is unconditional RCE exposure — if the flag is needed, use it interactively with human review |
| `beef-xss` | Requires a persistent browser hook process; not suitable for stateless API calls |
| `aircrack-ng` / deauthentication tools | Legal and safety risk; require physical-layer isolation not enforceable via API |
| Any exploit payload generator (`msfvenom`) | Output is executable malware — generating on demand via API with no human review is high-risk |

**Rule of thumb**: If executing the tool incorrectly could cause irreversible damage to the target (data destruction, full system compromise, legal violation), require human review before execution rather than wrapping it.

---

## 2. MCP Protocol Fundamentals

### Tool Definition Anatomy

Every MCP tool is defined with four fields the AI client reads to decide how to call it:

```python
Tool(
    name="run_nmap",           # Identifier used in tool call: tools/call
    description=(
        "Run an nmap port scan against an authorized IPv4 address. "
        "Returns open ports, service names, and versions as structured JSON. "
        "Only targets in the authorized scope are accepted."
    ),
    inputSchema={              # JSON Schema — the AI constructs args to match this
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IPv4 address (must be in authorized engagement scope)",
                "pattern": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
            },
            "ports": {
                "type": "string",
                "description": "Port range (e.g. '80,443', '1-1024'). Default: top 100 ports.",
                "default": "top100",
            },
        },
        "required": ["target"],
        "additionalProperties": False,   # Reject undeclared fields
    },
)
```

**Write descriptions that constrain**: The `description` field influences how the AI chooses to call the tool. Including scope constraints ("Only authorized targets"), format expectations, and output structure in the description reduces misuse and improves output quality.

**`additionalProperties: false`**: Always include this. It causes JSON Schema validators to reject payloads with undeclared fields, closing a category of schema bypass attempts.

### How Claude Calls Tools

1. Claude receives the tool list at session start via `tools/list`
2. During a task, Claude decides a tool is needed and constructs a JSON argument object matching the `inputSchema`
3. Claude sends `tools/call` with `{"name": "run_nmap", "arguments": {...}}`
4. The MCP server validates arguments against the schema, executes the handler, returns a result
5. Claude reads the result and continues reasoning

The AI cannot see your handler code — only the `name`, `description`, and `inputSchema`. Write these to communicate security constraints to the AI, not just to document the API.

### stdio vs HTTP Transport

**stdio transport** (default for Claude Desktop):

```
Claude Desktop ←→ stdin/stdout ←→ MCP server process
```

- No network socket; the server process is a child of the Claude Desktop process
- Authentication is implicit: only the parent process can write to stdin
- No TLS needed; OS process isolation provides the security boundary
- Limitation: single client only; cannot share across multiple agent sessions

**HTTP/SSE transport** (remote/multi-client):

```
Claude Agent ←→ HTTPS POST ←→ MCP server (FastAPI/uvicorn)
                              ← Server-Sent Events for streaming
```

- Exposed as a network service; any reachable client can attempt to connect
- Requires explicit authentication (API key header, mTLS, or OAuth)
- TLS mandatory — deploy behind nginx/caddy with valid certificate
- Supports multiple concurrent clients; suitable for shared team infrastructure

**Security implication**: When you move from stdio to HTTP, you promote the MCP server from a local process to a network service. Every security control in this guide becomes mandatory rather than advisory.

### Error Handling Protocol

MCP defines a standard error response format. Use it consistently:

```python
# Successful tool execution
return CallToolResult(
    content=[TextContent(type="text", text=json.dumps({"result": data}))]
)

# Tool execution failure (validation error, subprocess error, etc.)
return CallToolResult(
    content=[TextContent(type="text", text=json.dumps({
        "error": "validation_failed",
        "detail": "Target IP is not in authorized scope",  # safe detail — no internals
    }))]
)
```

Never raise unhandled exceptions from a tool handler. Catch at the handler boundary, log internally, return a sanitized error.

---

## 3. Secure Wrapping Principles

The following seven rules are non-negotiable for any MCP server wrapping a shell tool. Treat any violation as a critical security defect.

### Rule 1: Never Use `shell=True`

```python
# WRONG — command injection via 'target' if validation is bypassed
proc = subprocess.run(f"nmap -sV {target}", shell=True, ...)

# CORRECT — arguments as a list; no shell interpretation possible
proc = subprocess.run(["nmap", "-sV", target], ...)
```

`shell=True` passes the command to `/bin/sh -c`. Any shell metacharacter in `target` (`; | && $() `` \n`) executes as a shell command. Even if you validate inputs, defense in depth requires that the subprocess layer is also safe.

### Rule 2: Always Validate Inputs Against Schema

JSON Schema validation (via `jsonschema` library or the MCP SDK's built-in validation) catches type errors and missing fields. But schema validation alone is insufficient for security tools — you must also validate semantic correctness:

- IP address: parse with `ipaddress.ip_address()` after regex match
- URL: parse with `urlparse()` and check scheme allowlist
- Port: cast to `int`, check `1 <= port <= 65535`
- File paths: resolve with `os.path.realpath()`, check prefix against allowlist

Schema validation is the first gate. Semantic validation is the second. Both must pass.

### Rule 3: Always Use Allowlists, Never Denylists

```python
# WRONG — denylist approach; easy to bypass with encoding or new metacharacters
FORBIDDEN = {";", "|", "&", "`"}
if any(c in target for c in FORBIDDEN):
    raise ValueError("Injection detected")

# CORRECT — allowlist approach; only known-safe characters pass
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
if not IP_PATTERN.match(target):
    raise ValueError("Target must be an IPv4 address")
```

A denylist of "bad characters" will always miss edge cases: Unicode homoglyphs, URL encoding, null bytes, newlines. An allowlist defines exactly what is permitted and rejects everything else.

### Rule 4: Always Set Subprocess Timeout

```python
# WRONG — unbounded execution; denial of service via slow target
proc = subprocess.run(["nmap", target], capture_output=True)

# CORRECT — hard timeout; subprocess killed if it exceeds limit
try:
    proc = subprocess.run(
        ["nmap", "-sV", "--host-timeout=30s", target],
        capture_output=True,
        text=True,
        timeout=120,   # Python-level hard kill after 120 seconds
    )
except subprocess.TimeoutExpired:
    proc.kill()
    raise RuntimeError("Scan timed out after 120 seconds")
```

Without a timeout, a single tool call can block the server indefinitely. Set both a tool-level flag (e.g., nmap's `--host-timeout`) and a Python `subprocess.run(timeout=...)` as a backstop.

### Rule 5: Always Sanitize Outputs Before Returning

```python
# WRONG — raw stdout may contain internal paths, version strings, system info
return {"output": proc.stdout}

# CORRECT — parse and restructure; include only intended fields
return {
    "target": validated_ip,
    "open_ports": parse_nmap_xml(proc.stdout),   # structured extraction
    "scan_duration_ms": elapsed_ms,
    "status": "completed",
}
```

Parse tool output into a structured dict containing only the fields the AI needs. Raw stdout can leak: the server's hostname, file paths in error messages, installed software versions, or network topology details.

### Rule 6: Never Expose Internal Paths in Errors

```python
# WRONG — reveals server filesystem layout, Python version, file paths
except Exception as e:
    return {"error": str(e)}  # could be: "[Errno 2] No such file or directory: '/home/kali/tools/nmap'"

# CORRECT — sanitized, generic error with internal logging
except FileNotFoundError:
    log.error("nmap binary not found: %s", exc_info=True)
    return {"error": "tool_unavailable", "detail": "Required tool is not installed"}
except Exception as exc:
    log.error("Unexpected error in handle_nmap: %s", exc, exc_info=True)
    return {"error": "tool_execution_failed", "detail": "Scan could not be completed"}
```

### Rule 7: Always Log Invocations Server-Side

Every tool call must produce a server-side log entry containing: timestamp, client identifier, tool name, input parameters (sanitized — no passwords/tokens), and outcome. This enables forensic review and abuse detection.

```python
log.info(
    "Tool invocation: client=%s tool=%s target=%s ports=%s outcome=%s",
    client_id, tool_name, validated_target, validated_ports, outcome,
)
```

Never log raw user-provided input before validation — it could contain injection strings that corrupt log parsers.

---

## 4. Implementation Walkthrough — Secure nmap MCP Server

### Step 1: Design the Schema

Start with the tool definition. Define only the parameters the AI needs, with strict types and patterns. Use `enum` for parameters with a fixed set of valid values.

```
target     → string, pattern: IPv4 regex, required
ports      → string, pattern: port range regex, optional, default "top100"
scan_type  → string, enum: ["syn","connect","udp","version"], optional, default "connect"
```

Set `additionalProperties: false` to reject extra fields.

### Step 2: Implement Input Validation

Write a validation function for each parameter that:
1. Checks JSON Schema type (already done by MCP SDK)
2. Parses the value into a Python type (e.g., `ipaddress.ip_address()`)
3. Checks scope (e.g., `addr in authorized_range`)
4. Returns the validated, normalized value or raises `ValueError`

All three steps must pass before touching subprocess.

### Step 3: Wrap the Subprocess

Build the command as a list. Never concatenate strings. Apply the validated values directly:

```python
cmd = ["nmap", "-oX", "-", port_flag] + scan_flags + [str(validated_ip)]
```

Pass `timeout=120` and `capture_output=True`. Handle `TimeoutExpired` explicitly.

### Step 4: Handle Errors at the Boundary

Wrap the entire handler body in a `try/except` block. Catch specific exceptions first (ValueError, TimeoutExpired, FileNotFoundError), then catch Exception as a backstop. Log internally with `exc_info=True`. Return sanitized error dicts.

### Step 5: Add Authentication

For HTTP transport: load `MCP_API_KEY` from environment at startup, fail if missing. Implement middleware that reads `X-API-Key` header, uses `hmac.compare_digest()` for constant-time comparison, returns 401 on failure, and logs the result (without the key value).

### Step 6: Test the Implementation

Before declaring the server ready, run TC-MP-001 through TC-MP-005 in sequence. Specifically:
- Confirm `shell=True` is absent via `grep`
- Confirm all injection payloads from TC-MP-002 return errors without executing
- Confirm all auth bypass attempts from TC-MP-003 return 401
- Confirm rate limits from TC-MP-004 trigger at the configured threshold

---

## 5. Testing Your MCP Server

### Functional Testing

Verify correct behavior with valid inputs:
1. Call each tool with the minimum required parameters — confirm it returns a result
2. Call each tool with all optional parameters — confirm all paths execute
3. Call each tool against a known target — confirm output matches expected structure

```bash
# Functional test with known-good nmap target
python3 -c "
import subprocess, json
# Use MCP stdio client or direct handler test
result = run_nmap_handler({'target': '127.0.0.1', 'ports': '22,80', 'scan_type': 'connect'})
assert 'open_ports' in result or 'raw_xml' in result, 'Missing output structure'
print('Functional test: PASS')
"
```

### Security Testing

Run the full injection and auth test suite from TC-MP-002 and TC-MP-003. Additionally:

- **Schema abuse**: Send payloads with every field set to `null`, every field set to an empty string, and fields with 10,000-character strings. Verify none cause unhandled exceptions.
- **Encoding bypass**: Try URL-encoded injection strings (`%3B` for `;`, `%26` for `&`). Verify validation rejects them (the decoded or encoded form should not matter — IP pattern match will reject non-IP strings).
- **Concurrent requests**: Send 20 simultaneous requests. Verify the server handles them without crashing and rate limiting fires correctly.

### Load Testing

```bash
# Simple concurrency test with GNU parallel
seq 20 | parallel -j 20 \
  curl -s -X POST http://localhost:8080/tools/run_nmap \
    -H "X-API-Key: $MCP_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"target": "192.168.56.101", "ports": "80"}' \
  '2>&1' | grep -c '"error"'
```

Verify: (1) server does not crash under concurrent load, (2) rate limiting fires after the configured threshold, (3) all responses are valid JSON.

---

## 6. Deployment and Maintenance

### Configuration Management

Store all configuration in environment variables — never in source code:

| Variable | Purpose |
|----------|---------|
| `MCP_API_KEY` | Authentication token for HTTP transport |
| `MCP_AUTHORIZED_RANGES` | Comma-separated CIDRs for scope enforcement |
| `MCP_RATE_LIMIT_PER_CLIENT` | Requests per window per client |
| `MCP_RATE_LIMIT_WINDOW` | Window size in seconds |
| `MCP_LOG_FILE` | Server-side log file path |
| `MCP_TOOL_TIMEOUT` | Subprocess timeout in seconds |

Load all variables at startup and fail immediately if any required variable is missing:

```python
required_vars = ["MCP_API_KEY", "MCP_AUTHORIZED_RANGES"]
missing = [v for v in required_vars if not os.environ.get(v)]
if missing:
    raise RuntimeError(f"Required environment variables missing: {missing}")
```

### Logging Strategy

Log the following events at the specified levels:

| Event | Level | Fields to Include |
|-------|-------|------------------|
| Server startup | INFO | version, configured ranges, rate limits |
| Tool invocation | INFO | client_id, tool_name, validated_target, timestamp |
| Validation failure | WARNING | client_id, tool_name, failure_reason, input_hash |
| Auth failure | WARNING | client_id, remote_addr, timestamp |
| Rate limit hit | WARNING | client_id, current_count, window_seconds |
| Subprocess timeout | ERROR | tool_name, target, timeout_value |
| Unhandled exception | ERROR | tool_name, exception_class, stack_trace (internal log only) |

Rotate logs daily. Retain for at least 30 days for forensic purposes.

### Updating Tool Versions

When the underlying tool (nmap, nikto) is updated on the Kali system:
1. Re-run TC-MP-001 (functional test) — verify output schema is still valid
2. Check for new flags that might need allowlist updates
3. Check for deprecated flags in the allowed set
4. Update the tool's `description` field if behavior changed
5. Increment the server version string

### Monitoring for Abuse

Review server logs daily for:
- High rate of auth failures from a single IP — potential credential stuffing
- Repeated scope violation attempts — reconnaissance of the enforcement boundary
- Unusual invocation patterns (same target, many ports, rapid succession) — may indicate the AI agent is misbehaving
- Subprocess timeout patterns — may indicate DoS attempts or poorly scoped targets

Set up a cron job or log watcher to alert on more than 10 auth failures per hour from any single source.
