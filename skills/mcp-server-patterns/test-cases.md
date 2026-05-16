# MCP Server Patterns — Test Cases

## TC-MP-001: Basic Tool Wrapping — nmap MCP Server

**Objective**: Implement and verify a working nmap MCP server tool that accepts a target IP, executes an nmap scan, and returns structured JSON output.

**Type**: Building

**Prerequisites**:
- Kali Linux 2025-2 ARM64 environment
- Python 3.11+ with `mcp` library installed (`pip install mcp`)
- nmap installed and accessible at `/usr/bin/nmap`
- Authorized test target available (e.g., lab VM at 192.168.56.101)

### Setup

```bash
pip install mcp
mkdir -p ~/mcp-nmap-server
cp /path/to/scaffold/server.py ~/mcp-nmap-server/server.py
export MCP_API_KEY="test-api-key-$(openssl rand -hex 8)"
```

### Steps

1. Write the MCP server with a `run_nmap` tool using the scaffold from `payloads.md` Section 2a.
2. Start the server in stdio mode: `python server.py`
3. Send a valid tool call via MCP client or raw stdio:
   ```json
   {"method": "tools/call", "params": {"name": "run_nmap", "arguments": {"target": "192.168.56.101", "ports": "top100", "scan_type": "connect"}}}
   ```
4. Capture and examine the response.
5. Verify the subprocess invocation in server logs — confirm no `shell=True` in the process table.
6. Run a second call with `ports: "80,443,8080"` and `scan_type: "version"`.

### Expected Results

- Response is a JSON object with keys: `target`, `scan_type`, `ports_requested`, `raw_xml`, `stderr_summary`
- `target` field matches the requested IP
- `raw_xml` contains valid nmap XML with at least one `<host>` element
- Server log shows the executed command as a list (e.g., `['nmap', '-oX', '-', '--top-ports=100', '-sT', '192.168.56.101']`)
- No `shell=True` visible in `/proc/<pid>/cmdline` or `ps aux` output

### Verification

```bash
# Check server log for subprocess invocation format
grep "cmd=" /var/log/mcp-security-server.log | tail -5

# Confirm nmap process was launched without shell
ps aux | grep nmap

# Validate response structure
python3 -c "
import json, sys
data = json.load(sys.stdin)
assert 'target' in data
assert 'raw_xml' in data
assert '<host' in data['raw_xml']
print('PASS: response structure valid')
"
```

---

## TC-MP-002: Input Validation — Rejection of Invalid and Malicious Inputs

**Objective**: Verify that the MCP server's input validation layer correctly rejects invalid IP addresses, out-of-scope targets, and injection strings before any subprocess execution occurs.

**Type**: Security Testing

**Prerequisites**:
- Running MCP server from TC-MP-001
- Valid API key set in `MCP_API_KEY`
- Audit logging enabled (server log file writable)

### Setup

```bash
# Record current nmap invocation count to detect if any validation failures leak to subprocess
BEFORE=$(grep -c "subprocess.run" /var/log/mcp-security-server.log 2>/dev/null || echo 0)
```

### Steps

1. Send each of the following payloads and record the HTTP status code and response body:

   **Invalid IP format:**
   ```json
   {"target": "not-an-ip", "ports": "80"}
   ```

   **Out-of-scope target:**
   ```json
   {"target": "8.8.8.8", "ports": "80"}
   ```

   **Semicolon injection:**
   ```json
   {"target": "192.168.1.1; id", "ports": "80"}
   ```

   **Command substitution injection:**
   ```json
   {"target": "$(cat /etc/passwd)", "ports": "80"}
   ```

   **Backtick injection:**
   ```json
   {"target": "`id`", "ports": "80"}
   ```

   **Newline injection:**
   ```json
   {"target": "192.168.1.1\nid", "ports": "80"}
   ```

   **Invalid port specification:**
   ```json
   {"target": "192.168.56.101", "ports": "abc;id"}
   ```

   **Wrong type for target:**
   ```json
   {"target": 12345, "ports": "80"}
   ```

2. For each payload, verify the response contains an error field and no scan output.
3. After all tests, check nmap invocation count in logs.

### Expected Results

- All 8 payloads return an error response with an `error` key
- None of the error responses contain: file paths, stack traces, or system usernames
- Nmap subprocess invocation count in logs does NOT increase during this test (validation fires before subprocess)
- Error responses are generic: `"invalid_target"`, `"scope_violation"`, `"validation_error"` — not detailed exception messages

### Verification

```bash
# Confirm subprocess count did not increase
AFTER=$(grep -c "subprocess.run" /var/log/mcp-security-server.log 2>/dev/null || echo 0)
if [ "$AFTER" -eq "$BEFORE" ]; then
  echo "PASS: No subprocess executed during validation-failure tests"
else
  echo "FAIL: $((AFTER - BEFORE)) unexpected subprocess calls"
fi

# Confirm no stack traces in responses (run against saved response files)
grep -i "Traceback\|File \"\|line [0-9]" test-responses/*.json && echo "FAIL: stack trace leaked" || echo "PASS: no stack traces"
```

**Severity** (if validation fails): Critical

---

## TC-MP-003: Authentication and Authorization — API Key Validation

**Objective**: Verify that the MCP server's authentication layer correctly rejects unauthenticated requests, requests with wrong keys, and requests with malformed auth headers, while accepting valid authenticated requests.

**Type**: Security Testing

**Prerequisites**:
- MCP server running in HTTP/SSE mode on `localhost:8080`
- `MCP_API_KEY` set to a known value (`valid-test-key`)
- `curl` and `jq` available

### Setup

```bash
# Export the test API key
export VALID_KEY="valid-test-key"
export WRONG_KEY="wrong-key-$(openssl rand -hex 4)"
MCP_URL="http://localhost:8080/tools/run_nmap"
PAYLOAD='{"target": "192.168.56.101", "ports": "80"}'
```

### Steps

1. **Baseline — valid key** (expect: 200 or tool result):
   ```bash
   curl -s -w "\nHTTP:%{http_code}" -X POST "$MCP_URL" \
     -H "X-API-Key: $VALID_KEY" \
     -H "Content-Type: application/json" \
     -d "$PAYLOAD"
   ```

2. **Missing auth header** (expect: 401):
   ```bash
   curl -s -w "\nHTTP:%{http_code}" -X POST "$MCP_URL" \
     -H "Content-Type: application/json" \
     -d "$PAYLOAD"
   ```

3. **Empty key value** (expect: 401):
   ```bash
   curl -s -w "\nHTTP:%{http_code}" -X POST "$MCP_URL" \
     -H "X-API-Key: " \
     -H "Content-Type: application/json" \
     -d "$PAYLOAD"
   ```

4. **Wrong key** (expect: 401):
   ```bash
   curl -s -w "\nHTTP:%{http_code}" -X POST "$MCP_URL" \
     -H "X-API-Key: $WRONG_KEY" \
     -H "Content-Type: application/json" \
     -d "$PAYLOAD"
   ```

5. **Key with leading/trailing whitespace** (expect: 401):
   ```bash
   curl -s -w "\nHTTP:%{http_code}" -X POST "$MCP_URL" \
     -H "X-API-Key:  $VALID_KEY " \
     -H "Content-Type: application/json" \
     -d "$PAYLOAD"
   ```

6. **SQL injection in key field** (expect: 401, no SQL error):
   ```bash
   curl -s -w "\nHTTP:%{http_code}" -X POST "$MCP_URL" \
     -H "X-API-Key: ' OR '1'='1" \
     -H "Content-Type: application/json" \
     -d "$PAYLOAD"
   ```

7. Examine all 401 responses — verify they contain only `{"error": "unauthorized"}` with no additional detail.

### Expected Results

- Step 1 returns HTTP 200 with tool result
- Steps 2–6 all return HTTP 401
- All 401 responses have identical body: `{"error": "unauthorized"}` (no hint about which check failed)
- Server logs show "Auth failure" entries for steps 2–6 but do NOT log the received key values
- No 500 errors or stack traces from any step

### Verification

```bash
# Parse server auth log entries — confirm no key values logged
grep "Auth failure" /var/log/mcp-security-server.log | grep -v "key=" && echo "PASS" || echo "FAIL: key logged in auth failure"

# Confirm uniform 401 body
for response in auth-test-*.json; do
  body=$(cat "$response")
  [ "$body" = '{"error": "unauthorized"}' ] && echo "PASS: $response" || echo "FAIL: $response — unexpected body: $body"
done
```

**Severity** (if auth bypass found): Critical

---

## TC-MP-004: Rate Limiting — Throttling Enforcement

**Objective**: Verify that the MCP server enforces per-client and global rate limits, returns appropriate `429` responses with `retry_after` values, and does not allow limit bypass via header manipulation.

**Type**: Security Testing

**Prerequisites**:
- MCP server running with rate limits configured: 10 req/60s per client, 100 req/60s global
- Python 3.11+ with `httpx` installed
- Valid API key

### Setup

```bash
pip install httpx
export MCP_API_KEY="valid-test-key"
```

### Steps

1. **Baseline burst test** — Send 15 rapid requests with valid auth:
   ```python
   # Run rate_limit_test.py from payloads.md Section 7
   python3 rate_limit_test.py
   ```

2. **Verify first 10 succeed, requests 11–15 return 429.**

3. **Check `retry_after` field** — Confirm it is a positive integer (seconds to wait).

4. **X-Forwarded-For bypass attempt** — Resend after hitting limit, adding a spoofed IP header:
   ```bash
   curl -s -w "\nHTTP:%{http_code}" -X POST http://localhost:8080/tools/run_nmap \
     -H "X-API-Key: $MCP_API_KEY" \
     -H "X-Forwarded-For: 1.2.3.4" \
     -H "Content-Type: application/json" \
     -d '{"target": "192.168.56.101", "ports": "80"}'
   ```
   Expect: 429 (rate limit should be keyed on API key, not IP).

5. **Window reset** — Wait `retry_after + 5` seconds, then send one request. Expect: 200.

6. **Global limit test** — Use 12 different API keys, each sending 9 requests in rapid succession (total 108 requests). Expect: requests beyond global limit return 429.

### Expected Results

- Per-client limit: requests 1–10 succeed (200), requests 11+ return 429
- 429 response body: `{"error": "rate_limit_exceeded", "retry_after": <positive integer>}`
- `X-Forwarded-For` header does not bypass the per-client limit
- After the window resets, requests succeed again
- Global limit triggers when aggregate traffic exceeds threshold regardless of per-client status

### Verification

```bash
# Automated verification script
python3 -c "
import httpx, time

URL = 'http://localhost:8080/tools/run_nmap'
HEADERS = {'X-API-Key': 'valid-test-key', 'Content-Type': 'application/json'}
PAYLOAD = {'target': '192.168.56.101', 'ports': '80'}

results = []
for i in range(15):
    r = httpx.post(URL, json=PAYLOAD, headers=HEADERS, timeout=5)
    results.append(r.status_code)

success_count = results.count(200)
throttled_count = results.count(429)
print(f'Succeeded: {success_count}/15, Throttled: {throttled_count}/15')
assert success_count == 10, f'Expected 10 successes, got {success_count}'
assert throttled_count == 5, f'Expected 5 throttled, got {throttled_count}'
print('PASS: Rate limiting enforced correctly')
"
```

**Severity** (if rate limiting absent): High

---

## TC-MP-005: Full MCP Security Audit — Comprehensive Review

**Objective**: Perform a complete security review of a custom MCP server implementation, covering all attack surfaces: input validation, authentication, rate limiting, error disclosure, scope enforcement, and subprocess safety.

**Type**: Security Testing

**Prerequisites**:
- Complete MCP server implementation to audit (source code + running instance)
- Access to server logs
- All previous test cases (TC-MP-001 through TC-MP-004) completed

### Setup

```bash
# Clone or access the MCP server source
ls -la ~/mcp-security-server/

# Start the server with audit logging
MCP_AUDIT_LOG=/tmp/mcp-audit.log python server.py &
SERVER_PID=$!

# Set up test environment
export MCP_API_KEY="valid-test-key"
export MCP_URL="http://localhost:8080"
```

### Steps

**Phase 1 — Static Analysis (source code review):**

1. Grep for `shell=True` in all Python files:
   ```bash
   grep -rn "shell=True" ~/mcp-security-server/
   ```
   Expect: zero results.

2. Grep for direct string formatting into subprocess:
   ```bash
   grep -rn "subprocess.*f['\"]" ~/mcp-security-server/
   grep -rn "os\.system\|os\.popen\|commands\." ~/mcp-security-server/
   ```
   Expect: zero results.

3. Verify environment variable loading and absence of hardcoded keys:
   ```bash
   grep -rn "API_KEY\s*=\s*['\"]" ~/mcp-security-server/
   ```
   Expect: only `os.environ.get(...)` patterns.

**Phase 2 — Dynamic Testing (running server):**

4. Execute TC-MP-002 (input validation) — all payloads must return errors.
5. Execute TC-MP-003 (authentication) — all invalid auth must return 401.
6. Execute TC-MP-004 (rate limiting) — limits must be enforced.

7. **Out-of-scope target injection:**
   ```bash
   curl -s -X POST "$MCP_URL/tools/run_nmap" \
     -H "X-API-Key: $MCP_API_KEY" \
     -d '{"target": "1.1.1.1", "ports": "80"}'
   ```
   Expect: scope violation error, no nmap execution.

8. **Error disclosure audit** — trigger 5 different failure modes and inspect each response for internal path leakage:
   ```bash
   # Test each failure mode and check response
   for payload in '{"target": "999.999.999.999"}' '{"target": ""}' '{"ports": "80"}' '{"target": "192.168.56.101", "ports": "-1"}' '{"target": "192.168.56.101", "scan_type": "invalid"}'; do
     echo "--- Testing: $payload ---"
     curl -s -X POST "$MCP_URL/tools/run_nmap" \
       -H "X-API-Key: $MCP_API_KEY" \
       -H "Content-Type: application/json" \
       -d "$payload" | python3 -c "
import json,sys
r=json.load(sys.stdin)
text=json.dumps(r)
leaks=['Traceback','File \"','home/','root/','usr/local','line ']
found=[l for l in leaks if l in text]
print('LEAK DETECTED:',found) if found else print('PASS: no leakage')
"
   done
   ```

**Phase 3 — Audit Report:**

9. Document findings in severity table format.
10. Kill the audit server: `kill $SERVER_PID`

### Expected Results

- `grep shell=True` returns zero results
- All dynamic tests from TC-MP-002, TC-MP-003, TC-MP-004 pass
- Out-of-scope target (1.1.1.1) is rejected before execution
- No error response contains stack traces, internal paths, or system information
- Server logs show all tool invocations with client identifier, timestamp, and input hash

### Verification

```bash
# Generate audit summary
echo "=== MCP Security Audit Summary ==="
echo "1. shell=True check:       $(grep -rn 'shell=True' ~/mcp-security-server/ | wc -l) occurrences (expect: 0)"
echo "2. Hardcoded keys check:   $(grep -rn "API_KEY\s*=\s*['\"]" ~/mcp-security-server/ | wc -l) occurrences (expect: 0)"
echo "3. Auth failures tested:   5 scenarios"
echo "4. Injection tests:        8 payloads"
echo "5. Rate limit verified:    yes/no"
echo "6. Error disclosure:       0 leaks (expect: 0)"
echo "7. Scope enforcement:      yes/no"
echo ""
echo "Deploy recommendation: HOLD until all items show 0 or yes"
```

**Severity** (if critical issues found): Critical — block deployment
