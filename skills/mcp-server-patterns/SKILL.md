# Skill: MCP Server Patterns

> **Supplementary Files**:
> - `payloads.md` — Complete Python code templates, tool wrapping scaffolds, input validation snippets, auth middleware, rate limiting patterns, and MCP security testing commands
> - `test-cases.md` — Structured test cases covering tool wrapping verification, input validation enforcement, authentication testing, rate limiting, and full MCP security audit
> - `guides/security-mcp-server-design.md` — Deep-dive guide on tool selection, protocol fundamentals, secure wrapping principles, implementation walkthrough, testing, and deployment

## Description

Two complementary focuses drive this skill:

**Focus 1 — Building**: Wrapping Kali Linux security tools as MCP (Model Context Protocol) servers so the agent can call them programmatically via structured tool calls. This covers schema design, input validation, subprocess safety, structured output, authentication, and rate limiting for production-grade security tool APIs.

**Focus 2 — Testing**: Security auditing of MCP server implementations — authentication weakness, authorization gaps, input validation bypass, command injection via tool parameters, schema abuse, and information disclosure through error messages.

Runtime environment: Kali Linux 2025-2 ARM64.

MCP is Anthropic's open protocol for connecting AI models to external tools. An MCP server exposes tools, resources, and prompts that an AI agent calls. This skill treats MCP servers as both a force-multiplier for the agent (wrap tools, gain structured access) and as a target class (MCP servers are network services with real attack surfaces).

## Use Cases

- **Wrap nmap as an MCP tool**: Expose nmap's network scanning capability via a typed tool call with validated inputs, structured JSON output, and per-client rate limiting — enabling the agent to scan targets without constructing raw shell commands each time
- **Wrap sqlmap as an MCP tool**: Create a controlled sqlmap interface with target allowlisting, flag whitelisting, and output parsing, so the agent can invoke SQL injection testing through a safe, audited interface
- **Build a reusable security tool library for agents**: Assemble a suite of MCP tools (nmap, nikto, gobuster, sqlmap, whatweb) into a single MCP server that any agent session can connect to, establishing a persistent, authenticated API for the full toolset
- **Build a custom security tool API**: Expose project-specific scripts (custom exploit PoCs, recon aggregators, reporting generators) as MCP tools with schema-enforced inputs and structured outputs
- **Test MCP server authentication**: Audit an MCP server's API key validation, token expiration, and missing-auth behavior — verifying that unauthenticated callers are rejected with appropriate error codes rather than partial responses
- **Audit MCP tool input validation**: Fuzz tool input schemas with malformed types, injection strings, out-of-scope targets, and boundary values — confirming that all inputs are rejected before reaching subprocess execution

## MCP Server Architecture

### Core Components

An MCP server exposes three primitive types:

| Primitive | Purpose | Example |
|-----------|---------|---------|
| **Tools** | Functions the AI calls to take actions | `run_nmap`, `check_url`, `parse_output` |
| **Resources** | Data the AI reads (like files or DB records) | `scan_results`, `target_list` |
| **Prompts** | Templated instructions the AI can request | `pentest_report_template` |

For security tool wrapping, **tools** are the primary primitive. A tool definition has four fields:

```
name        — unique identifier the AI uses to invoke the tool
description — natural language explanation of what the tool does and when to use it
inputSchema — JSON Schema describing required/optional parameters and their types
handler     — the Python function that executes when the AI calls the tool
```

The AI (Claude) reads the tool list, decides which tool to call, constructs a JSON argument object matching the `inputSchema`, and sends it to the server. The server validates the arguments, executes the handler, and returns a structured result.

### Security Tool Wrapping Pattern

The canonical wrapping pattern follows this sequence:

```
AI tool call (JSON args)
       ↓
Input validation (schema + allowlist checks)
       ↓
Subprocess construction (shlex.split, no shell=True)
       ↓
Subprocess execution (timeout enforced)
       ↓
Output parsing (structured JSON from raw stdout)
       ↓
Error sanitization (no stack traces, no internal paths)
       ↓
Structured response returned to AI
```

Each step is a mandatory gate. Skipping input validation before subprocess construction is the primary attack surface in MCP servers that wrap shell tools.

### Transport Modes

| Mode | How It Works | Security Implications |
|------|-------------|----------------------|
| **stdio** | Server communicates over stdin/stdout; launched as child process | Default for Claude Desktop; no network exposure; authentication handled by OS-level process isolation |
| **HTTP/SSE** | Server runs as HTTP service; AI sends POST requests; Server-Sent Events for streaming | Exposed to network; requires explicit authentication (API key, OAuth); TLS mandatory for remote deployment |

For penetration testing use cases, HTTP/SSE transport introduces a real attack surface — the server becomes a network service accepting arbitrary JSON from callers.

## Building Secure MCP Servers

### Tool Design Principles

1. **Minimal permissions**: Each tool should run under the minimum OS permissions needed for its function. Do not run the MCP server as root.
2. **Explicit input schema**: Every parameter must appear in `inputSchema` with type, description, and constraints (enum for allowed values, pattern for format, minimum/maximum for ranges).
3. **Allowlist validation**: Validate inputs against an explicit allowlist (approved targets, approved flags), not a denylist (blocked strings). Denylists always have gaps.
4. **No `shell=True`**: Construct subprocess arguments as a list (`["nmap", "-sV", target]`), never as a shell string. `shell=True` with any user-controlled input is command injection.
5. **Explicit timeouts**: Every subprocess call must have a `timeout` parameter. Unbounded execution enables denial of service.
6. **Structured output only**: Parse tool output into a JSON-serializable dict before returning. Never return raw stdout as an unstructured string blob.
7. **Scope enforcement**: Maintain an allowlist of authorized target IPs/CIDRs. Reject any target not in scope before executing.

### Input Validation Patterns

```
IP/CIDR validation   — regex match + ipaddress module parse
URL validation       — urllib.parse.urlparse + scheme allowlist
Port range           — integer cast + 1-65535 bounds check
File path            — os.path.realpath + prefix allowlist
Target scope         — ip_network.supernet_of check against authorized_ranges
Tool flags           — set intersection against ALLOWED_FLAGS constant
```

### Authentication

For HTTP/SSE transport, implement token-based authentication on every request:

- Load the expected API key from an environment variable at startup; fail immediately if missing
- Validate the `X-API-Key` header on every incoming request before processing
- Return HTTP 401 with a generic `{"error": "unauthorized"}` body — no detail about why the key was rejected
- Never log the received key value; log only "auth success" or "auth failure" with the client address

### Rate Limiting

Per-client limits prevent abuse and limit blast radius if credentials are compromised:

- Track request timestamps per client identifier (API key or IP)
- Enforce a sliding window (e.g., 10 requests per 60 seconds per client)
- Enforce a global limit (e.g., 100 requests per 60 seconds across all clients)
- Return HTTP 429 with `{"error": "rate_limit_exceeded", "retry_after": N}` — never silently drop
- Apply exponential backoff signals in the `retry_after` field for repeated violations

### Error Handling

MCP server errors are a significant information disclosure vector:

- Catch all exceptions at the tool handler boundary; never let a raw exception propagate to the caller
- Log the full exception with stack trace server-side (to a file or syslog)
- Return a sanitized message to the caller: `{"error": "tool_execution_failed", "detail": "nmap returned non-zero exit code"}`
- Never include: internal file paths, stack traces, OS usernames, subprocess command strings, environment variable values

## Security Testing MCP Servers

### Attack Surface

| Surface | Attack Vector | Goal |
|---------|--------------|------|
| Tool input parameters | Injection strings (`;`, `&&`, `|`, `$()`) | Command injection via tool args |
| Input schema | Send wrong types, missing required fields | Schema bypass, unexpected code path |
| Authentication | Missing header, wrong key, replayed token | Unauthorized tool access |
| Rate limiting | Rapid sequential requests | Exhaust tool execution, DoS |
| Error messages | Trigger tool failures deliberately | Information disclosure (paths, versions) |
| Scope validation | Submit out-of-scope targets | Execute tools against unauthorized hosts |

### Testing Methodology

**Step 1 — Schema Fuzzing**: Send tool calls with wrong parameter types (string where int expected), missing required fields, extra undeclared fields, and boundary values (empty string, very long string, null).

**Step 2 — Injection Testing**: For every string input, test: semicolons (`; id`), shell metacharacters (`$(whoami)`, `` `id` ``), path traversal (`../../etc/passwd`), newlines (`\n`), and null bytes (`\x00`).

**Step 3 — Auth Bypass**: Test: missing `X-API-Key` header, empty key, key with extra whitespace, key from a different server, expired/rotated key. Verify all return 401 with no partial data.

**Step 4 — Rate Limit Bypass**: Send requests faster than the limit. Try: different client IPs (X-Forwarded-For spoofing), different API keys per request, large batch requests vs many small ones.

**Step 5 — Error Analysis**: Trigger failures by passing valid-format-but-broken inputs (unreachable IPs, nonexistent files, malformed URLs). Examine every error response for internal path leakage, version strings, or exception class names.

**Step 6 — Scope Bypass**: Submit targets just outside the authorized CIDR (adjacent IPs, neighboring subnets). Verify rejection. Test CIDR notation edge cases (host bits set, /0, /32).

## Tools

| Tool / SDK | Purpose |
|------------|---------|
| `mcp` Python SDK | Official MCP server implementation library (`pip install mcp`) |
| `fastmcp` | FastAPI-style high-level MCP server framework for rapid development |
| `httpx` / `requests` | HTTP client for testing HTTP/SSE transport MCP servers |
| `ipaddress` (stdlib) | IP and CIDR validation in tool handlers |
| `shlex` (stdlib) | Safe subprocess argument construction |
| `subprocess` (stdlib) | Tool execution with timeout and output capture |
| Custom Python scripts | Security testing automation (schema fuzzer, injection tester) |

## Orchestration

**ECC Loop Pattern**: Sequential Pipeline

**Rationale**: MCP server development follows a strict build-test-secure-deploy sequence. Each phase gates the next: schema design must precede implementation, implementation must precede security testing, security testing must pass before deployment. Skipping phases or running them in parallel introduces unvetted code into production.

**Integration**:
- Feeds into: `terminal-ops` (MCP server enables structured tool execution replacing ad-hoc shell commands), `autonomous-loops` (MCP tools called within agent autonomy loops), `multi-agent-collaboration` (shared MCP server exposes tools across multiple agent sessions)
- Consumes from: `security-review` (audit the MCP server implementation itself before deployment), `verification-loop` (confirm tool outputs are correct and reproducible)

**Cross-Skill Pipeline**:
```
[Identify security tools to wrap]
         ↓
mcp-server-patterns → [Design tool schemas + input validation rules]
         ↓
mcp-server-patterns → [Implement server: handlers, auth, rate limiting]
         ↓
security-review     → [Audit the MCP server implementation itself]
         ↓
verification-loop   → [Confirm tool outputs are correct and consistent]
         ↓
[Deploy + integrate with agent workflows]
```

**Quality Gate**: Before deploying any MCP server:
1. All tool inputs validated against JSON Schema before reaching handler code
2. No `shell=True` in any subprocess call — verified by grep
3. Authentication implemented and tested with missing/invalid key scenarios
4. Rate limiting configured with both per-client and global limits
5. Error messages sanitized — no stack traces, no internal paths in responses
6. All tool outputs structured as JSON-serializable dicts
7. Authorized target scope defined and enforced before any tool execution
