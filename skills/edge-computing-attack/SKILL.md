---
name: edge-computing-attack
description: "Attacks against edge computing platforms — Cloudflare Workers (V8 isolate), Fastly Compute@Edge (WASM/Wasmtime), AWS Lambda@Edge and CloudFront Functions, Akamai EdgeWorkers, Vercel Edge Functions, and Deno Deploy. Covers V8 isolate escape, WASM sandbox bypass, request smuggling at the edge, edge KV store abuse, secret leakage via edge logs, and bypass of origin WAF via edge script injection. Distinct from cloud-security (broader CSP control plane), container-security (Linux namespaces), and web-ssrf (origin-side issues)."
origin: openclaw
version: "0.1.40"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: edge-computing
  tool_count: 14
  guide_count: 2
  mitre: "T1190-Exploit Public-Facing Application, T1552.007-Container and Cloud Instance Credentials API"
---

# Edge Computing Attack

> **Supplementary Files**:
> - `payloads.md` — Attack payloads organized by edge platform: Cloudflare Workers (V8 isolate escape, KV abuse), Fastly Compute@Edge (WASM sandbox), AWS Lambda@Edge / CloudFront Functions, Akamai EdgeWorkers, Vercel Edge Functions, Deno Deploy
> - `test-cases.md` — 18 structured test cases covering reconnaissance, edge script injection, KV/Kvstore abuse, isolate escape attempts, request smuggling, and origin WAF bypass
> - `guides/edge-computing-attack-playbook.md` — End-to-end playbook with engagement scoping, lab setup (local Wrangler, Fastly CLI, SAM Local), attack workflows, and blue-team detection engineering
> - `guides/real-world-incident-case-studies.md` — Eight case studies including the 2024 Cloudflare Workers KV incident, AWS Lambda@Edge CVE-2023-XX pattern, Fastly WASM breakouts, and Deno Deploy SSRF waves

## Summary

This skill targets **edge computing** — where code runs in geographically-distributed nodes close to end users, typically in V8 isolates (Cloudflare Workers), WASM sandboxes (Fastly Compute@Edge), or restricted JavaScript engines (AWS CloudFront Functions, Lambda@Edge). The attack surface differs from origin-side attacks: edge platforms handle TLS termination, request routing, and caching, and their security model assumes a trusted-but-curious operator with strong tenant isolation.

**Tools**: wrangler, fastly-cli, sam-cli (SAM Local), gcloud edge, akamai-cli, vercel-cli, deno, vitesspa, chromium-headless, burp suite, postman, curl, jq

**Domain**: edge-computing

**MITRE ATT&CK**: T1190 Exploit Public-Facing Application · T1552.007 Container and Cloud Instance Credentials API · T1059 Command and Scripting Interpreter

## Description

Attacks against edge computing platforms — Cloudflare Workers (V8 isolate), Fastly Compute@Edge (WASM/Wasmtime), AWS Lambda@Edge and CloudFront Functions, Akamai EdgeWorkers, Vercel Edge Functions, and Deno Deploy.

Edge platforms share common architecture: code runs in **isolates** (V8) or **sandboxes** (WASM), often co-located with hundreds of other tenants on the same physical machine. The threat model assumes:
- Operator (CSP) is trusted to enforce isolation
- Other tenants are NOT trusted (cross-tenant attacks possible)
- Origin servers may be inaccessible directly (all traffic flows through edge)
- Edge scripts have access to KV stores, secrets, and request/response bodies

This skill is distinct from:
- **cloud-security** — which targets CSP control planes (IAM, EC2, S3) broadly
- **container-security** — which targets Linux namespaces and cgroups
- **web-ssrf** — which targets origin-side SSRF (edge-side SSRF has different rules)
- **api-security** — which targets REST/GraphQL endpoints, not edge routing

Where container-security asks "can I escape this container?", edge-computing-attack asks "given that my Worker shares a V8 isolate pool with 10,000 other tenants, how do I leak their secrets via shared state, KV race conditions, or isolate escape?"

Coverage includes:
- **Cloudflare Workers**: V8 isolate escape attempts, KV race conditions, Durable Objects abuse, Workers AI prompt injection, R2 storage abuse, Pages Functions injection
- **Fastly Compute@Edge**: WASM sandbox bypass, WASI host-call misuse, secret store leakage, edge KV abuse
- **AWS Lambda@Edge / CloudFront Functions**: token theft from env, origin WAF bypass via edge-managed headers, CloudFront function code injection
- **Akamai EdgeWorkers**: bypass of edge-based ARL parsing, Property Manager manipulation
- **Vercel Edge Functions / Edge Config**: env var leakage, Edge Config race conditions
- **Deno Deploy**: V8 isolate escape, KV store race conditions
- **Universal edge patterns**: cache poisoning, request smuggling (CL.TE / TE.CL via edge), TLS SNI manipulation, host header injection at edge, geographic DNS hijack prep

## Use Cases

- **Cloudflare Workers KV race condition** — concurrent reads/writes to same key to leak tenant data
- **Cloudflare Workers V8 isolate escape** — exploit V8 bugs (or Workers-specific quirks) to break isolation
- **Cloudflare Durable Objects abuse** — single-threaded object state to leak cross-tenant data
- **Cloudflare Workers AI prompt injection** — indirect prompt injection via Worker to leak secrets
- **Fastly Compute@Edge WASM escape** — exploit Wasmtime bug to escape sandbox
- **Fastly Secret Store leakage** — read secrets via misconfigured token
- **AWS Lambda@Edge env var leakage** — exploit logging side channel
- **AWS CloudFront Function code injection** — inject JS into edge function
- **Akamai EdgeWorkers bypass** — bypass ARL-based access control
- **Vercel Edge Config race** — concurrent reads to expose other tenant's config
- **Deno Deploy KV race** — concurrent KV operations to leak data
- **Origin WAF bypass via edge header manipulation** — set `X-Forwarded-For` to bypass IP-based rules
- **Cache poisoning via edge** — poison edge cache to serve malicious content to other users
- **Request smuggling at edge** — CL.TE via edge HTTP/2 → origin HTTP/1.1 boundary

## Differentiation from Adjacent Skills

| Skill | Target | Boundary | Typical entry |
|---|---|---|---|
| `cloud-security` | CSP control plane | Cloud IAM | IAM enumeration |
| `container-security` | OCI, K8s, containerd | Linux namespace | Container escape |
| `web-ssrf` | Origin application | Origin network | URL parameter |
| `api-security` | REST/GraphQL endpoints | API gateway | Injection |
| `edge-computing-attack` (this) | Edge isolate / sandbox | V8 / WASM boundary | Edge script exploit |
| `dns-attacks` | DNS protocol | DNS resolver | DNS hijack, cache poison |
| `cdn-cache-attack` | CDN cache | Cache key | Cache poison (overlaps) |

## Core Tools

### Cloudflare Workers
- **wrangler** — official Workers CLI; deploy, dev, KV, R2
- **miniflare** — local Workers emulator for testing
- **cloudflare-api-cli** — direct REST API access
- **workers-typescript-template** — boilerplate for TS Workers

### Fastly Compute@Edge
- **fastly-cli** — official Compute@Edge CLI
- **wasmtime** — local WASM runtime for testing
- **fastly-compute-starter** — Rust/JS starter kits

### AWS Lambda@Edge / CloudFront Functions
- **aws-cli** — Lambda and CloudFront API
- **sam-cli** — local SAM emulation for Lambda testing
- **cloudfront-testing-tools** — request-response replay

### Akamai EdgeWorkers
- **akamai-cli** with edgeworkers plugin
- **akamai-sandbox** — local EdgeWorkers emulator

### Vercel Edge
- **vercel-cli** — Vercel deployment CLI
- **next.js** edge runtime testing

### Deno Deploy
- **deno** — Deno runtime
- **deployctl** — Deno Deploy CLI

### Universal
- **curl** — edge protocol testing
- **Burp Suite** — request/response tampering
- **Wireshark** — packet capture (limited use; most edge is TLS)
- **vitesspa** — Vite + SPA testing harness
- **chromium-headless** — end-to-end browser testing

## Methodology

### Phase 1 — Reconnaissance
- Identify edge platform via HTTP headers (`Server: cloudflare`, `X-Fastly`, `X-Amz-Cf-Pop`, `X-Akamai-Transformed`, `X-Vercel-*`)
- Identify edge functions in use (timing analysis, behavior fingerprinting)
- Map edge KV store usage (timing, error patterns)
- Identify origin WAF patterns (security headers)
- Map request routing (geo DNS, edge POPs)

### Phase 2 — Edge Script Discovery
- Inspect client-side JS for `cf:` / `cdn-cgi/` indicators
- Use Wrangler dev mode for local Cloudflare Workers inspection (if authorized)
- Analyze edge function behavior via timing and error patterns
- Identify Worker bundling via DevTools / source maps (often enabled)

### Phase 3 — Tenant Isolation Testing
- Deploy own Worker on same platform
- Test for shared isolate patterns (timing, leak)
- Test KV store race conditions
- Test Durable Object cross-tenant access
- Test Deno Deploy KV cross-tenant

### Phase 4 — Edge Script Injection
- Inject malicious edge script (if edge function has injection vuln)
- Test edge function input validation (headers, query, body)
- Test edge function source map leakage

### Phase 5 — Cache and Routing Attacks
- Cache poisoning via edge header manipulation
- Request smuggling at HTTP version boundary
- Geographic DNS hijack preparation
- Host header injection at edge

### Phase 6 — Origin WAF Bypass
- Test edge header manipulation (`X-Forwarded-For`, `X-Real-IP`)
- Test edge-based request rewriting
- Test edge script that adds headers trusted by origin
- Test CloudFront signed URL bypass

### Phase 7 — Secret and Data Exfiltration
- Edge KV store exfiltration via race condition
- Edge logs containing secrets (Worker logs often include env vars)
- Workers AI prompt injection for secret leak
- Durable Objects state exfiltration

### Phase 8 — Persistence
- Persistent edge Worker via compromised deploy token
- Persistent cache poisoning
- Persistent KV store pollution
- Persistent DNS hijack prep

## Defense Perspective

### Core Principles
1. **Edge is privileged** — edge scripts see all traffic including TLS-terminated plaintext
2. **Tenant isolation is critical** — KV, Durable Objects, Edge Config must enforce hard isolation
3. **Cache is shared state** — cache poisoning affects other tenants
4. **Origin must NOT trust edge headers** — `X-Forwarded-For` etc. can be set by attacker
5. **Logs are sensitive** — edge logs often contain secrets in headers/body

### Hardening Checklist
- [ ] Validate `X-Forwarded-*` headers at origin (don't trust blindly)
- [ ] Rotate edge deployment tokens quarterly
- [ ] Audit edge function code for injection
- [ ] Use Cloudflare's API tokens (not Global API Key) for CI
- [ ] Restrict Worker secrets to specific Workers via bindings
- [ ] Enable Fastly Compute@Edge secret store ACLs
- [ ] Use signed URLs for CloudFront protected content
- [ ] Audit Vercel Edge Config access patterns
- [ ] Apply Deno Deploy KV access controls
- [ ] Monitor edge function logs for secret patterns

### Detection Engineering
- Edge function log anomaly detection (unexpected env var reads)
- KV store race condition detection (concurrent operations)
- Cache hit ratio anomaly (potential poisoning)
- Edge function cold start anomaly (potential injection)
- Edge-to-origin header consistency checks

## Practical Steps

### Cloudflare Workers Recon
```bash
# Identify Cloudflare
curl -sI https://target/ | grep -i server
# Server: cloudflare

# Identify edge POP
curl -sI https://target/ | grep -i cf-ray
# CF-RAY: 85abc123.def-LAX (LAX = Los Angeles POP)

# Detect Worker
curl -s https://target/cdn-cgi/trace
# Identifies colo, request source, etc.

# Worker source map leak (often enabled)
curl -s https://target/script.js.map
```

### Cloudflare Workers KV Race
```javascript
// Deploy own Worker with KV binding
// Race condition: read-write-read pattern

// Worker code:
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const key = 'shared_key';

  // Read value
  const initial = await KV.get(key);

  // Write attacker value
  await KV.put(key, 'attacker_value');

  // Read again quickly — may catch another tenant's write
  const after = await KV.get(key);

  return new Response(JSON.stringify({ initial, after }));
}
```

### Fastly Compute@Edge Recon
```bash
# Identify Fastly
curl -sI https://target/ | grep -i "X-Fastly"
# X-Fastly: hit
# X-Served-By: cache-lax1234-LAX

# Detect Compute@Edge usage
curl -sI https://target/ | grep -i server
# Server: Fastly Compute

# WASM source map leak
curl -s https://target/.well-known/fastly/source
```

### AWS Lambda@Edge Recon
```bash
# Identify CloudFront
curl -sI https://target/ | grep -i "X-Amz-Cf"
# X-Amz-Cf-Pop: LAX1-C1
# X-Amz-Cf-Id: ...

# Lambda@Edge logs in CloudWatch (us-east-1)
aws logs describe-log-groups \
  --region us-east-1 \
  --log-group-name-prefix "/aws/lambda/"

# CloudFront Function source
aws cloudfront list-functions
aws cloudfront describe-function --name REPLACE_WITH_YOUR_FUNCTION
```

### Vercel Edge Recon
```bash
# Identify Vercel
curl -sI https://target/ | grep -i "X-Vercel"
# X-Vercel-Cache: HIT
# X-Vercel-Id: vercel-sfo1:abc-def

# Edge Config endpoint
curl -s https://target/_vercel/edge-config/_default
```

## Cross-References
- `skills/cloud-security/SKILL.md` — broader CSP control plane attacks
- `skills/container-security/SKILL.md` — Linux container escapes
- `skills/web-ssrf/SKILL.md` — origin-side SSRF (compare to edge-side)
- `skills/dns-attacks/SKILL.md` — DNS attacks relevant to edge routing
- `skills/api-security/SKILL.md` — API gateway attacks
- `skills/persistence-attacks/SKILL.md` — edge-side persistence patterns
- `skills/cdn-cache-attack/SKILL.md` — CDN-specific cache attacks

## References

- Cloudflare — *Workers Security Model* (2024)
- Fastly — *Compute@Edge Security Documentation* (2024)
- AWS — *Lambda@Edge Security Best Practices* (2024)
- Akamai — *EdgeWorkers Security Guide* (2024)
- Vercel — *Edge Functions and Edge Config Documentation* (2024)
- Deno — *Deno Deploy Threat Model* (2024)
- Bishop Fox — *Edge Computing Attack Vectors* (2024 whitepaper)
- Black Hat USA — *Cross-Tenant Attacks in Edge Platforms* (2024)
- MITRE ATT&CK — T1190 Exploit Public-Facing Application, T1552.007 Container and Cloud Instance Credentials API
