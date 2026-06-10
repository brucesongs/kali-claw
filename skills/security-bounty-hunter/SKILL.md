---
name: security-bounty-hunter
description: "Hunt for exploitable, bounty-worthy security issues in target systems. Focuses on remotely reachable vulnerabilities that qualify for real reports and responsible disclosure, not broad best-practices reviews or theoretical findings."
origin: openclaw
version: "0.1.18"
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
  domain: assessment
  tool_count: 0
  guide_count: 8
---




# Skill: Security Bounty Hunter

> **Supplementary Files**:
> - `payloads.md` — Static analysis commands, triage scripts, and PoC templates organized by vulnerability class
> - `test-cases.md` — Structured test cases for bounty-worthy vulnerability discovery, triage, and reporting

## Summary

Focuses on remotely reachable vulnerabilities that qualify for real reports and responsible disclosure, not broad best-practices reviews or theoretical findings.

**Domain**: assessment

## Description

Hunt for exploitable, bounty-worthy security issues in target systems. Focuses on remotely reachable vulnerabilities that qualify for real reports and responsible disclosure, not broad best-practices reviews or theoretical findings.

Difference from `vulnerability-assessment`: vulnerability-assessment runs automated scanners for a wide inventory of weaknesses. This skill focuses on manually verifying that a specific attack path is exploitable, user-controlled, and impactful enough to submit as a bounty report.

## Use Cases

- Bug bounty hunting on HackerOne, Bugcrowd, Synack, or private programs
- Responsible disclosure vulnerability research on open-source projects
- Pre-engagement proof-of-concept development for penetration tests
- Validating scanner findings to separate real vulnerabilities from false positives
- Triage of large scan results to identify which findings are actually exploitable

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| semgrep | Static analysis with custom rules | `semgrep --config=auto --severity=ERROR --severity=WARNING --json` |
| Burp Suite | Web proxy and attack platform | Intercept → Repeater → Intruder |
| SQLMap | Automated SQL injection detection | `sqlmap -u "http://target/page?id=1" --batch --dbs` |
| Nuclei | Template-based vulnerability scanner | `nuclei -u http://target -t cves/ -t vulnerabilities/` |
| curl | Manual HTTP request crafting | `curl -X POST -H "Content-Type: application/json" -d '{"url":"http://internal"}' http://target/api` |
| searchsploit | Local exploit database search | `searchsploit apache 2.4.49` |

## Methodology

### Bounty Hunter Workflow

**Step 1: Scope Check**

Before any testing:
- Read the program's scope, rules, and exclusions (SECURITY.md, policy pages)
- Identify in-scope domains, IP ranges, and application types
- Note any out-of-scope targets and testing restrictions
- Check for existing reports on the same target

**Step 2: Find Real Entrypoints**

Focus on network-reachable attack surfaces:
- HTTP handlers, REST API endpoints, GraphQL resolvers
- File upload processing
- Webhook handlers and callback URLs
- Background job processors that consume external data
- Parser and deserializer code paths

**Step 3: Triage with Static Tooling**

Run automated tools as triage input only:

```bash
semgrep --config=auto --severity=ERROR --severity=WARNING --json
# Then manually filter:
# - drop tests, demos, fixtures, vendored code
# - keep only findings with a clear network or user-controlled route
```

**Step 4: Read the Full Code Path**

Trace user input from source to sink end-to-end. Confirm:
- Input is genuinely user-controlled
- The sink is meaningful and exploitable
- No intervening sanitization blocks the attack

**Step 5: Prove Exploitability**

Build the smallest safe PoC:
- RCE → harmless command (`id`, `whoami`)
- Data exfiltration → retrieve a known test value
- Auth bypass → access another user's resource
- SSRF → reach internal metadata endpoint

**Step 6: Report**

Draft a clear, reproducible report.

### In-Scope Vulnerability Patterns

| Pattern | CWE | Typical Impact |
|---------|-----|----------------|
| SSRF through user-controlled URLs | CWE-918 | Internal network access, cloud metadata theft |
| Auth bypass in middleware or API guards | CWE-287 | Unauthorized account or data access |
| Remote deserialization or upload-to-RCE | CWE-502 | Code execution |
| SQL injection in reachable endpoints | CWE-89 | Data exfiltration, auth bypass |
| Command injection in request handlers | CWE-78 | Code execution |
| Path traversal in file-serving paths | CWE-22 | Arbitrary file read or write |
| Auto-triggered XSS | CWE-79 | Session theft, admin compromise |

### Skip These (Usually Low-Signal)

- Local-only deserialization with no remote path
- `eval()` or `exec()` in CLI-only tooling
- `shell=True` on fully hardcoded commands
- Missing security headers by themselves
- Self-XSS requiring victim to paste code manually
- Demo, example, or test-only code

### Defense Perspective

- **Responsible disclosure**: Always report through proper channels
- **Scope respect**: Stay within authorized boundaries
- **Do no harm**: Minimize impact during testing; use safe payloads
- **Documentation**: Keep detailed logs of all testing activity

## Report Structure

```markdown
## Description
[What the vulnerability is and why it matters]

## Vulnerable Component
[File path/endpoint, line range, code snippet]

## Proof of Concept
[Minimal working request or script]

## Impact
[What the attacker can achieve]

## Affected Version
[Version, commit, or deployment target tested]

## Suggested Remediation
[How to fix it]
```

## Orchestration

### ECC Loop Pattern
- **Pattern**: Watch Loop (continuous monitoring) + Sequential Pipeline (per-finding flow)
- **Rationale**: Bounty hunting benefits from continuous target monitoring (new attack surfaces appear over time) combined with a structured per-finding pipeline from discovery to report
- **Integration**: recon-osint (surface discovery), verification-loop (finding confirmation), knowledge-ops (cross-session pattern tracking), article-writing (report generation)

### Cross-Skill Pipeline
```
recon-osint → security-bounty-hunter → verification-loop → article-writing
                                         ↓
                                    knowledge-ops (persist patterns)
```

### Quality Gate
- Pre-condition: Scope verified, target authorized for testing
- Post-condition: Finding independently reproduced with different method
- Verification: Use verification-loop Phase 4 (independent confirmation)

---

## Quality Gate

Before submitting any report:
- [ ] The code path is reachable from a real user or network boundary
- [ ] The input is genuinely user-controlled
- [ ] The sink is meaningful and exploitable
- [ ] The PoC works and demonstrates real impact
- [ ] The issue is not already covered by an advisory, CVE, or open ticket
- [ ] The target is in scope for the program
