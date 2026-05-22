# Cross-Skill Integration Scenarios

> Detailed definitions for each integration test scenario.
> Each scenario validates that multiple skills compose into a working pipeline with correct data handoff.

---

## INT-001: Recon Pipeline

### Objective

Validate the full reconnaissance-to-verification pipeline: passive intel gathering through active scanning to finding confirmation.

### Skill Chain

```
[osint] --domain_intel--> [recon-osint] --target_profile--> [network-pentest]
   --scan_results--> [vulnerability-assessment] --findings--> [verification-loop]
```

| Step | Skill | Input | Output |
|------|-------|-------|--------|
| 1 | osint | Target domain | WHOIS + DNS records + registrant info |
| 2 | recon-osint | Domain intel from step 1 | Subdomains, IP addresses, technology fingerprint |
| 3 | network-pentest | IP addresses from step 2 | Open ports, services, versions |
| 4 | vulnerability-assessment | Services from step 3 | NSE vulnerability findings (CVE IDs, severity) |
| 5 | verification-loop | Findings from step 4 | CONFIRMED / NOT CONFIRMED verdict per finding |

### ECC Pattern

Sequential Pipeline (autonomous-loops): FOR EACH stage → execute → pass output → next stage

### Pre-conditions

- whois, dig, nmap available
- Target: github.com (safe, public, well-documented)
- Network connectivity

### Execution Steps

1. **osint**: Run `whois github.com` + `dig github.com ANY` → capture registrant, nameservers, IPs
2. **recon-osint**: Run `dig github.com A` + `dig github.com AAAA` + `dig github.com MX` → build IP list
3. **network-pentest**: Run `nmap -sV -T4 --top-ports 100 <primary-IP>` → identify services
4. **vulnerability-assessment**: Run `nmap --script ssl-enum-ciphers,http-headers -p 443,80 <IP>` → check for weak configs
5. **verification-loop**: For each finding, verify independently (e.g., `curl -I` to confirm header issues)

### Expected Outcomes

| Checkpoint | Criterion | Evidence Type |
|-----------|-----------|---------------|
| After step 1 | WHOIS returns registrant org + nameservers | Terminal log |
| After step 2 | At least 1 IP address extracted | Terminal log |
| After step 3 | At least 2 open ports identified with service versions | Terminal log |
| After step 4 | At least 1 finding (weak cipher or missing header) | Terminal log |
| After step 5 | Finding verified with independent method | Terminal log |

### Failure Modes

| Handoff | What Can Break | Mitigation |
|---------|---------------|------------|
| 1→2 | WHOIS privacy hides registrant | Proceed with DNS-only data |
| 2→3 | CDN returns multiple IPs | Pick primary IP from A record |
| 3→4 | All ports filtered/closed | Use port 443 (always open for github.com) |
| 4→5 | No vulnerabilities found | Verify a configuration finding (e.g., HSTS header presence) |

---

## INT-002: Security Audit

### Objective

Validate the code-audit pipeline: onboard a codebase, scan for issues, review security, analyze from multiple perspectives, and produce a report.

### Skill Chain

```
[codebase-onboarding] --architecture_map--> [repo-scan] --hotspots-->
   [security-review] --findings--> [council] --decision--> [article-writing]
```

| Step | Skill | Input | Output |
|------|-------|-------|--------|
| 1 | codebase-onboarding | Repository path | Architecture map, language breakdown, entry points |
| 2 | repo-scan | Architecture map | File classification, security hotspots, dependency list |
| 3 | security-review | Hotspots from step 2 | OWASP findings with severity + evidence |
| 4 | council | Findings from step 3 | Three-perspective analysis (attack/defense/audit) |
| 5 | article-writing | Council output | Structured security audit report |

### ECC Pattern

Sequential Pipeline: each phase produces structured input for the next.

### Pre-conditions

- git, grep, find available
- Target: this repository (kali-claw-en) — safe, local, well-understood
- No external dependencies

### Execution Steps

1. **codebase-onboarding**: Analyze kali-claw-en repo — identify structure, file types, key directories, entry points
2. **repo-scan**: Classify files (config, skill definitions, memory, docs), identify any secrets or sensitive patterns
3. **security-review**: Check for hardcoded secrets, exposed credentials, unsafe patterns in any scripts
4. **council**: Analyze findings from attacker/defender/auditor perspectives
5. **article-writing**: Produce a brief security audit summary report

### Expected Outcomes

| Checkpoint | Criterion | Evidence Type |
|-----------|-----------|---------------|
| After step 1 | Architecture map identifies 49 skill dirs + core config files | Text output |
| After step 2 | File classification covers 5+ categories, 0% third-party code | Text output |
| After step 3 | At least 1 finding or explicit "no issues found" with evidence | Text output |
| After step 4 | Three perspectives documented with agreement/disagreement | Text output |
| After step 5 | Report follows pentest report template structure | Markdown file |

### Failure Modes

| Handoff | What Can Break | Mitigation |
|---------|---------------|------------|
| 1→2 | Repo too large for single pass | Use Targeted scope mode (specific directories) |
| 2→3 | No hotspots found | Review all config files as security-relevant |
| 3→4 | No findings to analyze | Council analyzes the security posture (absence of issues is a finding) |
| 4→5 | Council output too verbose | Article-writing extracts executive summary |

---

## INT-003: Credential Attack

### Objective

Validate the credential attack chain: enumerate targets via OSINT, attempt password attack, verify results, and log the event.

### Skill Chain

```
[recon-osint] --target_services--> [password-attack] --results-->
   [verification-loop] --verdict--> [chronicle]
```

| Step | Skill | Input | Output |
|------|-------|-------|--------|
| 1 | recon-osint | Target domain/IP | SSH/service endpoints discovered |
| 2 | password-attack | Service endpoint from step 1 | Attack results (success/failure + credentials if found) |
| 3 | verification-loop | Credentials from step 2 | CONFIRMED access / NOT CONFIRMED |
| 4 | chronicle | Verified finding | P0/P1 event record |

### ECC Pattern

Sequential Pipeline with scope lock (password-attack limited to authorized targets only).

### Pre-conditions

- hydra, nmap available
- Target: localhost SSH (safe, controlled) or scanme.nmap.org
- Small wordlist (top 10 passwords)

### Execution Steps

1. **recon-osint**: Run `nmap -sV -p 22 localhost` → confirm SSH service available
2. **password-attack**: Run `hydra -l root -P /dev/null -t 1 -w 1 ssh://localhost` → demonstrate attack methodology (intentionally fail with empty password list for safety)
3. **verification-loop**: Verify hydra output format is parseable, confirm attack completed without errors
4. **chronicle**: Record the test execution as a security event with timestamp, target, method, result

### Expected Outcomes

| Checkpoint | Criterion | Evidence Type |
|-----------|-----------|---------------|
| After step 1 | SSH service identified on target | Terminal log |
| After step 2 | Hydra executes without errors, produces structured output | Terminal log |
| After step 3 | Output verified as valid hydra result format | Terminal log |
| After step 4 | Event recorded with required fields (time, target, method, result) | Text output |

### Failure Modes

| Handoff | What Can Break | Mitigation |
|---------|---------------|------------|
| 1→2 | SSH not running on localhost | Use nmap scanme.nmap.org as fallback |
| 2→3 | Hydra blocked by rate limiting | Use -t 1 -w 5 (single thread, 5s wait) |
| 3→4 | Nothing to verify (no credentials found) | Verify the methodology executed correctly (negative result is valid) |

---

## INT-004: Intelligence Research

### Objective

Validate the intelligence pipeline: deep-dive a CVE, scrape structured data, persist to knowledge graph, correlate with social intelligence, and synthesize via council.

### Skill Chain

```
[deep-research] --cve_analysis--> [data-scraper-agent] --structured_data-->
   [knowledge-ops] --knowledge_graph--> [social-intelligence] --social_context-->
   [council]
```

| Step | Skill | Input | Output |
|------|-------|-------|--------|
| 1 | deep-research | CVE ID | Six-phase analysis (description, impact, exploit, mitigation, timeline, references) |
| 2 | data-scraper-agent | CVE ID from step 1 | Structured NVD data (CVSS, CWE, affected products, references) |
| 3 | knowledge-ops | Research + scraped data | Knowledge entity with cross-references and confidence score |
| 4 | social-intelligence | CVE ID + knowledge entity | Community discussion, exploit availability signals, threat actor interest |
| 5 | council | All gathered intelligence | Risk assessment from attacker/defender/auditor perspectives |

### ECC Pattern

Sequential Pipeline with Learning Cycle elements (confidence scoring at each stage).

### Pre-conditions

- curl, python3, jq available
- Internet access for NVD API
- Target CVE: CVE-2024-3094 (xz backdoor — well-documented, high-profile)

### Execution Steps

1. **deep-research**: Research CVE-2024-3094 — describe vulnerability, impact, affected versions, timeline
2. **data-scraper-agent**: Query NVD API `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094` → extract CVSS, CWE, references
3. **knowledge-ops**: Synthesize research + NVD data into structured knowledge entity with confidence scores
4. **social-intelligence**: Assess community awareness — known exploit availability, media coverage, patch adoption
5. **council**: Three-perspective risk assessment (attacker: exploitability, defender: mitigation priority, auditor: compliance impact)

### Expected Outcomes

| Checkpoint | Criterion | Evidence Type |
|-----------|-----------|---------------|
| After step 1 | Six research phases completed with cited sources | Text output |
| After step 2 | NVD API returns valid JSON with CVSS score | Terminal log (curl output) |
| After step 3 | Knowledge entity has ≥3 cross-references and confidence ≥75% | Text output |
| After step 4 | Social context includes exploit availability assessment | Text output |
| After step 5 | Three perspectives with consensus recommendation | Text output |

### Failure Modes

| Handoff | What Can Break | Mitigation |
|---------|---------------|------------|
| 1→2 | Research produces unstructured text | Extract CVE ID as structured handoff key |
| 2→3 | NVD API rate limited or down | Use cached/known data for CVE-2024-3094 |
| 3→4 | Knowledge entity format unclear | Use standard fields: id, description, severity, confidence, references |
| 4→5 | Social intel is speculative | Mark confidence levels explicitly |

---

## INT-005: Autonomous Batch Scan

### Objective

Validate the batch processing pattern: define scope, scan multiple targets in sequence with rate limiting, verify critical findings, and log with evidence-first protocol.

### Skill Chain

```
[autonomous-loops] --scope_lock--> [vulnerability-assessment] --batch_findings-->
   [verification-loop] --confirmed--> [terminal-ops]
```

| Step | Skill | Input | Output |
|------|-------|-------|--------|
| 1 | autonomous-loops | Target list + scope definition | Scope lock (immutable target list, rate limits, abort conditions) |
| 2 | vulnerability-assessment | Scope lock from step 1 | Batch scan results per target (findings with severity) |
| 3 | verification-loop | Critical/High findings from step 2 | CONFIRMED / NOT CONFIRMED per finding |
| 4 | terminal-ops | Verified findings | Evidence-chain log with timestamps and state tracking |

### ECC Pattern

Batch Processing: split targets → execute with concurrency limit → aggregate → verify critical.

### Pre-conditions

- nmap available
- Targets: 3 safe public hosts (scanme.nmap.org, example.com, github.com)
- Rate limit: 1 target per 10 seconds

### Execution Steps

1. **autonomous-loops**: Define scope lock — targets: [scanme.nmap.org, example.com, github.com], allowed operations: [nmap top-20 ports], rate limit: 10s between targets, abort if: error count > 2
2. **vulnerability-assessment**: FOR EACH target in scope → `nmap --script ssl-enum-ciphers -p 443 <target>` → collect findings
3. **verification-loop**: For any weak cipher found, verify with `openssl s_client -connect <target>:443`
4. **terminal-ops**: Log all results with evidence-first protocol (timestamp, command, output, state change)

### Expected Outcomes

| Checkpoint | Criterion | Evidence Type |
|-----------|-----------|---------------|
| After step 1 | Scope lock defined with 3 targets, rate limit, abort condition | Text output |
| After step 2 | All 3 targets scanned, results collected per target | Terminal log |
| After step 3 | At least 1 finding verified independently | Terminal log |
| After step 4 | Evidence log contains timestamp + command + output for each action | Text file |

### Failure Modes

| Handoff | What Can Break | Mitigation |
|---------|---------------|------------|
| 1→2 | Scope lock format not machine-parseable | Use structured YAML-like definition |
| 2→3 | No Critical/High findings in batch | Verify any finding (even informational) to prove the handoff works |
| 3→4 | Verification inconclusive | Document as PARTIALLY CONFIRMED with evidence |

---

## INT-006: Web App Attack

### Objective

Validate the web application attack chain: discover target, identify misconfigurations, exploit SQL injection, and produce a report.

### Skill Chain

```
[recon-osint] --target_info--> [security-misconfiguration] --weak_points-->
   [web-sqli] --exploit_results--> [article-writing]
```

| Step | Skill | Input | Output |
|------|-------|-------|--------|
| 1 | recon-osint | Target URL | Technology fingerprint, server headers, exposed endpoints |
| 2 | security-misconfiguration | Headers/config from step 1 | Missing security headers, verbose errors, directory listing |
| 3 | web-sqli | Endpoints from step 1+2 | Injection point detection, database type, extractable data |
| 4 | article-writing | All findings from steps 2+3 | Vulnerability disclosure report |

### ECC Pattern

Sequential Pipeline with conditional branching (if no SQLi found, report misconfigs only).

### Pre-conditions

- curl, sqlmap, nmap available
- Target: testphp.vulnweb.com (Acunetix public test site) or similar intentionally vulnerable target
- Internet access

### Execution Steps

1. **recon-osint**: `curl -sI http://testphp.vulnweb.com/` + `nmap -sV -p 80,443 testphp.vulnweb.com` → identify server, technology
2. **security-misconfiguration**: Analyze response headers for missing X-Frame-Options, CSP, X-Content-Type-Options, HSTS
3. **web-sqli**: `sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --batch --level=1 --risk=1` → detect injection
4. **article-writing**: Compile findings into vulnerability disclosure format (executive summary + technical detail + remediation)

### Expected Outcomes

| Checkpoint | Criterion | Evidence Type |
|-----------|-----------|---------------|
| After step 1 | Server type and version identified | Terminal log |
| After step 2 | At least 3 missing security headers identified | Terminal log |
| After step 3 | SQL injection confirmed OR methodology demonstrated | Terminal log |
| After step 4 | Report contains all findings with severity ratings | Markdown output |

### Failure Modes

| Handoff | What Can Break | Mitigation |
|---------|---------------|------------|
| 1→2 | Target unreachable | Fallback to example.com (headers only, no SQLi) |
| 2→3 | No injectable parameters found | Document methodology as valid; mark SQLi step as N/A |
| 3→4 | sqlmap blocked by WAF | Report WAF detection as a finding itself |

---

## INT-007: Multi-Agent Coordination

### Objective

Validate the parallel coordination pattern: decompose scope into parallel tasks, execute independently, and aggregate findings via council.

### Skill Chain

```
[multi-agent-collaboration]
   ├── [network-pentest] (parallel worker 1)
   ├── [osint] (parallel worker 2)
   └── [web-sqli] (parallel worker 3)
         ↓ aggregate
      [council]
```

| Step | Skill | Input | Output |
|------|-------|-------|--------|
| 1 | multi-agent-collaboration | Target scope + decomposition strategy | 3 parallel task definitions |
| 2a | network-pentest | Target IP/domain | Port scan + service enumeration |
| 2b | osint | Target domain | WHOIS + DNS + registrant intel |
| 2c | web-sqli | Target URL | Injection point assessment |
| 3 | council | Aggregated findings from 2a+2b+2c | Three-perspective synthesis |

### ECC Pattern

Parallel (Coordinator-Worker model from multi-agent-collaboration) → Sequential aggregation.

### Pre-conditions

- nmap, whois, dig, sqlmap/curl available
- Target: testphp.vulnweb.com (supports all three parallel tasks)
- Internet access

### Execution Steps

1. **multi-agent-collaboration**: Define coordination plan — decompose "assess testphp.vulnweb.com" into 3 parallel tasks: network scan, OSINT gathering, web injection testing
2. **Parallel execution**:
   - 2a: `nmap -sV --top-ports 20 testphp.vulnweb.com`
   - 2b: `whois vulnweb.com` + `dig vulnweb.com ANY`
   - 2c: `curl -s "http://testphp.vulnweb.com/listproducts.php?cat=1'"` (single-quote injection test)
3. **council**: Aggregate all findings → analyze from attacker/defender/auditor perspectives → produce consensus recommendation

### Expected Outcomes

| Checkpoint | Criterion | Evidence Type |
|-----------|-----------|---------------|
| After step 1 | 3 parallel tasks defined with clear scope boundaries | Text output |
| After step 2a | Port scan returns at least 1 open port | Terminal log |
| After step 2b | WHOIS returns registrant information | Terminal log |
| After step 2c | Response indicates potential injection (error or different behavior) | Terminal log |
| After step 3 | Council synthesizes all 3 inputs into unified assessment | Text output |

### Failure Modes

| Handoff | What Can Break | Mitigation |
|---------|---------------|------------|
| 1→2 | Task decomposition unclear | Use explicit task templates from multi-agent-collaboration SKILL.md |
| 2→3 | One parallel task fails | Aggregate available results; note incomplete coverage |
| 2c→3 | No injection found | Report negative result as valid data point for council |

---

## Evidence Standards

Integration test evidence follows the same standards as single-skill validation:
- **Naming**: `integration/INT-{XXX}-{YYYY-MM-DD}.log`
- **Content**: Full terminal output showing each skill's execution and data handoff
- **Handoff markers**: Each step clearly labeled with `=== STEP N: {skill-name} ===`
- **Data flow**: Show the output of step N being used as input to step N+1
