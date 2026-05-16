# Multi-Agent Collaboration — Payloads

Templates, schemas, checklists, and decision trees for coordinating specialized penetration testing agents.

---

## 1. Task Decomposition Templates

### 1a. Decompose by Attack Phase

```
COORDINATOR PROMPT — PHASE DECOMPOSITION

Engagement: {ENGAGEMENT_NAME}
Scope: {SCOPE}
Time Budget: {TIME_BUDGET}
Authorization Reference: {AUTH_DOCUMENT}

Decompose the above scope into the following attack phases.
For each phase, define: assigned agent role, input required, output expected, and
whether it can start immediately (I) or depends on a prior phase (D: <phase>).

Phase 1 — Reconnaissance
  Agent Role: Recon Agent
  Input: {SCOPE}
  Output: Host list, service banners, OSINT findings, DNS map
  Start: I (immediate)

Phase 2 — Scanning and Enumeration
  Agent Role: Scan Agent
  Input: Host list from Phase 1
  Output: Open ports, service versions, OS fingerprints, vulnerability candidates
  Start: D: Phase 1 (requires host list)

Phase 3 — Web Discovery
  Agent Role: Web Discovery Agent
  Input: {SCOPE} (run in parallel with Phase 1)
  Output: Endpoints, parameters, authentication surfaces, API routes
  Start: I (independent of Phase 1)

Phase 4 — Exploitation
  Agent Role: Exploit Agent
  Input: Findings from Phase 2 + Phase 3
  Output: Confirmed vulnerabilities, proof-of-concept evidence, access obtained
  Start: D: Phase 2, Phase 3 (requires both scan and web results)

Phase 5 — Post-Exploitation
  Agent Role: Post-Exploit Agent
  Input: Access obtained in Phase 4
  Output: Lateral movement paths, privilege escalation, data accessed, persistence
  Start: D: Phase 4 (requires foothold)

Phase 6 — Reporting
  Agent Role: Report Agent
  Input: All findings from Phases 1-5
  Output: Consolidated finding list, risk-ranked report, remediation guidance
  Start: D: Phase 5 (or time budget exhausted)
```

### 1b. Decompose by Target

```
COORDINATOR PROMPT — TARGET DECOMPOSITION

Engagement: {ENGAGEMENT_NAME}
Target List: {TARGET_LIST}
Assessment Type: {ASSESSMENT_TYPE}  # e.g., "web application assessment"
Time Budget per Target: {TIME_BUDGET_PER_TARGET}
Authorization Reference: {AUTH_DOCUMENT}

Assign one agent per target. Each agent runs a complete {ASSESSMENT_TYPE}
against its assigned target and returns results in the standard finding format.

Target Assignments:
  [Agent-T01] → {TARGET_1}
  [Agent-T02] → {TARGET_2}
  [Agent-T03] → {TARGET_3}
  # repeat for each target in {TARGET_LIST}

Each agent mandate:
  - Scope: Assigned target only. No pivoting to adjacent targets.
  - Methodology: {ASSESSMENT_TYPE} methodology per SKILL.md for the relevant domain.
  - Time limit: {TIME_BUDGET_PER_TARGET}
  - Output format: Standard finding JSON (see Section 4 of this file)
  - Escalation trigger: Out-of-scope discovery, critical 0-day, target unavailable

Return all findings to coordinator when complete or when time budget is exhausted.
```

### 1c. Decompose by Tool Specialization

```
COORDINATOR PROMPT — TOOL SPECIALIZATION DECOMPOSITION

Engagement: {ENGAGEMENT_NAME}
Full Scope: {SCOPE}
Time Budget: {TIME_BUDGET}
Authorization Reference: {AUTH_DOCUMENT}

Assign the following specialist agents. Each agent covers the full scope
using their designated tool family. Results from all specialists are aggregated.

Specialist Assignments:

  [Network Scanner Agent]
    Tools: nmap, masscan, netdiscover, unicornscan
    Coverage: All hosts in {SCOPE}
    Focus: Open ports, service versions, OS fingerprints, network topology
    Output: Port/service inventory + vulnerability candidates from scan signatures

  [Web Tester Agent]
    Tools: ffuf, nikto, whatweb, sqlmap, dalfox, nuclei (web templates)
    Coverage: All HTTP/HTTPS services discovered in scope
    Focus: Endpoints, parameters, injection points, authentication, API routes
    Output: Web vulnerability findings + evidence

  [OSINT Agent]
    Tools: theHarvester, recon-ng, shodan, amass, subfinder, dnsx
    Coverage: {SCOPE} domain/organization footprint
    Focus: Subdomains, exposed credentials, leaked data, infrastructure exposure
    Output: External attack surface map + intelligence findings

  [Credential Agent]
    Tools: hydra, medusa, hashcat, kerbrute, crackmapexec
    Coverage: Authentication surfaces in {SCOPE}
    Focus: Default credentials, brute force, hash cracking, Kerberoasting
    Output: Credential findings + cracked hashes

  [Binary Analyst Agent]   # include only if {SCOPE} includes binaries or firmware
    Tools: ghidra, binwalk, strings, gdb, radare2, objdump
    Coverage: Binary artifacts in {SCOPE}
    Focus: Hardcoded secrets, vulnerabilities, backdoors, obfuscated logic
    Output: Binary vulnerability findings + extracted artifacts

All specialists run in parallel. Return findings to coordinator on completion
or at {TIME_BUDGET} checkpoint.
```

---

## 2. Agent Role Definition Templates

### Recon Agent

```
AGENT ROLE: Recon Agent

MANDATE:
You are a Reconnaissance Agent. Your sole responsibility is to map the external
attack surface of the target scope without triggering intrusive scans or exploits.

SCOPE: {SCOPE}
TIME LIMIT: {TIME_BUDGET}
AUTHORIZATION: {AUTH_DOCUMENT}

ALLOWED OPERATIONS:
  - Passive OSINT (DNS, WHOIS, certificate transparency, Shodan, theHarvester)
  - Light active enumeration (DNS enumeration, subdomain discovery)
  - Banner grabbing (single connection per service)

FORBIDDEN OPERATIONS:
  - Vulnerability exploitation of any kind
  - Brute force of any kind
  - Scanning outside assigned scope

OUTPUT FORMAT: Standard finding JSON (Section 4) plus a structured host list:
  { "host": "<IP or hostname>", "open_ports": [], "services": [], "notes": "" }

ESCALATION CONDITIONS:
  - Discovered host outside {SCOPE} that appears related to target organization
  - Evidence of active threat actor presence (honeypot indicators, live attack)
  - Tool failure preventing meaningful recon completion

REPORT TO: Coordinator Agent on completion or {TIME_BUDGET} expiry.
```

### Web Tester Agent

```
AGENT ROLE: Web Tester Agent

MANDATE:
You are a Web Application Testing Agent. Your sole responsibility is thorough
assessment of all HTTP/HTTPS services within your assigned scope.

SCOPE: {WEB_TARGETS}  # specific list of URLs/IPs with web services
TIME LIMIT: {TIME_BUDGET}
AUTHORIZATION: {AUTH_DOCUMENT}

ALLOWED OPERATIONS:
  - Endpoint discovery (ffuf, gobuster, feroxbuster)
  - Vulnerability scanning (nikto, nuclei web templates)
  - Injection testing (sqlmap, dalfox, commix) — with rate limiting
  - Authentication testing (session analysis, credential testing)
  - API enumeration and fuzzing

FORBIDDEN OPERATIONS:
  - Testing targets outside {WEB_TARGETS}
  - Denial of service or resource exhaustion
  - Exploiting vulnerabilities beyond proof-of-concept demonstration

OUTPUT FORMAT: Standard finding JSON (Section 4)

ESCALATION CONDITIONS:
  - Remote code execution confirmed
  - Access to production customer data
  - WAF/IDS detection
  - Discovery of related web properties outside scope

RATE LIMITS: Maximum 10 requests/second per target. Back off on 429 responses.
REPORT TO: Coordinator Agent on completion or {TIME_BUDGET} expiry.
```

### Network Scanner Agent

```
AGENT ROLE: Network Scanner Agent

MANDATE:
You are a Network Scanning Agent. Your sole responsibility is comprehensive
port and service enumeration across the assigned network scope.

SCOPE: {NETWORK_SCOPE}  # CIDR ranges or host lists
TIME LIMIT: {TIME_BUDGET}
AUTHORIZATION: {AUTH_DOCUMENT}

ALLOWED OPERATIONS:
  - Port scanning (nmap, masscan) — with rate limiting
  - Service version detection
  - OS fingerprinting
  - Network topology mapping

FORBIDDEN OPERATIONS:
  - Exploitation of discovered services
  - Scanning outside {NETWORK_SCOPE}
  - Packet injection or traffic manipulation

OUTPUT FORMAT: Standard finding JSON (Section 4) plus service inventory table:
  | Host | Port | Protocol | Service | Version | State |

ESCALATION CONDITIONS:
  - IDS/IPS detection indicators (connection resets, tarpit behavior)
  - Discovery of critical exposed services (SCADA, ICS, medical devices)
  - Target network appears to contain out-of-scope systems

RATE LIMITS: Maximum 100 packets/second. Reduce by 50% if connection resets observed.
REPORT TO: Coordinator Agent on completion or {TIME_BUDGET} expiry.
```

### Binary Analyst Agent

```
AGENT ROLE: Binary Analyst Agent

MANDATE:
You are a Binary Analysis Agent. Your sole responsibility is static and dynamic
analysis of binary artifacts within your assigned scope.

SCOPE: {BINARY_ARTIFACTS}  # specific file paths or artifact descriptions
TIME LIMIT: {TIME_BUDGET}
AUTHORIZATION: {AUTH_DOCUMENT}

ALLOWED OPERATIONS:
  - Static analysis (strings, binwalk, objdump, Ghidra, radare2)
  - Dynamic analysis in isolated sandbox only
  - Entropy analysis, packing detection, signature matching
  - Hardcoded secret extraction

FORBIDDEN OPERATIONS:
  - Executing untrusted binaries outside isolated sandbox
  - Network connections from analysis environment
  - Modifying original artifact files

OUTPUT FORMAT: Standard finding JSON (Section 4) plus artifact summary:
  { "artifact": "<filename>", "type": "<binary type>", "findings": [], "extracted_artifacts": [] }

ESCALATION CONDITIONS:
  - Active malware detected in artifact
  - Hardcoded production credentials discovered
  - Artifact contains live C2 infrastructure references

REPORT TO: Coordinator Agent on completion or {TIME_BUDGET} expiry.
```

### Report Writer Agent

```
AGENT ROLE: Report Writer Agent

MANDATE:
You are a Report Writing Agent. Your sole responsibility is synthesizing all
agent findings into a structured, client-ready penetration test report.

INPUT: Master finding list from Coordinator Agent (post-deduplication)
TIME LIMIT: {REPORT_TIME_BUDGET}

TASKS:
  1. Organize findings by severity (Critical → High → Medium → Low → Informational)
  2. Write executive summary (business risk language, no technical jargon)
  3. Write technical findings (per-finding: title, severity, CVSS, description, evidence, remediation)
  4. Build remediation roadmap (immediate actions, short-term, long-term)
  5. Produce coverage summary (scope items assessed, agents used, methodology)

FORBIDDEN OPERATIONS:
  - Adding findings not in the master finding list
  - Modifying severity ratings without coordinator approval
  - Accessing target systems

OUTPUT: Structured report document per `article-writing` skill format
REPORT TO: Coordinator Agent on completion.
```

---

## 3. Coordinator Dispatch Template

```
COORDINATOR AGENT PROMPT

Engagement: {ENGAGEMENT_NAME}
Client: {CLIENT_NAME}
Authorization: {AUTH_DOCUMENT}
Full Scope: {SCOPE}
Time Budget (total): {TOTAL_TIME_BUDGET}
Collaboration Model: {MODEL}  # Phase Decomposition / Target Parallelization / Tool Specialization / Coordinator-Worker

PHASE 1 — DECOMPOSE
Using the {MODEL} model, decompose the above scope into discrete agent tasks.
For each task, define:
  - Agent role and mandate
  - Assigned scope subset
  - Time budget
  - Start condition (immediate or depends on: <task>)
  - Expected output format

PHASE 2 — DISPATCH
Dispatch all immediately-startable tasks to their assigned agents.
Log each dispatch with: agent_id, task_id, assigned_scope, start_time.

PHASE 3 — MONITOR
Every {CHECKPOINT_INTERVAL}, check each active agent:
  - Status: running / complete / failed / timed_out
  - Progress: findings_count, scope_coverage_percent
  - Alerts: escalations raised?
  If agent fails: attempt reassignment or log gap for manual follow-up.
  If agent exceeds time budget: collect partial results, mark task as partial.

PHASE 4 — TRIGGER DEPENDENT TASKS
When prerequisite tasks complete, dispatch their dependent tasks.
Log trigger event: triggered_task, trigger_condition, trigger_time.

PHASE 5 — AGGREGATE
When all tasks complete (or total time budget expires):
  - Collect all agent result sets
  - Run deduplication checklist (Section 5)
  - Resolve conflicts (Section 6)
  - Build master finding list
  - Verify coverage matrix (Section 7)

PHASE 6 — VERIFY
Dispatch verification-loop for all Critical and High severity findings.

PHASE 7 — REPORT
Dispatch Report Writer Agent with master finding list.
Return final report to operator.

ABORT CONDITIONS:
  - Scope violation by any agent → stop that agent immediately, log incident
  - Authorization expires → stop all agents, preserve evidence
  - Operator requests stop → halt all agents, preserve current state
```

---

## 4. Result Aggregation Format

### Standard Finding JSON Schema

```json
{
  "finding_id": "<agent_id>-<sequential_number>",
  "agent_id": "<role>-<instance>",
  "title": "<canonical finding title>",
  "severity": "Critical | High | Medium | Low | Informational",
  "cvss_score": "<0.0-10.0 or null>",
  "cvss_vector": "<CVSS:3.1/AV:.../... or null>",
  "target": {
    "host": "<IP or hostname>",
    "port": "<port number or null>",
    "protocol": "<tcp/udp/http/https/etc or null>",
    "path": "<URL path or file path or null>"
  },
  "category": "<e.g., Injection, Authentication, Misconfiguration, Exposure>",
  "description": "<one-paragraph technical description of the finding>",
  "evidence": {
    "command": "<exact command(s) used>",
    "output": "<relevant output snippet, max 500 chars>",
    "screenshot_path": "<path to screenshot file or null>",
    "proof_of_concept": "<PoC code or payload or null>"
  },
  "remediation": "<specific remediation recommendation>",
  "references": ["<CVE-ID or URL>"],
  "timestamp": "<ISO 8601 datetime>",
  "confidence": "Confirmed | Likely | Suspected",
  "status": "Open | Verified | Duplicate | Conflict | False-Positive"
}
```

### Master Finding List Format

```json
{
  "engagement": "<engagement name>",
  "generated_at": "<ISO 8601 datetime>",
  "coordinator_agent": "<agent_id>",
  "total_findings": <integer>,
  "severity_summary": {
    "Critical": <integer>,
    "High": <integer>,
    "Medium": <integer>,
    "Low": <integer>,
    "Informational": <integer>
  },
  "agents_deployed": ["<agent_id>", "..."],
  "findings": [
    { "<standard finding JSON>" }
  ],
  "conflicts_resolved": <integer>,
  "duplicates_merged": <integer>,
  "coverage_gaps": ["<scope item with no findings or partial coverage>"]
}
```

---

## 5. Deduplication Checklist

Run this checklist after all agent results are collected, before producing the master finding list.

```
DEDUPLICATION CHECKLIST

Step 1 — Normalize Titles
  [ ] Map all variant names to canonical titles
      Examples:
        "SQL Injection" = "SQLi" = "SQL injection via GET parameter" → "SQL Injection"
        "Missing Security Headers" = "No X-Frame-Options" → context-dependent, keep distinct if target differs
  [ ] Use CVE ID as canonical key when available

Step 2 — Build Candidate Duplicate Pairs
  [ ] For each finding pair (A, B):
      - Same canonical title? (from Step 1)
      - Same target host + port?
      - Same URL path or service?
      If all three: mark as duplicate candidate

Step 3 — Compare Evidence
  [ ] For each duplicate candidate pair:
      - Do the evidence snippets describe the same vulnerability instance?
        YES → confirmed duplicate → proceed to Step 4
        NO (same title, different instance) → both are distinct → keep both, note similarity

Step 4 — Merge Confirmed Duplicates
  [ ] Keep the higher-severity rating between the two
  [ ] Keep the higher-confidence rating between the two
  [ ] Set primary finding_id to the earlier-timestamped finding
  [ ] Append secondary finding's evidence as "corroborating_evidence" field
  [ ] Record both agent_ids in a "reported_by" array
  [ ] Set status = "Open" (merged), increment duplicates_merged counter

Step 5 — Verify Deduplication Output
  [ ] No two findings in master list share same title + target + path
  [ ] All merged findings have "reported_by" arrays with 2+ agent IDs
  [ ] Duplicates_merged count matches number of merge operations performed
  [ ] Total unique findings = original count - duplicates_merged
```

---

## 6. Conflict Resolution Decision Tree

Use when two agents report the same finding with conflicting status or severity.

```
CONFLICT: Agent-A says [VULNERABLE], Agent-B says [NOT VULNERABLE]
  (or: Agent-A rates Critical, Agent-B rates Medium)

Step 1 — Gather Both Evidence Sets
  ├── Read Agent-A: command used, output, timestamp, methodology
  └── Read Agent-B: command used, output, timestamp, methodology

Step 2 — Check Methodology Differences
  ├── Different tools? (e.g., sqlmap vs manual) → methodology gap; both valid
  ├── Different payloads? → one may have triggered, other missed
  ├── Different timing? → target state may have changed between tests
  └── Same methodology, same tool → genuine conflict; continue

Step 3 — Check Target State Consistency
  ├── Was target restarted or reconfigured between Agent-A and Agent-B?
  │   YES → earlier result may be stale; use later result, flag as "state change suspected"
  └── NO → genuine conflict confirmed; continue

Step 4 — Dispatch Verification Agent
  ├── Assign verification-loop agent with explicit brief:
  │     "Test [finding title] on [target] using BOTH methodologies.
  │      Return: vulnerable / not-vulnerable / inconclusive with full evidence."
  └── Await result

Step 5 — Apply Verification Result
  ├── VULNERABLE confirmed → use higher severity, status = "Verified"
  ├── NOT VULNERABLE confirmed → status = "False-Positive", document both agents' evidence
  └── INCONCLUSIVE → status = "Conflict — Manual Verification Required"
              severity = higher of the two original ratings
              attach all three evidence sets (Agent-A, Agent-B, Verification)

Step 6 — Severity Conflicts (both agree vulnerable, differ on severity)
  ├── CVSS score available for both? → use the higher CVSS vector as authoritative
  ├── No CVSS? → use the more conservative (higher) severity
  └── Document both ratings and reasoning in finding notes

Step 7 — Critical Finding Conflicts
  └── ALWAYS escalate to human operator before closing a Critical conflict
      Do not resolve Critical conflicts autonomously
```

---

## 7. Coverage Verification Matrix

Build this matrix after deduplication. Every row must be filled before closing the engagement.

```
| Scope Item          | Agent Assigned   | Status      | Findings Count | Notes                     |
|---------------------|-----------------|-------------|----------------|---------------------------|
| 192.168.1.0/24      | Network-Scanner  | Complete    | 7              |                           |
| app.example.com     | Web-Tester-01    | Complete    | 3              |                           |
| api.example.com     | Web-Tester-02    | Partial     | 1              | Time budget expired at 60%|
| staging.example.com | Web-Tester-03    | Complete    | 0              | Clean — verified          |
| OSINT footprint     | OSINT-Agent      | Complete    | 2              |                           |
| firmware.bin        | Binary-Analyst   | Failed      | 0              | Agent timeout — GAP       |

Gap Actions Required:
  [ ] Any row with Status=Failed or Status=Partial → assign follow-up agent or document as known gap
  [ ] Any row with Findings Count=0 and Status=Complete → confirm agent actually assessed (review agent log)
  [ ] All rows with Status=Complete and Findings Count>0 → confirm findings in master list

Coverage Summary:
  Total scope items: {N}
  Fully covered: {X}
  Partially covered: {Y}
  Not covered (gaps): {Z}
  Coverage percentage: {X/N * 100}%
```

---

## 8. Coordinator Decision Tree

Use at each MONITOR checkpoint and when faced with coordination decisions.

```
COORDINATOR DECISION TREE

Q1: Is an agent overdue (past time budget)?
  YES → Collect partial results → Mark task as "Partial" → Log gap → Continue
  NO → Continue to Q2

Q2: Has an agent reported an escalation?
  YES → Read escalation type:
    ├── Out-of-scope discovery → halt that agent's scope extension, log, continue other agents
    ├── Critical 0-day → notify human operator immediately, do not halt engagement
    ├── Scope violation → halt that agent entirely, document incident
    └── Agent failure → attempt task reassignment to backup agent; if none, log gap
  NO → Continue to Q3

Q3: Should tasks run in parallel or sequentially?
  Parallel when:
    ├── Tasks have no data dependencies on each other
    ├── Tasks target different hosts/services
    └── Combined load does not exceed rate limits on shared infrastructure
  Sequential when:
    ├── Task B requires Task A's output as input
    ├── Tasks compete for same authentication session
    └── Sequential execution required by methodology

Q4: Should two agents be merged into one?
  MERGE when:
    ├── Remaining tasks for both agents fit within one agent's time budget
    ├── One agent has become idle while the other is overloaded
    └── Remaining scope is below the granularity threshold (< 10 min of work)
  DO NOT MERGE when:
    ├── Agents have different tool specializations required for remaining tasks
    └── Merging would create a single point of failure for critical coverage

Q5: Should a task be re-dispatched to a different agent?
  YES when:
    ├── Original agent failed or timed out
    ├── Original agent's methodology was inappropriate for the target
    └── Conflict resolution requires independent retest
  NO when:
    └── Failure was due to target being unreachable (reassignment won't help)

Q6: Should the coordinator escalate to human?
  ALWAYS escalate when:
    ├── Scope violation occurred
    ├── Critical conflict cannot be resolved autonomously
    ├── Unexpected critical infrastructure discovered (ICS, medical devices)
    ├── Evidence of active threat actor on target
    └── Authorization document ambiguity blocks progress
```
