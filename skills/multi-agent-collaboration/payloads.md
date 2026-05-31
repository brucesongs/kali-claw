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

---

## 7. Agent Communication Patterns

### Task Assignment Message
```json
{
  "type": "task_assign",
  "from": "coordinator",
  "to": "agent-recon-01",
  "task_id": "RECON-001",
  "objective": "Enumerate subdomains and open ports for target.com",
  "scope": ["*.target.com"],
  "deadline": "2026-05-29T12:00:00Z",
  "priority": "high",
  "dependencies": []
}
```

### Status Report Message
```json
{
  "type": "status_report",
  "from": "agent-recon-01",
  "task_id": "RECON-001",
  "status": "in_progress",
  "progress": 0.6,
  "findings_count": 12,
  "blockers": [],
  "eta_minutes": 15
}
```

### Finding Handoff Message
```json
{
  "type": "finding_handoff",
  "from": "agent-recon-01",
  "to": "agent-exploit-01",
  "finding": {
    "type": "open_service",
    "host": "admin.target.com",
    "port": 8443,
    "service": "Apache Tomcat 9.0.50",
    "confidence": 0.95
  },
  "suggested_action": "Test for CVE-2021-42013 path traversal"
}
```

### Conflict Report Message
```json
{
  "type": "conflict_report",
  "from": "agent-exploit-01",
  "conflicting_findings": [
    {"agent": "agent-recon-01", "claim": "Port 8443 running Tomcat 9.0.50"},
    {"agent": "agent-exploit-01", "claim": "Port 8443 running Tomcat 10.1.2"}
  ],
  "resolution_needed": "version_verification",
  "suggested_resolver": "agent-recon-01"
}
```

## 8. Coordinator Orchestration Scripts

### Parallel Task Dispatch
```python
import asyncio
from dataclasses import dataclass

@dataclass
class AgentTask:
    agent_id: str
    task_id: str
    objective: str
    scope: list

async def dispatch_parallel(tasks):
    results = await asyncio.gather(*[
        send_task(task) for task in tasks
    ], return_exceptions=True)
    
    for task, result in zip(tasks, results):
        if isinstance(result, Exception):
            await reassign_task(task)
        else:
            print(f"OK {task.task_id}: {result.findings_count} findings")
```

### Health Check Loop
```python
async def monitor_agents(agents, interval=60):
    while True:
        for agent in agents:
            status = await agent.heartbeat()
            if status.is_stale(threshold_seconds=300):
                await coordinator.handle_stale_agent(agent)
            elif status.progress_stalled(threshold_minutes=10):
                await coordinator.nudge_or_reassign(agent)
        await asyncio.sleep(interval)
```

### Result Aggregation
```python
def aggregate_findings(agent_results):
    all_findings = []
    seen = set()
    
    for result in agent_results:
        for finding in result.findings:
            key = (finding.host, finding.port, finding.vuln_type)
            if key not in seen:
                seen.add(key)
                all_findings.append(finding)
            else:
                existing = next(f for f in all_findings if (f.host, f.port, f.vuln_type) == key)
                existing.confidence = min(0.99, existing.confidence + 0.1)
    
    return sorted(all_findings, key=lambda f: f.severity, reverse=True)
```

---

## 9. Agent Orchestration Patterns

### Coordinator Pattern — Central Hub

```python
import asyncio
from enum import Enum

class AgentState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class CoordinatorHub:
    def __init__(self):
        self.agents = {}
        self.task_queue = asyncio.Queue()
        self.results = []

    async def register_agent(self, agent_id, capabilities):
        self.agents[agent_id] = {
            "state": AgentState.IDLE,
            "capabilities": capabilities,
            "current_task": None
        }

    async def dispatch(self, task):
        best_agent = self._select_agent(task)
        if best_agent:
            self.agents[best_agent]["state"] = AgentState.RUNNING
            self.agents[best_agent]["current_task"] = task
            return await self._send_task(best_agent, task)
        else:
            await self.task_queue.put(task)

    def _select_agent(self, task):
        for agent_id, info in self.agents.items():
            if info["state"] == AgentState.IDLE and task["type"] in info["capabilities"]:
                return agent_id
        return None
```

### Pipeline Pattern — Sequential Processing

```python
class PipelineOrchestrator:
    def __init__(self, stages):
        self.stages = stages  # ordered list of agent roles

    async def execute(self, initial_input):
        current_data = initial_input
        for stage in self.stages:
            agent = await self._get_agent_for_stage(stage)
            result = await agent.process(current_data)
            if result.get("error"):
                return {"status": "failed", "stage": stage, "error": result["error"]}
            current_data = result["output"]
        return {"status": "completed", "final_output": current_data}

    async def _get_agent_for_stage(self, stage):
        # Select or spawn agent matching the stage role
        pass

# Usage: Recon → Scan → Exploit → Post-Exploit → Report
pipeline = PipelineOrchestrator([
    "recon_agent", "scan_agent", "exploit_agent", "postexploit_agent", "report_agent"
])
```

### Swarm Pattern — Decentralized Collaboration

```python
import asyncio
import random

class SwarmAgent:
    def __init__(self, agent_id, shared_board):
        self.agent_id = agent_id
        self.shared_board = shared_board  # shared task/finding board

    async def run(self):
        while True:
            task = await self.shared_board.claim_task(self.agent_id)
            if not task:
                break
            result = await self._execute(task)
            await self.shared_board.post_finding(self.agent_id, result)
            # Publish new tasks discovered during execution
            for new_task in result.get("spawned_tasks", []):
                await self.shared_board.add_task(new_task)

    async def _execute(self, task):
        # Agent-specific execution logic
        pass

class SharedBoard:
    def __init__(self):
        self.tasks = asyncio.Queue()
        self.findings = []
        self.claimed = set()

    async def claim_task(self, agent_id):
        try:
            task = self.tasks.get_nowait()
            self.claimed.add((agent_id, task["id"]))
            return task
        except asyncio.QueueEmpty:
            return None

    async def post_finding(self, agent_id, finding):
        self.findings.append({"agent": agent_id, **finding})

    async def add_task(self, task):
        await self.tasks.put(task)
```

### Fan-Out / Fan-In Pattern

```python
async def fan_out_fan_in(targets, agent_pool, timeout=300):
    """Distribute targets across agents, collect all results"""
    tasks = []
    for i, target in enumerate(targets):
        agent = agent_pool[i % len(agent_pool)]
        tasks.append(asyncio.create_task(
            asyncio.wait_for(agent.scan(target), timeout=timeout)
        ))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    successful = [r for r in results if not isinstance(r, Exception)]
    failed = [(i, r) for i, r in enumerate(results) if isinstance(r, Exception)]

    return {
        "successful": successful,
        "failed": failed,
        "success_rate": len(successful) / len(results)
    }
```

### Event-Driven Orchestration

```python
import asyncio
from collections import defaultdict

class EventBus:
    def __init__(self):
        self.subscribers = defaultdict(list)

    def subscribe(self, event_type, handler):
        self.subscribers[event_type].append(handler)

    async def publish(self, event_type, data):
        for handler in self.subscribers[event_type]:
            asyncio.create_task(handler(data))

# Usage
bus = EventBus()

async def on_recon_complete(data):
    # Automatically trigger scanning when recon finishes
    for host in data["hosts"]:
        await bus.publish("scan_request", {"host": host})

async def on_vuln_found(data):
    # Automatically trigger verification when vuln found
    await bus.publish("verify_request", {"finding": data})

bus.subscribe("recon_complete", on_recon_complete)
bus.subscribe("vuln_found", on_vuln_found)
```

---

## 10. Load Balancing and Scaling

### Round-Robin Work Distribution

```python
class RoundRobinDistributor:
    def __init__(self, agents):
        self.agents = agents
        self.index = 0

    def next_agent(self):
        agent = self.agents[self.index % len(self.agents)]
        self.index += 1
        return agent

    async def distribute_tasks(self, tasks):
        assignments = {}
        for task in tasks:
            agent = self.next_agent()
            assignments[task["id"]] = agent.agent_id
            await agent.assign(task)
        return assignments
```

### Weighted Load Balancing

```python
class WeightedBalancer:
    def __init__(self, agents):
        self.agents = agents  # each has .capacity and .current_load

    def select_agent(self, task_weight=1):
        available = [a for a in self.agents if a.current_load + task_weight <= a.capacity]
        if not available:
            return None
        # Select agent with most remaining capacity
        return min(available, key=lambda a: a.current_load / a.capacity)

    async def assign(self, task):
        agent = self.select_agent(task.get("weight", 1))
        if agent:
            agent.current_load += task.get("weight", 1)
            result = await agent.execute(task)
            agent.current_load -= task.get("weight", 1)
            return result
        raise RuntimeError("No available agents with sufficient capacity")
```

### Agent Pool Management

```python
class AgentPool:
    def __init__(self, min_agents=2, max_agents=10, scale_threshold=0.8):
        self.min_agents = min_agents
        self.max_agents = max_agents
        self.scale_threshold = scale_threshold
        self.agents = []

    async def scale_check(self):
        utilization = sum(a.current_load for a in self.agents) / sum(a.capacity for a in self.agents)
        if utilization > self.scale_threshold and len(self.agents) < self.max_agents:
            await self._scale_up()
        elif utilization < 0.3 and len(self.agents) > self.min_agents:
            await self._scale_down()

    async def _scale_up(self):
        new_agent = await self._spawn_agent()
        self.agents.append(new_agent)
        print(f"[+] Scaled up: {len(self.agents)} agents active")

    async def _scale_down(self):
        idle_agent = next((a for a in self.agents if a.current_load == 0), None)
        if idle_agent:
            self.agents.remove(idle_agent)
            await idle_agent.shutdown()
            print(f"[-] Scaled down: {len(self.agents)} agents active")
```

### Task Priority Queue

```python
import heapq
from dataclasses import dataclass, field

@dataclass(order=True)
class PrioritizedTask:
    priority: int
    task: dict = field(compare=False)

class PriorityTaskQueue:
    def __init__(self):
        self.heap = []
        self.counter = 0

    def push(self, task, priority):
        # Lower number = higher priority
        heapq.heappush(self.heap, PrioritizedTask(priority, task))

    def pop(self):
        if self.heap:
            return heapq.heappop(self.heap).task
        return None

    def peek_priority(self):
        return self.heap[0].priority if self.heap else None

# Priority levels: 1=Critical finding verification, 2=Exploitation, 3=Scanning, 4=Reporting
queue = PriorityTaskQueue()
queue.push({"type": "verify", "finding": "sqli"}, priority=1)
queue.push({"type": "scan", "target": "10.0.0.1"}, priority=3)
```

### Adaptive Rate Control

```bash
#!/bin/bash
# Adaptive rate control for distributed scanning agents
MAX_RATE=100
CURRENT_RATE=$MAX_RATE
ERROR_COUNT=0
SUCCESS_COUNT=0

adjust_rate() {
    local response_code=$1
    if [ "$response_code" = "429" ] || [ "$response_code" = "503" ]; then
        ERROR_COUNT=$((ERROR_COUNT + 1))
        CURRENT_RATE=$((CURRENT_RATE / 2))
        [ $CURRENT_RATE -lt 5 ] && CURRENT_RATE=5
        echo "[!] Rate limited. Reducing to $CURRENT_RATE req/s"
    else
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        if [ $SUCCESS_COUNT -gt 50 ] && [ $CURRENT_RATE -lt $MAX_RATE ]; then
            CURRENT_RATE=$((CURRENT_RATE + 10))
            SUCCESS_COUNT=0
            echo "[+] Increasing rate to $CURRENT_RATE req/s"
        fi
    fi
}
```

---

## 11. Inter-Agent Security

### Agent Authentication with HMAC

```python
import hmac
import hashlib
import time
import json

class AgentAuthenticator:
    def __init__(self, shared_secret):
        self.shared_secret = shared_secret.encode()

    def sign_message(self, agent_id, message):
        timestamp = str(int(time.time()))
        payload = f"{agent_id}:{timestamp}:{json.dumps(message)}"
        signature = hmac.new(self.shared_secret, payload.encode(), hashlib.sha256).hexdigest()
        return {
            "agent_id": agent_id,
            "timestamp": timestamp,
            "message": message,
            "signature": signature
        }

    def verify_message(self, signed_message, max_age=300):
        agent_id = signed_message["agent_id"]
        timestamp = signed_message["timestamp"]
        message = signed_message["message"]
        signature = signed_message["signature"]

        # Check timestamp freshness
        if abs(time.time() - int(timestamp)) > max_age:
            return False, "Message expired"

        payload = f"{agent_id}:{timestamp}:{json.dumps(message)}"
        expected = hmac.new(self.shared_secret, payload.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature, expected):
            return True, "Valid"
        return False, "Invalid signature"
```

### Trust Boundary Enforcement

```python
class TrustBoundary:
    def __init__(self):
        self.permissions = {
            "recon_agent": ["read_scope", "dns_query", "port_scan"],
            "exploit_agent": ["read_findings", "execute_exploit", "write_evidence"],
            "report_agent": ["read_findings", "read_evidence", "write_report"],
        }

    def check_permission(self, agent_role, action):
        allowed = self.permissions.get(agent_role, [])
        if action not in allowed:
            raise PermissionError(
                f"Agent role '{agent_role}' not authorized for action '{action}'. "
                f"Allowed: {allowed}"
            )
        return True

    def validate_scope(self, agent_id, target):
        assigned_scope = self._get_agent_scope(agent_id)
        if target not in assigned_scope:
            raise ScopeViolation(
                f"Agent {agent_id} attempted to access {target} outside assigned scope"
            )
```

### Encrypted Inter-Agent Communication

```python
from cryptography.fernet import Fernet
import json

class SecureChannel:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt_message(self, sender_id, recipient_id, payload):
        envelope = {
            "from": sender_id,
            "to": recipient_id,
            "payload": payload,
            "timestamp": time.time()
        }
        plaintext = json.dumps(envelope).encode()
        return self.cipher.encrypt(plaintext)

    def decrypt_message(self, encrypted_data, expected_recipient):
        plaintext = self.cipher.decrypt(encrypted_data)
        envelope = json.loads(plaintext)
        if envelope["to"] != expected_recipient:
            raise SecurityError("Message not intended for this agent")
        return envelope["payload"]
```

### Agent Identity Verification

```bash
#!/bin/bash
# Verify agent identity before accepting task results
verify_agent_identity() {
    local agent_id="$1"
    local claimed_token="$2"
    local expected_hash

    # Each agent has a pre-registered identity hash
    expected_hash=$(grep "^${agent_id}:" /etc/agents/registry | cut -d: -f2)

    actual_hash=$(echo -n "$claimed_token" | sha256sum | cut -d' ' -f1)

    if [ "$actual_hash" = "$expected_hash" ]; then
        echo "[+] Agent $agent_id identity verified"
        return 0
    else
        echo "[!] ALERT: Agent $agent_id failed identity verification"
        return 1
    fi
}
```

### Scope Isolation Enforcement

```python
class ScopeIsolator:
    def __init__(self, engagement_scope):
        self.engagement_scope = engagement_scope
        self.agent_scopes = {}
        self.violations = []

    def assign_scope(self, agent_id, scope_subset):
        # Verify subset is within engagement scope
        for item in scope_subset:
            if item not in self.engagement_scope:
                raise ValueError(f"Cannot assign {item} — not in engagement scope")
        self.agent_scopes[agent_id] = set(scope_subset)

    def validate_target(self, agent_id, target):
        allowed = self.agent_scopes.get(agent_id, set())
        if target not in allowed:
            violation = {
                "agent": agent_id,
                "target": target,
                "timestamp": time.time(),
                "action": "blocked"
            }
            self.violations.append(violation)
            raise ScopeViolation(f"Agent {agent_id} blocked from accessing {target}")
        return True
```

---

## 12. Monitoring and Observability

### Agent Health Dashboard

```python
import time
from dataclasses import dataclass

@dataclass
class AgentMetrics:
    agent_id: str
    last_heartbeat: float
    tasks_completed: int
    tasks_failed: int
    findings_reported: int
    avg_task_duration: float
    current_state: str

class MonitoringDashboard:
    def __init__(self):
        self.metrics = {}

    def update_heartbeat(self, agent_id):
        if agent_id not in self.metrics:
            self.metrics[agent_id] = AgentMetrics(
                agent_id=agent_id, last_heartbeat=time.time(),
                tasks_completed=0, tasks_failed=0,
                findings_reported=0, avg_task_duration=0.0,
                current_state="idle"
            )
        self.metrics[agent_id].last_heartbeat = time.time()

    def get_stale_agents(self, threshold_seconds=300):
        now = time.time()
        return [m for m in self.metrics.values()
                if now - m.last_heartbeat > threshold_seconds]

    def summary(self):
        total = len(self.metrics)
        active = sum(1 for m in self.metrics.values() if m.current_state == "running")
        findings = sum(m.findings_reported for m in self.metrics.values())
        return f"Agents: {active}/{total} active | Findings: {findings}"
```

### Task Metrics Collection

```python
import time
from collections import defaultdict

class TaskMetrics:
    def __init__(self):
        self.task_durations = defaultdict(list)
        self.task_outcomes = defaultdict(lambda: {"success": 0, "failure": 0})
        self.start_times = {}

    def task_started(self, task_id, task_type):
        self.start_times[task_id] = (time.time(), task_type)

    def task_completed(self, task_id, success=True):
        if task_id in self.start_times:
            start_time, task_type = self.start_times.pop(task_id)
            duration = time.time() - start_time
            self.task_durations[task_type].append(duration)
            outcome = "success" if success else "failure"
            self.task_outcomes[task_type][outcome] += 1

    def get_stats(self, task_type):
        durations = self.task_durations[task_type]
        outcomes = self.task_outcomes[task_type]
        if not durations:
            return None
        return {
            "avg_duration": sum(durations) / len(durations),
            "max_duration": max(durations),
            "min_duration": min(durations),
            "total_tasks": outcomes["success"] + outcomes["failure"],
            "success_rate": outcomes["success"] / (outcomes["success"] + outcomes["failure"])
        }
```

### Performance Tracking

```bash
#!/bin/bash
# Agent performance tracking script
LOG_FILE="/var/log/agent_performance.log"

track_agent_performance() {
    local agent_id="$1"
    local task_id="$2"
    local start_time=$(date +%s%N)

    # Wait for task completion signal
    wait_for_completion "$agent_id" "$task_id"
    local end_time=$(date +%s%N)

    local duration_ms=$(( (end_time - start_time) / 1000000 ))
    local findings=$(get_findings_count "$agent_id" "$task_id")
    local memory_mb=$(get_agent_memory "$agent_id")

    echo "$(date -Iseconds) | $agent_id | $task_id | ${duration_ms}ms | ${findings} findings | ${memory_mb}MB" >> "$LOG_FILE"
}

# Generate performance report
generate_report() {
    echo "=== Agent Performance Report ==="
    echo "Period: $(head -1 $LOG_FILE | cut -d'|' -f1) to $(tail -1 $LOG_FILE | cut -d'|' -f1)"
    echo ""
    awk -F'|' '{agents[$2]++; findings[$2]+=$5} END {for(a in agents) printf "%s: %d tasks, %d findings\n", a, agents[a], findings[a]}' "$LOG_FILE"
}
```

### Real-Time Alert System

```python
import asyncio
from enum import Enum

class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

class AlertSystem:
    def __init__(self):
        self.handlers = []
        self.alert_history = []

    def add_handler(self, handler):
        self.handlers.append(handler)

    async def fire_alert(self, severity, agent_id, message, context=None):
        alert = {
            "severity": severity.value,
            "agent_id": agent_id,
            "message": message,
            "context": context or {},
            "timestamp": time.time()
        }
        self.alert_history.append(alert)
        for handler in self.handlers:
            await handler(alert)

    async def check_conditions(self, metrics):
        for agent_id, m in metrics.items():
            if time.time() - m.last_heartbeat > 300:
                await self.fire_alert(AlertSeverity.WARNING, agent_id, "Agent heartbeat stale")
            if m.tasks_failed > 3:
                await self.fire_alert(AlertSeverity.CRITICAL, agent_id, "Multiple task failures")
```

### Engagement Progress Tracker

```python
class EngagementTracker:
    def __init__(self, total_scope_items):
        self.total_scope_items = total_scope_items
        self.completed_items = set()
        self.in_progress = set()
        self.findings_by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        self.start_time = time.time()

    def mark_complete(self, scope_item):
        self.in_progress.discard(scope_item)
        self.completed_items.add(scope_item)

    def add_finding(self, severity):
        self.findings_by_severity[severity] += 1

    def progress_report(self):
        elapsed = time.time() - self.start_time
        coverage = len(self.completed_items) / self.total_scope_items * 100
        return {
            "elapsed_minutes": int(elapsed / 60),
            "coverage_percent": round(coverage, 1),
            "items_complete": len(self.completed_items),
            "items_in_progress": len(self.in_progress),
            "items_remaining": self.total_scope_items - len(self.completed_items) - len(self.in_progress),
            "findings": dict(self.findings_by_severity),
            "total_findings": sum(self.findings_by_severity.values())
        }
```

---

## 13. Error Recovery Patterns

### Retry with Exponential Backoff

```python
import asyncio
import random

async def retry_with_backoff(func, max_retries=5, base_delay=1.0, max_delay=60.0):
    for attempt in range(max_retries):
        try:
            return await func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            delay = min(base_delay * (2 ** attempt) + random.uniform(0, 1), max_delay)
            print(f"[!] Attempt {attempt+1} failed: {e}. Retrying in {delay:.1f}s")
            await asyncio.sleep(delay)

# Usage
result = await retry_with_backoff(
    lambda: agent.execute_scan(target),
    max_retries=3,
    base_delay=2.0
)
```

### Circuit Breaker Pattern

```python
import time

class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "closed"  # closed, open, half-open

    async def call(self, func):
        if self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half-open"
            else:
                raise CircuitOpenError("Circuit breaker is open — target unreachable")

        try:
            result = await func()
            if self.state == "half-open":
                self.state = "closed"
                self.failure_count = 0
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                print(f"[!] Circuit OPEN after {self.failure_count} failures")
            raise
```

### Graceful Degradation Strategy

```python
class GracefulDegradation:
    def __init__(self):
        self.degradation_levels = {
            0: "full_operation",
            1: "reduced_scanning_rate",
            2: "passive_only",
            3: "evidence_collection_only",
            4: "emergency_stop"
        }
        self.current_level = 0

    async def escalate(self, reason):
        self.current_level = min(self.current_level + 1, 4)
        level_name = self.degradation_levels[self.current_level]
        print(f"[!] Degradation escalated to level {self.current_level}: {level_name} ({reason})")
        await self._apply_restrictions()

    async def _apply_restrictions(self):
        if self.current_level >= 1:
            await self._reduce_scan_rate(factor=0.5)
        if self.current_level >= 2:
            await self._disable_active_scanning()
        if self.current_level >= 3:
            await self._stop_all_agents()
        if self.current_level >= 4:
            await self._emergency_shutdown()

    def can_perform(self, action_type):
        restrictions = {
            1: ["aggressive_scan"],
            2: ["aggressive_scan", "active_scan", "exploitation"],
            3: ["aggressive_scan", "active_scan", "exploitation", "enumeration"],
            4: ["all"]
        }
        blocked = restrictions.get(self.current_level, [])
        return action_type not in blocked and "all" not in blocked
```

### Task Failover and Reassignment

```python
class FailoverManager:
    def __init__(self, agent_pool):
        self.agent_pool = agent_pool
        self.failed_tasks = []
        self.reassignment_log = []

    async def handle_agent_failure(self, failed_agent_id, task):
        self.failed_tasks.append({"agent": failed_agent_id, "task": task})

        # Find alternative agent with matching capabilities
        alternative = self._find_alternative(failed_agent_id, task)
        if alternative:
            await alternative.assign(task)
            self.reassignment_log.append({
                "task_id": task["id"],
                "from": failed_agent_id,
                "to": alternative.agent_id,
                "reason": "agent_failure"
            })
            return True

        # No alternative available — queue for manual handling
        print(f"[!] No alternative agent for task {task['id']} — queued for manual review")
        return False

    def _find_alternative(self, exclude_id, task):
        for agent in self.agent_pool:
            if agent.agent_id != exclude_id and agent.state == "idle":
                if task["type"] in agent.capabilities:
                    return agent
        return None
```

### State Checkpoint and Recovery

```python
import json
import os

class CheckpointManager:
    def __init__(self, checkpoint_dir="/tmp/agent_checkpoints"):
        self.checkpoint_dir = checkpoint_dir
        os.makedirs(checkpoint_dir, exist_ok=True)

    def save_checkpoint(self, engagement_id, state):
        path = os.path.join(self.checkpoint_dir, f"{engagement_id}.json")
        checkpoint = {
            "engagement_id": engagement_id,
            "timestamp": time.time(),
            "agent_states": state.get("agents", {}),
            "completed_tasks": state.get("completed", []),
            "pending_tasks": state.get("pending", []),
            "findings": state.get("findings", [])
        }
        with open(path, "w") as f:
            json.dump(checkpoint, f, indent=2)
        print(f"[+] Checkpoint saved: {path}")

    def restore_checkpoint(self, engagement_id):
        path = os.path.join(self.checkpoint_dir, f"{engagement_id}.json")
        if not os.path.exists(path):
            return None
        with open(path) as f:
            checkpoint = json.load(f)
        print(f"[+] Restored from checkpoint: {checkpoint['timestamp']}")
        return checkpoint

    async def resume_engagement(self, engagement_id):
        checkpoint = self.restore_checkpoint(engagement_id)
        if not checkpoint:
            raise FileNotFoundError(f"No checkpoint for {engagement_id}")
        # Re-dispatch only pending tasks
        for task in checkpoint["pending_tasks"]:
            await self.coordinator.dispatch(task)
        return checkpoint["findings"]
```
