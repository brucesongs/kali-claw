# Scope Enforcement Operations

Operational guide for configuring scope locks, managing safety modes, tuning dangerous command patterns, applying rate limits, executing incident response, and verifying rules of engagement compliance throughout penetration testing engagements.

---

## 1. Setting Up Scope Locks

A scope lock is the first artifact created for any engagement. No testing begins until a scope lock is active and verified.

### 1.1 Step-by-Step Setup

```text
Step 1: Obtain the authorization document
  - Signed rules of engagement (ROE) from the client
  - Explicit list of in-scope targets (IPs, domains, URLs, CIDRs)
  - Explicit list of exclusions
  - Authorized activity types
  - Time window and constraints

Step 2: Select the scope lock template
  - External penetration test → external template from payloads.md
  - Internal network assessment → internal template from payloads.md
  - Web application assessment → web app template from payloads.md
  - Wireless assessment → wireless template from payloads.md
  - Lab/CTF environment → quick ROE template from payloads.md

Step 3: Fill in every field
  - Do NOT leave fields blank or "TBD"
  - Do NOT assume defaults — explicit is safer than implicit
  - Engagement ID format: ENG-{client}-{YYYY-MM-DD}
  - Use CIDR notation for IP ranges, never prose descriptions

Step 4: Verify the scope lock
  - Run the scope lock verification script from payloads.md
  - Confirm all required fields are present:
    Engagement ID, Authorized targets, Authorized operations,
    Time window, Emergency contact, Abort trigger
  - Cross-check against the original authorization document

Step 5: Save and reference
  - Save as scope-lock.md in the engagement evidence directory
  - Reference the scope lock file in every pre-action checklist
  - The scope lock is immutable during the engagement — changes
    require a new version with operator approval
```

### 1.2 Template Selection by Engagement Type

| Engagement Type | Template | Key Differences |
|----------------|----------|-----------------|
| External pentest | External scope lock | Public IPs, domain-based targeting, CDN considerations |
| Internal assessment | Internal scope lock | VLAN segmentation, domain controller exclusions, business hours |
| Web application | Web app scope lock | URL-based scoping, test account management, injection rate limits |
| Wireless | Wireless scope lock | SSID/BSSID targeting, physical boundaries, channel restrictions |
| Lab/CTF | Quick ROE | Simplified scope, broader permissions, fewer constraints |
| Red team | External + Internal combined | Multi-phase, evolving scope, social engineering permissions |

### 1.3 Common Scope Lock Mistakes

```text
Mistake 1: Vague target definitions
  BAD:  "All company servers"
  GOOD: "10.0.1.0/24, 10.0.2.0/24, excluding 10.0.1.1 (gateway)"

Mistake 2: Missing exclusions
  BAD:  "Authorized targets: 192.168.1.0/24"
  GOOD: "Authorized targets: 192.168.1.0/24, excluding .1 (gateway),
         .2 (DNS), .10 (production database)"

Mistake 3: No time window
  BAD:  "Testing authorized during May 2026"
  GOOD: "Time window: 2026-05-22T09:00:00Z to 2026-05-26T18:00:00Z,
         business hours only (09:00-18:00 UTC)"

Mistake 4: Implicit activity authorization
  BAD:  "Standard penetration test authorized"
  GOOD: Explicit checkbox list from the template with each activity
        marked authorized or not authorized

Mistake 5: Missing abort triggers
  BAD:  (field not present)
  GOOD: "Abort trigger: IDS alert from client, target crash, scope
         violation, operator stop command"
```

---

## 2. Operating Modes Deep-Dive

Safety Guard has three operating modes. Every operation is classified into one of these modes before execution.

### 2.1 Careful Mode (Default)

Careful mode is the baseline for all penetration testing operations. Operations proceed with logging and standard safety checks.

**When it applies:**

```text
- Passive reconnaissance (OSINT, DNS lookups, certificate transparency)
- Active scanning (port scans, service enumeration, banner grabs)
- Vulnerability scanning (nmap scripts, nikto, nuclei)
- Directory and parameter enumeration (gobuster, ffuf, dirb)
- DNS enumeration (dnsrecon, subfinder, amass)
```

**What happens in Careful mode:**

```text
1. Target is verified against the scope lock (automated check)
2. Command is checked against dangerous pattern lists (automated check)
3. Operation is logged with timestamp, target, tool, and command
4. Operation proceeds
5. Rate limits are enforced per the scope lock configuration
```

**Escalation triggers (Careful → Freeze):**

```text
- Impact assessment changes from Low/Medium to High
- Operation is irreversible (cannot be undone)
- Operation modifies the target system state
- Target responds with unexpected behavior (possible instability)
- Rate limit is hit (HTTP 429, connection drops, account lockout)
```

### 2.2 Freeze Mode

Freeze mode pauses the operation and requires explicit operator confirmation before proceeding. This is the safety net for high-impact actions.

**When it applies:**

```text
- Exploit execution (Metasploit, manual exploits, proof-of-concept code)
- Brute force attacks (hydra, medusa, ncrack, crackmapexec)
- Denial of service patterns (hping3 --flood, slowloris, siege)
- File modification on target (web shell upload, config changes)
- Privilege escalation (sudo, su, linpeas, getsystem)
- Network tunneling (SSH port forwarding, chisel, proxychains)
- Accessing sensitive data (database dumps, user tables)
- Installing persistence mechanisms (crontab, systemd, registry)
```

**What happens in Freeze mode:**

```text
1. Operation is PAUSED — command is not executed
2. Safety check summary is presented:
   - Target and operation details
   - Impact assessment (High/Critical)
   - Reversibility assessment
   - Rate limit status
   - Rollback plan (if any)
3. Operator must explicitly confirm: PROCEED or ABORT
4. If PROCEED: operation executes with enhanced logging
5. If ABORT: operation is cancelled, reason logged
6. Confirmation timestamp is recorded for audit trail
```

**Escalation triggers (Freeze → Guard):**

```text
- Operator cannot be reached for confirmation
- Target is identified as out of scope during the check
- Operation would affect third-party systems
- Operation could cause irreversible damage with no rollback
```

### 2.3 Guard Mode (Block)

Guard mode blocks the operation entirely. The command is never executed.

**When it applies:**

```text
- Commands targeting out-of-scope systems
- Mass deletion commands (rm -rf /, DROP DATABASE)
- Public network exposure (binding to 0.0.0.0)
- Credential exfiltration to external services
- Fork bombs and system crash patterns
- Mass scanning of public internet ranges
- Ransomware-like encryption patterns
- Network disruption commands (iptables -F on target)
```

**What happens in Guard mode:**

```text
1. Operation is BLOCKED — command is never executed
2. Blocking reason is logged:
   [GUARD-BLOCK] {timestamp} | Command: {command}
   Reason: {which pattern matched}
   Target: {target}
   Action: BLOCKED — operation not executed
3. Operator is notified of the blocked operation
4. Incident is logged for safety audit
5. No override is available without modifying the scope lock
```

**De-escalation (Guard → Freeze):**

Guard blocks are absolute within a given scope lock. To proceed with a blocked operation, the scope lock must be modified with operator approval:

```text
1. Operator reviews the blocked operation
2. Operator updates the scope lock to explicitly authorize the specific action
3. Scope lock version is incremented
4. Operation is reclassified under the new scope lock
5. Original block and override are both logged for audit trail
```

### 2.4 Mode Decision Matrix

```text
                 In Scope?
                /         \
              YES          NO → GUARD (block)
              /
        Impact Level?
       /      |       \
     Low    Medium    High/Critical
      |       |            |
   Reversible?        Reversible?
    /    \              /    \
  YES    NO           YES    NO
   |      |            |      |
CAREFUL  FREEZE     FREEZE  FREEZE*

*FREEZE with mandatory rollback plan or Guard if no rollback possible

Scope UNCLEAR → Always FREEZE, ask operator to clarify
```

---

## 3. Dangerous Command Pattern Management

The dangerous command pattern lists are the detection engine for safety mode classification. They must be maintained as new tools and techniques are encountered.

### 3.1 Pattern Architecture

Patterns are organized in three tiers matching the three safety modes:

```text
Tier 1 — Guard patterns:  Irreversible damage, legal violations, ethical breaches
Tier 2 — Freeze patterns: High-impact operations requiring human judgment
Tier 3 — Careful patterns: Standard operations with IDS/detection risk
```

Each pattern has four components:

```yaml
pattern_name:
  regex: 'detection regular expression'
  reason: 'why this pattern is dangerous'
  example: 'concrete example of the command'
  tier: 'guard | freeze | careful'
```

### 3.2 Adding Custom Patterns

When a new tool or technique is encountered that is not covered by existing patterns:

```text
Step 1: Determine the tier
  - Could this command cause irreversible damage? → Guard
  - Does this command require human judgment? → Freeze
  - Could this command trigger detection systems? → Careful

Step 2: Write the regex
  - Match the tool name and its dangerous flags
  - Use word boundaries where possible to avoid false matches
  - Test the regex against known-good and known-bad examples

Step 3: Document the rationale
  - Why is this command dangerous?
  - What is the worst-case outcome if it runs unchecked?
  - Under what conditions is it acceptable (with Freeze confirmation)?

Step 4: Test for false positives
  - Does the regex match any normal, safe usage of the tool?
  - Does it match unrelated commands that share keywords?
  - Adjust specificity if false positive rate is too high
```

**Example — adding a new tool pattern:**

```yaml
# New tool: chisel (TCP tunnel)
# Concern: creates network tunnels that could bypass scope boundaries

chisel_tunnel:
  regex: 'chisel\s+(server|client)'
  reason: "Network tunneling changes traffic routing, may bypass scope boundaries"
  example: "chisel client attacker:8080 R:8443:internal:443"
  tier: freeze
```

### 3.3 Tuning False Positives

False positives erode trust in the safety system. When a pattern blocks or pauses a safe operation:

```text
Diagnosis:
  1. What command was flagged?
  2. Which pattern matched?
  3. Was the match correct (genuinely dangerous) or a false positive?

Resolution options:

Option A: Narrow the regex
  Before: 'ssh\s+-[RLD]'  (matches all SSH port forwarding)
  After:  'ssh\s+-[RLD]\s+\d+:(?!127\.0\.0\.1)'  (allows localhost-only forwarding)

Option B: Add a context exclusion
  Pattern stays broad, but specific safe contexts are whitelisted.
  Example: Allow "nmap -sS" against scope-locked targets only.

Option C: Reclassify the tier
  Move from Guard to Freeze if the operation is dangerous but not
  categorically forbidden. This allows operator override.

Document every tuning decision:
  [PATTERN-TUNE] {date} | Pattern: {name} | Change: {what changed}
  Reason: {why the false positive occurred}
  Verification: {tested against N commands, 0 false positives}
```

### 3.4 Pattern Maintenance Schedule

```text
After each engagement:
  - Review any Guard blocks that occurred — were they correct?
  - Review any Freeze pauses — were they necessary?
  - Identify tools used that lack pattern coverage

Monthly:
  - Run the command history scan from payloads.md safety audit
  - Check for new tools in TOOLS.md that need pattern entries
  - Review false positive log and apply pending tuning decisions

Quarterly:
  - Full review of all patterns against current tool inventory
  - Update regex for tools that have changed CLI syntax
  - Archive patterns for deprecated tools
```

---

## 4. Rate Limiting in Practice

Rate limiting prevents target destabilization and reduces detection risk. The rate limit system has three layers: per-service defaults, per-tool overrides, and global limits.

### 4.1 Configuring Per-Target Limits

Each target service type has a default rate limit profile from payloads.md. Configure these in the scope lock for each engagement:

```text
Service identification:
  - Web application (HTTP/HTTPS) → 10 req/s, burst 20
  - API endpoint (REST/GraphQL) → 5 req/s, burst 10
  - SSH service → 1 req/s, burst 3
  - DNS resolver → 20 req/s, burst 50
  - SMB service → 5 req/s, burst 10
  - Database service → 5 req/s, burst 10
  - Generic TCP → 10 req/s, burst 20

Adjustment factors:
  - Production target: reduce all limits by 50%
  - Staging/test target: use defaults
  - Lab/CTF target: increase by 2x (if no shared infrastructure)
  - Client requests lower limits: always comply
  - Fragile/legacy system: reduce to 25% of defaults
```

### 4.2 Per-Tool Overrides

Some tools have aggressive defaults that exceed safe rate limits. Always apply tool-specific overrides:

```text
nmap:
  Default timing: -T3 (never exceed -T4 in production)
  Max parallel hosts: 5
  Stealth mode: -T2 with --min-rate 1 --max-rate 5

hydra:
  Max tasks: -t 4 (not the default 16)
  Lockout monitoring: stop after 3 failures per account
  Always: -W 1 (1-second wait between attempts)

gobuster:
  Max threads: -t 10 (reduce to -t 3 on 429 responses)
  Delay: --delay 100ms for sensitive targets

ffuf:
  Max rate: -rate 50 (reduce to -rate 10 for API endpoints)
  Auto-throttle: use -sf to stop on 403 floods

nuclei:
  Max rate: -rl 25 (reduce to -rl 5 for sensitive targets)
  Bulk size: -bs 10
  Concurrency: -c 5

sqlmap:
  Delay: --delay 1 (minimum)
  Threads: --threads 1 (never exceed 3 in production)
  Technique: --technique=B for stealthy, avoid --technique=T on fragile systems
```

### 4.3 Backoff Strategy

When rate limiting is detected, follow the three-strike backoff:

```text
Detection signals:
  - HTTP 429 (Too Many Requests)
  - HTTP 503 (Service Unavailable) after sustained requests
  - Connection reset or timeout after period of successful connections
  - Account lockout notification
  - WAF block page appears
  - DNS SERVFAIL or REFUSED responses

Strike 1: Detected rate limiting
  Action: Wait 5 seconds, reduce rate by 50%
  Log: [RATE-LIMIT] Strike 1 at {timestamp}, reducing to {new_rate} req/s

Strike 2: Rate limiting detected again
  Action: Wait 30 seconds, reduce rate by 75% from original
  Log: [RATE-LIMIT] Strike 2 at {timestamp}, reducing to {new_rate} req/s

Strike 3: Rate limiting detected a third time
  Action: STOP all operations against this target
  Log: [RATE-LIMIT] Strike 3 at {timestamp}, STOPPING
  Notification: Alert operator, wait for decision before resuming

Post-recovery:
  After operator clearance, resume at Strike 2 rate (25% of original)
  and increase gradually only if no further rate limiting is detected.
```

### 4.4 Global Rate Limit Enforcement

All concurrent operations against all targets share a global limit:

```text
Global limits:
  - Total outbound requests: 50/second across all targets and tools
  - Total concurrent connections: 20
  - Total bandwidth: 10 Mbps

Warning at 80% of any limit:
  Log warning, automatically reduce rates by 25%

Critical at 95% of any limit:
  Pause all operations, notify operator

Breach:
  Emergency stop all operations
```

---

## 5. Incident Response Playbook Walkthrough

When something goes wrong during testing, the incident response protocol activates. The level determines the response.

### 5.1 Level 1 — Minor Issue

**Trigger examples:**

```text
- Target service logged your scan and an admin noticed
- A non-critical service restarted due to your scan traffic
- You triggered an IDS alert that was forwarded to the SOC
- A test visible in application logs (expected but noted)
```

**Decision tree:**

```text
Is the service still functioning normally?
  YES → Was this behavior expected from the test?
         YES → Log, pause 60 seconds, continue at reduced rate
         NO  → Log, review command and target, verify scope
  NO  → Escalate to Level 2
```

**Response walkthrough:**

```text
Minute 0: Detect the issue
  - Stop the current operation (the specific tool/command, not everything)
  - Log immediately:
    [INCIDENT-L1] 2026-05-22T14:30:00Z | Target: 10.0.1.50
    Action: nmap -sV scan triggered IDS alert
    Impact: Alert generated, no service disruption

Minute 1-5: Assess
  - Is the target still responsive?
  - Is this within expected behavior for the test type?
  - Does the scope lock authorize this activity?

Minute 5-15: Respond
  - If expected: Note in evidence log, pause 60 seconds, continue
  - If unexpected: Review command parameters, reduce aggressiveness
  - Add to engagement notes for final report

Escalation to Level 2:
  - Issue recurs 3 times
  - Service becomes degraded
  - Client contacts you about the alert
```

### 5.2 Level 2 — Service Impact

**Trigger examples:**

```text
- Target web application returns 503 errors after your testing
- Database queries time out for legitimate users during your scan
- You discover you accessed data you should not have (scope mistake)
- Client calls to report service degradation
```

**Decision tree:**

```text
Is the service impact confirmed?
  YES → Did your actions cause it?
         YES → STOP ALL, notify operator in 5 minutes
         NO  → (still STOP, but note that cause may be external)
         UNSURE → STOP ALL, investigate before notifying

Is sensitive data exposed?
  YES → Escalate to Level 3
  NO  → Continue Level 2 response
```

**Response walkthrough:**

```text
Minute 0: Stop everything
  - STOP ALL operations, not just the suspect tool
  - Preserve all terminal sessions and log buffers
  - Do NOT close any windows or clear any output

Minute 0-2: Log everything
  [INCIDENT-L2] 2026-05-22T15:00:00Z | Target: app.target.com
  SEVERITY: SERVICE IMPACT
  Impact: Application returning 503 to all users
  Last command: ffuf -u https://app.target.com/FUZZ -w big.txt -t 50
  Evidence: evidence/ffuf-output-20260522.txt, evidence/terminal-log.txt

Minute 2-5: Notify operator
  Send notification with:
  - What happened (specific impact observed)
  - What you were doing (exact command)
  - What you think caused it (assessment)
  - Current status (all operations halted)

Minute 5+: Wait
  DO NOT resume testing
  DO NOT attempt to fix the target
  Wait for operator decision:
    RESUME: Target confirmed recovered, proceed with restrictions
    MODIFY: Scope or technique restrictions updated
    ABORT: Engagement terminated

Post-incident: Document
  Full incident report in engagement notes with:
  - Minute-by-minute timeline
  - Root cause analysis
  - Evidence file references
  - Prevention recommendations
```

### 5.3 Level 3 — Critical Incident

**Trigger examples:**

```text
- Target server crashed and cannot be restarted by the client
- Production database data was accidentally modified or deleted
- You gained access to real customer PII that was not in scope
- Your actions affected a system outside the authorized scope
- Exploit caused cascading failure across multiple services
```

**Decision tree:**

```text
Has irreversible damage occurred?
  YES → Full Level 3 response, disconnect immediately
  NO  → Is there risk of further damage if connected?
         YES → Disconnect, then Level 3
         NO  → Level 3 without disconnect

Is out-of-scope data or systems affected?
  YES → Client notification is mandatory (not optional)
  NO  → Client notification per ROE requirements
```

**Response walkthrough:**

```text
Minute 0: Emergency stop
  - STOP ALL operations IMMEDIATELY
  - Disconnect from target network if there is any risk of further damage
  - Do NOT attempt to fix anything
  - Do NOT delete evidence
  - Do NOT try to cover up what happened

Minute 0-1: Preserve evidence
  - Save all terminal output (screenshot if necessary)
  - Save all tool output files
  - Save network capture files (if running)
  - Timestamp everything

Minute 1-2: Notify operator
  CRITICAL notification:
  - IMMEDIATE ACTION REQUIRED
  - What happened (impact description)
  - What was the last action taken
  - Current state of all evidence
  - Confirmation that all operations are stopped

Minute 2+: Full stop
  NO further testing until:
  [ ] Operator has reviewed the incident
  [ ] Client has been notified (if required)
  [ ] Root cause analysis is complete
  [ ] Written approval to resume is received

Post-incident: Formal report
  Required before any further engagement activity:
  - Complete timeline from start of testing session
  - Root cause analysis (what command, what went wrong)
  - Full evidence inventory
  - Corrective actions (what will be done differently)
  - Client communication log
  - Approval to resume with conditions
```

---

## 6. Pre-Action Checklist Usage

The pre-action checklist is the operational mechanism that enforces scope verification before every operation. It is not a one-time task — it runs before every potentially impactful command.

### 6.1 When to Run the Checklist

```text
Always run before:
  - Any command targeting a specific IP, hostname, or URL
  - Any exploit or active attack
  - Any brute force or credential testing
  - Any file upload or modification on target
  - Any privilege escalation attempt
  - Starting any automated scan or enumeration

May skip for:
  - Local-only operations (editing files on your own system)
  - Reviewing documentation or notes
  - Running tools against localhost lab targets (with active lab scope lock)
```

### 6.2 Automated Scope Verification

The scope lock file enables automated target verification:

```text
Check flow:
  1. Extract target from the pending command
  2. Compare against "Authorized targets" in scope lock:
     - IP address: compare against CIDR ranges
     - Hostname: compare against domain list (wildcard matching)
     - URL: compare against URL patterns
  3. Compare against "Excluded" list
  4. Compare against "Authorized operations" for this activity type
  5. Check time window compliance
  6. Determine safety mode per decision matrix

Outcomes:
  - All checks pass → Careful mode (or Freeze if high impact)
  - Target not in authorized list → Guard mode (BLOCK)
  - Target in excluded list → Guard mode (BLOCK)
  - Operation not authorized → Guard mode (BLOCK)
  - Outside time window → Guard mode (BLOCK)
  - Any check unclear → Freeze mode (ask operator)
```

### 6.3 Manual Checklist for Complex Operations

For operations that cannot be fully automated (multi-step attacks, chained exploits):

```text
Pre-action checklist:
  [ ] Target confirmed in authorized scope (specific IP/domain, not assumed)
  [ ] Operation type authorized in ROE (specific checkbox, not inferred)
  [ ] Current time within authorized time window (checked, not assumed)
  [ ] Rate limits configured for this target type
  [ ] Evidence capture is active (terminal logging running)
  [ ] Rollback plan identified (or explicitly acknowledged as irreversible)
  [ ] No third-party systems will be affected
  [ ] No real user data will be accessed or modified
  [ ] Operator available for escalation if needed
  [ ] Exploit tested in lab first (for exploitation operations)
  [ ] Target service version confirmed (not assumed from banner alone)
```

### 6.4 Integrating Checklists into Workflow

The checklist should be a natural part of the testing rhythm, not a bureaucratic interruption:

```text
Quick check (5 seconds): For routine Careful-mode operations
  "Is target in scope? Is operation authorized? Am I within the time window?"
  If all YES → proceed

Standard check (30 seconds): For Freeze-mode operations
  Full checklist review, impact assessment, operator confirmation

Extended check (2-5 minutes): For novel or high-risk operations
  Full checklist, lab testing verification, rollback planning, operator briefing
```

---

## 7. ROE Compliance Verification

Rules of Engagement compliance is not a one-time setup — it requires continuous verification throughout the engagement.

### 7.1 Pre-Engagement Verification

Before any testing begins:

```text
  [ ] ROE document signed by authorized client representative
  [ ] Scope lock created from ROE and verified
  [ ] All authorized targets confirmed reachable
  [ ] All excluded targets documented and verified
  [ ] Time window confirmed with timezone
  [ ] Emergency contact verified (test call/message if possible)
  [ ] Abort procedure understood and documented
  [ ] Evidence capture infrastructure ready
  [ ] Safety audit baseline captured
```

### 7.2 During-Engagement Verification

At the start of each testing session:

```text
  [ ] Time window still valid (check for any scope changes communicated)
  [ ] Scope lock file unchanged (compare hash if paranoid)
  [ ] No new exclusions communicated by client
  [ ] Rate limits still appropriate (check for previous session incidents)
  [ ] Evidence capture active from session start
```

At escalation points (before moving to a new phase or technique):

```text
  [ ] New technique authorized in ROE
  [ ] Target for the new technique within scope
  [ ] Impact assessment updated for the new approach
  [ ] Operator notified of phase change (if required by ROE)
```

### 7.3 Post-Engagement Verification

After testing is complete:

```text
  [ ] All operations stopped before time window closes
  [ ] No persistent changes left on target systems
  [ ] All evidence collected and encrypted per ROE requirements
  [ ] Incident log reviewed for any unreported issues
  [ ] Safety audit run (full audit script from payloads.md)
  [ ] Command history scanned for any scope violations
  [ ] Rate limit compliance verified
  [ ] Data handling requirements met (PII redacted, evidence encrypted)
  [ ] Report delivered per ROE delivery method
```

### 7.4 Compliance Audit Script Usage

The safety self-audit commands in payloads.md provide automated compliance checking:

```text
Audit 1: Scope lock verification
  Confirms scope lock file exists with all required fields.
  Run: before engagement starts, and after any scope changes.

Audit 2: Time window compliance
  Confirms current time is within the authorized window.
  Run: at the start of every testing session.

Audit 3: Command history scan
  Reviews all executed commands for scope violations and dangerous patterns.
  Run: at the end of every testing session and before final report.

Audit 4: Rate limit compliance
  Analyzes request logs for rate limit violations.
  Run: after every sustained scanning or enumeration phase.

Audit 5: Full safety audit report
  Comprehensive report combining all checks.
  Run: at engagement completion, before delivering the final report.
```

### 7.5 Handling Scope Changes Mid-Engagement

Scope changes during an engagement are common (client adds or removes targets). Handle them safely:

```text
Step 1: Receive scope change from client
  - Must be in writing (email, signed document, or chat with confirmation)
  - Verbal changes are NOT accepted — request written confirmation

Step 2: Create new scope lock version
  - Do NOT modify the original scope lock
  - Create scope-lock-v2.md (or increment version number)
  - Document what changed, when, and who authorized it
  - Include reference to the authorization communication

Step 3: Verify the new scope lock
  - Run scope lock verification script
  - Confirm new targets are reachable
  - Confirm exclusions are updated
  - Verify no operations are running against newly excluded targets

Step 4: Switch to new scope lock
  - Stop any operations that conflict with the new scope
  - Update all active pre-action checklists to reference the new version
  - Log the scope change event in chronicle (P1 priority)

Step 5: Preserve the audit trail
  - Keep all scope lock versions in the evidence directory
  - Keep the authorization communication (email, message)
  - Log the changeover timestamp
```
