---
name: autonomous-loops
description: "Performing repetitive enumeration across many targets - Running batch vulnerability scans on multiple hosts - Monitoring for changes in target environment - Executing attack chains that require iterative steps - User says \"loop\", \"automate\", \"batch\", \"repeat."
origin: openclaw
version: "0.2.0.2"
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
  - Agent
metadata:
  domain: infrastructure
  tool_count: 0
  guide_count: 8
  last_reviewed: "2026-07-26"
---




# Autonomous Loops

> **Supplementary Files**:
> - `payloads.md` — Scope Lock templates, rate limit configurations, loop command templates, and error handling response templates
> - `test-cases.md` — Structured test cases for sequential pipeline, watch loop, batch processing, learning cycle, scope violation, and rate limit backoff
> - `guides/safe-autonomous-pentest.md` — Deep-dive guide on autonomous vs manual decision making, scope lock construction, loop composition, and monitoring

## Summary

Autonomous Loops skill domain covering infrastructure operations.

**Domain**: infrastructure

## Use Cases

1. **Sequential Pipeline** — Chain multiple security tools in order (recon → scan → exploit) with automatic phase transitions
2. **Watch Loop** — Monitor a target for changes (new ports, updated services) over extended periods
3. **Batch Processing** — Run the same test against multiple targets with rate limiting and error recovery
4. **Learning Cycle** — Execute a skill, capture results, extract patterns, and update knowledge base automatically
5. **Scope-Locked Automation** — Run autonomous loops with hard boundaries that prevent actions outside authorized scope

## Activation

- Performing repetitive enumeration across many targets
- Running batch vulnerability scans on multiple hosts
- Monitoring for changes in target environment
- Executing attack chains that require iterative steps
- User says "loop", "automate", "batch", "repeat", "iterate"

## Core Principle

**Autonomous does not mean uncontrolled.** Every loop must have:
1. A defined scope (what it can and cannot touch)
2. A termination condition (when it stops)
3. Rate limiting (how fast it runs)
4. Evidence logging (what it did)
5. Error handling (what happens when things go wrong)

## Four Loop Patterns

### Pattern 1: Sequential Pipeline

Execute a sequence of steps across multiple targets, one at a time.

```
FOR EACH target IN target_list:
    IF scope_check(target) == ALLOWED:
        result = execute_step(target)
        log_evidence(target, result)
        IF result.status == FAIL:
            handle_error(target, result)
            CONTINUE or BREAK based on severity
    ELSE:
        log_skipped(target, "Out of scope")
```

**Use when:** Enumerating ports across a subnet, testing a specific vulnerability across multiple hosts.

**Safety rules:**
- Process targets sequentially (no parallel burst)
- Log every target attempted and result
- Stop on critical error (target down, IDS triggered)
- Maximum 100 targets per pipeline run

### Pattern 2: Watch Loop

Monitor a target for changes or conditions, then act when triggered.

```
WHILE condition_not_met AND iterations < max_iterations:
    current_state = observe(target)
    log_observation(current_state)
    IF trigger_condition(current_state):
        result = execute_response(target, current_state)
        log_evidence("trigger", result)
        IF one_shot: BREAK
    WAIT(polling_interval)
```

**Use when:** Waiting for a service to come online, monitoring for new open ports, watching log files for specific events.

**Safety rules:**
- Polling interval minimum: 5 seconds
- Maximum iterations: 1000
- Log every observation cycle
- Alert when approaching iteration limit

### Pattern 3: Batch Processing

Apply the same operation to a batch of targets in parallel (with concurrency limit).

```
CONCURRENCY = 5  # Maximum simultaneous operations
results = []

FOR EACH batch IN split_into_batches(target_list, CONCURRENCY):
    batch_results = PARALLEL execute_step(batch)
    FOR EACH result IN batch_results:
        log_evidence(result.target, result)
        results.append(result)
    WAIT(rate_limit_delay)  # Pause between batches
```

**Use when:** Running nmap scans across many hosts, batch DNS lookups, mass HTTP header checks.

**Safety rules:**
- Maximum concurrency: 10
- Rate limit delay between batches: 2 seconds minimum
- Log all results including failures
- Respect target-specific rate limits if known

### Pattern 4: Learning Cycle

Iteratively refine an approach based on results from previous iterations.

```
approach = initial_approach
FOR iteration IN range(max_iterations):
    result = execute(approach)
    analysis = analyze_result(result)
    log_evidence(iteration, approach, result, analysis)
    IF analysis.success:
        log_evidence("success", approach)
        BREAK
    approach = refine(approach, analysis)
    IF approach.confidence < min_confidence:
        log_evidence("abort", "Confidence below threshold")
        BREAK
```

**Use when:** Brute-forcing with adaptive wordlists, SQL injection payload refinement, fuzzing with feedback.

**Safety rules:**
- Maximum iterations: 50
- Log every attempt and result
- Confidence threshold: abort if below 10% after 10 attempts
- Never widen scope during refinement

## Safety Framework

### Scope Lock

Before ANY loop starts, define and lock the scope:

```markdown
## Scope Lock: [Operation Name]
- **Allowed targets:** [CIDR range / hostname list / URL list]
- **Allowed operations:** [Specific commands/techniques]
- **Forbidden operations:** [What must NOT be done]
- **Time limit:** [Maximum wall-clock time]
- **Iteration limit:** [Maximum number of iterations]
- **Abort conditions:** [Specific triggers that stop the loop]
```

Once defined, the scope cannot be widened during execution.

### Rate Limiting

| Operation Type | Minimum Interval | Max Concurrency |
|---------------|-----------------|-----------------|
| Network scan (nmap) | 2s between hosts | 5 |
| Web request (HTTP) | 100ms between requests | 3 |
| DNS lookup | 50ms between queries | 10 |
| Brute force attempt | 500ms between attempts | 1 |
| Exploit attempt | 5s between attempts | 1 |

### Evidence Logging

Every loop iteration must log:

```markdown
## Loop Log Entry
- **Timestamp:** [ISO 8601]
- **Iteration:** [N / max]
- **Target:** [host/port/URL]
- **Action:** [command or technique]
- **Result:** [success/fail/error/timeout]
- **Output:** [truncated to 500 chars, full output saved to file]
- **State change:** [what changed on target, if any]
```

### Error Handling

| Error Type | Response |
|-----------|----------|
| Target unreachable | Log and skip, continue to next target |
| Rate limit detected | Increase delay by 2x, retry once |
| Authentication failure | Log and skip (do NOT retry with variations) |
| Unexpected service response | Log details, flag for manual review, continue |
| IDS/IPS detected | STOP immediately, log incident |
| Target crash/unexpected downtime | STOP immediately, log incident |
| Scope violation attempt | STOP immediately, log incident |

### Notification Rules

Notify the operator when:
- Loop starts (with scope summary)
- Every 25 iterations or 5 minutes (whichever comes first)
- Any error condition occurs
- Loop completes or aborts

## Integration with Other Skills

| Skill | Loop Pattern | Application |
|-------|-------------|-------------|
| `vulnerability-assessment` | Batch Processing | Scan multiple hosts for vulnerabilities |
| `password-attack` | Learning Cycle | Adaptive brute force with feedback |
| `web-sqli` | Learning Cycle | Iterative payload refinement |
| `network-pentest` | Sequential Pipeline | Multi-host enumeration |
| `osint` | Batch Processing | Mass DNS/WHOIS lookups |
| `terminal-ops` | All patterns | Evidence logging protocol |
| `verification-loop` | Sequential Pipeline | Verify findings across multiple hosts |
| `safety-guard` | All patterns | Pre-execution safety checks |

## Detection Methods

### Autonomous Loop Indicators
- **Sustained agent activity**: Same agent token executing >100 sequential operations; >24h continuous runtime.
- **Tool call cadence**: Constant-interval tool calls (e.g., every 30s exactly); typical of cron-driven loops.
- **State persistence**: Agent re-loading state from previous session; checkpoint file access patterns.
- **Memory growth**: Agent process accumulating >2GB RAM; typical of long-running loops without state cleanup.
- **Self-modifying prompts**: Agent modifying its own system prompt or configuration mid-run.

### SIEM Detection Rules
- **Splunk SPL**: `index=llm gateway.user="agent-*" | stats range(_time) as duration by session_id | where duration > 86400`
- **Sigma rule**: `sigma/rules/ai/long_running_agent.yml`
- **LangSmith trace analysis**: Detect agents with >1000 turns in single session.

## Defense Evasion Techniques

### Loop Stealth
- **Off-hours operation**: Run loops during low-traffic hours; blends with maintenance tasks.
- **Distributed sessions**: Cycle through multiple agent sessions to avoid per-session limits.
- **Memory cleanup between cycles**: Clear conversation history to reduce token usage anomaly.
- **Slow pacing**: Pace tool calls at irregular intervals to avoid cadence detection.
- **State externalization**: Store state in external KV store rather than session memory.

### Self-Modification Stealth
- **Gradual config changes**: Modify system prompt in small increments over multiple sessions.
- **Use environment variables**: Modify env vars rather than prompts (less audited).
- **Persistence via legitimate mechanisms**: Use MCP server registration (looks legitimate).

## Anti-Patterns

- **Infinite loops** — Every loop MUST have a termination condition
- **Scope creep** — Never add targets during execution
- **Silent failures** — Every error must be logged and reported
- **Unbounded parallelism** — Always set and respect concurrency limits
- **Skipping evidence** — Even failed attempts must be logged
- **Ignoring rate limits** — Target stability is more important than speed

## Orchestration

### ECC Loop Pattern
- **Pattern**: Meta-Skill (defines loop patterns consumed by all other skills)
- **Rationale**: Autonomous loops is not an end-user skill but a meta-skill that provides loop constructs for all other security skills — every skill that needs iterative or batch operations consumes one of the four loop patterns
- **Integration**: All security skills that need repetitive operations consume loop patterns from this skill. Each skill selects the appropriate pattern based on its workflow needs.

### Cross-Skill Pipeline
```
autonomous-loops (provides loop patterns)
    ├── Sequential Pipeline → network-pentest, terminal-ops, verification-loop
    ├── Watch Loop → security-bounty-hunter, deep-research
    ├── Batch Processing → repo-scan, osint, vulnerability-assessment
    └── Learning Cycle → search-first, continuous-learning, password-attack
```

### Quality Gate
- Pre-condition: Scope Lock defined with allowed targets, operations, and abort conditions
- Post-condition: Evidence chain complete for every iteration, all results logged
- Verification: Scope not widened during execution, iteration/iteration limits respected, rate limits maintained
