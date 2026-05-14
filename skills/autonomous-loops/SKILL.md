# Autonomous Loops

> **Supplementary Files**:
> - `payloads.md` — Scope Lock templates, rate limit configurations, loop command templates, and error handling response templates
> - `test-cases.md` — Structured test cases for sequential pipeline, watch loop, batch processing, learning cycle, scope violation, and rate limit backoff
> - `guides/safe-autonomous-pentest.md` — Deep-dive guide on autonomous vs manual decision making, scope lock construction, loop composition, and monitoring

Controlled autonomous execution patterns for repetitive security tasks. Provides safe, supervised loop constructs with scope locks, rate limiting, and evidence logging.

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
