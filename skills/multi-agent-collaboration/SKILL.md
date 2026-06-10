---
name: multi-agent-collaboration
description: "Coordinating multiple specialized agents to conduct complex penetration testing engagements through task decomposition, parallel execution, result aggregation, and conflict resolution."
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
  - Agent
metadata:
  domain: infrastructure
  tool_count: 0
  guide_count: 5
---




# Skill: Multi-Agent Collaboration

> **Supplementary Files**:
> - `payloads.md` — Task decomposition templates, agent role definition prompts, coordinator dispatch templates, result aggregation JSON schema, deduplication checklist, conflict resolution decision tree, and coverage verification matrix
> - `test-cases.md` — Structured test cases for parallel recon, multi-target aggregation, deduplication conflicts, coverage auditing, and full coordinator-worker engagements
> - `guides/coordinated-pentest-playbook.md` — Deep-dive guide on agent role design, task decomposition methodology, communication protocol, result integration, quality gates, and common failure modes

## Summary

Multi Agent Collaboration skill domain covering infrastructure operations.

**Domain**: infrastructure

## Skill Identity

| Attribute | Value |
|-----------|-------|
| Domain | Multi-Agent Collaboration — Coordinated Penetration Testing |
| Skill ID | multi-agent-collaboration |
| Version | 1.0.0 |
| Hacker Laws | Law 4 (Parallel Attack Surface), Law 7 (Minimal Footprint), Law 8 (Trust but Verify), Law 10 (Orchestration over Isolation) |
| Related Skills | council, autonomous-loops, verification-loop, chronicle, article-writing, safety-guard |

## Description

Coordinating multiple specialized agents to conduct complex penetration testing engagements through task decomposition, parallel execution, result aggregation, and conflict resolution. Where a single agent works iteratively, multi-agent collaboration fans out work across specialized instances and fans the results back in — achieving coverage at a speed and depth that no single agent can match.

**Critical distinctions from related skills:**

| Skill | Core Mechanic | Input/Output Relationship |
|-------|--------------|--------------------------|
| `council` | Debate — same question, multiple analytical lenses | Same input → multiple perspectives → synthesized judgment |
| `autonomous-loops` | Iteration — single agent, repeating patterns | One agent → loop construct → sequential or batched results |
| `multi-agent-collaboration` | Decomposition — different tasks to different agents | Scope → decomposed tasks → parallel execution → aggregated findings |

Multi-agent collaboration is about **who does what**, not about how one agent thinks or iterates.

## Use Cases

1. **Large-Scope Engagements** — Enterprise networks with dozens of subnets, hundreds of hosts, and multiple service families (web, database, OT, cloud) exceed single-agent throughput; decompose by attack surface and run in parallel
2. **Multi-Target Assessments** — Client owns 5 separate web applications; assign one specialized web tester agent per application, aggregate findings into unified report
3. **Time-Constrained Red Teams** — 24-hour window to cover a 50-host network; compress wall-clock time by running recon, scanning, and initial exploitation in parallel across agent instances
4. **Comprehensive Attack Surface Coverage** — Simultaneous coverage of network perimeter (network-pentest), web entry points (web-*), credential risks (password-attack), and supply chain exposure (supply-chain-security) without sequential bottlenecks
5. **Verification at Scale** — After initial findings from multiple workers, assign a dedicated verification agent to confirm all Critical/High findings independently
6. **Specialized Tool Families** — When engagement requires deep expertise in binary analysis AND web testing AND OSINT simultaneously — assign agents by tool specialization rather than forcing one agent to context-switch

## Collaboration Models

### Model 1: Attack Phase Decomposition

Divide the engagement into phases and assign each phase to a specialized agent. Some phases can run in parallel (recon and initial web discovery); others are sequentially dependent (exploitation requires scan results).

```
Phase Assignment:
  [Recon Agent]        ← runs first or in parallel with Web Discovery
  [Scan Agent]         ← depends on Recon results
  [Web Discovery Agent]← can run in parallel with Recon
  [Exploit Agent]      ← depends on Scan + Web Discovery results
  [Post-Exploit Agent] ← depends on successful Exploit results
  [Report Agent]       ← depends on all prior results
```

**Best for:** Single complex target where deep sequential attack chains are needed but individual phases can be parallelized internally.

**Trigger conditions:** Single target, depth over breadth, phased penetration methodology required.

### Model 2: Target Parallelization

Assign each distinct target (host, application, subnet) to an independent agent instance. Each agent runs a complete assessment on its target, then results are aggregated.

```
Target Distribution:
  [Agent-T1] → 192.168.1.10
  [Agent-T2] → 192.168.1.11
  [Agent-T3] → app.example.com
  [Agent-T4] → api.example.com
  [Agent-T5] → staging.example.com
         ↓ (all parallel)
  [Coordinator] → aggregate + deduplicate → unified findings
```

**Best for:** Multiple independent targets with similar assessment scope (e.g., all web applications, all Linux hosts in a subnet).

**Trigger conditions:** N targets where N >= 3, targets are independently assessable, uniform assessment methodology.

### Model 3: Tool Specialization

Agents are defined by the tool family they master rather than by target or phase. Each specialist covers their domain across the entire scope.

```
Specialist Assignment (same scope, different tool families):
  [Network Scanner Agent] → nmap, masscan, netdiscover
  [Web Tester Agent]      → ffuf, nikto, sqlmap, burp
  [OSINT Agent]           → theHarvester, recon-ng, shodan
  [Binary Analyst Agent]  → ghidra, binwalk, strings, gdb
  [Credential Agent]      → hydra, hashcat, kerbrute
```

**Best for:** Comprehensive coverage where each domain requires deep expertise and the attack surface spans multiple tool families.

**Trigger conditions:** Broad scope, specialist depth required, tool domains are clearly separable.

### Model 4: Coordinator-Worker Pattern

One orchestrator agent holds the master scope, decomposes tasks, dispatches to N worker agents, monitors progress, handles failures, and aggregates results. Workers report back in structured format; coordinator maintains the master finding list.

```
[Coordinator Agent]
    ├── dispatches Task-A → [Worker-1]
    ├── dispatches Task-B → [Worker-2]
    ├── dispatches Task-C → [Worker-3]
    ├── monitors status + handles failures
    └── aggregates results → master finding list
```

**Best for:** Complex engagements where task dependencies shift dynamically, worker failures need rerouting, and a single authority must maintain engagement state.

**Trigger conditions:** High task complexity, dynamic dependencies, need for centralized state management.

## Decomposition Principles

### When to Use Multi-Agent Collaboration

Apply multi-agent collaboration when **two or more** of the following are true:

| Condition | Threshold |
|-----------|-----------|
| Independent attack surfaces | 3 or more clearly separable |
| Target count | 3 or more independent targets |
| Time constraint | Wall-clock budget < single-agent throughput |
| Specialist depth required | 2+ tool families need expert-level coverage |
| Verification burden | Critical findings require independent confirmation |

**Do not use** multi-agent collaboration for:
- Single-target, linear attack chains (use `autonomous-loops` Sequential Pipeline instead)
- Strategic decisions requiring debate before action (use `council` instead)
- Simple batch scans of homogeneous targets (use `autonomous-loops` Batch Processing instead)

### Task Independence Test

Before assigning tasks to parallel agents, verify independence:

1. **Data dependency check** — Does Agent B need Agent A's output to begin? If yes: sequential, not parallel.
2. **Resource conflict check** — Do Agents A and B write to the same evidence file or target the same service simultaneously? If yes: coordinate access or serialize.
3. **Scope overlap check** — Do both agents touch the same host/port/endpoint? If yes: assign explicit ownership or accept intentional duplication.
4. **State mutation check** — Does Agent A's action change target state in ways that affect Agent B's results? If yes: order them or document the dependency.

Tasks that pass all four checks are safe for true parallelization.

### Granularity Guidelines

| Granularity | Problem | Signal |
|-------------|---------|--------|
| Too coarse | Agents block each other waiting for shared resources | Agent idle time > 30% |
| Correct | Agents run independently, minimal coordination overhead | Steady progress, results accumulating |
| Too fine | Coordination overhead (dispatch, format, aggregate) exceeds task execution time | Tasks complete in <2 minutes |

**Practical rule:** Tasks smaller than 10 minutes of work are typically too fine-grained for separate agents — batch them together or use a loop pattern instead.

## Result Aggregation

### Deduplication

When multiple agents report findings on the same target:

1. **Normalize titles** — Map variant names to canonical finding titles (e.g., "SQL Injection" = "SQLi" = "SQL injection via GET parameter")
2. **Match on target + evidence** — Same CVE/technique on same host:port = duplicate candidate
3. **Merge, do not discard** — Keep the higher-confidence report as primary; append the secondary as corroboration evidence
4. **Escalate severity** — If Agent A rates Medium and Agent B rates High on the same finding, escalate to High and flag for coordinator review
5. **Document provenance** — Record which agents reported each finding for audit trail

### Conflict Resolution

When agents disagree on vulnerability status (one says vulnerable, one says not):

1. **Gather both evidence sets** — Read both agents' command output, screenshots, and methodology notes
2. **Check methodology differences** — Different tools, different payloads, different timing? Methodology gap explains most conflicts
3. **Check version/configuration** — Was target state consistent between both agents' tests? (Service restart, WAF rule change, etc.)
4. **Retest with third agent** — If conflict persists after evidence review, dispatch a dedicated verification agent with explicit instructions to test both approaches
5. **Document uncertainty** — If conflict cannot be resolved, report as "Unconfirmed — Requires Manual Verification" at the higher severity, with both evidence sets attached
6. **Escalate to human** — Conflicts on Critical findings always escalate to human operator before closing

### Coverage Verification

After all agents return results, audit for gaps using the Coverage Matrix (see `payloads.md`):

- Every scope item must map to at least one assigned agent
- Every agent result must map back to a scope item
- Any scope item with zero findings must be explicitly reviewed — absence of findings is not the same as absence of vulnerability

## Orchestration

**ECC Loop Pattern**: Batch Processing

**Rationale**: Multi-agent collaboration is inherently a batch distribution problem — the coordinator fans out tasks to specialized workers, monitors parallel execution, and fans in results for aggregation. The Batch Processing pattern from `autonomous-loops` provides exactly this dispatch/aggregate structure. The coordinator itself runs a Batch Processing loop; each worker may run any loop pattern appropriate to its assigned task.

**Integration**:
- Feeds into: `chronicle` (consolidated findings log), `article-writing` (final report aggregation), `verification-loop` (post-aggregation confirmation of critical findings)
- Consumes from: `council` (strategic model selection — which collaboration model fits this engagement), `autonomous-loops` (each worker agent runs its own appropriate loop pattern), `safety-guard` (scope enforcement applied independently to every agent)

**Cross-Skill Pipeline**:
```
council
  → [strategic decision: which collaboration model to use, scope risk assessment]
        ↓
multi-agent-collaboration
  → [decompose scope into parallel tasks, assign agents by model]
        ↓
[Worker A: network-pentest]  [Worker B: web-*]  [Worker C: osint]
  (each runs autonomous-loops pattern internally)
        ↓ (parallel execution, results returned to coordinator)
multi-agent-collaboration
  → [aggregate findings, run deduplication, resolve conflicts]
        ↓
verification-loop
  → [independent confirmation of all Critical/High findings]
        ↓
chronicle + article-writing
  → [consolidated engagement report]
```

**Quality Gate**: Before declaring a multi-agent engagement complete, verify all of the following:

1. Task coverage matrix shows 0 unassigned scope items
2. All agent results have been returned — no unresolved timeouts or failures
3. Deduplication pass complete — no duplicate finding IDs in master list
4. Conflict list reviewed — every conflict either resolved or escalated
5. Critical/High findings independently verified by verification-loop
6. Coverage matrix audited — every scope item has a confirmed result (finding or clean)
7. Scope boundaries confirmed — no agent exceeded its assigned scope

## Anti-Patterns

- **Phantom parallelism** — Declaring tasks parallel when they have hidden sequential dependencies; causes agents to block or produce inconsistent results
- **Format mismatch** — Agents return findings in incompatible formats; aggregation fails silently; standardize output contract before dispatch
- **Coordinator overload** — Assigning too many workers to one coordinator without checkpoints; coordinator loses track of state
- **Missing escalation** — Worker agents encounter out-of-scope opportunity and act without escalating to coordinator; scope creep
- **Orphaned tasks** — Task dispatched to agent that fails silently; gap in coverage goes undetected; always implement worker health checks
- **Over-decomposition** — Breaking a 20-minute task into 10 two-minute agent tasks; coordination overhead dominates; use loop patterns for small batches
- **Aggregate-then-forget** — Finding from one agent confirmed by another; original agent's evidence not linked; audit trail breaks
