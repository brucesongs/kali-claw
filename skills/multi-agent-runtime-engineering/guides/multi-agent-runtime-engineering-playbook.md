# Multi-Agent Runtime Engineering Playbook

> End-to-end operations manual for building agent systems with structured memory, atomic-write sync, convergence detection, anti-pattern prevention, and topology selection. Companion to `SKILL.md` and `payloads.md`. Focus: how to put these patterns into production for a real engagement.

## Overview

This playbook is the **purpose-driven walk-through** of the multi-agent runtime engineering skill. Where `SKILL.md` is the reference and `payloads.md` is the template library, this guide is the **hands-on, step-by-step tutorial** that takes an engineer from "I have a target and N parallel agents" to "we have a confirmed, differentially-verified PoC and a clean audit trail." Each chapter is a lab exercise — read it, run the example, internalize the principle, then apply it to your own engagement.

The objective is operational fluency: by the end of this playbook, you should be able to bootstrap a structured memory file, dispatch three parallel agents with path-claim coordination, run convergence detection at sync points, prevent the five canonical anti-patterns, and aggregate the final state into an engagement report. Every step is illustrated with copy-paste-runnable bash, jq, and python code.

## Chapter 1 — Engagement Framing

A multi-agent runtime engineering engagement starts long before any agent runs. The framing decisions made in the first hour determine whether the engagement converges in 45 minutes (SCEN-007 happy path) or spirals for 6 hours into hallucinated prose. This chapter walks the framing checklist.

### 1.1 Is Multi-Agent the Right Choice?

Apply the topology selection rule (§22 of `payloads.md`). Multi-agent is justified when:

- **Multiple independent directions exist.** The target has multiple entry points, multiple hypothesized bug classes, or multiple analytical lenses that can be explored without blocking each other.
- **Wall-clock budget < single-agent throughput.** A single agent would take 6+ hours; three parallel agents can do it in 2.
- **Specialist depth is real.** Different directions require genuinely different tools and reasoning (patch-diff vs. fuzzer vs. sanitizer — yes; nmap-fast vs. nmap-default — no, that's one specialist pretending to be two).

If any of these is false, use `autonomous-loops` (single-agent sequential pipeline) instead. Multi-agent overhead is real: coordinator logic, lock contention, schema validation, sync points. Don't pay it if you don't have to.

### 1.2 Topology Choice

If multi-agent is justified, pick the topology:

| If your task has... | Use topology... |
|---------------------|-----------------|
| Multiple independent exploration directions on one target | **parallel-explorers** |
| Clear phase-sequential pipeline (recon → exploit → report) | **pipeline** |
| One question, multiple analytical lenses (Attack/Defense/Audit) | **council** |
| Dynamic scope, 3+ shifting specialists | **hierarchical** |

SCEN-007 (CVE-2019-7317 libpng UAF exploit dev) uses **parallel-explorers**: three agents, three directions, one shared memory. That's the canonical case this playbook walks.

### 1.3 Scope, Time, and Cost Budgets

Set hard numbers before launching:

- **Time budget**: total wall-clock for the engagement (e.g., 90 minutes for SCEN-007)
- **Iteration budget**: max iterations per agent (e.g., 30 — then agent must yield)
- **Path-switch threshold**: failed attempts before pivoting (default 3)
- **Cost budget**: total USD for LLM calls (if LLM-driven)
- **Sync cadence**: every N iterations OR every M minutes (default: every 5 iterations / 5 minutes)

These values go into `convergence_state.path_switch_threshold`, `next_constraints.time_budget_remaining_hours`, and the coordinator's sync loop configuration.

### 1.4 Memory Bootstrap

Bootstrap the structured memory file before any agent runs. The coordinator (not the agents) creates the empty memory with all required fields. This is the **Phase 0** of SCEN-007.

```bash
mkdir -p /runs/SCEN-XXX/mem
cat > /runs/SCEN-XXX/mem/exploit-attempt-memory.json <<'JSON'
{
  "schema_version": "1.0",
  "target": { /* populated with engagement target info */ },
  "memory_lock": {"version": 0, "owner_agents": [], ...},
  "vulnerability_hypotheses": [],
  "candidate_pocs": [],
  "failed_attempts": [],
  "active_paths": {},
  "convergence_state": {
    "iterations": 0, "confirmed_poc": null,
    "stop_condition_met": false, "stop_reason": null,
    "sync_points_executed": 0
  },
  "decision_log": []
}
JSON
```

**Critical**: the memory file must exist *before* agents launch. Agents that try to write to a non-existent memory will fail; the atomic-write pattern requires a source file to read.

## Chapter 2 — Agent Design

Each agent is a stateless loop that reads memory, takes one action, writes a delta, repeats. The agent itself does not hold long-term state — the memory file is the state.

### 2.1 Agent Skeleton (Python)

```python
#!/usr/bin/env python3
# agent.py — generic agent skeleton
import sys, json, subprocess, os
from pathlib import Path

AGENT_ID = sys.argv[1]
MEM = sys.argv[2]
CLAIM_PATH = sys.argv[3]

def atomic_write_delta(mem_path, agent, jq_expr):
    """Apply a jq delta to memory under flock."""
    script = f'''
    (
      flock -x -w 30 9 || exit 1
      BEFORE=$(jq '.memory_lock.version' "{mem_path}")
      tmp=$(mktemp -p "$(dirname '{mem_path}')")
      jq --arg agent "{agent}" --argjson prever "$BEFORE" '{jq_expr}' "{mem_path}" > "$tmp"
      AFTER=$(jq '.memory_lock.version' "$tmp")
      [ "$AFTER" -eq "$((BEFORE + 1))" ] || {{ echo "[conflict]"; rm "$tmp"; exit 2; }}
      mv "$tmp" "{mem_path}"
    ) 9>"{mem_path}.lock"
    '''
    subprocess.run(["bash", "-c", script], check=True)

def read_memory(mem_path):
    """Read current memory (under shared lock)."""
    result = subprocess.run(
        ["jq", ".", mem_path], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)

def should_continue(mem):
    """Stop condition check."""
    return not mem["convergence_state"]["stop_condition_met"]

# Phase 1: claim path
atomic_write_delta(MEM, AGENT_ID, f'''
  .active_paths["{AGENT_ID}"] = "{CLAIM_PATH}"
  | .memory_lock.version = ($prever + 1)
  | .memory_lock.last_write_at = (now | todateiso8601)
  | .memory_lock.last_write_by = $agent
  | .memory_lock.last_read_at = (now | todateiso8601)
  | .decision_log += [{{"at": (now | todateiso8601), "by": $agent,
                       "decision": "claimed path {CLAIM_PATH}"}}]
''')

# Phase 2: main loop
iteration = 0
while should_continue(read_memory(MEM)) and iteration < 30:
    iteration += 1

    # 1. Read memory
    mem = read_memory(MEM)

    # 2. Pick a hypothesis (or extend existing one, or try a candidate input)
    action = decide_action(mem, AGENT_ID, CLAIM_PATH)

    # 3. Execute action
    evidence = execute_action(action)

    # 4. Write delta (new evidence, hypothesis update, or failed_attempt)
    delta = compute_delta(action, evidence)
    atomic_write_delta(MEM, AGENT_ID, delta)

# Phase 3: release path
atomic_write_delta(MEM, AGENT_ID, f'''
  del(.active_paths["{AGENT_ID}"])
  | .memory_lock.version = ($prever + 1)
  | .decision_log += [{{"at": (now | todateiso8601), "by": $agent,
                       "decision": "released path"}}]
''')
```

### 2.2 The Three Canonical Agents (SCEN-007 style)

The three agents in SCEN-007 each take a different direction. Their structure is identical; their action selection differs.

**Agent A — Patch-diff**:
- Read patch file, identify changed lines
- For each changed function, hypothesize the bug
- Use BinDiff / angr to confirm reachability
- Write hypothesis + evidence to memory

**Agent B — Harness-entry**:
- Build AFL++ harness
- Seed corpus, run fuzzer
- For each crash, symbolize the stack trace
- Write hypothesis + crash evidence

**Agent C — Sanitizer**:
- Build target with ASan+UBSan
- Run against malformed-input corpus
- Parse ASan traces, localize to source line
- Write hypothesis + ASan evidence

All three agents read/write the same memory; convergence emerges when they independently land on the same `path` field.

### 2.3 Avoiding Anti-Patterns in Agent Code

Each agent must:

1. **Read before write** — `last_read_at` must be set within the last 60 seconds before any write. The skeleton above does this naturally by calling `read_memory` at the top of each iteration.
2. **Write deltas, not prose** — every memory update touches a structured field (`findings`, `vulnerability_hypotheses`, `failed_attempts`), never just `decision_log`.
3. **Yield on stuck** — after 3 failed attempts on a hypothesis with no new evidence, the agent releases its path and either picks a new one or exits.
4. **Respect stop condition** — the loop checks `stop_condition_met` every iteration and halts cleanly.

## Chapter 3 — Coordinator Design

The coordinator bootstraps memory, dispatches agents, runs sync sweeps, and aggregates final state. It is *not* an agent — it has no LLM-driven reasoning. It's pure plumbing.

### 3.1 Coordinator Skeleton (Bash)

```bash
#!/usr/bin/env bash
# coordinator.sh
set -euo pipefail

RUN_DIR=/runs/SCEN-XXX
MEM="$RUN_DIR/mem/exploit-attempt-memory.json"

# Phase 0: bootstrap
bash lib/bootstrap_memory.sh "$MEM"

# Phase 1: dispatch
python3 agents/agent.py A "$MEM" patch-diff > "$RUN_DIR/A.log" 2>&1 &
PID_A=$!
python3 agents/agent.py B "$MEM" harness-entry > "$RUN_DIR/B.log" 2>&1 &
PID_B=$!
python3 agents/agent.py C "$MEM" sanitizer > "$RUN_DIR/C.log" 2>&1 &
PID_C=$!

# Phase 2: sync loop
SYNC_INTERVAL=60  # seconds
while true; do
  if jq -e '.convergence_state.stop_condition_met' "$MEM" >/dev/null; then
    echo "[coordinator] stop met, halting"
    kill -TERM "$PID_A" "$PID_B" "$PID_C" 2>/dev/null || true
    break
  fi

  # Run convergence detector
  python3 lib/convergence_detector.py "$MEM" || true
  # Run anti-pattern checker (advisory — log only, don't halt)
  python3 lib/anti_pattern_check.py "$MEM" >> "$RUN_DIR/anti-pattern.log" 2>&1 || true

  sleep "$SYNC_INTERVAL"
done

wait "$PID_A" "$PID_B" "$PID_C" 2>/dev/null || true

# Phase 3: aggregate
echo "[coordinator] final state:"
jq '{
  hypotheses_count: (.vulnerability_hypotheses | length),
  confirmed_count: ([.vulnerability_hypotheses[] | select(.status == "CONFIRMED")] | length),
  pocs_count: (.candidate_pocs | length),
  confirmed_pocs: [.candidate_pocs[] | select(.status == "CONFIRMED") | .id],
  iterations: .convergence_state.iterations,
  stop_reason: .convergence_state.stop_reason
}' "$MEM"
```

### 3.2 Sync-Point Cadence

The coordinator's sync interval (60s above) trades off responsiveness vs. overhead. Tune per engagement:

- **Fast sync (10-15s)** — tight feedback, fast convergence detection, but more lock contention and Python overhead
- **Default (60s)** — balanced for typical 30-90 minute engagements
- **Slow sync (5 min)** — for multi-hour engagements; risk: convergence detected late

Hybrid cadence (every N iterations OR every M minutes, whichever first) is more adaptive but requires the coordinator to track agent iteration counts.

### 3.3 Failure Modes

The coordinator handles three failure modes:

1. **Agent crash**: the `wait` returns non-zero; coordinator logs and continues. Other agents are unaffected.
2. **Lock contention**: an agent's atomic-write times out (30s). The agent retries internally; coordinator doesn't need to act.
3. **No convergence after iteration budget**: coordinator sets `stop_condition_met` with `stop_reason: "iteration budget exhausted without convergence"`. Better to halt and report than loop forever.

## Chapter 4 — Convergence Detection

The convergence detector is the highest-leverage component. It is what makes 1+1 > 2 — multiple agents independently arriving at the same answer is the strongest signal of truth.

### 4.1 When to Run the Detector

Run at every sync point. For SCEN-007 with a 60s sync interval over a 45-minute engagement, that's ~45 detector runs. Each run is cheap (jq query over a small JSON file).

### 4.2 Convergence Rule

The rule is mechanical: if 2+ hypotheses point at the same `.path` field AND have different `claimed_by` agents, they converge. Promote both to CONFIRMED, bump confidence by +0.30 (capped at 1.0), emit a convergence event to `decision_log`.

### 4.3 Why Convergence Beats Single-Agent Confidence

A single agent can be confidently wrong — it has one perspective, one tool chain, one set of assumptions. Two independent agents arriving at the same answer have different perspectives, different tool chains, different assumptions. The probability that both are wrong in the same way is much lower.

This is the triangulation principle from surveying and navigation: three landmarks give a far more accurate position than one. The confidence bump (+0.30) is the mathematical expression of this — independent corroboration is strong evidence.

### 4.4 Convergence Failure Modes

Convergence can fail in two directions:

- **False convergence** — two agents land on the same `path` by coincidence (e.g., both pointing at the entry function `main` because everything starts there). Mitigation: require the `path` to be specific (e.g., `parser.c:412`, not `parser.c`). Reject convergence on too-generic paths.
- **Missed convergence** — two agents land on equivalent-but-not-identical paths (e.g., `pngpread.c:412` vs. `pngpread.c:412 // png_read_row`). Mitigation: normalize paths (strip comments, normalize separators) before comparison.

## Chapter 5 — Anti-Pattern Discipline

The five anti-patterns (§17-§21 of `payloads.md`) are the most common ways agent systems go wrong. The discipline: detect them automatically, on every memory write.

### 5.1 Embedding Checks in the Atomic-Write Pattern

The canonical `write_memory` function (§1 of `SKILL.md`) embeds three checks:
- **Version-vector guard** (catches most concurrency bugs)
- **Path-claim deadlock check** (AP-4)
- **Premature-stop check** (AP-5)

The other three anti-patterns (AP-1 free-form, AP-2 drift, AP-3 repeat) require deeper semantic analysis and are better run as a periodic checker (every sync point).

### 5.2 Anti-Pattern Response

When the checker detects an anti-pattern, what should it do?

- **Log it** — always. Add to `decision_log` with reason.
- **Block the write** — for anti-patterns that corrupt state (AP-4 deadlock, AP-5 premature stop). The write is rejected.
- **Flag for coordinator** — for anti-patterns that signal an agent is stuck (AP-3 repeat). The coordinator may reassign the path.
- **Auto-remediate** — for anti-patterns with a clear fix (AP-3 path switch, AP-2 finding add). The checker applies the fix.

## Chapter 6 — Topology Selection in Practice

Topology choice is rarely pure. Real engagements mix topologies.

### 6.1 SCEN-007 — Pure Parallel-Explorers

Three agents, three independent directions, one target, one shared memory. The canonical parallel-explorers case.

### 6.2 Pentest Engagement — Pipeline with Parallel Bursts

A 5-phase pentest (recon → intrusion → privesc → lateral → exfil) is structurally a pipeline. But within each phase, parallel exploration may happen (e.g., recon phase has parallel sub-agents for port scan, web discovery, OSINT). The hybrid pattern:

```
recon (parallel: nmap, ffuf, subfinder)
  ↓
intrusion (parallel: sqlmap, burp-active, custom-exploit-attempts)
  ↓
privesc (single-agent — judgment heavy)
  ↓
lateral (parallel: bloodhound, crackmapexec, evil-winrm)
  ↓
exfil / report (single-agent)
```

### 6.3 Disclosure Decision — Council

Deciding whether to publish a 0-day disclosure is a council task. Three perspectives (Attack: how fast will adversaries weaponize? Defense: how fast will defenders patch? Audit: what are the disclosure rules?) deliberate. The output is a single decision.

### 6.4 Multi-Cloud Incident Response — Hierarchical

A multi-cloud incident (AWS + Azure + GCP) needs hierarchical coordination. Coordinator dispatches per-cloud specialists; each runs independently with their own sub-memory; coordinator aggregates.

## Chapter 7 — Common Failure Modes

The most common ways runtime engineering engagements fail, and what to do about them.

### 7.1 "Agents converged on a wrong answer"

Two agents landed on the same `path` and got promoted to CONFIRMED — but the path is wrong (both agents made the same reasoning error).

**Mitigation**: convergence is *evidence*, not proof. The differential verification step (the actual stop condition) is independent of convergence. If converged-on answer fails differential verification, the convergence was a coincidence — re-hunt.

### 7.2 "Agents never converged"

Three agents explored for an hour; no two of them landed on the same path. Memory has 9 hypotheses, all `LIKELY`, none `CONFIRMED`.

**Mitigation**: this is honest output — the bug may not be where any agent looked. Don't force convergence (don't lower the threshold). Instead, expand candidate paths or accept that the engagement is inconclusive.

### 7.3 "Path-claim deadlock loop"

Agents keep failing the deadlock check; none can make progress.

**Mitigation**: coordinator should detect this (3+ deadlock rejections for the same agent) and force path reassignment. Or expand `candidate_paths` so there are more options.

### 7.4 "Memory file grows huge"

After 200 iterations, the JSON is 50MB; jq takes seconds to parse.

**Mitigation**: compact the memory periodically (§34 of `payloads.md`). Move INVALIDATED hypotheses older than the cutoff to an archive; cap failed_attempts per hypothesis.

### 7.5 "Coordinator crashes; agents orphaned"

Coordinator process dies; agents keep running but no one is checking stop conditions.

**Mitigation**: agents should also check stop conditions themselves (the `should_continue` function in the agent skeleton). Use systemd or supervisor to restart the coordinator.

## Chapter 8 — Quality Gates

Before declaring a multi-agent runtime engineering engagement complete:

1. **Memory file is valid JSON** — `jq '.' mem.json > /dev/null` exits 0
2. **All required fields present** — schema validation passes
3. **No anti-pattern violations in the last sync** — anti-pattern checker reports clean
4. **Decision log is append-only** — no entries removed or modified
5. **Evidence hashes all match** — sha256 verification passes for all evidence_index entries
6. **Stop condition has a reason** — `stop_reason` is one of the recognized values
7. **If differential verification claimed, results are populated** — AP-5 check passes
8. **All agent processes halted cleanly** — no orphan processes
9. **Final state aggregated** — coordinator printed summary
10. **Engagement memory archived** — copied to `bak/engagement-<id>-<timestamp>.json`

## Chapter 9 — Cross-Skill Composition

This skill composes with several adjacent skills:

| Adjacent skill | Composition |
|----------------|-------------|
| `multi-agent-collaboration` | Provides task decomposition; this skill provides the runtime substrate |
| `council` | Council emits judgments; this skill persists them to shared memory |
| `verification-loop` | Verification reads from structured memory; writes results to evidence_for/against |
| `engagement-manager` | Engagement manager decides phases; this skill provides per-phase memory schema |
| `autonomous-loops` | Provides loop constructs; this skill provides state layer |
| `chronicle` | Distills engagements to long-term memory; this skill provides the JSON-to-prose distillation |

## Chapter 10 — References

- `validation/scenarios/SCEN-007.md` — the canonical reference scenario for this skill
- `validation/scenarios/SCEN-MEMORY-SCHEMA.md` — the schema library
- `docs/mopmonk-research-and-kali-claw-plan.md` — the MopMonk three招 research
- `skills/multi-agent-collaboration/SKILL.md` — task decomposition
- `skills/council/SKILL.md` — multi-perspective analysis
- `skills/agentic-pentest/SKILL.md` — LLM-driven pentest framework deployment
- Anthropic Multi-Agent Research System blog (2024-2026)
- LangGraph checkpointing documentation
- AutoGen GroupChat paper (Microsoft, 2023)
- Magentic-One paper (Microsoft, 2024)
- MopMonk Agent GitHub: https://github.com/MopMonkAI/MopMonkAgent
- Berkeley CyberGym paper: arXiv:2506.02548, OpenReview `2YvbLQEdYt`

## Appendix A — Hands-On Exercises

These exercises are **step-by-step tutorials** for the operator who wants hands-on practice with each layer of the runtime stack. Each exercise is self-contained and takes 15-45 minutes.

### Exercise 1 — Bootstrap an Empty Memory and Write Your First Delta

**Objective**: prove the atomic-write pattern works end-to-end.

```bash
# 1. Create the memory file
MEM=/tmp/runtime-lab.json
mkdir -p "$(dirname "$MEM")"
cat > "$MEM" <<'JSON'
{
  "schema_version": "1.0",
  "memory_lock": {"version": 0, "owner_agents": [], "last_read_at": null, "last_write_at": null, "last_write_by": null},
  "vulnerability_hypotheses": [],
  "candidate_pocs": [],
  "failed_attempts": [],
  "active_paths": {},
  "convergence_state": {"iterations": 0, "stop_condition_met": false, "stop_reason": null, "sync_points_executed": 0},
  "decision_log": []
}
JSON

# 2. Write a delta using the atomic-write helper
write_memory() {
  local mem="$1" agent="$2" jq_expr="$3"
  (
    flock -x -w 30 9 || exit 1
    local pre; pre=$(jq '.memory_lock.version' "$mem")
    local tmp; tmp=$(mktemp -p "$(dirname "$mem")")
    jq --arg agent "$agent" --argjson pre "$pre" "$jq_expr" "$mem" > "$tmp"
    local post; post=$(jq '.memory_lock.version' "$tmp")
    [ "$post" -eq "$((pre + 1))" ] || { rm "$tmp"; exit 2; }
    mv "$tmp" "$mem"
  ) 9>"$mem.lock"
}

write_memory "$MEM" "operator" '
  .memory_lock.version = ($prever + 1)
  | .memory_lock.last_write_at = (now | todateiso8601)
  | .memory_lock.last_write_by = $agent
  | .memory_lock.last_read_at = (now | todateiso8601)
  | .decision_log += [{"at": (now | todateiso8601), "by": $agent, "decision": "first write"}]
'

# 3. Verify
jq '.memory_lock.version, .decision_log' "$MEM"
```

**Expected outcome**: version is 1; decision_log has the "first write" entry.

### Exercise 2 — Simulate Three Agents Claiming Paths

**Objective**: prove the path-claim coordination works under concurrent contention.

```bash
# Launch 3 parallel path claims
for AGENT in A B C; do
  PATH_NAME=$(case $AGENT in A) echo patch-diff;; B) echo harness-entry;; C) echo sanitizer;; esac)
  (
    flock -x -w 30 9 || exit 1
    tmp=$(mktemp)
    jq --arg agent "$AGENT" --arg path "$PATH_NAME" '
      .active_paths[$agent] = $path
      | .memory_lock.version += 1
      | .memory_lock.owner_agents = (.active_paths | keys)
    ' "$MEM" > "$tmp"
    # AP-4 deadlock check
    jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$tmp" >/dev/null \
      || { rm "$tmp"; exit 4; }
    mv "$tmp" "$MEM"
  ) 9>"$MEM.lock" &
done
wait

# Verify
jq '.active_paths, .memory_lock' "$MEM"
```

**Expected outcome**: all three paths claimed uniquely; version is 4 (1 bootstrap + 3 claims).

### Exercise 3 — Trigger a Convergence Event

**Objective**: write two hypotheses pointing at the same path and watch the detector fire.

```bash
# Two agents independently write hypotheses pointing at parser.c:412
for AGENT in A B; do
  write_memory "$MEM" "$AGENT" "
    .vulnerability_hypotheses += [{
      \"id\": \"H-$AGENT-001\",
      \"hypothesis\": \"overflow at parser.c:412 ($AGENT perspective)\",
      \"path\": \"parser.c:412\",
      \"evidence_for\": [\"evidence from $AGENT\"],
      \"evidence_against\": [],
      \"status\": \"LIKELY\",
      \"confidence\": 0.55,
      \"claimed_by\": [\"$AGENT\"],
      \"created_at\": (now | todateiso8601)
    }]
    | .memory_lock.version = (\$prever + 1)
  "
done

# Run convergence detector
python3 convergence_detector.py "$MEM"

# Verify both promoted to CONFIRMED
jq '.vulnerability_hypotheses[] | {id, status, confidence}' "$MEM"
```

**Expected outcome**: both H-A-001 and H-B-001 promoted to CONFIRMED; confidence bumped.

### Exercise 4 — Trigger AP-4 Path Deadlock

**Objective**: deliberately cause a path-claim deadlock and watch it be rejected.

```bash
# Try to have two agents claim the same path
for AGENT in X Y; do
  (
    flock -x -w 30 9 || exit 1
    tmp=$(mktemp)
    jq --arg agent "$AGENT" '.active_paths[$agent] = "patch-diff"' "$MEM" > "$tmp"
    jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$tmp" >/dev/null \
      || { echo "[$AGENT rejected]"; rm "$tmp"; exit 4; }
    mv "$tmp" "$MEM"
  ) 9>"$MEM.lock"
done
```

**Expected outcome**: second agent's write rejected with `[Y rejected]` message.

### Exercise 5 — Run Differential Verification

**Objective**: confirm the stop condition logic fires correctly.

```bash
# Pretend we have a PoC and a target
echo "fake-poc" > /tmp/poc.bin

# Mock verification results
write_memory "$MEM" "verifier" '
  .verification_results = {
    "vulnerable": {"crashed": true, "sanitizer_output": "ERROR: AddressSanitizer"},
    "patched": {"crashed": false, "sanitizer_output": "clean"}
  }
  | .convergence_state.stop_condition_met = true
  | .convergence_state.stop_reason = "differential verification passed"
  | .memory_lock.version = ($prever + 1)
'

# Verify stop fired without AP-5
python3 anti_pattern_check.py "$MEM"
jq '.convergence_state' "$MEM"
```

**Expected outcome**: stop_condition_met=true; anti-pattern checker passes.

### Exercise 6 — Trigger AP-5 Premature Stop

**Objective**: confirm the premature-stop guard catches a missing verification step.

```bash
# Attempt to set stop without verification_results
cp "$MEM" "$MEM.before"
tmp=$(mktemp)
jq '.convergence_state.stop_condition_met = true | .memory_lock.version += 1' "$MEM" > "$tmp"
# AP-5 check
jq -e '
  .convergence_state.stop_condition_met
  | if . then (.verification_results.vulnerable != null and .verification_results.patched != null) else true end
' "$tmp" >/dev/null \
  && { echo "[should have failed]"; mv "$tmp" "$MEM"; } \
  || echo "[correctly rejected] AP-5"
rm -f "$tmp"
mv "$MEM.before" "$MEM"
```

**Expected outcome**: `[correctly rejected] AP-5`.

### Exercise 7 — Render the Decision-Log Timeline

**Objective**: visualize the audit trail.

```bash
jq -r '.decision_log[] | "\(.at)  [\(.by)]  \(.decision)"' "$MEM"
```

### Exercise 8 — Compact a Long Memory

**Objective**: prune a memory that has accumulated cruft.

```bash
# Add 50 failed attempts to bloat the memory
for i in $(seq 1 50); do
  write_memory "$MEM" "lab" '
    .failed_attempts += [{"attempt_id": "ATT-'$i'", "hypothesis": "H-stale", "yielded_new_evidence": false}]
    | .memory_lock.version = ($prever + 1)
  '
done

# Now compact
python3 - <<'PY' "$MEM" > "$MEM.compact"
import json, sys
m = json.load(open(sys.argv[1]))
m["failed_attempts"] = m["failed_attempts"][-10:]  # keep last 10
print(json.dumps(m, indent=2))
PY
mv "$MEM.compact" "$MEM"
jq '.failed_attempts | length' "$MEM"
```

**Expected outcome**: failed_attempts reduced to 10.

### Exercise 9 — Schema Migration

**Objective**: migrate a memory from schema 1.0 to 1.1.

```bash
# Set schema_version to 1.0 (it already is)
# Run migration
python3 - <<'PY' "$MEM"
import json, sys
m = json.load(open(sys.argv[1]))
assert m["schema_version"] == "1.0"
# 1.0 -> 1.1: add schema_history field if absent
m.setdefault("schema_history", []).append({
    "from": "1.0", "to": "1.1", "migrated_at": "2026-07-03T00:00:00Z",
    "migration_script": "exercise-9"
})
m["schema_version"] = "1.1"
json.dump(m, open(sys.argv[1], "w"), indent=2)
print("[migrated to 1.1]")
PY

jq '.schema_version, .schema_history' "$MEM"
```

### Exercise 10 — Topology Selection Practice

**Objective**: practice picking the right topology for different task shapes.

```python
# Paste into python3 REPL
tasks = [
    {"name": "libpng UAF PoC", "bug_class_exploration": True, "multiple_independent_directions": True},
    {"name": "5-phase pentest", "phase_sequential": True, "clear_handoffs": True},
    {"name": "0-day disclosure", "judgment_heavy": True, "multiple_lenses": True},
    {"name": "multi-cloud IR", "scope_dynamic": True, "specialist_count": 4},
    {"name": "single-host vuln scan", },
]
def select_topology(t):
    if t.get("bug_class_exploration") and t.get("multiple_independent_directions"):
        return "parallel-explorers"
    if t.get("phase_sequential") and t.get("clear_handoffs"):
        return "pipeline"
    if t.get("judgment_heavy") and t.get("multiple_lenses"):
        return "council"
    if t.get("scope_dynamic") and t.get("specialist_count", 0) >= 3:
        return "hierarchical"
    return "single-agent"
for t in tasks:
    print(f"  {t['name']:30s} -> {select_topology(t)}")
```

**Expected outcome**: each task maps to the correct topology.

---

## Appendix B — Common Pitfalls & Quick Fixes

| Symptom | Likely Cause | Quick Fix |
|---------|--------------|-----------|
| `[conflict]` errors in agent logs | Two agents read same version, one wrote first | Add retry loop: re-read, re-evaluate, retry write |
| `[deadlock]` errors | Two agents trying to claim same path | Add fallback path in agent code |
| Memory file grows huge (>10MB) | No compaction | Run compactor (§34 of payloads.md) post-engagement |
| Coordinator hangs | Lock not released (agent crashed mid-lock) | Add `flock -w 30` timeout; force-kill stuck agents |
| Anti-pattern checker noise | Agent not setting last_read_at | Add `last_read_at` update in agent's main loop |
| Convergence never fires | All agents write to same path from same `claimed_by` | Ensure each agent uses distinct `claimed_by` ID |
| Premature-stop fires | Stop flag set before verification results | Always populate `verification_results` first, then set flag |
