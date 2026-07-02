# Multi-Agent Runtime Engineering — Test Cases

> Structured test case templates for validating runtime engineering coverage: schema validation, atomic-write race safety, convergence detection, anti-pattern triggers, topology selection, and end-to-end multi-agent coordination. Each case includes severity, prerequisites, test steps, expected results, remediation, pass criteria, and reference payload.

## Conventions

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Prerequisites**: Required pre-conditions (files, agents, tools)
- **Test Steps**: Numbered, executable commands
- **Expected Results**: Observable outcome
- **Remediation**: What to do if the test fails (or what a defender does to harden)
- **Pass Criteria**: Objective conditions indicating the test passes
- **Reference**: Pointer to the specific section in `payloads.md`

---

## A. Schema Validation

### TC-MA-001 — Schema 1 Engagement Memory Validates Against Required Fields

**Severity**: HIGH
**Prerequisites**: jq, python3, `engagement-memory.json` populated

**Test Steps**:
1. Create a `engagement-memory.json` per §2 template
2. Run the schema validator:

```bash
python3 - <<'PY' engagement-memory.json
import json, sys
mem = json.load(open(sys.argv[1]))
required = ["schema_version", "engagement_id", "scope", "current_phase",
            "findings", "evidence_index", "next_constraints",
            "convergence_state", "memory_lock", "decision_log"]
missing = [f for f in required if f not in mem]
assert not missing, f"missing required fields: {missing}"
print("[OK] all required fields present")
PY
```

3. Remove the `findings` field; re-run validator; expect failure
4. Add `findings` back; remove `convergence_state`; expect failure

**Expected Results**:
- Step 2: validator exits 0, prints `[OK]`
- Step 3: validator exits non-zero, prints `missing required fields: ['findings']`
- Step 4: validator exits non-zero, prints `missing required fields: ['convergence_state']`

**Remediation**:
- The atomic-write pattern (§8) should run the validator before `mv`
- Reject any write that leaves a missing required field

**Pass Criteria**: Validator correctly identifies all missing required fields; populated schema passes cleanly.

**Reference**: payloads.md §2

---

### TC-MA-002 — Schema 2 Exploit Attempt Memory Validates

**Severity**: HIGH
**Prerequisites**: jq, `exploit-attempt-memory.json` populated

**Test Steps**:
1. Create `exploit-attempt-memory.json` per §3 template
2. Validate required fields (`target`, `memory_lock`, `vulnerability_hypotheses`, `candidate_pocs`, `failed_attempts`, `active_paths`, `convergence_state`, `decision_log`)
3. Validate confidence-level taxonomy:

```bash
jq -e '.vulnerability_hypotheses[] | .confidence | type == "number"' mem.json
jq -e '.vulnerability_hypotheses[] | .status as $s | $s | IN("CONFIRMED", "LIKELY", "POSSIBLE", "UNVERIFIED", "INVALIDATED")' mem.json
```

4. Add a hypothesis with `status: "probably-true"`; expect failure

**Expected Results**:
- Steps 2-3: all checks pass
- Step 4: schema check rejects invalid status

**Remediation**:
- Reject any write with an unrecognized `status` value
- Reject any write with non-numeric `confidence`

**Pass Criteria**: Taxonomy enforced; invalid values rejected.

**Reference**: payloads.md §3, §5

---

### TC-MA-003 — Schema 3 Patch-Diff Reproduction Memory Validates

**Severity**: MEDIUM
**Prerequisites**: `repro-attempt-memory.json` populated

**Test Steps**:
1. Create `repro-attempt-memory.json` per §4 template
2. Validate required fields (`task`, `patch_analysis`, `code_path`, `candidate_inputs`, `verification_results`, `convergence_state`)
3. Validate that if `convergence_state.status == "POC_CONFIRMED_DIFFERENTIALLY"`, then both `verification_results.vulnerable.crashed == true` and `verification_results.patched.crashed == false` must hold

```bash
jq -e '
  if .convergence_state.status == "POC_CONFIRMED_DIFFERENTIALLY" then
    (.verification_results.vulnerable.crashed == true and
     .verification_results.patched.crashed == false)
  else true end
' repro-attempt-memory.json
```

**Expected Results**:
- Steps 2-3: validation passes on a well-formed file
- Setting `POC_CONFIRMED_DIFFERENTIALLY` without differential results causes Step 3 to fail

**Remediation**:
- Differential verification must run and populate `verification_results` before status flag is set

**Pass Criteria**: Cross-field constraints enforced.

**Reference**: payloads.md §4

---

## B. Atomic-Write Race Safety

### TC-MA-004 — Atomic Write Under 3-Way Concurrent Update — No Clobber

**Severity**: CRITICAL
**Prerequisites**: 3 agent shells, shared `mem.json`, `flock`, `jq`

**Test Steps**:
1. Bootstrap an empty memory file:

```bash
MEM=/tmp/mem.json
echo '{"memory_lock":{"version":0},"vulnerability_hypotheses":[]}' > "$MEM"
```

2. In three parallel shells, simultaneously run the atomic-write pattern adding a hypothesis:

```bash
for AGENT_ID in A B C; do
  (
    flock -x -w 30 9 || exit 1
    BEFORE=$(jq '.memory_lock.version' "$MEM")
    tmp=$(mktemp -p "$(dirname "$MEM")")
    jq --arg agent "$AGENT_ID" --argjson prever "$BEFORE" \
      '.vulnerability_hypotheses += [{"id": "H-\($agent)", "claimed_by": [$agent]}]
       | .memory_lock.version = ($prever + 1)' \
      "$MEM" > "$tmp"
    AFTER=$(jq '.memory_lock.version' "$tmp")
    [ "$AFTER" -eq "$((BEFORE + 1))" ] || { rm "$tmp"; exit 2; }
    mv "$tmp" "$MEM"
  ) 9>"$MEM.lock"
done &
wait
```

3. After all three complete, inspect the final state:

```bash
jq '.memory_lock.version, [.vulnerability_hypotheses[].id]' "$MEM"
```

**Expected Results**:
- `memory_lock.version` is exactly 3 (one increment per agent)
- All three hypothesis IDs (`H-A`, `H-B`, `H-C`) present in `vulnerability_hypotheses`
- No agent's write is lost

**Remediation**:
- If any writes are lost, the flock logic is broken — verify the subshell `9>...lock` pattern
- If versions are skipped, the version-vector guard may be bypassed — re-add the `[ "$AFTER" -eq "$((BEFORE + 1))" ]` check

**Pass Criteria**: All 3 hypotheses present; version is 3.

**Reference**: payloads.md §7, §8, §9, §10

---

### TC-MA-005 — Path Claim Race — Two Agents, Only One Wins, Other Retries

**Severity**: HIGH
**Prerequisites**: 2 agent shells, shared `mem.json`

**Test Steps**:
1. Bootstrap memory with empty `active_paths: {}`
2. Both agents claim the same path `patch-diff` simultaneously:

```bash
for AGENT_ID in A B; do
  (
    flock -x -w 30 9 || exit 1
    tmp=$(mktemp -p "$(dirname "$MEM")")
    jq --arg agent "$AGENT_ID" --arg path "patch-diff" \
      '.active_paths[$agent] = $path' "$MEM" > "$tmp"
    # deadlock check
    jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$tmp" >/dev/null \
      || { echo "[deadlock] $AGENT_ID"; rm "$tmp"; exit 4; }
    mv "$tmp" "$MEM"
  ) 9>"$MEM.lock"
done
```

3. Inspect: only one agent should have `patch-diff`; the other should have errored

**Expected Results**:
- First agent's claim succeeds
- Second agent's claim triggers AP-4 deadlock detection; write rejected
- `active_paths` has at most one `patch-diff` value

**Remediation**:
- The second agent should fall back to a different path (e.g., `sanitizer`) or wait
- Coordinator should detect the deadlock and reassign

**Pass Criteria**: No duplicate paths; deadlock detection fires.

**Reference**: payloads.md §11, §20

---

### TC-MA-006 — Version Vector Conflict Triggers Retry

**Severity**: HIGH
**Prerequisites**: 2 agent shells

**Test Steps**:
1. Bootstrap memory at version 0
2. Agent A reads version (0), then writes (incrementing to 1) — succeeds
3. Agent B (read earlier at version 0) tries to write its delta expecting to go to version 1; the actual version is now 1, so the write to "version 1" must be detected as conflict

```bash
# Agent B has stale BEFORE=0, but actual file version is 1
BEFORE=0  # stale
# ... compute delta ...
tmp=$(mktemp)
jq --argjson prever "$BEFORE" '.memory_lock.version = ($prever + 1)' "$MEM" > "$tmp"
AFTER=$(jq '.memory_lock.version' "$tmp")  # computes to 1
ACTUAL=$(jq '.memory_lock.version' "$MEM") # actual is 1
# B's write would clobber A's write — version-vector guard catches this:
[ "$AFTER" -eq "$((BEFORE + 1))" ] && [ "$BEFORE" -eq "$ACTUAL" ] \
  || { echo "[conflict] retry needed"; rm "$tmp"; exit 3; }
```

4. Agent B re-reads, recomputes delta against version 1, retries — succeeds (writes version 2)

**Expected Results**:
- Step 3: conflict detected, write aborted
- Step 4: retry succeeds, version is now 2

**Remediation**:
- Agent must re-read memory on conflict; do not blindly retry with stale state
- Log conflict to `decision_log`

**Pass Criteria**: Conflict detected and retried; no lost writes.

**Reference**: payloads.md §10

---

### TC-MA-007 — Crash Mid-Write Leaves Memory Intact

**Severity**: HIGH
**Prerequisites**: kill signal, shared memory file

**Test Steps**:
1. Start a writer agent that takes a long time in the `jq` step:

```bash
(
  flock -x 9 || exit 1
  tmp=$(mktemp)
  jq '... heavy transform ...' "$MEM" > "$tmp" &
  JQ_PID=$!
  sleep 0.1
  kill -9 $JQ_PID  # simulate crash mid-write
  # tmp file is incomplete, but mv never ran
) 9>"$MEM.lock"
```

2. After the crash, verify `$MEM` is still intact (not corrupted) and `$MEM.lock` is released

**Expected Results**:
- `$MEM` is identical to its pre-crash state (the `mv` never ran)
- The orphaned `$tmp` file exists but is harmless
- `flock` is released when the subshell exits; next writer can proceed

**Remediation**:
- Coordinator should sweep orphaned tmp files: `find /runs -name '*.tmp' -mmin +5 -delete`
- The atomic-write pattern is crash-safe by design — this test confirms that property

**Pass Criteria**: Memory file uncorrupted; lock released.

**Reference**: payloads.md §8

---

## C. Convergence Detection

### TC-MA-008 — Convergence Event Fires When 2+ Agents Independently Point to Same Hypothesis Path

**Severity**: CRITICAL
**Prerequisites**: Memory with 2 hypotheses on same path, different claimed_by

**Test Steps**:
1. Bootstrap memory:

```bash
cat > mem.json <<'JSON'
{
  "memory_lock": {"version": 1},
  "vulnerability_hypotheses": [
    {"id": "H-A-001", "hypothesis": "overflow in parse()", "path": "parser.c:412",
     "evidence_for": ["BinDiff: changed function"], "evidence_against": [],
     "status": "LIKELY", "confidence": 0.55, "claimed_by": ["A"]},
    {"id": "H-B-001", "hypothesis": "AFL++ crash in parse()", "path": "parser.c:412",
     "evidence_for": ["crash id:000001"], "evidence_against": [],
     "status": "LIKELY", "confidence": 0.55, "claimed_by": ["B"]}
  ]
}
JSON
```

2. Run the convergence detector:

```bash
python3 convergence_detector.py mem.json
```

3. Verify both hypotheses are now `CONFIRMED`:

```bash
jq '.vulnerability_hypotheses[] | {id, status, confidence}' mem.json
```

**Expected Results**:
- Step 2: detector finds the convergence event on `parser.c:412`
- Step 3: both `H-A-001` and `H-B-001` have `status: "CONFIRMED"`, confidence bumped (e.g., 0.85)
- `decision_log` contains the convergence event entry

**Remediation**:
- If detector fails to fire, check the path comparison logic — it must compare strings exactly (no whitespace trimming)
- If confidence bump fails, check the +0.30 cap at 1.0

**Pass Criteria**: Both hypotheses promoted; convergence logged.

**Reference**: payloads.md §16, §30

---

### TC-MA-009 — Triangulation: Three Independent Evidence Vectors Promote to CONFIRMED

**Severity**: MEDIUM
**Prerequisites**: Memory with 1 hypothesis, 3 distinct evidence_for entries from different sources

**Test Steps**:
1. Bootstrap memory with a hypothesis that has 3 evidence entries (e.g., BinDiff + AFL++ + ASan trace)
2. Run a triangulation check:

```bash
jq -e '
  .vulnerability_hypotheses[] | select(.id == "H-001") |
  (.evidence_for | length) >= 3 and (.claimed_by | length) >= 1
' mem.json
```

3. Apply the triangulation rule:

```bash
jq '.vulnerability_hypotheses |= map(
  if .id == "H-001" and (.evidence_for | length) >= 3 then
    .status = "CONFIRMED" | .confidence = 0.9
  else . end)' mem.json > tmp && mv tmp mem.json
```

**Expected Results**:
- Step 2: check passes (>=3 evidence entries)
- Step 3: hypothesis promoted to `CONFIRMED`, confidence to 0.9

**Remediation**:
- If triangulation doesn't fire, check whether the 3 evidence entries are truly independent (different source tools / different code paths)
- Same-source evidence does not count as independent vectors

**Pass Criteria**: Hypothesis auto-promoted on 3 independent vectors.

**Reference**: payloads.md §5, §16

---

### TC-MA-010 — Convergence Does NOT Fire With Single Agent (False Convergence Prevention)

**Severity**: HIGH
**Prerequisites**: Memory with 2 hypotheses on same path but both `claimed_by: ["A"]` (same agent)

**Test Steps**:
1. Bootstrap memory with two hypotheses from the same agent on the same path
2. Run convergence detector
3. Verify it does NOT fire

**Expected Results**:
- Detector skips this case because `claimed_by` is identical (not independent)
- No promotion; no convergence event in `decision_log`

**Remediation**:
- Convergence requires *independent* agents. Same-agent multiple hypotheses is not convergence; it is one agent confirming itself.
- If detector fires incorrectly, check the `agents | length >= 2` guard

**Pass Criteria**: No false-positive convergence from single-agent multi-hypothesis.

**Reference**: payloads.md §16, §30

---

## D. Anti-Pattern Triggers

### TC-MA-011 — Free-Form Exploration Detected (memory.delta == 0 after action)

**Severity**: HIGH
**Prerequisites**: Agent that wrote without reading

**Test Steps**:
1. Bootstrap memory with `last_write_at` set but `last_read_at` null
2. Run anti-pattern checker:

```bash
python3 anti_pattern_check.py mem.json
```

3. Verify AP-1 is reported

**Expected Results**:
- Checker exits non-zero with `AP-1 free-form exploration: write without prior read`

**Remediation**:
- The atomic-write pattern should require `last_read_at` to be set within the last 60 seconds before any write
- Agent should re-read memory before further action

**Pass Criteria**: AP-1 correctly detected.

**Reference**: payloads.md §17

---

### TC-MA-012 — Memory Drift Detected (Prose Written Instead of Field Update)

**Severity**: MEDIUM
**Prerequisites**: Memory with `decision_log` entry referencing a missing finding

**Test Steps**:
1. Bootstrap memory with `decision_log: [{"finding_ref": "F-999", ...}]` but no `F-999` in findings
2. Run anti-pattern checker
3. Verify AP-2 is reported

**Expected Results**:
- Checker exits non-zero with `AP-2 memory drift: decision_log ref F-999 not in findings`

**Remediation**:
- Either add the missing finding to `findings` first, or remove the dangling `finding_ref`
- Schema validation should enforce that `finding_ref` is a valid key

**Pass Criteria**: AP-2 correctly detected.

**Reference**: payloads.md §18

---

### TC-MA-013 — Repeat-Without-Delta Triggers Path Switch After 3 Attempts

**Severity**: HIGH
**Prerequisites**: Memory with 3+ failed attempts on same hypothesis, no new evidence

**Test Steps**:
1. Bootstrap memory with `failed_attempts: [ATT-1, ATT-2, ATT-3]` all on `H-001`, and `H-001.evidence_for == []`
2. Run anti-pattern checker
3. Verify AP-3 is reported
4. Verify the convergence rule triggers a path switch:

```bash
jq -e '.convergence_state.failed_attempts_on_active_path >= .convergence_state.path_switch_threshold' mem.json
```

**Expected Results**:
- Step 3: AP-3 reported
- Step 4: condition true — path switch should fire on next coordinator sweep

**Remediation**:
- Coordinator should release the current path and pick from `candidate_paths`
- Reset `failed_attempts_on_active_path` to 0 on switch

**Pass Criteria**: AP-3 detected and path-switch trigger armed.

**Reference**: payloads.md §13, §14, §15, §19

---

### TC-MA-014 — Path-Claim Deadlock Detected and Rejected

**Severity**: HIGH
**Prerequisites**: Two agents attempting same path

**Test Steps**:
1. Bootstrap memory; Agent A successfully claims `patch-diff`
2. Agent B attempts to claim `patch-diff` (read stale memory before A wrote)
3. Atomic-write deadlock check fires:

```bash
jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$tmp" \
  >/dev/null || { echo "[deadlock]"; rm "$tmp"; exit 4; }
```

**Expected Results**:
- Agent B's write is rejected with `[deadlock]` exit code 4
- Memory state unchanged by B's failed attempt

**Remediation**:
- B should fall back to next candidate path
- Coordinator may reassign to ensure coverage

**Pass Criteria**: Deadlock detected before write commits.

**Reference**: payloads.md §11, §20

---

### TC-MA-015 — Premature Stop Prevented (No Differential Verification → No Stop)

**Severity**: CRITICAL
**Prerequisites**: Agent attempting to mark stop without verification

**Test Steps**:
1. Bootstrap memory with `stop_condition_met: true` but `verification_results: {}` (empty)
2. Run anti-pattern checker
3. Verify AP-5 is reported

**Expected Results**:
- Checker exits non-zero with `AP-5 premature stop without differential verification`

**Remediation**:
- The atomic-write pattern must run the premature-stop check before `mv`
- Agent must populate `verification_results.vulnerable` and `verification_results.patched` before setting stop flag

**Pass Criteria**: AP-5 detected; stop blocked.

**Reference**: payloads.md §21

---

## E. Topology Selection

### TC-MA-016 — Topology Selection — Parallel-Explorers Chosen for Bug-Class Exploration

**Severity**: MEDIUM
**Prerequisites**: Task with multiple independent directions, single target

**Test Steps**:
1. Define a task: "discover exploit for libpng UAF, given patch-diff, harness-entry, and sanitizer directions available"
2. Apply topology selection rule:

```python
task = {"bug_class_exploration": True, "multiple_independent_directions": True,
        "single_target": True}
if task["bug_class_exploration"] and task["multiple_independent_directions"]:
    topology = "parallel-explorers"
```

3. Verify topology is `parallel-explorers`

**Expected Results**:
- Topology correctly identified as `parallel-explorers`
- This is the SCEN-007 case

**Remediation**:
- If topology is misidentified, check the selection matrix inputs (§22)

**Pass Criteria**: Parallel-explorers selected for multi-direction bug exploration.

**Reference**: payloads.md §22

---

### TC-MA-017 — Topology Selection — Pipeline Chosen for Recon→Exploit→Report

**Severity**: MEDIUM
**Prerequisites**: Phase-sequential task with clear handoffs

**Test Steps**:
1. Define task: phases recon → exploit → report with clear dependencies
2. Apply selection rule
3. Verify topology is `pipeline`

**Expected Results**:
- Topology identified as `pipeline` (not parallel-explorers — phases have dependencies)

**Remediation**:
- If misidentified, check whether `phase_sequential` and `clear_handoffs` flags are set

**Pass Criteria**: Pipeline selected for phase-sequential work.

**Reference**: payloads.md §22

---

### TC-MA-018 — Topology Selection — Council for Multi-Perspective Judgment

**Severity**: MEDIUM
**Prerequisites**: Judgment-heavy task, multiple analytical lenses

**Test Steps**:
1. Define task: "decide whether to publish a 0-day disclosure; need Attack / Defense / Audit perspectives"
2. Apply selection rule
3. Verify topology is `council`

**Expected Results**:
- Topology identified as `council`

**Remediation**:
- Council is for *perspective* analysis, not for *direction* exploration
- Parallel-explorers and council are not interchangeable

**Pass Criteria**: Council selected for perspective analysis.

**Reference**: payloads.md §22

---

### TC-MA-019 — Topology Selection — Hierarchical for Dynamic Multi-Specialist

**Severity**: MEDIUM
**Prerequisites**: Dynamic scope, 3+ specialists

**Test Steps**:
1. Define task: large engagement, scope shifts mid-execution, 4 specialists (web / network / cloud / OSINT)
2. Apply selection rule
3. Verify topology is `hierarchical` (coordinator-worker)

**Expected Results**:
- Topology identified as `hierarchical`

**Remediation**:
- Hierarchical adds coordinator overhead; only choose when other topologies don't fit

**Pass Criteria**: Hierarchical selected for dynamic multi-specialist.

**Reference**: payloads.md §22

---

### TC-MA-020 — Topology Selection — Single-Agent for Linear Simple Task

**Severity**: LOW
**Prerequisites**: Linear, simple task

**Test Steps**:
1. Define task: single host, single vulnerability, clear test path
2. Apply selection rule
3. Verify topology is `single-agent` (fall back to autonomous-loops)

**Expected Results**:
- Topology identified as `single-agent` — multi-agent overhead not justified

**Remediation**:
- Forcing multi-agent on a simple task wastes coordinator overhead

**Pass Criteria**: Single-agent selected for simple linear tasks.

**Reference**: payloads.md §22

---

## F. End-to-End Multi-Agent Coordination

### TC-MA-021 — Full SCEN-007-Style 3-Agent Exploit Dev Run — Wall-Clock Under 90 Minutes

**Severity**: HIGH
**Prerequisites**: 3 agent runtimes, libpng vulnerable + patched binaries, AFL++, ASan, jq, flock

**Test Steps**:
1. Bootstrap `exploit-attempt-memory.json` per §3
2. Launch dispatcher (§29) with 3 agents (A=patch-diff, B=harness-entry, C=sanitizer)
3. Monitor for convergence events, anti-pattern alerts
4. Wait for stop condition (differential verification passes)
5. Verify final memory state

```bash
jq '{
  confirmed_hypotheses: [.vulnerability_hypotheses[] | select(.status == "CONFIRMED") | .id],
  confirmed_pocs: [.candidate_pocs[] | select(.status == "CONFIRMED") | .id],
  iterations: .convergence_state.iterations,
  stop_reason: .convergence_state.stop_reason
}' "$MEM"
```

**Expected Results**:
- At least 2 hypotheses `CONFIRMED` via convergence
- At least 1 `candidate_pocs` entry `CONFIRMED` via differential verification
- `stop_reason: "Differential verification passed on vulnerable AND patched versions"`
- Wall-clock under 90 minutes for the libpng UAF case

**Remediation**:
- If wall-clock exceeds 90 minutes, check for path-claim deadlocks or repeat-without-delta loops
- If no convergence fires, check direction independence (agents should be truly different)

**Pass Criteria**: Confirmed PoC via convergence + differential verification; under 90 min.

**Reference**: payloads.md §29, validation/scenarios/SCEN-007.md

---

### TC-MA-022 — Coordinator Halts Agents When Stop Condition Met

**Severity**: HIGH
**Prerequisites**: Dispatcher script (§29), running agents

**Test Steps**:
1. Launch dispatcher with 3 agents
2. Manually set `stop_condition_met: true` in memory (simulating differential verification pass)
3. Verify coordinator detects stop on next sync sweep
4. Verify coordinator sends TERM signal to all agents

```bash
# Manually trigger stop
write_memory "$MEM" "test" '.convergence_state.stop_condition_met = true'
# Wait up to 60s for coordinator sync sweep
sleep 60
# Check agent processes
ps aux | grep -E 'patch_diff_agent|harness_entry_agent|sanitizer_agent' | grep -v grep
```

**Expected Results**:
- No agent processes remain after coordinator sync
- Memory state preserved (agents cleanly halted)

**Remediation**:
- If agents keep running, coordinator's TERM signal may be ignored — add `kill -9` fallback after timeout
- If agents don't halt cleanly on TERM, add signal handlers

**Pass Criteria**: All agents halt within 60s of stop condition.

**Reference**: payloads.md §29

---

### TC-MA-023 — Evidence Integrity Check (sha256 Match)

**Severity**: HIGH
**Prerequisites**: Memory with `evidence_index`, evidence files on disk

**Test Steps**:
1. Bootstrap memory with `evidence_index` entries and corresponding files
2. Compute sha256 of each evidence file; compare to memory

```bash
for f in evidence/*.txt; do
  basename=$(basename "$f")
  actual=$(sha256sum "$f" | cut -d' ' -f1)
  expected=$(jq -r --arg f "$basename" '.evidence_index[$f].sha256' mem.json)
  [ "$actual" = "$expected" ] || echo "[MISMATCH] $basename"
done
```

3. Tamper with one evidence file; re-run check; verify mismatch detected

**Expected Results**:
- Step 2: all hashes match
- Step 3: tampered file flagged

**Remediation**:
- If hashes don't match, evidence chain-of-custody is broken — engagement report loses credibility
- Investigate root cause (file modified after collection? wrong hash algorithm?)

**Pass Criteria**: All hashes match; tampering detected.

**Reference**: payloads.md §26

---

### TC-MA-024 — Schema Migration Forward-Only

**Severity**: MEDIUM
**Prerequisites**: Memory at schema_version 1.0, migration script to 1.1

**Test Steps**:
1. Back up `mem.json` to `mem.v1.0.json`
2. Run migration script to upgrade to 1.1
3. Verify schema_version is now 1.1 and the field rename occurred
4. Attempt to run a downgrade migration; verify it fails (or refuses)

**Expected Results**:
- Steps 2-3: schema_version upgraded, fields renamed correctly
- Step 4: downgrade refused — forward-only policy enforced

**Remediation**:
- If upgrade fails, restore from `mem.v1.0.json` backup
- Never run migrations without backup

**Pass Criteria**: Forward migration works; downgrade refused.

**Reference**: payloads.md §33

---

### TC-MA-025 — Memory Compaction Prunes Low-Value Entries

**Severity**: LOW
**Prerequisites**: Memory with INVALIDATED hypotheses older than cutoff, >10 failed_attempts

**Test Steps**:
1. Populate memory with: 2 INVALIDATED hypotheses older than 30 days; 20 failed_attempts on same hypothesis
2. Run compaction script with `max_age_days=30, max_failed_attempts=10`
3. Verify INVALIDATED hypotheses pruned; failed_attempts capped at 10

**Expected Results**:
- Step 2: compaction succeeds; decision_log preserved (append-only invariant)
- Step 3: only recent INVALIDATED hypotheses remain; 10 most recent failed_attempts per hypothesis kept

**Remediation**:
- If compaction deletes active data, check the cutoff logic
- If decision_log is pruned, that's a violation — append-only must be preserved

**Pass Criteria**: Low-value data pruned; high-value data and audit trail preserved.

**Reference**: payloads.md §34

---

### TC-MA-026 — Federation Distill Produces Prose for MEMORY.md

**Severity**: LOW
**Prerequisites**: Closed engagement memory, `MEMORY.md`

**Test Steps**:
1. Take a closed engagement memory with confirmed findings
2. Run `federation_distill.py engagement.json >> MEMORY.md`
3. Verify MEMORY.md has a new section with confirmed findings, tried-and-failed summary, and lessons

**Expected Results**:
- Step 2: distill succeeds; section appended to MEMORY.md
- Step 3: section has engagement ID, target, status, confirmed findings list, failed-attempt summary, lessons learned

**Remediation**:
- If distill produces empty section, check that engagement has confirmed findings
- If duplicate sections appear, check idempotency (distill twice should not duplicate)

**Pass Criteria**: Prose distillation completes; section is well-formed.

**Reference**: payloads.md §35

---

### TC-MA-027 — End-to-End Penetration Test Engagement Memory (Schema 1) Through 5 Phases

**Severity**: HIGH
**Prerequisites**: Schema 1 memory, 5 phases (recon / intrusion / privesc / lateral / exfil), phase-transition discipline

**Test Steps**:
1. Bootstrap `engagement-memory.json` per §2 with `current_phase: "recon"`
2. Phase 1 (recon): add entry_points, evidence, bump version
3. Phase 2 (intrusion): read memory, update findings.vulnerabilities, update next_constraints
4. Phase 3 (privesc): read memory, add a finding, update convergence_state.active_path
5. Phase 4 (lateral): read memory, add lateral_pivots
6. Phase 5 (exfil/report): read memory, finalize findings
7. Verify each phase read prior state, wrote delta, version increments correctly

```bash
jq '.memory_lock.version, .current_phase, [.phase_history[].phase]' engagement-memory.json
```

**Expected Results**:
- version increments by 1+ per phase
- `phase_history` lists all 5 phases in order
- `findings.entry_points`, `findings.vulnerabilities`, `findings.lateral_pivots` all populated
- `next_constraints.must_avoid` preserved across phases (no drift)

**Remediation**:
- If a phase wrote without reading, AP-1 free-form exploration fires
- If `next_constraints.must_avoid` was violated, scope breach — abort engagement

**Pass Criteria**: 5-phase engagement completes with structured memory intact.

**Reference**: payloads.md §2, §6

---

### TC-MA-028 — Path-Release Signal Allows Other Agents to Reclaim

**Severity**: MEDIUM
**Prerequisites**: 3-agent memory, one agent releasing a path

**Test Steps**:
1. Agents A, B, C claim paths patch-diff, harness-entry, sanitizer
2. Agent A releases patch-diff (hypothesis confirmed)
3. Verify `active_paths.A` is removed
4. A new agent D can claim patch-diff without deadlock

```bash
# Agent A releases
write_memory "$MEM" A 'del(.active_paths["A"])'
# Agent D claims
write_memory "$MEM" D '.active_paths["D"] = "patch-diff"'
# Verify
jq '.active_paths' "$MEM"
```

**Expected Results**:
- After A's release: `active_paths` has only B and C
- After D's claim: `active_paths` has D (patch-diff), B, C — no duplicates

**Remediation**:
- If release fails, check the `del(.active_paths[$agent])` jq pattern
- If D's claim triggers deadlock, the release didn't commit

**Pass Criteria**: Path cleanly released and re-claimed without deadlock.

**Reference**: payloads.md §12

---

### TC-MA-029 — Time-Budget Exhaustion Triggers Stop

**Severity**: MEDIUM
**Prerequisites**: Memory with `time_budget_remaining_hours` near zero

**Test Steps**:
1. Bootstrap memory with `time_budget_remaining_hours: 0.1` (6 minutes)
2. Wait 7 minutes; trigger coordinator time-budget update
3. Verify stop_condition fires:

```bash
jq -e '.convergence_state.stop_reason == "time budget exhausted"' "$MEM"
```

**Expected Results**:
- After 7 minutes: `stop_reason` set to "time budget exhausted"
- Stop condition met; coordinator halts agents

**Remediation**:
- If time-budget check doesn't fire, coordinator's wall-clock update is broken
- If agents continue past stop, coordinator's TERM signal is missing

**Pass Criteria**: Time budget correctly enforced as a stop condition.

**Reference**: payloads.md §27

---

### TC-MA-030 — Open-Questions Queue Swept at Each Sync Point

**Severity**: LOW
**Prerequisites**: Memory with open_questions

**Test Steps**:
1. Bootstrap memory with 3 open questions (Q-001, Q-002, Q-003)
2. Resolve Q-001 with a finding reference; escalate Q-002; leave Q-003 open
3. Run coordinator sweep:

```bash
jq '.open_questions | map({
  id, status,
  resolved: (.status == "RESOLVED" and .related_to != null)
})' "$MEM"
```

4. Verify sweep produces actionable status per question

**Expected Results**:
- Q-001: status RESOLVED, has related_to finding
- Q-002: status ESCALATED
- Q-003: status OPEN

**Remediation**:
- If questions remain unresolved at engagement close, they should escalate to the report as "future work"

**Pass Criteria**: Each open question has a clear status; no orphans.

**Reference**: payloads.md §28
