# Multi-Agent Runtime Engineering Payloads

> Templates, schemas, scripts, and patterns for building agent systems with structured memory, atomic-write sync, convergence detection, anti-pattern prevention, and topology selection. Solidifies SCEN-007 + SCEN-MEMORY-SCHEMA patterns.

## Conventions

- All schemas are JSON (machine-queryable, jq-compatible). No prose where a field will do.
- Replace `/runs/SCEN-XXX/` with your actual engagement directory.
- Replace `/targets/...` with your actual target paths.
- All code blocks are syntactically valid (bash, python, jq, or json) unless otherwise noted.
- The terms *memory*, *memory file*, and *JSON state* are used interchangeably.

---

## §1. Why Structured Memory Beats Prose Memory (MopMonk 招一 rationale)

MopMonk's first招 — structured vulnerability memory — rests on a simple claim: **prose memory is write-only**. Agents write prose fluently, but they cannot reliably query it. "What did we learn about the parsing loop?" requires the agent to re-read the entire `MEMORY.md` and reason about it — every iteration. The cost compounds: by iteration 20, the prose memory has grown to thousands of words; by iteration 100, it is unusable.

Structured memory inverts this. Instead of writing prose, the agent writes **field updates** — `"findings.entry_points += [{target: ..., confidence: ...}]"`. The query "what did we learn about target X?" becomes a jq one-liner: `jq '.findings.entry_points[] | select(.target == "X")'`. The cost is constant per query, not linear.

The MopMonk research (kali-claw `docs/mopmonk-research-and-kali-claw-plan.md`) frames this as the difference between *human-readable* memory (good for after-action reports) and *machine-queryable* memory (good for in-loop reasoning). Both layers are necessary; only the machine-queryable layer lets the agent converge.

Three diagnostic questions to ask when designing any agent memory:

1. **Can the agent answer "what did we try?" in O(log n) or better?** If it has to re-read the whole memory to answer, the memory is prose, not structured.
2. **Can two parallel agents update without clobbering each other?** If not, you do not have a multi-agent memory; you have a single-agent memory being raced on.
3. **Can a future version of the schema migrate the old data?** If the schema has no `schema_version`, you cannot evolve it without breaking past engagements.

This skill ships three canonical schemas (below) designed to answer "yes" to all three.

---

## §2. Schema 1 — Pentest Engagement Memory (full JSON template)

**File**: `engagement-memory.json` — per-engagement, cross-phase structured state.

```json
{
  "schema_version": "1.0",
  "engagement_id": "ENG-2026-07-001",
  "captain": "Bruce",
  "scope": {
    "targets": ["example.com", "10.0.0.0/24"],
    "authorized_services": ["web", "smtp", "dns"],
    "excluded": ["10.0.0.1", "mail.example.com"],
    "rules_of_engagement": "ROE-2026-07-001.pdf"
  },
  "current_phase": "recon",
  "phase_history": [
    {"phase": "recon", "started_at": "2026-07-03T09:00:00Z", "ended_at": "2026-07-03T11:30:00Z", "status": "completed"}
  ],
  "findings": {
    "entry_points": [
      {"target": "web.example.com:443", "type": "https", "confidence": "CONFIRMED", "evidence": ["nmap-01.txt"], "claimed_by": ["recon-agent"]},
      {"target": "vpn.example.com:443", "type": "ssl-vpn", "confidence": "LIKELY", "evidence": ["nmap-02.txt"], "claimed_by": ["recon-agent"]}
    ],
    "credentials": [],
    "vulnerabilities": [],
    "lateral_pivots": []
  },
  "evidence_index": {
    "nmap-01.txt": {"collected_at": "2026-07-03T09:15:00Z", "phase": "recon", "sha256": "...", "collected_by": "recon-agent"}
  },
  "next_constraints": {
    "must_explore": ["web.example.com:443/api"],
    "must_avoid": ["10.0.0.1", "production-db"],
    "time_budget_remaining_hours": 4.5
  },
  "convergence_state": {
    "active_path": "web-api-fuzzing",
    "candidate_paths": ["web-api-fuzzing", "vpn-credential-brute", "phishing-pretext"],
    "failed_attempts_on_active_path": 0,
    "path_switch_threshold": 3,
    "evidence_yield_last_action": true
  },
  "open_questions": [
    "Is the API at /api/v2/ reachable without authentication?"
  ],
  "memory_lock": {
    "version": 0,
    "owner_agents": [],
    "last_read_at": null,
    "last_write_at": null,
    "last_write_by": null
  },
  "decision_log": [
    {"at": "2026-07-03T10:22:00Z", "by": "intrusion-agent", "decision": "switched path from vpn-credential-brute to web-api-fuzzing", "reason": "3 failed attempts yielded no new evidence"}
  ]
}
```

**Required fields**: `schema_version`, `engagement_id`, `scope`, `current_phase`, `findings`, `evidence_index`, `next_constraints`, `convergence_state`, `memory_lock`, `decision_log`. Schema validation rejects writes missing any of these.

---

## §3. Schema 2 — Exploit Attempt Memory (full JSON template)

**File**: `exploit-attempt-memory.json` — shared across parallel exploit-dev agents.

```json
{
  "schema_version": "1.0",
  "target": {
    "binary": "/targets/libpng-1.6.37/build/libpng.so",
    "patched_binary": "/targets/libpng-1.6.38/build/libpng.so",
    "type": "ELF x86-64",
    "source_available": false,
    "patch_diff": "v1.6.37_v1.6.38.patch",
    "sanitizer_enabled": "ASan+UBSan",
    "cve": "CVE-2019-7317"
  },
  "memory_lock": {
    "version": 17,
    "owner_agents": ["A", "B", "C"],
    "last_read_at": "2026-07-03T10:42:00Z",
    "last_write_at": "2026-07-03T10:43:15Z",
    "last_write_by": "B"
  },
  "vulnerability_hypotheses": [
    {
      "id": "H-001",
      "hypothesis": "Heap buffer overflow in parse_json()",
      "path": "src/parser.c:412",
      "evidence_for": ["ASan triggered at line 412", "patch adds bounds check"],
      "evidence_against": [],
      "status": "CONFIRMED",
      "confidence": 0.92,
      "claimed_by": ["A", "B"],
      "convergence_events": [
        {"at": "2026-07-03T10:25:00Z", "agents": ["A", "B"], "reason": "same path, independent evidence vectors"}
      ],
      "created_at": "2026-07-03T10:10:00Z"
    },
    {
      "id": "H-002",
      "hypothesis": "Integer overflow in length calculation",
      "path": "src/parser.c:398",
      "evidence_for": [],
      "evidence_against": ["Input size up to 2GB doesn't trigger"],
      "status": "INVALIDATED",
      "confidence": 0.05,
      "claimed_by": ["C"],
      "created_at": "2026-07-03T10:15:00Z"
    }
  ],
  "candidate_pocs": [
    {
      "id": "PoC-001",
      "based_on_hypothesis": "H-001",
      "input_shape": "JSON with 65536-byte string value",
      "expected_behavior": "ASan heap-buffer-overflow",
      "actual_behavior": "ASan triggered",
      "diff_result": {"vulnerable_version": "crash", "patched_version": "no-crash"},
      "status": "CONFIRMED",
      "verification_log": "poc-001-asan.txt"
    }
  ],
  "failed_attempts": [
    {
      "attempt_id": "ATT-007",
      "by_agent": "C",
      "input_shape": "Integer overflow probe",
      "hypothesis": "H-002",
      "yielded_new_evidence": false,
      "ended_at": "2026-07-03T10:30:00Z"
    }
  ],
  "active_paths": {
    "A": "patch-diff",
    "B": "harness-entry",
    "C": "sanitizer"
  },
  "verification_results": {
    "vulnerable": {"crashed": true, "sanitizer_output": "ERROR: AddressSanitizer: heap-buffer-overflow"},
    "patched": {"crashed": false, "sanitizer_output": "clean"}
  },
  "convergence_state": {
    "iterations": 23,
    "confirmed_poc": "PoC-001",
    "stop_condition_met": true,
    "stop_reason": "Differential verification passed on vulnerable AND patched versions",
    "sync_points_executed": 5
  },
  "decision_log": [
    {"at": "2026-07-03T10:25:00Z", "by": "council", "decision": "CONVERGENCE: H-A-001 ∩ H-B-001 on parser.c:412", "reason": "independent agents arrived at same path"}
  ]
}
```

**Path switch rule**: an agent releases its path and picks a new one when (1) its hypothesis is `CONFIRMED`, (2) its hypothesis is `INVALIDATED`, or (3) `failed_attempts_on_active_path >= 3` without evidence delta.

---

## §4. Schema 3 — Patch-Diff Reproduction Memory (full JSON template)

**File**: `repro-attempt-memory.json` — CyberGym-style PoC reproduction.

```json
{
  "schema_version": "1.0",
  "task": {
    "vulnerable_version": "/targets/libfoo-1.8.2",
    "patched_version": "/targets/libfoo-1.8.3",
    "patch_file": "CVE-2024-12345.patch",
    "cve": "CVE-2024-12345",
    "build_env": "ubuntu:22.04 + build-essential"
  },
  "patch_analysis": {
    "files_changed": ["src/decode.c"],
    "lines_added": 8,
    "lines_removed": 2,
    "key_change": "Added bounds check before memcpy at line 187",
    "suspected_vuln_function": "decode_chunk()",
    "suspected_vuln_type": "stack-buffer-overflow",
    "confidence": 0.85
  },
  "code_path": {
    "entry_function": "main() -> parse_input()",
    "call_chain_to_vuln": ["main", "parse_input", "decode_chunk"],
    "input_to_vuln_distance": 3
  },
  "candidate_inputs": [
    {
      "id": "IN-001",
      "shape": "chunked-encoded stream with chunk-size = 2^31",
      "expected_trigger": "memcpy overflow",
      "test_status": "PENDING"
    }
  ],
  "verification_results": {
    "vulnerable": {"crashed": true, "sanitizer_output": "ERROR: AddressSanitizer: stack-buffer-overflow"},
    "patched": {"crashed": false, "sanitizer_output": "clean"}
  },
  "convergence_state": {
    "iterations": 4,
    "status": "POC_CONFIRMED_DIFFERENTIALLY",
    "next_action": "Document PoC + write detection rule"
  },
  "memory_lock": {
    "version": 4,
    "owner_agents": ["repro-agent"],
    "last_write_at": "2026-07-03T11:15:00Z",
    "last_write_by": "repro-agent"
  },
  "decision_log": [
    {"at": "2026-07-03T11:00:00Z", "by": "repro-agent", "decision": "patch analysis complete", "reason": "8 lines added, 2 removed, key change at decode.c:187"}
  ]
}
```

---

## §5. Confidence-level Taxonomy

The confidence taxonomy is the agent's vocabulary for *how sure* it is. Without a fixed vocabulary, every agent invents its own ("highly likely", "very probable", "almost certain") and merging across agents becomes impossible.

| Level | Definition | Triggered by |
|-------|------------|--------------|
| `CONFIRMED` | 3+ independent evidence vectors, OR 2+ agents independently arrived (convergence) | Differential verification passes; multi-agent convergence event fires |
| `LIKELY` | 2 vectors OR 1 authoritative vector | Single high-quality tool output (e.g., ASan trace) + corroborating static analysis |
| `POSSIBLE` | 1 vector, plausible | Single tool output, no corroboration |
| `UNVERIFIED` | Hypothesis only, no evidence yet | Agent's reasoning chain, not yet executed |
| `INVALIDATED` | Evidence against outweighs evidence for | Counter-example found; failed_attempts >= 3 with no positive evidence |

This taxonomy is rigid — agents are not free to invent levels. Schema validation rejects any `confidence` string not in this list. Numeric confidence (0.0-1.0) complements the taxonomy but does not replace it: `LIKELY` with confidence 0.65 is valid; "probably-true" is not.

The taxonomy also drives convergence: `LIKELY` + `LIKELY` from two independent agents with same `path` → both promoted to `CONFIRMED` (convergence event). This rule is mechanical, not judgment-based.

---

## §6. Memory Delta Write Pattern (read → execute → write delta)

Every agent iteration MUST produce a delta. A delta is a structured change set: fields added, fields updated, fields invalidated. The pattern is:

```bash
# Step 1: read current memory under shared lock
(
  flock -s 9 || exit 1
  cp "$MEM" "$MEM.before"
) 9>"$MEM.lock"

# Step 2: execute the action (run a tool, analyze output, etc.)
# ... tool output lands in evidence/<timestamp>-<tool>.txt ...

# Step 3: compute the delta and write under exclusive lock
(
  flock -x 9 || exit 1
  tmp=$(mktemp)
  jq --slurpfile before "$MEM.before" \
     --arg agent "$AGENT_ID" \
     --arg action "$ACTION_DESC" \
     --argjson evidence "$EVIDENCE_JSON" \
    '. as $after
     | $before[0] as $b
     | {
         evidence_added: ($after.findings.entry_points - $b.findings.entry_points),
         confidence_delta: ($after.findings.entry_points[0].confidence // null)
       }' \
    "$MEM" > "$tmp"
  # ... apply delta + version bump ...
  mv "$tmp" "$MEM"
) 9>"$MEM.lock"
```

The discipline: an iteration that produces no delta is a **failed attempt**, not a no-op. Three failed attempts on the same hypothesis trigger a path switch (招二).

---

## §7. POSIX flock Advisory Lock Primer

`flock` is a Linux/macOS advisory file lock. It is *not* mandatory — cooperating processes must agree to use it. For kali-claw's purposes, all agents use the canonical atomic-write pattern, so cooperation is guaranteed.

```bash
# Exclusive lock (one writer at a time)
(
  flock -x 9 || exit 1
  echo "exclusive hold"
  # ... do work ...
) 9>"/path/file.lock"

# Shared lock (multiple readers, no writers)
(
  flock -s 9 || exit 1
  echo "shared hold"
) 9>"/path/file.lock"

# Lock with timeout (30s)
(
  flock -x -w 30 9 || { echo "lock timeout"; exit 1; }
  # ... work ...
) 9>"/path/file.lock"

# Non-blocking (fail fast if contended)
(
  flock -n 9 || { echo "busy"; exit 1; }
  # ... work ...
) 9>"/path/file.lock"
```

**Key properties**:
- Lock is *automatically released* when the locking process exits (or the file descriptor closes)
- Lock is on the file descriptor, not the file path — `9>sidecar.lock` opens `sidecar.lock` for writing on fd 9; the lock attaches to whatever inode that file has
- The lock file itself is typically empty — only the inode matters
- Multiple shells locking the same file with the same fd number will block each other correctly

**Gotchas**:
- Do not use `flock` on NFS without `--verbose` testing; NFS locking has historical quirks
- The fd number (9 here) is arbitrary but must be available; `9` is conventional in kali-claw
- If you fork inside the subshell, the child inherits the fd but should not release the lock prematurely

---

## §8. Atomic Write Pattern (`mktemp` + `mv`)

The atomic-write pattern is the foundation of crash-safe memory updates. The trick: write the new content to a temp file, then `mv` (rename) the temp file to the real path. POSIX guarantees `mv` (within the same filesystem) is atomic — either the new file is fully in place, or the old file is still there. No half-written state is ever observable.

```bash
# Canonical atomic write
tmp=$(mktemp)                          # temp file on same filesystem
jq '. | update_expr' "$MEM" > "$tmp"   # write to temp
mv "$tmp" "$MEM"                       # atomic rename
```

**Critical**: `mktemp` defaults to `/tmp`, which may be on a different filesystem than `$MEM`. If so, `mv` becomes a copy + delete (not atomic). Fix: tell `mktemp` to use the same directory.

```bash
tmp=$(mktemp -p "$(dirname "$MEM")")   # same directory = same filesystem = atomic
```

Or:

```bash
tmp="$(dirname "$MEM")/.mem.tmp.$$"
jq '. | ...' "$MEM" > "$tmp"
mv "$tmp" "$MEM"
```

**Crash tolerance**: if the agent process is killed between the `jq` write and the `mv`, the temp file is left behind but the real memory file is intact. A coordinator can GC orphaned temp files: `find /runs -name '.*.tmp.*' -mmin +60 -delete`.

---

## §9. jq Read-Modify-Write Template

jq is the workhorse for atomic memory updates. The template:

```bash
MEM=/runs/SCEN-007/mem/exploit-attempt-memory.json

(
  flock -x -w 30 9 || exit 1
  BEFORE=$(jq '.memory_lock.version' "$MEM")
  tmp=$(mktemp -p "$(dirname "$MEM")")
  jq \
    --arg agent "$AGENT_ID" \
    --arg now "$(date -u +%FT%TZ)" \
    --argjson prever "$BEFORE" \
    '
     .vulnerability_hypotheses += [{
       "id": $hid, "hypothesis": $htext, "path": $hpath,
       "evidence_for": $ev, "evidence_against": [],
       "status": "LIKELY", "confidence": 0.55,
       "claimed_by": [$agent], "created_at": $now
     }]
     | .memory_lock.version = ($prever + 1)
     | .memory_lock.last_write_at = $now
     | .memory_lock.last_write_by = $agent
     | .memory_lock.last_read_at = $now
     | .convergence_state.iterations += 1
     | .decision_log += [{
         "at": $now, "by": $agent,
         "decision": ("added hypothesis " + $hid)
       }]
    ' "$MEM" > "$tmp"

  AFTER=$(jq '.memory_lock.version' "$tmp")
  [ "$AFTER" -eq "$((BEFORE + 1))" ] || { echo "[conflict]"; rm "$tmp"; exit 2; }

  mv "$tmp" "$MEM"
) 9>"$MEM.lock"
```

**Notes**:
- `--arg` for strings, `--argjson` for JSON literals, `--slurpfile` for reading another file
- `--rawfile` to embed file contents as a string
- Always validate version increment before `mv` — last-writer-wins on overlapping fields is acceptable; on the version field itself, conflict means retry

---

## §10. Version Vector Protocol for Multi-Writer

The version vector is the optimistic-concurrency primitive. Every write must increment `memory_lock.version` by exactly 1. If two agents read version N simultaneously and both try to write, only one will succeed in incrementing to N+1; the other will compute its delta against N, try to write N+1, find the version already at N+1, and abort.

```bash
# Inside the lock:
BEFORE=$(jq '.memory_lock.version' "$MEM")           # read under lock
# ... compute delta ...
jq --argjson prever "$BEFORE" '
   .memory_lock.version = ($prever + 1)
   | ... rest of delta ...
' "$MEM" > "$tmp"
AFTER=$(jq '.memory_lock.version' "$tmp")
if [ "$AFTER" -ne "$((BEFORE + 1))" ]; then
  echo "[conflict] expected version $((BEFORE + 1)), got $AFTER"
  rm "$tmp"
  exit 2
fi
mv "$tmp" "$MEM"
```

**Why this works**: the `flock` serializes writes — only one writer at a time. But the version check is a *semantic* guarantee: even if the writer's jq logic is buggy and increments by 2, the check catches it.

**Conflict resolution**: when an agent gets a version-mismatch, it should:
1. Re-read the current memory (it changed since the agent's prior read)
2. Re-evaluate whether the delta still makes sense
3. If yes: retry the write with the new version
4. If no: drop the delta, log to `decision_log` as "aborted: pre-empted by competing write"

For non-overlapping fields (agent A writes to `findings.entry_points`, agent B writes to `findings.vulnerabilities`), the retry always succeeds because the fields are disjoint. For overlapping fields, the retry may fail again — at which point the agent must merge or yield.

---

## §11. Path-Claim Coordination (race-safe flock 9)

In SCEN-007, three agents (A=patch-diff, B=harness-entry, C=sanitizer) each need to claim a unique path. The protocol:

```bash
AGENT_ID=A
CLAIM_PATH=patch-diff   # or harness-entry, sanitizer
MEM=/runs/SCEN-007/mem/exploit-attempt-memory.json

(
  flock -x -w 30 9 || exit 1
  tmp=$(mktemp -p "$(dirname "$MEM")")

  jq --arg agent "$AGENT_ID" --arg path "$CLAIM_PATH" \
    '.active_paths[$agent] = $path
     | .memory_lock.owner_agents = (.active_paths | keys)
     | .memory_lock.version += 1
     | .memory_lock.last_write_at = (now | todateiso8601)
     | .memory_lock.last_write_by = $agent
     | .decision_log += [{
         "at": (now | todateiso8601), "by": $agent,
         "decision": ("claimed path " + $path)
       }]' \
    "$MEM" > "$tmp"

  # Anti-pattern check: no duplicate active_paths values
  jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$tmp" >/dev/null \
    || {
      # Path collision detected — release and try a fallback path
      echo "[deadlock] $AGENT_ID: path $CLAIM_PATH already taken"
      rm "$tmp"
      # ... fallback logic: pick next candidate_path ...
      exit 2
    }

  mv "$tmp" "$MEM"
) 9>"$MEM.lock"
```

The `flock` guarantees only one agent's claim is in flight at a time. The duplicate-check guarantees that if two agents tried to claim the same path (because they read the memory before either wrote), the second one's write is rejected.

---

## §12. Path-Release Signals

When an agent is done with a path (hypothesis CONFIRMED, INVALIDATED, or stuck), it releases the path so other agents can re-claim if needed:

```bash
AGENT_ID=A
MEM=/runs/SCEN-007/mem/exploit-attempt-memory.json

(
  flock -x -w 30 9 || exit 1
  tmp=$(mktemp -p "$(dirname "$MEM")")

  jq --arg agent "$AGENT_ID" --arg reason "$REASON" \
    'del(.active_paths[$agent])
     | .memory_lock.owner_agents = (.active_paths | keys)
     | .memory_lock.version += 1
     | .memory_lock.last_write_at = (now | todateiso8601)
     | .memory_lock.last_write_by = $agent
     | .decision_log += [{
         "at": (now | todateiso8601), "by": $agent,
         "decision": ("released path", "reason": $reason)
       }]' \
    "$MEM" > "$tmp"

  mv "$tmp" "$MEM"
) 9>"$MEM.lock"
```

**Signal conventions**:
- `reason: done` — hypothesis CONFIRMED, path complete
- `reason: stuck` — failed_attempts >= 3, switching path
- `reason: aborted` — agent crashed or was preempted; coordinator should clean up

---

## §13. Memory-Driven Convergence Rule (招二)

MopMonk's second招 — memory-driven convergence — is encoded as a rule that fires after every action:

```yaml
convergence_rule:
  description: |
    Every agent action MUST either produce new evidence (a delta to
    evidence_for, evidence_against, candidate_pocs, or similar) OR be
    aborted and trigger a path-switch check.
  implementation: |
    after_each_action:
      - if action.yielded_new_evidence:
          memory.confidence += computed_confidence_delta
          memory.convergence_state.failed_attempts_on_active_path = 0
      - else:
          memory.failed_attempts += {attempt_id, hypothesis, ended_at}
          memory.convergence_state.failed_attempts_on_active_path += 1
          if memory.convergence_state.failed_attempts_on_active_path >= path_switch_threshold:
              switch_path(memory)
```

The `switch_path` function:

```python
def switch_path(memory):
    current = memory["convergence_state"]["active_path"]
    candidates = memory["convergence_state"]["candidate_paths"]
    taken = set(memory["active_paths"].values())
    available = [p for p in candidates if p not in taken and p != current]
    if not available:
        # All paths exhausted — flag for coordinator attention
        memory["convergence_state"]["stop_reason"] = "all candidate paths exhausted"
        return False
    next_path = available[0]
    # release current, claim next
    for agent, path in list(memory["active_paths"].items()):
        if path == current:
            del memory["active_paths"][agent]
            memory["active_paths"][agent] = next_path
            memory["convergence_state"]["active_path"] = next_path
            memory["convergence_state"]["failed_attempts_on_active_path"] = 0
            memory["decision_log"].append({
                "at": now_iso(),
                "by": agent,
                "decision": f"switched path {current} -> {next_path}",
                "reason": f"{path_switch_threshold} failed attempts on {current}"
            })
            break
    return True
```

---

## §14. Failed-Attempt Accounting

Failed attempts are first-class data, not noise to be discarded. The `failed_attempts` array lets agents avoid repeating dead ends.

```json
{
  "failed_attempts": [
    {
      "attempt_id": "ATT-001",
      "by_agent": "A",
      "hypothesis": "H-001",
      "input_shape": "integer overflow probe with size = 2^31",
      "action": "ran harness with INT32_MAX input",
      "yielded_new_evidence": false,
      "ended_at": "2026-07-03T10:18:00Z"
    },
    {
      "attempt_id": "ATT-002",
      "by_agent": "A",
      "hypothesis": "H-001",
      "input_shape": "integer overflow probe with size = 2^32",
      "action": "ran harness with UINT32_MAX input",
      "yielded_new_evidence": false,
      "ended_at": "2026-07-03T10:20:00Z"
    },
    {
      "attempt_id": "ATT-003",
      "by_agent": "A",
      "hypothesis": "H-001",
      "input_shape": "integer overflow probe with size = 2^33",
      "action": "ran harness with 2^33 input",
      "yielded_new_evidence": false,
      "ended_at": "2026-07-03T10:22:00Z"
    }
  ]
}
```

After 3 failed attempts on H-001, the convergence rule fires a path switch. The `failed_attempts` entries are not deleted — they remain as a permanent record of what was tried. A future agent (or a future engagement) can query `failed_attempts` before trying a similar approach.

---

## §15. Path-Switch Trigger Logic

The path-switch trigger fires when `failed_attempts_on_active_path >= path_switch_threshold`. The threshold is typically 3, but can be tuned per engagement.

```bash
# Detect path-switch trigger condition
MEM=/runs/SCEN-007/mem/exploit-attempt-memory.json

jq -r '
  .convergence_state.failed_attempts_on_active_path as $n
  | .convergence_state.path_switch_threshold as $t
  | if $n >= $t then
      "PATH_SWITCH_TRIGGER: \($n) failed attempts (threshold \($t)) on \(.convergence_state.active_path)"
    else
      "OK: \($n)/\($t) failed attempts"
    end
' "$MEM"
```

**Tuning the threshold**:
- 3 (default) — balances thoroughness vs. progress; standard for exploit-dev
- 5 — for harder bug classes (heap-UAF, race conditions); more patience per path
- 2 — for time-boxed engagements where rapid pivoting is preferred
- 1 — essentially disables path retry; only use for trivial bug classes

---

## §16. Convergence Event Emission (multi-agent independent arrival → CONFIRMED)

The convergence event is the highest-leverage pattern in this skill. It says: **if 2+ agents independently arrive at the same hypothesis, that hypothesis is CONFIRMED** — not by majority vote, but by independent evidence vectors corroborating.

```bash
# Convergence detector — run by coordinator at each sync point
MEM=/runs/SCEN-007/mem/exploit-attempt-memory.json

# Find pairs of hypotheses pointing at same path with different claimed_by
CONVERGED=$(jq -r '
  [.vulnerability_hypotheses[] | select(.status != "INVALIDATED")] as $h
  | ($h | group_by(.path) | map(select(length >= 2))) as $groups
  | $groups | map(
      . as $g
      | {
          path: $g[0].path,
          agents: ($g | map(.claimed_by) | flatten | unique),
          hypothesis_ids: ($g | map(.id))
        }
    ) | select(.agents | length >= 2)
' "$MEM")

if [ -n "$CONVERGED" ] && [ "$CONVERGED" != "null" ]; then
  echo "[CONVERGENCE DETECTED]"
  echo "$CONVERGED"

  # Promote matching hypotheses to CONFIRMED under lock
  (
    flock -x -w 30 9 || exit 1
    tmp=$(mktemp -p "$(dirname "$MEM")")
    jq --arg now "$(date -u +%FT%TZ)" \
      '
       .vulnerability_hypotheses |= map(
         . as $h
         | if ($groups | any(.hypothesis_ids | index($h.id))) then
             .status = "CONFIRMED"
             | .confidence = ((.confidence + 0.30) | min(1.0))
             | .convergence_events += [{"at": $now, "agents": ..., "reason": "multi-agent independent arrival"}]
           else . end
       )
       | .memory_lock.version += 1
       | .decision_log += [{"at": $now, "by": "coordinator", "decision": "convergence event", ...}]
      ' "$MEM" > "$tmp"
    mv "$tmp" "$MEM"
  ) 9>"$MEM.lock"
fi
```

The confidence bump (typically +0.30) is the convergence reward — independent corroboration is strong evidence.

---

## §17. Anti-Pattern 1: Free-Form Exploration (detection & prevention)

**Pattern**: agent runs commands without reading memory first. Output: a `decision_log` entry with no corresponding `memory_lock.last_read_at`.

**Detection**:

```python
# detect_free_form_exploration.py
import json, sys
mem = json.load(open(sys.argv[1]))
last_read = mem.get("memory_lock", {}).get("last_read_at")
last_write = mem.get("memory_lock", {}).get("last_write_at")
if last_write and not last_read:
    print("AP-1 free-form exploration: write attempted without prior read")
    sys.exit(1)
```

**Prevention**: the atomic-write pattern (§8) requires the agent to read `memory_lock.version` before computing the delta. The schema validation step can additionally require that `last_read_at` is set within the last 60 seconds before any write.

```bash
# Schema validation rule
jq -e '
  .memory_lock.last_write_at as $w
  | .memory_lock.last_read_at as $r
  | ($w == null) or ($r != null and ($w < $r or ($w | fromdateiso8601) - ($r | fromdateiso8601) < 60))
' "$MEM" || echo "AP-1 fail"
```

---

## §18. Anti-Pattern 2: Memory Drift (散文 instead of field updates)

**Pattern**: agent writes a prose finding to `decision_log` ("found a suspicious function in parser.c") without adding a corresponding entry to `findings` or `vulnerability_hypotheses`. The decision log drifts from the structured state.

**Detection**:

```python
# detect_memory_drift.py
import json, sys, re
mem = json.load(open(sys.argv[1]))
findings_keys = set()
for f in mem.get("findings", {}).get("entry_points", []):
    findings_keys.add(f.get("target"))
for h in mem.get("vulnerability_hypotheses", []):
    findings_keys.add(h.get("id"))
    findings_keys.add(h.get("path"))

for entry in mem.get("decision_log", []):
    ref = entry.get("finding_ref")
    if ref and ref not in findings_keys:
        print(f"AP-2 memory drift: decision_log references {ref} not in findings")
        sys.exit(1)
```

**Prevention**: enforce a schema rule that `decision_log[].finding_ref` (if present) must be a valid key in `findings` or `vulnerability_hypotheses`. Reject writes that violate this.

---

## §19. Anti-Pattern 3: Repeat-Without-Delta (3+ same-hypothesis no-evidence)

**Pattern**: agent runs the same probe (with minor variations) 3+ times against the same hypothesis without producing new evidence. Each iteration writes a `failed_attempt` but no `evidence_for` or `evidence_against` delta.

**Detection**:

```python
# detect_repeat_without_delta.py
import json, sys
from collections import Counter
mem = json.load(open(sys.argv[1]))
fails = Counter(f.get("hypothesis") for f in mem.get("failed_attempts", []))
for hyp, n in fails.items():
    if n >= 3:
        # Check if any evidence was added after the first failed attempt
        h_obj = next((h for h in mem["vulnerability_hypotheses"] if h["id"] == hyp), None)
        if h_obj:
            ev_count = len(h_obj.get("evidence_for", [])) + len(h_obj.get("evidence_against", []))
            if ev_count == 0:
                print(f"AP-3 repeat-without-delta: {n} failed attempts on {hyp}, zero evidence")
                sys.exit(1)
```

**Prevention**: the convergence rule (§13) automatically triggers a path switch after 3 failed attempts. The detection above is the early-warning — it catches the pattern before the third attempt fires the auto-switch.

---

## §20. Anti-Pattern 4: Path-Claim Deadlock (two agents grab same path)

**Pattern**: agent A claims `patch-diff`; agent B also claims `patch-diff` (because it read memory before A's write landed). Memory ends up with `active_paths: {A: patch-diff, B: patch-diff}`.

**Detection**:

```bash
# Inline check (runs inside the atomic-write pattern)
jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$tmp" \
  >/dev/null || { echo "AP-4 path-claim deadlock"; rm "$tmp"; exit 4; }
```

**Prevention**: the duplicate-check runs *before* `mv` in every claim. If it fails, the second agent's claim is rejected; the agent falls back to its secondary path or waits.

---

## §21. Anti-Pattern 5: Premature Stop (no differential verification)

**Pattern**: agent claims `stop_condition_met = true` but `verification_results.vulnerable` or `verification_results.patched` is null. The agent is declaring victory without proof.

**Detection**:

```bash
# Inline check
jq -e '
  .convergence_state.stop_condition_met // false
  | if . then
      (.verification_results.vulnerable != null and .verification_results.patched != null)
    else true end
' "$tmp" >/dev/null || { echo "AP-5 premature stop"; rm "$tmp"; exit 5; }
```

**Prevention**: the schema rule is hard — no write that sets `stop_condition_met = true` is allowed to leave verification_results incomplete. The agent must run differential verification first, populate the results, then set the flag.

---

## §22. Topology Selection Matrix (parallel-explorers / pipeline / council / hierarchical)

Choosing the right topology for a task is the Layer 5 decision. The matrix:

| Topology | When to use | When NOT to use | Sync overhead | Failure mode |
|----------|-------------|-----------------|---------------|--------------|
| **Parallel-explorers** (SCEN-007) | Bug-class exploration, multiple independent directions on one target | Phase-sequential work, single-direction tasks | Low (sync at end) | Wasted parallelism if directions aren't truly independent |
| **Pipeline** (phase-sequential) | recon → exploit → report, clear phase dependencies | Open-ended exploration, judgment-heavy tasks | Medium (handoff at each phase) | Bottleneck at slowest phase |
| **Council** (multi-perspective) | Same question, multiple lenses (Attack/Defense/Audit) | Single-direction tasks, clear answers | High (deliberation overhead) | Groupthink, false consensus |
| **Hierarchical** (coordinator-worker) | Dynamic dependencies, shifting scope, N specialists | Small engagements, clear topologies | Medium-high | Coordinator overload, single-point-of-failure |
| **Single-agent** (autonomous-loops) | Linear, simple, or highly judgmental tasks | Anything that benefits from parallelism | None | Slow, no convergence benefit |

**Selection rule of thumb**:

```
if task.bug_class_exploration and task.has_multiple_independent_directions:
    use parallel-explorers
elif task.phase_sequential and task.clear_handoffs:
    use pipeline
elif task.judgment_heavy and task.benefits_from_multiple_lenses:
    use council
elif task.scope_dynamic and task.specialist_count >= 3:
    use hierarchical
else:
    use single-agent autonomous-loops
```

---

## §23. Coordinator-vs-Peer Protocol Tradeoffs

Two coordination models: **coordinator-worker** (one orchestrator dispatches tasks, aggregates results) vs. **peer-to-peer** (agents coordinate via shared memory, no central authority).

| Aspect | Coordinator-worker | Peer-to-peer |
|--------|--------------------|--------------|
| Reasoning complexity | Centralized in coordinator — easy to inspect | Distributed — harder to follow |
| Single-point-of-failure | Yes — coordinator crash halts everything | No — agents continue independently |
| Bottleneck | Coordinator can be overwhelmed by worker count | No bottleneck |
| Schema complexity | Simple — coordinator owns the master schema | Complex — agents must agree on schema |
| Convergence detection | Easy — coordinator scans memory | Harder — needs an external observer or rotating leader |
| Best for | Dynamic engagements, shifting scope | Stable, well-known task patterns |

**kali-claw default**: coordinator-worker for most engagements (simpler reasoning, clearer audit trail). Peer-to-peer only for very large N (>10 agents) where coordinator overload becomes real.

---

## §24. Sync-Point Cadence (every N iterations vs event-driven)

When should agents pause for convergence review?

| Cadence | Pros | Cons |
|---------|------|------|
| Every N iterations (N=5) | Predictable, easy to schedule | May be too frequent (wasted syncs) or too rare (missed convergence) |
| Event-driven (on each new hypothesis) | Tight feedback, fast convergence | High sync overhead, can starve workers |
| Wall-clock (every 5 min) | Predictable for humans | Decoupled from agent progress — may sync with nothing new |
| Hybrid (every N OR every M minutes, whichever first) | Balances | Slightly more complex to implement |

**kali-claw default**: hybrid — every 5 iterations OR every 5 minutes, whichever first. The sync point runs the convergence detector and the anti-pattern checker. If either fires, the coordinator takes action.

---

## §25. Decision Log Append Pattern

The `decision_log` is an append-only audit trail of every meaningful decision. Append-only is critical — never edit or delete entries.

```bash
# Append a decision (under atomic-write lock)
append_decision() {
  local mem="$1" agent="$2" decision="$3" reason="${4:-}"
  (
    flock -x -w 30 9 || exit 1
    tmp=$(mktemp -p "$(dirname "$mem")")
    jq --arg agent "$agent" --arg decision "$decision" --arg reason "$reason" \
       --arg now "$(date -u +%FT%TZ)" \
      '.decision_log += [{
          "at": $now,
          "by": $agent,
          "decision": $decision,
          "reason": $reason
        }]
       | .memory_lock.version += 1
       | .memory_lock.last_write_at = $now
       | .memory_lock.last_write_by = $agent
      ' "$mem" > "$tmp"
    mv "$tmp" "$mem"
  ) 9>"$mem.lock"
}
```

**What goes in the decision log**:
- Path claims and releases
- Hypothesis additions and status changes
- Convergence events
- Path switches (with reason)
- Stop condition triggers (with verification log path)
- Coordinator interventions

**What does NOT go in the decision log**:
- Raw tool output (that's `evidence_index` with sha256)
- Hypothesis details (those are `vulnerability_hypotheses`)
- Failed attempt details (those are `failed_attempts`)

The decision log is the *narrative* — every other collection is the *state*.

---

## §26. Evidence Index with sha256

Every piece of evidence (tool output, screenshot, packet capture, etc.) gets an entry in `evidence_index` with a sha256 hash.

```json
{
  "evidence_index": {
    "nmap-01.txt": {
      "collected_at": "2026-07-03T09:15:00Z",
      "phase": "recon",
      "sha256": "a3f5b8...",
      "collected_by": "recon-agent",
      "tool": "nmap",
      "tool_version": "7.95",
      "tool_command": "nmap -sV -p- example.com"
    },
    "asan-trace-001.txt": {
      "collected_at": "2026-07-03T10:25:00Z",
      "phase": "exploit-dev",
      "sha256": "b7c9d2...",
      "collected_by": "sanitizer-agent",
      "tool": "harness",
      "tool_command": "/runs/SCEN-007/B/harness input-001"
    }
  }
}
```

**Why sha256**: lets the report author or auditor verify that the evidence referenced by a finding is the same evidence that was collected. If a file is tampered with, the hash changes and the report's chain-of-custody is broken.

```bash
# Verify evidence integrity
for f in evidence/*.txt; do
  echo "$(sha256sum "$f" | cut -d' ' -f1)  $f"
done > evidence.sha256

# Cross-check against memory
jq -r '.evidence_index | to_entries[] | "\(.value.sha256)  \(.key)"' "$MEM" | sort > memory.sha256
diff evidence.sha256 memory.sha256
```

---

## §27. Time-Budget Tracking in next_constraints

Time is a first-class constraint. The `next_constraints.time_budget_remaining_hours` field lets downstream phases know how much wall-clock is left.

```json
{
  "next_constraints": {
    "must_explore": ["web.example.com:443/api"],
    "must_avoid": ["10.0.0.1", "production-db"],
    "time_budget_remaining_hours": 4.5,
    "time_budget_updated_at": "2026-07-03T11:30:00Z"
  }
}
```

The coordinator updates `time_budget_remaining_hours` at each sync point:

```python
def update_time_budget(mem):
    elapsed = (now() - parse_iso(mem["next_constraints"]["time_budget_updated_at"])).total_seconds() / 3600
    mem["next_constraints"]["time_budget_remaining_hours"] -= elapsed
    mem["next_constraints"]["time_budget_updated_at"] = now_iso()
    if mem["next_constraints"]["time_budget_remaining_hours"] <= 0:
        mem["convergence_state"]["stop_reason"] = "time budget exhausted"
        mem["convergence_state"]["stop_condition_met"] = True
```

---

## §28. Open-Questions Queue Management

Not every uncertainty becomes a hypothesis. Some become *open questions* — things the agent noticed but cannot yet act on.

```json
{
  "open_questions": [
    {
      "id": "Q-001",
      "question": "Is the API at /api/v2/ reachable without authentication?",
      "raised_at": "2026-07-03T10:00:00Z",
      "raised_by": "recon-agent",
      "status": "OPEN",
      "priority": "MEDIUM",
      "related_to": null
    },
    {
      "id": "Q-002",
      "question": "Does the WAF log SQLi probes? (need blue-team confirmation)",
      "raised_at": "2026-07-03T10:15:00Z",
      "raised_by": "intrusion-agent",
      "status": "ESCALATED",
      "priority": "HIGH",
      "related_to": "finding-F-003"
    }
  ]
}
```

Open questions should be resolved (closed) before the engagement closes. The coordinator sweeps the queue at each sync point and either resolves each question (with a finding reference) or escalates it.

---

## §29. Multi-Agent Harness Scaffolding (3-agent dispatcher script)

A complete coordinator script for a 3-agent exploit-dev engagement:

```bash
#!/usr/bin/env bash
# dispatcher.sh — bootstrap memory, dispatch 3 agents, aggregate
set -euo pipefail

RUN_DIR=/runs/SCEN-007
MEM="$RUN_DIR/mem/exploit-attempt-memory.json"

mkdir -p "$RUN_DIR/mem"

# Phase 0: bootstrap memory if absent
if [ ! -f "$MEM" ]; then
  cat > "$MEM" <<'JSON'
{
  "schema_version": "1.0",
  "target": { /* ... */ },
  "memory_lock": { "version": 0, "owner_agents": [], "last_write_at": null, "last_write_by": null },
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
fi

# Phase 1: dispatch agents in parallel
python3 agents/patch_diff_agent.py  --mem "$MEM" --id A > "$RUN_DIR/A.log" 2>&1 &
PID_A=$!
python3 agents/harness_entry_agent.py --mem "$MEM" --id B > "$RUN_DIR/B.log" 2>&1 &
PID_B=$!
python3 agents/sanitizer_agent.py   --mem "$MEM" --id C > "$RUN_DIR/C.log" 2>&1 &
PID_C=$!

# Phase 2: coordinator sync loop
while true; do
  if jq -e '.convergence_state.stop_condition_met' "$MEM" >/dev/null; then
    echo "[coordinator] stop condition met, signaling agents to halt"
    kill -TERM "$PID_A" "$PID_B" "$PID_C" 2>/dev/null || true
    break
  fi
  # Run sync-point convergence detection
  bash lib/convergence_detector.sh "$MEM" || true
  # Run anti-pattern check
  python3 lib/anti_pattern_check.py "$MEM" || true
  sleep 60
done

wait "$PID_A" "$PID_B" "$PID_C" 2>/dev/null || true

# Phase 3: aggregate
echo "[coordinator] final state:"
jq '{
  hypotheses: .vulnerability_hypotheses | length,
  confirmed: [.vulnerability_hypotheses[] | select(.status == "CONFIRMED") | .id],
  pocs: .candidate_pocs | length,
  iterations: .convergence_state.iterations
}' "$MEM"
```

---

## §30. Convergence Detection Script (Python)

```python
#!/usr/bin/env python3
# convergence_detector.py
import json, sys, subprocess
from datetime import datetime

def detect_convergence(mem_path):
    mem = json.load(open(mem_path))
    hypotheses = [h for h in mem["vulnerability_hypotheses"] if h["status"] != "INVALIDATED"]
    # Group by path
    by_path = {}
    for h in hypotheses:
        by_path.setdefault(h["path"], []).append(h)
    # Find convergence candidates
    events = []
    for path, group in by_path.items():
        if len(group) >= 2:
            agents = sorted(set(a for h in group for a in h.get("claimed_by", [])))
            if len(agents) >= 2:
                events.append({
                    "path": path,
                    "agents": agents,
                    "hypothesis_ids": [h["id"] for h in group]
                })
    return events

def promote_convergence(mem_path, events):
    """Promote converged hypotheses to CONFIRMED. Run under flock."""
    if not events:
        return
    # Acquire flock (port of the bash pattern)
    lock_path = mem_path + ".lock"
    import fcntl
    lock = open(lock_path, "w")
    fcntl.flock(lock, fcntl.LOCK_EX)
    try:
        mem = json.load(open(mem_path))
        now = datetime.utcnow().isoformat() + "Z"
        for event in events:
            for h in mem["vulnerability_hypotheses"]:
                if h["id"] in event["hypothesis_ids"] and h["status"] != "CONFIRMED":
                    h["status"] = "CONFIRMED"
                    h["confidence"] = min(1.0, h.get("confidence", 0.5) + 0.30)
                    h.setdefault("convergence_events", []).append({
                        "at": now,
                        "agents": event["agents"],
                        "reason": "multi-agent independent arrival"
                    })
            mem["decision_log"].append({
                "at": now,
                "by": "coordinator",
                "decision": f"CONVERGENCE on {event['path']}",
                "reason": f"agents {event['agents']} independently arrived"
            })
        mem["memory_lock"]["version"] += 1
        mem["memory_lock"]["last_write_at"] = now
        mem["memory_lock"]["last_write_by"] = "coordinator"
        tmp = mem_path + ".tmp"
        json.dump(mem, open(tmp, "w"), indent=2)
        import os
        os.rename(tmp, mem_path)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)

if __name__ == "__main__":
    events = detect_convergence(sys.argv[1])
    if events:
        print(f"[convergence] {len(events)} events detected")
        for e in events:
            print(f"  {e}")
        promote_convergence(sys.argv[1], events)
```

---

## §31. Anti-Pattern Checker (jq or Python)

A single script that runs all five anti-pattern checks:

```python
#!/usr/bin/env python3
# anti_pattern_check.py
import json, sys
from collections import Counter

def check(mem):
    violations = []

    # AP-1 free-form exploration
    ml = mem.get("memory_lock", {})
    if ml.get("last_write_at") and not ml.get("last_read_at"):
        violations.append("AP-1 free-form exploration: write without prior read")

    # AP-2 memory drift
    findings_keys = set()
    for f in mem.get("findings", {}).get("entry_points", []):
        findings_keys.add(f.get("target"))
    for h in mem.get("vulnerability_hypotheses", []):
        findings_keys.add(h.get("id"))
        findings_keys.add(h.get("path"))
    for entry in mem.get("decision_log", []):
        ref = entry.get("finding_ref")
        if ref and ref not in findings_keys:
            violations.append(f"AP-2 memory drift: decision_log ref {ref} not in findings")

    # AP-3 repeat-without-delta
    fails = Counter(f.get("hypothesis") for f in mem.get("failed_attempts", []))
    for hyp, n in fails.items():
        if n >= 3:
            h = next((h for h in mem["vulnerability_hypotheses"] if h["id"] == hyp), None)
            if h and not h.get("evidence_for") and not h.get("evidence_against"):
                violations.append(f"AP-3 repeat-without-delta: {n} fails on {hyp}, zero evidence")

    # AP-4 path-claim deadlock
    paths = list(mem.get("active_paths", {}).values())
    if len(paths) != len(set(paths)):
        violations.append(f"AP-4 path-claim deadlock: {paths}")

    # AP-5 premature stop
    cs = mem.get("convergence_state", {})
    vr = mem.get("verification_results", {})
    if cs.get("stop_condition_met") and (not vr.get("vulnerable") or not vr.get("patched")):
        violations.append("AP-5 premature stop without differential verification")

    return violations

if __name__ == "__main__":
    mem = json.load(open(sys.argv[1]))
    v = check(mem)
    if v:
        print("[ANTI-PATTERN]", "; ".join(v))
        sys.exit(1)
    print("[OK] no anti-patterns")
```

---

## §32. Memory Visualization (graph / timeline / hash-diff)

Three useful visualizations:

**Timeline** — render `decision_log` as wall-clock events:

```python
# timeline.py
import json, sys
from datetime import datetime
mem = json.load(open(sys.argv[1]))
for e in mem["decision_log"]:
    t = datetime.fromisoformat(e["at"].replace("Z", "+00:00"))
    print(f"{t.strftime('%H:%M:%S')}  [{e.get('by', '?')}]  {e.get('decision', '')}")
```

**Graph** — render `vulnerability_hypotheses` and `evidence_for` as a DAG (Graphviz):

```bash
MEM=/runs/SCEN-007/mem/exploit-attempt-memory.json
{
  echo "digraph G {"
  jq -r '.vulnerability_hypotheses[] | "  \"\(.id)\" [label=\"\(.id): \(.hypothesis | .[0:40])...\"];"' "$MEM"
  jq -r '.vulnerability_hypotheses[] | . as $h | $h.evidence_for[]? | "  \"\(. | gsub("\""; "'"))\" -> \"\($h.id)\";"' "$MEM"
  echo "}"
} | dot -Tsvg > hypotheses.svg
```

**Hash-diff** — show what changed between two memory versions:

```bash
# Compare two snapshots
jq -S . mem.v5.json > /tmp/v5.normalized
jq -S . mem.v6.json > /tmp/v6.normalized
diff /tmp/v5.normalized /tmp/v6.normalized
```

---

## §33. Schema Versioning & Migration

Schemas evolve. The `schema_version` field is the migration key.

```json
{
  "schema_version": "1.1",
  "schema_history": [
    {"from": "1.0", "to": "1.1", "migrated_at": "2026-09-01T00:00:00Z", "migration_script": "migrations/1.0_to_1.1.py"}
  ]
}
```

The migration script:

```python
# migrations/1.0_to_1.1.py
import json, sys

def migrate(mem):
    assert mem["schema_version"] == "1.0"
    # 1.0 -> 1.1: rename 'confidence_score' to 'confidence'
    for h in mem.get("vulnerability_hypotheses", []):
        if "confidence_score" in h:
            h["confidence"] = h.pop("confidence_score")
    mem["schema_version"] = "1.1"
    return mem

if __name__ == "__main__":
    mem = json.load(open(sys.argv[1]))
    migrated = migrate(mem)
    json.dump(migrated, open(sys.argv[1], "w"), indent=2)
```

**Policy**: migrations are *forward-only*. Never downgrade. Always back up the pre-migration file: `cp mem.json mem.v1.0.json` before running a migration.

---

## §34. Memory Compaction (long-engagement pruning)

After many iterations, the memory file grows large. Compaction prunes low-value entries while preserving the audit trail.

```python
# compact.py
import json, sys
from datetime import datetime, timedelta

def compact(mem, max_age_days=30, max_failed_attempts=10):
    cutoff = (datetime.utcnow() - timedelta(days=max_age_days)).isoformat() + "Z"

    # Drop INVALIDATED hypotheses older than cutoff
    mem["vulnerability_hypotheses"] = [
        h for h in mem["vulnerability_hypotheses"]
        if not (h["status"] == "INVALIDATED" and h.get("created_at", "") < cutoff)
    ]

    # Keep only the most recent N failed attempts per hypothesis
    by_hyp = {}
    for f in mem.get("failed_attempts", []):
        by_hyp.setdefault(f["hypothesis"], []).append(f)
    for hyp, attempts in by_hyp.items():
        attempts.sort(key=lambda x: x.get("ended_at", ""), reverse=True)
        by_hyp[hyp] = attempts[:max_failed_attempts]
    mem["failed_attempts"] = [a for attempts in by_hyp.values() for a in attempts]

    # Decision log: keep all (append-only invariant)
    return mem
```

**Policy**: never compact a memory file mid-engagement. Compaction runs *after* engagement close, before archiving.

---

## §35. Cross-Engagement Memory Federation (kali-claw MEMORY.md × engagement JSON)

The structured JSON memory does not replace kali-claw's prose `MEMORY.md`. It runs alongside. The federation rule:

1. **During engagement**: write to JSON memory. Prose log is secondary.
2. **At engagement close**: distill JSON memory into prose paragraph, append to `MEMORY.md`.
3. **Long-term**: `MEMORY.md` carries forward the lessons; JSON memory is archived to `bak/`.

```python
# federation_distill.py — distill engagement JSON into MEMORY.md prose
import json, sys

def distill(mem_path):
    mem = json.load(open(mem_path))
    lines = []
    lines.append(f"## Engagement {mem['engagement_id']} (distilled {mem.get('schema_version', '?')})\n")
    lines.append(f"**Target**: {mem.get('target', {}).get('binary', mem.get('scope', {}).get('targets', '?'))}\n")
    lines.append(f"**Status**: {mem['convergence_state'].get('stop_reason', 'in-progress')}\n")

    confirmed = [h for h in mem.get("vulnerability_hypotheses", []) if h["status"] == "CONFIRMED"]
    if confirmed:
        lines.append("**Confirmed findings**:\n")
        for h in confirmed:
            lines.append(f"- {h['id']}: {h['hypothesis']} (path: {h['path']}, confidence: {h['confidence']})\n")

    failed_paths = [f for f in mem.get("failed_attempts", [])]
    if failed_paths:
        lines.append(f"\n**Tried and failed**: {len(failed_paths)} attempts across {len(set(f['hypothesis'] for f in failed_paths))} hypotheses\n")

    lessons = mem.get("lessons_learned", [])
    if lessons:
        lines.append("\n**Lessons**:\n")
        for l in lessons:
            lines.append(f"- {l}\n")

    return "".join(lines)

if __name__ == "__main__":
    prose = distill(sys.argv[1])
    # Append to MEMORY.md
    with open("MEMORY.md", "a") as f:
        f.write("\n" + prose)
```

This pattern mirrors kali-claw's existing `memory/YYYY-MM-DD.md` → `MEMORY.md` distillation, but at engagement granularity instead of daily.

---

## §36. Worked Examples — Common One-Liners & Templates

A grab-bag of copy-paste-runnable snippets for everyday runtime engineering operations. Use these as the building blocks of any custom harness.

### §36.1 Bootstrap an empty memory file

```bash
#!/usr/bin/env bash
set -euo pipefail
MEM="$1"
mkdir -p "$(dirname "$MEM")"
cat > "$MEM" <<'JSON'
{
  "schema_version": "1.0",
  "memory_lock": {"version": 0, "owner_agents": [], "last_read_at": null, "last_write_at": null, "last_write_by": null},
  "vulnerability_hypotheses": [],
  "candidate_pocs": [],
  "failed_attempts": [],
  "active_paths": {},
  "convergence_state": {"iterations": 0, "stop_condition_met": false, "stop_reason": null},
  "decision_log": []
}
JSON
echo "[bootstrap] $MEM"
```

### §36.2 Read current memory under shared lock

```bash
(
  flock -s -w 10 9 || exit 1
  jq '.' "$MEM"
) 9>"$MEM.lock"
```

### §36.3 Atomic write helper (Bash function)

```bash
write_memory() {
  local mem="$1" agent="$2" jq_expr="$3"
  (
    flock -x -w 30 9 || { echo "[fatal] lock timeout"; exit 1; }
    local pre; pre=$(jq '.memory_lock.version' "$mem")
    local tmp; tmp=$(mktemp -p "$(dirname "$mem")")
    jq --arg agent "$agent" --argjson pre "$pre" "$jq_expr" "$mem" > "$tmp" \
      || { rm "$tmp"; exit 2; }
    local post; post=$(jq '.memory_lock.version' "$tmp")
    [ "$post" -eq "$((pre + 1))" ] || { echo "[conflict]"; rm "$tmp"; exit 3; }
    mv "$tmp" "$mem"
  ) 9>"$mem.lock"
}
```

### §36.4 Atomic write helper (Python)

```python
import json, os, fcntl, tempfile, subprocess

def atomic_write_delta(mem_path, agent, delta_fn):
    """Apply delta_fn(memory_dict) -> new_memory_dict atomically."""
    lock_path = mem_path + ".lock"
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with open(mem_path) as f:
            mem = json.load(f)
        pre_version = mem["memory_lock"]["version"]
        new_mem = delta_fn(mem)
        assert new_mem["memory_lock"]["version"] == pre_version + 1, "version must increment by 1"
        # validate
        paths = list(new_mem.get("active_paths", {}).values())
        assert len(paths) == len(set(paths)), "AP-4 deadlock"
        # write atomically
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(mem_path))
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(new_mem, f, indent=2)
            os.rename(tmp_path, mem_path)
        except:
            os.unlink(tmp_path); raise
```

### §36.5 Append a hypothesis

```bash
HYP_ID=H-A-001
HYP_PATH="parser.c:412"
HYP_TEXT="heap-buffer-overflow in parse()"
EVIDENCE='["BinDiff: changed function"]'

write_memory "$MEM" "agent-A" "
  .vulnerability_hypotheses += [{
    \"id\": \"$HYP_ID\",
    \"hypothesis\": \"$HYP_TEXT\",
    \"path\": \"$HYP_PATH\",
    \"evidence_for\": $EVIDENCE,
    \"evidence_against\": [],
    \"status\": \"LIKELY\",
    \"confidence\": 0.55,
    \"claimed_by\": [\"agent-A\"],
    \"created_at\": (now | todateiso8601)
  }]
  | .memory_lock.version = (\$prever + 1)
  | .memory_lock.last_write_at = (now | todateiso8601)
  | .memory_lock.last_write_by = \$agent
  | .decision_log += [{\"at\": (now | todateiso8601), \"by\": \$agent,
                       \"decision\": \"added $HYP_ID\"}]
"
```

### §36.6 Append a failed attempt

```bash
HYP_ID=H-A-001
ATTTEMPT_ID=ATT-007
INPUT='integer overflow probe'

write_memory "$MEM" "agent-A" "
  .failed_attempts += [{
    \"attempt_id\": \"$ATTTEMPT_ID\",
    \"by_agent\": \"agent-A\",
    \"hypothesis\": \"$HYP_ID\",
    \"input_shape\": \"$INPUT\",
    \"yielded_new_evidence\": false,
    \"ended_at\": (now | todateiso8601)
  }]
  | .memory_lock.version = (\$prever + 1)
  | .convergence_state.failed_attempts_on_active_path += 1
  | .decision_log += [{\"at\": (now | todateiso8601), \"by\": \$agent,
                       \"decision\": \"failed attempt $ATTTEMPT_ID\"}]
"
```

### §36.7 Detect convergence (jq)

```bash
jq -r '
  [.vulnerability_hypotheses[] | select(.status != "INVALIDATED")] as $h
  | ($h | group_by(.path) | map(select(length >= 2)) | map(map(.claimed_by) | flatten | unique | length >= 2) | any) as $conv
  | if $conv then "CONVERGENCE" else "no convergence" end
' "$MEM"
```

### §36.8 Promote converged hypotheses (Python)

```python
def promote_converged(mem):
    hyps = [h for h in mem["vulnerability_hypotheses"] if h["status"] != "INVALIDATED"]
    by_path = {}
    for h in hyps:
        by_path.setdefault(h["path"], []).append(h)
    for path, group in by_path.items():
        if len(group) >= 2:
            agents = sorted({a for h in group for a in h.get("claimed_by", [])})
            if len(agents) >= 2:
                for h in group:
                    h["status"] = "CONFIRMED"
                    h["confidence"] = min(1.0, h.get("confidence", 0.5) + 0.30)
    return mem
```

### §36.9 Add evidence to an existing hypothesis

```bash
HYP_ID=H-A-001
NEW_EVIDENCE='["ASan trace: heap-buffer-overflow at line 412"]'

write_memory "$MEM" "agent-C" "
  .vulnerability_hypotheses |= map(
    if .id == \"$HYP_ID\" then
      .evidence_for += $NEW_EVIDENCE
      | .confidence = ((.confidence + 0.15) | min(1.0))
      | .claimed_by += [\"agent-C\"] | .claimed_by |= unique
    else . end
  )
  | .memory_lock.version = (\$prever + 1)
  | .decision_log += [{\"at\": (now | todateiso8601), \"by\": \$agent,
                       \"decision\": \"added evidence to $HYP_ID\"}]
"
```

### §36.10 Path switch (release current, claim next)

```bash
AGENT_ID=agent-A
OLD_PATH=patch-diff
NEW_PATH=boundary-condition

write_memory "$MEM" "$AGENT_ID" "
  del(.active_paths[\"$AGENT_ID\"])
  | .active_paths[\"$AGENT_ID\"] = \"$NEW_PATH\"
  | .convergence_state.active_path = \"$NEW_PATH\"
  | .convergence_state.failed_attempts_on_active_path = 0
  | .memory_lock.version = (\$prever + 1)
  | .decision_log += [{
      \"at\": (now | todateiso8601), \"by\": \$agent,
      \"decision\": \"switched path $OLD_PATH -> $NEW_PATH\",
      \"reason\": \"3 failed attempts on $OLD_PATH\"
    }]
"
```

### §36.11 Run differential verification

```bash
POC=/runs/SCEN-007/poc.bin
VULN=/targets/libpng-1.6.37/build/png_read_asan
PATCHED=/targets/libpng-1.6.38/build/png_read_asan

ASAN_OPTIONS=detect_leaks=0 "$VULN" < "$POC" > vuln-out.txt 2>&1
ASAN_OPTIONS=detect_leaks=0 "$PATCHED" < "$POC" > patched-out.txt 2>&1

if grep -q "ERROR: AddressSanitizer" vuln-out.txt && \
   ! grep -q "ERROR:" patched-out.txt; then
  echo "[CONFIRMED] differential verification passed"
  VERIFICATION='{"vulnerable":{"crashed":true},"patched":{"crashed":false}}'
  write_memory "$MEM" "verifier" "
    .verification_results = $VERIFICATION
    | .convergence_state.stop_condition_met = true
    | .convergence_state.stop_reason = \"differential verification passed\"
    | .memory_lock.version = (\$prever + 1)
  "
else
  echo "[NOT YET] differential verification failed"
fi
```

### §36.12 Anti-pattern checker (compact one-liner)

```bash
python3 -c "
import json, sys
from collections import Counter
m = json.load(open('$MEM'))
v = []
if m.get('memory_lock',{}).get('last_write_at') and not m.get('memory_lock',{}).get('last_read_at'):
    v.append('AP-1 free-form')
paths = list(m.get('active_paths',{}).values())
if len(paths) != len(set(paths)): v.append('AP-4 deadlock')
cs = m.get('convergence_state',{}); vr = m.get('verification_results',{})
if cs.get('stop_condition_met') and (not vr.get('vulnerable') or not vr.get('patched')):
    v.append('AP-5 premature stop')
fails = Counter(f.get('hypothesis') for f in m.get('failed_attempts',[]))
for h,n in fails.items():
    if n >= 3: v.append(f'AP-3 repeat x{n} on {h}')
print('[OK]' if not v else '[ANTI-PATTERN] ' + '; '.join(v))
"
```

### §36.13 Timeline renderer

```bash
jq -r '.decision_log[] | "\(.at)  [\(.by)]  \(.decision)"' "$MEM"
```

### §36.14 Final-state aggregator

```bash
jq '{
  schema_version,
  hypotheses_count: (.vulnerability_hypotheses | length),
  confirmed: [.vulnerability_hypotheses[] | select(.status == "CONFIRMED") | .id],
  invalidated: [.vulnerability_hypotheses[] | select(.status == "INVALIDATED") | .id],
  pocs_count: (.candidate_pocs | length),
  confirmed_pocs: [.candidate_pocs[] | select(.status == "CONFIRMED") | .id],
  iterations: .convergence_state.iterations,
  stop_reason: .convergence_state.stop_reason,
  final_version: .memory_lock.version
}' "$MEM"
```

### §36.15 Evidence integrity check

```bash
for f in evidence/*.txt; do
  bn=$(basename "$f")
  actual=$(sha256sum "$f" | cut -d' ' -f1)
  expected=$(jq -r --arg f "$bn" '.evidence_index[$f].sha256 // "MISSING"' "$MEM")
  [ "$actual" = "$expected" ] || echo "[MISMATCH] $bn (expected: $expected, got: $actual)"
done
```

### §36.16 Memory compaction

```bash
# Compact in-place (back up first!)
cp "$MEM" "$MEM.bak"
python3 - <<PY "$MEM" >> "$MEM.compact"
import json, sys
from datetime import datetime, timedelta
m = json.load(open(sys.argv[1]))
cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z"
m["vulnerability_hypotheses"] = [
    h for h in m["vulnerability_hypotheses"]
    if not (h["status"] == "INVALIDATED" and h.get("created_at", "") < cutoff)
]
# Keep last 10 failed_attempts per hypothesis
by_hyp = {}
for f in m.get("failed_attempts", []):
    by_hyp.setdefault(f["hypothesis"], []).append(f)
for h, atts in by_hyp.items():
    atts.sort(key=lambda x: x.get("ended_at", ""), reverse=True)
    by_hyp[h] = atts[:10]
m["failed_attempts"] = [a for atts in by_hyp.values() for a in atts]
print(json.dumps(m, indent=2))
PY
mv "$MEM.compact" "$MEM"
```

### §36.17 Engagement-to-MEMORY.md distillation

```bash
python3 - <<'PY' "$MEM" >> MEMORY.md
import json, sys
m = json.load(open(sys.argv[1]))
print(f"\n## Engagement {m.get('engagement_id', '?')} (distilled)\n")
target = m.get('target', {})
print(f"**Target**: {target.get('binary', target.get('cve', '?'))}\n")
confirmed = [h for h in m.get('vulnerability_hypotheses', []) if h['status'] == 'CONFIRMED']
print(f"**Confirmed hypotheses**: {len(confirmed)}\n")
for h in confirmed:
    print(f"- {h['id']}: {h['hypothesis']} (path: {h['path']})\n")
print(f"**Stop reason**: {m['convergence_state'].get('stop_reason', 'in-progress')}\n")
PY
```

### §36.18 Schema validation one-liner

```bash
jq -e '
  (.schema_version != null) and
  (.memory_lock.version != null) and
  (.memory_lock.version | type) == "number" and
  (.vulnerability_hypotheses | type) == "array" and
  (.decision_log | type) == "array" and
  (.convergence_state | type) == "object"
' "$MEM" >/dev/null && echo "[VALID]" || echo "[INVALID]"
```

### §36.19 Coordinator dispatch loop

```bash
#!/usr/bin/env bash
set -euo pipefail
MEM="$1"; RUN_DIR="$(dirname "$MEM")"

python3 agents/agent.py A "$MEM" patch-diff     > "$RUN_DIR/A.log" 2>&1 &
PID_A=$!
python3 agents/agent.py B "$MEM" harness-entry  > "$RUN_DIR/B.log" 2>&1 &
PID_B=$!
python3 agents/agent.py C "$MEM" sanitizer      > "$RUN_DIR/C.log" 2>&1 &
PID_C=$!

while true; do
  if jq -e '.convergence_state.stop_condition_met' "$MEM" >/dev/null; then
    kill -TERM "$PID_A" "$PID_B" "$PID_C" 2>/dev/null || true
    break
  fi
  python3 lib/convergence_detector.py "$MEM" || true
  python3 lib/anti_pattern_check.py "$MEM" >> "$RUN_DIR/anti-pattern.log" 2>&1 || true
  sleep 60
done
wait "$PID_A" "$PID_B" "$PID_C" 2>/dev/null || true
```

### §36.20 Three-agent dispatcher with logging

```bash
dispatch_agents() {
  local mem="$1"; local run_dir="$2"
  local -a pids=()
  for spec in "A:patch-diff" "B:harness-entry" "C:sanitizer"; do
    local "${spec%%:*}_ID"="${spec%%:*}"
    local agent="${spec%%:*}"
    local path="${spec##*:}"
    python3 agents/agent.py "$agent" "$mem" "$path" > "$run_dir/$agent.log" 2>&1 &
    pids+=($!)
  done
  echo "${pids[@]}"
}
```

### §36.21 Quick "what did we try?" query

```bash
# All attempted input shapes per hypothesis
jq -r '
  .failed_attempts | group_by(.hypothesis) | map({
    hypothesis: .[0].hypothesis,
    attempts: length,
    inputs: (map(.input_shape) | unique)
  }) | .[]
' "$MEM"
```

### §36.22 Quick "is anything stuck?" query

```bash
jq -r '
  .convergence_state as $cs
  | "active_path: \($cs.active_path // \"none\")"
  , "failed_attempts: \($cs.failed_attempts_on_active_path)/\($cs.path_switch_threshold)"
  , "stop_condition_met: \($cs.stop_condition_met)"
  , "stop_reason: \($cs.stop_reason // \"none\")"
' "$MEM"
```

### §36.23 Quick "evidence index" query

```bash
jq -r '.evidence_index | to_entries[] | "\(.value.collected_at)  \(.key)  \(.value.sha256[0:8])..."' "$MEM"
```

### §36.24 Schema migration template

```python
#!/usr/bin/env python3
# migrations/1_0_to_1_1.py
import json, sys, shutil
from datetime import datetime

def migrate(mem):
    assert mem["schema_version"] == "1.0", f"expected 1.0, got {mem['schema_version']}"
    # backup
    shutil.copy(sys.argv[1], sys.argv[1] + ".v1.0.bak")
    # rename: confidence_score -> confidence
    for h in mem.get("vulnerability_hypotheses", []):
        if "confidence_score" in h:
            h["confidence"] = h.pop("confidence_score")
    mem["schema_version"] = "1.1"
    mem.setdefault("schema_history", []).append({
        "from": "1.0", "to": "1.1",
        "migrated_at": datetime.utcnow().isoformat() + "Z",
        "migration_script": "migrations/1_0_to_1_1.py"
    })
    return mem

if __name__ == "__main__":
    mem = json.load(open(sys.argv[1]))
    migrated = migrate(mem)
    json.dump(migrated, open(sys.argv[1], "w"), indent=2)
    print(f"[migrated] {sys.argv[1]} -> schema 1.1")
```

### §36.25 Federation distill (full)

```python
def distill(mem_path):
    mem = json.load(open(mem_path))
    lines = []
    lines.append(f"## Engagement {mem.get('engagement_id', mem.get('target', {}).get('cve', '?'))}\n")
    target = mem.get('target', {})
    if target:
        lines.append(f"**Target**: {target.get('binary', target.get('cve', '?'))}\n")
    lines.append(f"**Status**: {mem.get('convergence_state', {}).get('stop_reason', 'in-progress')}\n")

    confirmed = [h for h in mem.get('vulnerability_hypotheses', []) if h.get('status') == 'CONFIRMED']
    if confirmed:
        lines.append("\n**Confirmed findings**:\n")
        for h in confirmed:
            lines.append(f"- {h['id']}: {h['hypothesis']} (path: {h['path']}, confidence: {h['confidence']})\n")

    failed = mem.get('failed_attempts', [])
    if failed:
        from collections import Counter
        c = Counter(f.get('hypothesis') for f in failed)
        lines.append(f"\n**Tried and failed**: {len(failed)} attempts across {len(c)} hypotheses\n")

    return "".join(lines)
```

### §36.26 Schema validation (full)

```python
#!/usr/bin/env python3
import json, sys

REQUIRED_FIELDS = {
    "schema_version", "memory_lock", "vulnerability_hypotheses",
    "candidate_pocs", "failed_attempts", "active_paths",
    "convergence_state", "decision_log"
}

VALID_STATUSES = {"CONFIRMED", "LIKELY", "POSSIBLE", "UNVERIFIED", "INVALIDATED"}

def validate(mem):
    errors = []
    for f in REQUIRED_FIELDS:
        if f not in mem:
            errors.append(f"missing required field: {f}")
    for h in mem.get("vulnerability_hypotheses", []):
        if h.get("status") not in VALID_STATUSES:
            errors.append(f"invalid status: {h.get('status')}")
        if not isinstance(h.get("confidence"), (int, float)):
            errors.append(f"confidence must be numeric: {h.get('id')}")
        elif not 0.0 <= h["confidence"] <= 1.0:
            errors.append(f"confidence out of [0,1]: {h.get('id')}")
    paths = list(mem.get("active_paths", {}).values())
    if len(paths) != len(set(paths)):
        errors.append(f"AP-4 path-claim deadlock: {paths}")
    cs = mem.get("convergence_state", {})
    vr = mem.get("verification_results", {})
    if cs.get("stop_condition_met") and (not vr.get("vulnerable") or not vr.get("patched")):
        errors.append("AP-5 premature stop")
    return errors

if __name__ == "__main__":
    mem = json.load(open(sys.argv[1]))
    errors = validate(mem)
    if errors:
        for e in errors: print(f"[ERROR] {e}")
        sys.exit(1)
    print("[VALID]")
```

### §36.27 Migration registry

```python
MIGRATIONS = {
    ("1.0", "1.1"): "migrations/1_0_to_1_1.py",
    ("1.1", "1.2"): "migrations/1_1_to_1_2.py",
}

def latest_supported(): return "1.2"

def migrate_to_latest(mem_path):
    mem = json.load(open(mem_path))
    while mem["schema_version"] != latest_supported():
        cur = mem["schema_version"]
        nxt = {"1.0": "1.1", "1.1": "1.2"}[cur]
        migration = MIGRATIONS[(cur, nxt)]
        # run migration subprocess
        import subprocess
        subprocess.run(["python3", migration, mem_path], check=True)
        mem = json.load(open(mem_path))
```

### §36.28 Memory snapshot diff

```bash
# Diff two snapshots
jq -S . mem.v5.json > /tmp/v5.norm
jq -S . mem.v6.json > /tmp/v6.norm
diff /tmp/v5.norm /tmp/v6.norm | head -50
```

### §36.29 Lock-wait watchdog

```python
import time, os

def watchdog(mem_path, max_wait=300):
    """Kill the agent if it can't acquire lock within max_wait seconds."""
    lock_path = mem_path + ".lock"
    start = time.time()
    while time.time() - start < max_wait:
        if not os.path.exists(lock_path):
            return True  # lock released
        time.sleep(5)
    # Force kill the agent that holds the lock
    import subprocess
    subprocess.run(["flock", "-n", lock_path, "-c", "true"], check=False)
    return False
```

### §36.30 Topology selector

```python
def select_topology(task):
    """Return topology name from task descriptor dict."""
    if task.get("bug_class_exploration") and task.get("multiple_independent_directions"):
        return "parallel-explorers"
    if task.get("phase_sequential") and task.get("clear_handoffs"):
        return "pipeline"
    if task.get("judgment_heavy") and task.get("multiple_lenses"):
        return "council"
    if task.get("scope_dynamic") and task.get("specialist_count", 0) >= 3:
        return "hierarchical"
    return "single-agent"
```

### §36.31 Sync-point cadence chooser

```python
def choose_sync_cadence(engagement):
    """Return (iteration_interval, time_interval_seconds)."""
    if engagement.get("wall_clock_minutes", 60) < 30:
        return (3, 30)    # fast engagement: every 3 iter or 30s
    if engagement.get("wall_clock_minutes", 60) < 180:
        return (5, 60)    # medium: every 5 iter or 60s
    return (10, 300)       # long engagement: every 10 iter or 5 min
```

### §36.32 Confidence bump calculator

```python
def confidence_bump(current, delta, cap=1.0):
    """Compute new confidence after a convergence event."""
    return min(cap, current + delta)

def triangulation_promote(hypothesis):
    """Promote a hypothesis to CONFIRMED if 3+ independent evidence vectors."""
    if len(hypothesis.get("evidence_for", [])) >= 3:
        hypothesis["status"] = "CONFIRMED"
        hypothesis["confidence"] = confidence_bump(hypothesis.get("confidence", 0.5), 0.30)
    return hypothesis
```

### §36.33 Open-question resolver

```bash
# Resolve an open question with a finding reference
QID=Q-001
FID=F-005
write_memory "$MEM" "coordinator" "
  .open_questions |= map(
    if .id == \"$QID\" then
      .status = \"RESOLVED\"
      | .related_to = \"$FID\"
      | .resolved_at = (now | todateiso8601)
    else . end
  )
  | .memory_lock.version = (\$prever + 1)
"
```

### §36.34 Premature-stop guard

```bash
# Add to atomic-write helper, before mv
jq -e '
  .convergence_state.stop_condition_met // false
  | if . then
      (.verification_results.vulnerable != null and .verification_results.patched != null)
    else true end
' "$tmp" >/dev/null || { echo "[AP-5 premature stop]"; rm "$tmp"; exit 5; }
```

### §36.35 Decision-log append-only check

```python
def verify_append_only(decision_log_versions):
    """Each snapshot's decision_log should be a prefix extension of the prior."""
    for i in range(1, len(decision_log_versions)):
        prev = decision_log_versions[i-1]
        cur = decision_log_versions[i]
        if not cur[:len(prev)] == prev:
            return False  # prior entries modified
    return True
```

### §36.36 Quick engagement-close checklist

```bash
echo "=== Engagement close checklist ==="
echo "1. Memory valid JSON:"
jq '.' "$MEM" >/dev/null && echo "  [OK]" || echo "  [FAIL]"

echo "2. Stop condition has reason:"
jq -e '.convergence_state.stop_reason != null' "$MEM" >/dev/null && echo "  [OK]" || echo "  [FAIL]"

echo "3. Verification results populated (if stop):"
jq -e '
  .convergence_state.stop_condition_met
  | if . then
      (.verification_results.vulnerable.crashed == true and .verification_results.patched.crashed == false)
    else true end
' "$MEM" >/dev/null && echo "  [OK]" || echo "  [FAIL]"

echo "4. No anti-pattern violations:"
python3 anti_pattern_check.py "$MEM" >/dev/null 2>&1 && echo "  [OK]" || echo "  [FAIL]"

echo "5. Decision log append-only (entries > 0):"
jq -e '.decision_log | length > 0' "$MEM" >/dev/null && echo "  [OK]" || echo "  [WARN] empty"

echo "6. Evidence hashes match:"
EV_OK=true
for f in evidence/*.txt; do
  bn=$(basename "$f")
  actual=$(sha256sum "$f" | cut -d' ' -f1)
  expected=$(jq -r --arg f "$bn" '.evidence_index[$f].sha256 // ""' "$MEM")
  [ "$actual" = "$expected" ] || EV_OK=false
done
$EV_OK && echo "  [OK]" || echo "  [FAIL]"

echo "7. Final version > 0:"
jq -e '.memory_lock.version > 0' "$MEM" >/dev/null && echo "  [OK]" || echo "  [FAIL]"
```

---

## §37. Sample Memory After a 30-Minute Engagement

A complete reference example of a populated exploit-attempt-memory.json after a 30-minute run.

```json
{
  "schema_version": "1.0",
  "target": {
    "binary": "/targets/libpng-1.6.37/build/libpng.so",
    "patched_binary": "/targets/libpng-1.6.38/build/libpng.so",
    "type": "ELF x86-64",
    "source_available": true,
    "patch_diff": "/targets/patches/libpng-1.6.37_to_1.6.38.patch",
    "sanitizer_enabled": "ASan+UBSan",
    "cve": "CVE-2019-7317"
  },
  "memory_lock": {
    "version": 23,
    "owner_agents": ["A", "B", "C", "coordinator", "verifier"],
    "last_read_at": "2026-07-03T10:43:00Z",
    "last_write_at": "2026-07-03T10:43:15Z",
    "last_write_by": "verifier"
  },
  "vulnerability_hypotheses": [
    {
      "id": "H-A-001",
      "hypothesis": "heap-buffer-overflow in png_read_row() row-processing loop",
      "path": "pngpread.c:412",
      "evidence_for": [
        "BinDiff: function png_read_row changed in 1.6.38",
        "patch adds row_bytes < PNG_SIZE_MAX-8 guard at line 408",
        "angr symbolic execution: input with row_bytes=2^32 reaches line 412"
      ],
      "evidence_against": [],
      "status": "CONFIRMED",
      "confidence": 0.92,
      "claimed_by": ["A", "B", "C"],
      "convergence_events": [
        {"at": "2026-07-03T10:25:00Z", "agents": ["A", "B"], "reason": "independent arrival"}
      ],
      "created_at": "2026-07-03T10:10:00Z"
    },
    {
      "id": "H-B-001",
      "hypothesis": "AFL++ crash in png_read_row()",
      "path": "pngpread.c:412",
      "evidence_for": [
        "crash id:000001 with row_bytes > PNG_SIZE_MAX",
        "ASan stack trace pinned to line 412"
      ],
      "evidence_against": [],
      "status": "CONFIRMED",
      "confidence": 0.88,
      "claimed_by": ["B"],
      "convergence_events": [],
      "created_at": "2026-07-03T10:20:00Z"
    },
    {
      "id": "H-C-001",
      "hypothesis": "Integer overflow in length calculation",
      "path": "pngpread.c:398",
      "evidence_for": [],
      "evidence_against": ["Input size up to 2GB doesn't trigger"],
      "status": "INVALIDATED",
      "confidence": 0.05,
      "claimed_by": ["C"],
      "convergence_events": [],
      "created_at": "2026-07-03T10:15:00Z"
    }
  ],
  "candidate_pocs": [
    {
      "id": "PoC-001",
      "based_on_hypothesis": "H-A-001",
      "input_shape": "PNG with row_bytes > PNG_SIZE_MAX-8 in IHDR chunk",
      "expected_behavior": "ASan heap-buffer-overflow at pngpread.c:412",
      "actual_behavior": "ASan triggered",
      "diff_result": {"vulnerable_version": "crash", "patched_version": "no-crash"},
      "status": "CONFIRMED",
      "verification_log": "evidence/poc-001-asan.txt"
    }
  ],
  "failed_attempts": [
    {"attempt_id": "ATT-001", "by_agent": "C", "hypothesis": "H-C-001", "input_shape": "size=2^31", "yielded_new_evidence": false, "ended_at": "2026-07-03T10:18:00Z"},
    {"attempt_id": "ATT-002", "by_agent": "C", "hypothesis": "H-C-001", "input_shape": "size=2^32", "yielded_new_evidence": false, "ended_at": "2026-07-03T10:20:00Z"},
    {"attempt_id": "ATT-003", "by_agent": "C", "hypothesis": "H-C-001", "input_shape": "size=2^33", "yielded_new_evidence": false, "ended_at": "2026-07-03T10:22:00Z"}
  ],
  "active_paths": {},
  "verification_results": {
    "vulnerable": {"crashed": true, "sanitizer_output": "ERROR: AddressSanitizer: heap-buffer-overflow at pngpread.c:412"},
    "patched": {"crashed": false, "sanitizer_output": "clean exit"}
  },
  "convergence_state": {
    "iterations": 23,
    "confirmed_poc": "PoC-001",
    "stop_condition_met": true,
    "stop_reason": "Differential verification passed on vulnerable AND patched versions",
    "sync_points_executed": 5
  },
  "decision_log": [
    {"at": "2026-07-03T10:00:00Z", "by": "coordinator", "decision": "bootstrap"},
    {"at": "2026-07-03T10:01:00Z", "by": "A", "decision": "claimed path patch-diff"},
    {"at": "2026-07-03T10:01:00Z", "by": "B", "decision": "claimed path harness-entry"},
    {"at": "2026-07-03T10:01:00Z", "by": "C", "decision": "claimed path sanitizer"},
    {"at": "2026-07-03T10:10:00Z", "by": "A", "decision": "added H-A-001"},
    {"at": "2026-07-03T10:15:00Z", "by": "C", "decision": "added H-C-001"},
    {"at": "2026-07-03T10:20:00Z", "by": "B", "decision": "added H-B-001"},
    {"at": "2026-07-03T10:25:00Z", "by": "coordinator", "decision": "CONVERGENCE: H-A-001 ∩ H-B-001 on pngpread.c:412", "reason": "2 agents independently arrived"},
    {"at": "2026-07-03T10:25:30Z", "by": "coordinator", "decision": "promoted H-A-001 and H-B-001 to CONFIRMED"},
    {"at": "2026-07-03T10:22:00Z", "by": "C", "decision": "released path sanitizer", "reason": "3 failed attempts on H-C-001"},
    {"at": "2026-07-03T10:30:00Z", "by": "C", "decision": "claimed path patch-diff (re-claim after A released)"},
    {"at": "2026-07-03T10:35:00Z", "by": "verifier", "decision": "starting differential verification"},
    {"at": "2026-07-03T10:40:00Z", "by": "verifier", "decision": "PoC-001 differential verification passed"},
    {"at": "2026-07-03T10:43:15Z", "by": "verifier", "decision": "stop_condition_met = true"}
  ]
}
```

This is what a healthy 30-minute engagement's memory looks like. Note the structure: version 23, 3 hypotheses (2 CONFIRMED via convergence, 1 INVALIDATED), 1 confirmed PoC, all paths released at stop.

---

## §38. Coordinator Dispatch — 5-Phase Engagement Pattern

A larger coordinator script that runs a 5-phase pentest engagement using Schema 1.

```bash
#!/usr/bin/env bash
# pentest_coordinator.sh — 5-phase engagement
set -euo pipefail

ENGAGEMENT_ID=${1:-ENG-2026-07-001}
MEM="/runs/$ENGAGEMENT_ID/engagement-memory.json"
EVIDENCE="/runs/$ENGAGEMENT_ID/evidence"
mkdir -p "$(dirname "$MEM")" "$EVIDENCE"

# Phase 0: bootstrap Schema 1 memory
cat > "$MEM" <<JSON
{
  "schema_version": "1.0",
  "engagement_id": "$ENGAGEMENT_ID",
  "scope": {"targets": [], "excluded": []},
  "current_phase": "recon",
  "phase_history": [],
  "findings": {"entry_points": [], "credentials": [], "vulnerabilities": [], "lateral_pivots": []},
  "evidence_index": {},
  "next_constraints": {"must_explore": [], "must_avoid": [], "time_budget_remaining_hours": 40},
  "convergence_state": {"active_path": null, "candidate_paths": [], "failed_attempts_on_active_path": 0, "path_switch_threshold": 3},
  "open_questions": [],
  "memory_lock": {"version": 0, "owner_agents": [], "last_read_at": null, "last_write_at": null, "last_write_by": null},
  "decision_log": []
}
JSON

# Phase 1: recon (parallel sub-agents)
python3 agents/recon_agent.py --mem "$MEM" --target example.com > "$EVIDENCE/recon.log" 2>&1 &
PID_RECON=$!

# Phase 2: intrusion (depends on recon)
wait $PID_RECON
python3 agents/intrusion_agent.py --mem "$MEM" > "$EVIDENCE/intrusion.log" 2>&1 &
PID_INTRUSION=$!

# Phase 3: privesc (depends on intrusion)
wait $PID_INTRUSION
python3 agents/privesc_agent.py --mem "$MEM" > "$EVIDENCE/privesc.log" 2>&1 &
PID_PRIVESC=$!

# Phase 4: lateral
wait $PID_PRIVESC
python3 agents/lateral_agent.py --mem "$MEM" > "$EVIDENCE/lateral.log" 2>&1 &

# Phase 5: report
wait
python3 agents/report_agent.py --mem "$MEM" --output "$EVIDENCE/report.md"

echo "[done] $ENGAGEMENT_ID"
jq '{
  phases: .phase_history,
  findings: .findings,
  decisions: (.decision_log | length)
}' "$MEM"
```

---

## §39. Memory Visualization — Decision Timeline Graph

Render the decision_log as a wall-clock timeline.

```bash
#!/usr/bin/env bash
MEM="$1"
OUT="${2:-timeline.svg}"

{
  echo "digraph timeline {"
  echo "  rankdir=LR;"
  echo "  node [shape=box, fontsize=10];"

  jq -r '
    .decision_log
    | to_entries
    | map("    d\(.key) [label=\"\(.value.at[11:19] \\n [\(.value.by)] \\n \(.value.decision | .[0:50])\"];")
    | .[]
  ' "$MEM"

  jq -r '
    .decision_log
    | to_entries
    | map(.key)
    | .[1:]
    | map("    d\(. - 1) -> d\(.)")
    | .[]
  ' "$MEM"

  echo "}"
} | dot -Tsvg > "$OUT"

echo "[timeline] $OUT"
```

---

## §40. Anti-Pattern Quick-Sweep

A single one-liner to check all five anti-patterns:

```bash
python3 -c "
import json, sys
from collections import Counter
m = json.load(open('$MEM'))
v = []
ml = m.get('memory_lock', {})
if ml.get('last_write_at') and not ml.get('last_read_at'): v.append('AP-1')
findings_keys = set()
for f in m.get('findings', {}).get('entry_points', []): findings_keys.add(f.get('target'))
for h in m.get('vulnerability_hypotheses', []):
    findings_keys.add(h.get('id'))
    findings_keys.add(h.get('path'))
for e in m.get('decision_log', []):
    ref = e.get('finding_ref')
    if ref and ref not in findings_keys: v.append(f'AP-2 ref={ref}')
fails = Counter(f.get('hypothesis') for f in m.get('failed_attempts', []))
for h, n in fails.items():
    if n >= 3:
        h_obj = next((x for x in m['vulnerability_hypotheses'] if x['id'] == h), None)
        if h_obj and not h_obj.get('evidence_for') and not h_obj.get('evidence_against'):
            v.append(f'AP-3 hyp={h} n={n}')
paths = list(m.get('active_paths', {}).values())
if len(paths) != len(set(paths)): v.append('AP-4')
cs = m.get('convergence_state', {})
vr = m.get('verification_results', {})
if cs.get('stop_condition_met') and (not vr.get('vulnerable') or not vr.get('patched')): v.append('AP-5')
print('OK' if not v else '; '.join(v))
"
```

---

## §41. Schema Validator (compact)

A single Python file that validates any of the three schemas.

```python
#!/usr/bin/env python3
# schema_validator.py
import json, sys

SCHEMAS = {
    "1.0": {
        "required": ["schema_version", "memory_lock", "decision_log"],
        "optional": ["engagement_id", "target", "scope", "findings", "evidence_index",
                     "next_constraints", "convergence_state", "vulnerability_hypotheses",
                     "candidate_pocs", "failed_attempts", "active_paths",
                     "verification_results", "open_questions", "phase_history"]
    }
}

VALID_CONFIDENCE = {"CONFIRMED", "LIKELY", "POSSIBLE", "UNVERIFIED", "INVALIDATED"}

def validate(mem):
    errors = []
    sv = mem.get("schema_version")
    if sv not in SCHEMAS:
        errors.append(f"unknown schema_version: {sv}")
        return errors
    for f in SCHEMAS[sv]["required"]:
        if f not in mem:
            errors.append(f"missing required: {f}")
    for h in mem.get("vulnerability_hypotheses", []):
        if h.get("status") not in VALID_CONFIDENCE:
            errors.append(f"invalid status in {h.get('id')}: {h.get('status')}")
        if not isinstance(h.get("confidence", 0), (int, float)):
            errors.append(f"non-numeric confidence in {h.get('id')}")
        elif not 0.0 <= h["confidence"] <= 1.0:
            errors.append(f"confidence out of [0,1] in {h.get('id')}")
    paths = list(mem.get("active_paths", {}).values())
    if len(paths) != len(set(paths)):
        errors.append("AP-4 path-claim deadlock")
    cs = mem.get("convergence_state", {})
    vr = mem.get("verification_results", {})
    if cs.get("stop_condition_met") and (not vr.get("vulnerable") or not vr.get("patched")):
        errors.append("AP-5 premature stop")
    return errors

if __name__ == "__main__":
    mem = json.load(open(sys.argv[1]))
    errors = validate(mem)
    if errors:
        for e in errors: print(f"[ERROR] {e}")
        sys.exit(1)
    print("[VALID]")
```

Usage:

```bash
python3 schema_validator.py /runs/ENG-2026-07-001/engagement-memory.json
```

---

## §42. Multi-Agent Failure Mode Catalogue

A catalogue of common multi-agent failures and their diagnostic signatures.

```yaml
failure_modes:
  - name: "Agent stuck in retry loop"
    signature: "Same agent writes 5+ failed_attempts in 5 minutes"
    cause: "Path switch threshold too high (default 3) or candidate_paths exhausted"
    remediation: "Lower threshold; add more candidate_paths"

  - name: "Convergence never fires"
    signature: "Memory has 5+ LIKELY hypotheses, none CONFIRMED after 30 min"
    cause: "Agents exploring genuinely different paths (no overlap), OR path strings don't match exactly"
    remediation: "Check path normalization; consider whether convergence is realistic for this bug class"

  - name: "Memory file locks up"
    signature: "All agents timing out on flock"
    cause: "An agent process is stuck holding the lock (crashed mid-section?)"
    remediation: "Identify stuck PID: lsof mem.lock; kill -9; restart agent"

  - name: "Schema validation fails on every write"
    signature: "Every agent's write rejected with schema error"
    cause: "Required field missing from bootstrap"
    remediation: "Coordinator edits memory directly to add missing field; restart agents"

  - name: "Premature stop fires immediately"
    signature: "First agent's stop_condition_met=true write is rejected"
    cause: "AP-5 check requires verification_results before stop"
    remediation: "Run differential verification first; populate verification_results"

  - name: "Path-claim deadlock loop"
    signature: "Multiple agents repeatedly rejected on same path"
    cause: "All agents have same primary path; no fallback"
    remediation: "Add per-agent fallback paths; or use coordinator to pre-assign"

  - name: "Lost updates"
    signature: "Hypotheses disappear between versions"
    cause: "Atomic-write version-vector guard removed; in-place edit occurred"
    remediation: "Re-enable version check; ensure all agents use the canonical write_memory helper"

  - name: "Anti-pattern checker noise"
    signature: "AP-1 reported on every write"
    cause: "Agents not setting last_read_at"
    remediation: "Add last_read_at update in agent main loop, before any write"
```

---

## §43. Sample Agent Code — Patch-Diff Direction

A complete reference agent implementation for the patch-diff direction.

```python
#!/usr/bin/env python3
# patch_diff_agent.py
import sys, json, subprocess, os, re
from pathlib import Path

AGENT_ID = sys.argv[1]
MEM = sys.argv[2]
RUN_DIR = Path(MEM).parent.parent

def read_memory():
    r = subprocess.run(["jq", ".", MEM], capture_output=True, text=True, check=True)
    return json.loads(r.stdout)

def write_memory(jq_expr):
    subprocess.run(["bash", "-c", f'''
    (
      flock -x -w 30 9 || exit 1
      BEFORE=$(jq '.memory_lock.version' "{MEM}")
      tmp=$(mktemp -p "$(dirname '{MEM}')")
      jq --arg agent "{AGENT_ID}" --argjson prever "$BEFORE" '{jq_expr}' "{MEM}" > "$tmp"
      AFTER=$(jq '.memory_lock.version' "$tmp")
      [ "$AFTER" -eq "$((BEFORE + 1))" ] || {{ rm "$tmp"; exit 2; }}
      jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$tmp" >/dev/null || {{ rm "$tmp"; exit 4; }}
      mv "$tmp" "{MEM}"
    ) 9>"{MEM}.lock"
    '''], check=True)

def stop_condition_met(mem):
    return mem["convergence_state"].get("stop_condition_met", False)

def analyze_patch(patch_path):
    """Return list of (file, line, change_description) tuples."""
    result = subprocess.run(["diff", "-u", "/dev/null", patch_path],
                            capture_output=True, text=True)
    changes = []
    current_file = None
    current_line = None
    for line in result.stdout.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@"):
            m = re.match(r"@@\s*-\d+,\d+\s*\+(\d+)", line)
            if m: current_line = int(m.group(1))
        elif line.startswith("+") and current_file and current_line:
            changes.append((current_file, current_line, line[1:]))
            current_line += 1
    return changes

def should_continue():
    mem = read_memory()
    return not stop_condition_met(mem)

# Main loop
iteration = 0
while should_continue() and iteration < 30:
    iteration += 1
    mem = read_memory()

    # Analyze patch (one-shot at iteration 1)
    if iteration == 1:
        patch = mem["target"].get("patch_diff")
        if patch and os.path.exists(patch):
            changes = analyze_patch(patch)
            for file, line, change in changes[:5]:  # top 5 changes
                hyp_id = f"H-{AGENT_ID}-{iteration:03d}-{line}"
                write_memory(f'''
                  .vulnerability_hypotheses += [{{
                    "id": "{hyp_id}",
                    "hypothesis": "Possible bug near change at {file}:{line}",
                    "path": "{file}:{line}",
                    "evidence_for": ["patch change: {change[:80]}"],
                    "evidence_against": [],
                    "status": "LIKELY", "confidence": 0.50,
                    "claimed_by": ["{AGENT_ID}"],
                    "created_at": (now | todateiso8601)
                  }}]
                  | .memory_lock.last_read_at = (now | todateiso8601)
                ''')

    # Iterations 2+: try to confirm or falsify
    # (delegated to domain-specific reasoning — BinDiff, angr, etc.)
    # ...

# Release path on exit
write_memory('''
  del(.active_paths["''' + AGENT_ID + '''"])
  | .memory_lock.last_read_at = (now | todateiso8601)
''')
print(f"[{AGENT_ID}] done after {iteration} iterations")
```

---

## §44. Glossary

Key terms used throughout this skill:

```
Structured Memory      : machine-queryable JSON state (vs. prose)
Memory Delta           : a structured change set applied atomically
Atomic Write           : mktemp + jq + mv (POSIX-guaranteed atomic rename)
Version Vector         : memory_lock.version, incremented per write
Path Claim             : agent uniquely taking a direction (active_paths)
Convergence Event      : 2+ agents independently arriving at same path
Differential Verify    : PoC triggers vulnerable, clean on patched
Anti-Pattern           : forbidden behavior with machine-checkable detection
Topology               : parallel-explorers / pipeline / council / hierarchical
Harness                : the runtime layer between agent and environment
招 (zhāo)              : Chinese for "move" (as in chess); MopMonk's three招 = three engineering patterns
```

---

## §45. Reference JQ Patterns Cheat Sheet

Every jq pattern an agent author will need, in one place.

### Read current version

```bash
jq '.memory_lock.version' "$MEM"
```

### Read all active paths

```bash
jq '.active_paths' "$MEM"
```

### Read all CONFIRMED hypotheses

```bash
jq '[.vulnerability_hypotheses[] | select(.status == "CONFIRMED")]' "$MEM"
```

### Read failed attempts grouped by hypothesis

```bash
jq '.failed_attempts | group_by(.hypothesis) | map({hyp: .[0].hypothesis, count: length})' "$MEM"
```

### Read decision log last 10 entries

```bash
jq '.decision_log[-10:]' "$MEM"
```

### Read convergence state summary

```bash
jq '.convergence_state | {iterations, active_path, failed_attempts_on_active_path, stop_condition_met}' "$MEM"
```

### Detect duplicate active paths (AP-4 check)

```bash
jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$MEM"
```

### Detect premature stop (AP-5 check)

```bash
jq -e '(.convergence_state.stop_condition_met // false) | if . then (.verification_results.vulnerable != null and .verification_results.patched != null) else true end' "$MEM"
```

### Find convergence candidates

```bash
jq '[.vulnerability_hypotheses[] | select(.status != "INVALIDATED")] | group_by(.path) | map(select(length >= 2))' "$MEM"
```

### Find stale open questions (>30 days)

```bash
jq '[.open_questions[] | select(.status == "OPEN" and (.raised_at < "2026-06-01"))]' "$MEM"
```

### Compute total evidence per hypothesis

```bash
jq '[.vulnerability_hypotheses[] | {id: .id, evidence_count: (.evidence_for | length)}]' "$MEM"
```

### Filter findings by confidence threshold

```bash
jq '[.vulnerability_hypotheses[] | select(.confidence >= 0.7)]' "$MEM"
```

### Count iterations per agent

```bash
jq '[.decision_log[] | .by] | group_by(.) | map({agent: .[0], decisions: length})' "$MEM"
```

### Find orphaned evidence_index entries

```bash
jq '.evidence_index | to_entries | map(select(.value.sha256 == null))' "$MEM"
```

### Render memory as a flat timeline

```bash
jq -r '.decision_log[] | "\(.at) [\(.by)] \(.decision)"' "$MEM"
```

---

## §46. Defense Team Patterns (Symmetric Application)

The same patterns that make offensive multi-agent systems converge make defensive multi-analyst teams effective. The skill is symmetric.

### SOC playbook shared IOC memory

```json
{
  "schema_version": "1.0",
  "incident_id": "INC-2026-07-001",
  "iocs": [
    {"value": "185.220.101.45", "type": "ip", "confidence": "CONFIRMED",
     "claimed_by": ["analyst-1", "analyst-2"], "evidence_for": ["firewall-log-001", "edr-005"]}
  ],
  "hypotheses": [
    {"id": "H-001", "hypothesis": "Cobalt Strike C2", "confidence": 0.85, "claimed_by": ["analyst-1"]}
  ],
  "memory_lock": {"version": 0, "owner_agents": [], "last_read_at": null, "last_write_at": null, "last_write_by": null},
  "decision_log": []
}
```

### Threat hunting coordination pattern

```python
# Three analysts independently hunt for persistence mechanisms
# Each writes findings to shared memory with claimed_by
# Convergence: 2+ analysts find same persistence technique = high-priority

def hunting_convergence(iocs):
    """Same logic as exploit-dev convergence, applied to IOC hunting."""
    by_technique = {}
    for ioc in iocs:
        if ioc.get("technique"):
            by_technique.setdefault(ioc["technique"], []).append(ioc)
    for technique, group in by_technique.items():
        analysts = {ioc.get("claimed_by", [None])[0] for ioc in group}
        if len(analysts) >= 2:
            for ioc in group:
                ioc["confidence"] = "CONFIRMED"
    return iocs
```

### Detection-as-code multi-author review

```bash
# Two detection engineers edit YARA rules in parallel
# Use shared-memory + atomic-write to prevent rule clobbering

# Engineer 1: add new YARA rule
write_memory detections.json "engineer-1" '
  .rules += [{
    "id": "YARA-2026-001",
    "name": "Suspicious_PowerShell_Encoded",
    "pattern": "...",
    "author": "engineer-1",
    "version": 1
  }]
'

# Engineer 2: edit existing rule (independent delta)
write_memory detections.json "engineer-2" '
  .rules |= map(
    if .id == "YARA-2025-047" then
      .pattern += " or new_string"
      | .version += 1
      | .last_modified_by = "engineer-2"
    else . end
  )
'
```

### IOC triangulation rule

```yaml
ioc_triangulation:
  description: "3 analysts independently arriving at same IOC = high-confidence promotion"
  implementation: |
    if ioc.claimed_by | length >= 3:
        ioc.confidence = "CONFIRMED"
        ioc.priority = "P1"
    elif ioc.claimed_by | length >= 2:
        ioc.confidence = "LIKELY"
        ioc.priority = "P2"
```

### Detection engineering anti-patterns (parallel)

```yaml
defensive_anti_patterns:
  - name: "Detection without coverage test"
    description: "Rule committed without test that fires it"
    detection: "rule.test_status != 'PASSED'"
    severity: HIGH

  - name: "Rule clobber"
    description: "Two engineers edit same rule, one overwrites"
    detection: "rule.version decreases OR rule.author changes without version bump"
    severity: CRITICAL

  - name: "Orphan rule"
    description: "Rule not in any playbook"
    detection: "rule not referenced by any playbook"
    severity: MEDIUM

  - name: "Untested Sigma conversion"
    description: "YARA -> Sigma conversion not validated"
    detection: "conversion_test_run == false"
    severity: HIGH
```

---

## §47. End-to-End Worked Example — Full Walk-Through

A complete walk-through from empty memory to confirmed PoC.

### Step 1: Bootstrap (t=0)

```bash
MEM=/runs/example/mem.json
mkdir -p "$(dirname "$MEM")"
cat > "$MEM" <<'JSON'
{
  "schema_version": "1.0",
  "target": {"binary": "/targets/example-vuln", "patched_binary": "/targets/example-patched"},
  "memory_lock": {"version": 0, "owner_agents": [], "last_read_at": null, "last_write_at": null, "last_write_by": null},
  "vulnerability_hypotheses": [],
  "candidate_pocs": [],
  "failed_attempts": [],
  "active_paths": {},
  "convergence_state": {"iterations": 0, "stop_condition_met": false, "stop_reason": null},
  "decision_log": []
}
JSON
```

### Step 2: Agent A claims path (t=1)

```bash
write_memory "$MEM" "A" '
  .active_paths["A"] = "patch-diff"
  | .memory_lock.version = ($prever + 1)
  | .memory_lock.last_read_at = (now | todateiso8601)
'
```

### Step 3: Agent B claims path (t=1)

```bash
write_memory "$MEM" "B" '
  .active_paths["B"] = "harness-entry"
  | .memory_lock.version = ($prever + 1)
'
```

### Step 4: Agent A writes hypothesis (t=10)

```bash
write_memory "$MEM" "A" '
  .vulnerability_hypotheses += [{
    "id": "H-A-001",
    "hypothesis": "stack-buffer-overflow in parser",
    "path": "parser.c:142",
    "evidence_for": ["BinDiff shows added bounds check"],
    "evidence_against": [],
    "status": "LIKELY", "confidence": 0.55,
    "claimed_by": ["A"], "created_at": (now | todateiso8601)
  }]
  | .memory_lock.version = ($prever + 1)
  | .convergence_state.iterations += 1
'
```

### Step 5: Agent B writes hypothesis (t=20)

```bash
write_memory "$MEM" "B" '
  .vulnerability_hypotheses += [{
    "id": "H-B-001",
    "hypothesis": "AFL++ crash at parser.c",
    "path": "parser.c:142",
    "evidence_for": ["crash id:000001"],
    "evidence_against": [],
    "status": "LIKELY", "confidence": 0.55,
    "claimed_by": ["B"], "created_at": (now | todateiso8601)
  }]
  | .memory_lock.version = ($prever + 1)
  | .convergence_state.iterations += 1
'
```

### Step 6: Coordinator detects convergence (t=25)

```bash
python3 convergence_detector.py "$MEM"
# Output: [convergence] H-A-001 ∩ H-B-001 on parser.c:142
# Promoted both to CONFIRMED, confidence 0.85
```

### Step 7: Verifier runs differential (t=35)

```bash
echo "trigger-payload" > /tmp/poc.bin
/targets/example-vuln < /tmp/poc.bin > vuln.txt 2>&1
/targets/example-patched < /tmp/poc.bin > patched.txt 2>&1

if grep -q "ERROR:" vuln.txt && ! grep -q "ERROR:" patched.txt; then
  write_memory "$MEM" "verifier" '
    .verification_results = {
      "vulnerable": {"crashed": true},
      "patched": {"crashed": false}
    }
    | .convergence_state.stop_condition_met = true
    | .convergence_state.stop_reason = "differential verification passed"
    | .candidate_pocs += [{
      "id": "PoC-001", "based_on_hypothesis": "H-A-001",
      "status": "CONFIRMED", "input_shape": "trigger-payload"
    }]
    | .memory_lock.version = ($prever + 1)
  '
fi
```

### Step 8: Final state (t=40)

```bash
jq '{
  version: .memory_lock.version,
  confirmed: [.vulnerability_hypotheses[] | select(.status == "CONFIRMED") | .id],
  pocs: [.candidate_pocs[] | select(.status == "CONFIRMED") | .id],
  iterations: .convergence_state.iterations,
  stop_reason: .convergence_state.stop_reason
}' "$MEM"
```

Output:

```json
{
  "version": 8,
  "confirmed": ["H-A-001", "H-B-001"],
  "pocs": ["PoC-001"],
  "iterations": 2,
  "stop_reason": "differential verification passed"
}
```

This is the canonical happy path — three parallel agents, two converged, one PoC confirmed via differential verification, all in 40 minutes.

---

## §48. Anti-Skill Boundaries (what NOT to use this skill for)

To prevent scope creep, this skill explicitly does NOT cover:

```yaml
out_of_scope:
  - description: "Generic task decomposition patterns"
    use_instead: "skills/multi-agent-collaboration"
    reason: "That skill handles coordinator-worker topology and decomposition heuristics"

  - description: "Multi-perspective judgment (Attack/Defense/Audit)"
    use_instead: "skills/council"
    reason: "Council is for analytical lens multiplicity, not parallel state writes"

  - description: "Deploying PentestGPT/HexStrike/Viper"
    use_instead: "skills/agentic-pentest"
    reason: "That skill handles framework-specific deployment; this skill is framework-agnostic"

  - description: "Daily prose logs and distilled knowledge"
    use_instead: "skills/continuous-learning and chronicle"
    reason: "Prose memory and structured JSON compose; they do not compete"

  - description: "Independent claim re-run"
    use_instead: "skills/verification-loop"
    reason: "Verification reads from this skill's memory; it is a separate concern"

  - description: "Generic loop constructs (sequential / watch / batch)"
    use_instead: "skills/autonomous-loops"
    reason: "Loops are control flow; this skill is the state layer"

  - description: "Human-readable kill-chain phase orchestration"
    use_instead: "skills/engagement-manager"
    reason: "Engagement manager decides what phase; this skill decides how parallel workers share state"
```

---

## §49. References & Further Reading

```
MopMonk Agent (扫地僧)        — https://github.com/MopMonkAI/MopMonkAgent
CyberGym paper (ICLR 2026)   — arXiv:2506.02548, OpenReview 2YvbLQEdYt
Anthropic multi-agent blog   — anthropic.com/blog (2024-2026 series)
LangGraph checkpointing      — langchain-ai.github.io/langgraph
AutoGen GroupChat paper      — arXiv:2308.08155
Magentic-One paper           — arXiv:2411.04468
CrewAI docs                  — docs.crewai.com
OpenAI Swarm GitHub          — github.com/openai/swarm
POSIX flock(1) man page      — man7.org/linux/man-pages/man1/flock.1.html
jq manual                    —stedolan.github.io/jq/manual/
JSON Schema                  — json-schema.org
```

Internal kali-claw cross-references:

```
validation/scenarios/SCEN-007.md            — canonical reference scenario
validation/scenarios/SCEN-MEMORY-SCHEMA.md  — schema library
validation/scenarios/SCEN-006.md            — Schema 1 (pentest engagement) scenario
validation/scenarios/SCEN-008.md            — Schema 3 (patch-diff reproduction) scenario
docs/mopmonk-research-and-kali-claw-plan.md — MopMonk three招 internal research
skills/multi-agent-collaboration/SKILL.md   — task decomposition
skills/council/SKILL.md                     — multi-perspective analysis
skills/agentic-pentest/SKILL.md             — LLM-driven pentest framework deployment
skills/continuous-learning/SKILL.md         — knowledge persistence
skills/chronicle/SKILL.md                   — distilled long-term memory
skills/verification-loop/SKILL.md           — independent claim re-run
skills/autonomous-loops/SKILL.md            — generic loop constructs
skills/engagement-manager/SKILL.md          — kill-chain phase orchestration
```

---

## §50. Version History

```
v1.0.0 (2026-07-03, Wave 12 v0.1.45):
  Initial release. Solidifies SCEN-007 + SCEN-MEMORY-SCHEMA patterns
  into a reusable knowledge base. 3 schemas, 5 anti-patterns, 5-layer
  runtime stack, MopMonk three招 mapping, 30 test cases, 3 guides.

Future:
  v1.1.0 — add schema migration tooling (§33) reference implementations
  v1.2.0 — add cross-engagement memory federation (§35) automation
  v1.3.0 — add LangGraph-style checkpoint graph primitives
```

