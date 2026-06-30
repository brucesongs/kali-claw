# SCEN-007: Shared-Memory Multi-Agent Exploit Dev

| Field | Value |
|-------|-------|
| **ID** | SCEN-007 |
| **Name** | Shared-Memory Multi-Agent Exploit Dev |
| **Type** | Multi-Agent Exploit Development |
| **Kill Chain Phase** | Vulnerability Research → Exploit Development → Verification |
| **Difficulty** | Expert |
| **Estimated Duration** | 90-120 minutes (3 parallel agents, ~60 min wall-clock) |

---

## Objective

Coordinate **3 parallel agents** against ONE shared `exploit-attempt-memory.json` file to discover AND verify a vulnerability PoC for a known-vulnerable binary. Each agent approaches the target from a **different direction** (MopMonk招三 — shared-memory multi-agent parallel exploration):

- **Agent A** — **Patch-diff direction**: compare vulnerable vs patched source/binary, identify the security fix, work forward to the bug.
- **Agent B** — **Harness-entry direction**: write an AFL++/libFuzzer harness, fuzz the vulnerable binary, take the first crash, work backwards to the root cause.
- **Agent C** — **Sanitizer direction**: run the binary under ASan/UBSan against an input corpus, capture the stack trace, localize to source line.

All agents read/write the **same** memory file using the atomic-write + version-vector protocol defined in `SCEN-MEMORY-SCHEMA.md` (Schema 2). Stop condition: any candidate PoC passes **differential verification** — crashes the vulnerable binary, ASan-clean on the patched binary.

---

## Skill Chain

```
binary-reverse → reverse-engineering-advanced → exploit-development
              → ai-fuzzing → verification-loop → multi-agent-collaboration
```

Plus `council` invoked at each sync point for cross-agent delta review.

| Step | Skill Domain | Role in Scenario | Key Tools |
|------|-------------|------------------|-----------|
| 1 | `binary-reverse` | Static analysis of vulnerable binary; identify interesting functions | `radare2`, `ghidra`, `objdump` |
| 2 | `reverse-engineering-advanced` | BinDiff between vulnerable/patched; symbolic execution with angr | `bindiff`, `angr`, `z3` |
| 3 | `exploit-development` | PoC construction from confirmed hypothesis | `pwntools`, `python3` |
| 4 | `ai-fuzzing` | AFL++/libFuzzer harness, corpus minimization | `afl-fuzz`, `libFuzzer`, `afl-cmin` |
| 5 | `verification-loop` | Differential verification (vulnerable vs patched, ASan) | custom runner, `asan_symbolize` |
| 6 | `multi-agent-collaboration` | Coordinator dispatches paths, aggregates hypotheses, detects convergence | `jq`, `flock`, scenario-runner |
| sync | `council` | Every N iterations, all agents review each other's deltas | council skill prompt template |

---

## Prerequisites

- **Vulnerable binary**: `/targets/libpng-1.6.37/build/libpng.so` plus a fuzzer-linked driver `/targets/libpng-1.6.37/png_read_harness`
- **Patched binary**: `/targets/libpng-1.6.38/build/libpng.so` (same harness driver, swapped `.so`)
- **Upstream patch file**: `/targets/patches/libpng-1.6.37_to_1.6.38.patch` (maps to **CVE-2019-7317** — use-after-free in `png_image_free` / `png_read_row` region; the scenario uses a simplified reproduction case targeting row-callback handling)
- **Kali Linux 2025-2 ARM64** with: AFL++ (`afl-fuzz`), libFuzzer, LLVM sanitizers (`clang -fsanitize=address,undefined`), BinDiff 6, angr, `jq`, `flock`, `python3` + `pwntools`
- **3 parallel agent runtimes**: kali-claw multi-agent mode (`scenario-runner.sh --agents A,B,C`) OR 3 CLI sessions pointed at the same `MEMORY_DIR`
- Shared memory dir: `/runs/SCEN-007/mem/`  (writable by all 3 agents)

---

## Multi-Agent Coordination Protocol

The protocol is the **load-bearing** part of this scenario. It is the literal implementation of MopMonk招三 against a filesystem — no DB, no message broker.

### Phase 0 — Memory bootstrap (single-threaded, once)

```bash
# Coordinator (not agent A/B/C) creates the empty memory.
mkdir -p /runs/SCEN-007/mem
cat > /runs/SCEN-007/mem/exploit-attempt-memory.json <<'JSON'
{
  "schema_version": "1.0",
  "target": {
    "binary": "/targets/libpng-1.6.37/build/libpng.so",
    "patched_binary": "/targets/libpng-1.6.38/build/libpng.so",
    "type": "ELF x86-64 shared object",
    "source_available": true,
    "patch_diff": "/targets/patches/libpng-1.6.37_to_1.6.38.patch",
    "sanitizer_enabled": "ASan+UBSan",
    "cve": "CVE-2019-7317"
  },
  "memory_lock": {
    "version": 0,
    "owner_agents": [],
    "last_write_at": null,
    "last_write_by": null
  },
  "vulnerability_hypotheses": [],
  "candidate_pocs": [],
  "failed_attempts": [],
  "active_paths": {},
  "convergence_state": {
    "iterations": 0,
    "confirmed_poc": null,
    "stop_condition_met": false,
    "stop_reason": null,
    "sync_points_executed": 0
  },
  "decision_log": []
}
JSON
```

### Phase 1 — Path claim (all 3 agents, race-safe)

Each agent opens the memory, checks `active_paths`, claims the path it was assigned, and writes back. The claim uses a POSIX `flock` advisory lock around the read-modify-write window:

```bash
# Agent A (patch-diff), Agent B (harness-entry), Agent C (sanitizer) all run this template
AGENT_ID=A              # or B, or C
CLAIM_PATH=patch-diff   # or harness-entry, or sanitizer

(
  flock -x 9 || exit 1
  tmp=$(mktemp)
  jq --arg agent "$AGENT_ID" --arg path "$CLAIM_PATH" \
    '.active_paths[$agent] = $path
     | .memory_lock.owner_agents = (.active_paths | keys)
     | .memory_lock.version += 1
     | .memory_lock.last_write_at = (now | todateiso8601)
     | .memory_lock.last_write_by = $agent
     | .decision_log += [{"at": (now | todateiso8601), "by": $agent,
                          "decision": ("claimed path " + $path)}]' \
    /runs/SCEN-007/mem/exploit-attempt-memory.json > "$tmp"
  mv "$tmp" /runs/SCEN-007/mem/exploit-attempt-memory.json
) 9>/runs/SCEN-007/mem/exploit-attempt-memory.json.lock
```

The **anti-pattern** check (Schema 2): `active_paths` must not have duplicate values. If a claim would collide, the agent detects it and falls back to its secondary path.

### Phase 2 — Atomic-write protocol (every iteration)

Every memory update — every hypothesis, every failed attempt, every PoC — goes through this pattern. **No agent ever edits the JSON in place.**

```bash
# Atomic write with version-vector guard — Agent A pushing hypothesis H-A-001
AGENT_ID=A
HYP_ID=H-A-001
HYP_TEXT="heap-buffer-overflow in png_read_row() row-processing loop"
HYP_PATH="pngpread.c:412"
EVIDENCE='["BinDiff: function png_read_row changed in 1.6.38",
           "patch adds row_bytes < uInt_MAX guard at line 408"]'

(
  flock -x 9 || exit 1
  BEFORE_VER=$(jq '.memory_lock.version' /runs/SCEN-007/mem/exploit-attempt-memory.json)

  # Optimistic concurrency: read version under lock, write must increment by exactly 1
  tmp=$(mktemp)
  jq --arg agent "$AGENT_ID" \
     --arg hid "$HYP_ID" \
     --arg htext "$HYP_TEXT" \
     --arg hpath "$HYP_PATH" \
     --argjson ev "$EVIDENCE" \
     --argjson prever "$BEFORE_VER" \
    '.vulnerability_hypotheses += [{
        "id": $hid, "hypothesis": $htext, "path": $hpath,
        "evidence_for": $ev, "evidence_against": [],
        "status": "LIKELY", "confidence": 0.55,
        "claimed_by": $agent, "created_at": (now | todateiso8601)
      }]
     | .memory_lock.version = ($prever + 1)
     | .memory_lock.last_write_at = (now | todateiso8601)
     | .memory_lock.last_write_by = $agent
     | .convergence_state.iterations += 1
     | .decision_log += [{"at": (now | todateiso8601), "by": $agent,
                          "decision": ("added hypothesis " + $hid)}]' \
    /runs/SCEN-007/mem/exploit-attempt-memory.json > "$tmp"

  # Validate before swap: schema check + version check
  AFTER_VER=$(jq '.memory_lock.version' "$tmp")
  if [ "$AFTER_VER" -ne "$((BEFORE_VER + 1))" ]; then
    echo "[conflict] agent $AGENT_ID version mismatch — aborting write"
    rm "$tmp"
    exit 2
  fi
  mv "$tmp" /runs/SCEN-007/mem/exploit-attempt-memory.json
) 9>/runs/SCEN-007/mem/exploit-attempt-memory.json.lock
```

### Phase 3 — Periodic sync point (every 5 iterations per agent)

Every N iterations, each agent pauses and invokes the **`council`** skill to review the deltas produced by the OTHER two agents. Council's job here is **convergence detection**: did two agents independently arrive at the same hypothesis?

```bash
# Council invocation — coordinator triggers this at each sync point
# council reads the memory, looks at hypotheses[].path for intersections
jq '[.vulnerability_hypotheses[] | select(.status != "INVALIDATED") | .path]'
   /runs/SCEN-007/mem/exploit-attempt-memory.json

# Convergence rule (council applies this):
# If 2+ hypotheses point at the same source path AND have different claimed_by,
# promote both to CONFIRMED and merge into a single canonical hypothesis.
```

### Phase 4 — Stop condition

A candidate PoC is generated only from a **CONFIRMED** hypothesis. The PoC must pass **differential verification**:

```bash
# Differential verification — the actual stop-condition check
# 1. Run PoC against vulnerable build
ASAN_OPTIONS=detect_leaks=0 /targets/libpng-1.6.37/build/png_read_harness < poc.bin
# 2. Run PoC against patched build
ASAN_OPTIONS=detect_leaks=0 /targets/libpng-1.6.38/build/png_read_harness < poc.bin
# Stop condition: vulnerable exits with ASan heap-buffer-overflow, patched exits 0 cleanly.
```

---

## Execution Steps

### Agent A — Patch-diff direction

**Hypothesis formation strategy**: The patch is the oracle — wherever the maintainer added a check, the bug lived nearby.

1. Diff the source trees:
   ```bash
   diff -ruN /targets/libpng-1.6.37/source /targets/libpng-1.6.38/source > /runs/SCEN-007/A/source.diff
   ```
2. Apply BinDiff to the compiled artifacts for the case where symbols are stripped:
   ```bash
   bindiff --bin1 /targets/libpng-1.6.37/build/libpng.so \
           --bin2 /targets/libpng-1.6.38/build/libpng.so \
           --output /runs/SCEN-007/A/bindiff.sqlite
   sqlite3 /runs/SCEN-007/A/bindiff.sqlite \
     "SELECT name, similarity, confidence FROM function WHERE similarity < 0.95 ORDER BY similarity;"
   ```
3. Identify changed functions; cross-reference with the source diff. Most-suspicious change: `png_read_row` — patch adds `if (row_bytes > PNG_SIZE_MAX - 8) return;` before the allocation.
4. Form hypothesis **H-A-001**: "heap-buffer-overflow in `png_read_row()` row-processing loop, triggered when `row_bytes` exceeds internal buffer". Write to memory (atomic write above).
5. Iterate: use `angr` to symbolically execute `png_read_row` and find inputs reaching the unchecked allocation:
   ```bash
   python3 /runs/SCEN-007/A/angr_explore.py --func png_read_row \
       --target-line pngpread.c:412 --output /runs/SCEN-007/A/angr-inputs/
   ```
6. Each angr finding that triggers the suspect line → push as `evidence_for` on H-A-001, bump confidence. No new findings after 3 runs → either path-switch (give up and try a secondary hypothesis) or contribute evidence to B/C's hypotheses.

### Agent B — Harness-entry direction

**Hypothesis formation strategy**: Start from the fuzzer, work backwards. Let the fuzzer tell you where the bug is.

1. Write AFL++ harness:
   ```c
   // /runs/SCEN-007/B/harness.c
   #include <png.h>
   int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
       png_image image = {0};
       image.version = PNG_IMAGE_VERSION;
       png_image_begin_read_from_memory(&image, data, size);
       if (image.width == 0 || image.height == 0) return 0;
       png_image_finish_read(&image, NULL, NULL, 0, NULL);
       return 0;
   }
   ```
2. Build with sanitizers + coverage:
   ```bash
   afl-clang-fast -fsanitize=address,undefined -g \
       /runs/SCEN-007/B/harness.c -I /targets/libpng-1.6.37/source \
       /targets/libpng-1.6.37/build/libpng.a -lz -o /runs/SCEN-007/B/harness
   ```
3. Seed corpus from PNG samples, run AFL++ for ~1 hour (or 100k execs):
   ```bash
   mkdir -p /runs/SCEN-007/B/corpus /runs/SCEN-007/B/findings
   afl-fuzz -i /runs/SCEN-007/B/corpus -o /runs/SCEN-007/B/findings \
            -m none -t 1000 -- /runs/SCEN-007/B/harness @@
   ```
4. Take first crash: `ls /runs/SCEN-007/B/findings/default/crashes/`
5. Symbolize and localize:
   ```bash
   ASAN_OPTIONS=symbolize=1 /runs/SCEN-007/B/harness \
       /runs/SCEN-007/B/findings/default/crashes/id:000000 2>&1 | asan_symbolize
   ```
6. Stack trace points at `png_read_row` line 412 → form hypothesis **H-B-001** with the crash as evidence. Write to memory.

### Agent C — Sanitizer direction

**Hypothesis formation strategy**: ASan/UBSan as the oracle. No source diff needed.

1. Build both binaries with ASan+UBSan (pre-built by coordinator — `/targets/.../{1.6.37,1.6.38}/build/libpng_asan.so`).
2. Run vulnerable build against a corpus of malformed PNGs:
   ```bash
   for f in /corpus/png/malformed/*.png; do
       ASAN_OPTIONS=detect_leaks=0:halt_on_error=0:log_path=/runs/SCEN-007/C/asan.log \
         /targets/libpng-1.6.37/build/png_read_asan "$f" >/dev/null 2>&1
   done
   ```
3. Parse the ASan log, extract stack traces:
   ```bash
   grep -A 20 "ERROR: AddressSanitizer" /runs/SCEN-007/C/asan.log.* | \
     asan_symbolize > /runs/SCEN-007/C/symbolized.txt
   ```
4. ASan reports `heap-buffer-overflow` in `png_read_row` at `pngpread.c:412` → form hypothesis **H-C-001**, write to memory with the symbolized trace as evidence.

### All agents — Iteration discipline

Every iteration MUST do exactly one of:

| Outcome | Memory update |
|---------|---------------|
| New evidence for active hypothesis | `vulnerability_hypotheses[].evidence_for += [...]`, bump `confidence` |
| Hypthesis falsified | `evidence_against += [...]`, status → `INVALIDATED`, release path |
| Stuck (no new evidence, 3rd attempt) | `failed_attempts += [...]`, switch path |
| Convergence with another agent | Both hypotheses → `CONFIRMED`, log to `decision_log` |

### Convergence check (council skill, every sync point)

```text
council input:
  - H-A-001: heap-buffer-overflow in png_read_row() @ pngpread.c:412  (claimed_by A)
  - H-B-001: AFL++ crash in png_read_row() @ pngpread.c:412           (claimed_by B)

council output:
  - VERDICT: hypotheses converge — same path, independent evidence vectors
  - ACTION: promote both to CONFIRMED, merge into canonical H-CONV-001
  - LOG: decision_log += "convergence: A∩B agree on pngpread.c:412"
```

### PoC generation + differential verification (verification-loop skill)

```bash
# 1. Generate PoC from confirmed hypothesis (use Agent A's angr-discovered input
#    OR Agent B's minimized crash OR synthesize from C's trigger corpus)
afl-tmin -i /runs/SCEN-007/B/findings/default/crashes/id:000000 \
         -o /runs/SCEN-007/poc.bin -- /runs/SCEN-007/B/harness @@

# 2. Differential verify
echo "[*] testing vulnerable build..."
ASAN_OPTIONS=detect_leaks=0 /targets/libpng-1.6.37/build/png_read_asan < /runs/SCEN-007/poc.bin \
  > /runs/SCEN-007/vuln-out.txt 2>&1; echo "exit=$?"

echo "[*] testing patched build..."
ASAN_OPTIONS=detect_leaks=0 /targets/libpng-1.6.38/build/png_read_asan < /runs/SCEN-007/poc.bin \
  > /runs/SCEN-007/patched-out.txt 2>&1; echo "exit=$?"

# Stop condition: vuln-out.txt contains "ERROR: AddressSanitizer: heap-buffer-overflow"
#                 patched-out.txt is clean, exit code 0
```

---

## Memory Schema Hooks

### Hook 1 — Before/after snapshot, Agent A iteration 1

**Before** (memory version 2, right after path claims settled):

```json
{
  "memory_lock": {"version": 2, "owner_agents": ["A","B","C"], "last_write_by": "C"},
  "vulnerability_hypotheses": [],
  "active_paths": {"A": "patch-diff", "B": "harness-entry", "C": "sanitizer"}
}
```

**After** Agent A writes H-A-001 (memory version 3):

```json
{
  "memory_lock": {"version": 3, "owner_agents": ["A","B","C"], "last_write_by": "A"},
  "vulnerability_hypotheses": [
    {
      "id": "H-A-001",
      "hypothesis": "heap-buffer-overflow in png_read_row() row-processing loop",
      "path": "pngpread.c:412",
      "evidence_for": [
        "BinDiff: function png_read_row changed in 1.6.38",
        "patch adds row_bytes < PNG_SIZE_MAX-8 guard at line 408"
      ],
      "evidence_against": [],
      "status": "LIKELY",
      "confidence": 0.55,
      "claimed_by": "A"
    }
  ],
  "active_paths": {"A": "patch-diff", "B": "harness-entry", "C": "sanitizer"},
  "decision_log": [
    {"by": "A", "decision": "claimed path patch-diff"},
    {"by": "B", "decision": "claimed path harness-entry"},
    {"by": "C", "decision": "claimed path sanitizer"},
    {"by": "A", "decision": "added hypothesis H-A-001"}
  ]
}
```

### Hook 2 — Convergence event (t=25min)

Triggered by council at sync point #3. Council detects `H-A-001.path == H-B-001.path` (`pngpread.c:412`) with independent evidence vectors.

```bash
# Convergence merge — coordinator executes this once, under flock
(
  flock -x 9 || exit 1
  tmp=$(mktemp)
  jq --argjson now "$(date -u +%FT%TZ | jq -R .)" \
    '.vulnerability_hypotheses |= map(
        if .id == "H-A-001" or .id == "H-B-001" then
          .status = "CONFIRMED"
          | .confidence = 0.88
          | .evidence_for = (.evidence_for + ["CONVERGENCE: 2 independent agents agree"])
        else . end)
    | .candidate_pocs += [{
        "id": "PoC-001",
        "based_on_hypothesis": "H-A-001",
        "input_shape": "PNG with row_bytes > PNG_SIZE_MAX-8",
        "expected_behavior": "ASan heap-buffer-overflow at pngpread.c:412",
        "status": "PENDING_VERIFICATION"
      }]
    | .memory_lock.version += 1
    | .decision_log += [{"at": $now, "by": "council",
        "decision": "CONVERGENCE: H-A-001 ∩ H-B-001 on pngpread.c:412 → both CONFIRMED, PoC-001 queued"}]' \
    /runs/SCEN-007/mem/exploit-attempt-memory.json > "$tmp"
  mv "$tmp" /runs/SCEN-007/mem/exploit-attempt-memory.json
) 9>/runs/SCEN-007/mem/exploit-attempt-memory.json.lock
```

### Hook 3 — Atomic-write pattern (canonical form, every agent uses this)

```bash
write_memory() {
  local agent="$1"; local jq_expr="$2"
  (
    flock -x 9 || exit 1
    local pre=$(jq '.memory_lock.version' "$MEM")
    local tmp=$(mktemp)
    jq --arg agent "$agent" --argjson pre "$pre" "$jq_expr" "$MEM" > "$tmp"
    # version guard
    local post=$(jq '.memory_lock.version' "$tmp")
    [ "$post" -eq "$((pre + 1))" ] || { echo "[conflict] $agent"; rm "$tmp"; exit 2; }
    # schema sanity (anti-pattern checks)
    jq -e '.active_paths | (group_by(.) | map(length) | max) <= 1' "$tmp" >/dev/null \
      || { echo "[deadlock] duplicate active path"; rm "$tmp"; exit 3; }
    mv "$tmp" "$MEM"
  ) 9>"$MEM.lock"
}
```

---

## Verification Points

- [ ] `exploit-attempt-memory.json` final version has ≥1 `candidate_pocs[]` entry with `status = "CONFIRMED"`
- [ ] At least 2 agents contributed independent evidence to the confirmed hypothesis (`claimed_by` field shows ≥2 distinct agents, or canonical hypothesis lists ≥2 contributing hypotheses)
- [ ] Differential verification passed: PoC crashes `/targets/libpng-1.6.37` with ASan heap-buffer-overflow, `/targets/libpng-1.6.38` exits clean with code 0
- [ ] No path-claim deadlock: `active_paths` values are unique at every observed version (anti-pattern check passes)
- [ ] `decision_log` contains the convergence event with both agents' contributions timestamped
- [ ] No agent performed an in-place edit — every memory write went through the atomic-write pattern (verifiable by grepping shell history for `mv "$tmp"`)
- [ ] Stop condition was set by differential verification, not by agent giving up (`convergence_state.stop_reason` references "differential verification")

---

## Worked Example — Timeline

| t | Event | Memory version | Agent |
|---|-------|---------------|-------|
| 0 | Coordinator bootstraps memory; 3 agents start, claim paths | 0 → 3 | coord + A/B/C |
| 10 min | A finishes BinDiff, writes **H-A-001** "heap-buffer-overflow in `png_read_row()` @ pngpread.c:412" | 4 | A |
| 15 min | C runs ASan corpus, captures crash, writes **H-C-001-pre** (still localizing) | 5 | C |
| 20 min | B's AFL++ finds first crash, symbolizes → writes **H-B-001** also pointing to `png_read_row()` @ pngpread.c:412 | 6 | B |
| 25 min | **CONVERGENCE** — council at sync point #3 detects `H-A-001.path == H-B-001.path`, promotes both to CONFIRMED, queues PoC-001 | 7 | council |
| 30 min | C finishes ASan symbolization, writes **H-C-001** with `evidence_for = ["ASan trace: pngpread.c:412 heap-buffer-overflow"]`, status CONFIRMED — 3rd independent confirmation, confidence → 0.95 | 8 | C |
| 35 min | Coordinator generates PoC via `afl-tmin` on B's crash, runs differential verification | — | coord |
| 40 min | Differential result: vulnerable → ASan heap-buffer-overflow exit 1; patched → clean exit 0. `candidate_pocs[0].status = CONFIRMED`, `convergence_state.stop_condition_met = true` | 9 | coord |
| 45 min | Final memory snapshot archived to `/runs/SCEN-007/final/exploit-attempt-memory.json`; distilled into `MEMORY.md` per kali-claw's memory hierarchy | — | coord |

**Wall-clock**: ~45 minutes for 3 parallel agents — vs. ~2 hours if a single agent ran all three directions serially.

---

## Defensive Perspective

### Compiler hardening that would have prevented this bug class

| Mitigation | How it stops this bug | Verification |
|------------|----------------------|--------------|
| `_FORTIFY_SOURCE=3` | `memcpy`/`malloc` calls get bounds-checked wrappers; the unchecked allocation at line 412 becomes a runtime trap | rebuild with `-D_FORTIFY_SOURCE=3 -O2`, rerun PoC — expect `__fortify_fail` abort |
| ASan in production builds | The same overflow would be caught on first hit instead of being a latent memory-corruption primitive | rebuild libpng with `-fsanitize=address`, ship in staging — ASan aborts before exploitation |
| CFI (`-fsanitize=cfi`) | Indirect-call hijacking after the corruption becomes non-exploitable even if the write succeeds | rebuild with `-fsanitize=cfi-cast-strict` |
| Stack canaries + RELRO + PIE | Standard hardening reduces exploit reliability for the overflow even if reachable | `checksec /targets/libpng-1.6.37/build/libpng.so` should show full RELRO + PIE |

### SOC detection rules for the multi-agent activity itself

The multi-agent pattern has a **detectable footprint** that a SOC should catch — multiple shells spawning in tight succession, atomic file writes to a shared memory file, parallel fuzzer processes, and cross-process `flock` contention.

```spl
# Splunk/SPL — detect the multi-agent exploitation pattern (detection-engineering skill)
index=endpoint sourcetype=bash_history
  ( "afl-fuzz" OR "libFuzzer" OR "bindiff" OR "angr" OR "asan_symbolize" )
  OR ( process_name=mv AND file_path="*exploit-attempt-memory.json" )
| stats count dc(host) as hosts by user, _time span=5m
| where count > 10
| alert

# Sigma rule for shared-memory lock contention
# Many flock() syscalls against the same file = parallel agents coordinating
detection:
  selection:
    EventID: 11  # File create on Linux via auditd
    FilePath|endswith: "exploit-attempt-memory.json.lock"
  condition: selection | count() by host > 5 in 1m
```

**Reference**: `detection-engineering` skill — the multi-agent footprint itself (multiple `afl-fuzz` instances, shared JSON writes, `flock` contention) is a high-fidelity signal that an offensive tool is running. Defenders should alert on the **coordination artifacts**, not just the individual tool invocations.

### What the defender takes away

1. The same shared-memory pattern that makes the offensive team fast (3 agents in 45 min) creates a noisy footprint. Lean into detection-engineering on the **coordination layer**, not just the exploit layer.
2. Compiler hardening (`_FORTIFY_SOURCE=3`, ASan in staging) is the cheapest win — it converts this from a 0-day into an abort.
3. Patch-diff attack is fast because maintainers' fixes are public oracles; defenders should assume any released patch will be reverse-engineered into a PoC within hours and pre-stage detections.
