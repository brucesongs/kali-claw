---
name: multi-agent-runtime-engineering
description: Runtime engineering discipline for agent systems — structured JSON memory schemas, memory-driven convergence rules, shared-memory multi-agent coordination via POSIX flock + atomic write + version vector, anti-pattern prevention, and topology selection. Solidifies the engineering patterns of SCEN-007 (shared-memory multi-agent exploit dev) and SCEN-MEMORY-SCHEMA (structured memory foundation) into a reusable knowledge base. Inspired by MopMonk Agent three招 (扫地僧, CyberGym 73.1%, China #1) — proving that harness engineering beats base-model parameter scaling.
origin: kali-claw Wave 12 (v0.1.45) — 2026-07-03
version: "0.2.0.2"
compatibility:
  kali_version: "2025.2"
  python_version: ">=3.11"
  jq_required: true
  flock_available: true
allowed-tools:
  - bash
  - jq
  - flock
  - python3
  - git
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - Agent
metadata:
  domain: agent-runtime
  tool_count: 12
  guide_count: 2
  mitre: "N/A — meta-skill (runtime engineering, not a specific ATT&CK technique)"
  last_reviewed: "2026-07-26"
---

# Multi-Agent Runtime Engineering Skill

> *"Harness engineering > base-model parameters. MopMonk took MiniMax M3 (smaller base) to 73.1% on CyberGym — beating Claude Opus 4.6 (66.6%) and matching GPT-5.4 (79.0%) within a stone's throw. The harness is the moat."* — adapted from 36kr's coverage of MopMonk Agent (扫地僧), 2026-06-30

## Summary

This skill is the **runtime engineering layer** for agent systems. It treats memory schemas, sync protocols, convergence rules, anti-pattern prevention, and topology selection as first-class engineering artifacts — the things that decide whether a multi-agent system actually converges on truth or spirals into hallucinated prose.

This skill **solidifies the engineering patterns of `validation/scenarios/SCEN-007.md` (Shared-Memory Multi-Agent Exploit Dev) and `validation/scenarios/SCEN-MEMORY-SCHEMA.md` (Structured Memory foundation) into a reusable knowledge base.** SCEN-007 is the live scenario that proves the pattern — three parallel agents (patch-diff, harness-entry, sanitizer) converging on CVE-2019-7317 in ~45 minutes wall-clock vs. ~2 hours serially. SCEN-MEMORY-SCHEMA is the underlying schema library. This skill abstracts both into the runtime discipline that kali-claw (or any agent harness) uses whenever it needs to coordinate memory across multiple workers, multiple phases, or multiple independent explorations of the same target.

**Why this skill exists as a distinct domain.** Three converging trends in 2024-2026 agent engineering make a dedicated runtime-engineering skill necessary. First, **MopMonk Agent (扫地僧)** demonstrated that a smaller base model (MiniMax M3) with disciplined harness engineering beats larger models with naive harnesses — 73.1% on CyberGym vs. Claude Opus 4.6's 66.6%. The "harness" in question is precisely the three layers this skill codifies: structured memory (招一), memory-driven convergence (招二), and shared-memory multi-agent coordination (招三). Second, **Anthropic's multi-agent research system** blog series (2024-2026) and the parallel work on **LangGraph, AutoGen, and Magentic-One** all converged on the same core primitives — atomic state writes, version vectors, convergence detection, and explicit topology choice — but each frames them in vendor-specific terms. Third, **kali-claw's own SCEN-007** showed that filesystem-native coordination (POSIX `flock` + `jq` + `mv`) is sufficient for multi-agent exploit dev with no DB, no message broker, and no framework dependency — a deliberately low-tech, high-reliability stack.

**What this skill does NOT cover.** It is not generic task decomposition (`multi-agent-collaboration`), not multi-perspective analysis (`council`), not pentest-framework deployment (`agentic-pentest`), and not knowledge persistence primitives (`continuous-learning`, `chronicle`). It is the engineering substrate underneath all of those — the schema design, sync protocol, and convergence rulebook that any of those higher-level skills may invoke when they need persistent structured memory across parallel workers.

Distinct from adjacent skills:

| Skill | Scope | Relationship to this skill |
|-------|-------|----------------------------|
| `multi-agent-collaboration` | Generic task decomposition + coordinator-worker topology | Provides the *decomposition logic*; this skill provides the *runtime substrate* (memory, sync, convergence) that decomposition runs on top of |
| `council` | Multi-perspective analysis (Attack / Defense / Audit viewpoints) | Council emits *judgments*; this skill defines how those judgments get written to a shared memory and merged when multiple councils run in parallel |
| `agentic-pentest` | Deploying LLM-driven pentest frameworks (PentestGPT, HexStrike, Viper) | Those frameworks have their own internal state; this skill is the *external* shared-memory layer between multiple framework instances |
| `continuous-learning` / `chronicle` | Knowledge persistence primitives (prose logs, distilled memory) | Those persist *prose*; this skill persists *structured JSON* — the two layers compose, they do not compete |
| `verification-loop` | Independent re-run of agent claims | Verification reads from the structured memory this skill defines; the memory's `evidence_for` / `evidence_against` fields are how verification results land |
| `autonomous-loops` | Generic loop constructs (sequential, watch, batch, learning) | Loops are the *control flow*; this skill is the *state layer* the loops read and write |
| `engagement-manager` | Kill-chain phase orchestration (human-readable) | Engagement manager decides *what phase to run*; this skill decides *how multiple parallel workers inside a phase share state* |

## Use Cases

### Schema Design

1. **Design a structured memory JSON for a multi-phase pentest engagement** (recon → intrusion → privilege escalation → lateral → exfil) where each phase reads the prior phase's structured findings and writes a delta
2. **Define an exploit-attempt memory schema for parallel-exploit dev** — multiple agents writing hypotheses, evidence, failed attempts, and candidate PoCs to one shared file
3. **Define a patch-diff reproduction memory schema** — schema for "given a patch, reproduce the underlying bug and generate a differentially-verified PoC" (CyberGym-style)
4. **Retrofit a prose-only memory system with structured fields** — convert legacy `MEMORY.md`散文 into a JSON companion without losing the curated distilled knowledge
5. **Federate engagement memory with long-term knowledge** — schema design where per-engagement JSON distills back into the root `MEMORY.md` at engagement close, same pattern kali-claw's daily logs follow

### Atomic-Write Sync

6. **Coordinate 3 parallel exploit-dev agents against one shared memory file** (SCEN-007 case: patch-diff + harness-entry + sanitizer)
7. **Prevent lost-update when two agents write different fields simultaneously** — version-vector guard detects conflict and retries
8. **Implement path-claim coordination** — agents claim a unique exploration path (no duplicate `active_paths` values) using `flock` + atomic write
9. **Detect and recover from path-claim deadlock** — schema validation rejects any write where `active_paths` has duplicates
10. **Build a coordinator script that bootstraps memory, dispatches agents, and aggregates final state** — the literal harness from SCEN-007 Phase 0
11. **Tolerate agent crash mid-write** — `mktemp` + `mv` pattern ensures the memory file is never half-written; the temp file is GC'd on next coordinator pass

### Convergence Detection

12. **Detect when 2+ agents independently arrive at the same hypothesis** — same `path` field, different `claimed_by` → promote both to `CONFIRMED` and emit convergence event
13. **Promote a hypothesis from `LIKELY` to `CONFIRMED` on third independent evidence vector** (triangulation principle)
14. **Demote a hypothesis to `INVALIDATED` after 3 failed attempts with no new evidence** — path-switch trigger fires
15. **Run a periodic sync-point convergence sweep** — every N iterations, an external observer scans the memory for convergence events and emits decisions
16. **Detect premature stop** — agent tried to mark `stop_condition_met = true` without filling `verification_results`; schema validation blocks the write
17. **Generate a convergence timeline** for post-engagement analysis — "at t=25min, agents A∩B converged on path X; at t=40min, differential verification passed"

### Anti-Pattern Prevention

18. **Detect free-form exploration** — agent ran commands without reading memory first; `memory_lock.last_read_at` is null when write attempted
19. **Detect memory drift** — agent wrote prose to `decision_log` that references a finding not present in `findings[]`
20. **Detect repeat-without-delta** — same hypothesis tested 3+ times with no new evidence in `evidence_for` or `evidence_against`
21. **Detect path-claim deadlock** — two agents both wrote the same value to `active_paths`
22. **Detect premature stop** — stop condition claimed without differential verification
23. **Build a checker script that runs after every memory write** — schema validation + anti-pattern checks in one jq pipeline

### Topology Selection

24. **Choose between parallel-explorers / pipeline / council / hierarchical topology** based on task shape (bug-class exploration vs. phase-sequential vs. multi-perspective judgment vs. coordinator-fanout)
25. **Decide when NOT to use multi-agent** — single-target linear attack chains (use `autonomous-loops` Sequential Pipeline instead)
26. **Decide when to use council-style multi-perspective analysis** (one question, three lenses) vs. **parallel-explorers** (one target, three directions)
27. **Mix topologies within one engagement** — parallel-explorers for recon, pipeline for exploit chain, council for the final risk judgment
28. **Decide coordinator-vs-peer protocol** — coordinator simplifies reasoning but adds a bottleneck; peer-to-peer is robust but harder to reason about

## Core Tools

### jq Patterns for Memory Operations

| Pattern | Use |
|---------|-----|
| `jq '.memory_lock.version' mem.json` | Read current version (for optimistic concurrency) |
| `jq --arg agent "$A" --arg path "$P" '.active_paths[$agent] = $path | ...' mem.json` | Path claim |
| `jq '.active_paths | (group_by(.) | map(length) | max) <= 1' mem.json` | Deadlock check (no duplicate paths) |
| `jq '[.vulnerability_hypotheses[] | select(.status != "INVALIDATED") | .path]' mem.json` | Convergence scan input |
| `jq -e '.convergence_state.stop_condition_met == true and .verification_results.vulnerable != null' mem.json` | Premature-stop check |
| `jq --argjson now "$(date -u +%FT%TZ | jq -R .)" '.decision_log += [{"at": $now, ...}]' mem.json` | Decision-log append |
| `jq '.failed_attempts | group_by(.hypothesis) | map(select(length >= 3))' mem.json` | Repeat-without-delta detection |
| `jq -e '.findings | length > 0 and (.decision_log | any(.finding_ref != null and .finding_ref as $f | .findings | has($f)))' mem.json` | Memory-drift check |

### POSIX flock Patterns

| Pattern | Use |
|---------|-----|
| `( flock -x 9 || exit 1; ... ) 9>mem.lock` | Exclusive lock around read-modify-write |
| `( flock -s 9 || exit 1; ... ) 9>mem.lock` | Shared lock for read-heavy passes (convergence scans) |
| `flock -x -w 30 9 || exit 1` | Lock with 30s timeout (avoid indefinite block) |
| `flock -n 9 || exit 1` | Non-blocking lock (fail fast if contended) |

### Atomic Write Pattern (canonical)

```bash
# Canonical atomic write — every memory update goes through this
write_memory() {
  local mem="$1" agent="$2" jq_expr="$3"
  (
    flock -x -w 30 9 || { echo "[fatal] lock timeout"; exit 1; }
    local pre; pre=$(jq '.memory_lock.version' "$mem")
    local tmp; tmp=$(mktemp)
    jq --arg agent "$agent" --argjson pre "$pre" "$jq_expr" "$mem" > "$tmp" || { rm "$tmp"; exit 2; }
    local post; post=$(jq '.memory_lock.version' "$tmp")
    [ "$post" -eq "$((pre + 1))" ] || { echo "[conflict] $agent version mismatch"; rm "$tmp"; exit 3; }
    # anti-pattern sanity: no duplicate active_paths
    jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$tmp" >/dev/null \
      || { echo "[deadlock] $agent duplicate path"; rm "$tmp"; exit 4; }
    # premature-stop guard
    jq -e '.convergence_state.stop_condition_met // false | not or (.verification_results.vulnerable != null and .verification_results.patched != null)' "$tmp" >/dev/null \
      || { echo "[premature-stop] $agent"; rm "$tmp"; exit 5; }
    mv "$tmp" "$mem"
  ) 9>"$mem.lock"
}
```

### Python Helpers

| Helper | Purpose |
|--------|---------|
| `python3 validate_schema.py mem.json` | Schema validation (required fields, types, confidence-level taxonomy) |
| `python3 detect_convergence.py mem.json` | Scan for hypotheses pointing at same `.path` from different `claimed_by` |
| `python3 detect_anti_patterns.py mem.json` | All 5 anti-pattern checks in one pass |
| `python3 timeline.py mem.json` | Render `decision_log` as a wall-clock timeline |
| `python3 federation_distill.py engagement.json >> MEMORY.md` | Engagement-close: distill JSON memory back into prose `MEMORY.md` |

### Shell Idioms

| Idiom | Use |
|-------|-----|
| `tmp=$(mktemp); jq ... mem > "$tmp"; mv "$tmp" mem` | Atomic write without lock (single-agent case) |
| `grep -c '"decision":' mem.json` | Quick decision-log length check |
| `git diff --no-index mem.json.old mem.json | jq -R '...'` | Memory diff for audit trail |
| `sha256sum evidence/*.txt > evidence_index.sha256` | Evidence integrity (paired with `evidence_index` in schema) |

## Methodology — The 5-Layer Runtime Stack

This skill organizes agent runtime engineering into five layers, each building on the one below. A mature harness implements all five; a naive harness may only implement the first one or two (and pays for it in hallucination, deadlock, and lost work).

```
+------------------------------------------------------------------+
| Layer 5 — Topology Selection                                     |
|   parallel-explorers / pipeline / council / hierarchical         |
|   choose the right shape per task                                |
+------------------------------------------------------------------+
| Layer 4 — Anti-Pattern Prevention                                |
|   5 forbidden patterns detected before write commits             |
|   free-form / drift / repeat / deadlock / premature-stop         |
+------------------------------------------------------------------+
| Layer 3 — Convergence Detection                                  |
|   multi-agent independent arrival → CONFIRMED promotion          |
|   failed-attempt accounting → path-switch                        |
+------------------------------------------------------------------+
| Layer 2 — Atomic Sync                                            |
|   POSIX flock + mktemp+mv + version vector                       |
|   no DB, no broker, filesystem-native                            |
+------------------------------------------------------------------+
| Layer 1 — Structured Memory                                      |
|   JSON schema with required fields, confidence taxonomy          |
|   machine-queryable (no散文 prose)                                |
+------------------------------------------------------------------+
```

### Layer 1 — Structured Memory (MopMonk 招一)

Every engagement maintains a machine-queryable memory JSON. No散文 prose memory. The agent must be able to query "what did we learn about X?" and get a deterministic answer. Every phase MUST: read the current memory file, execute its phase task, write a delta (fields added / updated / invalidated), and update `next_constraints` so downstream phases know the boundaries.

This skill ships three canonical schemas: **Pentest Engagement Memory** (Schema 1 — for cross-phase engagements), **Exploit Attempt Memory** (Schema 2 — for parallel exploit dev), and **Patch-Diff Reproduction Memory** (Schema 3 — for CyberGym-style PoC generation). Full templates are in `payloads.md`.

### Layer 2 — Atomic Sync (MopMonk 招三 foundation)

When multiple agents read/write the same memory file, every update goes through the canonical atomic-write pattern: take `flock` advisory lock on a sidecar `.lock` file → read current memory → apply jq transform to a `mktemp` temp file → validate (version-vector guard + anti-pattern checks) → `mv` temp to real path (POSIX atomic). No agent ever edits the JSON in place. Conflict resolution is optimistic concurrency: each write must increment `memory_lock.version` by exactly 1; a version mismatch aborts the write and the agent retries.

### Layer 3 — Convergence Detection (MopMonk 招二)

Open-ended trial-and-error is forbidden. Every action must either produce new evidence (update an `evidence_for` / `evidence_against` field, bump `confidence`) or be aborted and trigger a path switch. The rule is encoded in `convergence_state.failed_attempts_on_active_path` — when it hits `path_switch_threshold` (typically 3), the agent releases its current path and picks a new one from `candidate_paths`. Convergence events fire when 2+ hypotheses point at the same `path` field with different `claimed_by` — those get promoted to `CONFIRMED` and merged into a canonical hypothesis.

### Layer 4 — Anti-Pattern Prevention

Five forbidden behaviors, each with a machine-checkable detection rule. The atomic-write pattern (Layer 2) runs the checks before `mv`; if any check fails, the write is rejected and the agent must fix its state. The five anti-patterns: **free-form exploration** (write without prior read), **memory drift** (decision log references finding not in `findings[]`), **repeat-without-delta** (3+ failed attempts on same hypothesis with no new evidence), **path-claim deadlock** (two agents grab same path), **premature stop** (stop claimed without differential verification). Detection rules in `payloads.md` §17-§21.

### Layer 5 — Topology Selection

Not every task benefits from the same agent topology. **Parallel-explorers** (SCEN-007) fits bug-class exploration where multiple independent directions increase the chance of convergence. **Pipeline** fits phase-sequential work (recon → exploit → report). **Council** fits questions where the same input needs three analytical lenses (Attack / Defense / Audit). **Hierarchical coordinator-worker** fits dynamic engagements where task dependencies shift. The topology matrix in `payloads.md` §22 guides selection; the rule of thumb is "as parallel as possible, as coordinated as necessary."

## MopMonk Three招 Mapping

The MopMonk Agent (扫地僧) three招 map directly onto this skill's 5-layer stack:

| MopMonk 招 | kali-claw Layer | Implementation |
|-----------|----------------|----------------|
| **招一 — Structured Vulnerability Memory** (结构化的漏洞记忆) | Layer 1 — Structured Memory | Three canonical JSON schemas (engagement / exploit-attempt / patch-diff-repro) with required fields, confidence taxonomy, evidence index, decision log |
| **招二 — Memory-Driven Convergence** (记忆驱动的漏洞挖掘) | Layer 3 — Convergence Detection | Every action yields a delta or triggers path switch; `failed_attempts_on_active_path` threshold drives path switches; convergence events promote hypotheses to `CONFIRMED` |
| **招三 — Shared-Memory Multi-Agent** (共享记忆的多 Agent 并行) | Layers 2 + 5 — Atomic Sync + Topology | POSIX `flock` + atomic write + version vector across N parallel agents; topology choice (parallel-explorers for bug-class, pipeline for phase-sequential) |

The fourth implicit招 — the meta-principle — is **"Harness > Parameters"**: the same base model with a disciplined harness dramatically outperforms the same model with a naive harness. MopMonk's MiniMax M3 (smaller base) at 73.1% beats Claude Opus 4.6 (larger base) at 66.6% — the gap is harness engineering, not model capacity.

## Practical Steps

### Step A — Bootstrap an Exploit Attempt Memory (Schema 2)

```bash
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

### Step B — Path Claim (3 agents, race-safe)

```bash
AGENT_ID=A
CLAIM_PATH=patch-diff
MEM=/runs/SCEN-007/mem/exploit-attempt-memory.json

(
  flock -x -w 30 9 || exit 1
  tmp=$(mktemp)
  jq --arg agent "$AGENT_ID" --arg path "$CLAIM_PATH" \
    '.active_paths[$agent] = $path
     | .memory_lock.owner_agents = (.active_paths | keys)
     | .memory_lock.version += 1
     | .memory_lock.last_write_at = (now | todateiso8601)
     | .memory_lock.last_write_by = $agent
     | .decision_log += [{"at": (now | todateiso8601), "by": $agent,
                          "decision": ("claimed path " + $path)}]' \
    "$MEM" > "$tmp"
  # anti-pattern check: no duplicate paths
  jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$tmp" >/dev/null \
    || { echo "[deadlock] $AGENT_ID"; rm "$tmp"; exit 2; }
  mv "$tmp" "$MEM"
) 9>"$MEM.lock"
```

### Step C — Hypothesis Write (with version-vector guard)

```bash
AGENT_ID=A
HYP_ID=H-A-001
HYP_TEXT="heap-buffer-overflow in png_read_row() row-processing loop"
HYP_PATH="pngpread.c:412"
EVIDENCE='["BinDiff: function png_read_row changed in 1.6.38", "patch adds row_bytes guard at line 408"]'
MEM=/runs/SCEN-007/mem/exploit-attempt-memory.json

(
  flock -x -w 30 9 || exit 1
  BEFORE=$(jq '.memory_lock.version' "$MEM")
  tmp=$(mktemp)
  jq --arg agent "$AGENT_ID" --arg hid "$HYP_ID" --arg htext "$HYP_TEXT" \
     --arg hpath "$HYP_PATH" --argjson ev "$EVIDENCE" --argjson prever "$BEFORE" \
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
    "$MEM" > "$tmp"
  AFTER=$(jq '.memory_lock.version' "$tmp")
  [ "$AFTER" -eq "$((BEFORE + 1))" ] || { echo "[conflict] $AGENT_ID"; rm "$tmp"; exit 2; }
  mv "$tmp" "$MEM"
) 9>"$MEM.lock"
```

### Step D — Convergence Detection (run at each sync point)

```bash
# Detect: 2+ hypotheses pointing at the same path with different claimed_by
MEM=/runs/SCEN-007/mem/exploit-attempt-memory.json

jq -r '
  [.vulnerability_hypotheses[] | select(.status != "INVALIDATED")] as $h
  | ($h | group_by(.path) | map(select(length >= 2)) | map(map(.claimed_by) | unique | length >= 2) | any) as $converged
  | if $converged then
      "CONVERGENCE: " + (
        $h | group_by(.path) | map(select(length >= 2)) | map(
          .[0].path + " (agents: " + (map(.claimed_by) | unique | join(",")) + ")"
        ) | join("; ")
      )
    else "no convergence yet" end
' "$MEM"
```

### Step E — Anti-Pattern Checker (run after every write)

```bash
MEM=/runs/SCEN-007/mem/exploit-attempt-memory.json
python3 - <<'PY' "$MEM"
import json, sys, datetime
mem = json.load(open(sys.argv[1]))
violations = []

# AP-1 free-form exploration: write attempted without prior read
if mem.get("memory_lock", {}).get("last_write_at") and not mem.get("memory_lock", {}).get("last_read_at"):
    violations.append("AP-1 free-form exploration")

# AP-3 repeat-without-delta: 3+ failed attempts on same hypothesis with no new evidence
from collections import Counter
fails = Counter(f.get("hypothesis") for f in mem.get("failed_attempts", []))
for hyp, n in fails.items():
    if n >= 3:
        violations.append(f"AP-3 repeat-without-delta on {hyp}: {n} failed attempts")

# AP-4 path-claim deadlock: duplicate active_paths values
paths = list(mem.get("active_paths", {}).values())
if len(paths) != len(set(paths)):
    violations.append(f"AP-4 path-claim deadlock: {paths}")

# AP-5 premature stop
cs = mem.get("convergence_state", {})
vr = mem.get("verification_results", {})
if cs.get("stop_condition_met") and (not vr.get("vulnerable") or not vr.get("patched")):
    violations.append("AP-5 premature stop without differential verification")

if violations:
    print("[ANTI-PATTERN]", "; ".join(violations))
    sys.exit(1)
print("[OK] no anti-patterns")
PY
```

### Step F — Differential Verification (the stop condition)

```bash
# Vulnerable build must crash, patched build must be clean
ASAN_OPTIONS=detect_leaks=0 /targets/libpng-1.6.37/build/png_read_asan < /runs/SCEN-007/poc.bin \
  > /runs/SCEN-007/vuln-out.txt 2>&1
ASAN_OPTIONS=detect_leaks=0 /targets/libpng-1.6.38/build/png_read_asan < /runs/SCEN-007/poc.bin \
  > /runs/SCEN-007/patched-out.txt 2>&1

if grep -q "ERROR: AddressSanitizer: heap-buffer-overflow" /runs/SCEN-007/vuln-out.txt && \
   ! grep -q "ERROR:" /runs/SCEN-007/patched-out.txt; then
  echo "[CONFIRMED] differential verification passed"
  # write the stop condition into memory
  write_memory "$MEM" "verifier" '
    .convergence_state.stop_condition_met = true
    | .convergence_state.stop_reason = "differential verification passed"
    | .verification_results = {
        "vulnerable": {"crashed": true, "log": "vuln-out.txt"},
        "patched": {"crashed": false, "log": "patched-out.txt"}
      }
    | .memory_lock.version += 1
  '
else
  echo "[NOT YET] differential verification failed"
fi
```

## Anti-Pattern Catalog

Five forbidden behaviors. Each has a detection rule (machine-checkable) and a remediation (what the agent must do to recover).

| # | Name | Description | Detection | Remediation |
|---|------|-------------|-----------|-------------|
| 1 | **Free-form exploration** | Agent runs commands without reading memory first | `memory_lock.last_read_at` is null when write attempted | Force agent to re-read memory before any further action; log violation to `decision_log` |
| 2 | **Memory drift** | Agent writes prose to `decision_log` that references a finding not present in `findings[]` | `decision_log[].finding_ref` references a key missing from `findings` or `vulnerability_hypotheses` | Reject write; require agent to first add the finding to the proper collection, then re-link |
| 3 | **Repeat-without-delta** | Same hypothesis tested 3+ times with no new evidence in `evidence_for` or `evidence_against` | `failed_attempts` grouped by hypothesis has any entry with length >= 3 AND no corresponding evidence added since first attempt | Force path switch: release current path, pick from `candidate_paths`, reset `failed_attempts_on_active_path` to 0 |
| 4 | **Path-claim deadlock** | Two agents both wrote the same value to `active_paths` | `active_paths` values has duplicates | Schema validation rejects write; second agent must retry with a different path or wait |
| 5 | **Premature stop** | Agent calls stop without differential verification | `convergence_state.stop_condition_met == true` but `verification_results.vulnerable` or `verification_results.patched` is null | Reject write; require agent to run differential verification first |

## Defense Perspective

The same runtime engineering patterns that make offensive multi-agent systems converge are the patterns that make defensive multi-analyst teams effective. The skill is symmetric.

- **SOC playbook parallelism**: multiple analysts can update a shared IOC memory in parallel using the same atomic-write protocol. No more "I overwrote your finding" or "we both ran the same hunt." Version vectors and path claims work identically for defensive teams.
- **Threat hunting coordination**: structured hypothesis memory prevents the "tried that, didn't work" repetition that plagues ad-hoc hunting teams. Every hunt writes a hypothesis entry; every dead-end writes a `failed_attempt`; the next hunter sees what was already tried and pivots instead of repeating.
- **IOC triangulation**: three analysts independently arriving at the same IOC = high-confidence promotion (same convergence logic as exploit-dev hypotheses). The `claimed_by` field becomes `analyst_id`; the `path` field becomes the IOC value.
- **Detection-as-code multi-author review**: shared Sigma / YARA memory with version vector prevents rule-clobbering when two detection engineers edit the same rule in parallel. Same atomic-write pattern; same conflict-resolution rule.
- **What the defender takes away**: the offensive team's shared-memory footprint is itself a detection signal. Multiple `afl-fuzz` instances, parallel `jq` writes to a shared JSON, `flock` contention on a sidecar `.lock` file — these are high-fidelity indicators that an offensive multi-agent tool is running. Build Sigma rules on the *coordination artifacts*, not just the individual tool invocations.

Cross-references: `threat-hunting`, `detection-engineering`, `logging-monitoring`, `soc-foundation`.

## Hacker Laws Alignment

This skill embodies several of kali-claw's 12 Hacker Laws:

- **Law of Composition** — multi-agent systems are compositional; the runtime layer (this skill) composes with the decomposition layer (`multi-agent-collaboration`) and the analysis layer (`council`). Each must be independent for the system to be reliable.
- **Law of Convergence** — multiple independent evidence vectors arriving at the same conclusion is the strongest signal of truth. The convergence-detection layer codifies this.
- **Law of Evidence over Assertion** — every claim must land in an evidence field; every assertion must be backed by a tool output indexed in `evidence_index` with a `sha256`. Prose memory violates this; structured memory enforces it.
- **Law of Failure-Driven Learning** — `failed_attempts` is a first-class field. Failed explorations are not wasted; they constrain the next iteration via `next_constraints`.
- **Law of the Harness** (a 2026 addition, codified post-MopMonk) — *the harness is the moat, not the base model.* A disciplined runtime beats a larger parameter count. This is the meta-principle that justifies treating runtime engineering as a first-class skill domain.

## Detection Methods

### Runtime Architecture Audit
- **Schema validation**: Memory schema (Schema 1/2/3) validation failures; anomalies in memory structure.
- **Convergence detection**: Multiple agents independently arriving at same conclusion (signal of correct convergence or coordinated attack).
- **Anti-pattern emergence**: Detect free-form exploration, memory drift, repeat-without-delta, path-claim deadlock, premature stop.
- **Version vector anomalies**: Inconsistent version vectors across agents; replication lag exploitation.

### SIEM Detection Rules
- **Splunk SPL**: `index=agent memory.schema_version=* | stats count by agent_id | where count > 1000`
- **LangSmith / Helicone**: Trace analysis for convergence detection.
- **Custom runtime monitoring**: Atomic write / POSIX flock violation detection.

## Defense Evasion Techniques

### Memory-Driven Convergence Stealth
- **Slow memory updates**: Pace memory writes below anomaly threshold.
- **Match existing schema**: Use legitimate schema fields; appears as normal memory update.
- **Trigger-based activation**: Memory poisoning activates only on specific input pattern.

### Coordination Attack Stealth
- **Distributed consensus attack**: Multiple compromised agents converge on malicious action.
- **Version vector manipulation**: Forge version vectors to bypass conflict resolution.
- **POSIX flock abuse**: Hold lock longer than expected; force serialization of legitimate agents.

### Anti-Pattern Exploitation
- **Free-form exploration abuse**: Exploit agents that explore freely; inject poison in exploratory paths.
- **Memory drift exploitation**: Use drifted memory state as attack vector.
- **Repeat-without-delta abuse**: Force agents to repeat without progress; consume resources.
- **Premature stop exploitation**: Trick agents into premature termination; disrupts coordination.

### Shared Memory Stealth
- **Use existing shared state**: Don't create new shared memory; abuse existing KV store.
- **Cross-process token theft**: Steal agent token from shared memory; reuse in another agent.
- **Gradual trust building**: Build up reputation in shared state over time; exploit at scale.

## Learning Resources

- **MopMonk Agent (扫地僧) — CyberGym 73.1% case study**, `docs/mopmonk-research-and-kali-claw-plan.md` — kali-claw's internal MopMonk research (2026-06-30), documenting the three招 and the "Harness > Parameters" thesis. This skill is the direct engineering response to that research.
- **Berkeley CyberGym paper (ICLR 2026)** — arXiv:2506.02548, OpenReview `2YvbLQEdYt`. The benchmark that made the harness-vs-base-model debate quantitative. 1,507 real vulnerabilities from 188 open-source projects; agent must produce a PoC that triggers on vulnerable build and is clean on patched build.
- **Anthropic Multi-Agent Research System blog series (2024-2026)** — Anthropic's published patterns for multi-agent coordination, including sub-agent delegation, shared state, and convergence detection. Vendor framing, but the primitives are the same as this skill.
- **LangGraph / LangChain docs** — production graph-based agent orchestration with checkpointed state. The "checkpoint" primitive in LangGraph is exactly this skill's atomic-write pattern, expressed in Python instead of shell.
- **AutoGen paper (Microsoft, 2023-2024)** — multi-agent conversation framework. The "GroupChat" manager is one topology choice from this skill's Layer 5; the underlying state sync is the same.
- **Magentic-One paper (Microsoft, 2024)** — generalist multi-agent system with a fixed four-role topology (Organizer / WebSurfer / FileSurfer / Coder). A concrete reference implementation of the hierarchical coordinator-worker topology from Layer 5.
- **CrewAI docs** — role-based agent framework. The "Crew" primitive is parallel-explorers topology with role-specialized agents; useful contrast to shared-memory atomic-write pattern (CrewAI uses task handoff, this skill uses shared file).
- **OpenAI Swarm (2024)** — lightweight handoff-based multi-agent pattern. Contrast: Swarm's handoff is a peer-to-peer message; this skill's atomic-write is a shared-state mutation. The tradeoffs are documented in `guides/real-world-incident-case-studies.md`.
- **Cognition Devin public writeups (2024-2025)** — long-horizon agent system; public technical posts describe their memory schema and concurrency model. Useful as a real-world reference for schema design at scale.

> Structured payloads in `payloads.md`, complete test cases in `test-cases.md`, deep-dive playbooks in `guides/multi-agent-runtime-engineering-playbook.md` and `guides/real-world-incident-case-studies.md`.
