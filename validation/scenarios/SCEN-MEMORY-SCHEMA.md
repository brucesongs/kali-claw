# SCEN-MEMORY-SCHEMA: Structured Memory Foundation for v0.1.44 Scenarios

> **What this is**: The shared structured-memory schema that powers SCEN-006 / SCEN-007 / SCEN-008.
> **Why it exists**: Inspired by MopMonk Agent's three招 (structured vulnerability memory + memory-driven convergence + shared-memory multi-agent), adapted for kali-claw's workspace.
> **Used by**: scenario-runner.sh, orchestrator.sh, and any agent that needs to chain multiple skill domains with persistent context.

---

## Design Principles (三招 in kali-claw terms)

### 招一 — Structured Memory (结构化记忆)

Every engagement maintains a **machine-queryable memory JSON**. No散文体 prose memory. The agent must be able to query "what did we learn about X?" and get a deterministic answer.

```yaml
memory_principle: |
  For every phase of an engagement, the agent MUST:
  1. Read the current memory file
  2. Execute its phase task
  3. Write a delta — fields added, updated, or invalidated
  4. Update next_constraints so downstream phases know the boundaries
```

### 招二 — Memory-Driven Convergence (记忆驱动收敛)

Open-ended trial-and-error is forbidden. Every action must either:
- **Produce new evidence** that updates a memory field, OR
- **Be aborted** and the agent switches path

```yaml
convergence_rule: |
  if action.yielded_new_evidence == false:
    memory.failed_attempts += 1
    if memory.failed_attempts >= memory.path_switch_threshold:
      memory.active_path = pick_next_path(memory.candidate_paths)
      memory.failed_attempts = 0
    abort_action()
  else:
    memory.confidence += computed_confidence_delta
```

### 招三 — Shared-Memory Multi-Agent (共享记忆多 Agent)

When a task benefits from parallel exploration, multiple agents run concurrently against the **same memory file**. A coordination protocol (file-lock + atomic-write) prevents clobbering. Agents explicitly claim paths and release them.

```yaml
multi_agent_protocol:
  - agent_id: A
    claimed_paths: [patch-diff]
    released_signals: [patch-diff:done, patch-diff:stuck]
  - agent_id: B
    claimed_paths: [harness-entry]
    released_signals: [harness-entry:done]
  - shared_memory: exploit-attempt-memory.json
  - sync_method: atomic_write_with_version_vector
```

---

## Schema 1 — Pentest Engagement Memory (SCEN-006)

**File**: `engagement-memory.json` (per engagement, in `validation/evidence/scenarios/SCEN-006/<engagement-id>/`)

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
    {"phase": "recon", "started_at": "...", "ended_at": "...", "status": "completed"}
  ],
  "findings": {
    "entry_points": [
      {"target": "web.example.com:443", "type": "https", "confidence": "CONFIRMED", "evidence": ["nmap-01.txt"]},
      {"target": "vpn.example.com:443", "type": "ssl-vpn", "confidence": "LIKELY", "evidence": ["nmap-02.txt"]}
    ],
    "credentials": [],
    "vulnerabilities": [],
    "lateral_pivots": []
  },
  "evidence_index": {
    "nmap-01.txt": {"collected_at": "...", "phase": "recon", "sha256": "..."}
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
  "decision_log": [
    {"at": "...", "decision": "switched path from vpn-credential-brute to web-api-fuzzing", "reason": "3 failed attempts yielded no new evidence"}
  ]
}
```

**Confidence levels** (triangulation principle from deep-research skill):
- `CONFIRMED` — 3 independent evidence vectors
- `LIKELY` — 2 vectors or 1 authoritative vector
- `POSSIBLE` — 1 vector, plausible
- `UNVERIFIED` — hypothesis only

---

## Schema 2 — Exploit Attempt Memory (SCEN-007)

**File**: `exploit-attempt-memory.json` (shared across parallel agents)

```json
{
  "schema_version": "1.0",
  "target": {
    "binary": "/targets/crashme-v1.2",
    "type": "ELF x86-64",
    "source_available": false,
    "patch_diff": "v1.2_v1.3.patch",
    "sanitizer_enabled": "ASan+UBSan"
  },
  "memory_lock": {
    "version": 17,
    "owner_agents": ["A", "B", "C"],
    "last_write_at": "...",
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
      "claimed_by": "A"
    },
    {
      "id": "H-002",
      "hypothesis": "Integer overflow in length calculation",
      "path": "src/parser.c:398",
      "evidence_for": [],
      "evidence_against": ["Input size up to 2GB doesn't trigger"],
      "status": "INVALIDATED",
      "confidence": 0.05,
      "claimed_by": "C"
    }
  ],
  "candidate_pocs": [
    {
      "id": "PoC-001",
      "based_on_hypothesis": "H-001",
      "input_shape": "JSON with 65536-byte string value",
      "expected_behavior": "ASan heap-buffer-overflow",
      "actual_behavior": "ASan triggered ✓",
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
      "ended_at": "..."
    }
  ],
  "active_paths": {
    "A": "patch-diff",
    "B": "harness-entry",
    "C": "sanitizer"
  },
  "convergence_state": {
    "iterations": 23,
    "confirmed_poc": "PoC-001",
    "stop_condition_met": true,
    "stop_reason": "Differential verification passed on vulnerable AND patched versions"
  }
}
```

**Path switch rule**: An agent releases its path and picks a new one when:
1. Its hypothesis is `CONFIRMED` (success → move to verification or stop)
2. Its hypothesis is `INVALIDATED` (dead end → pick another candidate)
3. `failed_attempts >= 3` on the current hypothesis without evidence delta (stuck)

---

## Schema 3 — Patch-Diff Reproduction Memory (SCEN-008)

**File**: `repro-attempt-memory.json`

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
    "entry_function": "main() → parse_input()",
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
    "vulnerable": {"crashed": true, "sanitizer_output": "..."},
    "patched": {"crashed": false, "sanitizer_output": "clean"}
  },
  "convergence_state": {
    "iterations": 4,
    "status": "POC_CONFIRMED_DIFFERENTIALLY",
    "next_action": "Document PoC + write detection rule"
  }
}
```

---

## Convergence Anti-Patterns (Forbidden Behaviors)

These are explicit "do not do this" rules. The scenario-runner checks for them:

```yaml
anti_patterns:
  - name: "Free-form exploration"
    description: "Agent runs commands without reading memory first"
    detection: "memory_lock.last_read_at is null when write attempted"

  - name: "Memory drift"
    description: "Agent writes prose findings without updating a structured field"
    detection: "decision_log entry references finding not in findings[]"

  - name: "Repeat-without-delta"
    description: "Same hypothesis tested >3 times with no new evidence"
    detection: "failed_attempts >= 3 on same hypothesis"

  - name: "Path-claim deadlock"
    description: "Two agents both claim same path"
    detection: "active_paths has duplicate values"

  - name: "Premature stop"
    description: "Agent calls stop without differential verification"
    detection: "convergence_state.stop_condition_met = true but verification_results has null fields"
```

---

## Multi-Agent Sync Protocol (File-Level Implementation)

kali-claw runs in a filesystem-native environment (no DB required). Sync uses:

1. **Atomic writes**: every memory update writes to a temp file, then `mv` to the real path (POSIX atomic)
2. **Version vector**: `memory_lock.version` increments on each write; agents check before write
3. **Conflict resolution**: last-writer-wins on non-overlapping fields; on overlapping fields, the agent with stronger evidence wins (configurable per field)

```bash
# Atomic write pattern used by scenario-runner.sh
tmp_file=$(mktemp)
jq ". | .memory_lock.version += 1 | .memory_lock.last_write_at = \"$(date -u +%FT%TZ)\" | .memory_lock.last_write_by = \"$AGENT_ID\"" memory.json > "$tmp_file"
mv "$tmp_file" memory.json
```

---

## Tying Back to kali-claw's Existing Memory Hierarchy

kali-claw already has:
- `memory/YYYY-MM-DD.md` (daily prose logs)
- `MEMORY.md` (distilled long-term knowledge)
- `chronicle/YYYY-MM/*.md` (monthly milestones)

**The new structured-memory schema does NOT replace these.** It runs alongside them:

| Layer | Purpose | Format | Lifecycle |
|---|---|---|---|
| `memory/` | Daily session logs | Markdown prose | Archived after 30 days |
| `MEMORY.md` | Distilled cross-session knowledge | Markdown prose | Manually curated |
| `chronicle/` | Monthly milestones | Markdown prose | Append-only |
| **Engagement memory** (NEW) | Per-engagement structured state | JSON | Engagement-scoped, archived post-engagement |
| **Exploit attempt memory** (NEW) | Per-target exploit dev state | JSON | Target-scoped, archived post-PoC |

When an engagement closes, its structured memory gets **distilled** into prose and merged into `MEMORY.md` — same pattern that daily logs follow, but at engagement granularity.

---

## Worked Example — Mini Scenario

To illustrate: a 4-phase recon-to-exploit engagement using Schema 1.

```bash
# Phase 1: recon
$ scenario-runner.sh SCEN-006 --engagement ENG-2026-07-001
[memory] read engagement-memory.json (version=0)
[phase=recon] running nmap + subfinder + whatweb
[memory] wrote engagement-memory.json (version=1)
[delta] findings.entry_points += [web.example.com:443, vpn.example.com:443]
[delta] next_constraints.must_explore += [web.example.com/api]

# Phase 2: intrusion attempt on web (path: web-api-fuzzing)
[phase=intrusion] running nuclei + sqlmap on /api
[memory] wrote engagement-memory.json (version=2)
[delta] findings.vulnerabilities += [SQLi on /api/v1/user]
[delta] convergence_state.active_path unchanged (evidence yielded)

# Phase 2b: same path, no new evidence
[phase=intrusion] running nuclei templates again
[memory] wrote engagement-memory.json (version=3)
[delta] failed_attempts += 1 (no new evidence)
[delta] convergence_state.failed_attempts_on_active_path = 1

# ... (2 more failures) ...

# Phase 2c: convergence triggers path switch
[memory] wrote engagement-memory.json (version=5)
[delta] active_path: web-api-fuzzing → vpn-credential-brute
[delta] failed_attempts_on_active_path reset to 0
[decision] logged: switched path after 3 evidence-free attempts
```

This is the **MopMonk招二 in action**: trial-and-error is converted to evidence-based convergence. The agent cannot get stuck repeating the same unproductive action.

---

## What's Next

- **SCEN-006**: Full scenario definition using Schema 1 (pentest engagement)
- **SCEN-007**: Full scenario definition using Schema 2 (multi-agent exploit dev)
- **SCEN-008**: Full scenario definition using Schema 3 (patch-diff reproduction)
- **scenario-runner.sh updates**: Optional — add `--memory-driven` flag that enforces schema validation
