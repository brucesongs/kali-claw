# Multi-Agent Runtime Engineering — Quick Reference Card

> One-page (mental) cheat sheet for the runtime engineering discipline. Distilled from `SKILL.md`, `payloads.md`, and the playbook. Objective: serve as a fast lookup for in-engagement queries — "what's the right jq pattern for X?" "what's the convergence rule?" "how do I detect anti-pattern Y?"

## Overview

This card is the operator's pocket reference. Each section answers a single question with a copy-paste-runnable snippet. Bookmark this page during engagements; reach for the full `payloads.md` only when you need depth.

## The Three Layers (MopMonk three招 mapping)

```
招一 Structured Memory        → Schema design (Layer 1)
招二 Memory-Driven Convergence → Failed-attempt accounting + path switch (Layer 3)
招三 Shared-Memory Multi-Agent → POSIX flock + atomic write + version vector (Layers 2 + 5)
```

## Schema Quick-Templates

### Empty Memory Bootstrap

```bash
cat > mem.json <<'JSON'
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
```

### Confidence Levels (rigid taxonomy)

```
CONFIRMED  — 3+ independent evidence vectors OR 2+ agents independently arrived
LIKELY     — 2 vectors OR 1 authoritative vector
POSSIBLE   — 1 vector, plausible
UNVERIFIED — hypothesis only
INVALIDATED — evidence against outweighs
```

## Atomic Write Helper

```bash
write_memory() {
  local mem="$1" agent="$2" jq_expr="$3"
  (
    flock -x -w 30 9 || exit 1
    local pre; pre=$(jq '.memory_lock.version' "$mem")
    local tmp; tmp=$(mktemp -p "$(dirname "$mem")")
    jq --arg agent "$agent" --argjson pre "$pre" "$jq_expr" "$mem" > "$tmp" || { rm "$tmp"; exit 2; }
    local post; post=$(jq '.memory_lock.version' "$tmp")
    [ "$post" -eq "$((pre + 1))" ] || { echo "[conflict]"; rm "$tmp"; exit 3; }
    # AP-4 deadlock check
    jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1' "$tmp" >/dev/null || { rm "$tmp"; exit 4; }
    # AP-5 premature-stop check
    jq -e '(.convergence_state.stop_condition_met // false) | if . then (.verification_results.vulnerable != null and .verification_results.patched != null) else true end' "$tmp" >/dev/null || { rm "$tmp"; exit 5; }
    mv "$tmp" "$mem"
  ) 9>"$mem.lock"
}
```

## Path Claim (race-safe)

```bash
AGENT_ID=A
CLAIM_PATH=patch-diff

write_memory "$MEM" "$AGENT_ID" "
  .active_paths[\"$AGENT_ID\"] = \"$CLAIM_PATH\"
  | .memory_lock.owner_agents = (.active_paths | keys)
  | .memory_lock.last_write_at = (now | todateiso8601)
  | .memory_lock.last_write_by = \$agent
  | .memory_lock.last_read_at = (now | todateiso8601)
  | .decision_log += [{\"at\": (now | todateiso8601), \"by\": \$agent, \"decision\": \"claimed $CLAIM_PATH\"}]
"
```

## Hypothesis Write

```bash
HYP_ID=H-A-001
HYP_PATH="parser.c:412"
HYP_TEXT="heap-buffer-overflow"

write_memory "$MEM" "agent-A" "
  .vulnerability_hypotheses += [{
    \"id\": \"$HYP_ID\", \"hypothesis\": \"$HYP_TEXT\", \"path\": \"$HYP_PATH\",
    \"evidence_for\": [], \"evidence_against\": [],
    \"status\": \"LIKELY\", \"confidence\": 0.55,
    \"claimed_by\": [\"agent-A\"], \"created_at\": (now | todateiso8601)
  }]
  | .convergence_state.iterations += 1
"
```

## Convergence Detector (jq one-liner)

```bash
jq -r '
  [.vulnerability_hypotheses[] | select(.status != "INVALIDATED")] as $h
  | ($h | group_by(.path) | map(select(length >= 2)) | map((map(.claimed_by) | flatten | unique | length) >= 2) | any) as $conv
  | if $conv then "CONVERGENCE DETECTED" else "no convergence" end
' "$MEM"
```

## Convergence Promote (Python)

```python
import json, sys
mem = json.load(open(sys.argv[1]))
for h in mem["vulnerability_hypotheses"]:
    if h["status"] == "INVALIDATED": continue
    siblings = [x for x in mem["vulnerability_hypotheses"]
                if x["path"] == h["path"] and x["id"] != h["id"]
                and x["status"] != "INVALIDATED"]
    agents_others = {a for s in siblings for a in s.get("claimed_by", [])}
    if siblings and (agents_others & set(h.get("claimed_by", []))) != agents_others:
        if h["status"] != "CONFIRMED":
            h["status"] = "CONFIRMED"
            h["confidence"] = min(1.0, h.get("confidence", 0.5) + 0.30)
json.dump(mem, open(sys.argv[1], "w"), indent=2)
```

## Five Anti-Patterns

| # | Name | Detection (one-liner) |
|---|------|----------------------|
| AP-1 | Free-form exploration | `jq -e '(.memory_lock.last_write_at != null) and (.memory_lock.last_read_at == null)' mem.json` |
| AP-2 | Memory drift | decision_log `finding_ref` not in findings |
| AP-3 | Repeat-without-delta | `failed_attempts` grouped by hypothesis has length >= 3 with no evidence added |
| AP-4 | Path-claim deadlock | `jq -e '.active_paths | (group_by(.) | map(length) | max // 0) <= 1'` |
| AP-5 | Premature stop | `stop_condition_met && !verification_results.complete` |

## Topology Selection Decision Tree

```
if task.bug_class_exploration and task.multiple_independent_directions:
    → parallel-explorers
elif task.phase_sequential and task.clear_handoffs:
    → pipeline
elif task.judgment_heavy and task.multiple_lenses:
    → council
elif task.scope_dynamic and task.specialist_count >= 3:
    → hierarchical
else:
    → single-agent (use autonomous-loops)
```

## Differential Verification

```bash
ASAN_OPTIONS=detect_leaks=0 vuln_build < poc.bin > vuln.txt 2>&1
ASAN_OPTIONS=detect_leaks=0 patched_build < poc.bin > patched.txt 2>&1

if grep -q "ERROR: AddressSanitizer" vuln.txt && ! grep -q "ERROR:" patched.txt; then
  echo "CONFIRMED"
fi
```

## Stop Condition Guard

```bash
# Block premature stop
jq -e '
  (.convergence_state.stop_condition_met // false) as $stop
  | if $stop then
      (.verification_results.vulnerable != null and .verification_results.patched != null)
    else true end
' "$MEM"
```

## Quick Queries

```bash
# What did we try?
jq -r '.failed_attempts | group_by(.hypothesis) | map({hyp: .[0].hypothesis, n: length}) | .[]' "$MEM"

# Is anything stuck?
jq -r '.convergence_state | "active=\(.active_path) failed=\(.failed_attempts_on_active_path)/\(.path_switch_threshold) stop=\(.stop_condition_met)"' "$MEM"

# Decision log
jq -r '.decision_log[] | "\(.at) [\(.by)] \(.decision)"' "$MEM"

# Confirmed hypotheses
jq '[.vulnerability_hypotheses[] | select(.status == "CONFIRMED") | .id]' "$MEM"
```

## Engagement-Close Checklist

```bash
echo "1. JSON valid:"; jq '.' "$MEM" >/dev/null && echo OK || echo FAIL
echo "2. Stop reason set:"; jq -e '.convergence_state.stop_reason != null' "$MEM" >/dev/null && echo OK || echo FAIL
echo "3. Anti-patterns clean:"; python3 anti_pattern_check.py "$MEM" >/dev/null 2>&1 && echo OK || echo FAIL
echo "4. Decision log non-empty:"; jq -e '.decision_log | length > 0' "$MEM" >/dev/null && echo OK || echo WARN
echo "5. Version > 0:"; jq -e '.memory_lock.version > 0' "$MEM" >/dev/null && echo OK || echo FAIL
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Edit JSON in place | Always use atomic write helper |
| Skip last_read_at update | Add to write_memory function |
| Use prose memory | Use structured fields only |
| Same agent claims two paths | Schema rejects; fix agent code |
| Stop without differential verify | Premature-stop guard blocks write |
| No timeout on flock | Add `-w 30`; indefinite waits hang coordinator |

## References

- `SKILL.md` — full skill reference
- `payloads.md` — 36+ section template library
- `multi-agent-runtime-engineering-playbook.md` — end-to-end operations manual with 10 hands-on exercises
- `real-world-incident-case-studies.md` — 10 real-world agent systems analyzed
- `validation/scenarios/SCEN-007.md` — canonical scenario
- `validation/scenarios/SCEN-MEMORY-SCHEMA.md` — schema library
- `docs/mopmonk-research-and-kali-claw-plan.md` — MopMonk three招 research
- MopMonk GitHub: https://github.com/MopMonkAI/MopMonkAgent
- CyberGym paper: arXiv:2506.02548
