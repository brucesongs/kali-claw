# Cross-Session Continuity Guide

> Techniques for maintaining context across agent sessions, including state reconstruction, handoff protocols, and continuity verification. Ensures no knowledge loss between sessions and enables seamless resumption of complex multi-session tasks.

---

## 1. Session State Capture

Capture the essential state at session end so the next session can reconstruct context without re-reading everything.

```python
# Python — Session state snapshot for handoff
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass(frozen=True)
class SessionState:
    session_id: str
    timestamp: datetime
    active_tasks: tuple[dict, ...]
    decisions_made: tuple[str, ...]
    blockers: tuple[str, ...]
    next_actions: tuple[str, ...]
    context_files: tuple[str, ...]  # Files that were actively being worked on
    working_hypotheses: tuple[str, ...]
    environment_state: dict = field(default_factory=dict)

def capture_session_state(
    session_id: str,
    tasks: list[dict],
    decisions: list[str],
    blockers: list[str],
    next_steps: list[str]
) -> SessionState:
    """Capture current session state for handoff to next session."""
    return SessionState(
        session_id=session_id,
        timestamp=datetime.utcnow(),
        active_tasks=tuple(tasks),
        decisions_made=tuple(decisions),
        blockers=tuple(blockers),
        next_actions=tuple(next_steps),
        context_files=tuple(_get_recently_modified_files()),
        working_hypotheses=tuple(_extract_hypotheses()),
        environment_state=_capture_env_state()
    )

def _get_recently_modified_files() -> list[str]:
    """Get files modified in current session."""
    import subprocess
    result = subprocess.run(
        ['find', '.', '-name', '*.md', '-mmin', '-60', '-type', 'f'],
        capture_output=True, text=True
    )
    return result.stdout.strip().split('\n')
```

## 2. Handoff Protocol Format

```yaml
# YAML — Standard handoff document structure
---
handoff:
  from_session: "2025-03-15-session-02"
  to_session: "next"
  timestamp: "2025-03-15T18:30:00Z"

  # What was being worked on
  active_context:
    primary_task: "Enumerate internal network via SSRF in payment gateway"
    phase: "exploitation"
    progress: "60%"

  # Critical state that must not be lost
  state:
    target: "10.0.0.0/24 internal network"
    entry_point: "https://payments.target.com/webhook/validate"
    discovered_hosts:
      - "10.0.0.1 (gateway)"
      - "10.0.0.5 (redis, port 6379 open)"
      - "10.0.0.12 (internal API, ports 8080/8443)"
    credentials_found:
      - "Redis: no auth required"
      - "Internal API: Bearer token in env var INTERNAL_TOKEN"

  # Decisions already made (don't re-evaluate)
  decisions:
    - "Using blind SSRF via DNS rebinding — direct SSRF blocked by allowlist"
    - "Prioritizing Redis for credential extraction over API enumeration"
    - "Reporting partial findings at 72-hour mark per program rules"

  # What to do next (ordered)
  next_actions:
    - "Extract Redis keys matching *session* and *token* patterns"
    - "Test internal API authentication with discovered token"
    - "Map remaining hosts in 10.0.0.0/24 (13-255 not yet scanned)"

  # Known blockers
  blockers:
    - "Rate limiting on webhook endpoint — max 10 req/min"
    - "DNS rebinding requires 60s TTL wait between requests"

  # Files to read first in next session
  priority_reads:
    - "memory/2025-03-15.md"
    - "skills/web-ssrf/payloads.md"
---
```

## 3. State Reconstruction on Session Start

```python
# Python — Reconstruct context from handoff document
from pathlib import Path
import yaml

def reconstruct_session_context(memory_dir: Path) -> dict:
    """Load the most recent handoff and reconstruct working context."""
    # Find most recent daily log
    logs = sorted(memory_dir.glob("*.md"), reverse=True)
    if not logs:
        return {'status': 'fresh_start', 'context': None}

    latest_log = logs[0]
    content = latest_log.read_text()

    # Extract handoff block if present
    handoff_match = re.search(
        r'```yaml\n---\nhandoff:(.*?)---\n```',
        content, re.DOTALL
    )

    if handoff_match:
        handoff = yaml.safe_load('---\nhandoff:' + handoff_match.group(1) + '---')
        return {
            'status': 'resuming',
            'context': handoff['handoff'],
            'priority_reads': handoff['handoff'].get('priority_reads', []),
            'next_actions': handoff['handoff'].get('next_actions', []),
        }

    # No explicit handoff — reconstruct from log structure
    return {
        'status': 'implicit_resume',
        'context': _extract_implicit_state(content),
        'priority_reads': [str(latest_log)],
    }

def _extract_implicit_state(log_content: str) -> dict:
    """Extract state from unstructured daily log."""
    sections = re.split(r'^## ', log_content, flags=re.MULTILINE)
    return {
        'last_section': sections[-1][:500] if sections else '',
        'todos': re.findall(r'- \[ \] (.+)', log_content),
        'completed': re.findall(r'- \[x\] (.+)', log_content),
    }
```

## 4. Continuity Verification

```bash
# Bash — Verify session continuity integrity
#!/bin/bash
# Check that no knowledge gaps exist between sessions

MEMORY_DIR="memory"
CHRONICLE_DIR="chronicle"

echo "=== Continuity Verification ==="

# Check for consecutive daily logs (no gaps)
prev_date=""
gaps=0
for log in $(ls "$MEMORY_DIR"/*.md 2>/dev/null | sort | tail -14); do
  current_date=$(basename "$log" .md)
  if [ -n "$prev_date" ]; then
    expected=$(date -d "$prev_date + 1 day" +%Y-%m-%d 2>/dev/null || \
               date -v+1d -jf "%Y-%m-%d" "$prev_date" +%Y-%m-%d)
    if [ "$current_date" != "$expected" ]; then
      echo "GAP: Missing log between $prev_date and $current_date"
      gaps=$((gaps + 1))
    fi
  fi
  prev_date="$current_date"
done

echo "Gaps found: $gaps"

# Verify handoff documents reference existing files
latest_log=$(ls "$MEMORY_DIR"/*.md | sort | tail -1)
grep -oP '(?<=- ")[^"]+(?=")' "$latest_log" 2>/dev/null | while read -r ref; do
  if [ ! -f "$ref" ]; then
    echo "BROKEN REF: $ref referenced in handoff but does not exist"
  fi
done

echo "=== Verification Complete ==="
```

## 5. Context Compression for Long-Running Tasks

```python
# Python — Compress context when approaching memory limits
def compress_task_context(
    full_history: list[dict],
    max_entries: int = 50
) -> list[dict]:
    """Compress task history while preserving critical decision points."""
    if len(full_history) <= max_entries:
        return full_history

    # Always keep: first entry, last 10 entries, all decision points
    critical = set()
    critical.add(0)  # First entry
    critical.update(range(len(full_history) - 10, len(full_history)))  # Last 10

    # Keep entries marked as decisions or milestones
    for i, entry in enumerate(full_history):
        if entry.get('type') in ('decision', 'milestone', 'blocker', 'breakthrough'):
            critical.add(i)

    # If still over budget, sample evenly from remaining
    remaining_budget = max_entries - len(critical)
    non_critical = [i for i in range(len(full_history)) if i not in critical]

    if remaining_budget > 0 and non_critical:
        step = max(1, len(non_critical) // remaining_budget)
        sampled = non_critical[::step][:remaining_budget]
        critical.update(sampled)

    return [full_history[i] for i in sorted(critical)]
```

## 6. Continuity Best Practices

| Practice | When | Purpose |
|----------|------|---------|
| Write handoff block | End of every session | Enable clean resumption |
| List next actions | Before session end | Direct next session start |
| Record decisions | When made | Prevent re-evaluation |
| Note blockers | When encountered | Avoid repeated dead ends |
| Reference files | Always | Speed up context loading |
| Verify continuity | Session start | Catch gaps early |

The handoff document is the single most important artifact for cross-session continuity. A well-written handoff saves 10-15 minutes of context reconstruction at the start of each session. Invest 2 minutes at session end to write it properly.
