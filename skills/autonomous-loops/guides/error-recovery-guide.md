# Error Recovery and Retry Strategies Guide

## Introduction

Autonomous security loops must handle failures gracefully — network timeouts, rate limiting, target unavailability, and tool crashes are expected, not exceptional. This guide covers retry strategies, circuit breakers, and failure isolation patterns for building resilient autonomous agents.

## Practical Steps

### 1. Exponential Backoff with Jitter

```python
import random
import time

def retry_with_backoff(fn, max_retries=5, base_delay=1.0, max_delay=60.0):
    """Retry with exponential backoff and random jitter."""
    for attempt in range(max_retries):
        try:
            return fn()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            delay = min(base_delay * (2 ** attempt), max_delay)
            jitter = random.uniform(0, delay * 0.5)
            time.sleep(delay + jitter)
```

### 2. Circuit Breaker Pattern

```python
import time

class CircuitBreaker:
    """Stop calling a failing service to prevent cascading failures."""

    def __init__(self, failure_threshold=5, recovery_timeout=60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures = 0
        self._last_failure = 0
        self._state = "closed"  # closed, open, half-open

    def call(self, fn):
        if self._state == "open":
            if time.monotonic() - self._last_failure > self.recovery_timeout:
                self._state = "half-open"
            else:
                raise Exception("Circuit breaker is open")

        try:
            result = fn()
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise

    def _on_success(self):
        self._failures = 0
        self._state = "closed"

    def _on_failure(self):
        self._failures += 1
        self._last_failure = time.monotonic()
        if self._failures >= self.failure_threshold:
            self._state = "open"
```

### 3. Failure Isolation

```python
def scan_with_isolation(targets, scan_fn):
    """Isolate failures — one target failure shouldn't halt the batch."""
    results = {"success": [], "failed": []}

    for target in targets:
        try:
            result = scan_fn(target)
            results["success"].append({"target": target, "result": result})
        except Exception as e:
            results["failed"].append({
                "target": target,
                "error": str(e),
                "error_type": type(e).__name__,
            })
            continue  # proceed to next target

    return results
```

### 4. State Recovery

```python
import json
import os

class StateManager:
    """Persist and recover loop state across restarts."""

    def __init__(self, state_file="state.json"):
        self._file = state_file
        self._state = self._load()

    def _load(self):
        if os.path.exists(self._file):
            with open(self._file) as f:
                return json.load(f)
        return {"completed": [], "failed": {}, "metadata": {}}

    def save(self):
        with open(self._file, "w") as f:
            json.dump(self._state, f, indent=2)

    def mark_completed(self, target):
        self._state["completed"].append(target)
        self.save()

    def mark_failed(self, target, error):
        self._state["failed"][target] = error
        self.save()

    @property
    def completed(self):
        return set(self._state["completed"])

    @property
    def failed(self):
        return dict(self._state["failed"])
```

### 5. Timeout Handling

```python
import signal

class TimeoutError(Exception):
    pass

def with_timeout(fn, seconds=30):
    """Wrap a function call with a hard timeout."""
    def handler(signum, frame):
        raise TimeoutError(f"Function timed out after {seconds}s")

    old_handler = signal.signal(signal.SIGALRM, handler)
    signal.alarm(seconds)
    try:
        return fn()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
```

### 6. Retry Strategy Decision Table

| Error Type | Strategy | Backoff | Max Retries |
|------------|----------|---------|-------------|
| Connection timeout | Retry | Exponential | 3 |
| Rate limit (429) | Retry | Respect Retry-After header | 5 |
| Auth failure (401/403) | Skip | None | 0 |
| Server error (5xx) | Retry | Exponential + jitter | 3 |
| DNS resolution failure | Retry | Linear (5s) | 2 |
| Tool crash (segfault) | Skip + log | None | 0 |

### 7. Graceful Degradation Strategies

When components fail in an autonomous loop, the system should continue operating with reduced functionality rather than halting entirely. Graceful degradation requires identifying which features are essential versus optional and defining fallback behaviors for each failure mode.

```python
class DegradationLevel:
    """Define feature availability at each degradation level."""
    FULL = 0       # All features active
    DEGRADED = 1   # Skip optional checks, reduce scope
    MINIMAL = 2    # Core monitoring only, no deep scans
    SURVIVAL = 3   # Heartbeat only, log everything for later

class GracefulDegradation:
    """Manage feature availability based on system health."""

    def __init__(self):
        self._level = DegradationLevel.FULL
        self._failures_by_component = {}
        self._thresholds = {
            DegradationLevel.DEGRADED: 3,
            DegradationLevel.MINIMAL: 6,
            DegradationLevel.SURVIVAL: 10,
        }

    def report_failure(self, component):
        """Report a component failure."""
        self._failures_by_component[component] = (
            self._failures_by_component.get(component, 0) + 1
        )
        self._recalculate_level()

    def report_success(self, component):
        """Report component recovery."""
        if component in self._failures_by_component:
            self._failures_by_component[component] = max(
                0, self._failures_by_component[component] - 2
            )
        self._recalculate_level()

    def _recalculate_level(self):
        total_failures = sum(self._failures_by_component.values())
        self._level = DegradationLevel.FULL
        for level, threshold in sorted(self._thresholds.items()):
            if total_failures >= threshold:
                self._level = level

    @property
    def level(self):
        return self._level

    def should_run(self, feature_tier):
        """Check if a feature should run at current degradation level."""
        return feature_tier >= self._level

    def get_disabled_features(self):
        """List features disabled at current level."""
        feature_map = {
            DegradationLevel.DEGRADED: ["deep_scan", "fuzzing", "brute_force"],
            DegradationLevel.MINIMAL: ["deep_scan", "fuzzing", "brute_force",
                                       "port_scan_full", "service_enum"],
            DegradationLevel.SURVIVAL: ["deep_scan", "fuzzing", "brute_force",
                                        "port_scan_full", "service_enum",
                                        "header_check", "ssl_check"],
        }
        return feature_map.get(self._level, [])
```

### 8. Health Check Patterns

Autonomous loops need self-monitoring to detect when they or their dependencies become unhealthy. Health checks should cover the loop process itself, external dependencies (network, APIs, tools), and resource constraints (disk, memory, CPU).

```python
import os
import shutil
import time
from dataclasses import dataclass

@dataclass
class HealthStatus:
    healthy: bool
    checks: dict
    timestamp: float

class HealthChecker:
    """Verify system health for autonomous loop operation."""

    def __init__(self, config=None):
        self._config = config or {}
        self._last_check = None

    def check_all(self):
        """Run all health checks and return aggregate status."""
        checks = {
            "disk_space": self._check_disk(),
            "memory": self._check_memory(),
            "network": self._check_network(),
            "tools": self._check_tools(),
            "loop_liveness": self._check_loop_liveness(),
        }

        all_healthy = all(c["healthy"] for c in checks.values())
        self._last_check = HealthStatus(
            healthy=all_healthy,
            checks=checks,
            timestamp=time.time(),
        )
        return self._last_check

    def _check_disk(self):
        """Ensure sufficient disk space for results."""
        usage = shutil.disk_usage("/")
        free_gb = usage.free / (1024 ** 3)
        min_gb = self._config.get("min_disk_gb", 1.0)
        return {
            "healthy": free_gb > min_gb,
            "free_gb": round(free_gb, 2),
            "min_required_gb": min_gb,
        }

    def _check_memory(self):
        """Check available memory (Linux)."""
        try:
            with open("/proc/meminfo") as f:
                lines = f.readlines()
            meminfo = {}
            for line in lines:
                parts = line.split()
                meminfo[parts[0].rstrip(":")] = int(parts[1])

            available_mb = meminfo.get("MemAvailable", 0) / 1024
            min_mb = self._config.get("min_memory_mb", 256)
            return {
                "healthy": available_mb > min_mb,
                "available_mb": round(available_mb, 1),
                "min_required_mb": min_mb,
            }
        except (OSError, ValueError):
            return {"healthy": True, "note": "Memory check unavailable on this platform"}

    def _check_network(self):
        """Verify network connectivity."""
        import socket
        test_hosts = self._config.get(
            "network_test_hosts", ["1.1.1.1", "8.8.8.8"]
        )
        reachable = 0
        for host in test_hosts:
            try:
                sock = socket.create_connection((host, 53), timeout=5)
                sock.close()
                reachable += 1
            except OSError:
                pass

        return {
            "healthy": reachable > 0,
            "reachable_hosts": reachable,
            "total_tested": len(test_hosts),
        }

    def _check_tools(self):
        """Verify required security tools are available."""
        required = self._config.get("required_tools", ["nmap", "nuclei"])
        available = []
        for tool in required:
            path = shutil.which(tool)
            if path:
                available.append(tool)

        return {
            "healthy": len(available) >= len(required),
            "available": available,
            "missing": [t for t in required if t not in available],
        }

    def _check_loop_liveness(self):
        """Check if the loop is running within expected time bounds."""
        if self._last_check is None:
            return {"healthy": True, "note": "First health check"}

        elapsed = time.time() - self._last_check.timestamp
        max_interval = self._config.get("max_loop_interval", 600)
        return {
            "healthy": elapsed < max_interval,
            "seconds_since_last_check": round(elapsed, 1),
            "max_allowed": max_interval,
        }
```

### 9. Dead Letter Queues for Failed Tasks

Tasks that exhaust all retry attempts should not be silently discarded. A dead letter queue (DLQ) preserves failed work items for manual inspection, later retry with different parameters, or root cause analysis.

```python
import json
import os
from datetime import datetime, timezone

class DeadLetterQueue:
    """Persistently store failed tasks for later analysis."""

    def __init__(self, dlq_dir="dead_letters"):
        self._dir = dlq_dir
        os.makedirs(dlq_dir, exist_ok=True)

    def enqueue(self, task, error, attempts, context=None):
        """Add a permanently failed task to the DLQ."""
        entry = {
            "task": task,
            "error": str(error),
            "error_type": type(error).__name__,
            "attempts": attempts,
            "context": context or {},
            "enqueued_at": datetime.now(timezone.utc).isoformat(),
        }

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"dlq_{timestamp}_{abs(hash(str(task))) % 100000:05d}.json"
        filepath = os.path.join(self._dir, filename)

        with open(filepath, "w") as f:
            json.dump(entry, f, indent=2, default=str)

        return filepath

    def dequeue_all(self):
        """Load all dead letter entries for inspection."""
        entries = []
        for filename in sorted(os.listdir(self._dir)):
            if filename.endswith(".json"):
                with open(os.path.join(self._dir, filename)) as f:
                    entries.append(json.load(f))
        return entries

    def retry_all(self, retry_fn, new_config=None):
        """Re-attempt all dead letter tasks with optional new config."""
        results = {"retried": 0, "succeeded": 0, "still_failed": 0}

        for entry in self.dequeue_all():
            results["retried"] += 1
            try:
                config = new_config or entry.get("context", {})
                retry_fn(entry["task"], config)
                results["succeeded"] += 1
            except Exception:
                results["still_failed"] += 1

        return results

    def summary(self):
        """Generate a summary of dead letter contents."""
        entries = self.dequeue_all()
        error_types = {}
        for e in entries:
            etype = e.get("error_type", "unknown")
            error_types[etype] = error_types.get(etype, 0) + 1

        return {
            "total_dead_letters": len(entries),
            "error_breakdown": error_types,
            "oldest": entries[0]["enqueued_at"] if entries else None,
            "newest": entries[-1]["enqueued_at"] if entries else None,
        }
```

### 10. Rollback Mechanisms

When a batch operation produces incorrect or harmful results (e.g., accidentally modifying target configurations during testing), rollback mechanisms restore the previous state. This requires maintaining snapshots before each destructive operation.

```python
import json
import os
import shutil
from datetime import datetime, timezone

class RollbackManager:
    """Create and restore snapshots for rollback capability."""

    def __init__(self, rollback_dir="rollbacks", max_snapshots=10):
        self._dir = rollback_dir
        self._max = max_snapshots
        os.makedirs(rollback_dir, exist_ok=True)

    def create_snapshot(self, label, state_data):
        """Save a named snapshot of current state."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snapshot_name = f"{timestamp}_{label}"
        snapshot_path = os.path.join(self._dir, snapshot_name)
        os.makedirs(snapshot_path, exist_ok=True)

        # Save state data
        with open(os.path.join(snapshot_path, "state.json"), "w") as f:
            json.dump(state_data, f, indent=2, default=str)

        # Save metadata
        metadata = {
            "label": label,
            "timestamp": timestamp,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(os.path.join(snapshot_path, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)

        # Prune old snapshots
        self._prune_old_snapshots()

        return snapshot_path

    def restore_snapshot(self, label=None, index=None):
        """Restore a snapshot by label or index (0 = most recent)."""
        snapshots = sorted(os.listdir(self._dir), reverse=True)

        if index is not None and 0 <= index < len(snapshots):
            snap = snapshots[index]
        elif label:
            snap = next((s for s in snapshots if label in s), None)
        else:
            snap = snapshots[0] if snapshots else None

        if snap is None:
            raise ValueError(f"Snapshot not found: label={label}, index={index}")

        path = os.path.join(self._dir, snap, "state.json")
        with open(path) as f:
            return json.load(f)

    def list_snapshots(self):
        """List available snapshots in reverse chronological order."""
        snapshots = []
        for name in sorted(os.listdir(self._dir), reverse=True):
            meta_path = os.path.join(self._dir, name, "metadata.json")
            if os.path.exists(meta_path):
                with open(meta_path) as f:
                    snapshots.append(json.load(f))
        return snapshots

    def _prune_old_snapshots(self):
        """Remove oldest snapshots beyond the limit."""
        snapshots = sorted(os.listdir(self._dir))
        while len(snapshots) > self._max:
            oldest = snapshots.pop(0)
            shutil.rmtree(os.path.join(self._dir, oldest), ignore_errors=True)
```

### 11. Logging and Observability for Autonomous Loops

Autonomous loops that run without human supervision need comprehensive logging that enables post-hoc debugging. Structured logs with trace IDs, correlation across loop iterations, and searchable fields make it possible to reconstruct what happened and why.

```python
import json
import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

class LoopLogger:
    """Structured logger with loop context and trace correlation."""

    def __init__(self, loop_name, log_file=None):
        self._loop_name = loop_name
        self._run_id = uuid.uuid4().hex[:12]
        self._logger = logging.getLogger(f"loop.{loop_name}")
        self._logger.setLevel(logging.DEBUG)

        if log_file:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

        # Also log to console at INFO level
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        self._logger.addHandler(console)

    def _log(self, level, message, **context):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "loop": self._loop_name,
            "run_id": self._run_id,
            "level": level,
            "message": message,
            **context,
        }
        record = logging.LogRecord(
            name=self._logger.name, level=getattr(logging, level.upper()),
            pathname="", lineno=0, msg=json.dumps(entry), args=(), exc_info=None,
        )
        self._logger.handle(record)

    def info(self, message, **context):
        self._log("info", message, **context)

    def error(self, message, **context):
        self._log("error", message, **context)

    def warning(self, message, **context):
        self._log("warning", message, **context)

    def debug(self, message, **context):
        self._log("debug", message, **context)

    @contextmanager
    def operation(self, name, **context):
        """Track an operation with timing and error capture."""
        op_id = uuid.uuid4().hex[:8]
        start = datetime.now(timezone.utc)
        self._log("info", f"Started: {name}", operation_id=op_id, **context)

        try:
            yield
            duration = (datetime.now(timezone.utc) - start).total_seconds()
            self._log("info", f"Completed: {name}",
                      operation_id=op_id, duration_seconds=duration, **context)
        except Exception as e:
            duration = (datetime.now(timezone.utc) - start).total_seconds()
            self._log("error", f"Failed: {name}",
                      operation_id=op_id, duration_seconds=duration,
                      error=str(e), error_type=type(e).__name__, **context)
            raise
```

### 12. Crash Recovery with State Machines

When an autonomous loop crashes mid-operation, a state machine ensures it can resume from the last known good state rather than restarting from scratch. Each state transition is persisted, enabling exact crash recovery.

```python
import json
import os
from enum import Enum, auto

class LoopState(Enum):
    IDLE = auto()
    INITIALIZING = auto()
    DISCOVERING = auto()
    SCANNING = auto()
    ANALYZING = auto()
    REPORTING = auto()
    COMPLETED = auto()
    FAILED = auto()

VALID_TRANSITIONS = {
    LoopState.IDLE: [LoopState.INITIALIZING],
    LoopState.INITIALIZING: [LoopState.DISCOVERING, LoopState.FAILED],
    LoopState.DISCOVERING: [LoopState.SCANNING, LoopState.FAILED],
    LoopState.SCANNING: [LoopState.ANALYZING, LoopState.FAILED],
    LoopState.ANALYZING: [LoopState.REPORTING, LoopState.FAILED],
    LoopState.REPORTING: [LoopState.COMPLETED, LoopState.FAILED],
    LoopState.COMPLETED: [LoopState.IDLE],
    LoopState.FAILED: [LoopState.IDLE],  # allow restart after failure
}

class StateMachine:
    """Persistent state machine for crash recovery."""

    def __init__(self, state_file="loop_state.json"):
        self._file = state_file
        self._state = self._load()

    def _load(self):
        """Load state from disk."""
        if os.path.exists(self._file):
            with open(self._file) as f:
                data = json.load(f)
                return {
                    "state": LoopState(data["state"]),
                    "context": data.get("context", {}),
                    "progress": data.get("progress", {}),
                }
        return {"state": LoopState.IDLE, "context": {}, "progress": {}}

    def _save(self):
        """Persist current state to disk."""
        data = {
            "state": self._state["state"].value,
            "context": self._state["context"],
            "progress": self._state["progress"],
        }
        tmp = self._file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self._file)

    def transition(self, new_state, context=None):
        """Attempt a state transition."""
        current = self._state["state"]
        if new_state not in VALID_TRANSITIONS.get(current, []):
            raise ValueError(
                f"Invalid transition: {current.name} -> {new_state.name}"
            )
        self._state["state"] = new_state
        if context:
            self._state["context"].update(context)
        self._save()

    @property
    def state(self):
        return self._state["state"]

    @property
    def context(self):
        return dict(self._state["context"])

    def update_progress(self, key, value):
        """Update progress data within current state."""
        self._state["progress"][key] = value
        self._save()

    def recover(self):
        """Return recovery info after a crash."""
        state = self._state["state"]
        if state == LoopState.IDLE or state == LoopState.COMPLETED:
            return {"needs_recovery": False}

        return {
            "needs_recovery": True,
            "crashed_at_state": state.name,
            "context": self._state["context"],
            "progress": self._state["progress"],
            "recommended_action": f"Resume from {state.name} with saved progress",
        }
```

### 13. Distributed Consensus for Multi-Agent Error Handling

When multiple autonomous agents collaborate on a shared task, error handling requires coordination. Agents must agree on whether a task has failed, who owns the retry, and how to reconcile conflicting results. Use a simple consensus protocol for shared error state.

```python
import hashlib
import json
import time

class ConsensusErrorState:
    """Coordinate error handling across multiple agents."""

    def __init__(self, agent_id, shared_storage):
        """
        shared_storage: dict-like object accessible by all agents
                       (could be Redis, shared filesystem, or database)
        """
        self._agent_id = agent_id
        self._storage = shared_storage

    def report_error(self, task_id, error, vote="retry"):
        """Cast a vote for how to handle a task error."""
        key = f"consensus:{task_id}"
        entry = self._storage.get(key, {
            "task_id": task_id,
            "votes": {},
            "created_at": time.time(),
        })

        entry["votes"][self._agent_id] = {
            "action": vote,  # "retry", "skip", "escalate"
            "error": str(error),
            "timestamp": time.time(),
        }
        self._storage[key] = entry

    def get_consensus(self, task_id, required_votes=2):
        """Determine consensus action for a failed task."""
        key = f"consensus:{task_id}"
        entry = self._storage.get(key, None)

        if not entry:
            return {"consensus": None, "reason": "no votes"}

        votes = entry["votes"]
        if len(votes) < required_votes:
            return {"consensus": None, "reason": "insufficient votes",
                    "current_votes": len(votes), "required": required_votes}

        # Tally votes
        tally = {}
        for agent_id, vote_data in votes.items():
            action = vote_data["action"]
            tally[action] = tally.get(action, 0) + 1

        # Majority wins
        winner = max(tally, key=tally.get)
        majority = len(votes) // 2 + 1

        if tally[winner] >= majority:
            return {
                "consensus": winner,
                "vote_breakdown": tally,
                "total_votes": len(votes),
            }

        return {"consensus": None, "reason": "no majority", "vote_breakdown": tally}

    def claim_retry(self, task_id):
        """Atomically claim retry ownership for a task."""
        key = f"retry_claim:{task_id}"
        existing = self._storage.get(key, None)

        if existing and time.time() - existing["claimed_at"] < 300:
            return {"claimed": False, "owner": existing["agent_id"]}

        self._storage[key] = {
            "agent_id": self._agent_id,
            "claimed_at": time.time(),
        }
        return {"claimed": True, "owner": self._agent_id}
```

### 14. Monitoring Error Rates and Circuit Breaker Metrics

Tracking error metrics over time reveals degrading infrastructure, problematic targets, and opportunities to tune retry parameters. Collect and aggregate error metrics to inform both automated decisions and operator dashboards.

```python
import time
from collections import defaultdict, deque

class ErrorMetrics:
    """Track and analyze error rates for autonomous loops."""

    def __init__(self, window_seconds=300, max_events=10000):
        self._window = window_seconds
        self._max = max_events
        self._events = deque(maxlen=max_events)
        self._circuit_states = {}

    def record(self, operation, error_type, target=None, duration=None):
        """Record an error event."""
        self._events.append({
            "timestamp": time.monotonic(),
            "operation": operation,
            "error_type": error_type,
            "target": target,
            "duration": duration,
        })

    def error_rate(self, operation=None, window=None):
        """Calculate error rate within a time window."""
        window = window or self._window
        cutoff = time.monotonic() - window
        recent = [e for e in self._events if e["timestamp"] >= cutoff]

        if operation:
            recent = [e for e in recent if e["operation"] == operation]

        if not recent:
            return 0.0

        errors = sum(1 for e in recent if e["error_type"] != "success")
        return errors / len(recent)

    def top_errors(self, n=10, window=None):
        """Get the most frequent error types."""
        window = window or self._window
        cutoff = time.monotonic() - window
        recent = [e for e in self._events if e["timestamp"] >= cutoff]

        counts = defaultdict(int)
        for e in recent:
            if e["error_type"] != "success":
                counts[e["error_type"]] += 1

        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def circuit_breaker_metrics(self, circuit_name):
        """Track circuit breaker state transitions."""
        if circuit_name not in self._circuit_states:
            self._circuit_states[circuit_name] = {
                "state": "closed",
                "opens": 0,
                "last_open": None,
                "total_failures": 0,
            }
        return self._circuit_states[circuit_name]

    def record_circuit_open(self, circuit_name):
        """Record a circuit breaker opening."""
        metrics = self.circuit_breaker_metrics(circuit_name)
        metrics["state"] = "open"
        metrics["opens"] += 1
        metrics["last_open"] = time.monotonic()

    def record_circuit_close(self, circuit_name):
        """Record a circuit breaker closing (recovery)."""
        metrics = self.circuit_breaker_metrics(circuit_name)
        metrics["state"] = "closed"

    def health_report(self):
        """Generate a comprehensive error health report."""
        return {
            "overall_error_rate": round(self.error_rate(), 4),
            "error_rate_5min": round(self.error_rate(window=300), 4),
            "error_rate_1min": round(self.error_rate(window=60), 4),
            "top_errors": self.top_errors(5),
            "total_events": len(self._events),
            "circuit_breakers": dict(self._circuit_states),
            "generated_at": time.time(),
        }
```

## References

- [Microsoft — Retry Pattern](https://learn.microsoft.com/en-us/azure/architecture/patterns/retry)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)
- [Python Resilience Patterns](https://docs.python.org/3/library/asyncio-task.html)
- [AWS — Error Retries and Exponential Backoff](https://docs.aws.amazon.com/general/latest/gr/api-retries.html)
- [Google SRE — Handling Overload](https://sre.google/sre-book/handling-overload/)
- [NIST SP 800-61 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [Release It! — Stability Patterns](https://pragprog.com/titles/mnee2/release-it-second-edition/)
