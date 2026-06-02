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

## References

- [Microsoft — Retry Pattern](https://learn.microsoft.com/en-us/azure/architecture/patterns/retry)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)
- [Python Resilience Patterns](https://docs.python.org/3/library/asyncio-task.html)
- [AWS — Error Retries and Exponential Backoff](https://docs.aws.amazon.com/general/latest/gr/api-retries.html)
