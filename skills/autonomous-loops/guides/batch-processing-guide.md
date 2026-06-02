# Batch Processing Guide for Security Tasks

## Introduction

Batch processing enables autonomous security agents to operate on multiple targets in parallel with controlled concurrency, error isolation, and result aggregation. This guide covers patterns for building reliable batch pipelines for scanning, enumeration, and analysis tasks.

## Practical Steps

### 1. Target List Management

```python
class TargetList:
    """Immutable target list with deduplication and validation."""

    def __init__(self, targets):
        validated = [self._normalize(t) for t in targets]
        self._targets = list(dict.fromkeys(validated))  # dedupe, preserve order

    @staticmethod
    def _normalize(target):
        target = target.strip().rstrip("/")
        if not target:
            raise ValueError("Empty target")
        return target

    @property
    def targets(self):
        return list(self._targets)  # return copy

    def chunk(self, size):
        """Split into chunks for parallel processing."""
        return [TargetList(self._targets[i:i+size])
                for i in range(0, len(self._targets), size)]
```

### 2. Concurrent Scanning with Semaphore

```python
import asyncio
import aiohttp

async def scan_batch(targets, concurrency=10, timeout=30):
    """Scan targets with bounded concurrency."""
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def scan_one(target):
        async with semaphore:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{target}/api/version",
                        timeout=aiohttp.ClientTimeout(total=timeout)
                    ) as resp:
                        return {"target": target, "status": resp.status,
                                "data": await resp.text()}
            except Exception as e:
                return {"target": target, "error": str(e)}

    tasks = [scan_one(t) for t in targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if not isinstance(r, Exception)]
```

### 3. Result Aggregation

```python
from collections import defaultdict

def aggregate_results(results):
    """Group results by category and severity."""
    summary = {
        "total": len(results),
        "by_status": defaultdict(int),
        "errors": [],
        "findings": [],
    }

    for result in results:
        if "error" in result:
            summary["errors"].append(result)
            summary["by_status"]["error"] += 1
        else:
            summary["by_status"][result["status"]] += 1
            if result.get("findings"):
                summary["findings"].extend(result["findings"])

    return summary
```

### 4. Pipeline with Checkpointing

```python
import json
import os

def pipeline(targets, checkpoint_file="checkpoint.json"):
    """Execute pipeline stages with checkpoint/resume capability."""
    checkpoint = load_checkpoint(checkpoint_file)
    remaining = [t for t in targets if t not in checkpoint.get("completed", [])]

    for stage in [dns_resolve, port_scan, service_detect, vuln_scan]:
        stage_results = []
        for target in remaining:
            result = stage(target)
            stage_results.append(result)
            checkpoint.setdefault("completed", []).append(target)
            save_checkpoint(checkpoint, checkpoint_file)

        remaining = [r["target"] for r in stage_results if r.get("next_stage")]

    return stage_results
```

### 5. Rate Limiting

```python
import time
from threading import Lock

class RateLimiter:
    """Token bucket rate limiter for batch operations."""

    def __init__(self, rate=10, burst=20):
        self.rate = rate
        self.burst = burst
        self._tokens = burst
        self._last = time.monotonic()
        self._lock = Lock()

    def acquire(self):
        with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self.burst,
                self._tokens + (now - self._last) * self.rate
            )
            self._last = now
            if self._tokens < 1:
                sleep_time = (1 - self._tokens) / self.rate
                time.sleep(sleep_time)
            self._tokens -= 1
```

## References

- [asyncio — Asynchronous I/O](https://docs.python.org/3/library/asyncio.html)
- [Nuclei Batch Scanning](https://docs.projectdiscovery.io/nuclei/)
- [OWASP Testing Guide — Automation](https://owasp.org/www-project-web-security-testing-guide/)
