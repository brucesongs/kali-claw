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

### 6. Parallel Vulnerability Scanning with Multiprocessing

For CPU-intensive scanning tasks where the GIL limits asyncio performance, use Python's `multiprocessing` module to distribute work across all available cores. This is particularly effective for tasks like payload generation, hash cracking batches, and custom vulnerability checks.

```python
import multiprocessing
from functools import partial

def scan_target_worker(target, scan_config):
    """Worker function executed in a separate process."""
    import subprocess
    import json

    result = {
        "target": target,
        "status": "unknown",
        "findings": [],
    }

    try:
        proc = subprocess.run(
            ["nuclei", "-u", target, "-t", scan_config["template"],
             "-severity", scan_config.get("min_severity", "low"),
             "-json", "-silent"],
            capture_output=True, text=True, timeout=scan_config.get("timeout", 300)
        )
        for line in proc.stdout.strip().split("\n"):
            if line:
                finding = json.loads(line)
                result["findings"].append({
                    "template": finding.get("template-id"),
                    "name": finding.get("info", {}).get("name"),
                    "severity": finding.get("info", {}).get("severity"),
                    "matched_at": finding.get("matched-at"),
                })
        result["status"] = "completed"
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result

def parallel_scan(targets, scan_config, workers=None):
    """Run vulnerability scans across multiple processes."""
    workers = workers or multiprocessing.cpu_count()
    scan_fn = partial(scan_target_worker, scan_config=scan_config)

    with multiprocessing.Pool(processes=workers) as pool:
        results = pool.map(scan_fn, targets)

    return results
```

### 7. Distributed Scanning Across Multiple Hosts

When operating from multiple vantage points (different cloud regions, VPN exit nodes, or compromised pivot hosts), distribute scanning workloads across all available machines for both speed and perspective diversity.

```python
import json
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

class DistributedScanner:
    """Coordinate batch scans across multiple scanning nodes."""

    def __init__(self, nodes):
        """nodes: list of {'host': str, 'port': int, 'ssh_key': str}"""
        self._nodes = nodes

    def distribute_targets(self, targets, method="round_robin"):
        """Assign targets to scanning nodes."""
        assignments = {i: [] for i in range(len(self._nodes))}

        if method == "round_robin":
            for idx, target in enumerate(targets):
                assignments[idx % len(self._nodes)].append(target)
        elif method == "chunk":
            chunk_size = max(1, len(targets) // len(self._nodes))
            for i, node_idx in enumerate(assignments):
                assignments[node_idx] = targets[i * chunk_size:(i + 1) * chunk_size]

        return assignments

    def execute_on_node(self, node, targets, scan_command):
        """Execute scan on a remote node via SSH."""
        target_list = " ".join(targets)
        cmd = [
            "ssh", "-i", node["ssh_key"],
            "-o", "StrictHostKeyChecking=no",
            "-o", f"ConnectTimeout=10",
            f"root@{node['host']}",
            f"{scan_command} {target_list} --json",
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            results = []
            for line in proc.stdout.strip().split("\n"):
                if line:
                    results.append(json.loads(line))
            return {"node": node["host"], "status": "success", "results": results}
        except subprocess.TimeoutExpired:
            return {"node": node["host"], "status": "timeout", "results": []}
        except Exception as e:
            return {"node": node["host"], "status": "error", "error": str(e), "results": []}

    def run_distributed(self, targets, scan_command):
        """Run scans across all nodes in parallel."""
        assignments = self.distribute_targets(targets)
        all_results = []

        with ThreadPoolExecutor(max_workers=len(self._nodes)) as executor:
            futures = []
            for idx, node in enumerate(self._nodes):
                if assignments[idx]:
                    futures.append(
                        executor.submit(self.execute_on_node, node, assignments[idx], scan_command)
                    )

            for future in futures:
                all_results.append(future.result())

        return all_results
```

### 8. Progress Tracking and ETA Calculation

Long-running batch operations need real-time progress feedback. Track completion rate, estimate remaining time, and provide throughput metrics.

```python
import time
from datetime import datetime, timedelta

class ProgressTracker:
    """Track batch progress with ETA calculation."""

    def __init__(self, total, description="Scanning"):
        self._total = total
        self._completed = 0
        self._failed = 0
        self._start_time = time.monotonic()
        self._description = description
        self._recent_rates = []  # track recent throughput for smoother ETA

    def update(self, completed=1, failed=0):
        """Record progress."""
        self._completed += completed
        self._failed += failed

    @property
    def elapsed(self):
        return time.monotonic() - self._start_time

    @property
    def rate(self):
        """Items per second (overall)."""
        if self.elapsed == 0:
            return 0
        return self._completed / self.elapsed

    @property
    def eta(self):
        """Estimated time remaining."""
        if self.rate == 0:
            return None
        remaining = self._total - self._completed - self._failed
        if remaining <= 0:
            return timedelta(0)
        return timedelta(seconds=remaining / self.rate)

    @property
    def percent(self):
        done = self._completed + self._failed
        if self._total == 0:
            return 100.0
        return (done / self._total) * 100

    def format_progress(self):
        """Human-readable progress string."""
        eta_str = str(self.eta).split(".")[0] if self.eta else "calculating..."
        return (
            f"[{self._description}] {self._completed}/{self._total} "
            f"({self.percent:.1f}%) | "
            f"Rate: {self.rate:.1f}/s | "
            f"Failed: {self._failed} | "
            f"ETA: {eta_str}"
        )

    def log_progress(self, interval_seconds=30):
        """Call periodically to log progress at intervals."""
        if int(self.elapsed) % interval_seconds == 0:
            return self.format_progress()
        return None
```

### 9. Result Filtering and Deduplication

Raw scan output often contains duplicates from different templates testing the same vulnerability, or multiple scanners reporting identical findings. A deduplication layer consolidates results before reporting.

```python
import hashlib
from collections import defaultdict

class ResultDeduplicator:
    """Deduplicate findings across multiple scan runs and tools."""

    def __init__(self):
        self._seen = {}
        self._groups = defaultdict(list)

    def _finding_key(self, finding):
        """Generate a deterministic key for deduplication."""
        parts = [
            finding.get("target", ""),
            finding.get("template", finding.get("plugin", "")),
            finding.get("name", ""),
            finding.get("matched_at", finding.get("url", "")),
        ]
        content = "|".join(str(p) for p in parts)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def add(self, finding):
        """Add a finding; return True if new, False if duplicate."""
        key = self._finding_key(finding)
        if key in self._seen:
            # Track duplicate count
            self._seen[key]["duplicate_count"] += 1
            self._seen[key]["sources"].add(finding.get("source", "unknown"))
            return False

        self._seen[key] = {
            **finding,
            "duplicate_count": 0,
            "sources": {finding.get("source", "unknown")},
            "first_seen": finding.get("timestamp"),
        }
        return True

    def add_batch(self, findings):
        """Add multiple findings, return only new ones."""
        new_findings = []
        for f in findings:
            if self.add(f):
                new_findings.append(self._seen[self._finding_key(f)])
        return new_findings

    def get_unique(self):
        """Return all unique findings."""
        return list(self._seen.values())

    def summary(self):
        total = len(self._seen)
        dupes = sum(f["duplicate_count"] for f in self._seen.values())
        return {"unique_findings": total, "duplicates_removed": dupes}
```

### 10. Memory-Efficient Large Target Processing

Scanning tens of thousands of targets can exhaust memory if all results are held in memory simultaneously. Use generators and streaming to process results incrementally.

```python
import json
import os

class StreamingBatchProcessor:
    """Process large target lists without loading everything into memory."""

    def __init__(self, output_dir="scan_results"):
        self._output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def process_targets_from_file(self, target_file, scan_fn, batch_size=100):
        """Read targets lazily and process in batches."""
        with open(target_file) as f:
            batch = []
            for line in f:
                target = line.strip()
                if target and not target.startswith("#"):
                    batch.append(target)
                    if len(batch) >= batch_size:
                        yield from self._process_batch(batch, scan_fn)
                        batch = []

            if batch:  # process remaining
                yield from self._process_batch(batch, scan_fn)

    def _process_batch(self, batch, scan_fn):
        """Process a batch and stream results to disk."""
        output_file = os.path.join(
            self._output_dir,
            f"batch_{hash(tuple(batch)) % 100000:05d}.jsonl"
        )

        with open(output_file, "a") as out:
            for target in batch:
                try:
                    result = scan_fn(target)
                    result["target"] = target
                    out.write(json.dumps(result) + "\n")
                    yield result
                except Exception as e:
                    error_entry = {"target": target, "error": str(e)}
                    out.write(json.dumps(error_entry) + "\n")

    def merge_results(self):
        """Stream-merge all batch result files."""
        for filename in sorted(os.listdir(self._output_dir)):
            if filename.endswith(".jsonl"):
                with open(os.path.join(self._output_dir, filename)) as f:
                    for line in f:
                        yield json.loads(line)
```

### 11. Retry Logic for Failed Targets

Failed targets should be collected and retried with modified parameters, rather than re-scanning the entire target list. Implement a failure queue with configurable retry strategies.

```python
from enum import Enum
from dataclasses import dataclass

class RetryReason(Enum):
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    CONNECTION_REFUSED = "connection_refused"
    UNEXPECTED_ERROR = "unexpected"

@dataclass
class FailedTarget:
    target: str
    reason: RetryReason
    attempts: int
    last_error: str
    original_config: dict

class RetryManager:
    """Manage retry attempts for failed targets."""

    def __init__(self, max_retries=3, max_total_attempts=None):
        self._max_retries = max_retries
        self._max_total = max_total_attempts or (max_retries * 2)
        self._failed = []

    def add_failure(self, target, error, config=None):
        """Register a failed target for potential retry."""
        reason = self._classify_error(error)
        existing = next((f for f in self._failed if f.target == target), None)

        if existing:
            existing.attempts += 1
            existing.last_error = str(error)
        else:
            self._failed.append(FailedTarget(
                target=target,
                reason=reason,
                attempts=1,
                last_error=str(error),
                original_config=config or {},
            ))

    def get_retryable(self):
        """Get targets eligible for retry."""
        return [f for f in self._failed if f.attempts <= self._max_retries]

    def get_permanently_failed(self):
        """Get targets that have exhausted retries."""
        return [f for f in self._failed if f.attempts > self._max_retries]

    def get_retry_config(self, failed):
        """Adjust scan parameters based on failure reason."""
        config = dict(failed.original_config)
        if failed.reason == RetryReason.TIMEOUT:
            config["timeout"] = config.get("timeout", 30) * 2
        elif failed.reason == RetryReason.RATE_LIMITED:
            config["delay"] = config.get("delay", 0) + 5
        elif failed.reason == RetryReason.CONNECTION_REFUSED:
            config["skip_ports"] = config.get("skip_ports", []) + [80, 443]
        return config

    @staticmethod
    def _classify_error(error):
        error_str = str(error).lower()
        if "timeout" in error_str:
            return RetryReason.TIMEOUT
        elif "429" in error_str or "rate" in error_str:
            return RetryReason.RATE_LIMITED
        elif "refused" in error_str:
            return RetryReason.CONNECTION_REFUSED
        return RetryReason.UNEXPECTED_ERROR
```

### 12. Output Format Conversion (JSON/CSV/HTML)

Security tools produce output in diverse formats. A unified conversion layer normalizes results into the format needed by downstream consumers: JSON for API integrations, CSV for spreadsheet analysis, HTML for management reports.

```python
import csv
import json
from html import escape
from datetime import datetime

class OutputConverter:
    """Convert scan results between formats."""

    def __init__(self, results):
        self._results = results

    def to_json(self, filepath):
        """Write results as JSON array."""
        with open(filepath, "w") as f:
            json.dump(self._results, f, indent=2, default=str)

    def to_csv(self, filepath):
        """Flatten results and write as CSV."""
        if not self._results:
            return

        # Collect all unique keys
        fieldnames = set()
        for r in self._results:
            fieldnames.update(self._flatten(r).keys())

        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
            writer.writeheader()
            for r in self._results:
                writer.writerow(self._flatten(r))

    def to_html(self, filepath, title="Scan Report"):
        """Generate an HTML report from results."""
        rows = ""
        for r in self._results:
            severity = r.get("severity", "info").lower()
            color = {"critical": "#ff4444", "high": "#ff8800",
                     "medium": "#ffbb00", "low": "#4488ff"}.get(severity, "#888")
            rows += f"""<tr>
                <td>{escape(str(r.get('target', '')))}</td>
                <td style="color:{color}">{escape(severity)}</td>
                <td>{escape(str(r.get('name', r.get('template', ''))))}</td>
                <td>{escape(str(r.get('matched_at', '')))}</td>
            </tr>\n"""

        html = f"""<!DOCTYPE html>
<html><head><title>{escape(title)}</title>
<style>
body {{ font-family: sans-serif; margin: 20px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #333; color: white; }}
</style></head>
<body><h1>{escape(title)}</h1>
<p>Generated: {datetime.utcnow().isoformat()} | Total findings: {len(self._results)}</p>
<table><tr><th>Target</th><th>Severity</th><th>Finding</th><th>Matched At</th></tr>
{rows}</table></body></html>"""

        with open(filepath, "w") as f:
            f.write(html)

    @staticmethod
    def _flatten(d, parent_key="", sep="_"):
        """Flatten nested dicts for CSV output."""
        items = {}
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.update(OutputConverter._flatten(v, new_key, sep))
            elif isinstance(v, list):
                items[new_key] = ", ".join(str(i) for i in v)
            else:
                items[new_key] = v
        return items
```

### 13. Integration with Nuclei and Nmap Batch Mode

Both Nuclei and Nmap natively support batch operations. Wrapping their built-in batching with Python orchestration adds checkpointing, rate limiting, and result normalization.

```bash
#!/bin/bash
# Nuclei batch scanning with built-in features
TARGETS_FILE="targets.txt"

# Batch scan with rate limiting and multiple output formats
nuclei -l "$TARGETS_FILE" \
    -t cves/ -t vulnerabilities/ -t misconfiguration/ \
    -severity critical,high,medium \
    -rate-limit 150 \
    -bulk-size 25 \
    -o results_nuclei.txt \
    -json-output results_nuclei.json \
    -markdown-export results_nuclei.md \
    -timeout 10 \
    -retries 2 \
    -stats -si 60

# Nmap batch scanning with optimization
nmap -iL "$TARGETS_FILE" \
    -sS -sV -O --version-intensity 5 \
    -T4 --max-retries 2 --host-timeout 30m \
    -min-rate 100 \
    -oA results_nmap \
    --script=default,vuln
```

```python
import subprocess
import json

def nuclei_batch_scan(target_file, templates=None, severity=None, rate_limit=100):
    """Run Nuclei in batch mode with Python-controlled parameters."""
    cmd = [
        "nuclei",
        "-l", target_file,
        "-rate-limit", str(rate_limit),
        "-json", "-silent",
        "-timeout", "10",
        "-retries", "2",
    ]

    if templates:
        for t in templates:
            cmd.extend(["-t", t])

    if severity:
        cmd.extend(["-severity", ",".join(severity)])

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

    results = []
    for line in proc.stdout.strip().split("\n"):
        if line:
            try:
                findings = json.loads(line)
                results.append({
                    "target": findings.get("host", ""),
                    "template": findings.get("template-id", ""),
                    "name": findings.get("info", {}).get("name", ""),
                    "severity": findings.get("info", {}).get("severity", ""),
                    "matched_at": findings.get("matched-at", ""),
                    "source": "nuclei",
                })
            except json.JSONDecodeError:
                continue

    return results
```

## References

- [asyncio — Asynchronous I/O](https://docs.python.org/3/library/asyncio.html)
- [Nuclei Batch Scanning](https://docs.projectdiscovery.io/nuclei/)
- [OWASP Testing Guide — Automation](https://owasp.org/www-project-web-security-testing-guide/)
- [Python multiprocessing](https://docs.python.org/3/library/multiprocessing.html)
- [Nmap Optimization](https://nmap.org/book/man-performance.html)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
