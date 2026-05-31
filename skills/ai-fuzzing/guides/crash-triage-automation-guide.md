# Crash Triage Automation Guide

> Companion to `skills/ai-fuzzing/SKILL.md`. This guide covers crash deduplication, root cause analysis, exploitability assessment, and automated triage pipelines using casr, crashwalk, and custom scripts.

---

## 1. Crash Deduplication Fundamentals

When a fuzzer produces thousands of crashes, most are duplicates triggered by the same underlying bug. Deduplication reduces noise so analysts focus on unique root causes.

**Stack hash deduplication** groups crashes by their call stack at the point of failure:

```bash
# Generate stack hashes from AFL++ crash directory using crashwalk
cw -root /path/to/crashes -cmd "./target @@" | sort -u -t'|' -k2 > unique_crashes.txt

# Count unique bugs vs total crashes
echo "Total crashes: $(ls /path/to/crashes/id:* | wc -l)"
echo "Unique bugs: $(wc -l < unique_crashes.txt)"
```

**CASR-based deduplication** uses more sophisticated clustering:

```bash
# Install casr toolkit
cargo install casr

# Cluster crashes by root cause
casr-cluster -c /path/to/crashes -o /path/to/clustered \
  -- ./target @@

# View cluster summary
casr-cluster -d /path/to/clustered
```

---

## 2. Exploitability Assessment with CASR

CASR (Crash Analysis and Severity Rating) automatically classifies crash severity and potential exploitability:

```bash
# Analyze a single crash for exploitability
casr-san -i crash_input -o report.casrep \
  -- ./target_asan crash_input

# Batch analysis of all crashes in a directory
for crash in /path/to/crashes/id:*; do
  casr-san -i "$crash" -o "reports/$(basename $crash).casrep" \
    -- ./target_asan "$crash"
done

# Generate severity summary
casr-cluster -r reports/ | grep -E "(EXPLOITABLE|PROBABLY_EXPLOITABLE)"
```

CASR severity classifications:

| Severity | Meaning | Priority |
|----------|---------|----------|
| EXPLOITABLE | Confirmed exploitable condition | Critical |
| PROBABLY_EXPLOITABLE | Likely exploitable (heap overflow, UAF) | High |
| PROBABLY_NOT_EXPLOITABLE | Unlikely exploitable (null deref, stack read) | Medium |
| NOT_EXPLOITABLE | Benign crash (assertion, abort) | Low |

---

## 3. Crashwalk Pipeline Setup

Crashwalk automates the process of running each crash through GDB/ASAN to extract stack traces and classify bugs:

```bash
# Install crashwalk
go install github.com/bnagy/crashwalk/cmd/cw@latest
go install github.com/bnagy/crashwalk/cmd/cwdump@latest
go install github.com/bnagy/crashwalk/cmd/cwfind@latest

# Run crashwalk against AFL++ output
cw -root ./output/default/crashes \
   -cmd "./target_debug @@" \
   -workers 8 \
   -output crashes.db

# Dump unique crashes sorted by exploitability
cwdump crashes.db | sort -t'|' -k3 -r
```

---

## 4. Automated Triage Script

A complete triage pipeline that processes fuzzer output end-to-end:

```python
#!/usr/bin/env python3
"""Automated crash triage pipeline for AFL++ output."""

import subprocess
import json
import hashlib
from pathlib import Path
from dataclasses import dataclass

@dataclass(frozen=True)
class CrashReport:
    crash_file: str
    stack_hash: str
    severity: str
    crash_type: str
    faulting_address: str

def run_casr_analysis(crash_path: str, target_cmd: str) -> dict:
    """Run CASR on a single crash and return parsed report."""
    report_path = f"/tmp/report_{hashlib.md5(crash_path.encode()).hexdigest()}.json"
    result = subprocess.run(
        ["casr-san", "-i", crash_path, "-o", report_path, "--", *target_cmd.split(), crash_path],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        with open(report_path) as f:
            return json.load(f)
    return {}

def deduplicate_by_stack(reports: list[CrashReport]) -> list[CrashReport]:
    """Remove duplicate crashes based on stack hash."""
    seen_hashes = set()
    unique = []
    for report in reports:
        if report.stack_hash not in seen_hashes:
            seen_hashes.add(report.stack_hash)
            unique.append(report)
    return unique

def triage_directory(crash_dir: str, target: str) -> list[CrashReport]:
    """Process all crashes in directory and return deduplicated reports."""
    crashes = sorted(Path(crash_dir).glob("id:*"))
    reports = []
    for crash in crashes:
        analysis = run_casr_analysis(str(crash), target)
        if analysis:
            reports.append(CrashReport(
                crash_file=str(crash),
                stack_hash=analysis.get("stack_hash", "unknown"),
                severity=analysis.get("severity", "UNKNOWN"),
                crash_type=analysis.get("crash_type", "unknown"),
                faulting_address=analysis.get("faulting_address", "0x0")
            ))
    return deduplicate_by_stack(reports)
```

---

## 5. GDB-Based Root Cause Analysis

When automated tools are insufficient, use GDB scripting for deeper analysis:

```bash
# GDB batch script for crash analysis
cat > /tmp/triage.gdb << 'EOF'
set pagination off
set logging on /tmp/crash_analysis.log
run
bt full
info registers
x/32xw $sp
info proc mappings
exploitable
quit
EOF

# Run against crash input
gdb -batch -x /tmp/triage.gdb --args ./target_debug crash_input

# Extract exploitability from GDB exploitable plugin
grep -E "^Description:|^Exploitability:" /tmp/crash_analysis.log
```

---

## 6. AddressSanitizer Report Parsing

ASAN reports contain rich information for root cause analysis. Parse them systematically:

```bash
# Run crash with ASAN-instrumented binary and capture report
ASAN_OPTIONS="symbolize=1:detect_leaks=0" \
  ./target_asan crash_input 2> asan_report.txt

# Extract key fields from ASAN report
grep -A5 "ERROR: AddressSanitizer" asan_report.txt
grep "SUMMARY:" asan_report.txt

# Classify ASAN error types
# heap-buffer-overflow → EXPLOITABLE (write) / PROBABLY_NOT (read)
# heap-use-after-free → EXPLOITABLE
# stack-buffer-overflow → EXPLOITABLE
# null-dereference → PROBABLY_NOT_EXPLOITABLE
# global-buffer-overflow → EXPLOITABLE (write)
```

---

## 7. Continuous Triage Integration

Integrate triage into the fuzzing loop so new unique crashes are flagged immediately:

```yaml
# triage-pipeline.yaml — runs alongside fuzzer
name: continuous-triage
schedule: "*/15 * * * *"  # Every 15 minutes

steps:
  - name: sync-crashes
    command: |
      rsync -a fuzzer_output/crashes/ /triage/incoming/

  - name: deduplicate
    command: |
      casr-cluster -c /triage/incoming -o /triage/clustered \
        -- ./target @@

  - name: assess-severity
    command: |
      for cluster in /triage/clustered/cl*/; do
        sample=$(ls "$cluster" | head -1)
        casr-san -i "$cluster/$sample" -o "$cluster/report.casrep" \
          -- ./target_asan "$cluster/$sample"
      done

  - name: alert-critical
    command: |
      grep -rl "EXPLOITABLE" /triage/clustered/*/report.casrep | \
        xargs -I{} notify-send "Critical crash found: {}"
```

---

## 8. Minimizing Crash Inputs

Smaller crash inputs make root cause analysis faster and more precise:

```bash
# Use AFL++ crash minimizer
afl-tmin -i crash_input -o crash_minimized \
  -- ./target_asan @@

# Verify minimized input still triggers the same crash
./target_asan crash_minimized 2>&1 | grep "ERROR: AddressSanitizer"

# Batch minimize all unique crashes
for crash in /triage/unique/*; do
  afl-tmin -i "$crash" -o "/triage/minimized/$(basename $crash)" \
    -- ./target_asan @@
done
```

Minimized inputs are essential for writing reliable proof-of-concept exploits and for reporting bugs upstream with clear reproduction steps.
