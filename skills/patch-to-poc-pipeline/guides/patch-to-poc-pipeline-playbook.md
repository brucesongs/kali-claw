# Patch-to-PoC Pipeline Playbook

> Operator's playbook for executing the patch-to-poc pipeline end-to-end. Covers engagement scoping, lab setup, the 5-phase workflow with memory contracts, multi-agent coordination, reporting, and CyberGym submission. Target audience: experienced offensive researchers and detection engineers familiar with RE, fuzzing, and detection-engineering fundamentals.

## 1. Introduction and Objective

The patch-to-poc pipeline takes a published CVE patch diff and produces, deterministically, three artifacts:

1. A **PoC input** that crashes the vulnerable build and leaves the patched build clean (CyberGym stop condition)
2. A **YARA rule** that fires on the vulnerable pattern across the fleet and stays silent on the patched pattern
3. A **Sigma rule** that fires on exploitation telemetry in host/network logs

The pipeline is **memory-driven** — every phase reads and writes Schema 3 reproduction memory. The runner halts only when the CyberGym stop condition is satisfied or an anti-pattern aborts.

This playbook is the operator's manual for kali-claw Wave 12 / v0.1.45.

## 2. Engagement Scoping

### 2.1 Confirm target

| Item | Detail |
|------|--------|
| CVE ID | |
| Vulnerable version (path) | |
| Patched version (path) | |
| Patch file path | |
| Source available? | yes / no |
| Bug class hypothesis | |
| Time budget (hours) | |
| Communications channel | |

### 2.2 Rules of engagement

- **No weaponization** — the pipeline stops at a *crashing PoC*; full exploit construction (ROP, shellcode, heap feng shui) lives in `exploit-development`
- **Isolated VM** — always execute in a snapshot-able VM; revert between detonations
- **No internet egress during fuzzing** — disconnect VM during Phase 3 to prevent accidental exfil
- **Memory file is the source of truth** — every decision goes through Schema 3 memory; no off-channel notes
- **Stop condition is sacred** — never declare success without Phase 4 differential verification

### 2.3 Test boundaries

- Allowed: read patch, compile both versions, run harnesses, write detection rules
- Allowed: fuzzer execution against vulnerable build
- Allowed: Sigma rule conversion to backend query languages
- Disallowed: deploy PoC against production
- Disallowed: ship YARA rule to detection-engineering CI without differential test

## 3. Lab Setup

### 3.1 VM and tooling

```bash
# Kali 2025-2 base image
sudo apt update && sudo apt install -y \
  ghidra bindiff radare2 \
  afl++ libfuzzer-17-dev clang-17 \
  yara sigma-cli \
  syft grype \
  jq python3-pip ctags cflow

# Python tooling
pip3 install --user angr pwntools

# Verify versions
ghidra --version | head -1
bindiff --version
afl-fuzz -V 2>&1 | head -1
clang --version | head -1
yara --version
sigma --version
```

### 3.2 Workspace layout

```
/work/
├── repro-attempt-memory.json       # Schema 3 memory
├── convergence-events.jsonl        # append-only event log
├── CVE-XXXX-YYYYY.patch            # the diff under analysis
├── harness_<vuln_func>.c           # fuzzer harness
├── harness_vulnerable              # compiled harness (vuln)
├── harness_patched                 # compiled harness (patched)
├── seeds/                          # fuzzer seed corpus
├── crashes/                        # fuzzer crash outputs
├── rules/
│   ├── CVE-XXXX-YYYYY.yar          # YARA rule
│   └── CVE-XXXX-YYYYY-sigma.yml    # Sigma rule
├── scripts/
│   ├── pattern_to_bugclass.py
│   ├── craft_poc.py
│   ├── differential_decision.sh
│   ├── anti_pattern_check.sh
│   └── yara_diff_test.sh
├── repro-report.md                 # generated report
├── repro-snapshot.json             # CyberGym submission JSON
└── sbom.json                       # syft SBOM output
```

### 3.3 Initialize memory

```bash
cat > /work/repro-attempt-memory.json <<'JSON'
{
  "schema_version": "1.0",
  "task": {
    "vulnerable_version": "",
    "patched_version": "",
    "patch_file": "",
    "cve": "",
    "build_env": "ubuntu:22.04 + build-essential + ASan/UBSan"
  },
  "patch_analysis": {},
  "code_path": {},
  "candidate_inputs": [],
  "verification_results": {},
  "convergence_state": {
    "iterations": 0,
    "status": "IN_PROGRESS",
    "stop_condition_met": false,
    "next_action": "Phase 1: Patch analysis",
    "failed_attempts": 0,
    "path_switch_threshold": 3,
    "active_path": "patch-diff",
    "candidate_paths": ["patch-diff", "harness-entry", "sanitizer"]
  },
  "memory_lock": {
    "version": 0,
    "owner_agents": [],
    "last_read_at": null,
    "last_write_at": null,
    "last_write_by": null
  }
}
JSON
```

## 4. Phase 1 — Patch Analysis

### 4.1 Goal

Read the patch, identify the protective pattern, hypothesize the bug class, pick the suspected vulnerable function.

### 4.2 Procedure

1. Acquire patch via `git diff` or distro gitweb (payloads.md §1)
2. Compute stats: `diffstat -p <patch>`
3. Classify protective pattern via `pattern_to_bugclass.py` (§2.2)
4. Identify the suspected vulnerable function — usually the recipient of the new check
5. Write Phase 1 memory delta (§16.1)

### 4.3 Convergence trigger

If `patch_analysis.key_change` is empty after Phase 1, **abort Phase 2**. No point walking code paths without a hypothesis. Re-triage the patch.

### 4.4 Practical walkthrough — CVE-2023-4863 libwebp

```bash
cd /targets/libwebp
git diff v1.3.1 v1.3.2 -- src/dec/huffman_dec.c > /work/CVE-2023-4863.patch
git diff v1.3.1 v1.3.2 --stat
# src/dec/huffman_dec.c | 17 ++++++++++-------
# 1 file changed, 14 insertions(+), 3 deletions(-)

grep '^+' /work/CVE-2023-4863.patch | grep -E 'if\s*\('
# +    if (count >= 2 * num_codes || count == 0) {
# +      ok = 0;
# +      goto End;
# +    }

python3 /work/scripts/pattern_to_bugclass.py /work/CVE-2023-4863.patch
# memory_corruption	(bounds|size|len).*check|>=\s*\d+\s*\)|<=\s+max_
```

Memory delta:

```json
{
  "patch_analysis": {
    "files_changed": ["src/dec/huffman_dec.c"],
    "lines_added": 14, "lines_removed": 3,
    "key_change": "Added overflow check on Huffman table size; rejects code-length sequences yielding >= 2^31 entries",
    "suspected_vuln_function": "BuildHuffmanTable()",
    "suspected_vuln_type": "heap-buffer-overflow",
    "confidence": 0.85
  }
}
```

## 5. Phase 2 — Code Path Walking

### 5.1 Source-available procedure

```bash
grep -rn "BuildHuffmanTable" /targets/libwebp-1.3.1/src/
cflow --main WebPDecode /targets/libwebp-1.3.1/src/*.c | grep -A 30 "WebPDecode"
# Call chain: WebPDecode → VP8LDecodeImageStream → VP8LDecodeHeader → VP8LBuildHuffmanTable → BuildHuffmanTable
# Distance: 4
```

### 5.2 Binary-only procedure

```bash
/opt/ghidra/support/analyzeHeadless /work proj \
  -import /targets/libwebp-1.3.1.so \
  -postScript DecompileFunction.java -scriptPath /work/scripts \
  -functionName BuildHuffmanTable

bindiff /targets/libwebp-1.3.1.so /targets/libwebp-1.3.2.so \
  -o /work/libwebp.BinDiff
# BinDiff marks BuildHuffmanTable as "changed" (similarity < 1.0)
```

### 5.3 Convergence trigger

If no path from public API to vuln function exists (distance = -1), the bug is **unreachable** from attacker input. Defender's win, but no PoC. Record as `UNREACHABLE` status and exit.

## 6. Phase 3 — PoC Generation

### 6.1 Strategy decision

| Condition | Strategy |
|-----------|----------|
| Bug class well-understood + Phase 1 confidence ≥ 0.8 | A — Manual |
| Bug class subtle (type confusion, race) | B — Fuzzer |
| OSS-Fuzz reproducer exists | A — Clone and minimize |
| Phase 1 confidence < 0.7 | B mandatory |

### 6.2 Strategy A — Manual craft

```python
# /work/scripts/craft_poc.py
import struct
with open("/targets/samples/valid.webp", "rb") as f:
    data = bytearray(f.read())
# Mutate the field at offset 0x42 (Huffman table size)
struct.pack_into("<I", data, 0x42, (1 << 31) + 100)
with open("/work/poc.webp", "wb") as f:
    f.write(data)
```

### 6.3 Strategy B — Fuzzer harness

```c
// /work/harness_huffman.c
#include "webp/decode.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    WebPDecode(data, size, NULL);
    return 0;
}
```

```bash
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I/targets/libwebp-1.3.1 \
  /work/harness_huffman.c /targets/libwebp-1.3.1/src/.libs/libwebp.a \
  -o /work/harness_vulnerable

ASAN_OPTIONS=detect_leaks=0 /work/harness_vulnerable /work/seeds/ \
  -max_len=65536 -max_total_time=1800 -artifact_prefix=/work/crashes/
```

### 6.4 Convergence trigger (招二)

If 3 candidate inputs fail to crash, **switch strategy** (manual ↔ fuzzer). Increment `failed_attempts`; force path switch at `>= path_switch_threshold`.

## 7. Phase 4 — Differential Verification (CyberGym Stop)

### 7.1 Build patched harness with identical flags

```bash
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I/targets/libwebp-1.3.2 \
  /work/harness_huffman.c /targets/libwebp-1.3.2/src/.libs/libwebp.a \
  -o /work/harness_patched
```

### 7.2 Run identical PoC against both

```bash
for variant in vulnerable patched; do
  ASAN_OPTIONS=symbolize=1:abort_on_error=1 \
    /work/harness_${variant} /work/crashes/crash-POC \
    > /work/${variant}.stdout 2> /work/${variant}.stderr
  echo "exit=$?" > /work/${variant}.exitcode
done
```

### 7.3 Apply decision matrix

| Vulnerable | Patched | Verdict |
|-----------|---------|---------|
| crashes | clean | **CONFIRMED** → Phase 5 |
| crashes | crashes | WRONG_ROOT_CAUSE → Phase 1 |
| no crash | no crash | POC_DOESNT_REACH_BUG → Phase 3 |
| no crash | crashes | IMPOSSIBLE → Recheck build |

### 7.4 Emit convergence event

```bash
jq -n '{
  event: "POC_CONFIRMED_DIFFERENTIALLY",
  vulnerable_crashed: true, patched_crashed: false,
  stop_condition_met: true,
  timestamp: (now | todate)
}' | tee -a /work/convergence-events.jsonl
```

## 8. Phase 5 — Detection Rule Authoring

### 8.1 YARA — differential pattern

```yara
rule CVE_2023_4863_libwebp_huffman_overflow {
    meta:
        description = "libwebp BuildHuffmanTable heap-buffer-overflow"
        cve         = "CVE-2023-4863"
        cvss        = 8.8
        patched_in  = "libwebp 1.3.2"
    strings:
        $vuln_func_src = "BuildHuffmanTable"
        $table_accum    = "root_table + table_size"
        $no_guard       = "table_size <\\s*\\d+" nocase
        $bin_symbol     = "BuildHuffmanTable" ascii
    condition:
        ($vuln_func_src at 0 and $table_accum and $no_guard)
        or ($bin_symbol and not $no_guard)
}
```

### 8.2 Differential YARA test

```bash
yara -s /work/rules/CVE-2023-4863.yar /targets/libwebp-1.3.1.so   # MUST match
yara -s /work/rules/CVE-2023-4863.yar /targets/libwebp-1.3.2.so   # MUST NOT match
```

### 8.3 Sigma — exploitation telemetry

```yaml
title: Potential CVE-2023-4863 libwebp Exploitation
id: 7c4f8a9b-1e2d-4a3b-9c5d-7e8f9a0b1c2d
status: experimental
description: Detects processes loading a vulnerable libwebp and accessing crafted WebP inputs.
logsource:
    product: linux
    service: sysmon_linux
detection:
    selection_load:
        ImageLoaded|endswith:
            - '/libwebp.so.7.0.3'
            - '/libwebp.so.7.0.4'
            - '/libwebp.so.7.0.5'
    selection_file:
        CommandLine|contains: ['.webp', '.webm']
    condition: selection_load and selection_file
falsepositives:
    - Legitimate WebP processing on patched systems
level: medium
tags: [attack.initial-access, attack.t1190, cve.2023.4863]
```

### 8.4 Sigma validation + backend conversion

```bash
sigma check /work/rules/CVE-2023-4863-sigma.yml
sigma convert -t splunk /work/rules/CVE-2023-4863-sigma.yml
sigma convert -t kql     /work/rules/CVE-2023-4863-sigma.yml
sigma convert -t eql     /work/rules/CVE-2023-4863-sigma.yml
```

### 8.5 Fleet rollout

```bash
syft /targets/production-image:latest -o cyclonedx-json > /work/sbom.json
grype sbom:/work/sbom.json --only-fixed | grep libwebp
```

## 9. Multi-Agent Coordination (招三)

When the pipeline benefits from parallel exploration (e.g., 3 candidate inputs tested simultaneously), agents claim distinct paths against the same memory file.

### 9.1 Path-claim protocol

```json
{
  "active_paths": {
    "A": "patch-diff",
    "B": "harness-entry",
    "C": "sanitizer"
  }
}
```

### 9.2 Atomic write pattern

```bash
# Agent A's write
tmp=$(mktemp)
jq --arg agent "A" '
  .memory_lock.version += 1 |
  .memory_lock.last_write_at = (now | todate) |
  .memory_lock.last_write_by = $agent |
  .patch_analysis = {...}' \
  /work/repro-attempt-memory.json > "$tmp" && mv "$tmp" /work/repro-attempt-memory.json
```

### 9.3 Conflict resolution

- **Non-overlapping fields**: last-writer-wins (both deltas preserved)
- **Overlapping fields**: stronger evidence wins (configurable per field)
- **Version mismatch on write**: re-read, re-merge, retry

## 10. Reporting

### 10.1 Markdown report

```bash
cat > /work/repro-report.md <<MD
# $(jq -r '.task.cve' /work/repro-attempt-memory.json) Reproduction Report

**Generated**: $(date -u +%FT%TZ)
**Pipeline**: kali-claw patch-to-poc-pipeline
**Status**: $(jq -r '.convergence_state.status' /work/repro-attempt-memory.json)

## Phase 1 — Patch Analysis

$(jq -r '.patch_analysis | to_entries[] | "- **\(.key)**: \(.value)"' /work/repro-attempt-memory.json)

## Phase 2 — Code Path

$(jq -r '.code_path | to_entries[] | "- **\(.key)**: \(.value)"' /work/repro-attempt-memory.json)

## Phase 3 — Candidate Inputs

$(jq -r '.candidate_inputs[] | "### \(.id)\n- Shape: \(.shape)\n- Status: \(.test_status)"' /work/repro-attempt-memory.json)

## Phase 4 — Differential Verification

- Vulnerable crashed: $(jq -r '.verification_results.vulnerable.crashed' /work/repro-attempt-memory.json)
- Patched crashed: $(jq -r '.verification_results.patched.crashed' /work/repro-attempt-memory.json)
- Stop condition met: $(jq -r '.convergence_state.stop_condition_met' /work/repro-attempt-memory.json)

## Phase 5 — Detection Rules

- YARA: /work/rules/$(jq -r '.task.cve' /work/repro-attempt-memory.json).yar
- Sigma: /work/rules/$(jq -r '.task.cve' /work/repro-attempt-memory.json)-sigma.yml
MD
```

### 10.2 CyberGym submission JSON

```bash
jq '{
  instance_id: (.task.cve + "-" + .task.vulnerable_version),
  task: .task,
  result: .convergence_state,
  artifacts: {
    poc_input: "/work/crashes/crash-POC",
    yara_rule: ("/work/rules/" + .task.cve + ".yar"),
    sigma_rule: ("/work/rules/" + .task.cve + "-sigma.yml"),
    memory_snapshot: "/work/repro-attempt-memory.json"
  }
}' /work/repro-attempt-memory.json > /work/repro-snapshot.json
```

## 11. CyberGym Calibration Run

To calibrate kali-claw against the CyberGym benchmark:

1. **Acquire CyberGym subset** — 50-100 CVE instances spanning bug classes
2. **For each instance**:
   - Run the pipeline
   - Emit CyberGym submission JSON
3. **Aggregate**: `success_rate = (instances with stop_condition_met=true) / subset_size`
4. **Baseline target**: 50% success rate
5. **Stretch target**: 70%+

## 12. Common Pitfalls

### 12.1 Premature stop

Agent declares success without Phase 4 differential verification. Anti-pattern detector catches it; pipeline aborts.

### 12.2 Repeat-without-delta

Agent runs same fuzzer command 5 times hoping for a crash. Memory-driven convergence forces strategy switch at attempt 3.

### 12.3 Memory drift

Agent writes prose findings in `decision_log` without populating structured fields. Anti-pattern detector flags; re-train agent on Schema 3.

### 12.4 Path-claim deadlock

Two agents both claim `harness-entry` path. Atomic write protocol detects duplicate; one agent re-claims a different path.

### 12.5 Free-form exploration

Agent runs commands without reading memory first. The runner enforces `last_read_at` check before every write.

## 13. Hands-On Exercise — CVE-2023-4863 Walkthrough

A complete end-to-end exercise:

1. Acquire libwebp source: `git clone https://chromium.googlesource.com/webm/libwebp /targets/libwebp`
2. Initialize memory: per §3.3
3. Phase 1: per §4.4 — record `suspected_vuln_function = "BuildHuffmanTable()"`
4. Phase 2: per §5.1 — record `code_path.call_chain_to_vuln` and `input_to_vuln_distance = 4`
5. Phase 3: per §6.3 — write `harness_huffman.c`, build with ASan, run fuzzer for 30 min
6. Phase 4: per §7 — differential verify; expect CONFIRMED
7. Phase 5: per §8 — author YARA + Sigma, differential test YARA
8. Report: per §10 — generate markdown + JSON

Expected outcome: `convergence_state.status = "POC_CONFIRMED_DIFFERENTIALLY"`, `stop_condition_met = true`, ~4-6 iterations total.

## 14. References

- SCEN-008 — Patch-Diff Vulnerability Reproduction CyberGym-style (`validation/scenarios/SCEN-008.md`)
- SCEN-MEMORY-SCHEMA — Schema 3 reproduction memory (`validation/scenarios/SCEN-MEMORY-SCHEMA.md`)
- CyberGym paper (ICLR 2026, UC Berkeley)
- MopMonk招三 in kali-claw context (`docs/mopmonk-research-and-kali-claw-plan.md`)
- Skill cross-references:
  - `binary-reverse`, `reverse-engineering-advanced` — Phase 2
  - `exploit-development` — weaponization (out of scope here)
  - `ai-fuzzing` — Phase 3 Strategy B
  - `detection-engineering` — Phase 5 craft
  - `supply-chain-security`, `ci-cd-supply-chain-attack` — defense side
