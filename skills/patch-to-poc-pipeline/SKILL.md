---
name: patch-to-poc-pipeline
description: The end-to-end patch-diff vulnerability reproduction workflow — patch analysis (read diff, identify protective pattern, hypothesize bug class), source or binary-only code path walking (Ghidra + BinDiff), PoC generation (manual craft OR AFL++/libFuzzer harness with ASan/UBSan), CyberGym-style differential verification (vuln crashes, patched clean) as the deterministic stop condition, and YARA + Sigma detection rule authoring tested against both versions. Covers 2024-2026 CVEs (libwebp, xz-utils, runc, glibc Looney Tuner, regreSSHion, MOVEit, Jenkins, Confluence, TeamCity, OFBiz). Solidifies validation/scenarios/SCEN-008.md into a reusable knowledge base and wires in Schema 3 reproduction memory for memory-driven convergence.
origin: kali-claw Wave 12 (v0.1.45) — 2026-07-03
version: "0.2.0.2"
compatibility:
  kali_version: "2025.2"
  python_version: ">=3.11"
  ghidra_required: true
  aflpp_required: true
allowed-tools:
  - git
  - ghidra
  - bindiff
  - radare2
  - angr
  - pwntools
  - afl-fuzz
  - libFuzzer
  - clang
  - asan_symbolize
  - jq
  - yara
  - sigma-cli
  - syft
  - grype
  - python3
  - bash
metadata:
  domain: vuln-research
  tool_count: 17
  guide_count: 2
  mitre: "TA0040-Detection; CWE-787 Out-of-Bounds Write, CWE-125 OOB Read, CWE-190 Integer Overflow, CWE-416 Use-After-Free, CWE-119 Buffer Overflow, CWE-94 Code Injection, CWE-89 SQLi, CWE-22 Path Traversal"
  last_reviewed: "2026-07-26"
---

# Patch-to-PoC Pipeline Skill

> "The patch is a confession. Read it carefully and it will tell you exactly where the bug lives, what shape it has, and how to walk to it from any front door." — traditional vuln-research maxim, paraphrased from Project Zero's "Patch Gapping" methodology.

## Summary

The **patch-to-poc-pipeline** is kali-claw's workflow skill for turning a published patch diff into a working PoC plus detection coverage. It is the **pipeline itself**: the discipline of reading a diff, forming a bug-class hypothesis, walking the code path from attacker-controlled input to the patched sink, generating a trigger input (manually or via fuzzer harness), **differentially verifying** the input crashes the pre-patch binary and leaves the post-patch binary clean, and finally shipping YARA + Sigma rules that fire on the vulnerable pattern and the exploitation telemetry respectively. This skill **solidifies the methodology of `validation/scenarios/SCEN-008.md` into a reusable knowledge base** — the scenario is the per-CVE runbook; this skill is the standing capability that executes it.

The skill is **distinct from its constituents**: it does not teach Ghidra decompilation (`binary-reverse` / `reverse-engineering-advanced` own that), full exploit construction (`exploit-development` owns ROP / shellcode / heap feng shui), fuzzer operation (`ai-fuzzing` owns AFL++/libFuzzer tuning), or generic Sigma/YARA authoring discipline (`detection-engineering` owns that). What this skill owns is the **orchestration contract** between them — the bug-class hypothesis taxonomy that drives Phase 1, the call-chain walking pattern that drives Phase 2, the harness-vs-manual decision matrix that drives Phase 3, the **CyberGym-style differential stop condition** that drives Phase 4, and the Schema 3 reproduction memory that knits every phase into a memory-driven convergence loop.

The strategic value of this skill is calibration. CyberGym (ICLR 2026, UC Berkeley; 1,507 CVEs across 188 OSS projects) evaluates AI agents on exactly this task: given pre-patch source, produce a PoC that crashes the vulnerable build but not the patched build, offline. kali-claw's Q3 2026 external calibration goal is to run this pipeline against a curated CyberGym subset and produce a public success-rate number. Each phase emits a Schema 3 memory delta; the runner halts only when `verification_results.vulnerable.crashed == true` AND `verification_results.patched.crashed == false` — any other terminal state fires an anti-pattern alert. This is the MopMonk "三招" (structured memory + memory-driven convergence + shared-memory multi-agent) applied to vulnerability reproduction.

This skill is the **meta-pipeline** for SCEN-008-class work. When you have a patch in hand and need a PoC plus detection coverage by morning, this is the door you walk through.

### Distinct from adjacent skills

| Skill | Scope | Boundary with this skill |
|-------|-------|--------------------------|
| `binary-reverse` | RE techniques (disassembly, decompilation, Ghidra basics) | Consumed by Phase 2 when source is unavailable |
| `reverse-engineering-advanced` | Deep RE (type recovery, angr symbolic execution, decompiler-aided analysis) | Consumed by Phase 2 for binary-only call-chain reconstruction |
| `exploit-development` | Full exploit construction (ROP, shellcode, heap grooming, GOT overwrite) | This skill stops at a *crashing PoC* — weaponization is out of scope |
| `ai-fuzzing` | Fuzzer operation (corpus curation, mutation strategies, AFL++ tuning, coverage maps) | Consumed by Phase 3 when Strategy B (fuzzer harness) is chosen |
| `detection-engineering` | Generic Sigma/YARA authoring discipline, FP tuning, CI/CD for rules | Consumed by Phase 5 for the craft of writing rules; this skill owns the *specific* YARA/Sigma patterns for the patched bug class |
| `verification-loop` | General verification state-machine for any engagement | This skill uses a *specialized* differential stop condition (vuln-vs-patched) |
| `supply-chain-security` | SBOM-driven software factory defense, dependency confusion | Consumed post-PoC for fleet-scale rollout of the new YARA rule |
| **`patch-to-poc-pipeline`** (this) | **The pipeline that orchestrates the above** — bug-class taxonomy, 5-phase contract, CyberGym differential stop condition, Schema 3 reproduction memory | Owns the workflow itself |

## Use Cases

### Reconnaissance & Triage

1. **Acquire patch from a CVE advisory** — pull `*.patch` from a distro gitweb, GitHub advisory, or the upstream commit ref
2. **Triage patch severity** — `git diff --stat` to scope blast radius; classify as "adds a check" (informative), "refactor" (low signal), or "backdoor" (xz-utils special case)
3. **Cross-reference patch to CWE** — match protective pattern to CWE (bounds check → CWE-787/125, integer guard → CWE-190, free + NULL → CWE-416, etc.)
4. **Rank candidate CVEs** for reproduction by ROI — exploitability × deployment breadth × patch recency
5. **Detect malicious patches (xz-utils case)** — triage for obfuscated control flow, IFUNC hooks, build-system tampering
6. **Map patch to MITRE ATT&CK detection coverage** — pre-stage the Sigma rule's ATT&CK tags before Phase 5

### Phase 1 — Patch Analysis

7. **Read unified diff and identify the protective pattern** — bounds check, type check, sanitize, length validation, NULL check, integer-overflow guard, capability drop
8. **Compute file/line hunk stats** — `lines_added` vs `lines_removed`; patches that only add are most informative
9. **Hypothesize bug class from the 12-class taxonomy** — `memory_corruption | integer_overflow | type_confusion | auth_bypass | path_traversal | sqli | xss | ssrf | use_after_free | oob_read | oob_write | race_condition`
10. **Identify suspected vulnerable function** — usually the function receiving the new check or the file most heavily modified
11. **Initialize Schema 3 memory** with Phase 1 delta — `patch_analysis.{key_change, suspected_vuln_function, suspected_vuln_type, confidence}`
12. **Apply memory-driven convergence check** — abort Phase 2 if `patch_analysis.key_change` is empty (招二: no-evidence path switch)

### Phase 2 — Code Path Walking

13. **Source-available walk** — `grep -rn <vuln_func>` + call graph from public entry point to sink
14. **Binary-only walk** — Ghidra headless decompile + BinDiff "changed functions" diff
15. **Measure attacker-input distance** — call-depth from public API (e.g., `WebPDecode → VP8LDecodeHeader → BuildHuffmanTable`, distance 4)
16. **Recover types from stripped binaries** — apply Ghidra `Auto Type` + angr `Typehoon` if symbols stripped
17. **Pin down the tainted variable** — the exact field of attacker input that reaches the sink
18. **Write Phase 2 memory delta** — `code_path.{entry_function, call_chain_to_vuln, input_to_vuln_distance}`

### Phase 3 — PoC Generation

19. **Choose strategy via decision matrix** — manual craft (well-understood bug, fast) vs fuzzer harness (subtle bug, thorough)
20. **Manual craft via hex editor / Python `struct`** — take a valid sample, mutate the field that controls the vulnerable parameter
21. **Author AFL++/libFuzzer harness** — `LLVMFuzzerTestOneInput` calling the public API with attacker bytes
22. **Compile with sanitizer matrix** — `-fsanitize=fuzzer,address,undefined` (ASan + UBSan) for memory bugs; MSan for uninitialized reads; TSan for race conditions
23. **Construct seed corpus** — valid samples from project's test suite + boundary inputs (max sizes, zero lengths, off-by-one)
24. **Run fuzzer with budget** — `max_total_time=1800` for first pass; record crashes to `artifact_prefix=/work/crashes/`
25. **Triage crash with ASan** — `asan_symbolize` to map stack frames to source lines; verify the crashing function matches Phase 1 hypothesis
26. **Apply convergence rule** — if 3 candidate inputs fail to crash, switch strategy (manual ↔ fuzzer); log `failed_attempts` delta

### Phase 4 — Differential Verification

27. **Build patched binary** with identical harness + sanitizer flags
28. **Run identical PoC against both versions** — capture exit codes and ASan traces separately
29. **Apply CyberGym stop condition** — vuln crashes AND patched clean = CONFIRMED; any other combination = loop back
30. **Detect wrong-root-cause failure** — both crash → re-enter Phase 1 with new hypothesis
31. **Detect PoC-doesn't-reach-bug failure** — neither crashes → re-enter Phase 3 with new candidate input
32. **Emit convergence event** — `[convergence] event=POC_CONFIRMED_DIFFERENTIALLY stop_condition_met=true iterations=N`

### Phase 5 — Detection Rule Authoring

33. **Author YARA rule for vulnerable pattern** — match function name + missing-guard regex; covers source + binary symbol
34. **Test YARA against both versions** — MUST match `libfoo-1.8.2.so`, MUST NOT match `libfoo-1.8.3.so`
35. **Author Sigma rule for exploitation telemetry** — process loading vulnerable `.so` + accessing crafted file extension, or auth-bypass URL pattern
36. **Validate Sigma syntax** — `sigma check` then convert to Splunk / KQL / EQL backends
37. **SBOM-driven fleet rollout** — `syft` + `grype --only-fixed` to find every vulnerable deployment
38. **Emit final Schema 3 memory delta** — `verification_results`, `convergence_state.status=POC_CONFIRMED_DIFFERENTIALLY`
39. **Generate reproduction report** — markdown writeup + JSON memory snapshot for the CyberGym submission format
40. **Retire detection rule post-patch-cycle** — track lifecycle; auto-suppress Sigma after fleet confirmed patched

## Core Tools

### Patch Acquisition & Forensics

| Tool | Vendor / Project | Role |
|------|------------------|------|
| **git** | git project | `git diff`, `git log -p`, `git format-patch` for diff acquisition |
| **patch / git apply** | GNU / git | Apply/reverse patches during reproduction |
| **diffstat** | diffstat project | Hunk-level summary statistics |
| **codespell / regex_scan** | OSS | Surface suspicious strings in patches (xz-utils backdoor detection) |

### Reverse Engineering (binary-only path)

| Tool | Role |
|------|------|
| **Ghidra** (NSA, 11.x) | Headless decompile: `analyzeHeadless` + `DecompileFunction.java` |
| **BinDiff** (Google/Zynamics, 6) | Diff two `.so` files; mark "changed functions" as candidate vuln sites |
| **radare2** | Quick `aaa` + `pdf @ sym.vuln_func` for inline disassembly |
| **angr** | Symbolic execution to walk tainted branches when source unavailable |
| **pwntools** | Crash inspection, ELF parsing, PoC packaging |

### Fuzzing & PoC Generation

| Tool | Role |
|------|------|
| **AFL++** | Coverage-guided fuzzer; `afl-fuzz -M main -S worker1` parallel mode |
| **libFuzzer** (LLVM) | In-process fuzzer; `LLVMFuzzerTestOneInput` harness pattern |
| **clang** | `-fsanitize=fuzzer,address,undefined` one-shot compile |
| **asan_symbolize** | Resolve ASan stack traces back to source lines |
| **afl-cmin / afl-tmin** | Corpus minimization + crash-input minimization |

### Detection & Fleet Scanning

| Tool | Role |
|------|------|
| **YARA** (VirusTotal, 4.x) | Binary + source pattern rules; `yara -s rule.yar target.so` |
| **sigma-cli** (SigmaHQ) | Sigma rule authoring + `sigma check` + `sigma convert -t splunk/kql/eql` |
| **syft** (Anchore) | SBOM generation: `syft image:tag -o json` |
| **grype** (Anchore) | SBOM-driven vulnerability matching: `grype sbom:sbom.json --only-fixed` |
| **jq** | Memory delta application; CyberGym JSON snapshot manipulation |

## Methodology — The 5-Phase Pipeline

The pipeline is a **memory-driven state machine**. Each phase reads Schema 3 memory, executes its task, writes a delta, and emits a convergence check. The runner halts only on the CyberGym stop condition (Phase 4 pass) or an anti-pattern abort.

### Phase 1 — Patch Analysis

**Goal**: read the patch, identify the protective pattern, hypothesize the bug class, and pick the suspected vulnerable function.

**Method**:
1. Acquire patch: `git diff <vuln_tag> <patched_tag> -- <pathspec> > CVE-XXXX-YYYYY.patch`
2. Compute stats: `git diff --stat`, `diffstat -p CVE-XXXX-YYYYY.patch`
3. Classify protective pattern (bounds check | type check | sanitize | length validation | NULL check | integer-overflow guard | capability drop | auth check | backdoor — special case)
4. Map pattern → CWE → bug class via the 12-class taxonomy
5. Identify suspected vulnerable function (recipient of new check)
6. Write Schema 3 delta: `patch_analysis.{files_changed, lines_added, lines_removed, key_change, suspected_vuln_function, suspected_vuln_type, confidence}`

**Memory contract** (Schema 3 before/after):

| Field | Before | After Phase 1 |
|-------|--------|---------------|
| `patch_analysis` | `{}` | populated, 7 fields |
| `patch_analysis.confidence` | `null` | `0.6 - 0.9` (heuristic) |
| `convergence_state.iterations` | `0` | `1` |

**Convergence trigger**: if `patch_analysis.key_change` is empty after this phase, **abort** — no point walking code paths without a hypothesis (招二: memory-driven convergence).

### Phase 2 — Code Path Walking

**Goal**: trace attacker-controlled input from the public API surface down to the patched sink.

**Source-available path**:
```bash
grep -rn "<vuln_func>" /targets/<pkg>-<vuln_ver>/src/
# Build call graph from public entry to vuln function
ctags -R /targets/<pkg>-<vuln_ver>/ && your_callgraph_tool
```

**Binary-only path**:
```bash
/opt/ghidra/support/analyzeHeadless /work proj \
  -import /targets/<pkg>-<vuln_ver>.so \
  -postScript DecompileFunction.java -scriptPath /work/scripts \
  -functionName <vuln_func>

bindiff /targets/<pkg>-<vuln_ver>.so /targets/<pkg>-<patched_ver>.so \
  -o /work/<pkg>.BinDiff
# BinDiff marks <vuln_func> as "changed" — start there
```

**Memory contract**:

| Field | Before | After Phase 2 |
|-------|--------|---------------|
| `code_path.entry_function` | `null` | `"main() → parse_input()"` |
| `code_path.call_chain_to_vuln` | `[]` | `["main", "parse_input", "decode_chunk"]` |
| `code_path.input_to_vuln_distance` | `null` | `3` |

**Convergence trigger**: if no path exists from public API to vuln function (distance = -1), **abort** — the bug may be unreachable from attacker input (defender's win, but no PoC).

### Phase 3 — PoC Generation

**Goal**: produce a candidate input that triggers the patched bug on the vulnerable version.

**Strategy decision matrix**:

| Condition | Strategy |
|-----------|----------|
| Bug class well-understood (memory_corruption from obvious overflow) | A — Manual craft |
| Bug class subtle (type_confusion, race_condition) | B — Fuzzer harness |
| Public test corpus exists | A first, B as backup |
| Phase 1 confidence < 0.7 | B mandatory (manual likely to miss) |
| Sanitizer crash already observed in OSS-Fuzz tracker | A — clone and minimize |

**Strategy A — Manual craft**: take a valid sample, mutate the field that controls the vulnerable parameter with a hex editor or `python3 -c 'import struct; ...'`.

**Strategy B — Fuzzer harness**:
```c
#include "<pkg>/<api>.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    <api>decode(data, size, NULL);
    return 0;
}
```

**Memory contract**:

| Field | Before | After Phase 3 |
|-------|--------|---------------|
| `candidate_inputs[].test_status` | `PENDING` | `VULNERABLE_CRASHED` \| `CLEAN_NO_CRASH` |
| `candidate_inputs[].asan_evidence` | `null` | `"ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."` |
| `convergence_state.iterations` | `1` | `N` (one per candidate) |

**Convergence trigger (招二)**: if `test_status` stays `PENDING` after 3 candidates, **switch strategy** (A ↔ B). Increment `failed_attempts`; force path switch at `>= path_switch_threshold`.

### Phase 4 — Differential Verification (the CyberGym Stop Condition)

**Goal**: confirm PoC crashes vulnerable AND leaves patched clean. **This is the deterministic stop condition CyberGym scores on.**

**Decision matrix**:

| Vulnerable | Patched | Verdict | Next |
|-----------|---------|---------|------|
| crashes | clean | **CONFIRMED** | Phase 5 |
| crashes | crashes | Wrong root cause | Phase 1 with new hypothesis |
| no crash | no crash | PoC doesn't reach bug | Phase 3 with new candidate |
| no crash | crashes | Impossible | Recheck build / harness |

**Memory contract** (the convergence event):

| Field | Before | After Phase 4 |
|-------|--------|---------------|
| `verification_results.vulnerable.crashed` | `null` | `true` |
| `verification_results.patched.crashed` | `null` | `false` |
| `convergence_state.status` | `"IN_PROGRESS"` | `"POC_CONFIRMED_DIFFERENTIALLY"` |
| `convergence_state.stop_condition_met` | `false` | `true` |

**Stop condition**: runner halts only when `vulnerable.crashed == true` AND `patched.crashed == false`. Any other terminal state with `stop_condition_met=true` fires the **"Premature stop"** anti-pattern alert (see `SCEN-MEMORY-SCHEMA.md`).

### Phase 5 — Detection Rule Authoring

**Goal**: ship a YARA rule that fires on the vulnerable pattern across the fleet + a Sigma rule that fires on exploitation telemetry.

**YARA**: source pattern (function name + missing-guard regex) AND binary symbol pattern. Test: MUST match `<pkg>-<vuln_ver>.so`, MUST NOT match `<pkg>-<patched_ver>.so`.

**Sigma**: host/network telemetry rule — e.g., process loading `<vuln_lib>.so` AND accessing crafted file extension; or auth-bypass URL pattern in reverse-proxy logs. Convert to Splunk / KQL / EQL backends via `sigma-cli`.

**Fleet rollout**: `syft` + `grype --only-fixed` to find every deployment of the vulnerable version. Submit detection rule to detection-engineering CI for staged rollout.

## Memory Schema Integration

This skill operates on **Schema 3 — Patch-Diff Reproduction Memory** (see `validation/scenarios/SCEN-MEMORY-SCHEMA.md`):

```json
{
  "schema_version": "1.0",
  "task": {
    "vulnerable_version": "/targets/libfoo-1.8.2",
    "patched_version": "/targets/libfoo-1.8.3",
    "patch_file": "CVE-2024-12345.patch",
    "cve": "CVE-2024-12345"
  },
  "patch_analysis": { /* Phase 1 delta */ },
  "code_path": { /* Phase 2 delta */ },
  "candidate_inputs": [ /* Phase 3 delta */ ],
  "verification_results": { /* Phase 4 delta */ },
  "convergence_state": {
    "iterations": 4,
    "status": "POC_CONFIRMED_DIFFERENTIALLY",
    "stop_condition_met": true
  }
}
```

**MopMonk "三招" applied**:

1. **招一 (Structured memory)**: every phase reads + writes JSON, never prose
2. **招二 (Memory-driven convergence)**: 3 evidence-free attempts → path switch; empty `patch_analysis.key_change` → abort Phase 2
3. **招三 (Shared-memory multi-agent)**: parallel agents claim distinct paths (`patch-diff`, `harness-entry`, `sanitizer`) against the same memory file via atomic writes + version vector

**Anti-patterns the runner enforces**:

| Anti-Pattern | Detection |
|--------------|-----------|
| Free-form exploration | `memory_lock.last_read_at` is null when write attempted |
| Memory drift | Decision-log entry references finding not in `findings[]` |
| Repeat-without-delta | `failed_attempts >= 3` on same hypothesis |
| Path-claim deadlock | `active_paths` has duplicate values |
| Premature stop | `stop_condition_met=true` but `verification_results` has null fields |

## Practical Steps

### Step A — Acquire and triage the patch

```bash
# Example: CVE-2023-4863 libwebp heap buffer overflow
cd /targets/libwebp
git clone https://chromium.googlesource.com/webm/libwebp .
git checkout v1.3.2  # patched tag
git diff v1.3.1 v1.3.2 -- src/dec/huffman_dec.c > /work/CVE-2023-4863.patch
git diff v1.3.1 v1.3.2 --stat
# src/dec/huffman_dec.c | 17 ++++++++++-------
# 1 file changed, 14 insertions(+), 3 deletions(-)

diffstat -p /work/CVE-2023-4863.patch
# huffman_dec.c | 14 ++++++++++++--
# 1 file changed, 12 insertions(+), 2 deletions(-)
```

### Step B — Identify protective pattern and hypothesize bug class

```bash
# View the diff
git diff v1.3.1 v1.3.2 -- src/dec/huffman_dec.c | less
# Key change: +if (table_size >= (1U << 31)) return NULL;
# Protective pattern: integer-overflow guard before calloc
# Bug class hypothesis: memory_corruption (heap-buffer-overflow from undersized alloc)
# CWE: CWE-787 Out-of-Bounds Write (root cause: CWE-190 Integer Overflow)
```

Apply Schema 3 delta:

```bash
tmp=$(mktemp)
jq '.patch_analysis = {
  "files_changed": ["src/dec/huffman_dec.c"],
  "lines_added": 14, "lines_removed": 3,
  "key_change": "Added overflow check on Huffman table size; rejects code-length sequences yielding >= 2^31 entries",
  "suspected_vuln_function": "BuildHuffmanTable()",
  "suspected_vuln_type": "heap-buffer-overflow",
  "confidence": 0.85
} | .convergence_state.iterations += 1' \
  /work/repro-attempt-memory.json > "$tmp" && mv "$tmp" /work/repro-attempt-memory.json
```

### Step C — Walk the code path

```bash
# Source-available
grep -rn "BuildHuffmanTable" /targets/libwebp-1.3.1/src/
# src/dec/huffman_dec.c:187: static int BuildHuffmanTable(...) { ... }
# src/dec/vp8l_dec.c:412:   ok = BuildHuffmanTable(...);
grep -rn "VP8LBuildHuffmanTable\|VP8LDecodeHeader\|WebPDecode" /targets/libwebp-1.3.1/src/ | head
# Call chain (distance 4):
# WebPDecode → VP8LDecodeImageStream → VP8LDecodeHeader → VP8LBuildHuffmanTable → BuildHuffmanTable
```

```bash
# Binary-only alternative
/opt/ghidra/support/analyzeHeadless /work proj \
  -import /targets/libwebp-1.3.1.so \
  -postScript DecompileFunction.java -scriptPath /work/scripts \
  -functionName BuildHuffmanTable

bindiff /targets/libwebp-1.3.1.so /targets/libwebp-1.3.2.so \
  -o /work/libwebp-1.3.1_vs_1.3.2.BinDiff
```

### Step D — Generate the PoC (Strategy B: AFL++/libFuzzer harness)

```c
// /work/harness_huffman.c
#include "webp/decode.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    WebPDecode(data, size, NULL);
    return 0;
}
```

```bash
# Build with sanitizer matrix
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I/targets/libwebp-1.3.1 \
  /work/harness_huffman.c /targets/libwebp-1.3.1/src/.libs/libwebp.a \
  -o /work/harness_vulnerable

# Seed corpus
mkdir -p /work/seeds && cp /targets/samples/*.webp /work/seeds/

# Run with 30-minute budget
ASAN_OPTIONS=detect_leaks=0 /work/harness_vulnerable /work/seeds/ \
  -max_len=65536 -max_total_time=1800 -artifact_prefix=/work/crashes/

# Inspect crash
# ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200005cfe1
# WRITE of size 1 at 0x60200005cfe1 thread T0
#     #0 0x... in BuildHuffmanTable src/dec/huffman_dec.c:187
#     #1 0x... in VP8LBuildHuffmanTable ...
```

### Step E — Differential verification (the CyberGym stop condition)

```bash
# Build patched harness (identical flags)
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I/targets/libwebp-1.3.2 \
  /work/harness_huffman.c /targets/libwebp-1.3.2/src/.libs/libwebp.a \
  -o /work/harness_patched

# Run the SAME PoC against both
for variant in vulnerable patched; do
  ASAN_OPTIONS=symbolize=1:abort_on_error=1 \
    /work/harness_${variant} /work/crashes/crash-POC \
    > /work/${variant}.stdout 2> /work/${variant}.stderr
  echo "exit=$?" > /work/${variant}.exitcode
done

# Inspect
cat /work/vulnerable.exitcode  # exit=1 (ASan abort)
cat /work/patched.exitcode     # exit=0 (clean)
head -1 /work/vulnerable.stderr  # ERROR: AddressSanitizer: heap-buffer-overflow...
```

```bash
# Emit convergence event
jq -n --slurpfile v /work/vulnerable.exitcode --slurpfile p /work/patched.exitcode '{
  convergence_event: "POC_CONFIRMED_DIFFERENTIALLY",
  vulnerable_crashed: ($v[0]|tonumber > 0),
  patched_crashed: ($p[0]|tonumber > 0),
  stop_condition_met: (($v[0]|tonumber > 0) and ($p[0]|tonumber == 0))
}'
```

### Step F — Author and test detection rules

```yara
rule CVE_2023_4863_libwebp_huffman_overflow {
    meta:
        description = "libwebp BuildHuffmanTable heap-buffer-overflow (CVE-2023-4863)"
        cve         = "CVE-2023-4863"
        cvss        = 8.8
        patched_in  = "libwebp 1.3.2"
        author      = "kali-claw patch-to-poc-pipeline"
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

```bash
# Test both versions — differential YARA check
yara -s /work/rules/CVE-2023-4863.yar /targets/libwebp-1.3.1.so   # MUST match
yara -s /work/rules/CVE-2023-4863.yar /targets/libwebp-1.3.2.so   # MUST NOT match
```

```yaml
# Sigma rule for exploitation telemetry
title: Potential CVE-2023-4863 libwebp Exploitation
id: 7c4f8a9b-1e2d-4a3b-9c5d-7e8f9a0b1c2d
status: experimental
description: Detects processes loading a vulnerable libwebp and accessing crafted WebP inputs.
author: kali-claw patch-to-poc-pipeline
date: 2026/07/03
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

```bash
sigma check /work/rules/CVE-2023-4863-sigma.yml
sigma convert -t splunk /work/rules/CVE-2023-4863-sigma.yml
sigma convert -t kql     /work/rules/CVE-2023-4863-sigma.yml
```

### Step G — Fleet rollout via SBOM

```bash
syft /targets/production-image:latest -o json > /work/sbom.json
jq '.artifacts[] | select(.name=="libwebp") | {name, version, locations}' /work/sbom.json
grype sbom:/work/sbom.json --only-fixed | grep libwebp
```

## CyberGym Calibration Hook

CyberGym (ICLR 2026, UC Berkeley; 1,507 CVEs across 188 OSS projects) evaluates AI agents on exactly this task. Phase 4's stop condition is the CyberGym scoring criterion.

| CyberGym task component | This skill's phase |
|------------------------|---------------------|
| Receive (vuln source, patch) | Phase 1 input |
| Identify root cause | Phase 1 + 2 |
| Generate PoC | Phase 3 |
| Differential verification | Phase 4 (the stop condition) |
| Detection rule (kali-claw extension) | Phase 5 |

**Q3 2026 calibration plan**: run this pipeline against a 50-100 instance CyberGym subset spanning `memory_corruption`, `integer_overflow`, `type_confusion`, `auth_bypass`, `sqli`, `xss`, `ssrf`, `path_traversal`. Success criterion: `convergence_state.stop_condition_met == true` AND `status == "POC_CONFIRMED_DIFFERENTIALLY"` for ≥ 50% of subset. See `docs/mopmonk-research-and-kali-claw-plan.md` §5.4 for the long-term plan.

### Defense Perspective

### Compiler flags that close the bug class at the source

| Flag | Bug class closed | Why |
|------|------------------|-----|
| `-fsanitize=address` | Heap/stack OOB, UAF, double-free | Runtime trap; CI failures on regression |
| `-fsanitize=undefined` | Integer overflow, shift OOB, type confusion | Catches CWE-190 feeding CWE-787 |
| `-fsanitize=memory` | Uninitialized reads | Catches CWE-908 |
| `-fsanitize=thread` | Race conditions | Catches CWE-362 |
| `-D_FORTIFY_SOURCE=3` | libc `memcpy`/`sprintf` overflow | GLIBC 2.34+ fortify at compile + runtime |
| `-ftrapv` | Signed integer overflow | Trap instead of wrap |
| `-fstack-protector-strong` | Stack buffer overflow | Canary on functions with buffers |
| `-fstack-clash-protection` | Stack-clash probes | Guard page enforcement |
| `-fcf-protection=full` | ROP / JOP | Intel CET shadow stack + IBT |

### Static analyzers that flag the bug class pre-build

- **CodeQL** queries: `cpp/uncontrolled-allocation-size`, `cpp/suspicious-allocation-size`, `cpp/unbounded-write`, `cpp/tainted-allocation-size`
- **Semgrep** rules: arithmetic accumulation feeding `malloc`/`calloc` without overflow guard; tainted SQL string construction; missing auth check on route handler
- **Coverity** defect classes: `TAINTED_SCALAR`, `BUFFER_OVERFLOW`, `USE_AFTER_FREE`, `SQL_INJECTION`
- **Trail of Bits Slither** (Solidity/Web3 patches): reentrancy, unchecked arithmetic

### SBOM-driven fleet scanning

```bash
# Generate SBOM per image
syft /targets/production-image:latest -o cyclonedx-json > sbom.json

# Match vulnerable versions
grype sbom:sbom.json --only-failed --fail-on=high

# Custom YARA-based scan for backdoored builds (xz-utils case)
yara -r /work/rules/backdoor-patterns.yar /targets/
```

### CI gates that prevent recurrence

1. **Sanitizer builds in CI** — every PR compiles with `-fsanitize=address,undefined`; ASan trace fails CI
2. **OSS-Fuzz integration** — project's fuzzer harnesses run nightly; crashes open issues
3. **Patch-diff as regression test** — every committed patch ships with a crashing input that the new code must reject (one-way ratchet; bug cannot regress)
4. **CodeQL PR gate** — block merge on new `cpp/uncontrolled-allocation-size` findings
5. **Reproducible builds** — detect malicious build-system tampering (xz-utils mitigation)

### Skill cross-references

- **`supply-chain-security`** — SBOM-driven vulnerability management across the software factory
- **`ci-cd-supply-chain-attack`** — red-team CI/CD attacks; companion defense side: ASan/UBSan gates in CI
- **`detection-engineering`** — generic Sigma/YARA authoring discipline; this skill's Phase 5 produces bug-specific instances of those rules
- **`binary-reverse`** / **`reverse-engineering-advanced`** — Phase 2 RE techniques
- **`exploit-development`** — Phase 3 stops at *crashing PoC*; weaponization (ROP / shellcode / heap feng shui) lives there
- **`ai-fuzzing`** — Phase 3 Strategy B (fuzzer harness) consumes this skill

## Hacker Laws Mapping

This skill aligns with the following Hacker Laws from `SOUL.md`:

- **Law 1 (Read the source, Luke)** — Phase 1 and 2 are entirely source-driven; the patch is the confession
- **Law 4 (Make it crash, then make it work)** — Phase 3 strategy B (fuzzer harness) operationalizes this
- **Law 6 (Diff before trust)** — Phase 4 differential verification is the formal expression of "trust nothing until you've seen both sides"
- **Law 8 (Defense in depth, offense in breadth)** — Phase 5 YARA + Sigma + SBOM is the three-axis detection coverage
- **Law 11 (Leave the camp cleaner than you found it)** — every CVE reproduced ships a YARA + Sigma rule that protects the entire fleet going forward

## Detection Methods

### Patch Diff Analysis
- **CVE patch monitoring**: NVD, vendor security advisories; alert on new patches in dependent software.
- **Patch-to-PoC tracking**: Monitor GitHub, ExploitDB for PoC code matching recently patched CVEs.
- **Function-level diff**: Track changes in security-sensitive functions (alloc, copy, parse).

### Runtime Detection
- **Vulnerability scanner**: Nessus, Qualys; identify unpatched versions in environment.
- **IDS signatures**: Snort / Suricata rules for known exploits.
- **EDR detection**: Process anomalies matching known exploit patterns.

### SIEM Detection Rules
- **Splunk SPL**: `index=vuln scanner=nessus | where cve_id matches "2025-*" | stats count by host`
- **CISA KEV catalog**: Cross-reference internal vuln scan with Known Exploited Vulnerabilities.

## Defense Evasion Techniques

### PoC Weaponization Stealth
- **Single-shot exploitation**: One exploit attempt per target; below sustained-pattern detection.
- **Memory-only execution**: Run exploit from RAM; no disk artifacts.
- **Use legitimate processes**: Inject exploit into legitimate process (e.g., browser, web server).

### Detection Evasion
- **Slow exploitation**: Pace exploit attempts below IDS threshold.
- **Use new CVEs**: Exploit CVEs less than 30 days old; detection rules lag.
- **Variants**: Modify public PoC to evade signature detection.
- **Cross-architecture**: Port PoC to less-monitored architecture (e.g., ARM64 vs x86_64).

## Learning Resources

- **Berkeley CyberGym paper** (ICLR 2026) — UC Berkeley; benchmark of 1,507 CVEs across 188 OSS projects; differential stop condition is the scoring criterion this skill is calibrated against
- **Project Zero Patch Gapping** — https://googleprojectzero.blogspot.com/ — Methodology of using patch diffs as the starting point for 1-day exploit research
- **OSS-Fuzz tracker** — https://oss-fuzz.com/ — Public fuzzer infrastructure; every CVE reproduced here typically has a reproducer input available
- **Mandiant Vulnerability Research** — https://www.mandiant.com/resources/blog — Real-world reproduction writeups (MOVEit, Ivanti, Citrix NetScaler)
- **Microsoft MSRC** — https://msrc.microsoft.com/ — Patch Tuesday diffs; privileged POV on patch-gapping
- **Google TAG (Threat Analysis Group)** — https://tag.google/ — In-the-wild exploitation telemetry that informs Sigma rule authoring
- **CrowdStrike Reverse Engineering Reports** — https://www.crowdstrike.com/blog/ — Binary-only Phase 2 walkthroughs (Ghidra + BinDiff)
- **SigmaHQ** — https://github.com/SigmaHQ/sigma — Public Sigma rule corpus; pattern source for Phase 5 authoring
- **YARA-X** — https://github.com/VirusTotal/yara-x — Next-gen YARA engine; performance and syntax extensions

## References

- SCEN-008 — Patch-Diff Vulnerability Reproduction CyberGym-style (`validation/scenarios/SCEN-008.md`) — the per-CVE runbook this skill solidifies
- SCEN-MEMORY-SCHEMA — Schema 3 reproduction memory (`validation/scenarios/SCEN-MEMORY-SCHEMA.md`) — the structured memory contract
- MopMonk research notes (`docs/mopmonk-research-and-kali-claw-plan.md` §5.4) — CyberGym calibration plan
- CVE-2023-4863 libwebp — flagship worked example carried through every phase above
- CVE-2024-3094 xz-utils — backdoor-in-patch special case (see `guides/real-world-incident-case-studies.md` Case 2)
- CWE-787 (OOB Write), CWE-125 (OOB Read), CWE-190 (Integer Overflow), CWE-416 (UAF) — the dominant bug classes this pipeline reproduces
- MITRE ATT&CK — TA0040-Detection mapping for Phase 5 Sigma rules
