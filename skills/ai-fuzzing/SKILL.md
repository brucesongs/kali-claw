---
name: ai-fuzzing
description: "AI-assisted fuzzing for automated vulnerability discovery. Coverage-guided fuzzing engines, AI-driven seed generation, intelligent mutation strategies, and systematic crash triage."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: ai
  tool_count: 6
  guide_count: 7
---




# AI-Assisted Fuzzing

> **Supplementary Files**:
> - `payloads.md` — Tool commands and payloads organized by 9 phases (target analysis, corpus preparation, AFL++ execution, libFuzzer, Honggfuzz, web API fuzzing, protocol fuzzing, crash analysis, quick start checklist)
> - `test-cases.md` — Structured test case templates (4 cases covering binary discovery, web API, protocol, and file format fuzzing)
>
> **Extended Guides** (`guides/`):
> - `guides/coverage-guided-fuzzing.md` — AFL++ internals, corpus management, mutation operators, parallel fuzzing, crash triage
> - `guides/web-api-fuzzing.md` — OpenAPI schema fuzzing, GraphQL fuzzing, REST boundary testing, authentication fuzzing
> - `guides/protocol-fuzzing.md` — Network protocol fuzzing, TLS/SSL fuzzing, custom binary protocols, BooFuzz framework

## Summary

Coverage-guided fuzzing engines, AI-driven seed generation, intelligent mutation strategies, and systematic crash triage.

**Tools**: AFL++, libFuzzer, Honggfuzz, radare2, BooFuzz, wfuzz

**Domain**: ai

## Skill Identity

| Attribute | Value |
|-----------|-------|
| Domain | Vulnerability Discovery |
| Skill ID | ai-fuzzing |
| Version | 1.0.0 |
| Hacker Laws | Law 2 (First Principles), Law 5 (Trust but Verify), Law 7 (Divergent Thinking) |
| Related Skills | binary-reverse, verification-loop, knowledge-ops, web-xss, web-sqli |

## Description

AI-assisted fuzzing for automated vulnerability discovery. Coverage-guided fuzzing engines, AI-driven seed generation, intelligent mutation strategies, and systematic crash triage. Integrates with AFL++, libFuzzer, and Honggfuzz to maximize path exploration and uncover memory corruption, logic errors, and parsing flaws in binaries, web APIs, and network protocols.

Fuzzing is the single most effective technique for discovering unknown vulnerabilities at scale. This skill combines traditional coverage-guided approaches with AI-enhanced seed selection and mutation to dramatically increase the probability of reaching deep code paths that manual testing misses.

---

## Use Cases

1. **Binary Vulnerability Discovery** — Fuzz native binaries (C/C++/Rust) for memory corruption: buffer overflows, use-after-free, integer overflows, and null pointer dereferences
2. **Web API Fuzzing** — Systematically test REST/GraphQL endpoints with malformed inputs, boundary values, and unexpected content types to uncover auth bypasses and injection flaws
3. **Protocol Fuzzing** — Fuzz network protocol implementations (TLS, SSH, HTTP parsers, DNS resolvers) by generating malformed packets and invalid state transitions
4. **File Format Fuzzing** — Fuzz parsers for complex file formats (images, documents, archives, media) to discover parsing vulnerabilities in consumer software
5. **Regression Testing** — Maintain continuous fuzzing in CI/CD pipelines to catch regressions and newly introduced vulnerabilities before release

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **AFL++** | Advanced coverage-guided fuzzer, fork of AFL with enhanced instrumentation | `afl-fuzz -i seeds/ -o output/ -m none -- ./target @@` |
| **libFuzzer** | LLVM/Clang built-in fuzzer, in-process coverage-guided fuzzing | `clang -fsanitize=fuzzer,address target.c && ./a.out corpus/` |
| **Honggfuzz** | Feedback-driven fuzzer with hardware-based coverage (Intel PT) | `honggfuzz -i seeds/ -o output/ -- ./target` |
| **radare2** | Crash analysis, reverse engineering, vulnerability root cause identification | `r2 -A crash_sample && pdf @ vuln_func` |
| **BooFuzz** | Python-based network protocol fuzzer, Sulley successor | `python fuzz_template.py` |
| **wfuzz** | Web application fuzzer for parameter brute-forcing and injection testing | `wfuzz -z file,wordlist.txt http://target/FUZZ` |

---

## Methodology

### Attack Chain

```
  Phase 1              Phase 2              Phase 3
 Target Analysis    Corpus Preparation    Fuzzing Execution
 ┌────────────┐     ┌──────────────┐     ┌──────────────┐
 │ Binary ID  │     │ Seed         │     │ AFL++ /      │
 │ Attack     │────>│ Creation &   │────>│ libFuzzer /  │
 │ Surface    │     │ Minimization │     │ Honggfuzz    │
 │ Map        │     │ Quality      │     │ Execution    │
 └────────────┘     └──────────────┘     └──────┬───────┘
                                               │
  Phase 6              Phase 5              Phase 4
  Report &             Crash               Verification
  Hardening            Triage              & PoC
 ┌────────────┐     ┌──────────────┐     ┌──────────────┐
 │ Root Cause │<────│ Dedup &      │<────│ Independent  │
 │ Analysis   │     │ Severity     │     │ Crash        │
 │ Advisory   │     │ Classify     │     │ Reproduction │
 └────────────┘     └──────────────┘     └──────────────┘
```

**Phase Details**:

1. **Target Analysis** — Identify binary format, architecture, and attack surface. Map input parsing functions, file format structures, and protocol state machines. Select fuzzer based on target type and available source/binary.
2. **Corpus Preparation** — Collect seed inputs representing diverse code paths. Minimize corpus with `afl-cmin`/`afl-tmin`. Generate dictionaries from format specifications and string analysis.
3. **Fuzzing Execution** — Launch fuzzer with appropriate instrumentation. Monitor coverage growth and stability. Tune mutation parameters, dictionaries, and memory limits. Run parallel instances for multi-core utilization.
4. **Verification** — Reproduce each unique crash independently. Eliminate false positives (ASAN glitches, OOM, timeout). Confirm exploitability with radare2/GDB analysis.
5. **Crash Triage** — Deduplicate crashes by root cause. Classify severity (code execution, denial of service, information leak). Assess exploitability with exploitability metrics.
6. **Report & Hardening** — Document root cause, affected versions, and reproduction steps. Recommend fixes (input validation, bounds checking, sanitizer integration). Feed crash patterns to knowledge-ops for future reference.

### Defense Perspective

| Defense Technique | Function | How Attackers Respond |
|-------------------|----------|----------------------|
| **Address Sanitizer (ASAN)** | Runtime memory error detection, catches overflows and use-after-free | Fuzz with ASAN builds to find bugs that only manifest with specific memory layouts |
| **OSS-Fuzz** | Google's continuous fuzzing infrastructure for open-source projects | Submit targets to OSS-Fuzz to discover vulnerabilities before attackers do |
| **CI/CD Fuzzing** | Automated fuzzing in build pipelines (fuzz introspector, cifuzz) | Integrate fuzzing into every PR to catch regressions at development time |
| **Sanitizer Integration** | UBSan, MSan, TSan for undefined behavior, memory, and thread issues | Combine multiple sanitizers during fuzzing to maximize bug detection |
| **Coverage-Guided Testing** | Maximize code coverage metrics to improve test effectiveness | Use coverage data to identify untested code paths and focus fuzzing efforts |

---

## Practical Steps

> **For detailed commands and payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.** Below is a summary of core operations for each phase.

### 1. Binary Fuzzing with AFL++

```bash
# Step 1: Instrument the target (source available)
afl-clang-fast -o target_fuzz target.c -fsanitize=address

# Step 2: Prepare minimal seed corpus
mkdir seeds/ && echo "sample" > seeds/seed1
afl-cmin -i seeds/ -o seeds_min/ -- ./target_fuzz @@

# Step 3: Launch fuzzer
afl-fuzz -i seeds_min/ -o findings/ -m none -- ./target_fuzz @@

# Step 4: Analyze crashes
afl-showmap -o /dev/null -- ./target_fuzz findings/default/crashes/id:000001*
```

### 2. Web API Fuzzing

```bash
# Fuzz API parameters with wfuzz
wfuzz -z file,/usr/share/seclists/Fuzzing/big.txt \
  --hc 404,400 http://target/api/v1/FUZZ

# Boundary value testing
wfuzz -z range,0-255 http://target/api/v1/users?id=FUZZ

# Content-type manipulation
for ct in application/json text/xml application/x-www-form-urlencoded; do
  curl -X POST -H "Content-Type: $ct" -d '{"test":"data"}' http://target/api/v1/endpoint
done
```

### 3. Protocol Fuzzing with BooFuzz

```python
# Define protocol structure and fuzz
from boofuzz import *
session = Session(target=Target(connection=TCPSocketConnection("target", 8080)))
s_initialize("request")
s_string("GET", fuzzable=True)
s_delim(" ", fuzzable=True)
s_string("/api/endpoint", fuzzable=True)
s_delim(" ", fuzzable=True)
s_string("HTTP/1.1", fuzzable=True)
s_static("\r\n\r\n")
session.connect(s_get("request"))
session.fuzz()
```

### 4. Crash Analysis Workflow

```bash
# Analyze crash with radare2
r2 -A findings/default/crashes/id:000001*
aaa                          # Full analysis
pdf @ sym.vulnerable_func   # Disassemble crash location
db sym.vulnerable_func      # Set breakpoint at crash site
dc                          # Run until breakpoint

# Analyze ASAN report for root cause
# Look for heap-buffer-overflow, stack-use-after-scope, etc.
ASAN_SYMBOLIZER_PATH=llvm-symbolizer ./target_fuzz crash_input
```

---

## Hacker Laws

| Law | Manifestation in AI Fuzzing |
|-----|----------------------------|
| **First Principles** | Understand the target's input parsing logic before fuzzing. Coverage-guided fuzzing is most effective when you know which code paths are under-tested. Instrumentation reveals what the fuzzer actually reaches. |
| **Trust but Verify** | Every crash requires independent reproduction. Fuzzer output includes many false positives (OOM, timeouts, ASAN glitches). Only independently confirmed crashes become findings. |
| **Divergent Thinking** | When coverage plateaus, try unconventional approaches: custom mutators, grammar-based generation, protocol state machine fuzzing, or combining multiple fuzzers on the same target. |

---

## Orchestration

### ECC Pattern: Learning Cycle

```
┌─────────────────────────────────────────────────────────┐
│                   Learning Cycle                         │
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────────┐      │
│  │ Analyze  │───>│  Fuzz    │───>│   Triage     │      │
│  │ Coverage │    │  Cycle   │    │   Crashes    │      │
│  └────┬─────┘    └──────────┘    └──────┬───────┘      │
│       │                                 │              │
│       │        ┌──────────┐             │              │
│       └────────│ Refine   │<────────────┘              │
│                │ Strategy │                            │
│                └──────────┘                             │
└─────────────────────────────────────────────────────────┘
```

- **Pattern**: Learning Cycle (iterative refinement of fuzzing strategies based on coverage feedback)
- **Rationale**: Fuzzing is inherently iterative — seed quality, mutation strategies, and coverage improve with each cycle. Each round of triage informs the next fuzzing strategy.
- **Integration**:
  - `binary-reverse` — Crash analysis and root cause identification
  - `verification-loop` — Independent finding confirmation before reporting
  - `knowledge-ops` — Persisting crash patterns and successful mutation strategies for future campaigns

### Cross-Skill Pipeline

```
codebase-onboarding → ai-fuzzing → verification-loop → article-writing
      (target          (discover      (confirm each       (document
       analysis)        crashes)       crash)              findings)
```

### Quality Gate

| Gate | Criteria |
|------|----------|
| **Pre-condition** | Target binary or schema is available and instrumented; seed corpus prepared |
| **Post-condition** | Every reported crash reproduced independently with a different method |
| **Verification** | verification-loop Phase 4 (Independent Confirmation) applied to each finding |

---

## Learning Resources

**Supplementary files for this skill**:
- `payloads.md` — Complete command collection organized by 9 phases (ready to copy and use)
- `test-cases.md` — Structured test cases (4 scenarios with preconditions and expected results)

**Extended guides** (`guides/`):
- `guides/coverage-guided-fuzzing.md` — AFL++ internals, mutation operators, corpus management, parallel fuzzing, crash triage, performance tuning
- `guides/web-api-fuzzing.md` — OpenAPI schema fuzzing, GraphQL fuzzing, REST boundary testing, authentication fuzzing, Burp Suite integration
- `guides/protocol-fuzzing.md` — Network protocol fuzzing, TLS/SSL fuzzing, custom binary protocol analysis, BooFuzz framework, real-world examples

**Related skills**:
- `skills/binary-reverse/SKILL.md` — Crash analysis and reverse engineering (used in Phase 4/5)
- `skills/verification-loop/SKILL.md` — Finding confirmation protocol (used in Quality Gate)
- `skills/api-security/SKILL.md` — API attack surface analysis (informs web API fuzzing)

**External resources**:
- [AFL++ Documentation](https://github.com/AFLplusplus/AFLplusplus/tree/stable/docs) — AFL++ architecture, usage, and best practices
- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html) — LLVM fuzzing library reference
- [OSS-Fuzz](https://github.com/google/oss-fuzz) — Google's continuous fuzzing service for open-source software
- [Fuzzing101](https://github.com/antonio-morales/Fuzzing101) — Step-by-step fuzzing tutorial with AFL++
- [The Fuzzing Book](https://www.fuzzingbook.org/) — Comprehensive fuzzing techniques reference
