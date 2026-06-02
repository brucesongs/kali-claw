# Coverage-Guided Fuzzing: Deep Dive

## Introduction

Coverage-guided fuzzing is a dynamic testing technique that uses code coverage feedback to generate inputs that explore new execution paths. This guide covers the theory and practice of coverage-guided fuzzing using AFL++, libFuzzer, and Honggfuzz, with real-world examples of vulnerability discovery through fuzzing.

> Companion to `skills/ai-fuzzing/SKILL.md`. This guide covers AFL++ internals, corpus management, mutation operators, parallel fuzzing strategies, crash triage workflows, and performance tuning.

---

## 1. AFL++ Internals

### Coverage Instrumentation

AFL++ instruments compiled code at basic block boundaries to track which code paths are exercised during execution. The instrumentation is inserted at compile time by the modified compiler (`afl-clang-fast`, `afl-clang-lto`).

**Instrumentation types (in order of preference)**:

| Type | Mechanism | Performance | Coverage Quality |
|------|-----------|-------------|-----------------|
| `afl-clang-lto` | LLVM link-time optimization | Fast | Best (full program) |
| `afl-clang-fast` | LLVM pass instrumentation | Fast | Good |
| `afl-gcc` | GCC plugin instrumentation | Medium | Good |
| `afl-compiler-rt` | Runtime library (QEMU mode) | Slow | Basic |
| `afl-qemu-trace` | Binary-only QEMU tracing | Slowest | Basic |

**How coverage is tracked**:

```
Source code         Instrumented code
┌──────────────┐    ┌──────────────────────────────┐
│ if (x > 0) { │    │ cov_shm[id_A]++;             │
│   foo();     │──> │ foo();                       │
│ } else {     │    │ } else {                     │
│   bar();     │    │ cov_shm[id_B]++;             │
│ }            │    │ bar();                       │
│              │    │ }                            │
└──────────────┘    └──────────────────────────────┘
```

Each basic block transition (edge) gets a unique ID. The fuzzer maintains a 64KB shared memory bitmap where each byte tracks how many times a particular edge has been hit. New edge transitions discovered by mutated inputs drive the fuzzing loop forward.

### Edge Coverage and Path Discovery

AFL++ tracks **edges** (transitions between basic blocks), not just basic blocks. This matters because the same block reached from different predecessors represents different program behaviors.

**Edge hashing formula**:

```
edge_id = (current_block << 1) ^ previous_block
```

This means path `A -> B -> C` and path `X -> B -> C` produce different edge IDs, even though they share block `B`. This granularity catches significantly more behavioral differences than block-level coverage alone.

**Path discovery process**:

1. Fuzzer mutates a seed input from the corpus
2. Executes the mutated input through the instrumented target
3. Compares the resulting coverage bitmap against all previously seen bitmaps
4. If new edges are discovered, the mutated input is added to the corpus
5. If no new edges, the mutation is discarded

This feedback loop is what makes coverage-guided fuzzing so powerful: every new discovery feeds back into the mutation engine.

### AFL++ Dashboard Interpretation

```
┌─────────────────────────────────────────────────────────────┐
│  afl-fuzz status: running                                    │
│                                                              │
│  overall results:  cycles done: 42    total paths: 1,247    │
│                     total crashes: 23  total tmouts: 156     │
│                                                              │
│  last new path: 0:05:12 ago  last unique crash: 1:42:33 ago │
│                                                              │
│  stability: 99.8%  map density: 4.2%                        │
│                                                              │
│  stage progress:  stage: havoc  value: 42/100               │
│                   exec speed: 12,450/sec                     │
│                                                              │
│  fuzzing strategy yields:                                    │
│    bit flip: 1/256   arith 8/8: 0/128                       │
│    havoc: 3/1024     splice: 1/512                          │
└─────────────────────────────────────────────────────────────┘
```

**Key metrics to watch**:

- **stability**: Should remain above 90%. Low stability means non-deterministic behavior (timestamps, random numbers, threads).
- **map density**: Percentage of coverage bitmap filled. Above 80% means the target is very complex and may need custom mutators.
- **last new path**: Time since last new coverage. If this keeps growing, coverage is plateauing.
- **exec speed**: Higher is better. Persistent mode can increase this 10-100x.

---

## 2. Corpus Management

### Seed Selection

Good seeds are the foundation of effective fuzzing. Seed quality directly determines how quickly the fuzzer explores the target's code paths.

**Seed selection criteria**:

| Criteria | Why It Matters | How to Achieve |
|----------|---------------|----------------|
| Diversity | Different seeds exercise different code paths | Collect samples from various sources |
| Minimal size | Smaller inputs mutate faster | Minimize with `afl-tmin` |
| Valid structure | Well-formed inputs reach deep parsing logic | Use real-world samples |
| Edge coverage | Each seed should contribute unique edges | Verify with `afl-showmap` |

**Seed sources**:

```bash
# 1. Real-world samples (best quality)
cp /path/to/production/samples/* seeds/

# 2. Minimal valid inputs
echo '{"key":"val"}' > seeds/json_min
printf '\x89PNG\r\n\x1a\n' > seeds/png_header

# 3. Generated from format specifications
# Create seeds based on RFC or protocol docs
python3 generate_seeds.py > seeds/generated

# 4. Captured traffic (for protocol fuzzing)
tcpdump -r capture.pcap -X | extract_payloads.py > seeds/
```

### Corpus Minimization

Minimizing the corpus removes redundant seeds while preserving coverage.

```bash
# Step 1: Remove seeds that don't contribute unique coverage
afl-cmin -i seeds/ -o seeds_cmin/ -- ./target @@

# Step 2: Minimize each individual seed to smallest size
for f in seeds_cmin/*; do
  afl-tmin -i "$f" -o "seeds_min/$(basename $f)" -- ./target @@
done

# Step 3: Verify all minimized seeds still produce unique paths
for f in seeds_min/*; do
  hash=$(afl-showmap -m none -o /dev/null -- ./target "$f" 2>&1 | grep "paths")
  echo "$f: $hash"
done
```

### Quality Metrics

Track these metrics to evaluate corpus health:

```bash
# Total unique edges covered
afl-showmap -m none -o map.txt -- ./target seed_input
wc -l map.txt

# Corpus size vs. coverage ratio
echo "Seeds: $(ls seeds/ | wc -l)"
echo "Unique edges: $(cat merged_map.txt | wc -l)"

# Check for unstable seeds (non-deterministic paths)
for f in seeds/*; do
  h1=$(afl-showmap -m none -o /tmp/m1 -- ./target "$f" && md5sum /tmp/m1)
  h2=$(afl-showmap -m none -o /tmp/m2 -- ./target "$f" && md5sum /tmp/m2)
  if [ "$h1" != "$h2" ]; then
    echo "UNSTABLE: $f"
  fi
done
```

---

## 3. Mutation Operators

AFL++ applies a sequence of mutation stages to each seed. Understanding these stages helps diagnose why coverage plateaus and when to switch strategies.

### Built-in Mutation Stages

**Stage 1: Bit Flip**

Systematically flips individual bits in the input.

```
Original:  0x41 0x42 0x43 0x44  (8 bits each)
Flip bit 0: 0x40 0x42 0x43 0x44
Flip bit 1: 0x43 0x42 0x43 0x44
Flip bit 2: 0x45 0x42 0x43 0x44
...
```

Variations: flip 1 bit, flip 2 consecutive bits, flip 4 consecutive bits.

**Stage 2: Arithmetic Operations**

Replaces values with nearby arithmetic results.

```
Original byte:  0x41 (65)
-1:  0x40 (64)
+1:  0x42 (66)
-2:  0x3F (63)
+2:  0x43 (67)
...
```

Applied to 8-bit, 16-bit, and 32-bit values at interesting offsets.

**Stage 3: Interesting Values**

Inserts known "interesting" values that tend to trigger edge cases:

```
8-bit:  0x00, 0x01, 0xFF, 0x7F, 0x80
16-bit: 0x0000, 0x0001, 0xFFFF, 0x7FFF, 0x8000
32-bit: 0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000
```

**Stage 4: Dictionary Operations**

If a dictionary is provided, inserts dictionary tokens at random positions.

**Stage 5: Havoc**

Random combination of multiple mutation operations applied to a single input:

```
- Random bit flips
- Random byte insertions/deletions
- Random arithmetic operations
- Random dictionary insertions
- Random block duplication/deletion
- Random byte replacement with interesting values
```

Havoc is the most productive stage for finding deep bugs because it makes large structural changes.

**Stage 6: Splice**

Takes two different seeds from the corpus and combines them at a random crossover point:

```
Seed A: AAAA|BBBB
Seed B: CCCC|DDDD
Result: AAAADDDD   (splice at midpoint)
```

This creates novel inputs that exercise previously unreachable code paths.

### Custom Mutators

When built-in mutations plateau, custom mutators can dramatically improve results.

```python
#!/usr/bin/env python3
"""AFL++ custom mutator example for JSON fuzzing"""
import json
import random

def init(seed):
    """Called once at startup. seed is the initial seed."""
    return seed

def fuzz(buf, add_buf, max_size):
    """Called for each mutation. Return mutated input."""
    try:
        data = json.loads(buf.decode('utf-8', errors='ignore'))
        # Mutate a random field
        keys = list(data.keys())
        if keys:
            key = random.choice(keys)
            data[key] = random.choice([
                None, True, False, 0, -1, 2147483647,
                "A" * 10000, [], {}, b'\x00' * 100
            ])
        return json.dumps(data).encode()
    except (json.JSONDecodeError, AttributeError):
        # Fall back to random byte mutation
        pos = random.randint(0, len(buf) - 1)
        buf = buf[:pos] + bytes([random.randint(0, 255)]) + buf[pos+1:]
        return buf
```

---

## 4. Persistent Mode and Deferred Forkserver

### Persistent Mode

Persistent mode avoids the overhead of fork() for every test case, allowing the target to process multiple inputs in a single process lifetime.

```c
// Persistent mode harness
#include <stdio.h>
#include <unistd.h>

// Target function to fuzz
extern int parse_input(const char *data, size_t len);

int main(void) {
    char buf[65536];

    // __AFL_LOOP: process multiple inputs without re-forking
    while (__AFL_LOOP(10000)) {
        ssize_t len = read(0, buf, sizeof(buf));
        if (len > 0) {
            parse_input(buf, len);
        }
    }
    return 0;
}
```

**Performance comparison**:

| Mode | Executions/sec | Overhead |
|------|---------------|----------|
| Standard (fork per input) | 500-2,000 | High (fork overhead) |
| Deferred forkserver | 2,000-8,000 | Medium |
| Persistent mode | 20,000-100,000+ | Minimal |

**Important caveats for persistent mode**:
- Reset all global state between iterations (no leftover state from previous input)
- Do not rely on process cleanup (malloc cleanup, file handles)
- The loop count (10000) is a maximum; AFL++ may interrupt earlier
- Not suitable for targets with complex global state or persistent connections

### Deferred Forkserver

Deferred forkserver delays instrumentation initialization until after program setup, saving time on targets with expensive initialization.

```c
// Deferred forkserver: manual initialization
#include <stdio.h>
extern void expensive_init(void);
extern int parse_input(const char *data, size_t len);

int main(void) {
    // Run expensive init ONCE before forkserver starts
    expensive_init();

    // Signal AFL++ that we are ready for forkserver
    __AFL_INIT();

    // This code runs after fork() in each child
    char buf[65536];
    ssize_t len = read(0, buf, sizeof(buf));
    if (len > 0) {
        parse_input(buf, len);
    }
    return 0;
}
```

Compile and run:

```bash
afl-clang-fast -o target_deferred harness.c target.c
afl-fuzz -i seeds/ -o findings/ -m none -- ./target_deferred
```

---

## 5. Parallel Fuzzing

### Multi-Core Strategy

AFL++ supports parallel fuzzing by running multiple instances that share a single output directory. Each instance discovers new paths and feeds them to all other instances.

```
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│  Main    │  │  Sub 1   │  │  Sub 2   │  │  Sub 3   │
│  (determ)│  │  (havoc) │  │  (havoc) │  │  (custom)│
│  -M main │  │  -S sub1 │  │  -S sub2 │  │  -S sub3 │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │             │
     v             v             v             v
┌──────────────────────────────────────────────────┐
│              Shared findings/ directory           │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ corpus/  │  │ crashes/ │  │ hangs/        │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
└──────────────────────────────────────────────────┘
```

### Job Distribution

```bash
# Determine number of cores available
nproc  # e.g., returns 8

# Strategy: 1 main + (N-1) secondary nodes
# With 8 cores: 1 main + 7 secondary

# Main node (deterministic fuzzing + havoc)
afl-fuzz -i seeds/ -o findings/ -M main -m none -- ./target @@

# Secondary nodes (different strategies)
afl-fuzz -i seeds/ -o findings/ -S sub1 -m none -- ./target @@
afl-fuzz -i seeds/ -o findings/ -S sub2 -m none -L 0 -- ./target @@  # CMPLOG
afl-fuzz -i seeds/ -o findings/ -S sub3 -m none -x dict.txt -- ./target @@  # With dict
# ... more secondary nodes as needed
```

**Strategy assignment for secondary nodes**:

| Node Count | Recommended Strategy |
|------------|---------------------|
| 2-4 cores | 1 main + 1-3 secondary (default) |
| 4-8 cores | 1 main + 1 CMPLOG + 1 dictionary + rest default |
| 8+ cores | 1 main + 1 CMPLOG + 1 custom mutator + 1 dictionary + rest default |

### Monitoring Parallel Campaigns

```bash
# Watch overall progress
watch -n 5 'ls findings/main/corpus/ | wc -l; \
  ls findings/main/crashes/ | wc -l; \
  ls findings/sub1/corpus/ | wc -l'

# AFL++ whippets dashboard (if installed)
afl-whatisup findings/

# Check for path sharing between nodes
diff <(ls findings/main/corpus/) <(ls findings/sub1/corpus/)
```

---

## 6. Crash Triage

### Crash Deduplication

AFL++ performs basic deduplication by crash path, but many crashes may share the same root cause.

```bash
# List all unique crashes
ls findings/default/crashes/ | grep -v README

# Categorize crashes by ASAN error type
for crash in findings/default/crashes/id:*; do
  result=$(timeout 5 ./target_asan "$crash" 2>&1)
  error_type=$(echo "$result" | grep -oP "ERROR: AddressSanitizer: \K[^ ]+")
  echo "$(basename $crash): $error_type"
done

# Expected output:
# id:000000: heap-buffer-overflow
# id:000001: stack-buffer-overflow
# id:000002: heap-buffer-overflow
# id:000003: null-deref
```

### Severity Classification

| Severity | ASAN Error Type | Impact |
|----------|----------------|--------|
| **Critical** | heap-buffer-overflow (write), use-after-free | Remote code execution likely |
| **High** | stack-buffer-overflow, heap-buffer-overflow (read) | Potential code execution, information leak |
| **Medium** | null-deref, integer-overflow | Denial of service, unexpected behavior |
| **Low** | memory-leaks, timeout | Resource exhaustion, quality issue |

### Exploitability Assessment

```bash
# Method 1: !exploitable GDB plugin
gdb -batch \
  -ex "set pagination off" \
  -ex "run < crash_input" \
  -ex "!exploitable -v" \
  --args ./target crash_input

# Method 2: Manual assessment with radare2
r2 -d -A target
db sym.vulnerable_func
dc
dr                              # Check registers
px 64 @ rsp                     # Check stack content
dbt                             # Backtrace

# Method 3: ASAN exploitability hints
ASAN_OPTIONS=abort_on_error=1:print_legend=1 \
  ./target_asan crash_input 2>&1 | grep -A5 "SUMMARY"
```

### Crash Triage Workflow

```
Raw crashes (from fuzzer)
       │
       v
  Reproduce each crash
  (ASAN build, timeout 5s)
       │
       ├─── Unreproducible ──> Discard (environment artifact)
       │
       v
  Group by error type
  (heap-overflow, uaf, null-deref)
       │
       v
  Deduplicate within groups
  (compare crash stacks, root cause)
       │
       v
  Assign severity
  (Critical/High/Medium/Low)
       │
       v
  Independent verification
  (verification-loop Phase 4)
       │
       v
  Confirmed findings
  (report + PoC)
```

---

## 7. Performance Tuning

### Memory Limits

```bash
# Default memory limit is 256MB - may be too low
# Set to unlimited (-m none) if target legitimately uses more memory
afl-fuzz -i seeds/ -o findings/ -m none -- ./target @@

# Or set a specific limit (e.g., 2GB)
afl-fuzz -i seeds/ -o findings/ -m 2048 -- ./target @@
```

### Timeout Calibration

```bash
# Find average execution time
time ./target seed1
time ./target seed2
time ./target seed3

# Set timeout to 3-5x the average execution time
# Default is 1000ms; adjust based on target
afl-fuzz -i seeds/ -o findings/ -t 5000 -- ./target @@  # 5 second timeout
```

### Dictionary Usage

```bash
# Generate dictionary from binary strings
strings -n 4 target | sort -u > raw.dict
# Convert to AFL dictionary format
awk '{print "str_\"" $0 "\""}' raw.dict > fuzz.dict

# Use with AFL++
afl-fuzz -i seeds/ -o findings/ -x fuzz.dict -- ./target @@

# For structured formats, create manual dictionaries
cat > pdf.dict << 'EOF'
"%PDF-1."
"1 0 obj"
"endobj"
"stream"
"endstream"
"xref"
"trailer"
"startxref"
"%%EOF"
EOF
```

### Execution Speed Optimization

| Optimization | Impact | How |
|-------------|--------|-----|
| Persistent mode | 10-100x speedup | Use `__AFL_LOOP()` harness |
| Deferred forkserver | 2-5x speedup | Use `__AFL_INIT()` after setup |
| Disable sanitizers | 2-5x speedup | Remove `-fsanitize=address` (debug builds only) |
| Multiple workers | Linear with cores | Run N parallel AFL++ instances |
| Smaller inputs | Faster execution | Minimize corpus with `afl-tmin` |
| CMPLOG mode | Better coverage | Add `-c 0` flag for comparison logging |
| LLVM LTO mode | Better instrumentation | Use `afl-clang-lto` instead of `afl-clang-fast` |

### Common Performance Issues

```bash
# Issue: Low execution speed (< 1000/sec)
# Diagnosis:
#   1. Check if target is I/O bound (file operations, network)
#   2. Check if sanitizer overhead is too high
#   3. Check if inputs are too large

# Solution: Switch to persistent mode and stdin input
afl-clang-fast -o target_persistent harness_persistent.c target.c
afl-fuzz -i seeds/ -o findings/ -m none -- ./target_persistent

# Issue: Coverage plateau (no new paths for hours)
# Diagnosis:
#   1. Check stability (should be > 90%)
#   2. Check if custom mutator is needed
#   3. Check if dictionary helps

# Solution: Add CMPLOG mode + custom dictionary
afl-clang-lto -o target_cmplog -c 0 target.c
afl-fuzz -i seeds/ -o findings/ -S cmplog -c 0 -m none -- ./target_cmplog @@
```

## References

- [AFL++ Documentation](https://github.com/AFLplusplus/AFLplusplus)
- [libFuzzer Tutorial (LLVM)](https://llvm.org/docs/LibFuzzer.html)
- [Honggfuzz GitHub](https://github.com/google/honggfuzz)
- [OSS-Fuzz - Continuous Fuzzing Platform](https://google.github.io/oss-fuzz/)
- [Fuzzing Book](https://www.fuzzingbook.org/)
