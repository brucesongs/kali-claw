# Crash Triage and Vulnerability Analysis Guide

> Methodical approach to analyzing fuzzer-generated crashes: reproducing, deduplicating, assessing exploitability, and triaging with ASAN/MSAN. Turns a pile of crashing inputs into actionable vulnerability reports.

---

## Introduction

A successful fuzzing campaign can produce hundreds or thousands of crashing inputs. Raw crashes are not vulnerabilities — they are leads that must be triaged, deduplicated, and analyzed to determine which ones represent real security bugs and how severe they are. This guide lays out a structured workflow for going from a corpus of crashes to a prioritized list of vulnerabilities with root cause analysis.

---

## Practical Steps

### 1. Collecting and Organizing Crashes

After a fuzzing session ends, crashes are typically scattered across the output directory. Start by gathering them into a single location.

```bash
# AFL++ crashes are in <output_dir>/default/crashes/
ls -la fuzz_output/default/crashes/

# Copy unique crash inputs to a working directory
mkdir -p triage/crashes
cp fuzz_output/default/crashes/id:* triage/crashes/

# Count unique crashes
ls triage/crashes/ | wc -l
```

### 2. Reproducing Crashes

Before investing analysis time, confirm each crash reproduces reliably.

```bash
# Reproduce a single crash against the target binary
./target_binary < triage/crashes/id:000000,sig:11,src:000001

# Batch reproduce all crashes
for crash in triage/crashes/id:*; do
  echo "Testing: $crash"
  timeout 5 ./target_binary < "$crash" 2>&1 | tail -1
done | tee triage/repro_results.txt
```

### 3. Crash Deduplication

Multiple crashes often hit the same bug. Deduplication reduces analysis effort.

```bash
# Using afl-collect to deduplicate and categorize
pip install afl-collect
afl-collect -j$(nproc) -d triage/crashes triage/database ./target_binary

# Manual deduplication using ASAN stack traces
for crash in triage/crashes/id:*; do
  echo "=== $crash ==="
  ./target_asan < "$crash" 2>&1 | grep "ERROR:" | head -1
done | sort | uniq -c | sort -rn

# Using crashwalk (casr)
casr-cli triage --binary ./target_binary --crashes-dir triage/crashes/
```

### 4. Determining Exploitability

Not every crash is exploitable. Use ASAN and MSAN to assess the severity.

```bash
# Build with AddressSanitizer (detects buffer overflows, use-after-free)
gcc -fsanitize=address -g -O1 -o target_asan target.c

# Build with MemorySanitizer (detects uninitialized reads)
clang -fsanitize=memory -g -O1 -o target_msan target.c

# Build with UndefinedBehaviorSanitizer (detects undefined behavior)
gcc -fsanitize=undefined -g -O1 -o target_ubsan target.c

# Run crash through ASAN build for detailed report
./target_asan < triage/crashes/id:000000,sig:11,src:000001 2>&1 | tee triage/asan_report.txt
```

Key exploitability indicators from ASAN output:
- **heap-buffer-overflow (write)**: Often exploitable — arbitrary write primitive.
- **stack-buffer-overflow**: May lead to code execution via return address overwrite.
- **use-after-free**: High exploitability — can be chained into arbitrary read/write.
- **heap-use-after-free**: Similar to UAF, common in browser and PDF parser bugs.
- **null-pointer-dereference**: Usually a DoS, rarely exploitable for code execution.
- **uninitialized-read (MSAN)**: May leak sensitive data (information disclosure).

### 5. Root Cause Analysis Workflow

Once you have a deduplicated, prioritized crash list, analyze each root cause.

```bash
# Step 1: Get the exact crash location from ASAN
./target_asan < crash_input 2>&1 | grep "SUMMARY:"

# Step 2: Examine the source code at the crash location
# Look for the file and line number in the ASAN stack trace

# Step 3: Generate a minimized test case
# AFL++ stores minimized inputs; alternatively use CReduce for C/C++
creduce ./reproduce_crash.sh crash_input

# Step 4: Write the vulnerability report
# Include: crash input, ASAN output, root cause, exploitability assessment, affected versions
```

### 6. Automating Triage with casr

```bash
# Install casr
cargo install casr

# Run full triage pipeline
casr-cli triage --binary ./target_asan --crashes-dir fuzz_output/default/crashes/ -o triage_report.json

# View clustered results
casr-cli report -i triage_report.json
```

---

## References

- AddressSanitizer Wiki: [https://github.com/google/sanitizers/wiki/AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- MemorySanitizer: [https://github.com/google/sanitizers/wiki/MemorySanitizer](https://github.com/google/sanitizers/wiki/MemorySanitizer)
- casr (Crash Analysis and Reporting): [https://github.com/ispras/casr](https://github.com/ispras/casr)
- AFL++ Documentation: [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)
- CReduce Test Case Reducer: [https://github.com/csmith-project/creduce](https://github.com/csmith-project/creduce)
- Mozilla Fuzzing Triage Guide: [https://firefox-source-docs.mozilla.org/tools/fuzzing/triage.html](https://firefox-source-docs.mozilla.org/tools/fuzzing/triage.html)
