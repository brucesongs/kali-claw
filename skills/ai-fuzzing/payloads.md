# AI Fuzzing Payloads / Tool Commands

> This file is a companion to `SKILL.md`, containing a complete collection of fuzzing tool commands organized by phase.

---

## Index

1. [Target Analysis](#1-target-analysis)
2. [Corpus Preparation](#2-corpus-preparation)
3. [AFL++ Execution](#3-afl-execution)
4. [libFuzzer](#4-libfuzzer)
5. [Honggfuzz](#5-honggfuzz)
6. [Web API Fuzzing](#6-web-api-fuzzing)
7. [Protocol Fuzzing](#7-protocol-fuzzing)
8. [Crash Analysis](#8-crash-analysis)
9. [Quick Start Checklist](#9-quick-start-checklist)

---

## 1. Target Analysis

### Binary Identification

```bash
# Determine file type, architecture, linking
file target_binary
readelf -h target_binary          # ELF header info
readelf -S target_binary          # Section headers
objdump -f target_binary          # File format summary

# Check security mechanisms
checksec --file=target_binary     # NX, ASLR, Canary, PIE, RELRO

# Identify dynamically linked libraries
ldd target_binary
readelf -d target_binary | grep NEEDED

# Quick string extraction for attack surface hints
strings -n 8 target_binary | grep -iE "error|parse|input|read|buffer|format|open|load|import|decode"
```

### radare2 Attack Surface Mapping

```bash
# Load and analyze binary
r2 -A target_binary

# List all functions (identify parsing/input handling)
afl | grep -iE "parse|read|input|handle|process|decode|load|import|parse"

# Identify imported functions (potential vulnerable APIs)
ii | grep -iE "strcpy|sprintf|gets|read|memcpy|malloc|free|printf|scanf|strcat"

# Find cross-references to dangerous functions
axt sym.imp.strcpy
axt sym.imp.sprintf
axt sym.imp.gets

# Map input parsing entry points
pdf @ sym.main                   # Disassemble main
pdf @ sym.parse_input            # Disassemble input parser
VV                               # Visual mode for control flow

# Quick exit after analysis
r2 -c 'aaa; afl; ii; iz' -q target_binary
```

### Input Format Identification

```bash
# Identify file magic bytes and format
xxd sample_input | head -20
file sample_input

# Identify protocol patterns
tcpdump -i any -w capture.pcap port 8080
wireshark capture.pcap

# Extract strings for dictionary generation
strings -n 4 target_binary > fuzz_dict.txt
```

---

## 2. Corpus Preparation

### Seed Creation

```bash
# Create minimal seed files
mkdir -p seeds
echo "" > seeds/empty
echo "A" > seeds/minimal
echo "AAAAAA" > seeds/basic

# Generate structured seeds for specific formats
# JSON seed
echo '{"key":"value"}' > seeds/json_seed

# PNG seed (minimal valid header)
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde' > seeds/png_seed

# Generate seed from valid inputs
cp /path/to/valid/samples/* seeds/

# Create seeds from captured traffic
tcpdump -r capture.pcap -w - | tcpreplay-edit --seed=42 -i - -o seeds/captured
```

### Corpus Minimization

```bash
# Minimize corpus: keep only seeds producing unique coverage
afl-cmin -i seeds/ -o seeds_min/ -- ./target @@

# Minimize individual test case: reduce to smallest input producing same path
afl-tmin -i seeds/seed1 -o seeds_min/seed1_min -- ./target @@

# Batch minimize all seeds
for f in seeds/*; do
  afl-tmin -i "$f" -o "seeds_min/$(basename $f)_min" -- ./target @@
done

# Verify corpus quality (all seeds should produce unique paths)
for f in seeds_min/*; do
  echo "=== $f ==="
  afl-showmap -o /dev/null -m none -- ./target "$f" 2>&1 | tail -1
done
```

### Dictionary Generation

```bash
# Auto-generate dictionary from binary strings
strings -n 4 target_binary | sort -u > fuzz.dict
# Convert to AFL dictionary format
awk '{print "str_\"" $0 "\""}' fuzz.dict > afl.dict

# Manual dictionary for structured formats (example: XML)
cat > xml.dict << 'EOF'
"<?xml version=\"1.0\"?>"
"<!DOCTYPE"
"<!ENTITY"
"<!--"
"-->"]
"<tag>"
"</tag>"
"<![CDATA["
"]]>"]
EOF
```

---

## 3. AFL++ Execution

### Basic Fuzzing

```bash
# Compile target with AFL++ instrumentation (source available)
afl-clang-fast -o target_fuzz target.c -fsanitize=address,undefined

# Compile without sanitizers (for performance)
afl-clang-fast -o target_fuzz target.c

# Basic fuzzing with file input
afl-fuzz -i seeds/ -o findings/ -m none -- ./target_fuzz @@

# Fuzzing with stdin input
afl-fuzz -i seeds/ -o findings/ -m none -- ./target_fuzz

# With dictionary
afl-fuzz -i seeds/ -o findings/ -m none -x xml.dict -- ./target_fuzz @@
```

### Parallel Fuzzing

```bash
# Main node (deterministic + havoc)
afl-fuzz -i seeds/ -o findings/ -M main -m none -- ./target_fuzz @@

# Secondary nodes (havoc-focused, different strategies)
afl-fuzz -i seeds/ -o findings/ -S sub1 -m none -- ./target_fuzz @@
afl-fuzz -i seeds/ -o findings/ -S sub2 -m none -- ./target_fuzz @@
afl-fuzz -i seeds/ -o findings/ -S sub3 -m none -- ./target_fuzz @@

# With custom mutator on a secondary node
afl-fuzz -i seeds/ -o findings/ -S custom -m none -L 0 -- ./target_fuzz @@
```

### Persistent Mode

```c
// Harness for persistent mode (dramatically faster)
#include <stdio.h>
#include <stdlib.h>
#include "afl-fuzz.h"

int main(int argc, char **argv) {
    char buf[4096];
    while (__AFL_LOOP(10000)) {
        int len = read(0, buf, sizeof(buf));
        if (len > 0) {
            // Call target parsing function
            parse_input(buf, len);
        }
    }
    return 0;
}
```

```bash
# Compile persistent mode harness
afl-clang-fast -o target_persistent harness.c target_lib.c -fsanitize=address

# Run persistent mode fuzzer
afl-fuzz -i seeds/ -o findings/ -m none -- ./target_persistent
```

### Custom Mutators

```bash
# Use grammar-based mutator for structured inputs
afl-fuzz -i seeds/ -o findings/ -m none \
  -L 0 \
  -- ./target_fuzz @@

# Python custom mutator
# Create custom_mutator.py implementing AFL++ custom mutator API
afl-fuzz -i seeds/ -o findings/ -m none \
  -- ./target_fuzz @@
```

---

## 4. libFuzzer

### Harness Compilation

```c
// Minimal libFuzzer harness
#include <stdint.h>
#include <stddef.h>

extern int parse_input(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;  // Skip tiny inputs
    parse_input(data, size);
    return 0;
}
```

```bash
# Compile with sanitizers
clang -fsanitize=fuzzer,address -o target_fuzz harness.c target.c

# Compile with multiple sanitizers (pick one at a time, some conflict)
clang -fsanitize=fuzzer,undefined -o target_ubsan harness.c target.c
clang -fsanitize=fuzzer,memory -o target_msan harness.c target.c
clang -fsanitize=fuzzer,thread -o target_tsan harness.c target.c
```

### Running libFuzzer

```bash
# Basic run with corpus directory
./target_fuzz corpus/

# Run with specific options
./target_fuzz corpus/ \
  -max_len=4096 \
  -timeout=10 \
  -jobs=4 \
  -workers=4

# Merge corpus (minimize without losing coverage)
./target_fuzz -merge=1 corpus/ corpus_backup/

# Generate coverage report
clang -fsanitize=fuzzer,address -fprofile-instr-generate -fcoverage-mapping \
  -o target_cov harness.c target.c
LLVM_PROFILE_FILE="default.profraw" ./target_cov -runs=1000 corpus/
llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov show ./target_cov -instr-profile=default.profdata
```

### Sanitizer Flags

```bash
# Address Sanitizer (most common for fuzzing)
-fsanitize=address
ASAN_OPTIONS=detect_leaks=1:detect_stack_use_after_return=1

# Undefined Behavior Sanitizer
-fsanitize=undefined
UBSAN_OPTIONS=print_stacktrace=1

# Memory Sanitizer (detects uninitialized reads)
-fsanitize=memory
MSAN_OPTIONS=halt_on_error=1

# Thread Sanitizer (data races)
-fsanitize=thread
TSAN_OPTIONS=halt_on_error=1
```

---

## 5. Honggfuzz

### Basic Usage

```bash
# Basic file fuzzing
honggfuzz -i seeds/ -o output/ -- ./target

# Stdin fuzzing
honggfuzz -i seeds/ -o output/ -s -- ./target

# With Address Sanitizer
honggfuzz -i seeds/ -o output/ -- ./target_asan

# Hardware-based feedback (Intel PT, if available)
honggfuzz -i seeds/ -o output/ --linux_pt -- ./target

# Persistent mode
honggfuzz -i seeds/ -o output/ -P -- ./target_persistent
```

### Network Fuzzing

```bash
# TCP port fuzzing
honggfuzz -i seeds/ -o output/ \
  --tcp_server port=8080 \
  -- ./target
```

---

## 6. Web API Fuzzing

### wfuzz Commands

```bash
# Directory and endpoint discovery
wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/common.txt \
  --hc 404,400 http://target/FUZZ

# Parameter fuzzing
wfuzz -z file,/usr/share/seclists/Fuzzing/big.txt \
  http://target/api/v1/users?FUZZ=value

# Value fuzzing for specific parameter
wfuzz -z file,/usr/share/seclists/Fuzzing/numbers.txt \
  http://target/api/v1/users?id=FUZZ

# POST data fuzzing
wfuzz -z file,payloads.txt -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  http://target/api/v1/login

# Fuzz headers
wfuzz -z file,/usr/share/seclists/Fuzzing/X-headers.txt \
  -H "FUZZ: value" http://target/api/v1/endpoint

# Range-based boundary testing
wfuzz -z range,0-65535 http://target/api/v1/users?id=FUZZ
wfuzz -z range,-1000-1000 http://target/api/v1/users?offset=FUZZ
```

### OpenAPI-Based Fuzzing

```bash
# Generate fuzz tests from OpenAPI spec
# Using schemathesis
pip install schemathesis
st run --base-url http://target http://target/openapi.json

# Using restler (Microsoft REST API fuzzer)
# Compile restler
python restler-quick-start.py --api_spec /path/to/openapi.json \
  --target_host target --target_port 8080

# Custom OpenAPI fuzzing with curl
# Extract endpoints from spec and fuzz each parameter
jq -r '.paths | keys[]' openapi.json | while read endpoint; do
  curl -X POST "http://target${endpoint}" \
    -H "Content-Type: application/json" \
    -d '{"fuzz":"AAAAAAAAAA"}'
done
```

### Burp Intruder Payloads

```
# Boundary value payloads for numeric parameters
0
-1
2147483647
-2147483648
99999999999
1.5
NaN
Infinity
-0
0x7FFFFFFF

# String fuzzing payloads
(empty string)
(null)
(undefined)
AAAAAAAAAA...A  (10000 chars)
%s%s%s%s%s
%d%d%d%d%d
{{7*7}}
${7*7}
<%= 7*7 %>
{{constructor.constructor('return this')()}}
```

---

## 7. Protocol Fuzzing

### BooFuzz HTTP Template

```python
#!/usr/bin/env python3
"""HTTP protocol fuzzer with BooFuzz"""
from boofuzz import *

def main():
    session = Session(
        target=Target(
            connection=TCPSocketConnection("192.168.1.100", 8080)
        ),
    )

    # Define HTTP request structure
    s_initialize("HTTP_REQUEST")
    s_group("Method", values=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
    s_delim(" ", name="space1", fuzzable=True)
    s_string("/api/v1/endpoint", name="path", fuzzable=True)
    s_delim(" ", name="space2", fuzzable=True)
    s_string("HTTP/1.1", name="version", fuzzable=True)
    s_static("\r\n")
    s_string("Host: target", name="host")
    s_static("\r\n")
    s_string("Content-Type: application/json", name="content_type")
    s_static("\r\n")
    s_string("Content-Length: ", name="cl_header")
    s_size("body", output_format="ascii", name="cl_value")
    s_static("\r\n\r\n")
    s_string('{"data":"test"}', name="body", fuzzable=True)
    s_static("\r\n\r\n")

    session.connect(s_get("HTTP_REQUEST"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

### BooFuzz Custom Binary Protocol Template

```python
#!/usr/bin/env python3
"""Custom binary protocol fuzzer with BooFuzz"""
from boofuzz import *

def main():
    session = Session(
        target=Target(
            connection=TCPSocketConnection("192.168.1.100", 9999)
        )
    )

    # Define custom binary protocol: [MAGIC][LEN][CMD][DATA][CRC]
    s_initialize("BINARY_PACKET")
    s_static(b"\xAA\xBB")                          # Magic bytes
    s_size("data", length=2, endian=">")           # Length field (big-endian)
    s_byte(0x01, name="cmd", fuzzable=True)        # Command byte
    s_string("payload_data", name="data", fuzzable=True)  # Payload
    s_checksum("data", algorithm="crc32", name="crc")     # CRC checksum

    session.connect(s_get("BINARY_PACKET"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

### Network Protocol Fuzzing

```bash
# DNS fuzzer with AFL++
# Build BIND9 with AFL instrumentation
CC=afl-clang-fast ./configure --disable-shared
CC=afl-clang-fast make -j$(nproc)

# SSH fuzzing with libFuzzer
clang -fsanitize=fuzzer,address \
  -I/path/to/openssh/include \
  harness_ssh.c -o ssh_fuzz \
  -L/path/to/openssh/lib -lssh

# HTTP parser fuzzing
clang -fsanitize=fuzzer,address \
  -o http_parser_fuzz \
  harness_http.c http_parser.c
./http_parser_fuzz corpus/
```

---

## 8. Crash Analysis

### radare2 Crash Debugging

```bash
# Load crash sample in debug mode
r2 -d -A findings/default/crashes/id:000001*

# Analyze crash location
db sym.vulnerable_func     # Set breakpoint
dc                         # Continue to crash
dr                         # Display registers at crash
px @ rsp                   # Inspect stack
px @ rdi                   # Inspect argument registers

# Trace execution path
dbt                        # Backtrace
aei                        # Analyze esil imports
aeim                       # Initialize memory
drt                        # Display register types

# Automated crash analysis
r2 -c 'aaa; db sym.main; dc; dr; px @ rsp; dbt' -q crash_binary < crash_input
```

### ASAN Report Analysis

```bash
# Run crash with ASAN for detailed report
ASAN_SYMBOLIZER_PATH=llvm-symbolizer \
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
./target_asan crash_input

# Typical ASAN output fields to analyze:
# ==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
# READ of size N at 0x... thread T0
#     #0 0x... in vulnerable_function target.c:42:3
#     #1 0x... in main target.c:100:5
# 0x... is located N bytes to the right of N-byte region [0x...,0x...)
# allocated by thread T0 here:
#     #0 0x... in malloc

# Run with GDB for interactive debugging
gdb --args ./target_asan crash_input
(gdb) run
# ASAN will report the crash location and stack trace
```

### Crash Deduplication

```bash
# AFL++ built-in deduplication (crashes organized by unique path)
ls findings/default/crashes/
# Each crash has unique path ID: id:000000, id:000001, etc.

# Manual deduplication with afl-showmap
for crash in findings/default/crashes/id:*; do
  echo "=== $(basename $crash) ==="
  afl-showmap -o /dev/null -m none -- ./target "$crash" 2>&1 | head -5
done

# Exploitability assessment with !exploitable (GDB plugin)
gdb -batch -ex "run" -ex "!exploitable -v" --args ./target crash_input

# Cluster crashes by similarity
mkdir -p crashes_sorted/{critical,medium,low,unreproducible}
for crash in findings/default/crashes/id:*; do
  result=$(timeout 5 ./target "$crash" 2>&1)
  if echo "$result" | grep -q "heap-buffer-overflow"; then
    cp "$crash" crashes_sorted/critical/
  elif echo "$result" | grep -q "stack-overflow"; then
    cp "$crash" crashes_sorted/critical/
  elif echo "$result" | grep -q "timeout"; then
    cp "$crash" crashes_sorted/medium/
  fi
done
```

---

## 9. Quick Start Checklist

### Binary Fuzzing Quick Start

```bash
# 1. Prepare target (30 seconds)
afl-clang-fast -o target_fuzz target.c -fsanitize=address

# 2. Prepare corpus (1 minute)
mkdir -p seeds seeds_min findings
echo "sample_input" > seeds/seed1
afl-cmin -i seeds/ -o seeds_min/ -- ./target_fuzz @@

# 3. Launch fuzzer (immediate)
afl-fuzz -i seeds_min/ -o findings/ -m none -- ./target_fuzz @@

# 4. Monitor (ongoing)
# Watch AFL++ dashboard for coverage growth and crash count

# 5. Analyze crashes (when crashes found)
for crash in findings/default/crashes/id:*; do
  echo "=== $(basename $crash) ==="
  ./target_fuzz "$crash" 2>&1 | head -20
done
```

### Web API Fuzzing Quick Start

```bash
# 1. Identify endpoints
wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/common.txt \
  --hc 404 http://target/api/FUZZ

# 2. Fuzz parameters
wfuzz -z file,/usr/share/seclists/Fuzzing/big.txt \
  http://target/api/v1/users?FUZZ=test

# 3. Test boundaries
wfuzz -z range,0-255 http://target/api/v1/users?id=FUZZ

# 4. Test content types
for ct in application/json text/xml multipart/form-data; do
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: $ct" \
    -d '{"test":"data"}' http://target/api/v1/endpoint
done
```

### Protocol Fuzzing Quick Start

```bash
# 1. Capture valid traffic sample
tcpdump -i any -w sample.pcap port 8080

# 2. Create BooFuzz template (see Protocol Fuzzing section above)

# 3. Run protocol fuzzer
python protocol_fuzz.py

# 4. Monitor for crashes on target system
journalctl -f | grep -i "segfault\|crash\|error"
```

---

## 10. Coverage-Guided Fuzzing

### AFL++ Advanced Setup

```bash
# Build AFL++ from source with all features
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make distrib
sudo make install

# Compile target with LLVM mode (best instrumentation)
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_INSTRUMENT=CLASSIC
./configure --disable-shared && make -j$(nproc)

# Compile with CmpLog (comparison logging for magic byte solving)
afl-clang-lto -o target_cmplog target.c -DCMPLOG_INSTRUMENTATION
afl-clang-lto -o target_fuzz target.c -fsanitize=address

# Launch with CmpLog companion binary
afl-fuzz -i seeds/ -o findings/ -m none \
  -c ./target_cmplog \
  -- ./target_fuzz @@

# Use MOpt mutation scheduler (adaptive mutation selection)
afl-fuzz -i seeds/ -o findings/ -m none -L 0 -- ./target_fuzz @@
```

### Corpus Management

```bash
# Import corpus from multiple sources
mkdir -p corpus_combined
cp -r project_seeds/* corpus_combined/
cp -r oss-fuzz-corpus/* corpus_combined/
cp -r regression_tests/* corpus_combined/

# Deduplicate and minimize combined corpus
afl-cmin -i corpus_combined/ -o corpus_final/ -m none -- ./target_fuzz @@

# Measure corpus coverage before fuzzing
afl-showmap -C -i corpus_final/ -o coverage_map -m none -- ./target_fuzz @@
wc -l coverage_map  # Total unique edges covered

# Sync corpus across parallel fuzzers (shared filesystem)
# All fuzzers write to same -o directory; AFL++ auto-syncs
afl-fuzz -i corpus_final/ -o shared_findings/ -M main -- ./target_fuzz @@
afl-fuzz -i corpus_final/ -o shared_findings/ -S worker1 -- ./target_fuzz @@

# Export minimized corpus for CI regression testing
afl-cmin -i shared_findings/main/queue/ -o regression_corpus/ -m none -- ./target_fuzz @@
tar czf regression_corpus.tar.gz regression_corpus/
```

### Coverage Visualization

```bash
# Generate LCOV coverage from AFL++ corpus
afl-clang-lto -fprofile-arcs -ftest-coverage -o target_gcov target.c
for f in findings/main/queue/id:*; do
  ./target_gcov "$f" 2>/dev/null
done
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_html

# Generate coverage with llvm-cov (Clang-based)
clang -fprofile-instr-generate -fcoverage-mapping -o target_cov target.c
for f in findings/main/queue/id:*; do
  LLVM_PROFILE_FILE="prof_%p.profraw" ./target_cov "$f" 2>/dev/null
done
llvm-profdata merge -sparse prof_*.profraw -o merged.profdata
llvm-cov show ./target_cov -instr-profile=merged.profdata -format=html > coverage.html
llvm-cov report ./target_cov -instr-profile=merged.profdata

# AFL++ plot_data for time-series coverage tracking
afl-plot findings/main/ plot_output/
# Generates: edges over time, crashes over time, exec speed
```

### Coverage-Guided Differential Fuzzing

```bash
# Compare two implementations with same input (find behavioral differences)
afl-clang-fast -o impl_a impl_a.c -fsanitize=address
afl-clang-fast -o impl_b impl_b.c -fsanitize=address

# Wrapper script for differential testing
cat > diff_harness.sh << 'EOF'
#!/bin/bash
out_a=$(./impl_a "$1" 2>/dev/null)
out_b=$(./impl_b "$1" 2>/dev/null)
if [ "$out_a" != "$out_b" ]; then
  exit 1  # Signal difference to fuzzer
fi
exit 0
EOF
chmod +x diff_harness.sh

# Fuzz with differential harness
afl-fuzz -i seeds/ -o diff_findings/ -m none -- ./diff_harness.sh @@
```

### AFL++ QEMU Mode (Binary-Only Fuzzing)

```bash
# Build AFL++ QEMU mode for closed-source binaries
cd AFLplusplus/qemu_mode && ./build_qemu_support.sh

# Fuzz binary without source code
afl-fuzz -Q -i seeds/ -o findings/ -m none -- ./closed_source_binary @@

# QEMU persistent mode (faster binary-only fuzzing)
# Requires identifying a loop point in the binary
AFL_QEMU_PERSISTENT_ADDR=0x401000 \
AFL_QEMU_PERSISTENT_CNT=10000 \
afl-fuzz -Q -i seeds/ -o findings/ -m none -- ./closed_source_binary @@

# Combine QEMU mode with CmpLog for binary-only targets
AFL_QEMU_CMPLOG=1 \
afl-fuzz -Q -i seeds/ -o findings/ -m none \
  -c 0 -- ./closed_source_binary @@
```

---

## 11. Protocol Fuzzing (Advanced)

### BooFuzz State-Aware Fuzzing

```python
#!/usr/bin/env python3
"""State-aware FTP protocol fuzzer with session tracking"""
from boofuzz import *

def main():
    session = Session(
        target=Target(
            connection=TCPSocketConnection("192.168.1.100", 21)
        ),
        sleep_time=0.5,
    )

    # FTP login sequence (stateful)
    s_initialize("USER")
    s_string("USER", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("anonymous", name="username", fuzzable=True)
    s_static("\r\n")

    s_initialize("PASS")
    s_string("PASS", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("anonymous@", name="password", fuzzable=True)
    s_static("\r\n")

    s_initialize("CWD")
    s_string("CWD", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/pub", name="directory", fuzzable=True)
    s_static("\r\n")

    s_initialize("RETR")
    s_string("RETR", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("file.txt", name="filename", fuzzable=True)
    s_static("\r\n")

    # Define state transitions
    session.connect(s_get("USER"))
    session.connect(s_get("USER"), s_get("PASS"))
    session.connect(s_get("PASS"), s_get("CWD"))
    session.connect(s_get("CWD"), s_get("RETR"))

    session.fuzz()

if __name__ == "__main__":
    main()
```

### BooFuzz with Process Monitoring

```python
#!/usr/bin/env python3
"""Protocol fuzzer with crash detection via process monitor"""
from boofuzz import *

def main():
    # Monitor target process for crashes
    procmon = ProcessMonitor("192.168.1.100", 26002)
    procmon.set_options(
        start_commands=["./target_server -p 9999"],
        proc_name="target_server",
    )

    session = Session(
        target=Target(
            connection=TCPSocketConnection("192.168.1.100", 9999),
            monitors=[procmon],
        ),
        restart_sleep_time=2,
    )

    s_initialize("REQUEST")
    s_dword(0x01, name="msg_type", fuzzable=True, endian=BIG_ENDIAN)
    s_size("payload", length=4, endian=BIG_ENDIAN)
    s_string("AAAA", name="payload", fuzzable=True, max_len=65535)
    s_checksum("payload", algorithm="crc32")

    session.connect(s_get("REQUEST"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

### Custom Protocol Template (TLS Record Layer)

```python
#!/usr/bin/env python3
"""TLS record layer fuzzer targeting handshake messages"""
from boofuzz import *

def main():
    session = Session(
        target=Target(
            connection=SSLSocketConnection("192.168.1.100", 443)
        ),
    )

    # TLS ClientHello structure
    s_initialize("CLIENT_HELLO")
    # Record layer
    s_byte(0x16, name="content_type")          # Handshake
    s_word(0x0303, endian=BIG_ENDIAN)          # TLS 1.2
    s_size("handshake", length=2, endian=BIG_ENDIAN)

    # Handshake header
    if s_block_start("handshake"):
        s_byte(0x01, name="handshake_type")    # ClientHello
        s_size("hello_body", length=3, endian=BIG_ENDIAN)

        if s_block_start("hello_body"):
            s_word(0x0303, endian=BIG_ENDIAN)  # Client version
            s_random(b"\x00" * 32, min_length=32, max_length=32, name="random")
            s_byte(0x00, name="session_id_len")
            # Cipher suites
            s_word(0x0002, endian=BIG_ENDIAN)  # Length
            s_word(0x002F, endian=BIG_ENDIAN, fuzzable=True)  # TLS_RSA_WITH_AES_128_CBC_SHA
            # Compression
            s_byte(0x01)
            s_byte(0x00, fuzzable=True)        # null compression
        s_block_end("hello_body")
    s_block_end("handshake")

    session.connect(s_get("CLIENT_HELLO"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

### Scapy-Based Protocol Fuzzing

```python
#!/usr/bin/env python3
"""Scapy-based DNS protocol fuzzer with mutation strategies"""
from scapy.all import *
import random
import string

def fuzz_dns_query(target_ip, target_port=53, iterations=1000):
    """Fuzz DNS queries with various mutation strategies"""
    for i in range(iterations):
        # Generate random domain name
        labels = [
            ''.join(random.choices(string.ascii_lowercase, k=random.randint(1, 63)))
            for _ in range(random.randint(1, 5))
        ]
        domain = '.'.join(labels)

        # Mutate DNS packet fields
        pkt = IP(dst=target_ip) / UDP(dport=target_port) / DNS(
            id=random.randint(0, 65535),
            qr=random.choice([0, 1]),
            opcode=random.randint(0, 15),
            rd=random.choice([0, 1]),
            qdcount=random.randint(0, 10),
            qd=DNSQR(
                qname=domain,
                qtype=random.choice([1, 2, 5, 6, 15, 16, 28, 33, 255]),
                qclass=random.choice([1, 3, 4, 255]),
            )
        )

        # Send and check for anomalous responses
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp and resp.haslayer(DNS):
            if resp[DNS].rcode not in [0, 2, 3, 5]:
                print(f"[!] Unusual rcode {resp[DNS].rcode} for domain: {domain}")

if __name__ == "__main__":
    fuzz_dns_query("192.168.1.100")
```

### Mutiny Fuzzing Framework (Replay-Based)

```bash
# Capture legitimate protocol traffic
tcpdump -i eth0 -w legitimate_session.pcap port 8080

# Convert pcap to Mutiny fuzzing template
mutiny_prep.py legitimate_session.pcap -o fuzz_template/

# Run Mutiny replay-based fuzzer
mutiny.py fuzz_template/ 192.168.1.100 8080 \
  --sleep 0.1 \
  --timeout 5 \
  --log crashes.log

# Radamsa-based protocol mutation (pipe through radamsa)
cat legitimate_request.bin | radamsa -n 1000 -o fuzzed_%n.bin
for f in fuzzed_*.bin; do
  nc -w 2 192.168.1.100 8080 < "$f"
  if [ $? -ne 0 ]; then
    cp "$f" crashes/
  fi
done
```

---

## 12. API Fuzzing (Advanced)

### RESTler Stateful API Fuzzing

```bash
# Install RESTler
dotnet tool install RESTlerTool --global

# Compile API specification into fuzzing grammar
restler compile --api_spec openapi.json

# Run RESTler in test mode (validate grammar)
restler test --grammar_file Compile/grammar.py \
  --dictionary_file Compile/dict.json \
  --settings Compile/engine_settings.json \
  --host target.com --target_port 443 --use_ssl

# Run RESTler in fuzz-lean mode (quick coverage)
restler fuzz-lean --grammar_file Compile/grammar.py \
  --dictionary_file Compile/dict.json \
  --settings Compile/engine_settings.json \
  --host target.com --target_port 443 --use_ssl \
  --time_budget 1

# Run RESTler in full fuzz mode (deep testing)
restler fuzz --grammar_file Compile/grammar.py \
  --dictionary_file Compile/dict.json \
  --settings Compile/engine_settings.json \
  --host target.com --target_port 443 --use_ssl \
  --time_budget 24
```

### Schemathesis Advanced Usage

```bash
# Install schemathesis
pip install schemathesis

# Basic stateful testing from OpenAPI spec
st run http://target/openapi.json --stateful=links

# Run with specific test strategies
st run http://target/openapi.json \
  --hypothesis-max-examples=500 \
  --hypothesis-deadline=10000 \
  --checks all \
  --validate-schema true

# Target specific endpoints
st run http://target/openapi.json \
  --endpoint "/api/v1/users" \
  --method POST \
  --hypothesis-max-examples=1000

# Run with authentication
st run http://target/openapi.json \
  --auth admin:password \
  --auth-type basic

# Run with custom headers (Bearer token)
st run http://target/openapi.json \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."

# Generate JUnit XML report for CI integration
st run http://target/openapi.json \
  --junit-xml=results.xml \
  --cassette-path=cassette.yaml
```

### GraphQL Fuzzing

```python
#!/usr/bin/env python3
"""GraphQL API fuzzer with introspection-based mutation"""
import requests
import random
import string
import json

TARGET = "http://target/graphql"

def introspect_schema():
    """Fetch full schema via introspection"""
    query = """
    {
      __schema {
        queryType { fields { name args { name type { name kind ofType { name } } } } }
        mutationType { fields { name args { name type { name kind ofType { name } } } } }
      }
    }
    """
    resp = requests.post(TARGET, json={"query": query})
    return resp.json()

def generate_fuzz_value(type_name):
    """Generate fuzzed values based on GraphQL type"""
    fuzz_map = {
        "String": [
            "A" * 10000, "<script>alert(1)</script>", "' OR 1=1--",
            "\x00\x01\x02", "{{7*7}}", "${7*7}", "../../../etc/passwd",
            None, "", " " * 1000,
        ],
        "Int": [0, -1, 2147483647, -2147483648, 99999999999],
        "Float": [0.0, -1.0, float('inf'), float('-inf'), 1e308],
        "Boolean": [True, False, None],
        "ID": ["0", "-1", "999999", "admin", "../1", "null"],
    }
    values = fuzz_map.get(type_name, fuzz_map["String"])
    return random.choice(values)

def fuzz_queries(schema, iterations=500):
    """Generate and send fuzzed queries"""
    fields = schema["data"]["__schema"]["queryType"]["fields"]
    for i in range(iterations):
        field = random.choice(fields)
        args = {}
        for arg in field.get("args", []):
            type_name = arg["type"].get("name") or (
                arg["type"].get("ofType", {}).get("name", "String")
            )
            args[arg["name"]] = generate_fuzz_value(type_name)

        args_str = ", ".join(f'{k}: {json.dumps(v)}' for k, v in args.items())
        query = f'{{ {field["name"]}({args_str}) {{ __typename }} }}'

        resp = requests.post(TARGET, json={"query": query})
        if resp.status_code >= 500:
            print(f"[!] Server error with query: {query[:200]}")

if __name__ == "__main__":
    schema = introspect_schema()
    fuzz_queries(schema)
```

### OpenAPI Mutation Fuzzing with Custom Scripts

```bash
# Extract all endpoints and parameters from OpenAPI spec
python3 -c "
import json, sys
spec = json.load(open('openapi.json'))
for path, methods in spec.get('paths', {}).items():
    for method, details in methods.items():
        if method in ('get','post','put','patch','delete'):
            params = [p['name'] for p in details.get('parameters', [])]
            print(f'{method.upper()} {path} params={params}')
"

# Fuzz each endpoint with type-confused payloads
for endpoint in $(jq -r '.paths | keys[]' openapi.json); do
  # Integer overflow
  curl -s -o /dev/null -w "%{http_code}" -X POST "http://target${endpoint}" \
    -H "Content-Type: application/json" \
    -d '{"id":99999999999999999999}'

  # Type confusion (string where int expected)
  curl -s -o /dev/null -w "%{http_code}" -X POST "http://target${endpoint}" \
    -H "Content-Type: application/json" \
    -d '{"id":"not_a_number","count":[],"name":{"$gt":""}}'

  # Null injection
  curl -s -o /dev/null -w "%{http_code}" -X POST "http://target${endpoint}" \
    -H "Content-Type: application/json" \
    -d '{"id":null,"name":null,"data":null}'

  # Array where object expected
  curl -s -o /dev/null -w "%{http_code}" -X POST "http://target${endpoint}" \
    -H "Content-Type: application/json" \
    -d '[{"id":1},{"id":2},{"id":3}]'
done
```

### API Rate Limit and Resource Exhaustion Fuzzing

```bash
# Concurrent request flooding (test rate limiting)
seq 1 1000 | xargs -P 50 -I {} curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://target/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query":"test"}'

# Large payload testing (memory exhaustion)
python3 -c "import json; print(json.dumps({'data': 'A'*10485760}))" | \
  curl -s -o /dev/null -w "%{http_code}" -X POST http://target/api/v1/upload \
  -H "Content-Type: application/json" -d @-

# Deeply nested JSON (stack overflow)
python3 -c "
depth = 10000
payload = '{\"a\":' * depth + '1' + '}' * depth
print(payload)
" | curl -s -o /dev/null -w "%{http_code}" -X POST http://target/api/v1/parse \
  -H "Content-Type: application/json" -d @-

# Slowloris-style slow POST (connection exhaustion)
for i in $(seq 1 100); do
  (echo -ne "POST /api/v1/upload HTTP/1.1\r\nHost: target\r\nContent-Length: 1000000\r\n\r\n"; sleep 30) | \
    nc target 80 &
done
```

---

## 13. Kernel Fuzzing

### Syzkaller Setup and Configuration

```bash
# Install syzkaller dependencies
sudo apt-get install -y golang-go git make gcc flex bison libssl-dev libelf-dev
go install github.com/google/syzkaller/...@latest

# Build kernel with coverage and debug options
cd linux-source/
cat >> .config << 'EOF'
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_ENABLE_COMPARISONS=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF4=y
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_FAULT_INJECTION=y
CONFIG_FAULT_INJECTION_DEBUG_FS=y
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
EOF
make olddefconfig && make -j$(nproc)

# Create syzkaller VM image
mkdir -p syzkaller-workdir/image
cd syzkaller-workdir/image
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh
chmod +x create-image.sh
./create-image.sh
```

### Syzkaller Configuration File

```yaml
# syzkaller.cfg - Main configuration for kernel fuzzing
{
    "target": "linux/arm64",
    "http": "127.0.0.1:56741",
    "workdir": "/path/to/syzkaller-workdir",
    "kernel_obj": "/path/to/linux-source",
    "image": "/path/to/syzkaller-workdir/image/bullseye.img",
    "sshkey": "/path/to/syzkaller-workdir/image/bullseye.id_rsa",
    "syzkaller": "/path/to/go/bin",
    "procs": 8,
    "type": "qemu",
    "vm": {
        "count": 4,
        "kernel": "/path/to/linux-source/arch/arm64/boot/Image",
        "cpu": 2,
        "mem": 2048
    },
    "enable_syscalls": [
        "open", "read", "write", "close", "mmap", "ioctl",
        "socket", "bind", "listen", "accept", "connect",
        "sendmsg", "recvmsg", "setsockopt", "getsockopt"
    ]
}
```

### Running Syzkaller

```bash
# Start syzkaller fuzzer
syz-manager -config syzkaller.cfg

# Monitor via web dashboard (http://127.0.0.1:56741)
# Key metrics: coverage, crashes, reproducers

# Reproduce a crash
syz-repro -config syzkaller.cfg crash-log-file

# Minimize reproducer
syz-prog2c reproducer.syz > reproducer.c
gcc -o reproducer reproducer.c -lpthread
./reproducer  # Should trigger the crash

# Extract C reproducer from syzkaller log
syz-execprog -executor=/path/to/syz-executor \
  -repeat=0 -procs=1 -cover=0 reproducer.syz
```

### Trinity Syscall Fuzzer

```bash
# Install Trinity
git clone https://github.com/kernelslacker/trinity
cd trinity && ./configure && make -j$(nproc)

# Basic syscall fuzzing (all syscalls)
./trinity -N 100000

# Fuzz specific syscall group
./trinity -g vm -N 50000          # Virtual memory syscalls
./trinity -g network -N 50000     # Network syscalls
./trinity -g filesystem -N 50000  # Filesystem syscalls

# Fuzz specific syscall with children
./trinity -c ioctl -N 100000 -C 4

# Run in namespace for isolation
unshare --mount --net --pid --fork ./trinity -N 100000

# Log all operations for crash reproduction
./trinity -N 100000 -l trinity.log --dangerous
```

### Kernel Module Fuzzing with ioctl

```python
#!/usr/bin/env python3
"""Kernel ioctl fuzzer targeting custom device drivers"""
import os
import fcntl
import struct
import random

DEVICE = "/dev/target_device"
IOCTL_BASE = 0x40  # Device-specific ioctl base

def fuzz_ioctl(device_path, iterations=10000):
    """Fuzz ioctl calls with random command numbers and data"""
    fd = os.open(device_path, os.O_RDWR)

    for i in range(iterations):
        # Generate random ioctl command number
        direction = random.choice([0x00, 0x40, 0x80, 0xC0])  # none/write/read/rw
        size = random.randint(0, 0x3FFF)
        cmd_type = random.randint(0, 255)
        cmd_nr = random.randint(0, 255)
        ioctl_cmd = (direction << 30) | (size << 16) | (cmd_type << 8) | cmd_nr

        # Generate random data buffer
        buf_size = random.choice([0, 4, 8, 16, 64, 256, 1024, 4096])
        buf = os.urandom(buf_size)

        try:
            fcntl.ioctl(fd, ioctl_cmd, buf)
        except OSError:
            pass  # Expected for invalid ioctls
        except Exception as e:
            print(f"[!] Unexpected error: ioctl=0x{ioctl_cmd:08x} err={e}")

    os.close(fd)

if __name__ == "__main__":
    fuzz_ioctl(DEVICE)
```

### Kernel Crash Log Analysis

```bash
# Parse kernel crash logs from syzkaller
grep -A 20 "BUG: KASAN" /var/log/kern.log
grep -A 20 "general protection fault" /var/log/kern.log
grep -A 20 "unable to handle kernel" /var/log/kern.log

# Extract crash reproducers from syzkaller workdir
ls syzkaller-workdir/crashes/
cat syzkaller-workdir/crashes/*/description
cat syzkaller-workdir/crashes/*/repro.prog  # Syzkaller program format
cat syzkaller-workdir/crashes/*/repro.cprog # C reproducer

# Decode kernel OOPS with addr2line
addr2line -e vmlinux -a 0xffffffff81234567
scripts/decode_stacktrace.sh vmlinux < crash_log.txt

# Test reproducer in isolated VM
qemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio \
  -append "console=ttyS0" -nographic -m 2G \
  -hda disk.img -snapshot
```
