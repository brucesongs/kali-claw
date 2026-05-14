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
