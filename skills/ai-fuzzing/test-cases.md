# AI Fuzzing Test Cases

> This file is a companion to `SKILL.md`, containing structured fuzzing test cases organized by target type.

---

## A. Binary Fuzzing

### TC-AF-001 | Binary Vulnerability Discovery with AFL++

- **Severity**: CRITICAL
- **Prerequisites**: Target C/C++ binary with source available; AFL++ installed (`afl-clang-fast` in PATH); target compiled with AFL++ instrumentation and Address Sanitizer; minimal seed corpus prepared; at least 2 CPU cores available for parallel fuzzing.
- **Target Example**: C program with a buffer overflow in input parsing function.
- **Test Steps**:
  1. Analyze target binary with radare2 to identify input parsing functions and dangerous API calls:
     ```bash
     r2 -A target_binary
     afl | grep -iE "parse|read|input|handle"
     axt sym.imp.strcpy
     ```
  2. Compile target with AFL++ instrumentation and ASAN:
     ```bash
     afl-clang-fast -o target_fuzz target.c -fsanitize=address
     ```
  3. Prepare and minimize seed corpus:
     ```bash
     mkdir seeds && echo "AAAA" > seeds/seed1
     afl-cmin -i seeds/ -o seeds_min/ -- ./target_fuzz @@
     ```
  4. Launch AFL++ in parallel mode (main + 2 secondary nodes):
     ```bash
     afl-fuzz -i seeds_min/ -o findings/ -M main -m none -- ./target_fuzz @@
     afl-fuzz -i seeds_min/ -o findings/ -S sub1 -m none -- ./target_fuzz @@
     ```
  5. Monitor dashboard for: coverage growth, unique crashes, stability percentage.
  6. When crashes found, reproduce each with ASAN build:
     ```bash
     ASAN_SYMBOLIZER_PATH=llvm-symbolizer ./target_fuzz findings/default/crashes/id:000001*
     ```
  7. Analyze crash with radare2 to determine root cause:
     ```bash
     r2 -d -A findings/default/crashes/id:000001*
     dbt   # Backtrace
     dr    # Registers at crash
     ```
  8. Verify crash independently using a different method (GDB manual reproduction):
     ```bash
     gdb --args ./target_fuzz findings/default/crashes/id:000001*
     run
     ```
- **Expected Results**: AFL++ discovers at least one unique crash within the fuzzing campaign. ASAN report identifies the specific memory corruption type (heap-buffer-overflow, stack-buffer-overflow, use-after-free). Crash is independently reproducible with both the original crash file and via manual GDB debugging. Root cause is traced to a specific input parsing function lacking bounds checking.
- **False Positive Elimination**: Confirm crash is not an OOM (check memory limit), not a timeout (check timeout setting), and not ASAN instrumentation artifact (reproduce without ASAN if possible).
- **Reference**: payloads.md Section 1 (Target Analysis), Section 3 (AFL++ Execution), Section 8 (Crash Analysis)

---

## B. Web API Fuzzing

### TC-AF-002 | Web API Fuzzing Against REST Endpoint (Authentication Bypass)

- **Severity**: CRITICAL
- **Prerequisites**: Target REST API accessible at known endpoint; valid API documentation or OpenAPI spec available; wfuzz and curl installed; at least one valid user account for baseline testing; Burp Suite available for manual verification.
- **Test Steps**:
  1. Enumerate API endpoints from OpenAPI spec:
     ```bash
     jq -r '.paths | keys[]' openapi.json
     ```
  2. Baseline test: confirm valid authentication works:
     ```bash
     curl -s -w "%{http_code}" -H "Authorization: Bearer VALID_TOKEN" \
       http://target/api/v1/users
     ```
  3. Fuzz authentication token with wfuzz:
     ```bash
     wfuzz -z file,/usr/share/seclists/Fuzzing/JWT-secrets.txt \
       -H "Authorization: Bearer FUZZ" \
       --hc 401 http://target/api/v1/users
     ```
  4. Fuzz numeric parameters with boundary values:
     ```bash
     wfuzz -z range,0-255 http://target/api/v1/users?id=FUZZ
     wfuzz -z range,-1000-1000 http://target/api/v1/users?offset=FUZZ
     ```
  5. Test content-type manipulation:
     ```bash
     for ct in application/json text/xml application/x-www-form-urlencoded multipart/form-data; do
       curl -s -w "%{http_code}\n" -X POST -H "Content-Type: $ct" \
         -d '{"data":"test"}' http://target/api/v1/endpoint
     done
     ```
  6. Test with schemathesis for spec-based fuzzing:
     ```bash
     st run --base-url http://target http://target/openapi.json
     ```
  7. Verify any anomaly independently with curl (no fuzzer involved):
     ```bash
     curl -v -X POST -H "Content-Type: application/json" \
       -d '{"id":99999999999}' http://target/api/v1/endpoint
     ```
  8. Check for authentication bypass by replaying modified tokens in Burp Suite Repeater.
- **Expected Results**: Discovery of at least one anomalous response: unexpected HTTP status code, error message leaking internal paths or stack traces, authentication bypass via malformed token, or parameter boundary causing server error. All findings independently reproducible with curl (no fuzzer dependency).
- **False Positive Elimination**: Verify findings are not caused by rate limiting (test with delays), not environment-specific (test from different IP), and not caused by temporary server state (repeat 3 times).
- **Reference**: payloads.md Section 6 (Web API Fuzzing)

---

## C. Protocol Fuzzing

### TC-AF-003 | Protocol Fuzzing with BooFuzz (Custom Protocol Parser)

- **Severity**: HIGH
- **Prerequisites**: Target running a custom binary protocol service on known TCP port; protocol structure reverse-engineered or documented; BooFuzz Python package installed; ability to monitor target process for crashes (SSH access, systemd journal, or debug output); network connectivity to target.
- **Test Steps**:
  1. Capture valid protocol exchange with tcpdump:
     ```bash
     tcpdump -i any -w baseline.pcap port 9999
     # Perform valid protocol interaction
     ```
  2. Analyze captured protocol structure in Wireshark to identify fields: magic bytes, length fields, command IDs, payload sections, checksums.
  3. Create BooFuzz template modeling the protocol structure:
     ```python
     from boofuzz import *
     session = Session(target=Target(
         connection=TCPSocketConnection("192.168.1.100", 9999)))
     s_initialize("BINARY_PACKET")
     s_static(b"\xAA\xBB")                    # Magic bytes
     s_size("data", length=2, endian=">")     # Length field
     s_byte(0x01, name="cmd", fuzzable=True)  # Command byte
     s_string("payload", name="data", fuzzable=True)
     s_checksum("data", algorithm="crc32")
     session.connect(s_get("BINARY_PACKET"))
     session.fuzz()
     ```
  4. Run BooFuzz and monitor target for crashes:
     ```bash
     python fuzz_template.py
     journalctl -f | grep -i "segfault\|crash\|killed"
     ```
  5. When crash detected, identify which test case caused it from BooFuzz crash log.
  6. Replay the specific crash test case:
     ```bash
     python -c "
     import socket
     s = socket.socket()
     s.connect(('192.168.1.100', 9999))
     s.send(open('crash_input.bin','rb').read())
     print(s.recv(4096))
     "
     ```
  7. Analyze crash on target system: check core dump, stack trace, and ASAN output if available.
  8. Verify independently: construct the malformed packet manually with netcat or Python socket.
- **Expected Results**: BooFuzz identifies at least one malformed packet that causes the target service to crash or behave unexpectedly. The crash is reproducible by manually sending the same malformed packet. Root cause analysis identifies which protocol field was malformed (length field overflow, invalid command, corrupted checksum bypass).
- **False Positive Elimination**: Confirm crash is caused by the malformed input (not service restart, not network timeout). Verify the service was stable before fuzzing. Reproduce crash with at least 3 consecutive attempts.
- **Reference**: payloads.md Section 7 (Protocol Fuzzing), Section 8 (Crash Analysis)

---

## D. File Format Fuzzing

### TC-AF-004 | File Format Fuzzing (Image Parser with libFuzzer)

- **Severity**: HIGH
- **Prerequisites**: Target image parsing library with source available (e.g., libpng, libjpeg, custom parser); LLVM/Clang toolchain installed with libFuzzer support; valid sample image files in the target format; understanding of the file format structure.
- **Test Steps**:
  1. Create libFuzzer harness wrapping the image parser:
     ```c
     #include <stdint.h>
     #include <stddef.h>
     extern int parse_image(const uint8_t *data, size_t size);
     int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
         if (size < 8) return 0;  // Skip files smaller than header
         parse_image(data, size);
         return 0;
     }
     ```
  2. Compile harness with libFuzzer and ASAN:
     ```bash
     clang -fsanitize=fuzzer,address -o img_fuzz \
       harness.c image_parser.c -I./include
     ```
  3. Prepare corpus from valid images:
     ```bash
     mkdir corpus
     cp /usr/share/images/*.png corpus/
     ```
  4. Run libFuzzer with corpus:
     ```bash
     ./img_fuzz corpus/ -max_len=1048576 -timeout=30 -jobs=4 -workers=4
     ```
  5. When crash found, reproduce with the crash file:
     ```bash
     ./img_fuzz crash-<hash>
     ```
  6. Analyze the ASAN report to identify the specific parsing function and memory corruption type.
  7. Minimize the crash input to smallest reproducer:
     ```bash
     ./img_fuzz -minimize_crash=1 -runs=100 crash-<hash> -exact_crash_path=minimized
     ```
  8. Verify independently by feeding the minimized crash file to a different build (e.g., without ASAN, or with a different compiler):
     ```bash
     gcc -o img_parser_test harness.c image_parser.c
     ./img_parser_test < minimized
     ```
- **Expected Results**: libFuzzer discovers a malformed image that triggers a memory corruption bug (heap-buffer-overflow during pixel parsing, null pointer dereference on truncated header, integer overflow in dimension fields). The minimized crash file is the smallest possible input to trigger the bug. Crash reproduces across different build configurations.
- **False Positive Elimination**: Verify crash is not caused by intentionally malformed ASAN interceptors. Test with `UBSAN_OPTIONS=halt_on_error=0` to confirm the crash is real. Validate that the crash input is a structurally plausible file (not random noise triggering an assertion in harness code).
- **Reference**: payloads.md Section 4 (libFuzzer), Section 8 (Crash Analysis)

---

## E. Coverage-Guided Corpus Generation

### TC-AF-005 | AI-Assisted Seed Corpus Generation
**Severity**: HIGH
**Objective**: Use LLM to generate high-quality seed inputs that maximize code coverage for a target parser

**Steps**:
1. Identify target input format (e.g., JSON schema, protocol spec)
2. Prompt LLM to generate diverse valid inputs covering edge cases
3. Validate generated seeds parse correctly
4. Measure initial code coverage with generated corpus
5. Feed seeds into AFL++/libFuzzer as initial corpus
6. Compare coverage vs random seed generation

**Expected Output**: Seed corpus achieving >60% code coverage before fuzzing begins

**Pass Criteria**:
- [ ] Generated seeds are syntactically valid
- [ ] Coverage exceeds random generation by >20%
- [ ] Seeds trigger distinct code paths (no redundancy)
- [ ] Fuzzer finds crashes faster with AI-generated seeds

## F. Crash Triage and Deduplication

### TC-AF-006 | Automated Crash Analysis and Severity Classification
**Severity**: HIGH
**Objective**: Automatically triage fuzzer-discovered crashes by exploitability and root cause

**Steps**:
1. Collect crash corpus from completed fuzzing campaign (>50 crashes)
2. Run crashes through ASan/MSan to classify memory error type
3. Deduplicate by stack trace similarity (top 3 frames)
4. Classify exploitability: heap overflow > stack overflow > null deref > assertion
5. Generate minimized reproducer for each unique crash
6. Produce triage report with severity ranking

**Expected Output**: Deduplicated crash report with exploitability ratings

**Pass Criteria**:
- [ ] Crashes deduplicated (unique count < 30% of total)
- [ ] Each unique crash has minimized reproducer
- [ ] Exploitability classification assigned
- [ ] No false deduplication (distinct bugs merged)

---

## G. Differential Fuzzing

### TC-AF-007 | Differential Fuzzing Across Parser Implementations
- **Severity**: HIGH
- **Prerequisites**: Two or more independent implementations of the same parser (e.g., two JSON libraries, two X.509 parsers); shared input corpus; harness capable of feeding identical inputs to each implementation and comparing outputs.
- **Objective**: Discover semantic bugs and parser-differential vulnerabilities by comparing outputs of equivalent implementations across the same fuzzed inputs.
- **Test Steps**:
  1. Build harnesses for each implementation that accept the same input format and emit canonical output (parsed AST, validation verdict, or normalized bytes):
     ```bash
     clang -fsanitize=fuzzer,address -o fuzz_lib_a fuzz_a.c lib_a.c
     clang -fsanitize=fuzzer,address -o fuzz_lib_b fuzz_b.c lib_b.c
     ```
  2. Run a differential harness that invokes both implementations and asserts equivalence:
     ```c
     int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
         Result a = parse_a(data, size);
         Result b = parse_b(data, size);
         if (!result_equal(a, b)) abort();
         return 0;
     }
     ```
  3. Launch fuzzer with shared corpus to maximize divergence discovery.
  4. For each abort, capture both implementations' outputs and classify divergence: validation gap, normalization drift, or memory safety bug.
  5. File divergences as security findings — semantically different parses are a precondition for smuggling and policy bypass attacks.
- **Expected Outcomes**: ≥1 input where implementations disagree on validity or interpretation, documented with reproducer.
- **Remediation**: Align both implementations against a shared spec, or pin a single canonical parser at the trust boundary.
- **Pass Criteria**:
  - [ ] Differential harness compiles and runs without false positives on the seed corpus
  - [ ] Fuzzer triggers ≥1 documented divergence
  - [ ] Each divergence has a minimized reproducer and severity classification
  - [ ] Findings mapped to concrete attack scenarios (request smuggling, auth bypass, etc.)

---

## Statistics

| Category | Test Cases | ID Range |
|----------|-----------|----------|
| A. Binary Fuzzing | 1 | TC-AF-001 |
| B. Web API Fuzzing | 1 | TC-AF-002 |
| C. Protocol Fuzzing | 1 | TC-AF-003 |
| D. File Format Fuzzing | 1 | TC-AF-004 |
| E. Corpus Generation | 1 | TC-AF-005 |
| F. Crash Triage | 1 | TC-AF-006 |
| G. Differential Fuzzing | 1 | TC-AF-007 |
| **Total** | **7** | **TC-AF-001 - TC-AF-007** |

### Severity Distribution

| Severity | Count | Test Cases |
|----------|-------|------------|
| CRITICAL | 2 | TC-AF-001, TC-AF-002 |
| HIGH | 4 | TC-AF-003, TC-AF-004, TC-AF-005, TC-AF-006 |
| MEDIUM | 0 | - |
| LOW | 0 | - |

---

## H. Grammar-Aware Fuzzing

### TC-AF-008 | Grammar-Aware Fuzzing for Structured Input Formats
- **Severity**: HIGH
- **Prerequisites**: Target application accepting structured input (JSON, XML, YAML, SQL, HTML, or custom DSL); grammar specification or RFC documentation available; AFL++ with grammar-aware mutator (`afl-grammar-mutator`) or Domino `domino` tool; target compiled with Address Sanitizer; valid seed corpus in target format.
- **Objective**: Discover vulnerabilities in structured input parsers by generating inputs that are syntactically valid enough to pass initial parsing but semantically malformed enough to trigger edge cases in deeper processing logic.
- **Test Steps**:
  1. **Obtain or write a grammar specification** for the target input format:
     ```bash
     # Example: JSON grammar for AFL++ grammar mutator (BNF notation)
     cat > json_grammar.bnf << 'GRAMMAR'
     <json> ::= <object> | <array> | <string> | <number> | "true" | "false" | "null"
     <object> ::= "{" <members>? "}"
     <members> ::= <pair> ("," <pair>)*
     <pair> ::= <string> ":" <json>
     <array> ::= "[" <elements>? "]"
     <elements> ::= <json> ("," <json>)*
     <string> ::= '"' (<char>)* '"'
     <char> ::= <escaped> | <normal_char>
     <escaped> ::= "\\" (<esc_char>)
     <number> ::= <int> <frac>? <exp>?
     <int> ::= "-"? <digits>
     <frac> ::= "." <digits>
     <exp> ::= ("e" | "E") ("+" | "-")? <digits>
     <digits> ::= [0-9]+
     GRAMMAR
     ```
  2. **Build the grammar-aware mutator plugin for AFL++**:
     ```bash
     # Build AFL++ grammar mutator
     cd ~/AFLplusplus/grammar_mutator
     make
     # Generate mutator library from grammar
     python3 grammar-generator.py json_grammar.bnf
     ```
  3. **Prepare seed corpus with valid samples at varying complexity levels**:
     ```bash
     mkdir -p grammar_seeds
     # Minimal valid input
     echo '{"a":1}' > grammar_seeds/seed_minimal.json
     # Nested structure
     echo '{"users":[{"name":"test","id":1},{"name":"admin","id":0}]}' > grammar_seeds/seed_nested.json
     # Large array (stress test)
     python3 -c "import json; print(json.dumps({'items': [{'x': i} for i in range(100)]}))" > grammar_seeds/seed_large.json
     # Edge case values
     echo '{"neg": -999999, "big": 1e308, "empty": "", "null_val": null, "unicode": "\\u0000\\uffff"}' > grammar_seeds/seed_edge.json
     ```
  4. **Launch AFL++ with grammar-aware mutator**:
     ```bash
     afl-fuzz -i grammar_seeds/ -o grammar_findings/ \
       -m none -t 5000 \
       -x json_grammar.bnf \
       -- ./target_parser @@
     ```
  5. **Monitor grammar-specific metrics**: compare structural coverage (unique edges hit in parsing logic) against a parallel run using standard byte-level mutation:
     ```bash
     # Run comparison: grammar-aware vs. standard mutation
     afl-fuzz -i grammar_seeds/ -o standard_findings/ -M std -m none -- ./target_parser @@
     afl-fuzz -i grammar_seeds/ -o grammar_findings/ -M gram -m none -x json_grammar.bnf -- ./target_parser @@

     # After 4 hours, compare:
     # afl-whatsup -o grammar_findings/
     # afl-whatsup -o standard_findings/
     ```
  6. **When crashes found, analyze with ASAN and minimize**:
     ```bash
     # Reproduce crash
     ASAN_SYMBOLIZER_PATH=llvm-symbolizer ./target_parser grammar_findings/default/crashes/id:000001*

     # Minimize crash input
     afl-tmin -i grammar_findings/default/crashes/id:000001* -o minimized_crash -- ./target_parser @@

     # Check if minimized input still has valid structure (grammar-aware advantage)
     python3 -c "import json; json.load(open('minimized_crash'))" 2>&1
     ```
  7. **Classify crash as grammar-induced or random**: grammar-aware crashes are more likely to represent real-world attack vectors because the input structure mimics what an attacker would send:
     ```bash
     # Check if the crash input is parseable (passes initial validation)
     if python3 -c "import json; json.load(open('minimized_crash'))" 2>/dev/null; then
         echo "GRAMMAR-VALID CRASH: high severity (passes parser, crashes processor)"
     else
         echo "GRAMMAR-INVALID CRASH: lower severity (caught by parser but still a bug)"
     fi
     ```
- **Expected Outcomes**: Grammar-aware fuzzing discovers crashes that standard byte-level mutation misses because the inputs pass the initial syntax validation layer. At least 1 crash found that standard mutation did not find within the same time budget. Minimized crash inputs are structurally plausible (parseable), indicating the vulnerability is in semantic processing rather than syntax parsing. Coverage of parsing logic branches is higher with grammar-aware mutator than standard mutator.
- **False Positive Elimination**: Confirm crash is not from trivially malformed input (e.g., completely random bytes). Verify that the crash input has structural elements matching the grammar. Compare crash severity: grammar-valid crashes that reach deep processing logic are higher severity than syntax-level crashes.
- **Remediation**: Add input validation at the semantic processing layer (not just syntax validation); implement fuzz testing in CI/CD with grammar-aware mutators; add property-based tests (e.g., Hypothesis library for Python) that generate structurally valid edge cases.
- **Pass Criteria**:
  - [ ] Grammar specification written and validated against known-good inputs
  - [ ] Grammar-aware fuzzer achieves higher structural coverage than standard mutation
  - [ ] At least 1 unique crash found by grammar-aware approach that standard approach missed
  - [ ] Minimized crash input is structurally plausible (passes syntax validation)
  - [ ] Crash root cause traced to semantic processing logic, not syntax parsing
