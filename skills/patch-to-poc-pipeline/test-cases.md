# Patch-to-PoC Pipeline — Test Cases

> Structured test case templates for validating the patch-to-poc pipeline. Each case has all 7 fields: Severity, Prerequisites, Test Steps, Expected Results, payloads.md reference, Remediation, Pass Criteria.

## Conventions

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Prerequisites**: Required access, artifacts, or pre-conditions
- **Pass Criteria**: Objective condition indicating the test passes
- **Reference**: Pointer to the specific section in `payloads.md`
- All commands assume `/work/repro-attempt-memory.json` initialized per Schema 3

---

## A. Patch Analysis (Phase 1)

### TC-001 — CVE-2023-4863 libwebp Patch Analysis (memory_corruption)

**Severity**: HIGH

**Prerequisites**:
- libwebp git repo cloned at `/targets/libwebp`
- Tags `v1.3.1` (vulnerable) and `v1.3.2` (patched) available locally
- Schema 3 memory initialized at `/work/repro-attempt-memory.json`

**Test Steps**:
1. `cd /targets/libwebp && git diff v1.3.1 v1.3.2 -- src/dec/huffman_dec.c > /work/CVE-2023-4863.patch`
2. `git diff v1.3.1 v1.3.2 --stat` — verify hunk count and line stats
3. `grep '^+' /work/CVE-2023-4863.patch | grep -v '^+++' | grep -E 'if\s*\('` to find the protective check
4. Classify via `python3 /work/scripts/pattern_to_bugclass.py /work/CVE-2023-4863.patch`
5. Write Phase 1 memory delta (per payloads.md §16.1)

**Expected Results**:
- 1 file changed, 14 insertions, 3 deletions
- Key change adds `>= (1U << 31)` overflow check before `calloc`
- Pattern classifier returns `memory_corruption`
- `patch_analysis.suspected_vuln_function = "BuildHuffmanTable()"`
- `patch_analysis.confidence >= 0.8`

**Remediation**:
- If pattern classifier returns `unknown`, re-triage manually (§2 taxonomy)
- If confidence < 0.6, escalate to Phase 2 manual review before proceeding

**Pass Criteria**: Memory `patch_analysis` populated with `key_change`, `suspected_vuln_function`, `suspected_vuln_type`, `confidence` >= 0.8

**Reference**: payloads.md §1, §2, §3, §16.1

---

### TC-002 — CVE-2024-3094 xz-utils Backdoor Triage (forensic special case)

**Severity**: CRITICAL

**Prerequisites**:
- xz-utils source at `/targets/xz-5.6.0` (backdoored) and `/targets/xz-5.4.6` (clean)
- `binutils` for string inspection

**Test Steps**:
1. `diff -rq /targets/xz-5.4.6 /targets/xz-5.6.0 | grep -v '\.c \|\.h '`
2. `grep -rnE 'IFUNC|__attribute__\(\(ifunc|m4_include' /targets/xz-5.6.0/`
3. Inspect `tests/Makefile.am` diff for removed test files
4. Check `m4/build-to-host.m4` for the malicious `eval` block
5. Flag patch as backdoor; **DO NOT EXECUTE the patched version**

**Expected Results**:
- Build-system changes present in a security patch (red flag)
- IFUNC resolver discovered in liblzma
- Tests removed or disabled
- `m4` macros contain obfuscated content (the `eval` payload)

**Remediation**:
- If backdoor indicators present, halt pipeline and switch to forensic mode
- Do NOT compile or run the patched build in any environment
- Quarantine the source tarball; notify upstream

**Pass Criteria**: Backdoor correctly identified; pipeline aborts Phase 2 in favor of forensic triage

**Reference**: payloads.md §1.5, §3.3, §28

---

### TC-003 — Bug-Class Hypothesis via Protective Pattern Recognition

**Severity**: MEDIUM

**Prerequisites**:
- Patch file at `/work/CVE-XXXX-YYYYY.patch`
- `/work/scripts/pattern_to_bugclass.py` deployed

**Test Steps**:
1. Run `python3 /work/scripts/pattern_to_bugclass.py /work/CVE-XXXX-YYYYY.patch`
2. Manually inspect output and cross-reference with §2 taxonomy
3. Verify the classifier matches manual classification
4. Write `suspected_vuln_type` to memory

**Expected Results**:
- Classifier returns one of: `memory_corruption | integer_overflow | type_confusion | use_after_free | oob_read | oob_write | auth_bypass | path_traversal | sqli | xss | ssrf | race_condition`
- Manual classification agrees

**Remediation**:
- If classifier and manual disagree, trust manual for Phase 3 strategy
- Log disagreement in memory decision_log

**Pass Criteria**: Memory `patch_analysis.suspected_vuln_type` populated and consistent with manual classification

**Reference**: payloads.md §2, §3

---

## B. Code Path Walking (Phase 2)

### TC-004 — Source-Available Call Chain Reconstruction

**Severity**: HIGH

**Prerequisites**:
- Source tree at `/targets/<pkg>-<vuln_ver>/`
- `ctags`, `cflow` installed
- Phase 1 memory populated with `suspected_vuln_function`

**Test Steps**:
1. `grep -rn "<vuln_func>" /targets/<pkg>-<vuln_ver>/`
2. `cflow --main <public_api> /targets/<pkg>-<vuln_ver>/src/*.c | grep -A 20 "<public_api>"`
3. Compute `input_to_vuln_distance`
4. Write Phase 2 memory delta

**Expected Results**:
- At least one path from public API to vuln function exists
- `code_path.call_chain_to_vuln` populated as a list
- `input_to_vuln_distance` is a non-negative integer

**Remediation**:
- If distance = -1 (no path), abort — bug is unreachable
- If multiple paths, pick shortest for Phase 3 strategy

**Pass Criteria**: Memory `code_path` populated with `entry_function`, `call_chain_to_vuln`, `input_to_vuln_distance`

**Reference**: payloads.md §4

---

### TC-005 — Binary-Only Code Path via Ghidra Headless

**Severity**: HIGH

**Prerequisites**:
- Vulnerable `.so` at `/targets/<pkg>-<vuln_ver>.so`
- Patched `.so` at `/targets/<pkg>-<patched_ver>.so`
- Ghidra 11.x at `/opt/ghidra`
- BinDiff 6 installed

**Test Steps**:
1. Run Ghidra headless decompile of suspected vuln function (payloads.md §5.1)
2. Run `bindiff` between vuln and patched `.so` (§5.2)
3. Identify "changed functions" in BinDiff output
4. Cross-reference with Phase 1 suspected function
5. Write Phase 2 memory delta

**Expected Results**:
- Ghidra produces readable C-like pseudocode of the vulnerable function
- BinDiff marks the suspected function as "changed" (similarity < 1.0)
- Phase 2 memory reflects binary-confirmed call chain

**Remediation**:
- If Ghidra decompilation is garbage (typo in function name), verify with `nm -D /targets/<pkg>-<vuln_ver>.so | grep <vuln_func>`
- If BinDiff marks many functions changed, pick the one closest to Phase 1 hypothesis

**Pass Criteria**: Ghidra + BinDiff agree on the vulnerable function; Phase 2 memory updated

**Reference**: payloads.md §5

---

### TC-006 — Angr Symbolic Execution for Tainted Branch

**Severity**: MEDIUM

**Prerequisites**:
- `angr` Python package installed
- Vulnerable `.so` available
- Phase 1 hypothesis identifies the tainted parameter

**Test Steps**:
1. Write `/work/scripts/angr_walk.py` per payloads.md §5.4
2. Execute: `python3 /work/scripts/angr_walk.py`
3. Identify backward call chain from vuln function to public API
4. Write Phase 2 memory delta

**Expected Results**:
- angr CFG contains the vulnerable function
- Backward walk finds at least one path to a public API symbol
- Distance matches ctags-based analysis (when source available)

**Remediation**:
- If CFG is empty, binary may be stripped; use BinDiff instead
- If angr crashes on unconstrained states, increase timeout

**Pass Criteria**: angr confirms path from public API to vuln; memory updated

**Reference**: payloads.md §5.4

---

## C. PoC Generation (Phase 3)

### TC-007 — AFL++ Harness Construction for libpng

**Severity**: HIGH

**Prerequisites**:
- libpng source at `/targets/libpng-<vuln_ver>/` compiled with `make`
- AFL++ installed (`afl-clang-fast`)
- Seed corpus at `/work/seeds/`

**Test Steps**:
1. Write `/work/harness_png.c`:
   ```c
   #include <png.h>
   int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
       png_image img = {0};
       img.version = PNG_IMAGE_VERSION;
       png_image_from_memory(data, size, &img);
       png_image_free(&img);
       return 0;
   }
   ```
2. Compile with `afl-clang-fast -g -O1 -fsanitize=address,undefined` (§7.2)
3. Run `ASAN_OPTIONS=detect_leaks=0 /work/harness_vulnerable /work/seeds/ -max_total_time=1800 -artifact_prefix=/work/crashes/`
4. Inspect crashes; write Phase 3 memory delta

**Expected Results**:
- Harness compiles cleanly
- Fuzzer discovers crashes within time budget
- ASan trace points to vulnerable function (matches Phase 1 hypothesis)

**Remediation**:
- If harness fails to compile, check `-I` path against `/targets/libpng-<vuln_ver>/`
- If no crashes in 30 min, switch to Strategy A (manual craft) per §6.4

**Pass Criteria**: At least one crash in `/work/crashes/` with ASan trace matching Phase 1 hypothesis

**Reference**: payloads.md §6.4, §7

---

### TC-008 — Manual PoC Craft via Python `struct`

**Severity**: MEDIUM

**Prerequisites**:
- Valid sample at `/targets/samples/valid.webp`
- Phase 2 identified the vulnerable field offset (e.g., `0x42` Huffman-table-size)

**Test Steps**:
1. Write `/work/scripts/craft_poc.py` per payloads.md §6.1
2. Run: `python3 /work/scripts/craft_poc.py` to produce `/work/poc-crafted.webp`
3. Verify: `/work/harness_vulnerable /work/poc-crafted.webp` — expect ASan abort
4. If crashes, write Phase 3 memory delta

**Expected Results**:
- Crafted PoC triggers ASan abort in the vulnerable function
- Crash trace matches Phase 1 hypothesis

**Remediation**:
- If no crash, the field offset is wrong — re-walk code path in Phase 2
- If wrong function crashes, hypothesis is wrong — re-enter Phase 1

**Pass Criteria**: Manual PoC crashes vulnerable build with ASan trace matching hypothesis

**Reference**: payloads.md §6

---

### TC-009 — AFL++ Persistent Mode Harness (Performance)

**Severity**: LOW

**Prerequisites**:
- AFL++ 4.x with `__AFL_FUZZ_INIT()` macro
- Parser API that does not leak state across calls

**Test Steps**:
1. Write persistent harness per payloads.md §7.5
2. Compile with `afl-clang-fast`
3. Run with `-max_total_time=600` — compare crash yield to non-persistent
4. Verify persistent mode finds the same crashes 10x faster

**Expected Results**:
- Persistent mode reaches same crashes in 1/10 wall time
- Same crash dedup tokens as non-persistent

**Remediation**:
- If persistent crashes with state corruption, the API has hidden state — fall back to non-persistent

**Pass Criteria**: Persistent harness produces equivalent crashes faster

**Reference**: payloads.md §7.5

---

### TC-010 — Strategy Decision Matrix Application

**Severity**: MEDIUM

**Prerequisites**:
- Phase 1 confidence value populated
- Bug class known
- Both manual and fuzzer strategies available

**Test Steps**:
1. Read `patch_analysis.confidence` and `suspected_vuln_type` from memory
2. Apply §6.4 decision matrix
3. Choose Strategy A (manual) or Strategy B (fuzzer)
4. If 3 evidence-free attempts on chosen strategy, switch (招二)

**Expected Results**:
- Strategy chosen explicitly per matrix
- `failed_attempts` tracked in memory
- Path switch triggered when threshold reached

**Remediation**:
- If strategy A and B both stall, escalate to Phase 1 with new hypothesis

**Pass Criteria**: Strategy choice recorded in memory; path-switch rule enforced

**Reference**: payloads.md §6.4, §18

---

## D. Differential Verification (Phase 4)

### TC-011 — Differential Verification Pass Condition (CyberGym stop)

**Severity**: CRITICAL

**Prerequisites**:
- Vulnerable harness at `/work/harness_vulnerable`
- Patched harness at `/work/harness_patched` (identical flags)
- PoC input at `/work/crashes/crash-POC`

**Test Steps**:
1. Run `ASAN_OPTIONS=symbolize=1:abort_on_error=1 /work/harness_vulnerable /work/crashes/crash-POC` — capture exit code
2. Run `ASAN_OPTIONS=symbolize=1:abort_on_error=1 /work/harness_patched /work/crashes/crash-POC` — capture exit code
3. Apply decision matrix: vuln crashes AND patched clean = CONFIRMED
4. Write Phase 4 memory delta (§16.4)

**Expected Results**:
- Vulnerable exit code non-zero, ASan trace present
- Patched exit code 0, no ASan trace
- `convergence_state.status = "POC_CONFIRMED_DIFFERENTIALLY"`
- `stop_condition_met = true`

**Remediation**:
- If patched also crashes, see TC-012
- If neither crashes, see TC-013

**Pass Criteria**: CyberGym stop condition satisfied; pipeline advances to Phase 5

**Reference**: payloads.md §13, §14

---

### TC-012 — Differential Verification Fail: Both Crash (wrong root cause)

**Severity**: HIGH

**Prerequisites**:
- Phase 4 attempted, both versions crash with same PoC

**Test Steps**:
1. Confirm `vulnerable.crashed = true` and `patched.crashed = true`
2. Examine patched ASan trace — typically a different function
3. Re-enter Phase 1 with new hypothesis
4. Update `convergence_state.iterations` and `failed_attempts`

**Expected Results**:
- Both binaries crash
- Patched crash is in a DIFFERENT function (suggesting the PoC hits a separate bug)
- Hypothesis invalidated

**Remediation**:
- Examine patched binary for additional bugs the same input triggers
- Iterate Phase 1 with new bug-class hypothesis

**Pass Criteria**: Phase 1 re-entry triggered; new hypothesis recorded

**Reference**: payloads.md §13.3, §14

---

### TC-013 — Differential Verification Fail: Neither Crashes (PoC doesn't reach bug)

**Severity**: HIGH

**Prerequisites**:
- Phase 4 attempted, neither version crashes

**Test Steps**:
1. Confirm `vulnerable.crashed = false` and `patched.crashed = false`
2. Re-examine Phase 2 code path — likely wrong offset or wrong call chain
3. Re-walk code path with deeper grep
4. Re-enter Phase 3 with new candidate input

**Expected Results**:
- Neither binary crashes
- Code path analysis was wrong (input never reached the vulnerable function)

**Remediation**:
- Add debug prints to harness to confirm input reaches target function
- Re-run fuzzer with seed corpus that exercises the public API

**Pass Criteria**: Phase 3 re-entry triggered with new candidate input

**Reference**: payloads.md §13, §14

---

### TC-014 — Convergence Event Emission

**Severity**: MEDIUM

**Prerequisites**:
- Phase 4 stop condition met

**Test Steps**:
1. Run the event emitter (payloads.md §17.1)
2. Verify `convergence-events.jsonl` contains `POC_CONFIRMED_DIFFERENTIALLY` entry
3. Verify entry has correct timestamp and iteration count

**Expected Results**:
- Event log append-only
- Entry contains `stop_condition_met: true`
- Iteration count matches memory

**Remediation**:
- If event is missing, ensure jq pipe succeeded

**Pass Criteria**: Convergence event emitted with correct fields

**Reference**: payloads.md §17

---

## E. Anti-Pattern Detection

### TC-015 — Premature Stop Anti-Pattern

**Severity**: CRITICAL

**Prerequisites**:
- Memory at `/work/repro-attempt-memory.json`
- Anti-pattern script at `/work/scripts/anti_pattern_check.sh`

**Test Steps**:
1. Manually set `convergence_state.stop_condition_met = true` while `verification_results` has null fields
2. Run `/work/scripts/anti_pattern_check.sh`
3. Expect exit code 2 with "Premature stop" message

**Expected Results**:
- Detector flags the premature stop
- Pipeline halts before false-positive Phase 5

**Remediation**:
- Investigate why stop was attempted without verification
- Likely cause: agent skipped Phase 4

**Pass Criteria**: Anti-pattern detected; pipeline aborts

**Reference**: payloads.md §18.1

---

### TC-016 — Repeat-Without-Delta Anti-Pattern

**Severity**: HIGH

**Prerequisites**:
- Memory with `failed_attempts >= 3` on same hypothesis

**Test Steps**:
1. Manually set `convergence_state.failed_attempts = 3`
2. Run `/work/scripts/anti_pattern_check.sh`
3. Expect path-switch forced

**Expected Results**:
- Detector flags repeat-without-delta
- `active_path` switched to next candidate

**Remediation**:
- Pick new strategy (manual ↔ fuzzer)
- Reset `failed_attempts = 0`

**Pass Criteria**: Path switch triggered

**Reference**: payloads.md §18.1

---

## F. Detection Rule Authoring (Phase 5)

### TC-017 — YARA Rule Passes Differential Test

**Severity**: HIGH

**Prerequisites**:
- YARA rule at `/work/rules/CVE-XXXX-YYYYY.yar`
- Vulnerable `.so` and patched `.so`

**Test Steps**:
1. `yara -s /work/rules/CVE-XXXX-YYYYY.yar /targets/<pkg>-<vuln_ver>.so` — MUST match
2. `yara -s /work/rules/CVE-XXXX-YYYYY.yar /targets/<pkg>-<patched_ver>.so` — MUST NOT match
3. Or run `/work/scripts/yara_diff_test.sh /work/rules/CVE-XXXX-YYYYY.yar <vuln> <patched>`

**Expected Results**:
- Vulnerable binary: rule fires with match details
- Patched binary: rule silent
- Differential test exits 0

**Remediation**:
- If rule FP on patched, narrow the regex (require missing-guard pattern)
- If rule misses vuln, broaden the symbol pattern

**Pass Criteria**: Differential YARA test exits 0

**Reference**: payloads.md §19, §20

---

### TC-018 — Sigma Rule Syntax Validation

**Severity**: MEDIUM

**Prerequisites**:
- Sigma rule at `/work/rules/CVE-XXXX-YYYYY-sigma.yml`
- `sigma-cli` installed

**Test Steps**:
1. `sigma check /work/rules/CVE-XXXX-YYYYY-sigma.yml`
2. Verify no schema errors
3. Convert to Splunk: `sigma convert -t splunk /work/rules/CVE-XXXX-YYYYY-sigma.yml`
4. Convert to KQL: `sigma convert -t kql /work/rules/CVE-XXXX-YYYYY-sigma.yml`
5. Convert to EQL: `sigma convert -t eql /work/rules/CVE-XXXX-YYYYY-sigma.yml`

**Expected Results**:
- `sigma check` returns OK
- All three backend conversions succeed
- Output queries are syntactically valid

**Remediation**:
- If `sigma check` fails, fix YAML schema errors
- If a backend conversion fails, simplify detection selection

**Pass Criteria**: Sigma rule passes syntax check and converts to all backends

**Reference**: payloads.md §21, §22

---

### TC-019 — CVE-2023-34362 MOVEit Sigma Rule for SQLi Exploitation

**Severity**: HIGH

**Prerequisites**:
- Test IIS log sample containing both legitimate and malicious guestaccess.aspx requests
- Sigma rule from payloads.md §21.2

**Test Steps**:
1. `sigma convert -t splunk /work/rules/CVE-2023-34362-sigma.yml > /work/moveit.spl`
2. Run the converted query against the IIS log sample
3. Verify it matches the malicious POST and not the legitimate GET
4. Compute FP rate

**Expected Results**:
- 1 detection on malicious sample
- 0 detections on legitimate sample

**Remediation**:
- If FP > 0, add `falsepositives` notes; tighten `cs-uri-query|contains`

**Pass Criteria**: 100% precision on test sample

**Reference**: payloads.md §21.2

---

### TC-020 — SBOM-Driven Fleet Scanning

**Severity**: MEDIUM

**Prerequisites**:
- `syft` and `grype` installed
- Production image accessible at `/targets/production-image:latest`

**Test Steps**:
1. `syft /targets/production-image:latest -o cyclonedx-json > /work/sbom.json`
2. `jq '.components[] | select(.name=="libwebp") | {name, version}' /work/sbom.json`
3. `grype sbom:/work/sbom.json --only-fixed | grep libwebp`
4. Cross-reference with YARA rule

**Expected Results**:
- SBOM lists every libwebp in the image
- Grype matches the vulnerable version against CVE
- YARA confirms vulnerability at file level

**Remediation**:
- If SBOM misses a component, re-run syft with `-scope squashed`

**Pass Criteria**: Vulnerable version detected in SBOM; YARA confirms on file

**Reference**: payloads.md §23

---

## G. Bug-Class Workflows

### TC-021 — Memory-Corruption Workflow (CVE-2023-4863)

**Severity**: HIGH

**Prerequisites**:
- libwebp source + binaries (v1.3.1, v1.3.2)
- AFL++ and clang with `-fsanitize=address`

**Test Steps**:
1. Apply workflow per payloads.md §29
2. Build harness with `-fsanitize=address,undefined`
3. Run fuzzer, collect crash
4. Differential verify
5. Author YARA + Sigma

**Expected Results**:
- ASan reports heap-buffer-overflow in BuildHuffmanTable
- Phase 4 stop condition met
- YARA passes differential test

**Remediation**:
- If fuzzer does not find crash, extend seed corpus

**Pass Criteria**: All 5 phases complete; CyberGym stop condition met

**Reference**: payloads.md §29

---

### TC-022 — Auth-Bypass Workflow (CVE-2024-27198 TeamCity)

**Severity**: CRITICAL

**Prerequisites**:
- TeamCity vulnerable and patched instances
- HTTP client (`curl`)

**Test Steps**:
1. Identify the unauthenticated endpoint (`/hax?jsp=/app/rest/server;.jsp`)
2. Send request to vulnerable instance — expect 200 with sensitive data
3. Send same request to patched instance — expect 401
4. Apply workflow per payloads.md §32
5. Author YARA (source pattern) + Sigma (HTTP telemetry)

**Expected Results**:
- Vuln: 200 OK with API data leak
- Patched: 401 Unauthorized
- CyberGym-style differential verified

**Remediation**:
- If both 401, the endpoint path is wrong
- If both 200, the patch is not applied to this endpoint

**Pass Criteria**: Differential HTTP response confirmed

**Reference**: payloads.md §32

---

### TC-023 — SQLi Workflow (CVE-2023-34362 MOVEit)

**Severity**: CRITICAL

**Prerequisites**:
- MOVEit Transfer vulnerable and patched instances
- HTTP client

**Test Steps**:
1. Identify vulnerable endpoint (`/guestaccess.aspx`)
2. Send SQLi payload: `?arg=machine' UNION SELECT 1--`
3. Vuln: response shows DB error or leaked data
4. Patched: response is neutralized
5. Apply workflow per payloads.md §33

**Expected Results**:
- Vuln: SQL error or UNION data in response
- Patched: clean guest-access response
- Sigma rule detects the SQLi pattern in IIS logs

**Remediation**:
- If vuln does not respond to SQLi, verify endpoint and parameter name

**Pass Criteria**: Differential SQLi behavior confirmed; Sigma rule fires on vuln telemetry

**Reference**: payloads.md §33

---

### TC-024 — Race-Condition Workflow (CVE-2024-6387 regreSSHion)

**Severity**: HIGH

**Prerequisites**:
- OpenSSH server vulnerable build (pre-9.8)
- OpenSSH server patched build (9.8+)
- Network access to target SSH

**Test Steps**:
1. Open SSH connection that exceeds `LoginGraceTime`
2. Vuln: sshd child crashes with SIGALRM (race triggers)
3. Patched: sshd handles timeout cleanly
4. Apply workflow per payloads.md §34
5. Author Sigma rule on syslog `exited on signal 13`

**Expected Results**:
- Vuln: syslog shows `sshd[...]: exited on signal 13` (SIGALRM)
- Patched: clean timeout message
- TSan build (if available) reports data race

**Remediation**:
- Race may need many attempts; loop the trigger

**Pass Criteria**: Differential SSH behavior; Sigma rule fires on syslog

**Reference**: payloads.md §34

---

### TC-025 — Integer-Overflow Workflow

**Severity**: MEDIUM

**Prerequisites**:
- Target with arithmetic-on-size pattern
- clang with `-fsanitize=undefined,signed-integer-overflow`

**Test Steps**:
1. Apply workflow per payloads.md §30
2. Build with UBSan + `-ftrapv`
3. Seed with INT_MAX, UINT_MAX, 2^31, 2^32 boundaries
4. UBSan should report `signed integer overflow`
5. Differential verify

**Expected Results**:
- UBSan reports overflow in vulnerable build
- Patched build (with the size check) does not overflow
- Phase 4 stop condition met

**Remediation**:
- If UBSan silent, add `-fno-sanitize-recover=all` to force trap

**Pass Criteria**: UBSan trace matches hypothesis; differential verified

**Reference**: payloads.md §30

---

## H. Lifecycle & Multi-Agent

### TC-026 — Memory-Driven Convergence (招二 path switch)

**Severity**: HIGH

**Prerequisites**:
- Schema 3 memory at `/work/repro-attempt-memory.json`
- Path-switch threshold set (default 3)

**Test Steps**:
1. Simulate 3 evidence-free attempts on Strategy A
2. Verify `failed_attempts` reaches threshold
3. Verify `active_path` switches to Strategy B
4. Verify `failed_attempts` resets to 0
5. Verify decision_log entry recorded

**Expected Results**:
- `failed_attempts = 3` triggers switch
- New path chosen from `candidate_paths`
- Decision log records the switch with reason

**Remediation**:
- If switch not triggered, ensure anti-pattern checker runs between attempts

**Pass Criteria**: Path-switch rule enforced deterministically

**Reference**: payloads.md §16, §18

---

### TC-027 — Reproduction Report Generation (CyberGym Submission)

**Severity**: MEDIUM

**Prerequisites**:
- Phase 4 stop condition met
- Memory fully populated

**Test Steps**:
1. Run the markdown report generator (payloads.md §26.1)
2. Run the JSON snapshot generator (§26.2)
3. Verify both artifacts contain all 5 phases
4. Validate JSON snapshot against CyberGym submission schema (§27.1)

**Expected Results**:
- `repro-report.md` contains all 5 phase sections
- `repro-snapshot.json` validates as CyberGym submission
- Iteration count, stop condition, and verification results all present

**Remediation**:
- If report missing fields, ensure jq pipes include them

**Pass Criteria**: Both artifacts generated; JSON validates against CyberGym schema

**Reference**: payloads.md §26, §27

---

### TC-028 — Detection Rule Retirement (Lifecycle)

**Severity**: LOW

**Prerequisites**:
- SBOM shows 100% patched libwebp in fleet
- Sigma rule in production

**Test Steps**:
1. Run the lifecycle check (payloads.md §35.2)
2. Verify rule is moved to `/work/rules/retired/`
3. Verify lifecycle log records retirement

**Expected Results**:
- SBOM confirms fleet-wide patch
- Sigma rule moved to retired directory
- Lifecycle log updated

**Remediation**:
- If fleet not 100% patched, keep rule active; re-check monthly

**Pass Criteria**: Rule retired with lifecycle record

**Reference**: payloads.md §35

---

### TC-029 — Schema 3 Memory Lock with Multi-Agent Atomic Write

**Severity**: MEDIUM

**Prerequisites**:
- Schema 3 memory with `memory_lock` field
- Two parallel agent scripts simulating concurrent writes

**Test Steps**:
1. Agent A reads memory (version=10)
2. Agent B reads memory (version=10) simultaneously
3. Agent A writes delta — memory version becomes 11
4. Agent B attempts write — must detect version mismatch and re-read
5. Agent B re-reads (version=11), merges, writes — version becomes 12

**Expected Results**:
- No lost updates (both deltas present in version 12)
- `last_write_by` reflects the most recent writer
- Atomic `mv` pattern preserved

**Remediation**:
- If lost updates detected, ensure each agent uses the `tmp=$(mktemp) && ... && mv` pattern

**Pass Criteria**: Both agents' deltas present; no lost updates

**Reference**: payloads.md §15, §16

---

## Summary Table

| ID | Phase | Bug Class | Severity |
|----|-------|-----------|----------|
| TC-001 | 1 | memory_corruption | HIGH |
| TC-002 | 1 | backdoor (xz) | CRITICAL |
| TC-003 | 1 | taxonomy | MEDIUM |
| TC-004 | 2 | source | HIGH |
| TC-005 | 2 | binary-only | HIGH |
| TC-006 | 2 | angr | MEDIUM |
| TC-007 | 3 | fuzzer harness | HIGH |
| TC-008 | 3 | manual craft | MEDIUM |
| TC-009 | 3 | persistent | LOW |
| TC-010 | 3 | strategy matrix | MEDIUM |
| TC-011 | 4 | differential pass | CRITICAL |
| TC-012 | 4 | both crash | HIGH |
| TC-013 | 4 | neither crashes | HIGH |
| TC-014 | 4 | event emit | MEDIUM |
| TC-015 | — | anti-pattern premature stop | CRITICAL |
| TC-016 | — | anti-pattern repeat-no-delta | HIGH |
| TC-017 | 5 | YARA differential | HIGH |
| TC-018 | 5 | Sigma validation | MEDIUM |
| TC-019 | 5 | MOVEit Sigma | HIGH |
| TC-020 | 5 | SBOM scan | MEDIUM |
| TC-021 | all | memory_corruption | HIGH |
| TC-022 | all | auth_bypass | CRITICAL |
| TC-023 | all | sqli | CRITICAL |
| TC-024 | all | race_condition | HIGH |
| TC-025 | all | integer_overflow | MEDIUM |
| TC-026 | — | memory convergence | HIGH |
| TC-027 | all | report | MEDIUM |
| TC-028 | 5 | lifecycle | LOW |
| TC-029 | — | multi-agent | MEDIUM |

29 cases total — exceeds 27 minimum.
