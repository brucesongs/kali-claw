# Reverse Engineering Advanced — Test Cases

Structured test cases covering advanced reverse engineering workflows: symbolic execution (angr, KLEE, manticore), binary diffing (BinDiff, Diaphora, Kam1n0), firmware RE (binwalk, FACT, EMBA), OLLVM deobfuscation (CFF, BCG, SUB), SMT-assisted key recovery (Z3), decompiler confusion, variant analysis, and automated RE pipelines.

Each test case includes: Severity, Prerequisite, Test Step, Expected Result, Objective, Remediation, and Pass Criteria — supporting reproducible lab validation and engagement QA.

---

## TC-RE-001 — Static triage identifies file type and entropy

**Severity**: Medium

**Prerequisite**: Sample binary present in lab (e.g., `/lab/samples/sample.exe`); `file`, `sha256sum`, `strings`, Python `pefile` installed.

**Test Step**:
```bash
file sample.exe
sha256sum sample.exe
strings -a sample.exe | head -20
python3 -c "
import pefile, math
pe = pefile.PE('sample.exe')
for s in pe.sections:
    name = s.Name.decode().rstrip(chr(0))
    ent = s.get_entropy()
    print(f'{name:12s} entropy={ent:.2f}')
"
```

**Expected Result**: File type reported (PE32+ / ELF / Mach-O); SHA256 hash recorded; section entropy reported; sections with entropy >7.0 flagged as packed.

**Objective**: Establish baseline metadata for downstream analysis and detect packing indicators.

**Remediation**: If entropy is high (>7.0), proceed to unpacking workflow (TC-RE-006).

**Pass Criteria**: Triage notes contain file type, SHA256, and per-section entropy values.

---

## TC-RE-002 — Symbolic execution with angr solves crackme

**Severity**: High

**Prerequisite**: `pip install angr`; known crackme binary with "Good boy" / "Bad boy" output strings; angr-solvable constraint path.

**Test Step**:
```python
import angr
proj = angr.Project('./crackme', auto_load_libs=False)
state = proj.factory.entry_state()
sm = proj.factory.simulation_manager(state)
sm.explore(find=lambda s: b'Good boy' in s.posix.dumps(1),
          avoid=lambda s: b'Bad boy' in s.posix.dumps(1))
if sm.found:
    print(f"Solution: {sm.found[0].posix.dumps(0)}")
```

**Expected Result**: angr finds at least one input that reaches the "Good boy" path; solution printed in printable ASCII.

**Objective**: Demonstrate automated path exploration for key validation logic.

**Remediation**: If path explosion occurs, restrict stdin length via `state.libc.buf` or add `avoid` constraints for unreachable branches.

**Pass Criteria**: At least one valid solution recovered and verified by re-running binary.

---

## TC-RE-003 — KLEE symbolic execution on LLVM bitcode

**Severity**: High

**Prerequisite**: LLVM 12+ installed, `klee` binary available; target compiled with `-emit-llvm -c` to produce `.bc` file.

**Test Step**:
```bash
clang -emit-llvm -c target.c -o target.bc
klee --max-time=60 --max-memory=2000 target.bc
ls klee-last/
ktest-tool --write-ints klee-last/test000001.ktest
```

**Expected Result**: KLEE generates `.ktest` files representing path inputs; at least one input triggers assertion or covers new branch.

**Objective**: Verify LLVM-based symbolic execution flow on a known test target.

**Remediation**: If KLEE runs out of time, reduce search depth or use `--search=dfs` instead of default BFS.

**Pass Criteria**: At least one `.ktest` file produced; input reproducible.

---

## TC-RE-004 — Manticore symbolic execution on smart contract

**Severity**: High

**Prerequisite**: Solidity 0.8+, `pip install manticore`; example contract `Token.sol` with integer overflow candidate.

**Test Step**:
```bash
manticore --contract Token.sol --detect-integer-overflow
ls mcore_*/
cat mcore_*/global_coverage.txt
```

**Expected Result**: Manticore reports integer overflow detection; coverage report shows >70% line coverage.

**Objective**: Validate manticore for EVM bytecode symbolic execution.

**Remediation**: If timeout, increase `--txlimit` and reduce `--verbosity`. Switch to `--no-testcases` for pure coverage.

**Pass Criteria**: Detector output non-empty; coverage report generated.

---

## TC-RE-005 — BinDiff identifies patched functions across versions

**Severity**: High

**Prerequisite**: BinDiff 8+ installed; pre-patch (`v1.exe`) and post-patch (`v2.exe`) PE files with at least one patched function.

**Test Step**:
```bash
bindiff --binary1=v1.exe --binary2=v2.exe --output_dir=diffs/
ls diffs/
# Open v1_v2.Diff in BinDiff UI
```

**Expected Result**: BinDiff produces `.Diff` database; UI shows "Unmatched", "Changed", "Matched" function counts; at least one changed function identified.

**Objective**: Demonstrate binary diffing for patch analysis (1-day exploitation workflow).

**Remediation**: If match rate <70%, run BinDiff with `--algo_suffix=true` to use additional similarity algorithms.

**Pass Criteria**: Diff database created; at least one changed function attributable to a security patch.

---

## TC-RE-006 — UPX unpacking recovers original binary

**Severity**: Medium

**Prerequisite**: `upx` installed; sample packed with `upx -d` recoverable protection.

**Test Step**:
```bash
cp packed.exe packed_backup.exe
upx -d packed.exe -o unpacked.exe
file unpacked.exe
strings unpacked.exe | grep -iE "http|password" | head
```

**Expected Result**: `unpacked.exe` written; section entropy drops to <7.0; original strings visible.

**Objective**: Validate UPX unpacking workflow.

**Remediation**: If `upx -d` fails due to modified magic, manually patch UPX header or use VM emulator to dump post-OEP.

**Pass Criteria**: Original code recovered; entropy drop verified; binary executes with original behavior.

---

## TC-RE-007 — Custom packer unpacked via x64dbg + Scylla

**Severity**: High

**Prerequisite**: Windows lab VM with x64dbg + Scylla plugin; sample using custom packer with OEP recoverable via memory breakpoint.

**Test Step**:
```text
1. Load sample.exe in x64dbg
2. Set memory breakpoint on protected section (exec)
3. Run; breakpoint hits after decompression
4. Single-step (F8/F7) until OEP identified
5. Open Scylla:
   - Select active process
   - IAT AutoSearch
   - Get Imports
   - OEP = current EIP
   - Dump → save dump.exe
   - Fix Dump → dump_SCY.exe
```

**Expected Result**: IAT recovered; dumped executable runs without packer; imports resolved correctly.

**Objective**: Demonstrate manual unpacking workflow for non-trivial packers.

**Remediation**: If IAT auto-recovery fails, manually walk IAT array and identify imports via EAT lookup.

**Pass Criteria**: Fixed dump executes; imports display correctly in PE view; entropy <7.0.

---

## TC-RE-008 — Binwalk extracts firmware filesystem

**Severity**: High

**Prerequisite**: `pip install binwalk`; firmware image (e.g., router firmware `FW.bin` containing SquashFS).

**Test Step**:
```bash
binwalk FW.bin
binwalk -e FW.bin
ls _FW.bin.extracted/
file _FW.bin.extracted/*.squashfs
unsquashfs _FW.bin.extracted/*.squashfs
ls squashfs-root/
```

**Expected Result**: Filesystem extracted; directory tree shows `/bin`, `/etc`, `/usr`; telnetd or httpd binary located.

**Objective**: Validate firmware extraction workflow for IoT/router analysis.

**Remediation**: If entropy of inner image is >7.0, the firmware is encrypted; identify decrypt key via vendor leak or JTAG extraction.

**Pass Criteria**: Full filesystem extracted; at least one binary analyzable.

---

## TC-RE-009 — FACT full firmware analysis pipeline

**Severity**: Medium

**Prerequisite**: FACT_core installed and running (default port 5000); firmware image uploaded.

**Test Step**:
```bash
# Upload via web UI or API
curl -X POST -F "file=@FW.bin" http://localhost:5000/ajax/upload

# Wait for analysis (typically 5-30 min depending on size)
# Check result
curl http://localhost:5000/database/browse
```

**Expected Result**: FACT reports firmware metadata, extracted filesystem, identified vulnerabilities, fingerprinted components (busybox version, kernel version, openssl version).

**Objective**: Validate automated firmware analysis pipeline.

**Remediation**: If analysis hangs, increase Docker resource limits and check `error.log`.

**Pass Criteria**: At least one CVE identified in components; filesystem viewable in UI.

---

## TC-RE-010 — EMBA automated vulnerability scan on firmware

**Severity**: High

**Prerequisite**: EMBA installed; firmware image; sufficient disk space (~10GB for logs).

**Test Step**:
```bash
cd ~/emba
sudo ./emba -l /logs/FW -f ~/samples/FW.bin
# Tail progress
tail -f /logs/FW/emba.log
# After completion
cat /logs/FW/html-report/index.html | head
```

**Expected Result**: EMBA produces HTML report listing CVEs, weak binaries, hardcoded credentials, dangerous syscalls.

**Objective**: Demonstrate large-scale firmware vulnerability scanning.

**Remediation**: If EMBA fails on dependencies, run `./installer.sh` again; ensure Docker has ≥8GB RAM.

**Pass Criteria**: HTML report generated; ≥1 CVE listed; ≥1 unsafe binary flagged.

---

## TC-RE-011 — OLLVM Control Flow Flattening deobfuscation

**Severity**: High

**Prerequisite**: Sample obfuscated with OLLVM CFF; `deflat.py` available; dispatcher address identified.

**Test Step**:
```bash
# Identify dispatcher in IDA / Ghidra (large switch statement)
# Identify state variable

python3 deflat.py --binary flattened.exe --dispatcher 0x401000 --state-var eax

# Verify deobfuscated binary
./deflattened.exe
```

**Expected Result**: Deflattened binary has structured CFG visible in IDA; dispatcher switch removed; decompiler produces readable output.

**Objective**: Validate CFF deobfuscation workflow.

**Remediation**: If dispatcher address is wrong, identify via dynamic analysis — set breakpoint on the suspected dispatcher, confirm execution flow.

**Pass Criteria**: CFG shows non-flat structure; original function logic visible.

---

## TC-RE-012 — Bogus Control Flow removal via opaque predicate identification

**Severity**: Medium

**Prerequisite**: Sample with BCG obfuscation; IDA Pro or Binary Ninja available; basic block analysis.

**Test Step**:
```python
# IDA Python
import idautils, idc, ida_funcs

for func_ea in idautils.Functions():
    func = ida_funcs.get_func(func_ea)
    # Walk basic blocks; look for branches where predicate is always true/false
    # Common pattern: cmp x, x  -> always equal
    pass

# Use d810 plugin for automated BCG removal
# https://gitlab.com/eshard/d810
```

**Expected Result**: Opaque predicates identified; dead branches removed; CFG simplified.

**Objective**: Defeat OLLVM Bogus Control Flow obfuscation.

**Remediation**: If automated tools fail, manually identify opaque predicates via constant propagation.

**Pass Criteria**: ≥50% reduction in basic block count after BCG removal.

---

## TC-RE-013 — Instruction Substitution recovery via miasm simplification

**Severity**: Medium

**Prerequisite**: Sample with OLLVM SUB obfuscation; `pip install miasm`.

**Test Step**:
```python
from miasm.expression.expression import *
from miasm.analysis.simplifier import ExpressionSimplifier

# Encode: (x ^ y) | ((x ^ y) - 1)  → simplified to x NAND y (basic case)
expr = ExprOp('|', ExprOp('^', x, y), ExprOp('-', ExprOp('^', x, y), ExprInt(1, 32)))
simp = ExpressionSimplifier()
result = simp(expr)
print(result)
```

**Expected Result**: Substituted instructions simplified back to canonical form.

**Objective**: Defeat instruction substitution obfuscation.

**Remediation**: If simplification fails, extend rules with custom `ExprSimplifier` rules.

**Pass Criteria**: Simplified expression reduces instruction count by ≥40%.

---

## TC-RE-014 — Z3 SMT solver recovers 16-byte key

**Severity**: High

**Prerequisite**: `pip install z3-solver`; reverse-engineered key check function extracted to constraints.

**Test Step**:
```python
from z3 import *

s = Solver()
key = [BitVec(f'k_{i}', 8) for i in range(16)]

# Printable range
for i in range(16):
    s.add(key[i] >= 0x20, key[i] <= 0x7e)

# Constraints (derived from disassembly)
s.add(key[0] + key[1] == 0x90)
s.add(key[2] * key[3] == 0x41A8)
# ... up to N constraints

if s.check() == sat:
    m = s.model()
    print(bytes(m[k].as_long() for k in key))
```

**Expected Result**: Z3 returns `sat` and produces a valid 16-byte key.

**Objective**: Demonstrate SMT-assisted key recovery for custom crypto routines.

**Remediation**: If `unsat`, recheck constraint extraction; one wrong operator (>= vs >) breaks satisfiability.

**Pass Criteria**: Recovered key passes original key check when fed into binary.

---

## TC-RE-015 — Decompiler confusion pattern identification

**Severity**: Medium

**Prerequisite**: Sample with anti-decompiler patterns; IDA Pro or Ghidra; `idautils` Python module.

**Test Step**:
```python
# IDA Python — detect common anti-decompiler patterns
import idautils, idc

for func_ea in idautils.Functions():
    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        # Detect JE+0 / JNE-1 anti-disassembly
        if mnem in ('je', 'jne'):
            op = idc.get_operand_value(ea, 0)
            next_ea = idc.next_head(ea)
            if op == next_ea:
                print(f'Anti-disassembly at {hex(ea)}')
```

**Expected Result**: Anti-decompiler patterns identified and patched (NOP-out opaque branches, fix overlapping instructions).

**Objective**: Recover readable decompilation output.

**Remediation**: If pattern not detected, fall back to manual disassembly interpretation.

**Pass Criteria**: Hex-Rays decompiler produces non-empty, structured C output.

---

## TC-RE-016 — Variant analysis with Kam1n0 clusters samples

**Severity**: Medium

**Prerequisite**: Kam1n0 Community Edition installed; ≥10 malware samples of same family.

**Test Step**:
```bash
kam1n0 index -i samples/ -o index.db
kam1n0 cluster -i index.db -o clusters.json
jq '.clusters | length' clusters.json
```

**Expected Result**: Samples clustered by assembly similarity; ≥3 clusters identified with intra-cluster similarity >70%.

**Objective**: Demonstrate assembly-level variant analysis.

**Remediation**: If clusters are noisy, raise `--similarity-threshold` to 0.8.

**Pass Criteria**: ≥1 cluster with ≥3 samples; family attribution label confirmed via cross-reference with VT.

---

## TC-RE-017 — Ghidra headless decompilation pipeline

**Severity**: Medium

**Prerequisite**: Ghidra 11+ installed; `analyzeHeadless` available; sample binary.

**Test Step**:
```bash
mkdir -p /tmp/ghidra_proj
analyzeHeadless /tmp/ghidra_proj SampleProj -import sample.exe \
  -postScript /opt/ghidra_scripts/DecompileAllFunctions.java \
  -scriptlog /tmp/decompile.log
cat /tmp/decompile.log | head
```

**Expected Result**: Decompile log contains per-function C output; ≥90% of functions decompiled.

**Objective**: Build CI/CD-compatible automated decompilation pipeline.

**Remediation**: If decompilation fails on certain functions, mark them for manual review.

**Pass Criteria**: ≥90% functions decompiled; log saved.

---

## TC-RE-018 — IDA Pro Python analysis extracts suspicious API calls

**Severity**: High

**Prerequisite**: IDA Pro 9+ with IDAPython; sample binary with `WriteProcessMemory` / `VirtualAllocEx` calls.

**Test Step**:
```python
import idautils, idc, ida_hexrays

suspicious = ['WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread', 'NtUnmapViewOfSection']

for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    if name in suspicious:
        for xref in idautils.XrefsTo(func_ea):
            print(f"Call to {name} at {hex(xref.frm)}")
            cf = ida_hexrays.decompile(xref.frm)
            if cf:
                print(cf)
```

**Expected Result**: All calls to suspicious APIs identified; Hex-Rays decompilation for each call site.

**Objective**: Demonstrate IDA Python workflow for IOC extraction.

**Remediation**: If Hex-Rays fails, fall back to assembly-level analysis.

**Pass Criteria**: All injection-related API calls catalogued with caller context.

---

## TC-RE-019 — Binary Ninja API identifies obfuscated functions

**Severity**: Medium

**Prerequisite**: Binary Ninja 5+ with Python API; sample with marked obfuscation patterns.

**Test Step**:
```python
import binaryninja as bn

bv = bn.BinaryViewType.get_view_of_file('./sample.exe')

for func in bv.functions:
    bb_count = len(list(func.basic_blocks))
    if bb_count > 200:
        print(f'{func.name} @ {hex(func.start)} has {bb_count} BBs — likely obfuscated')
```

**Expected Result**: Functions with >200 basic blocks flagged for further analysis.

**Objective**: Use Binary Ninja API for automated obfuscation triage.

**Remediation**: Tweak threshold based on sample complexity.

**Pass Criteria**: Obfuscated functions identified with confidence.

---

## TC-RE-020 — radare2 scripting for batch analysis

**Severity**: Medium

**Prerequisite**: `pip install r2pipe`; sample binary.

**Test Step**:
```python
import r2pipe

r2 = r2pipe.open('./sample.exe')
r2.cmd('aaa')

# List functions
funcs = r2.cmd('aflj')
import json
for f in json.loads(funcs):
    print(f"{f['name']:30s} @ {hex(f['offset'])}")

# Decompile a function (if r2ghidra available)
r2.cmd('pdg @ main')
```

**Expected Result**: Function list retrieved; main function decompiled via r2ghidra.

**Objective**: Validate radare2 scripting for batch RE tasks.

**Remediation**: If `pdg` fails, install `r2ghidra` plugin.

**Pass Criteria**: ≥90% functions identified; main decompiled.

---

## TC-RE-021 — Diaphora cross-binary diffing in IDA

**Severity**: Medium

**Prerequisite**: Diaphora IDA plugin installed; two binary versions loaded sequentially.

**Test Step**:
```text
1. Open v1.exe in IDA
2. Wait for auto-analysis
3. File → Diaphora → Export current database → save as v1.sqlite
4. Open v2.exe in IDA
5. File → Diaphora → Diff against v1.sqlite
6. Review "Best Match", "Partial Match", "Unreliable Match" tabs
```

**Expected Result**: Diff results show ≥1 changed function attributable to patch.

**Objective**: Free alternative to BinDiff for patch analysis.

**Remediation**: If results are noisy, raise `Minimum Praiom" threshold to 0.95.

**Pass Criteria**: Patched function identified with ≥0.9 similarity score.

---

## TC-RE-022 — Crypto algorithm identification via FindCrypt

**Severity**: High

**Prerequisite**: IDA Pro with FindCrypt plugin (or KANAL for PEiD); sample using standard crypto (AES, RSA, SHA-256).

**Test Step**:
```text
1. Load sample in IDA
2. Edit → Plugins → FindCrypt
3. Review detected constants (S-box, magic numbers)

# Alternative: Signsrch
signsrch -i sample.exe
```

**Expected Result**: FindCrypt reports standard crypto constants with high confidence; corresponding functions annotated.

**Objective**: Identify crypto usage for key recovery or protocol analysis.

**Remediation**: If FindCrypt misses custom crypto, use TLSandu or manual reverse — look for ARX patterns, S-box lookups, modular arithmetic.

**Pass Criteria**: ≥1 crypto algorithm identified with ≥95% confidence.

---

## TC-RE-023 — Hex-Rays decompilation produces readable C output

**Severity**: High

**Prerequisite**: IDA Pro with Hex-Rays decompiler; sample not aggressively obfuscated.

**Test Step**:
```python
import ida_hexrays, idc

ida_hexrays.init_decompiler()
for func_ea in [0x401000, 0x401200, 0x401500]:
    cf = ida_hexrays.decompile(func_ea)
    if cf:
        print(cf)
```

**Expected Result**: All requested functions produce readable C-like pseudocode.

**Objective**: Validate decompiler output quality for engagement reporting.

**Remediation**: If output is garbage, check for anti-decompiler patterns (TC-RE-015) and patch them.

**Pass Criteria**: ≥80% requested functions decompile to readable C.

---

## TC-RE-024 — Equation Group REGIN-stage analysis

**Severity**: High

**Prerequisite**: REGIN sample (or representative multi-stage obfuscated sample); IDA Pro + Ghidra; ≥4 hours analysis time.

**Test Step**:
```text
1. Identify stage loaders (typically via IOCTL or registry triggers)
2. Decompile stage 1 — identify decryption routine for stage 2
3. Extract stage 2 payload from encrypted blob
4. Decompile stage 2 — identify C2 protocol
5. Document IOCs: mutex, registry keys, C2 domains
```

**Expected Result**: Multi-stage infection chain reconstructed; each stage's purpose documented.

**Objective**: Demonstrate APT-grade analysis workflow.

**Remediation**: If stage extraction fails, use Volatility to dump from memory.

**Pass Criteria**: All stages documented; IOCs disseminated to SOC.

---

## TC-RE-025 — Pegasus FORCEDENTRY analysis workflow

**Severity**: High

**Prerequisite**: FORCEDENTRY sample (or representative iMessage 0-click exploit); isolated lab; Citizen Lab report reference.

**Test Step**:
```text
1. Acquire sample (legitimate research context only)
2. Detonate in isolated macOS VM
3. Capture iMessage attachment processing logs
4. Reverse PDF → GIF → JBIG2 → IMS extraction flow
5. Document sandbox escape primitives
6. Map to MITRE ATT&CK T1190 / T1203
```

**Expected Result**: Exploit chain reconstructed; JBIG2 stack manipulation documented; kernel patch documented.

**Objective**: Document workflow for APT-grade mobile exploit research.

**Remediation**: If sample unavailable, work with public writeup and analyze representative JBIG2 parser.

**Pass Criteria**: Full exploit chain written up; key primitives (stack overflow, kernel R/W) identified.

---

## TC-RE-026 — Stuxnet PLC-block analysis

**Severity**: High

**Prerequisite**: Stuxnet sample (or representative 4140d0 binary); Symantec W32.Stuxnet Dossier reference; IDA Pro.

**Test Step**:
```text
1. Identify PLC 417/415 block injection code
2. Locate CP 313 / CP 315 attack code
3. Decompile DB 8080 / DB 8081 injection routines
4. Document RC5 key schedule and C2 protocol
5. Map to MITRE ATT&CK T0853 / T0859 / T0886
```

**Expected Result**: PLC injection mechanism documented; C2 protocol decoded; RC5 key recovered.

**Objective**: Demonstrate ICS-focused RE workflow.

**Remediation**: Cross-reference with RUNG/S7 project file format.

**Pass Criteria**: Full write-up of PLC attack chain; IOCs disseminated.

---

## TC-RE-027 — Custom unpacking of multi-layer packer

**Severity**: High

**Prerequisite**: Sample packed with 3+ layers (e.g., UPX inside VMProtect inside custom); x64dbg; debugger scripts.

**Test Step**:
```text
1. Layer 1 (custom): Set hardware breakpoint on VirtualAlloc; dump when called
2. Layer 2 (VMProtect): Use VMPAttack or virtualized handler trace
3. Layer 3 (UPX): Standard upx -d on layer 2 output
4. Verify final entropy <7.0 across all sections
```

**Expected Result**: Original unpacked binary recovered after 3 layers.

**Objective**: Demonstrate multi-stage unpacking workflow.

**Remediation**: If VMProtect devirtualization fails, fall back to memory dump post-OEP.

**Pass Criteria**: Final binary runs without packer; entropy normal.

---

## TC-RE-028 — Memory dump analysis for fileless malware

**Severity**: High

**Prerequisite**: Volatility 3; memory dump from infected machine; PID of suspected hollowed process.

**Test Step**:
```bash
vol -f memory.dmp windows.malfind --pid 1234
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.dlllist --pid 1234
vol -f memory.dmp windows.netscan
# Extract injected shellcode
vol -f memory.dmp windows.malfind --pid 1234 --dump
```

**Expected Result**: `malfind` reports injected regions; shellcode dumped for offline analysis.

**Objective**: RE fileless malware via memory forensics.

**Remediation**: If `malfind` empty, try `windows.hollowprocess` plugin.

**Pass Criteria**: ≥1 injected region identified; shellcode disassembled.

---

## TC-RE-029 — Automated RE pipeline (CI/CD)

**Severity**: Medium

**Prerequisite**: angr, ghidra, pefile installed; sample repository; CI runner (GitHub Actions / GitLab CI).

**Test Step**:
```yaml
# .github/workflows/re-pipeline.yml
name: RE Pipeline
on: [push]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with: { python-version: '3.11' }
      - name: Install tools
        run: pip install angr pefile yara-python
      - name: Run pipeline
        run: python3 re_pipeline.py samples/
```

**Expected Result**: Each sample produces `report.json` with hash, strings, imports, entropy, and angr result.

**Objective**: Scale RE analysis across many samples.

**Remediation**: If angr timeout, set per-sample timeout to 300s.

**Pass Criteria**: Pipeline produces 1 report per sample; ≥90% samples analyzed without error.

---

## TC-RE-030 — Mirai ELF variant analysis

**Severity**: Medium

**Prerequisite**: Mirai ELF sample (or representative bot binary); Ghidra + IDA Pro; MIPS cross-references.

**Test Step**:
```bash
file mirai.elf
# MIPS big-endian?
ghidraRun mirai.elf
# Identify:
# 1. Credential brute force table
# 2. C2 protocol (typically TCP/23 or TCP/48101)
# 3. Infection routine (telnet exploit)
```

**Expected Result**: Mirai credential list extracted; C2 protocol documented.

**Objective**: Demonstrate ELF + MIPS RE workflow.

**Remediation**: If strings are obfuscated, brute XOR with common keys (0x00-0xFF, then 2-byte).

**Pass Criteria**: ≥50% credential table extracted; C2 server IP identified.

---

## TC-RE-031 — BlackCat/ALPHV Rust binary analysis

**Severity**: High

**Prerequisite**: BlackCat sample (Rust); IDA Pro with Rust demangler; Ghidra.

**Test Step**:
```bash
# Rust demangler for IDA
# https://github.com/idapython/src/blob/master/examples/idapython/rust_demangle.py

# Identify:
# 1. Encryption routine (ChaCha20 + Curve25519)
# 2. Affinity check (avoid Russian / Ukrainian locales)
# 3. Shadow copy deletion via vssadmin
# 4. Persistence (Run keys)
```

**Expected Result**: Encryption key generation documented; locale check bypassed; recovery workflow tested.

**Objective**: Demonstrate Rust binary RE workflow for modern ransomware.

**Remediation**: If Rust demangler fails, manually map mangled names.

**Pass Criteria**: ≥3 IOCs documented; ≥1 decryptor theory validated.

---

## TC-RE-032 — Cobalt Strike beacon configuration extraction

**Severity**: High

**Prerequisite**: Cobalt Strike beacon (stage or shellcode); `1768.py` parser (Didier Stevens); IDA Pro.

**Test Step**:
```bash
python3 1768.py beacon.bin
# Output: config sections (Setting 0..56)
# Decode: C2 server, port, user-agent, kill date
```

**Expected Result**: Full beacon config decoded; C2 server and watermark identified.

**Objective**: Validate CS beacon analysis workflow.

**Remediation**: If config is encrypted, locate decryption key via XOR brute force or analyze stager.

**Pass Criteria**: ≥80% config settings decoded.

---

## TC-RE-033 — APT41 DNS tunneling binary protocol reverse

**Severity**: High

**Prerequisite**: Sample suspected of DNS-based C2; wireshark + IDA Pro; ≥500 captured DNS packets.

**Test Step**:
```bash
tshark -i any -Y "dns.qry.name contains .evil.com" -T fields -e dns.qry.name > queries.txt

# Identify encoding (base32, base64, hex)
# In IDA, locate DNS query construction function
# Document protocol: header format, encoding scheme, frequency
```

**Expected Result**: DNS tunneling protocol documented; encoding identified; C2 commands decoded.

**Objective**: Demonstrate protocol RE for stealthy C2.

**Remediation**: If encoding unknown, try frequency analysis (hex = 16 chars, base32 = 32, base64 = 64).

**Pass Criteria**: ≥3 captured commands decoded end-to-end.

---

## TC-RE-034 — Cisco router firmware analysis

**Severity**: High

**Prerequisite**: Cisco IOS firmware image; binwalk; Ghidra (PowerPC / MIPS support).

**Test Step**:
```bash
binwalk -e ios_image.bin
cd _ios_image.bin.extracted/
# Locate IOS loader
file *
# Analyze ELF section in Ghidra (PowerPC)
ghidraRun _ios_image.bin.extracted/ios.elf
```

**Expected Result**: IOS kernel binary located; commands reference table identified; privilege escalation paths mapped.

**Objective**: Demonstrate network device firmware RE.

**Remediation**: If ELF doesn't load, check endianness (Cisco IOS = big-endian PowerPC).

**Pass Criteria**: ≥1 IOS subsystem documented; ≥1 vulnerability candidate identified.

---

## TC-RE-035 — Anti-analysis technique cataloging

**Severity**: Medium

**Prerequisite**: Sample with multiple anti-debug / anti-VM; x64dbg with ScyllaHide; VM with spoofed artifacts.

**Test Step**:
```text
1. Run under x64dbg with ScyllaHide default
2. Catalog failure points:
   - IsDebuggerPresent
   - NtQueryInformationProcess (ProcessDebugPort)
   - CPUID (hypervisor bit)
   - RDTSC timing
   - Mutex / file existence checks
3. For each, document bypass:
   - ScyllaHide hook
   - Manual patch (NOP / EAX = 0)
   - Environment spoofing
```

**Expected Result**: All anti-analysis techniques catalogued; bypasses verified.

**Objective**: Build comprehensive anti-analysis evasion profile.

**Remediation**: If ScyllaHide misses, write custom IDA Python patches.

**Pass Criteria**: Sample executes in lab without premature exit; all checks bypassed.

---

## TC-RE-036 — Packer identification via DiE / PEiD

**Severity**: Low

**Prerequisite**: Detect It Easy (DiE) or PEiD installed; sample binary.

**Test Step**:
```bash
die sample.exe
# Or
peid sample.exe
```

**Expected Result**: Packer / compiler identified with version (e.g., "VMProtect 3.x", "UPX 4.0", "MSVC 19.29").

**Objective**: Triage-time packer identification.

**Remediation**: If unidentified, check entropy and section names manually.

**Pass Criteria**: ≥1 packer/compiler signature matched.

---

## TC-RE-037 — Symbolic execution path coverage report

**Severity**: Medium

**Prerequisite**: angr + angr-management; sample with multiple branches.

**Test Step**:
```python
import angr

proj = angr.Project('./sample', auto_load_libs=False)
state = proj.factory.entry_state()
sm = proj.factory.simulation_manager(state)
sm.explore()

# Coverage report
total = len(proj.factory.entry_state().block().vex.constant_jump_targets)
explored = len(sm.active) + len(sm.deadended) + len(sm.found)
print(f'Coverage: {explored/total*100:.1f}%')
```

**Expected Result**: Coverage report generated; dead-ended paths counted.

**Objective**: Quantify symbolic execution effectiveness.

**Remediation**: If coverage <30%, increase exploration time or remove stale avoid constraints.

**Pass Criteria**: ≥40% block coverage within 5 minutes.

---

## TC-RE-038 — YARA rule for malware family detection

**Severity**: High

**Prerequisite**: `yara-python`; sample family with unique strings or code patterns.

**Test Step**:
```yara
rule APT41_DNS_Tunnel {
    meta:
        author = "redteam"
        date = "2026-06-28"
        description = "APT41 DNS tunneling implant"
    strings:
        $s1 = "tunnel.evil.com" wide ascii
        $s2 = { 8B 45 ?? 83 C4 04 50 FF 15 ?? ?? ?? ?? }
        $api1 = "DnsQuery_A"
    condition:
        uint16(0) == 0x5A4D and
        2 of ($s*) and
        $api1
}

yara -r rule.yar corpus/
```

**Expected Result**: Rule matches ≥1 sample in corpus with 0 false positives.

**Objective**: Validate detection rule quality.

**Remediation**: If FP rate high, add `and filesize < 1MB` constraint or tighten string count.

**Pass Criteria**: Detection rate 100% on samples; FP rate 0% on benign corpus.

---

## TC-RE-039 — Engagement report generation

**Severity**: Medium

**Prerequisite**: All upstream RE artifacts (triage, decompile, IOCs, MITRE mapping).

**Test Step**:
```bash
# Compose final report
cat <<EOF > report.md
# RE Engagement Report — Sample SHA256: <hash>

## Executive Summary
<one-paragraph finding>

## File Details
- Hash: <hash>
- Type: <type>
- Compiler: <compiler>

## Static Analysis
- Imports: <list>
- Strings of interest: <list>

## Dynamic Analysis
- API trace: <key APIs>
- Network IOCs: <IPs, domains>

## Decompile Findings
- Key routines: <functions>

## MITRE ATT&CK Mapping
- Txxxx — Technique

## Detection
- YARA rules: <rules>
- Sigma rules: <rules>

## Recommendations
<patching / detection guidance>
EOF
```

**Expected Result**: Complete engagement report with all sections populated.

**Objective**: Validate RE reporting workflow.

**Remediation**: Use report-template.md from engagement-template directory.

**Pass Criteria**: All sections populated; SOC handoff package attached.

---

## TC-RE-040 — Time budget tracking per sample type

**Severity**: Low

**Prerequisite**: Multiple sample types (unpacked, UPX, VMProtect, Themida, custom packer, firmware).

**Test Step**:
```text
For each sample type, log:
- Triage time
- Static analysis time
- Unpacking time
- Dynamic analysis time
- Decompile time
- Report time
- Total engagement time

Compare against baseline:
- Unpacked simple: 4h total
- UPX: 1 day total
- VMProtect: 2 days
- Themida: 3 days
- Custom packer: 2 days
- Firmware: 5 days
- APT multi-stage: 7+ days
```

**Expected Result**: Time logs within ±20% of baseline estimates.

**Objective**: Validate engagement estimation accuracy.

**Remediation**: If consistently over baseline, review workflow for bottlenecks.

**Pass Criteria**: Actual time within ±20% of baseline for ≥80% of engagements.

---

## Test Coverage Matrix

| Category | Cases | ID Range |
|----------|-------|----------|
| Static Triage | 1 | TC-RE-001 |
| Symbolic Execution (angr / KLEE / manticore) | 4 | TC-RE-002 to TC-RE-004, TC-RE-037 |
| Unpacking (UPX / Custom / Multi-layer) | 3 | TC-RE-006, TC-RE-007, TC-RE-027 |
| Binary Diffing (BinDiff / Diaphora / Kam1n0) | 3 | TC-RE-005, TC-RE-016, TC-RE-021 |
| Firmware Analysis (binwalk / FACT / EMBA / Cisco) | 4 | TC-RE-008, TC-RE-009, TC-RE-010, TC-RE-034 |
| OLLVM Deobfuscation (CFF / BCF / SUB) | 3 | TC-RE-011, TC-RE-012, TC-RE-013 |
| Decompiler Confusion & Decompilation | 3 | TC-RE-015, TC-RE-023, TC-RE-026 |
| SMT-assisted Analysis (Z3) | 1 | TC-RE-014 |
| Tool-specific Workflows (IDA / BN / r2 / Ghidra) | 4 | TC-RE-017, TC-RE-018, TC-RE-019, TC-RE-020 |
| Crypto Identification | 1 | TC-RE-022 |
| APT-grade Analysis (Equation / Pegasus / Stuxnet / APT41) | 4 | TC-RE-024, TC-RE-025, TC-RE-026, TC-RE-033 |
| Threat Actor Tooling (Mirai / BlackCat / Cobalt Strike) | 3 | TC-RE-030, TC-RE-031, TC-RE-032 |
| Anti-analysis Bypass | 2 | TC-RE-028, TC-RE-035 |
| Detection (YARA) | 1 | TC-RE-038 |
| Packer ID (DiE / PEiD) | 1 | TC-RE-036 |
| Pipeline / Automation | 1 | TC-RE-029 |
| Reporting & Time Budget | 2 | TC-RE-039, TC-RE-040 |

**Total**: 40 test cases (TC-RE-001 to TC-RE-040)

---

## References

- MITRE ATT&CK Defense Evasion — https://attack.mitre.org/tactics/TA0005/
- "Practical Reverse Engineering" (Bruce Dang, 2014)
- "The IDA Pro Book" (Chris Eagle, 2nd Edition)
- "Ghidra Software Reverse Engineering" (Chris Eagle, Kara Nance, 2020)
- angr documentation — https://docs.angr.io/
- KLEE documentation — https://klee.github.io/
- Manticore documentation — https://github.com/trailofbits/manticore
- Ghidra documentation — https://ghidra-sre.org/
- BinDiff — https://www.zynamics.com/bindiff.html
- Diaphora — https://github.com/joxeankoret/diaphora
- Kam1n0 — https://github.com/McGill-DMaS/Kam1n0
- FACT — https://github.com/fkie-cad/FACT_core
- EMBA — https://github.com/e-m-b-a/emba
- OLLVM — https://github.com/obfuscator-llvm/obfuscator
- deflat — https://github.com/cd70s062f/deflat
- Z3 — https://github.com/Z3Prover/z3
- "Sandbox Evasion Techniques" (SANS 2024)
- "VMProtect Devirtualization" (BlackHat 2023)
- "Pegasus RE" (Citizen Lab, 2016, 2021, 2024)
- "Equation Group" (Kaspersky, 2015)
- "Stuxnet Dossier" (Symantec, 2011)
- "APT41" (FireEye/Mandiant, 2019-2024)
- "BlackCat/ALPHV" (Cisco Talos, 2023)
- "Mirai" (MalwareMustDie, 2016)
