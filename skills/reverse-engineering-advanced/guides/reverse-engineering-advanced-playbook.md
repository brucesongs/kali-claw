# Reverse Engineering Advanced Playbook

> Operator's playbook for advanced reverse engineering. Covers symbolic execution (angr, KLEE, manticore), binary diffing (BinDiff, Diaphora, Kam1n0), firmware RE workflow (binwalk, FACT, EMBA), OLLVM deobfuscation, and SMT-assisted key recovery. Target audience: experienced reverse engineers already familiar with PE / ELF formats, x86/x64 / ARM / MIPS assembly, and foundational RE techniques.

## Overview and Purpose

This playbook provides a structured methodology for advanced reverse engineering beyond foundational disassembly. It walks analysts through static triage, symbolic execution, binary diffing, firmware analysis, OLLVM deobfuscation, decompiler confusion handling, SMT-assisted key recovery, variant analysis, and automated RE pipeline construction. The objective is to produce a complete analysis report with decompiled code, IOCs, MITRE ATT&CK mapping, YARA detection rules, and Sigma rules for SOC handoff. The playbook is hands-on: every section includes commands and techniques validated against modern APT-grade samples (Equation Group REGIN, Pegasus FORCEDENTRY, Stuxnet, OLLVM-protected crackmes, Mirai variants, BlackCat Rust binaries). Use this as a step-by-step reference for your next advanced RE engagement.

## 1. Engagement Scoping

### 1.1 Confirm scope

| Item | Detail |
|------|--------|
| Sample source | Customer / threat intel / honeypot / APT research |
| Sample type | PE / ELF / Mach-O / firmware / smart contract |
| Analysis depth | Triage / static / dynamic / full RE |
| Lab environment | Isolated VM (Cuckoo / Joe) / bare metal / network isolation |
| Time window | 4h (unpacked) → 7d (APT multi-stage) |
| Output | Report + decompilation + IOCs + YARA + Sigma |
| Disclosure policy | Vendor disclosure / 90-day / NDA |

### 1.2 Rules of engagement

- **No internet egress from analysis VM** — isolated network only
- **No real customer data** — use synthetic samples
- **Containment** — sample must not escape lab
- **Document all activity** for audit trail
- **Coordinate with SOC** for IOC dissemination
- **Vendor disclosure process** followed for 0-day discoveries

### 1.3 Test boundaries

- Allowed: static analysis in isolated environment
- Allowed: dynamic analysis in sandboxed VM with snapshots
- Disallowed: detonation on production network
- Disallowed: shipping sample to external services without permission

## 2. Pre-Analysis Recon

### 2.1 Lab setup verification

```bash
# Verify isolated network
ping -c 1 8.8.8.8  # Should fail

# Verify snapshot
virsh snapshot-list re-lab

# Verify monitoring
which tcpdump process-monitor procmon
```

### 2.2 Tool inventory check

```bash
# Symbolic execution
pip list | grep -E "angr|manticore|z3"

# Disassemblers
which ida ghidra radare2 binary-ninja

# Firmware
which binwalk
ls /opt/FACT_core
ls /opt/emba

# Binary diffing
which bindiff
ls /opt/diaphora
```

## 3. Lab Setup

### 3.1 angr install

```bash
pip install angr
# Verify
python3 -c "import angr; print(angr.__version__)"
```

### 3.2 KLEE install

```bash
# KLEE requires LLVM 11+
sudo apt install llvm-11 llvm-11-dev libsqlite3-dev libz3-dev
git clone https://github.com/klee/klee
cd klee
mkdir build && cd build
cmake -DENABLE_SOLVER_STP=ON -DENABLE_SOLVER_Z3=ON ..
make -j$(nproc)
sudo make install
```

### 3.3 Manticore install

```bash
pip install manticore
# Verify smart contract analysis
manticore --help
```

### 3.4 Ghidra install

```bash
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip
unzip ghidra_11.0_PUBLIC_20231222.zip
cd ghidra_11.0_PUBLIC
./ghidraRun
```

### 3.5 BinDiff install

```bash
# Download BinDiff 8 from https://github.com/google/bindiff/releases
# Linux: bindiff_8.0.0_amd64.deb
sudo dpkg -i bindiff_8.0.0_amd64.deb

# Verify
bindiff --help
```

### 3.6 EMBA install

```bash
git clone https://github.com/e-m-b-a/emba
cd emba
sudo ./installer.sh
```

### 3.7 FACT install

```bash
git clone https://github.com/fkie-cad/FACT_core
cd FACT_core
./install
# Start
docker compose up -d
```

## 4. Analysis Workflow — Stage by Stage

### Stage 1 — Triage (1 hour)

**Goal**: classify sample, identify packer, plan analysis.

```bash
sha256sum sample
file sample
strings -a sample | head -20

python3 -c "
import pefile, math
pe = pefile.PE('sample.exe')
for s in pe.sections:
    name = s.Name.decode().rstrip(chr(0))
    ent = s.get_entropy()
    flag = 'PACKED' if ent > 7.0 else 'NORMAL'
    print(f'{name:12s} entropy={ent:.2f} {flag}')
"

# Packer ID
die sample.exe
```

**Output**: `triage.md` with hash, type, packer ID.

### Stage 2 — Symbolic execution with angr (4 hours)

```python
import angr

proj = angr.Project('./crackme', auto_load_libs=False)
state = proj.factory.entry_state()

sm = proj.factory.simulation_manager(state)
sm.explore(find=lambda s: b'Good boy' in s.posix.dumps(1),
          avoid=lambda s: b'Bad boy' in s.posix.dumps(1))

if sm.found:
    found = sm.found[0]
    print(f"Solution: {found.posix.dumps(0)}")
else:
    print("No solution found — try larger stdin length or relax avoid")
```

**Output**: `symbolic.md` with solution or path explosion report.

### Stage 3 — Binary diffing (1 day, if variant)

```bash
# BinDiff
bindiff --binary1=v1.exe --binary2=v2.exe --output_dir=diffs/

# Diaphora
# 1. Open v1.exe in IDA → Export with Diaphora → v1.sqlite
# 2. Open v2.exe → Diff against v1.sqlite
# 3. Review "Best Match", "Partial Match" tabs
```

**Output**: `diff.md` with changed functions and CVE analysis.

### Stage 4 — Firmware analysis (1-2 days, if firmware)

```bash
# Binwalk
binwalk firmware.bin
binwalk -e firmware.bin
ls _firmware.bin.extracted/

# FACT
curl -X POST -F "file=@firmware.bin" http://localhost:5000/ajax/upload

# EMBA
sudo /opt/emba/emba -l /logs/fw -f firmware.bin
```

**Output**: `firmware.md` with extracted filesystem, CVE list, vulnerable binaries.

### Stage 5 — OLLVM deobfuscation (1 day, if obfuscated)

```bash
# Control Flow Flattening — deflat
python3 deflat.py --binary flattened.exe --dispatcher 0x401000

# Bogus Control Flow — d810 plugin for IDA
# https://gitlab.com/eshard/d810

# Instruction Substitution — miasm simplifier
python3 simplify.py --input sample.exe
```

**Output**: `deobfuscation.md` with original logic recovered.

### Stage 6 — Decompiler confusion handling (4 hours)

```python
# IDA Python — detect and patch anti-decompiler patterns
import idautils, idc

for func_ea in idautils.Functions():
    for ea in idautils.FuncItems(func_ea):
        # Detect JE+0 / JNE-1 anti-disassembly
        mnem = idc.print_insn_mnem(ea)
        if mnem in ('je', 'jne'):
            target = idc.get_operand_value(ea, 0)
            next_ea = idc.next_head(ea)
            if target == next_ea:
                # NOP-out the branch
                idc.patch_byte(ea, 0x90)
```

**Output**: `decompile.md` with patched binary + readable decompile output.

### Stage 7 — SMT-assisted key recovery (4 hours)

```python
from z3 import *

s = Solver()
key = [BitVec(f'k_{i}', 8) for i in range(16)]

# Printable range
for i in range(16):
    s.add(key[i] >= 0x20, key[i] <= 0x7e)

# Constraints extracted from disassembly
s.add(key[0] + key[1] == 0x90)
s.add(key[2] * key[3] == 0x41A8)
# ...

if s.check() == sat:
    m = s.model()
    print("Key:", bytes(m[k].as_long() for k in key))
```

**Output**: `key.md` with recovered key.

### Stage 8 — Variant analysis (4 hours)

```bash
# Kam1n0 — cluster samples
kam1n0 index -i samples/ -o index.db
kam1n0 cluster -i index.db -o clusters.json

# BinDiff — pairwise
for s1 in samples/*; do
    for s2 in samples/*; do
        [ "$s1" = "$s2" ] && continue
        bindiff --binary1=$s1 --binary2=$s2 --output_dir=diffs/$(basename $s1)_$(basename $s2)
    done
done
```

**Output**: `variant.md` with family clusters.

### Stage 9 — IDA / Ghidra deep dive (1 day)

```python
# IDA Python — extract suspicious API calls
import idautils, idc, ida_hexrays

suspicious = ['WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread']

for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    if name in suspicious:
        for xref in idautils.XrefsTo(func_ea):
            print(f"Call to {name} at {hex(xref.frm)}")
            cf = ida_hexrays.decompile(xref.frm)
            if cf:
                print(cf)
```

**Output**: `re_report.md` with annotated decompile.

### Stage 10 — Reporting (1 day)

Produce final report:

- Executive summary
- File details (hash, type, compiler)
- Static analysis (imports, strings)
- Dynamic analysis (API trace, network)
- Symbolic execution results
- Decompile output
- Variant analysis
- IOCs (hashes, URLs, mutexes)
- MITRE ATT&CK mapping
- YARA rules
- Sigma rules
- Detection recommendations

## 5. Common Pitfalls

### 5.1 Path explosion in angr

Complex binaries trigger state explosion, making symbolic execution intractable.

**Fix**: Constrain stdin length; use `avoid` aggressively; switch from BFS to DFS via `sm.use_tech(angr.exploration_techniques.DFS())`.

### 5.2 BinDiff match rate <70%

BinDiff may miss functions due to compiler optimization differences.

**Fix**: Run with `--algo_suffix=true`; cross-check with Diaphora multi-algorithm mode.

### 5.3 Firmware extraction fails (encrypted)

Firmware images are often encrypted with AES + per-vendor key.

**Fix**: Identify key via JTAG extraction, vendor leak, or known plaintext attack on header.

### 5.4 OLLVM deflat produces wrong output

Wrong dispatcher address leads to broken binaries.

**Fix**: Validate dispatcher by dynamic tracing — set breakpoint on suspected dispatcher, confirm execution hits.

### 5.5 SMT solver returns unsat

Constraint extraction has a bug (off-by-one, signed/unsigned mismatch).

**Fix**: Re-derive constraints from disassembly; use `s.unsat_core()` to identify conflicting assertions.

### 5.6 Decompiler produces garbage output

Anti-decompiler patterns or aggressive optimization confuse Hex-Rays / Ghidra.

**Fix**: Manually patch anti-decompiler patterns (TC-RE-015); fall back to assembly reading.

### 5.7 Kam1n0 clusters noisy

Threshold too low — benign samples cluster with malware.

**Fix**: Raise `--similarity-threshold` to 0.8; cross-reference clusters with VT.

### 5.8 APT sample too complex for full RE

Multi-stage samples with VM-based obfuscation (VMProtect, Themida VM) cannot be fully RE'd in time budget.

**Fix**: Focus on stage 1 (loader) and stage N (impact); use memory forensics for middle stages.

## 6. Time Budget Cheat Sheet

| Sample complexity | Triage | Symbolic | Diff | Firmware | Deobfusc | Decompile | Report |
|-------------------|--------|----------|------|----------|----------|-----------|--------|
| Unpacked simple | 30m | 2h | n/a | n/a | 0h | 2h | 4h |
| Crackme (CTF) | 30m | 1h | n/a | n/a | 0h | 1h | 1h |
| UPX packed | 30m | 2h | n/a | n/a | 0h | 2h | 1d |
| VMProtect | 1h | 4h | n/a | n/a | 0h | 1d | 2d |
| Themida VM | 1h | 4h | n/a | n/a | 0h | 2d | 3d |
| Custom packer | 1h | 4h | n/a | n/a | 0h | 1d | 2d |
| OLLVM obfuscated | 1h | 4h | n/a | n/a | 1d | 1d | 2d |
| Firmware (IoT) | 1h | n/a | n/a | 1d | 0h | 1d | 3d |
| Firmware (router) | 1h | n/a | n/a | 2d | 0h | 1d | 4d |
| APT multi-stage | 1d | 1d | 4h | n/a | 1d | 2d | 7d |
| 1-day patch diff | 30m | n/a | 4h | n/a | 0h | 4h | 1d |

## 7. Tool Inventory

### 7.1 Symbolic execution

| Tool | Best for | Limitations |
|------|----------|-------------|
| angr | CTF, crackmes, key recovery | Path explosion on complex binaries |
| KLEE | Linux / LLVM binaries | Limited Windows support |
| manticore | Smart contracts, lightweight binaries | Slower than angr |
| S2E | Full-system symbolic | Heavy setup, complex |

### 7.2 Disassemblers

| Tool | License | Strength |
|------|---------|----------|
| IDA Pro | Commercial | Industry standard, Hex-Rays decompiler |
| Ghidra | Open source (NSA) | Free, full-featured, scriptable |
| Binary Ninja | Commercial | Modern API, IL |
| radare2 | Open source | Lightweight, scripting |

### 7.3 Binary diffing

| Tool | Algorithm | Cost |
|------|-----------|------|
| BinDiff | Graph isomorphism | Commercial (Zynamics) |
| Diaphora | Multiple algorithms | Free (IDA plugin) |
| Kam1n0 | Assembly clustering | Free (academic) |
| patchkit | Function similarity | Free |

### 7.4 Firmware analysis

| Tool | Purpose |
|------|---------|
| binwalk | Initial scan + extraction |
| FACT | Full firmware analysis |
| EMBA | Automated vulnerability scan |
| firmware-mod-kit | Filesystem repack |

### 7.5 Decompilers

| Tool | Output | Notes |
|------|--------|-------|
| Hex-Rays | C-like | Best commercial option |
| Ghidra decompiler | C-like | Free, integrated |
| Binary Ninja IL | IL | Strong for analysis |
| snowman-decompiler | C-like | Open source |
| retdec | C-like | Avast open source |

### 7.6 Deobfuscation

| Tool | Targets |
|------|---------|
| deflat | OLLVM CFF |
| d810 | OLLVM BCF, SUB |
| miasm | Instruction simplification |
| IDA-deobfuscator | Various patterns |

## 8. Engagement Quality Checklist

Before reporting complete:

- [ ] Sample hash + VT lookup
- [ ] File type + PE / ELF analysis
- [ ] Packer / compiler identified
- [ ] Sample unpacked (if applicable)
- [ ] Static strings categorized
- [ ] Symbolic execution attempted (if applicable)
- [ ] Binary diffing performed (if variant)
- [ ] Firmware extraction (if firmware)
- [ ] Deobfuscation applied (if obfuscated)
- [ ] Decompile output saved
- [ ] SMT-assisted analysis (if key recovery)
- [ ] Variant analysis (if family)
- [ ] IOCs documented
- [ ] MITRE ATT&CK mapping
- [ ] YARA rule authored + validated
- [ ] Sigma rule authored
- [ ] Final report delivered
- [ ] SOC handoff (detection rules)

## 9. References

- MITRE ATT&CK Defense Evasion — https://attack.mitre.org/tactics/TA0005/
- "Practical Reverse Engineering" (Bruce Dang, 2014)
- "The IDA Pro Book" (Chris Eagle, 2nd Edition)
- "Ghidra Software Reverse Engineering" (Chris Eagle, Kara Nance, 2020)
- angr documentation — https://docs.angr.io/
- KLEE documentation — https://klee.github.io/
- Manticore — https://github.com/trailofbits/manticore
- Ghidra documentation — https://ghidra-sre.org/
- BinDiff — https://www.zynamics.com/bindiff.html
- Diaphora — https://github.com/joxeankoret/diaphora
- Kam1n0 — https://github.com/McGill-DMaS/Kam1n0
- FACT — https://github.com/fkie-cad/FACT_core
- EMBA — https://github.com/e-m-b-a/emba
- OLLVM — https://github.com/obfuscator-llvm/obfuscator
- deflat — https://github.com/cd70s062f/deflat
- Z3 — https://github.com/Z3Prover/z3
- "Symbolic Execution for Software Testing" (Cadar, Sen, 2013)
- "OLLVM Deobfuscation" (RolfRolles, 2016)
- "Defeating OLLVM" (Quarkslab, 2019)
- "Pegasus RE" (Citizen Lab, 2016, 2021, 2024)
- "Equation Group" (Kaspersky, 2015)
- BlackHat USA 2023 — "Advanced RE Techniques"
- "Firmware RE" (Firmware Sltp)
