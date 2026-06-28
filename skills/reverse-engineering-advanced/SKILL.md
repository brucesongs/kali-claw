---
name: reverse-engineering-advanced
description: Advanced reverse engineering covering symbolic execution (angr, KLEE, manticore), decompiler confusion (Hex-Rays, Ghidra deobfuscation), binary diffing (BinDiff, Diaphora, Kam1n0), firmware RE workflow (binwalk, FACT, EMBA), and obfuscated code analysis (LLVM obfuscation, OLLVM, Tigress). Distinct from foundational `binary-reverse` — focuses on advanced program analysis, automated RE techniques, and firmware / obfuscation workflows. Use when analyzing obfuscated or packed binaries, automating RE pipelines, analyzing firmware, or studying APT-grade obfuscation (Equation Group, Pegasus).
origin: kali-claw
version: 0.1.42
compatibility:
  - kali-linux-2025-2-arm64
  - python-3.11+
  - angr-9.2+
  - ghidra-11.0+
  - ida-9.0+
  - binary-ninja-5.0+
  - radare2-5.8+
  - binwalk-3.0+
  - bindiff-8.0+
allowed-tools:
  - angr
  - klee
  - manticore
  - ghidra
  - ida
  - binary-ninja
  - radare2
  - binwalk
  - bindiff
  - diaphora
  - kam1n0
  - fact-core
  - emba
  - ollvm-tools
  - deflat
  - snowman-decompiler
  - retdec
  - imhex
  - pe-tree
  - ida-deobfuscator
  - ghidra-deobfuscator
metadata:
  domain: reverse-engineering
  tool_count: 20
  guide_count: 2
  mitre: "TA0005-Defense Evasion, T1027-Obfuscated Files, T1027.002-Binary Padding, T1027.010-Command Obfuscation, T1140-Deobfuscate/Decode"
---

# Reverse Engineering Advanced

## Summary

Advanced reverse engineering is the discipline of analyzing obfuscated, packed, or firmware binaries using automated program analysis: symbolic execution (angr, KLEE, manticore) for path exploration, decompiler confusion techniques (Hex-Rays deobfuscation, Ghidra script automation), binary diffing (BinDiff, Diaphora, Kam1n0) for variant analysis, firmware RE workflow (binwalk, FACT, EMBA) for embedded device analysis, and obfuscated code analysis (LLVM obfuscation, OLLVM, Tigress). This domain covers modern program-analysis techniques that scale beyond manual reverse engineering, with industry-standard tooling workflows. Distinct from foundational `binary-reverse` (which covers basic radare2 / Ghidra introduction) — this skill focuses on advanced program analysis, automated RE pipelines, and firmware / obfuscation workflows.

## Key Terms

- **Symbolic execution** — Program analysis technique that explores all paths via symbolic variables
- **SMT solver** — Satisfiability Modulo Theories solver (Z3) used by symbolic execution
- **Concolic execution** — Concrete + symbolic execution (manticore, angr)
- **Decompiler confusion** — Code patterns that confuse Hex-Rays / Ghidra decompilers
- **Binary diffing** — Comparing two binaries to identify changes (BinDiff, Diaphora)
- **Control Flow Flattening (CFF)** — OLLVM obfuscation that flattens control flow
- **Bogus Control Flow (BCF)** — OLLVM obfuscation that adds fake branches
- **Instruction Substitution (SUB)** — OLLVM obfuscation that replaces operations
- **Firmware RE** — Reverse engineering embedded device firmware (routers, IoT, OT)
- **Unpacker** — Tool that recovers original code from packed binary
- **CFG** — Control Flow Graph
- **AST** — Abstract Syntax Tree
- **IR** — Intermediate Representation (used by angr, Ghidra)
- **VEX IR** — angr's intermediate representation
- **P-code** — Ghidra's intermediate representation

## Scope

This skill covers **advanced reverse engineering**:
- Symbolic execution (angr / KLEE / manticore) for path exploration + key recovery
- Binary diffing (BinDiff / Diaphora / Kam1n0) for variant analysis
- Firmware RE workflow (binwalk / FACT / EMBA)
- Obfuscated code analysis (LLVM / OLLVM / Tigress)
- Decompiler confusion + deobfuscation
- APT-grade analysis (Equation Group, Pegasus)

**Out of scope**: foundational RE (see `binary-reverse`), malware analysis workflow (see `malware-analysis-advanced`), exploit development (see `exploit-development`).

## Use Cases

- **Symbolic execution for key validation**: Recover algorithm via SMT solving
- **Binary diffing for patch analysis**: Identify CVE patches + 1-day exploitation
- **Firmware RE for routers / IoT**: Extract filesystem + analyze embedded services
- **OLLVM deobfuscation**: Defeat Control Flow Flattening + Bogus Control Flow
- **Decompiler-resistant code analysis**: Manual disassembly when decompiler fails
- **Variant analysis**: Identify family of malware / binaries via diffing
- **SMT-assisted key recovery**: Recover cryptographic keys via Z3
- **Automated RE pipeline**: Build CI/CD for binary analysis
- **Equation Group / Pegasus analysis**: APT-grade obfuscation research
- **Embedded device security**: Audit router / IoT / OT firmware

## Core Tools

| Tool | Purpose |
|------|---------|
| `angr` | Python symbolic execution framework |
| `KLEE` | LLVM-based symbolic execution |
| `manticore` | Symbolic execution (Trail of Bits) |
| `Ghidra` | NSA open-source RE tool |
| `IDA Pro` | Industry-standard disassembler + decompiler |
| `Binary Ninja` | Modern disassembler with rich API |
| `radare2` | Open-source disassembler |
| `binwalk` | Firmware analysis tool |
| `BinDiff` | Binary diffing (Google/Zynamics) |
| `Diaphora` | Free BinDiff alternative (IDA plugin) |
| `Kam1n0` | Binary similarity (assembly) |
| `FACT` | Firmware Analysis Compare Tool |
| `EMBA` | Embedded firmware analyzer |
| `ollvm-tools` | OLLVM deobfuscation tools |
| `deflat` | Control Flow Flattening deobfuscation |
| `snowman-decompiler` | Open-source decompiler |
| `retdec` | Avast open-source decompiler |
| `imhex` | Modern hex editor |
| `pe-tree` | Visual PE analysis |
| `ida-deobfuscator` | IDA plugin for deobfuscation |

## Methodology

### Phase 1 — Static triage

```bash
file binary
sha256sum binary
strings binary | head -20

# Architecture
file binary

# Imported functions
nm -D binary 2>/dev/null | head
readelf -d binary 2>/dev/null | head

# Section entropy (packed indicator)
python3 -c "
import sys
with open('binary', 'rb') as f:
    data = f.read()
import math
entropy = -sum((data.count(b)/len(data)) * math.log2(data.count(b)/len(data)) for b in set(data))
print(f'Entropy: {entropy:.2f}')
"
```

### Phase 2 — Binary diffing

```bash
# BinDiff (Google)
bindiff --binary1=v1.exe --binary2=v2.exe --output_dir=diffs/

# Diaphora (IDA plugin)
# 1. Open v1.exe in IDA → Export with Diaphora
# 2. Open v2.exe in IDA → Diff with Diaphora

# Patch diff (CVE analysis)
# 1. Get pre-patch binary
# 2. Get post-patch binary
# 3. BinDiff / Diaphora to identify changed functions
# 4. Analyze changed function for CVE
```

### Phase 3 — Firmware analysis

```bash
# Binwalk - scan for signatures
binwalk firmware.bin

# Extract filesystem
binwalk -e firmware.bin

# FACT (Firmware Analysis Compare Tool)
git clone https://github.com/fkie-cad/FACT_core
cd FACT_core
./install

# EMBA (firmware analyzer)
git clone https://github.com/e-m-b-a/emba
cd emba
./emba -l /logs -f firmware.bin
```

### Phase 4 — Symbolic execution

```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state()

# Find address that prints "Good boy"
good_addr = 0x400a00
# Avoid address that prints "Bad boy"
bad_addr = 0x400a50

sm = proj.factory.simulation_manager(state)
sm.explore(find=good_addr, avoid=bad_addr)

if sm.found:
    found_state = sm.found[0]
    print(f"Solution: {found_state.posix.dumps(0)}")
```

### Phase 5 — OLLVM deobfuscation

```bash
# Control Flow Flattening (CFF) - deflat
# Requires identification of dispatcher + state variable
python3 deflat.py --binary flattened.exe --dispatcher 0x401000 --state-var eax

# Bogus Control Flow (BCF) - identify opaque predicates
# Use semantic analysis to identify always-true/always-false branches

# Instruction Substitution (SUB) - use MVP / miasm for simplification
```

### Phase 6 — Decompiler confusion identification

```python
# IDA Python: identify anti-decompiler patterns
import idautils, idc

for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    # Look for anti-decompiler patterns:
    # - Stack manipulation tricks
    # - Self-modifying code
    # - Anti-disassembly patterns (JE+0 / JNE-1)
    # - Overlapping instructions
    pass
```

### Phase 7 — SMT-assisted key recovery

```python
import angr
from z3 import *

# Sym execute key check
proj = angr.Project('./binary', auto_load_libs=False)

# Set up initial state with symbolic input
state = proj.factory.entry_state(
    stdin=angr.SimFileStream(name='stdin', content=angr.BVS('input', 32*8), size=32)
)

# Find / avoid
sm = proj.factory.simulation_manager(state)
sm.explore(find=0x400a00, avoid=0x400a50)

# Recover solution
print(sm.found[0].posix.dumps(0))
```

### Phase 8 — Variant analysis

```bash
# Kam1n0 - assembly-level similarity
kam1n0 cluster -i samples/ -o clusters.json

# BinDiff - cross-binary
bindiff --binary1=sample1 --binary2=sample2 --output_dir=diff

# Diaphora - many-to-many diff
# Export all samples → database
# Diff against each other → cluster
```

### Phase 9 — Automated RE pipeline

```python
# CI/CD for binary analysis
import angr, ghidra

def analyze_binary(binary_path):
    # 1. Static triage
    file_info = file_binary(binary_path)

    # 2. Symbolic execution
    proj = angr.Project(binary_path)
    sm = proj.factory.simulation_manager(proj.factory.entry_state())
    sm.explore(find=0x400a00)
    if sm.found:
        solution = sm.found[0].posix.dumps(0)
        return {'status': 'solved', 'solution': solution}

    # 3. Ghidra decompilation
    result = ghidra.decompile(binary_path)

    return {'status': 'analyzed', 'result': result}
```

### Phase 10 — Reporting

Produce RE report:
- Binary details
- Architecture + format
- Static analysis
- Dynamic analysis (if performed)
- Symbolic execution results
- Decompile output
- Vulnerabilities / capabilities
- TTP mapping (if malware)

## Practical Steps

### Step 1 — Triage

```bash
file binary
sha256sum binary
strings binary | head
python3 -c "
import pefile
pe = pefile.PE('binary.exe')
for s in pe.sections:
    print(s.Name.decode().rstrip(chr(0)), s.get_entropy())
"
```

### Step 2 — Symbolic execution with angr

```python
import angr

proj = angr.Project('./crackme', auto_load_libs=False)
state = proj.factory.entry_state()

# Find / avoid
sm = proj.factory.simulation_manager(state)
sm.explore(find=lambda s: b'Good boy' in s.posix.dumps(1),
          avoid=lambda s: b'Bad boy' in s.posix.dumps(1))

if sm.found:
    found = sm.found[0]
    print(f"Password: {found.posix.dumps(0)}")
```

### Step 3 — BinDiff for variant analysis

```bash
bindiff --binary1=original --binary2=patched --output_dir=diffs

# Analyze results
cd diffs
ls
# original_patched.Diff → open in BinDiff UI
```

### Step 4 — Binwalk for firmware

```bash
binwalk firmware.bin
binwalk -e firmware.bin

ls _firmware.bin.extracted/
# Find filesystem (squashfs, jffs2, etc.)
```

### Step 5 — OLLVM deflattening

```bash
# Identify dispatcher function
# Look for big switch statement on state variable

# Use deflat.py (https://github.com/cd70s062f/deflat)
python3 deflat.py --binary flattened.exe --dispatcher 0x401000
```

### Step 6 — SMT key recovery

```python
import z3

# Encode key check
s = z3.Solver()

# Input: 16-byte key
key = [z3.BitVec(f'key_{i}', 8) for i in range(16)]

# Constraints
for i in range(16):
    s.add(key[i] >= 0x20)
    s.add(key[i] <= 0x7e)

# Key check (derived from disassembly)
s.add(key[0] + key[1] == 0x90)
s.add(key[2] * key[3] == 0x41A8)
# ...

if s.check() == z3.sat:
    m = s.model()
    print(bytes(m[k].as_long() for k in key))
```

### Step 7 — Ghidra decompile

```bash
analyzeHeadless /tmp ghidra_proj -import binary
# Then open GUI
ghidraRun
```

### Step 8 — Build automated RE pipeline

```python
# Full pipeline: file → static → symbolic → decompile → report
def full_analysis(binary_path):
    # Static triage
    info = triage(binary_path)

    # Symbolic execution (if applicable)
    if info['has_constraint_check']:
        result = symbolic_solve(binary_path)

    # Decompile
    decompiled = decompile(binary_path)

    # Generate report
    return generate_report(info, result, decompiled)
```

## Defense Perspective

Defenders must assume:

1. **Symbolic execution defeats custom checks** — angr + Z3 can solve most constraints
2. **BinDiff identifies patches quickly** — 1-day exploitation easier
3. **Firmware RE exposes vulnerabilities** — embedded devices poorly protected
4. **OLLVM is defeatable** — deflat + semantic analysis
5. **Decompilers have blind spots** — manual disassembly still needed
6. **APT-grade obfuscation (Equation, Pegasus) is hard but possible**
7. **Variant analysis scales RE** — BinDiff clusters malware families
8. **SMT solvers can recover keys** — custom crypto can be defeated

Key defensive controls:

- Anti-debug + anti-VM in binaries
- Code obfuscation (OL VMM, Tigress)
- Stripped binaries (no symbols)
- Dynamic anti-tampering (self-modifying code)
- Encryption + packing
- Anti-symbolic execution (state explosion)

## Symbolic Execution Cheat Sheet

| Tool | Best for | Limitations |
|------|----------|-------------|
| angr | CTF, crackmes, key recovery | Path explosion on complex binaries |
| KLEE | Linux / LLVM binaries | Limited Windows support |
| manticore | Smart contracts, lightweight binaries | Slower than angr |

## Binary Diffing Cheat Sheet

| Tool | Algorithm | Cost |
|------|-----------|------|
| BinDiff | Graph isomorphism | Commercial (Zynamics) |
| Diaphora | Multiple algorithms | Free (IDA plugin) |
| Kam1n0 | Assembly clustering | Free (academic) |
| patchkit | Function similarity | Free |

## Firmware RE Cheat Sheet

| Tool | Purpose |
|------|---------|
| binwalk | Initial scan + extraction |
| FACT | Full firmware analysis |
| EMBA | Automated vulnerability scan |
| firmware-mod-kit | Filesystem repack |
| firmware-sltp | Tool suite |

## OLLVM Obfuscation Types

| Type | Description | Detection |
|------|-------------|-----------|
| CFF (Control Flow Flattening) | Big switch dispatcher | Visual CFG |
| BCF (Bogus Control Flow) | Fake branches | Opaque predicates |
| SUB (Instruction Substitution) | Replace operations | Pattern matching |
| CMP (Constant Masking) | Hide constants | Constant analysis |

## Engagement Workflow

1. **Triage** — file type, format, entropy
2. **Static analysis** — strings, imports, sections
3. **Symbolic execution** (if applicable) — angr / KLEE
4. **Binary diffing** (if variant) — BinDiff / Diaphora
5. **Firmware analysis** (if firmware) — binwalk / FACT / EMBA
6. **Deobfuscation** (if obfuscated) — deflat / BCF removal
7. **Decompilation** — IDA / Ghidra / Binary Ninja
8. **Reporting** — findings + recommendations

## Lab Setup

```bash
# angr
pip install angr

# Ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip
unzip ghidra_11.0_PUBLIC_20231222.zip

# BinDiff
# Download from https://www.zynamics.com/bindiff.html

# Diaphora (IDA plugin)
git clone https://github.com/joxeankoret/diaphora

# binwalk
pip install binwalk

# FACT
git clone https://github.com/fkie-cad/FACT_core
cd FACT_core && ./install

# EMBA
git clone https://github.com/e-m-b-a/emba
cd emba && ./installer.sh
```

## Quality Checklist

- [ ] File hash + type identified
- [ ] Architecture + format analyzed
- [ ] Static analysis complete
- [ ] Symbolic execution attempted (if applicable)
- [ ] Binary diffing performed (if variant)
- [ ] Firmware extraction (if firmware)
- [ ] Deobfuscation applied (if obfuscated)
- [ ] Decompile output saved
- [ ] Findings documented
- [ ] Final report delivered

## References

- MITRE ATT&CK Defense Evasion — https://attack.mitre.org/tactics/TA0005/
- "Practical Reverse Engineering" (Bruce Dang, 2014)
- "The IDA Pro Book" (Chris Eagle, 2nd Edition)
- "Ghidra Software Reverse Engineering" (Chris Eagle, Kara Nance, 2020)
- angr documentation — https://docs.angr.io/
- KLEE documentation — https://klee.github.io/
- Ghidra documentation — https://ghidra-sre.org/
- BinDiff documentation — https://www.zynamics.com/bindiff.html
- "Symbolic Execution for Software Testing" (Cadar, Sen, 2013)
- "OLLVM Deobfuscation" (RolfRolles, 2016)
- "Defeating OLLVM" (Quarkslab 2019)
- "Pegasus RE" (Citizen Lab, 2016, 2021, 2024)
- "Equation Group" (Kaspersky, 2015)
- BlackHat USA 2023 — "Advanced RE Techniques"
- "Firmware RE" (Firmware Sltp)
- FACT documentation — https://github.com/fkie-cad/FACT_core
- EMBA documentation — https://github.com/e-m-b-a/emba
