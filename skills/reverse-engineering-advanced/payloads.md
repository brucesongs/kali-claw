# Reverse Engineering Advanced — Payloads & Commands

> Operational commands for advanced reverse engineering: symbolic execution, binary diffing, firmware RE, OLLVM deobfuscation, and decompiler workflows. Each section focuses on a specific RE technique. Use during triage, static analysis, dynamic analysis, and reporting.

## Section 1 — Static triage

### 1.1 File identification

```bash
file binary
sha256sum binary
strings binary | head -20

# Section analysis
python3 << 'EOF'
import pefile
pe = pefile.PE('binary.exe')
print(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
print(f"Sections: {len(pe.sections)}")
for s in pe.sections:
    name = s.Name.decode().rstrip(chr(0))
    print(f"  {name:12s} VA={hex(s.VirtualAddress)} entropy={s.get_entropy():.2f}")
EOF
```

### 1.2 ELF analysis

```bash
# ELF
readelf -h binary
readelf -S binary  # Sections
readelf -d binary  # Dynamic
readelf -l binary  # Program headers

# Symbol table
nm binary 2>/dev/null | head -20
nm -D binary 2>/dev/null | head -20  # Dynamic symbols

# Imported functions
objdump -T binary | head
objdump -R binary | head  # Relocations
```

### 1.3 Strings + categorization

```bash
strings -a binary > strings.txt
strings -el binary > strings_wide.txt  # UTF-16

# Find interesting strings
grep -iE "http[s]?://" strings.txt
grep -iE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" strings.txt
grep -iE "password|secret|key" strings.txt
```

## Section 2 — Symbolic execution with angr

### 2.1 Basic angr solve

```python
import angr

proj = angr.Project('./crackme', auto_load_libs=False)
state = proj.factory.entry_state()

# Explore - find success, avoid failure
sm = proj.factory.simulation_manager(state)
sm.explore(
    find=lambda s: b'Good boy' in s.posix.dumps(1),
    avoid=lambda s: b'Bad boy' in s.posix.dumps(1)
)

if sm.found:
    found = sm.found[0]
    print(f"Solution: {found.posix.dumps(0)}")
else:
    print("No solution found")
```

### 2.2 angr with hooks

```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)

# Hook complex function with simpler one
class CustomCheck(angr.SimProcedure):
    def run(self, arg):
        return self.state.solver.If(arg > 100, 1, 0)

proj.hook_symbol('complex_check', CustomCheck())

state = proj.factory.entry_state()
sm = proj.factory.simulation_manager(state)
sm.explore(find=0x400a00, avoid=0x400a50)
```

### 2.3 angr memory exploration

```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state()

# Set symbolic stdin
stdin_size = 32
stdin = angr.BVS('stdin', stdin_size * 8)
state.regs.rdi = stdin

# Find / avoid
sm = proj.factory.simulation_manager(state)
sm.explore(find=0x400a00, avoid=0x400a50)

if sm.found:
    found = sm.found[0]
    print(f"Solution: {found.solver.eval(stdin, cast_to=bytes)}")
```

### 2.4 angr with constraints

```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state()

# Add constraints on input (e.g., printable ASCII)
for i in range(32):
    byte = state.posix.stdin.load(i, 1)
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)

sm = proj.factory.simulation_manager(state)
sm.explore(find=0x400a00)

if sm.found:
    print(sm.found[0].posix.dumps(0))
```

## Section 3 — KLEE (LLVM symbolic execution)

### 3.1 Compile to LLVM bitcode

```bash
# Compile C to LLVM bitcode
clang -emit-llvm -c -g program.c -o program.bc

# Run KLEE
klee program.bc

# Solutions in klee-last/
ls klee-last/
# *.ktest files contain solutions

# Read solution
ktest-tool klee-last/test000001.ktest
```

### 3.2 KLEE with assertions

```c
// program.c
#include <klee/klee.h>

int check(int x) {
    if (x * 2 + 1 == 0x12345) {
        return 1;  // success
    }
    return 0;
}

int main() {
    int x;
    klee_make_symbolic(&x, sizeof(x), "x");
    return check(x);
}
```

```bash
clang -emit-llvm -c program.c -o program.bc
klee program.bc
```

## Section 4 — Manticore

### 4.1 Basic manticore

```python
from manticore.ethereum import SolidityContract

# Smart contract analysis
m = ManticoreEVM()
owner = m.create_account(owner=True)
user = m.create_account()

contract = m.solidity_create_contract(
    'Vulnerable.sol',
    owner=owner,
    args=[]
)

# Symbolic argument
symbolic_value = m.make_symbolic_value()
contract.f(symbolic_value)

# Find assertion violation
for state in m.running_states:
    if state.can_complete:
        print("Solution found")
```

### 4.2 Manticore for binary

```python
from manticore.native import Manticore

m = Manticore('./binary', stdin_payload=b'A' * 32)

@m.hook(0x400a00)
def success(state):
    print(f"Solution: {state.solve()}")
    m.terminate()

@m.hook(0x400a50)
def fail(state):
    m.terminate()

m.run()
```

## Section 5 — Binary diffing

### 5.1 BinDiff

```bash
# Install BinDiff (Google/Zynamics)
# https://www.zynamics.com/bindiff.html

# Run from CLI
bindiff --binary1=original.exe --binary2=patched.exe --output_dir=diffs/

# Open in BinDiff GUI
# View function changes
# Filter by similarity score
```

### 5.2 Diaphora (IDA plugin)

```bash
# Install Diaphora (free)
# https://github.com/joxeankoret/diaphora

# In IDA:
# 1. Open original.exe
# 2. File → Script File → diaphora.py
# 3. Export to database
# 4. Open patched.exe
# 5. Diff with previous database
# 6. View best matches / partial matches
```

### 5.3 Patch diff (CVE analysis)

```bash
# 1. Get pre-patch binary (from software vendor archive)
# 2. Get post-patch binary (latest version)
# 3. BinDiff / Diaphora
# 4. Identify changed functions (similarity < 1.0)
# 5. Analyze changed function → identify CVE

# Example: CVE-2021-34527 (PrintNightmare)
# Compare pre-patch C:\Windows\System32\spoolsv.exe
# With post-patch version
```

## Section 6 — Firmware analysis

### 6.1 Binwalk scan

```bash
binwalk firmware.bin

# Output:
# DECIMAL       HEX         DESCRIPTION
# --------------------------------------------------------------------------------
# 0             0x0         TP-Link firmware header...
# 14592         0x3900      LZMA compressed data...
# 1038416       0xFD6F0     SquashFS filesystem...

# Extract
binwalk -e firmware.bin

# View extracted
ls _firmware.bin.extracted/
# squashfs-root/
```

### 6.2 Filesystem analysis

```bash
cd _firmware.bin.extracted/squashfs-root/

# Web server files
ls -la usr/www/
find . -name "*.cgi"
find . -name "*.php"

# Config files
find . -name "*.conf" -o -name "*.cfg"
cat etc/passwd  # Default credentials?
cat etc/shadow  # Password hashes

# Telnet / SSH config
cat etc/inetd.conf 2>/dev/null
cat etc/init.d/S50sshd 2>/dev/null
```

### 6.3 FACT (Firmware Analysis Compare Tool)

```bash
git clone https://github.com/fkie-cad/FACT_core
cd FACT_core
./install

# Start FACT
./start_all_installed_fact_components

# Web UI: https://localhost:5000
# Upload firmware → automated analysis
```

### 6.4 EMBA (firmware analyzer)

```bash
git clone https://github.com/e-m-b-a/emba
cd emba
./installer.sh

# Run on firmware
sudo ./emba -l /logs -f firmware.bin

# Output: HTML report + CVE matches
```

### 6.5 Hardcoded credentials

```bash
# Search for hardcoded credentials
cd _firmware.bin.extracted/squashfs-root/
grep -rE "password|passwd|admin|root" --include="*.conf" --include="*.cfg" --include="*.sh" | head -30

# Telnet default creds
cat etc/init.d/rcS 2>/dev/null | grep -iE "telnetd|passwd"

# SSH default keys
ls -la etc/dropbear/ 2>/dev/null
cat etc/dropbear/dropbear_rsa_host_key 2>/dev/null | head
```

## Section 7 — OLLVM deobfuscation

### 7.1 Identify OLLVM CFF (Control Flow Flattening)

```bash
# Visual signature: large dispatcher function with switch statement
# In Ghidra / IDA:
# 1. Open binary
# 2. View CFG (Control Flow Graph)
# 3. Look for dispatcher pattern:
#    - Single entry function
#    - Big switch statement on state variable
#    - All basic blocks branch back to dispatcher

# Ghidra script for CFF detection
# @category: Deobfuscation
from ghidra.app.decompiler import DecompInterface

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    result = decompiler.decompileFunction(func, 60, None)
    if result.decompileCompleted():
        hcode = result.getDecompiledFunction().getC()
        if "switch" in hcode and hcode.count("case") > 10:
            print(f"Possible CFF: {func.getName()} at {func.getEntryPoint()}")
```

### 7.2 Deflattening (deflat.py)

```bash
# https://github.com/cd70s062f/deflat

# Identify dispatcher address
# In IDA: look for big switch

# Run deflat
python3 deflat.py --binary flattened.exe \
  --dispatcher 0x401000 \
  --state-var eax \
  --output deflattened.exe
```

### 7.3 Bogus Control Flow (BCF) removal

```bash
# BCF adds always-true/always-false branches
# Identify opaque predicates

# Pattern: if (x*x % 2 == 0) - always true (squares are even-divisible by 2 if x is even)
# Pattern: if (x^2 + 1 > 0) - always true (squares are non-negative)

# Use semantic-aware tools: miasm, Triton
python3 << 'EOF'
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine

# Parse binary
cont = Container.from_stream(open('binary', 'rb'))
machine = Machine(cont.arch)
# ...
# Identify opaque predicates via symbolic execution
EOF
```

### 7.4 Instruction Substitution (SUB) reversal

```bash
# SUB replaces simple operations with complex equivalents
# E.g., x + y → (x ^ y) + 2*(x & y)

# Use Triton for simplification
python3 << 'EOF'
from triton import TritonContext, ARCH, Instruction, OPCODE

ctx = TritonContext(ARCH.X86_64)

# Set up symbolic
# Execute + simplify
EOF
```

## Section 8 — Decompiler confusion

### 8.1 Anti-decompiler patterns

```python
# Common anti-decompiler patterns:

# 1. Stack manipulation tricks
# push X; pop Y → mov Y, X (but decompiler may not simplify)

# 2. Self-modifying code
# Code that rewrites itself at runtime

# 3. Overlapping instructions
# Jump into middle of instruction

# 4. Anti-disassembly (JE+0 / JNE-1)
# Two consecutive jumps - one taken, one not
# Forces disassembler down wrong path

# 5. Indirect calls
# call dword ptr [eax+0x4]
# Hard for decompiler to resolve

# 6. Function pointer tables
# Many possible call targets

# 7. Exception-based control flow
# Setjmp / longjmp patterns

# Identify in IDA Python:
import idautils, idc

for func_ea in idautils.Functions():
    for head in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(head)
        # Look for patterns
        if mnem == "jmp":
            # Check if indirect
            if idc.get_operand_type(head, 0) == idc.o_reg:
                print(f"Indirect jmp at {hex(head)}")
```

### 8.2 Manual deobfuscation

```python
# IDA Python: patch overlapping instructions
import idc

# Original: jmp into middle of instruction
# Patch: NOP out overlapping, replace with direct jmp
idc.patch_byte(0x401000, 0x90)  # NOP
idc.patch_byte(0x401001, 0x90)  # NOP
idc.patch_byte(0x401002, 0xEB)  # jmp short
idc.patch_byte(0x401003, 0x10)  # offset
```

## Section 9 — SMT-assisted analysis (Z3)

### 9.1 Z3 key recovery

```python
from z3 import *

# Input: 16-byte key
key = [BitVec(f'key_{i}', 8) for i in range(16)]

s = Solver()

# Constraints (derived from disassembly)
s.add(key[0] == 0x41)  # 'A'
s.add(key[1] + key[2] == 0xc2)
s.add(key[3] * key[4] == 0x410)
s.add(key[5] - key[6] == 5)
s.add(key[7] ^ key[8] == 0x10)

# All printable
for i in range(16):
    s.add(key[i] >= 0x20)
    s.add(key[i] <= 0x7e)

if s.check() == sat:
    m = s.model()
    print(bytes(m[k].as_long() for k in key))
```

### 9.2 Z3 for crypto key

```python
from z3 import *

# Recover XOR key from known plaintext
plaintext = b"Hello World"
ciphertext = b"\x12\x04\x0d\x09\x08\x49\x2a\x1c\x0e\x09\x2f"

# XOR key
key_len = 4
key = [BitVec(f'key_{i}', 8) for i in range(key_len)]

s = Solver()

for i in range(len(plaintext)):
    s.add((plaintext[i] ^ key[i % key_len]) == ciphertext[i])

if s.check() == sat:
    m = s.model()
    print(bytes(m[k].as_long() for k in key))
```

## Section 10 — Variant analysis

### 10.1 Kam1n0 clustering

```bash
# Install Kam1n0 (https://github.com/McGill-DMaS/Kam1n0-Community)

# Index samples
kam1n0 index -i samples/

# Cluster
kam1n0 cluster -i samples/ -o clusters.json

# View clusters
jq '.clusters[] | .name' clusters.json
```

### 10.2 BinDiff multi-binary

```bash
# Diff all pairs in directory
for f1 in samples/*; do
    for f2 in samples/*; do
        [ "$f1" = "$f2" ] && continue
        bindiff --binary1=$f1 --binary2=$f2 --output_dir=diffs/$(basename $f1)_$(basename $f2)/
    done
done
```

### 10.3 Diaphora multi-diff

```bash
# In IDA:
# 1. For each sample: Export to SQLite database
# 2. Diff each pair
# 3. Track similarity scores

# Script to bulk export
for f in samples/*; do
    ida -A -S"diaphora.py --export-only" $f
done
```

## Section 11 — Ghidra workflows

### 11.1 Ghidra headless analysis

```bash
analyzeHeadless /tmp proj -import binary -postScript MyScript.py -scriptPath /path/to/scripts

# Example script
cat > MyScript.py << 'EOF'
from ghidra.program.model.symbol import SymbolType

sm = currentProgram.getSymbolTable()
for sym in sm.getAllSymbols(True):
    if sym.getSymbolType() == SymbolType.FUNCTION:
        print(f"{sym.getName()} at {sym.getAddress()}")
EOF
```

### 11.2 Ghidra Python decompile

```python
# In Ghidra Script Manager
from ghidra.app.decompiler import DecompInterface

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    result = decompiler.decompileFunction(func, 60, None)
    if result.decompileCompleted():
        hcode = result.getDecompiledFunction().getC()
        print(f"// Function: {func.getName()}")
        print(hcode)
```

### 11.3 Ghidra script: find crypto constants

```python
# Search for known crypto constants
crypto_constants = {
    "AES_SBOX": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
    "MD5_INIT": 0x67452301,
    "SHA256_INIT": 0x6a09e667,
    "AES_RCON": 0x9d,
}

mem = currentProgram.getMemory()
for name, const in crypto_constants.items():
    if isinstance(const, int):
        addr = findBytes(toAddr(0), struct.pack('>I', const), None, True, None)
    else:
        addr = findBytes(toAddr(0), const, None, True, None)
    if addr:
        print(f"Found {name} at {addr}")
```

## Section 12 — IDA Pro workflows

### 12.1 IDA Python batch analysis

```python
import idautils, idc, ida_hexrays

# Initialize Hex-Rays
ida_hexrays.init_hexrays_plugin()

# Iterate all functions
for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    size = idc.get_func_attr(func_ea, idc.FUNCATTR_END) - func_ea

    if size > 1000:  # Large function
        print(f"Large function: {name} ({size} bytes)")

        # Decompile
        cf = ida_hexrays.decompile(func_ea)
        if cf:
            print(cf)
```

### 12.2 IDA batch script

```bash
# Run script on all binaries
for f in samples/*; do
    ida -A -S"analysis.py" $f
done
```

### 12.3 IDA Python: find injections

```python
import idautils, idc

# Find VirtualAlloc + WriteProcessMemory patterns
suspicious_apis = ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
                   "CreateRemoteThread", "NtUnmapViewOfSection"]

imports = []
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if name in suspicious_apis:
        imports.append((name, ea))

for name, ea in imports:
    callers = list(idautils.XrefsTo(ea))
    if callers:
        print(f"{name} called by {len(callers)} functions")
        for xref in callers[:5]:
            print(f"  Caller: {hex(xref.frm)}")
```

## Section 13 — Binary Ninja workflows

### 13.1 Binary Ninja Python

```python
import binaryninja as bn

bv = bn.load("binary.exe")

# Iterate functions
for func in bv.functions:
    print(f"{func.name}: {hex(func.start)}")
    # Iterate basic blocks
    for bb in func.basic_blocks:
        print(f"  BB at {hex(bb.start)}")
```

### 13.2 Binary Ninja API

```python
import binaryninja as bn

bv = bn.load("binary.exe")

# Find calls to VirtualAlloc
for func in bv.functions:
    for callee in func.callees:
        if "VirtualAlloc" in callee.name:
            print(f"{func.name} calls VirtualAlloc at {hex(func.start)}")
```

## Section 14 — radare2 workflows

### 14.1 r2 batch analysis

```bash
r2 -A -q -c "afl" binary

# Multi-binary
for f in samples/*; do
    r2 -A -q -c "afl; ii" $f > analysis_$(basename $f).txt
done
```

### 14.2 r2 decompile

```bash
r2 -A binary

# In r2 prompt:
pdf @ main  # disassemble main
pdc @ main  # pseudo-C decompile
```

## Section 15 — Crypto identification

### 15.1 Find AES

```bash
# AES S-box starts: 63 7c 77 7b f2 6b 6f c5
# Look in binary
xxd binary | grep -E "63.*7c.*77.*7b.*f2.*6b.*6f.*c5"

# Or in Python:
python3 << 'EOF'
with open('binary', 'rb') as f:
    data = f.read()

aes_sbox = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
offset = data.find(aes_sbox)
if offset >= 0:
    print(f"AES S-box at offset {hex(offset)}")
EOF
```

### 15.2 Find RSA

```bash
# RSA public key typically stored as ASN.1 DER
# Header: 30 82 XX XX 02 82 XX XX 00

xxd binary | grep -E "^.*: 30 82.*02 82.*00"

# Or in Python:
python3 << 'EOF'
with open('binary', 'rb') as f:
    data = f.read()

# RSA DER pattern
import re
matches = re.findall(b'\x30\x82.{2}\x02\x82.{2}\x00', data, re.DOTALL)
print(f"Possible RSA public keys: {len(matches)}")
EOF
```

### 15.3 Find DES

```bash
# DES S-boxes are well-known
# S1 starts: 0x0e, 0x04, 0x0d, 0x01

xxd binary | grep -E "0e 04 0d 01"
```

## Section 16 — Equation Group / Pegasus-style obfuscation

### 16.1 Multi-layer obfuscation

```python
# Equation Group binaries use:
# - Custom packers
# - Encrypted sections
# - Self-modifying code
# - Virtualized code (VMProtect-style)

# Multi-layer unpacking workflow:
# 1. Static analysis (identify outer packer)
# 2. Dynamic analysis (let packer unpack to layer 2)
# 3. Memory dump (capture layer 2)
# 4. Repeat until original code found

# Use pe-sieve for memory dumps
pe-sieve /pid 1234 /imp 3 /dump
```

### 16.2 Pegasus-specific (Citizen Lab workflow)

```bash
# Pegasus uses:
# - SMS / iMessage exploitation
# - Memory-only operation (no files)
# - Encrypted C2
# - Self-destruct mechanism

# Analysis (Citizen Lab):
# 1. MobileVerificationToolkit (MVT)
pip install mvt

mvt-ios check-backup --output ./output/ ./backup/

# 2. Look for indicators of compromise
# - Suspicious SMS / iMessage
# - Network anomalies
# - Filesystem artifacts
```

## Section 17 — Custom unpacking

### 17.1 Manual unpacking workflow

```bash
# 1. Identify OEP (Original Entry Point)
#    - Look for transitions from packer code to original code
#    - Common: jmp / call to non-packed section

# 2. Set breakpoint at suspected OEP
#    - In x64dbg: bp <address>

# 3. Run until OEP reached
#    - Use memory breakpoint on packed section to catch unpacker transition

# 4. Dump process memory
#    - Scylla plugin
#    - pe-sieve /pid $PID /imp 3 /dump

# 5. Fix IAT (Import Address Table)
#    - Scylla: IAT AutoSearch → Get Imports → Fix Dump
```

### 17.2 Memory dump with pe-sieve

```bash
# After reaching OEP in debugger
pe-sieve /pid 1234 /imp 3 /dump

# Output: process_1234_*.exe files
ls -la process_1234_*
```

## Section 18 — Reporting

### 18.1 RE report template

```markdown
# Reverse Engineering Report

## Executive Summary
- Binary: sample.exe
- SHA256: abc...
- Type: PE32 executable
- Purpose: Credential stealer

## Static Analysis
### Architecture
- x86-64 (64-bit Windows)

### Sections
| Name | Entropy | Packed |
|------|---------|--------|
| .text | 6.45 | No |
| .data | 7.12 | No |
| .vmp0 | 7.95 | Yes |

### Imports
- ADVAPI32: RegOpenKeyA, RegSetValueA
- KERNEL32: CreateFileA, WriteFile
- WININET: InternetOpenA, HttpSendRequestA

## Dynamic Analysis
- Process injection: Yes (svchost.exe)
- C2 protocol: HTTP POST with RC4 encryption
- C2 endpoint: bad.example.com/api/beacon

## Symbolic Execution
- Constraint check solved via angr
- Solution: <key>

## Capabilities
- Credential theft (browser passwords)
- Keylogger
- C2 beacon

## IOCs
- SHA256: ...
- C2: bad.example.com
- Mutex: Global\sample_v1

## YARA Rule
```yara
rule Sample_Cred_Stealer {
    ...
}
```

## Recommendations
- Deploy YARA at endpoint
- Block C2 domain at SWG
- Train SOC on indicators
```

### 18.2 SOC handoff checklist

```markdown
- [ ] Sample hash + family
- [ ] IOCs documented
- [ ] YARA rule authored
- [ ] Sigma rule authored
- [ ] C2 endpoints added to blocklist
- [ ] Detection tuned in SIEM
- [ ] Final report delivered
```

## Section 19 — Hybrid symbolic + dynamic analysis (concolic)

Concolic execution combines concrete runs with symbolic constraints, useful for patching coverage gaps.

```python
# manticore concolic on Ethereum smart contract
from manticore.eth import ManticoreEVM

m = ManticoreEVM()
with m.shutdown_on_exit():
    source = """
    contract C {
        function check(uint x) public pure returns (bool) {
            if (x * 2 == 0xdeadbeef) return true;
            return false;
        }
    }
    """
    user_account = m.create_account(balance=1000)
    contract_account = m.solidity_create_contract(source, owner=user_account)
    contract_account.check(123, value=0)
    symbolic_val = m.make_symbolic_value()
    contract_account.check(symbolic_val)

for state in m.ready_states:
    result = state.platform.get_transaction_log()
    print(f"Found state: {result}")
```

## Section 20 — RE pipeline as code (full automation)

```python
import angr
import ghidra
import yara
import pefile
import hashlib
import json
from pathlib import Path

class REPipeline:
    def __init__(self, sample_path):
        self.sample = Path(sample_path)
        self.report = {'sample': str(self.sample)}
        self._hash()

    def _hash(self):
        h = hashlib.sha256(self.sample.read_bytes()).hexdigest()
        self.report['sha256'] = h

    def triage(self):
        pe = pefile.PE(str(self.sample))
        self.report['type'] = 'PE'
        self.report['sections'] = [
            {'name': s.Name.decode().rstrip(chr(0)),
             'entropy': s.get_entropy()}
            for s in pe.sections
        ]
        return self

    def symbolic_solve(self, find_str=b'Good', avoid_str=b'Bad'):
        proj = angr.Project(str(self.sample), auto_load_libs=False)
        state = proj.factory.entry_state()
        sm = proj.factory.simulation_manager(state)
        sm.explore(find=lambda s: find_str in s.posix.dumps(1),
                   avoid=lambda s: avoid_str in s.posix.dumps(1))
        if sm.found:
            self.report['solution'] = sm.found[0].posix.dumps(0).decode(errors='ignore')
        return self

    def decompile(self):
        # Ghidra headless
        ghidra.analyze_headless(str(self.sample), out='/tmp/decompile.json')
        self.report['decompile'] = ghidra.read_output('/tmp/decompile.json')
        return self

    def yara_match(self, rules_path):
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(str(self.sample))
        self.report['yara_matches'] = [m.rule for m in matches]
        return self

    def finalize(self):
        out = self.sample.with_suffix('.re.json')
        out.write_text(json.dumps(self.report, indent=2))
        return out

# Usage
report = (REPipeline('sample.exe')
          .triage()
          .symbolic_solve()
          .decompile()
          .yara_match('rules.yar')
          .finalize())
print(f"Report: {report}")
```

## Section 21 — Patch diffing for 1-day exploitation

Identify patched vulnerabilities by diffing pre/post-patch binaries.

```bash
# 1. Acquire pre-patch + post-patch binaries
# Often available from vendor's older releases

# 2. BinDiff
bindiff --binary1=app_v1.0.exe --binary2=app_v1.1.exe --output_dir=diffs/

# 3. Open .Diff in BinDiff UI
# Filter to "Changed functions" — these are patched

# 4. Diaphora for free alternative
# In IDA: File → Diaphora → Export v1.0.sqlite
# In IDA: File → Diaphora → Diff v1.0.sqlite against v1.1
# Sort by "Reliability" column

# 5. Analyze changed function in v1.0
# Look for:
# - Removed bounds check
# - Replaced strcpy with strncpy
# - Added size parameter to memcpy
# - Changed signed comparison to unsigned (integer overflow fix)

# 6. Develop 1-day exploit from identified vuln
# Often patch diffs lead to CVE exploitation in <30 days for active researchers
```

## Section 22 — VMProtect devirtualization

VMProtect translates original instructions to a custom bytecode interpreter. Devirtualization is hard.

```bash
# 1. Identify VM dispatcher (typically a big switch / jump table)
# In IDA: look for large function with consistent loop pattern

# 2. Trace VM execution dynamically
# Set hardware breakpoint on VM entry; trace each "virtual instruction"

# 3. Tools:
# - VMPAttack (https://github.com/jbainesai/vmattack)
# - VTIL (Virtual-machine Translation Intermediate Language)
# - ScyllaHide for anti-debug bypass during trace

# 4. Workflow:
# a) Run binary under x64dbg with ScyllaHide
# b) Set breakpoint at VM entry (just after VM dispatcher prologue)
# c) Log every virtual handler call + operand
# d) Map virtual opcode to x86 equivalent
# e) Rebuild native x86 function from logged trace

# 5. Memory dump post-OEP as fallback
# When full devirtualization is too expensive, dump from memory after decryption
# This gives unpacked code but with VM'd functions still virtualized
```

## Section 23 — Themida VM analysis

Themida uses per-function VMs with different bytecode sets.

```bash
# 1. Identify Themida-protected functions
die sample.exe
# "Themida 2.x / WinLicense 2.x"

# 2. Per-function VM analysis
# Each VM'd function has unique bytecode → must analyze individually

# 3. Tools:
# - ThemidaUnpack (community tools)
# - DevirtualizeThemida (research scripts)
# - Custom x64dbg tracing scripts

# 4. Workflow:
# a) Identify VM entry stubs (look for pusha + custom stack setup)
# b) For each VM'd function, build opcode map
# c) Trace execution in debugger, log opcode + operands
# d) Reconstruct original logic from trace

# 5. Practical tip: many malware authors only VM 1-2 critical functions
# Focus on those; leave rest as-is
```

## Section 24 — Anti-analysis technique catalog

Catalog of common anti-debug / anti-VM / anti-disassembly techniques.

```python
# IDA Python — detect common anti-analysis patterns
import idautils, idc, ida_bytes

ANTI_DEBUG_APIS = [
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'OutputDebugString',
    'kernel32!GetTickCount', 'NtSetInformationThread',
    'ProcessDebugFlags', 'ProcessDebugPort',
]

ANTI_VM_KEYS = [
    'SOFTWARE\\VMware, Inc.\\VMware Tools',
    'HARDWARE\\ACPI\\DSTD\\VBOX__',
    'HARDWARE\\Description\\System\\SystemBiosVersion',
    'HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier',
]

ANTI_DISASM_PATTERNS = [
    # JE+0 / JNE-1
    (0x74, 0x00),   # JE $+2 (skip next byte)
    (0x75, 0xFF),   # JNE $+1 (overlap)
    (0xEB, 0xFF),   # JMP $-1 (infinite loop / overlap)
    # SEH abuse
    (0x64, 0x89, 0x20),  # mov fs:[eax], esp — push SEH
]

def scan_anti_debug():
    for name in ANTI_DEBUG_APIS:
        for ea in idautils.Names():
            if name in ea[1]:
                print(f"Anti-debug API: {name} at {hex(ea[0])}")

scan_anti_debug()
```

## Section 25 — Bypass techniques

For each anti-analysis technique, document bypass.

```python
# ScyllaHide config (x64dbg plugin)
# Profile: "VMProtect" / "Themida" / "NSPack"

# Manual bypass via IDA patch:
# 1. NOP-out anti-debug check
# 2. Or: force return value (EAX = 0 for IsDebuggerPresent)

# IDA Python — patch IsDebuggerPresent to always return 0
import idc

# Locate IsDebuggerPresent import
for ea, name in idautils.Names():
    if 'IsDebuggerPresent' in name:
        # Patch with: xor eax, eax; ret
        idc.patch_byte(ea, 0x31)  # xor
        idc.patch_byte(ea + 1, 0xC0)  # eax, eax
        idc.patch_byte(ea + 2, 0xC3)  # ret
        break

# Anti-VM bypass via registry spoofing (in analysis VM):
# HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.\VMware Tools → delete
# HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\SystemBiosVersion → "Bochs"

# CPUID hypervisor bit bypass:
# Hook CPUID via IOCTL or binary patch
# Patch cpuid dispatcher to clear ECX[31]
```

## Section 26 — Reverse engineering smart contracts (EVM)

Solidity / Vyper bytecode analysis with specialized tooling.

```bash
# 1. Acquire bytecode
cast code 0xCONTRACT_ADDRESS --rpc-url $RPC > bytecode.hex

# 2. Decompile with:
# - Panoramix (https://github.com/eveem-org/panoramix)
# - EthervmDe (https://ethervm.io)
# - Dedaub (https://app.dedaub.com)
python3 panoramix.py bytecode.hex

# 3. Symbolic execution with manticore
manticore --contract contract.sol --detect-all

# 4. Static analysis with Slither
pip install slither-analyzer
slither contract.sol

# 5. Fuzzing with Echidna
echidna-test contract.sol

# 6. Reentrancy + integer overflow patterns
# - Look for: state changes after external calls
# - Look for: unchecked arithmetic
# - Look for: tx.origin authentication
```

## Section 27 — ELF reverse engineering (Linux / IoT)

```bash
# 1. ELF header
readelf -h sample.elf

# 2. Sections
readelf -S sample.elf
readelf -l sample.elf  # Program headers

# 3. Dynamic linking
readelf -d sample.elf
ldd sample.elf  # Library dependencies (CAUTION: only on analysis VM)

# 4. Symbols
nm sample.elf 2>/dev/null | head -30
nm -D sample.elf 2>/dev/null | grep " U "  # Undefined (imported)

# 5. Disassembly
objdump -d sample.elf | head
objdump -d -M intel sample.elf | head  # Intel syntax

# 6. GOT / PLT (imports)
objdump -R sample.elf

# 7. Relocations
readelf -r sample.elf | head

# 8. MIPS-specific (for IoT firmware)
# Ghidra MIPS plugin
mips-linux-gnu-objdump -d sample.elf  # Cross-architecture objdump

# 9. ARM-specific
arm-linux-gnueabi-objdump -d sample.elf
```

## Section 28 — Mach-O reverse engineering (macOS / iOS)

```bash
# 1. Mach-O header
otool -h binary
file binary  # Mach-O 64-bit executable

# 2. Architectures (universal binary)
lipo -info binary
lipo -detailed_info binary

# 3. Sections
otool -l binary | head -100

# 4. Dynamic libraries
otool -L binary

# 5. Symbols
nm -m binary | head -30
nm -g binary | head  # Global symbols

# 6. Disassembly
otool -tV binary | head

# 7. Objective-C class info
otool -ov binary | head

# 8. Code signature
codesign -dvvv binary

# 9. Class-dump for Objective-C
class-dump-z binary > classes.h

# 10. iOS-specific:
# - Decrypt binary first (with dumpdecrypted / frida-ios-dump)
# - Use Ghidra Mach-O plugin
# - Use Hopper Disassembler (macOS-native)
```

## Section 29 — Network protocol reverse engineering

```bash
# 1. Capture traffic
sudo tcpdump -i any -w capture.pcap host 192.168.1.100
# or
tshark -i any -f "host 192.168.1.100" -w capture.pcap

# 2. Analyze in Wireshark / tshark
tshark -r capture.pcap -Y "tcp.port == 4444" -T fields -e data | xxd -r -p

# 3. Identify protocol structure
# - Magic header?
# - Length-prefixed?
# - Delimiter-based?

# 4. Decrypt if TLS
# - Extract TLS session key from process memory
# - Use SSLKEYLOGFILE environment variable
# - Wireshark: Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename

# 5. Custom protocol decode in Python
from scapy.all import *
import struct

def parse_packet(data):
    magic = data[:4]
    if magic != b'\xAA\xBB\xCC\xDD':
        return None
    length = struct.unpack('>I', data[4:8])[0]
    opcode = data[8]
    payload = data[9:9+length-1]
    return {'magic': magic.hex(), 'length': length, 'opcode': opcode, 'payload': payload}

packets = rdpcap('capture.pcap')
for p in packets:
    if p.haslayer('TCP') and p['TCP'].dport == 4444:
        result = parse_packet(bytes(p['TCP'].payload))
        if result:
            print(result)
```

## Section 30 — Anti-forensics in malware

Identify and document anti-forensic techniques.

```bash
# 1. Self-deletion
strings sample.exe | grep -iE "delete|remove|unlink"

# 2. Timestomping (kernel32!SetFileTime)
# In IDA, look for SetFileTime calls

# 3. Log clearing
# Event log: ClearEventLog
# syslog: rm /var/log/messages

# 4. Process hollowing detection
# In memory: vol -f dump.dmp windows.hollowprocess

# 5. Code signing abuse
codesign -dvvv suspicious.app
# Verify certificate chain, look for stolen / mis-issued certs
```

## Section 31 — Memory-only malware (fileless)

Analysis without filesystem artifacts.

```bash
# 1. Acquire memory dump
winpmem.exe dump.dmp
# Or via VMware: .vmem file

# 2. Volatility analysis
vol -f dump.dmp windows.pslist
vol -f dump.dmp windows.pstree
vol -f dump.dmp windows.malfind --dump
vol -f dump.dmp windows.netscan
vol -f dump.dmp windows.modscan
vol -f dump.dmp windows.ssdt  # SSDT hooks (rootkit)

# 3. Process injection detection
vol -f dump.dmp windows.malfind
# Reports injected regions with PAGE_EXECUTE_READWRITE

# 4. Dump injected shellcode
vol -f dump.dmp windows.malfind --pid 1234 --dump
# Outputs process.1234.0xADDR.dmp

# 5. Disassemble shellcode
# Open in IDA as raw binary
# Identify syscall pattern: mov eax, SYSCALL_NUMBER; syscall
```

## Section 32 — Mobile malware reverse (Android / iOS)

```bash
# Android APK
apktool d sample.apk -o sample_decoded/

# Inspect AndroidManifest.xml
cat sample_decoded/AndroidManifest.xml

# Decompile DEX
jadx-gui sample.apk

# Inspect native libraries
cd sample_decoded/lib/arm64-v8a/
file *.so
ghidraRun libnative.so

# iOS IPA
unzip sample.ipa -d sample_extracted/
cd sample_extracted/Payload/Sample.app/
class-dump-z Sample > classes.h
# Decrypt binary if encrypted
dumpdecrypted Sample
```

## Section 33 — Container / Kubernetes malware

```bash
# 1. Pull malicious container image
docker pull evilrepo/malware:latest
docker save evilrepo/malware -o malware.tar

# 2. Extract layers
mkdir malware_extracted && cd malware_extracted
tar xf ../malware.tar
ls -la
# Each layer is a separate tarball

# 3. Extract all layers
for layer in */layer.tar; do
    mkdir "${layer%/*}_extracted"
    tar xf "$layer" -C "${layer%/*}_extracted"
done

# 4. Analyze extracted binaries
file malware_extracted/*/usr/local/bin/*

# 5. Check for crypto miners
strings extracted_binary | grep -iE "stratum\+tcp|monero|xmr"
```

## Section 34 — Cross-architecture RE (ARM / MIPS / RISC-V)

```bash
# 1. Identify architecture
file binary
# ELF 32-bit LSB executable, MIPS, MIPS-I

# 2. Configure Ghidra for correct language
# File → Configure → MIPS:BE:32:default

# 3. Cross-architecture objdump
mips-linux-gnu-objdump -d binary
arm-linux-gnueabihf-objdump -d binary
riscv64-linux-gnu-objdump -d binary

# 4. QEMU for dynamic analysis
qemu-mips binary  # Run MIPS binary on x86
qemu-mips-static binary
qemu-aarch64 binary  # ARM64

# 5. QEMU system for full-system emulation
qemu-system-mips -M malta -kernel vmlinux -hda rootfs.ext2 -append "root=/dev/sda"

# 6. Cross-compilation for testing
# Build test programs in same architecture to validate findings
```

## Section 35 — Differential RE for vulnerability discovery

```bash
# 1. Acquire multiple versions of target software
# - Older versions often from archive.org / vendor archives
# - Diff pre-patch vs post-patch for CVE identification

# 2. BinDiff across versions
for v in v1 v2 v3; do
    bindiff --binary1=app_$v.bin --binary2=app_${v}_patched.bin \
        --output_dir=diffs/$v
done

# 3. Focus on changed functions
# Functions changed between versions are most likely vuln fixes

# 4. Diaphora for many-to-many diff
# Export all versions to SQLite, then diff against latest patched

# 5. Pattern-based vuln hunting
# After identifying vuln functions, search across other parts of binary
# for similar patterns (e.g., all strcpy calls, all sprintf calls)

# 6. Symbolic execution on candidate vuln functions
# Use angr to explore if user-controlled input reaches vuln function
```

## Section 36 — Reporting + threat intel dissemination

```python
# Generate STIX 2.1 bundle for IOC dissemination
from stix2 import Indicator, Malware, Relationship, Bundle

# Create malware family object
malware = Malware(
    name="SampleFamily",
    is_family=True,
    description="Custom packer with OLLVM obfuscation",
)

# Create indicators
indicators = []
for hash_val in ['abc123...', 'def456...']:
    indicators.append(Indicator(
        name=f"SampleFamily sample {hash_val[:8]}",
        pattern=f"[file:hashes.'SHA-256' = '{hash_val}']",
        pattern_type="stix",
        valid_from="2026-06-28T00:00:00Z",
    ))
for domain in ['c1.evil.com', 'c2.evil.com']:
    indicators.append(Indicator(
        name=f"SampleFamily C2 {domain}",
        pattern=f"[domain-name:value = '{domain}']",
        pattern_type="stix",
        valid_from="2026-06-28T00:00:00Z",
    ))

# Relationships
relationships = []
for ind in indicators:
    relationships.append(Relationship(
        source_ref=ind.id,
        target_ref=malware.id,
        relationship_type="indicates",
    ))

# Bundle
bundle = Bundle(objects=[malware] + indicators + relationships)
print(bundle.serialize(pretty=True))
```

## Section 37 — Operator OPSEC during RE

```bash
# 1. Isolated analysis network
# - No internet egress
# - INetSim for fake services
# - SOCKS proxy for safe VT lookups

# 2. Sample handling
# - Hash sample before any analysis
# - Use dedicated sample repository with version control
# - Encrypt samples at rest

# 3. VM snapshots
# - Snapshot before each detonation
# - Revert after each sample
# - Never reuse VM without revert

# 4. Tool OPSEC
# - Don't upload samples to public services without authorization
# - Use private VT API key for sensitive samples
# - Sign all custom tools (prevent tampering)

# 5. Documentation OPSEC
# - Encrypt engagement reports
# - Store in air-gapped repo
# - Redact customer data before sharing with SOC
```

## Section 38 — Engagement closure

```bash
# 1. Final report delivery
# - PDF + Markdown
# - Encrypted ZIP for sensitive findings
# - Separate IOC feed for SOC

# 2. SOC handoff
# - YARA rules
# - Sigma rules
# - Sigma rules
# - Splunk / Sentinel queries
# - EDR detections

# 3. Vendor disclosure (if 0-day)
# - PGP-encrypted report
# - 90-day disclosure deadline
# - CVE request via MITRE

# 4. Lessons learned
# - What worked
# - What didn't
# - Tool gaps identified
# - Training needs

# 5. Cleanup
# - Wipe analysis VMs
# - Revoke any credentials used
# - Archive sample in encrypted repo
```


---

## Ghidra Headless Script Guide + RE CVEs (v0.2.5.3)

### Ghidra 内置脚本清单（F-RE-001）

Kali 2026.1 Ghidra 11.x 安装后可用的 headless 脚本（在 `/usr/share/ghidra/Ghidra/Features/Decompiler/ghidra_scripts/`）：

| 脚本 | 用途 |
|------|------|
| `DecompilerParameterID.java` | 参数自动命名 |
| `DecompilerSwitchAnalysis.java` | switch 语句分析 |
| `FindDialog.java` | 搜索引用 |
| `PropagateExternalParameters.java` | 外部参数传播 |
| `ResolveX86orX64Binary.java` | x86/x64 二进制解析 |

**注意**：`ListSymbols.java` 不是内置脚本。如需列出符号，用：

```bash
# 方法 1: Ghidra 分析后用 readelf/objdump
readelf -sW target_binary | head -30

# 方法 2: Ghidra headless 不加 -postScript（仅导入分析）
analyzeHeadless /tmp/proj Proj -import target
# 然后在 Ghidra GUI 中查看

# 方法 3: radare2 替代（更快）
r2 -q -c 'is; afl' target_binary
```

### Ghidra ARM64 headless 完整流程

```bash
mkdir -p ~/re-lab/ghidra_proj
/usr/share/ghidra/support/analyzeHeadless \
  ~/re-lab/ghidra_proj ReProj \
  -import ~/re-lab/target_binary \
  -analysisTimeoutPerFile 300
# 期望输出: "INFO  ANALYZING..." + "INFO  SCRIPT SUCESSFUL"
```

### RE 相关 CVEs（F-RE-002）

| CVE | 工具 | CVSS | 描述 |
|-----|------|------|------|
| CVE-2024-24582 | Ghidra < 11.0.3 | 7.8 | 反序列化 RCE（加载恶意 project） |
| CVE-2023-38205 | IDA Pro | 7.8 | heap overflow in loader |
| CVE-2023-26967 | Ghidra | 7.8 | unzip path traversal |
| CVE-2022-2440 | Ghidra | 7.5 | XXE in project import |
| CVE-2021-31630 | OpenPLC (RE 目标) | 9.8 | Modbus 异常报文 DoS |
