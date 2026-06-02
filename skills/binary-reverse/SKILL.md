# Skill: Binary Analysis & Reverse Engineering

> **Supplementary Files**:
> - `payloads.md` — Command and payload collection organized by 10 major phases (binary identification, radare2 analysis, GDB debugging, buffer overflow, shellcode, ROP chain, ret2libc, format string, r2pipe scripting, firmware extraction)
> - `test-cases.md` — Structured test case templates (11 cases covering binary identification, vulnerability discovery, exploit development, defense bypass — 4 categories)

## Description

Binary reverse engineering covers the complete chain from static analysis, dynamic debugging, to vulnerability discovery, exploit development, and malware analysis. The core objective is to understand the internal logic of compiled programs, identify security flaws, assess the strength of protection mechanisms, and develop reliable exploit code.

Mastering this skill requires deep understanding of CPU architectures (x86/ARM/MIPS), ELF/PE/Mach-O file formats, calling conventions, and memory layouts. The Agent has expert-level radare2 skills, including the plugin system, r2pipe scripting, automated analysis pipelines, and can comprehensively use Ghidra, GDB, checksec, ROPgadget, and other tools to complete the full process from binary identification to shellcode construction.

---

## Use Cases

1. **CTF Pwn / Reverse Challenges** - Analyze challenge binaries, discover vulnerabilities, and construct exploits to capture flags
2. **Malware Analysis** - Static and dynamic analysis of viruses, trojans, and rootkits; extract IoCs and understand attack behavior
3. **Firmware Security Audit** - Use binwalk to extract embedded device firmware, reverse engineer closed-source components
4. **Vulnerability Research** - Analyze binary differences before and after CVE patches, reconstruct vulnerability causes and write PoCs
5. **Software Supply Chain Verification** - Reverse engineer third-party closed-source dependencies, check for backdoors or unsafe behavior

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **radare2** | Full-featured reverse engineering framework, static/dynamic analysis, script automation | `r2 -A binary && afl \|\| pdf @ main` |
| **ghidra** | NSA open-source reverse engineering platform, decompiler, GUI, headless batch analysis | `analyzeHeadless /tmp project binary` |
| **objdump** | Quick disassembly, ELF/PE structure viewing | `objdump -d -M intel binary` |
| **gdb** | Dynamic debugger, breakpoints, registers, memory inspection | `gdb ./binary && break main && run` |
| **checksec** | Binary security mechanism detection (NX, ASLR, Canary, PIE, RELRO) | `checksec --file=binary` |
| **ROPgadget** | ROP gadget search and chain construction | `ROPgadget --binary binary --ropchain` |
| **binwalk** | Firmware signature identification and extraction | `binwalk -Me firmware.bin` |
| **readelf** | In-depth ELF format analysis (section table, symbol table, relocation) | `readelf -a binary` |
| **strings** | Quick extraction of readable strings for information gathering | `strings -n 8 binary` |

---

## Methodology

### Attack Chain

```
Binary ID           Static Analysis       Dynamic Analysis     Vulnerability Discovery
(file, checksec)  (r2 -A, objdump)     (gdb, r2 -d)        (pattern, fuzz)
     |                 |                 |               |
     v                 v                 v               v
Security Assessment  Exploit Dev         Shellcode          Report & Fix
(ASLR, Canary,     (ROP chain,         (arch adaptation,   (root cause analysis,
 NX, PIE, RELRO)   ret2libc)           encoding bypass)    hardening advice)
```

**Phase Details**:

1. **Binary Identification** - Use `file` to determine architecture and format, `checksec` to assess protection mechanism strength
2. **Static Analysis** - radare2 deep analysis (`aaa`), identify function lists, strings, cross-references, control flow
3. **Dynamic Analysis** - Set breakpoints in GDB/radare2 debug mode, track register and memory state changes
4. **Vulnerability Discovery** - Locate dangerous function calls (`strcpy`/`sprintf`/`printf`), calculate overflow offsets
5. **Exploit Development** - Choose exploitation strategy based on checksec results (ROP, ret2libc, ret2plt)
6. **Shellcode** - Write or adapt shellcode for the target architecture, handle bad characters and encoding

### Defense Perspective

| Protection Mechanism | Function | Bypass Approach |
|---------------------|----------|-----------------|
| **NX (No-eXecute)** | Stack/heap non-executable, prevents direct shellcode execution | ROP, ret2libc, ret2plt |
| **ASLR** | Address space layout randomization, different load addresses each time | Information leakage, partial overwrite, ret2plt |
| **Stack Canary** | Validate stack canary value before function return | Format string leak canary, byte-by-byte brute force |
| **PIE** | Executable base address randomization | Information leak base address, partial overwrite |
| **Full RELRO** | GOT table read-only, prevents GOT overwriting | Target other write destinations (__malloc_hook, __free_hook) |
| **Safe Coding** | Replace dangerous functions with safe alternatives | Eliminate strcpy/sprintf/gets calls at the source |

---

## Practical Steps

> **For detailed commands and payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.** Below is a summary of core operations for each phase.

### 1. radare2 Analysis Workflow

```bash
# Quick analysis mode (recommended for daily use)
r2 -A binary              # Load and auto-analyze (equivalent to aaa)

# Deep analysis mode (complex targets)
r2 -AA binary             # Deeper auto-analysis

# Common analysis commands
afl                       # List all functions
iz                        # Extract all strings (including data segments)
pdf @ sym.main            # Disassemble main function
axt sym.imp.strcpy        # Find all cross-references to strcpy
iS                        # Section table info (.text, .data, .bss)
ii                        # Import function table
VV                        # Visual control flow graph mode

# Debug mode
r2 -d binary              # Load in debugger mode
db main                   # Set breakpoint at main
dc                        # Continue execution
dr                        # Display register state
px @ rsp                  # Inspect stack memory
```

### 2. Buffer Overflow Detection and Offset Calculation

```bash
# Step 1: checksec confirms protection status
checksec --file=binary
#    NX      : disabled    --> Shellcode executable on stack
#    Canary  : disabled    --> No stack protection
#    PIE     : disabled    --> Fixed addresses

# Step 2: radare2 locate dangerous functions
r2 -A binary
afl | grep -E "strcpy|sprintf|gets|read"
pdf @ sym.vulnerable_function
# Observe buffer size and dangerous function calls

# Step 3: Use pattern to calculate offset
# Generate unique pattern (in GDB)
gdb ./binary
pattern_create 200
run $(pattern)
# Observe crash value overwriting RIP/EIP
pattern_offset <crash_value>
```

### 3. ROP Chain Construction

```bash
# Search available gadgets
ROPgadget --binary binary --only "pop|ret"
ROPgadget --binary binary --only "int|ret"

# Auto-generate ROP chain
ROPgadget --binary binary --ropchain

# Search gadgets in radare2
r2 -A binary
/R pop rdi; ret           # Search specific gadget sequence
/R ret                    # Search ret gadget (for stack alignment)

# Common exploitation strategy selection:
# - NX disabled  --> Direct shellcode on stack
# - NX enabled, no ASLR --> ret2shellcode (BSS section)
# - NX + ASLR    --> ret2libc / ROP / ret2plt
```

### 4. radare2 Script Automation

```python
#!/usr/bin/env python3
"""r2pipe automation script - batch vulnerability scanning"""
import r2pipe

def analyze_binary(filepath):
    r2 = r2pipe.open(filepath)
    r2.cmd("aaa")  # Deep analysis

    # Extract key information
    functions = r2.cmd("afl")
    strings = r2.cmd("iz")

    # Scan for dangerous function calls
    dangerous = ["strcpy", "sprintf", "gets", "strcat", "printf"]
    findings = []
    for func in dangerous:
        xrefs = r2.cmd(f"axt sym.imp.{func}")
        if xrefs.strip():
            findings.append({"function": func, "xrefs": xrefs})

    # Check for hidden functions (uncalled symbols)
    all_funcs = r2.cmd("afl~sym.").strip().split("\n")
    # Cross-reference analysis to find orphaned functions

    r2.quit()
    return {"file": filepath, "findings": findings, "functions": functions}
```

### 5. checksec Security Assessment and Exploitation Strategy

```bash
# Complete security assessment
checksec --file=binary --output=json

# Strategy selection based on protection combination:
# +---------+--------+--------+------------------+
# | NX      | ASLR   | Canary | Strategy          |
# +---------+--------+--------+------------------+
# | off     | off    | off    | Direct shellcode   |
# | on      | off    | off    | ret2libc           |
# | on      | on     | off    | ROP + info leak    |
# | on      | on     | on     | Leak + ROP         |
# +---------+--------+--------+------------------+

# Verify ASLR status
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled, 1 = partial randomization, 2 = full randomization

# Compile unprotected binary (for practice)
gcc -o target target.c -fno-stack-protector -z execstack -no-pie
```

---

## Hacker Laws

| Law | Manifestation in Binary Reverse Engineering |
|------|---------------------------------------------|
| **First Principles** | Do not rely on black-box tool output; understand the semantics of each assembly instruction. Understanding calling conventions is necessary to correctly trace parameters; understanding memory layout is necessary to precisely calculate offsets |
| **Divergent Thinking First** | When conventional exploitation paths are blocked, seek alternative attack surfaces: GOT overwriting, __malloc_hook, .dtors, vtable hijacking, one_gadget |
| **Trust but Verify** | Decompiler output may be inaccurate; cross-validate radare2 and Ghidra results. checksec reports also need practical verification that protections are actually effective |
| **Skill Over Credentials** | CTF rankings and CVE counts reflect practical ability better than certifications. The core of binary analysis is the intuition and pattern recognition formed through extensive practice |

---

## Automation and Scripting

Automated binary analysis pipelines drastically reduce manual effort when assessing large numbers of binaries. r2pipe enables Python-driven batch scanning that can process entire firmware images or package collections, flagging dangerous function calls and missing protections automatically. Combining radare2 scripting with Ghidra headless analysis creates a powerful hybrid pipeline where radare2 handles rapid triage and Ghidra performs deep decompilation on candidates that warrant closer inspection.

## Common Pitfalls

A frequent mistake in binary exploitation is relying solely on decompiler output without cross-referencing assembly — decompilers often misrepresent pointer arithmetic, union types, and optimized loops. Another common error is neglecting to verify ASLR status at runtime (not just at compile time), since some distributions disable ASLR for specific binaries via `personality` flags. Always confirm protection status with `checksec` and `/proc/sys/kernel/randomize_va_space` simultaneously before committing to an exploitation strategy.

## Detection Methods

Identifying vulnerable binaries requires systematic pattern recognition across multiple dimensions. String analysis (`strings -n 8`) reveals hardcoded paths, credentials, and format strings that may be exploitable. Symbol table inspection (`readelf -s`, `nm`) exposes dangerous imported functions like `strcpy`, `system`, and `sprintf`. Cross-reference analysis in radare2 (`axt @ sym.imp.strcpy`) maps every call site, enabling prioritized review of the most dangerous functions first.

---

## Learning Resources

**Supplementary files for this skill**:
- `payloads.md` — Complete command and payload collection (10 major phases, ready to copy and use)
- `test-cases.md` — Structured test cases (11 case templates with preconditions and expected results)

**Extended learning materials (guides/)**:
- `guides/Binary_Analysis_Reverse_Engineering_Story.md` - radare2 complete learning path from beginner to expert level

**Related skills**:
- `skills/web-sqli/SKILL.md` — SQL injection (web-side data extraction, complementary to binary reverse engineering)
- `skills/web-auth-bypass/SKILL.md` — Authentication bypass (auxiliary reference when reverse engineering authentication protocols)

**External resources**:
- [Nightmare](https://guyinatuxedo.github.io/) - CTF binary exploitation step-by-step tutorial (stack overflow to ROP)
- [pwn.college](https://pwn.college/) - ASU University open-source binary exploitation lab platform
- [radare2 Official Documentation](https://book.rada.re/) - radare2 Book, command and script API reference
- [CTF Wiki - Pwn](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/) - Chinese CTF binary exploitation knowledge base
