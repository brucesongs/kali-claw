# Binary Reverse Engineering Test Cases

> This file is a companion to `SKILL.md`, providing structured binary analysis test case templates.
> Purpose: Check each item during penetration testing or CTF competitions to ensure no critical analysis steps are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments and CTF competitions.

---

## Test Case Format

```
TC-BXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. Binary Identification & Assessment](#a-binary-identification--assessment)
- [B. Vulnerability Discovery](#b-vulnerability-discovery)
- [C. Exploit Development](#c-exploit-development)
- [D. Defense Bypass & Advanced Techniques](#d-defense-bypass--advanced-techniques)

---

## A. Binary Identification & Assessment

### TC-B001 | Binary File Type and Architecture Identification

- **Severity**: HIGH
- **Prerequisites**: Obtained target binary file
- **Test Steps**:
  1. `file binary` determine file format (ELF/PE/Mach-O), architecture (x86/ARM/MIPS), bit width (32/64)
  2. `readelf -h binary` confirm entry point and detailed architecture information
  3. `strings -n 8 binary | grep -iE "flag|pass|key|/bin/sh"` extract key strings
  4. `nm binary 2>/dev/null` check symbol table (whether stripped)
- **Expected Results**: Clearly identify target architecture, format, stripped status, selecting toolchain for subsequent analysis
- **Reference**: payloads.md §1 Binary Identification & Assessment

### TC-B002 | Security Mechanism Detection (checksec)

- **Severity**: CRITICAL
- **Prerequisites**: Binary format confirmed
- **Test Steps**:
  1. `checksec --file=binary` detect NX/ASLR/Canary/PIE/RELRO
  2. `readelf -l binary | grep GNU_STACK` manually verify NX
  3. `cat /proc/sys/kernel/randomize_va_space` check system ASLR
  4. Determine exploitation strategy based on protection combination:
     - NX off + ASLR off -> Direct Shellcode
     - NX on + ASLR off -> ret2libc
     - NX on + ASLR on -> ROP + Information Leak
     - All enabled -> Leak Canary + Leak Base Address + ROP
- **Expected Results**: Output protection mechanism matrix, clarify viable exploitation paths
- **Reference**: payloads.md §1 Security Mechanism Detection

---

## B. Vulnerability Discovery

### TC-B003 | Dangerous Function Call Localization

- **Severity**: CRITICAL
- **Prerequisites**: Binary loaded into radare2 with auto-analysis complete
- **Test Steps**:
  1. `r2 -A binary` load and analyze
  2. `axt sym.imp.strcpy` search all strcpy calls
  3. `axt sym.imp.sprintf` search sprintf calls
  4. `axt sym.imp.gets` search gets calls
  5. `axt sym.imp.printf` search printf calls (format string)
  6. For each dangerous call, execute `pdf @ caller_func` to analyze buffer size and bounds checking
- **Expected Results**: Locate all dangerous function calls without bounds checking -> Potential buffer overflow/format string vulnerabilities
- **Reference**: payloads.md §2 Cross-References

### TC-B004 | Buffer Overflow Offset Calculation

- **Severity**: CRITICAL
- **Prerequisites**: Located target functions containing dangerous function calls
- **Test Steps**:
  1. `pdf @ sym.vulnerable_func` analyze buffer size (e.g., `char buf[64]`)
  2. Use GDB pattern_create to generate unique pattern
  3. Run program with pattern input, trigger crash
  4. `pattern_offset <RIP/EIP_value>` calculate exact offset
  5. Verify: construct `A*offset + B*8 + DEADBEEF`, confirm RIP is controllable
- **Expected Results**: Precisely determine offset from buffer to return address -> EIP/RIP fully controllable
- **Reference**: payloads.md §4 Buffer Overflow Offset Calculation

### TC-B005 | Format String Vulnerability Verification

- **Severity**: HIGH
- **Prerequisites**: Binary contains `printf(user_input)` type calls
- **Test Steps**:
  1. Input `%p.%p.%p.%p` observe if stack data is leaked
  2. Input `AAAA%1$x.%2$x...%10$x` find format string offset on stack
  3. Input `%x.%x` confirm 32-bit or 64-bit leak format
  4. Verify `%n` write capability (if allowed)
- **Expected Results**: Format string offset determined -> Can leak/write arbitrary addresses
- **Reference**: payloads.md §8 Format String Exploitation

---

## C. Exploit Development

### TC-B006 | Shellcode Injection and Execution

- **Severity**: CRITICAL
- **Prerequisites**: NX disabled, EIP/RIP controllable, can jump to Shellcode address
- **Test Steps**:
  1. Determine writable executable region (stack/BSS/heap)
  2. Use `shellcode_test.c` framework to test Shellcode
  3. Generate bad character list and detect filtered bytes
  4. Construct payload: `padding + shellcode_address + NOP_sled + shellcode`
  5. Or use `padding + jmp_esp + shellcode` (if stack address uncertain)
- **Expected Results**: Successfully obtain shell -> Shellcode exploitation confirmed
- **Reference**: payloads.md §5 Shellcode Construction

### TC-B007 | ret2libc Exploitation

- **Severity**: CRITICAL
- **Prerequisites**: NX enabled, ASLR disabled or libc base leaked, system() available
- **Test Steps**:
  1. `readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system` confirm system address
  2. `strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh` confirm "/bin/sh" address
  3. Construct 64-bit payload: `padding + pop_rdi_gadget + binsh_addr + system_addr`
  4. If crash inside system, add ret gadget for stack alignment
  5. Use one_gadget to quickly test viable constraint addresses
- **Expected Results**: Obtain shell via ret2libc -> Bypass NX
- **Reference**: payloads.md §7 ret2libc/ret2plt Exploitation

### TC-B008 | ROP Chain Construction

- **Severity**: CRITICAL
- **Prerequisites**: NX + ASLR enabled, libc base leaked or not needed
- **Test Steps**:
  1. `ROPgadget --binary binary --only "pop|ret"` search gadgets
  2. `ROPgadget --binary binary --ropchain` attempt auto-generation
  3. Manually construct ROP chain (e.g., execve syscall):
     - pop rdi; ret -> set rdi = "/bin/sh"
     - pop rsi; pop r15; ret -> set rsi = 0
     - pop rdx; ret -> set rdx = 0 (or use libc gadget)
     - pop rax; ret -> set rax = 59
     - syscall
  4. Add ret gadget to resolve stack alignment issues
- **Expected Results**: ROP chain executes successfully -> Bypass NX + ASLR
- **Reference**: payloads.md §6 ROP Chain Construction

### TC-B009 | ret2plt Information Leak

- **Severity**: HIGH
- **Prerequisites**: ASLR enabled, PLT/GOT present, puts/printf available
- **Test Steps**:
  1. `readelf -r binary` confirm puts entry in GOT table
  2. Construct payload1: `padding + pop_rdi + puts_got + puts_plt + main_addr`
  3. Send payload1, receive leaked puts runtime address
  4. Calculate libc_base = leaked_puts - libc.symbols['puts']
  5. Construct payload2 using leaked real addresses for ret2libc
- **Expected Results**: Successfully leak libc base -> Second-stage exploitation to obtain shell
- **Reference**: payloads.md §7 ret2libc/ret2plt Exploitation

---

## D. Defense Bypass & Advanced Techniques

### TC-B010 | Stack Canary Leak Bypass

- **Severity**: HIGH
- **Prerequisites**: Canary enabled, format string vulnerability or information leak exists
- **Test Steps**:
  1. Leak Canary value on stack via format string (typically ends with \x00)
  2. Or brute force Canary byte by byte (fork server mode, child crash does not affect parent)
  3. Fill leaked Canary value at correct position in overflow payload
  4. Verify: payload passes Canary check then reaches return address overwrite
- **Expected Results**: Bypass Canary check -> Successfully overwrite return address
- **Reference**: payloads.md §8 Format String Leak Canary

### TC-B011 | Firmware Security Audit

- **Severity**: HIGH
- **Prerequisites**: Obtained target device firmware file
- **Test Steps**:
  1. `binwalk firmware.bin` scan signatures and filesystem offsets
  2. `binwalk -Me firmware.bin` recursively extract filesystem
  3. Find sensitive configuration files: `find . -name "*.conf" -o -name "shadow" -o -name "passwd"`
  4. Analyze binary components: `checksec --file=./bin/httpd` + `strings ./bin/httpd | grep "cmd|system"`
  5. Find hardcoded credentials: `grep -r "password|admin|root" ./etc/`
  6. Use qemu to emulate key components and verify vulnerabilities
- **Expected Results**: Extract filesystem and discover hardcoded credentials/unprotected binaries -> Firmware security risk
- **Reference**: payloads.md §10 Firmware Extraction & Analysis

---

## Test Case Statistics

| Category | Cases | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| A. Binary Identification & Assessment | 2 | 1 | 1 | 0 | 0 |
| B. Vulnerability Discovery | 3 | 2 | 1 | 0 | 0 |
| C. Exploit Development | 4 | 3 | 1 | 0 | 0 |
| D. Defense Bypass & Advanced Techniques | 2 | 0 | 2 | 0 | 0 |
| **Total** | **11** | **6** | **5** | **0** | **0** |
