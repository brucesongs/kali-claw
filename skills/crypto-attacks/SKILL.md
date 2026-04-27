# Skill: Cryptographic Attacks

> **Supplementary Files**:
> - `payloads.md` — Cryptographic attack payload collection: weak algorithm detection, hash cracking, Padding Oracle, Hash Length Extension, ECB mode, JWT attacks, RSA attacks, SSL/TLS test commands
> - `test-cases.md` — Structured test cases: complete test checklist covering cryptographic detection, hash cracking, protocol attacks, JWT attacks, and advanced techniques

## Description

Cryptographic Attacks target implementation flaws and algorithm weaknesses in encryption systems, covering OWASP A04: Cryptographic Failures. Attackers do not break mathematical problems; instead, they exploit engineering implementation errors: weak algorithm remnants (RC4/DES/MD5/SHA1), key management mistakes (hardcoded/reused/non-rotated), encryption mode misuse (ECB/Padding Oracle/IV Reuse), protocol downgrade (SSLv3/TLS 1.0), and missing signature verification (JWT alg:none/Algorithm Confusion).

**Core Insight**: The mathematical foundations of modern cryptography are robust — attackers almost never "break encryption algorithms" but rather "break how encryption is used." A rule of thumb: if you feel like you are attacking the math, you are probably heading in the wrong direction; instead, look for who wrote the key in the code, which IV is fixed, which service still accepts SSLv3.

**Key Attack Surfaces**:

- **Weak Algorithms**: RC4 (fully broken), DES (56-bit brute forceable), MD5/SHA1 (collision attacks), Blowfish (64-bit block)
- **Key Management Flaws**: Hardcoded keys, fixed IVs, key reuse, no key rotation, keys stored in source code/config files
- **Padding Oracle**: Server returns different responses for decryption padding errors, allowing attackers to recover plaintext byte by byte without the key
- **Hash Length Extension**: Hash functions based on Merkle-Damgard construction (SHA-1/MD5) allow appending data to MAC without knowing the key
- **SSL/TLS Vulnerabilities**: POODLE (SSLv3), BEAST (TLS 1.0 CBC), Heartbleed (OpenSSL), certificate verification bypass

---

## Use Cases

1. **Web Application Encryption Audit** - Detect HTTPS configuration flaws, cookie encryption weaknesses, missing API signature verification, sensitive data transmitted in plaintext
2. **JWT / Token Security Testing** - Algorithm confusion attacks (RS256 -> HS256), alg:none bypass, key brute force, payload tampering
3. **CTF Cryptography Challenges** - Quickly identify encryption modes (ECB/CBC/CTR), known plaintext attacks, Padding Oracle, hash extension attacks
4. **Data Breach Assessment** - Analyze whether leaked data uses weak encryption, assess cracking feasibility (hash type/salt/iterations)
5. **TLS/SSL Configuration Hardening** - Scan server-supported protocol versions, cipher suites, certificate chain validity

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **openssl** | Certificate analysis, protocol testing, encryption/decryption operations | `openssl s_client -connect target:443 -tls1` |
| **sslscan** | Quick TLS configuration scan, detect supported protocols and cipher suites | `sslscan target.com` |
| **testssl.sh** | Comprehensive SSL/TLS security audit, 200+ checks | `testssl.sh --full target.com` |
| **hashcat** | Offline hash cracking (including JWT key brute force mode 16500) | `hashcat -m 16500 jwt.txt rockyou.txt` |
| **CyberChef** | Encoding/decoding/encryption/hashing online analysis (identify unknown encodings) | Browser tool, drag-and-drop operation |
| **padbuster** | Automated Padding Oracle attacks | `padbuster URL ENC_BLOCK 8` |

Auxiliary tools: **hash-identifier** (hash type identification), **htlea** (Hash Length Extension), **RsaCtfTool** (RSA attack collection), **jwt_tool** (full JWT testing workflow).

---

## Methodology

### Attack Chain

```
[1] Crypto ID            [2] Algorithm Analysis    [3] Key/IV Attacks
  - Protocol version       - Weak algorithm detect   - Hardcoded key search
  - Cipher suite enum      - Block size/mode detect  - IV predictability
  - Hash type ID           - Key length assessment   - Key reuse detection
  - Token format parse     - Padding mode analysis   - ECB mode detection
       |                        |                        |
       v                        v                        v
[4] Protocol Downgrade    [5] Data Decryption       [6] Signature Bypass
  - TLS version downgrade   - Padding Oracle          - JWT alg:none
  - Cipher suite downgrade  - Known plaintext attack  - Algorithm Confusion
  - Forward secrecy test    - Bit flipping attack     - Key brute force
  - Cert chain validation   - Hash extension attack   - Replay attacks
```

### Defense Perspective

| Defense Measure | Description | Attack Types Countered |
|-----------------|-------------|----------------------|
| AES-256-GCM / ChaCha20-Poly1305 | Authenticated encryption (AEAD), ensures both confidentiality and integrity | ECB/CBC mode attacks, Padding Oracle |
| TLS 1.3 Only | Disable old protocols, enforce forward secrecy (PFS) | POODLE/BEAST/protocol downgrade |
| Key Management (KMS/HSM) | Keys never touch source code, hardware-isolated storage | Hardcoded keys, key leakage |
| PBKDF2/bcrypt/argon2id | Slow hashing + salt, increases offline cracking cost | Hash cracking, rainbow tables |
| JWT Security Practices | Algorithm allowlist + short expiration + strong keys + token blacklist | alg:none / Algorithm Confusion |
| Certificate Pinning | Pin expected certificates/public keys, prevent MITM | Forged certificates, MITM |

---

## Practical Steps

### 1. Crypto Identification Phase

```bash
# SSL/TLS protocol scanning
testssl.sh --protocols target.com
sslscan target.com | grep -E "SSLv3|TLS 1.0|TLS 1.1"

# Hash type identification
hash-identifier
# Or: hashcat --identify hash.txt
```

### 2. Algorithm Analysis and Key Attacks

```bash
# Padding Oracle attack
padbuster http://target/page?data=ENC ENC 8 -encoding 0 -plaintext "admin=true"

# ECB mode detection: Submit repeated plaintext, observe ciphertext block repetition
# IV Reuse: Encrypt same plaintext twice, compare ciphertexts
```

### 3. Signature Bypass and Token Attacks

```bash
# JWT alg:none bypass
python3 jwt_tool.py <TOKEN> -X a

# JWT Algorithm Confusion (RS256 -> HS256)
python3 jwt_tool.py <TOKEN> -I -at HS256 -pc role -pv admin -k public_key.pem

# JWT key brute force
hashcat -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt
```

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.**

---

## Hacker Laws

1. **Obscurity Is Not Security** -- Relying on hidden algorithms, custom encryption, or secret IVs to protect data is the biggest trap. Kerckhoffs' principle: security should depend only on the secrecy of the key, not the secrecy of the algorithm. Homemade encryption algorithms are almost certainly weaker than AES.

2. **First Principles** -- Understanding the design principles of cryptographic primitives is more important than memorizing attack steps. Padding Oracle works because the server leaks a 1-bit piece of information: "whether the padding is valid." Understanding this, you can find similar information leaks in any implementation.

3. **Defense in Depth** -- Single-layer encryption is not enough. TLS protects transmission + AES-256-GCM protects storage + HMAC protects integrity + HSM protects keys. No single point of failure should lead to total collapse.

---

## Learning Resources

  **Supplementary files for this skill**: payloads.md, test-cases.md
  **Related skills**: skills/web-auth-bypass/SKILL.md, skills/password-attack/SKILL.md
  **External resources**:
  - **Workspace internal materials**: `guides/cryptographic_failures_complete_guide.md` -- Complete OWASP A04 guide with weak algorithm attacks, ECB/Padding Oracle/IV Reuse attacks, JWT tampering, and complete offensive and defensive code for key management
  - **PortSwigger Crypto Lab**: https://portswigger.net/web-security/cryptography -- Systematic cryptographic attack labs
  - **Cryptopals**: https://cryptopals.com/ -- 8 sets of cryptography programming challenges, from basic to advanced
  - **testssl.sh GitHub**: https://github.com/drwetter/testssl.sh -- TLS/SSL security scanning tool
  - **JWT.io**: https://jwt.io/ -- Online JWT decoding and analysis
  - **HackTricks - Crypto**: https://book.hacktricks.xyz/crypto -- Cryptographic attack quick reference
