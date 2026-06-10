---
name: crypto-attacks
description: "Cryptographic Attacks target implementation flaws and algorithm weaknesses in encryption systems, covering OWASP A04: Cryptographic Failures."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: cryptography
  tool_count: 7
  guide_count: 5
  owasp: "A04:2021-Cryptographic Failures"
---




# Skill: Cryptographic Attacks

> **Supplementary Files**:
> - `payloads.md` — Cryptographic attack payload collection: weak algorithm detection, hash cracking, Padding Oracle, Hash Length Extension, ECB mode, JWT attacks, RSA attacks, SSL/TLS test commands
> - `test-cases.md` — Structured test cases: complete test checklist covering cryptographic detection, hash cracking, protocol attacks, JWT attacks, and advanced techniques

## Summary

Crypto Attacks skill domain covering cryptography operations.

**Tools**: openssl, sslscan, testssl.sh, hashcat, CyberChef, padbuster, RsaCtfTool

**Domain**: cryptography

**OWASP**: A04:2021-Cryptographic Failures

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

## Common Pitfalls

- **Assuming encryption means security**: Encryption that uses AES-256 but with a hardcoded IV or ECB mode is trivially breakable. Always verify the complete cryptographic configuration — algorithm, mode, key management, IV handling — not just the algorithm name.
- **Neglecting to check for key rotation**: Many systems generate a single encryption key at deployment and never rotate it. A key leaked through a single code repository commit compromises all data encrypted with that key since the system was deployed.
- **Overlooking JWT in non-obvious locations**: JWTs are used in cookies, Authorization headers, URL parameters, and WebSocket upgrade requests. Testing only one transport mechanism misses attack surface.

## Automation and Scripting

Automate TLS configuration scanning by running testssl.sh with the `--json` output flag and piping results into a comparison script that flags deviations from security baselines. Use hashcat in benchmark mode (`hashcat -b`) to measure GPU cracking throughput before launching long-running cracking jobs. Script Padding Oracle attacks with padbuster's batch mode and custom Python wrappers that automate the byte-by-byte decryption loop with retry logic for network errors.

## Reporting and Documentation

Cryptographic findings should be mapped to OWASP A04:2021 (Cryptographic Failures) and include the specific misconfiguration discovered (e.g., "TLS 1.0 enabled with CBC cipher suite" rather than "weak encryption"). Document the full attack chain from discovery to impact: how the weak configuration was identified, what data could be decrypted or tampered with, and the estimated effort to exploit. Include specific remediation with library-specific configuration examples (e.g., OpenSSL cipher string, node.js TLS options).

## Legal and Ethical Considerations

Testing SSL/TLS configurations against production servers is generally permissible but be cautious with aggressive scanning that could trigger DoS conditions. Testing `Heartbleed` or similar memory-disclosure vulnerabilities on production systems may expose other users' sensitive data — use dedicated test environments when possible. Never store intercepted SSL private keys or decrypted session data beyond what is needed for the engagement report, and always verify that cryptographic testing is included in the scope of authorization.

## Integration with Other Tools

Cryptographic attack findings feed directly into several adjacent skills. Weak TLS configurations discovered through testssl.sh inform network-pentest MITM attack planning. JWT vulnerabilities (alg:none, key brute force) connect to web-auth-bypass for authentication exploitation. Hash cracking results from hashcat feed into password-attack workflows for credential stuffing. Use burpsuite to intercept and replay JWT tampering payloads against authenticated API endpoints, combining crypto analysis with web application testing.

## Case Studies and Examples

- **JWT algorithm confusion**: A web application used RS256 (asymmetric) for JWT signing. An attacker obtained the public key from the `/jwks.json` endpoint, then forged a token signed with HS256 using the public key as the HMAC secret. The server accepted the forged token because it trusted the key without verifying the algorithm, granting admin access.
- **Padding Oracle in payment gateway**: An e-commerce platform's payment callback URL returned different HTTP status codes for valid versus invalid padding. Using padbuster, the attacker decrypted the encrypted order ID parameter, modified the amount to zero, and re-encrypted it — purchasing items for free.
- **Heartbleed memory dump**: During a TLS security audit, the Heartbleed vulnerability was confirmed on a legacy load balancer. The memory dump contained database connection strings with plaintext credentials, enabling full database compromise through the cryptographic implementation flaw.

## Detection and Evasion

Defenders can detect cryptographic attacks through several indicators: unusual TLS negotiation patterns (downgrade attempts logged by the server), repeated decryption errors in application logs (Padding Oracle attempts), JWT validation failures with algorithm mismatches, and anomalous hash cracking activity (high GPU utilization on compromised machines). Monitor certificate transparency logs for unauthorized certificate issuance. To evade detection during testing: spread JWT brute force attempts across multiple API endpoints, use timing delays in Padding Oracle attacks to avoid triggering rate limits, and test TLS downgrade resistance through a single well-crafted ClientHello rather than a noisy scan. For hash cracking, offload to dedicated GPU rigs outside the target network.

## Advanced Techniques

Beyond the core attacks, advanced cryptographic testing includes: RSA key recovery from partial key exposure (known bits of p or q), Bleichenbacher attacks against PKCS#1 v1.5 padding in RSA encryption, BEAST and Lucky13 attacks against TLS CBC cipher suites, hash length extension attacks against SHA-256 and SHA-512 (not just MD5/SHA1), and cryptographic side-channel attacks using timing analysis to extract secrets. For CTF challenges, practice with RsaCtfTool for automated RSA attack selection and CyberChef for rapid encoding/decoding chain prototyping.

## Tool Comparison Matrix

| Tool | Best For | Speed | Coverage | Skill Level |
|------|----------|-------|----------|-------------|
| **testssl.sh** | Comprehensive TLS auditing | Moderate | Very broad | Beginner |
| **sslscan** | Quick protocol/cipher check | Fast | Broad | Beginner |
| **hashcat** | GPU hash/JWT cracking | Very fast | 300+ hash types | Intermediate |
| **padbuster** | Padding Oracle automation | Slow (network-bound) | Narrow | Intermediate |
| **CyberChef** | Encoding/decoding analysis | N/A (manual) | Very broad | Beginner |
| **RsaCtfTool** | RSA attack collection | Variable | RSA-specific | Advanced |

## Performance and Remediation

GPU-accelerated cracking with hashcat can achieve billions of MD5 hashes per second on modern hardware, but performance drops dramatically for memory-hard algorithms like bcrypt (thousands per second) and argon2id (hundreds per second). Choose attack modes based on target hash type: dictionary + rules for fast hashes, targeted dictionaries with custom mutations for slow hashes. For TLS scanning, testssl.sh performs 200+ checks but takes 5-10 minutes per host. Prioritize cryptographic remediation by replacing the weakest components first: disable SSLv3 and TLS 1.0/1.1 immediately, migrate from CBC mode to GCM/ChaCha20-Poly1305, enforce TLS 1.3 where possible, and implement proper key management using HSMs or cloud KMS services. For JWT security, enforce algorithm allowlists, use short token lifetimes, and rotate any exposed keys.

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
