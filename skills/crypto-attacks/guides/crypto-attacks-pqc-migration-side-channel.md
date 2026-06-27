# Post-Quantum Cryptography Migration and Side-Channel Analysis Guide

> A practitioner guide to NIST PQC standardization (ML-KEM / ML-DSA / SLH-DSA / FN-DSA), hybrid and TLS 1.3 post-quantum deployment, and physical side-channel analysis (SPA / DPA / timing / EM / cache-timing) of cryptographic implementations. Covers lab setup on STM32 with ChipWhisperer, OQS-OpenSSL handshake simulation, and references to real-world research (KyberSlash, Injecting Crystals, Crystal-Slinger, GROUNDTRUTH).

---

## 0. Scope, Threat Model, and Reading Map

This guide targets two converging concerns that are now mandatory for any Distinguished-tier crypto assessment:

1. **Post-Quantum Cryptography (PQC) migration** -- the multi-year industry transition away from RSA/ECC toward lattice- and hash-based algorithms standardized by NIST (FIPS 203/204/205). The threat is not a working quantum computer today, but the **"harvest now, decrypt later"** (HNDL) adversary who records long-lived ciphertexts now and decrypts them when a cryptographically relevant quantum computer (CRQC) appears.
2. **Side-channel analysis (SCA)** -- physical and microarchitectural leakage of secret-dependent operations, the most common root cause of real-world breaks of mathematically sound algorithms (Padding Oracle is in fact a side channel; Heartbleed is a memory side channel; Spectre/Meltdown are cache-timing side channels).

**Reading map**:

| If you are working on... | Read sections |
|--------------------------|---------------|
| A PQC algorithm deep-dive | 1, 2, 3, 4 |
| A TLS / X.509 / hybrid deployment audit | 5, 6, 7 |
| Power / EM / timing lab work | 8, 9, 10, 11, 14 |
| PQC-specific implementation attacks | 12 |
| Tooling and lab bring-up | 13, 14 |
| Reporting and remediation | 15, 16 |

**Threat model scope**: this guide covers black-box and gray-box assessment of deployed cryptographic implementations, lab evaluation of reference software, and review of cryptographic agility posture. It does **not** cover design of new PQC primitives, formal verification of constant-time assembly, or nation-state TEMPEST collection.

---

## 1. Quantum Threat Primer and Why PQC Now

### 1.1 Shor's Algorithm -- the Existential Threat

Shor's algorithm (1994) solves integer factorization and discrete logarithm in polynomial time on a fault-tolerant quantum computer. This breaks:

- **RSA** (integer factorization -- 2048-bit RSA falls to ~4096 logical qubits with millions of physical qubits for error correction)
- **ECDSA / ECDH** (elliptic-curve discrete logarithm -- 256-bit curves fall to ~2330 logical qubits)
- **DH / DHE** (finite-field discrete logarithm)

Grover's algorithm (1996) provides a quadratic speedup on unstructured search, reducing the effective security of symmetric primitives:

- AES-256 -> ~128-bit post-quantum security (still strong)
- AES-128 -> ~64-bit post-quantum security (marginal)
- SHA-256 -> ~128-bit collision resistance post-quantum (still strong)

**Practical implication**: Shor's algorithm is the existential threat to public-key cryptography; Grover only forces a doubling of symmetric key lengths, which is largely solved by AES-256.

### 1.2 The "Harvest Now, Decrypt Later" Adversary

The HNDL threat justifies action **before** a CRQC exists:

- TLS 1.3 traffic captured today protects ephemeral ECDH only via forward secrecy -- but if the peer's long-term ECDSA signing key is later recovered (or if PFS was not deployed), the captured handshake can be reconstructed and the recorded session key recovers all application data.
- Stored encrypted archives (backups, diplomatic cables, PKI-encrypted blobs) with multi-decade confidentiality requirements are already at risk.

Conservative guidance: any data with a confidentiality lifetime of 10+ years (medical records, state secrets, infrastructure SCADA keys) must be PQC-protected **today**.

### 1.3 Cryptographically Relevant Quantum Computer (CRQC) Timeline

The NIST PQC standardization process (2016-2024) was launched without consensus on the CRQC arrival date. Surveys of experts (Global Risk Institute, 2023-2024) place a 50%+ chance of a CRQC within 10-25 years. Migration itself takes 5-15 years for large enterprises. Therefore:

```
[Today] ----[5-15y migration window]----> [Possible CRQC] ----[HNDL window closes]
   |                                            |
   v                                            v
Pilot -> Production PQC              Classical ciphertexts become plaintext
```

The migration lead time, not the quantum hardware timeline, is the binding constraint.

---

## 2. NIST PQC Standardization Landscape

### 2.1 The Four Standards (2024)

After three rounds of public evaluation (2017-2022) and a follow-on round for digital signature diversification, NIST finalized:

| Standard | Algorithm | Origin Proposal | Family | Purpose | Parameters |
|----------|-----------|-----------------|--------|---------|------------|
| **FIPS 203** | ML-KEM | CRYSTALS-Kyber | Module Lattice (M-LWE) | Key Encapsulation Mechanism (KEM) | 512 / 768 / 1024 |
| **FIPS 204** | ML-DSA | CRYSTALS-Dilithium | Module Lattice (M-LWE) | Digital Signature | 44 / 65 / 87 |
| **FIPS 205** | SLH-DSA | SPHINCS+ | Hash-based (Few-time / Winternitz) | Digital Signature (stateless) | 128s/128f/192s/192f/256s/256f |
| **FIPS 203 draft follow** | FN-DSA | FALCON | NTRU Lattice (short integer solution) | Digital Signature (compact) | 512 / 1024 |

ML-KEM and ML-DSA are the workhorses: Kyber for key exchange, Dilithium for signatures. SPHINCS+ is the conservative hash-based fallback (very large signatures, 7-49 KB, but security rests only on SHA-2/SHAKE). Falcon was added for size-critical contexts (small signatures ~600-1300 bytes) but has a complex floating-point signing procedure that creates side-channel headaches.

### 2.2 ML-KEM (Kyber / FIPS 203) Internals

ML-KEM is built on the Module Learning-With-Errors (M-LWE) problem. A severely simplified view:

```
Public:    A (random k x k matrix over ring R_q), t = A*s + e
Secret:    s, e (small noise polynomials in R_q)
Encap:     r, e1, e2 (small); u = A^T * r + e1; v = t^T * r + e2 + m * q/2
           ciphertext = (u, v); shared_secret = v - s^T * u ≈ m * q/2
Decap:     m recovered by rounding v - s^T * u
```

Concrete parameter sizes for ML-KEM-768 (the intended TLS default):

| Quantity | Size |
|----------|------|
| Public key | 1184 bytes |
| Secret key | 2400 bytes |
| Ciphertext | 1088 bytes |
| Shared secret | 32 bytes |
| Claimed security | NIST Level 3 (AES-192 equivalent) |

Key implementation detail for assessors: the **compression / rounding step** (`Compress` / `Decompress` in FIPS 203, section 4) is the source of nearly all Kyber side-channel leaks -- it makes arithmetic secret-dependent in a way that constant-time coding can only partially hide.

### 2.3 ML-DSA (Dilithium / FIPS 204) Internals

Dilithium signs via Fiat-Shamir with aborts on M-LWE. Each signature involves:

1. Sample a masking polynomial `y`
2. Compute `w = A*y` (high-dim product)
3. Compute hint `h` from `w` and the secret
4. Compute response `z = y + c*s1` -- **reject if `z` leaks the secret mask**

The **rejection sampling loop** is the key side-channel target: the number of iterations leaks information about the secret unless carefully blinded. FIPS 204 mandates deterministic signing (no random nonce), which simplifies some attacks (repeatable) but defeats others (no nonce reuse).

Signature sizes (ML-DSA-65, Level 3): public key 1952 bytes, signature ~3300 bytes -- roughly 10x RSA-3072 signatures.

### 2.4 SLH-DSA (SPHINCS+ / FIPS 205) Internals

SPHINCS+ is a stateless hash-based signature combining:

- WOTS+ (Winternitz one-time signatures) for leaf signing
- FORS (Forest of Random Subsets) few-time signatures for authentication
- Hypertree (Merkle trees of Merkle trees) for stateless public-key derivation

The advantage: **security reduces to the underlying hash function** (SHA-2 or SHAKE). The disadvantage: signatures are 7-49 KB (versus ~3 KB for Dilithium) and signing is 100x-1000x slower. Practical use: root CA signing, firmware signing -- rare, high-value signatures where signature size is not a constraint.

### 2.5 FN-DSA (Falcon / Draft FIPS)

Falcon signs on the NTRU lattice using a Gaussian sampler over the floating-point FFT representation. The sampler is the side-channel soft spot -- it has historically required careful constant-time implementation. Falcon produces the smallest PQC signatures (~666 bytes at Level 1, ~1273 bytes at Level 5), making it the preferred choice for bandwidth-constrained protocols (DNSSEC, BLE, embedded firmware update).

---

## 3. PQC Algorithm Comparison Matrix

### 3.1 Performance and Size Comparison (Level 3 ≈ AES-192 security)

| Algorithm | Type | PubKey | Signature / CT | Sign / Encap time | Verify / Decap time | Notes |
|-----------|------|--------|----------------|-------------------|---------------------|-------|
| RSA-3072 (classical) | Sig | 384 B | 384 B | 1 ms | 0.1 ms | Baseline |
| ECDSA P-384 (classical) | Sig | 49 B | 96 B | 0.5 ms | 1 ms | Baseline |
| **ML-KEM-768** | KEM | 1184 B | 1088 B | N/A | N/A | Encap/decap ~0.05 ms each |
| **ML-DSA-65** | Sig | 1952 B | 3293 B | 1.5 ms | 0.5 ms | Fastest lattice sig |
| **SLH-DSA-192s** | Sig | 768 B | 16224 B | 100s ms | tens ms | Conservative |
| **FN-DSA-1024** | Sig | 1792 B | ~1273 B | ~3 ms | ~0.3 ms | Smallest PQ sig; complex impl |

### 3.2 Bandwidth Impact on Protocols

The bandwidth impact is the single biggest protocol-engineering problem of PQC migration:

| Protocol | Classical handshake bytes | Hybrid (X25519 + ML-KEM-768) | Pure PQ (ML-KEM-768) |
|----------|---------------------------|-------------------------------|----------------------|
| TLS 1.3 full | ~5 KB | ~7 KB | ~7 KB |
| TLS 1.3 resumption | ~1 KB | ~1.5 KB | ~1.5 KB |
| IKEv2 (IPsec) | ~2 KB | ~5 KB | ~5 KB |
| SSH | ~2 KB | ~5 KB | ~5 KB |
| DNSSEC (per RR) | ~100 B | N/A | ~17 KB (SLH-DSA) / ~1.3 KB (Falcon) |
| X.509 cert chain (3-deep) | ~3 KB | ~10 KB | ~10-50 KB |

MTU-fragmentation issues in TLS, DNSSEC UDP fallback, and certificate chain bloat are first-order migration concerns.

### 3.3 Performance on Constrained Devices (Cortex-M4)

Numbers from pqm4 (PQC benchmarking on STM32F407):

| Algorithm | Keygen (kCycles) | Sign/Encap (kCycles) | Verify/Decap (kCycles) | RAM (KB) |
|-----------|------------------|----------------------|------------------------|----------|
| ML-KEM-768 | 1,400 | 1,600 | 1,800 | 22 |
| ML-DSA-65 | 1,300 | 9,000 | 4,000 | 88 |
| SLH-DSA-192s | 50 | 1,200,000 | 50 | 40 |
| FN-DSA-1024 | 30,000 | 60,000 | 8,000 | 110 |

Practical takeaway: SPHINCS+ signing is unusable on constrained devices (~10 seconds per signature on a 168 MHz Cortex-M4). ML-DSA is the only practical general-purpose PQ signature for IoT.

---

## 4. Migration Challenges

### 4.1 The "Drop-In Replacement" Fallacy

PQC algorithms are not drop-in replacements for RSA/ECC. The differences that break protocols:

- **Key sizes**: 1-5 KB public keys blow up protocol messages that assumed 32-256 byte keys (e.g., DNSKEY RRs, OCSP responses embedded in TLS, JWT headers).
- **Signature sizes**: handshake fragmentation, certificate chain truncation by middleboxes.
- **Determinism**: ML-DSA is deterministic (replay-able), unlike ECDSA which uses a random `k`. Protocols relying on signature randomness (some challenge-response schemes) need rework.
- **KEM vs encryption**: PQC KEMs expose a different API (`Encapsulate -> (ct, ss)`, `Decapsulate(ct) -> ss`) than classical public-key encryption (`Encrypt(pk, m) -> c`, `Decrypt(sk, c) -> m`). Protocols that need raw public-key encryption (some broadcast / multicast designs) need an HPKE-style wrapper.
- **No PQC PKI**: until a root of trust signs PQC certificates that clients validate end-to-end, the PQ path is only as strong as the classical fallback that anchors it.

### 4.2 Hybrid Mode -- the Industry Default

Because PQC algorithms are newer and less battle-tested, the industry has converged on **hybrid mode**: combine a classical key exchange with a PQC KEM, so that the session key is secure if **either** the classical or the PQC primitive holds.

For TLS 1.3, the standardization track defines a new `key_share` extension carrying both X25519 and ML-KEM shares:

```
TLS 1.3 hybrid key share (X25519Kyber768Draft00 / X25519MLKEM768):

ClientHello.key_share:
  - X25519 (32 bytes) + Kyber768/ML-KEM-768 encapsulation (1088 bytes)

ServerHello.key_share:
  - X25519 (32 bytes) + Kyber768/ML-KEM-768 ciphertext (1088 bytes)

Shared secret = HKDF-Extract(X25519_shared || MLKEM_shared)
```

If either the X25519 portion or the ML-KEM portion is broken, the session key remains secure. The cost is the bytes on the wire (~1.1 KB additional each direction).

Hybrid is the recommended posture for the 2025-2030 window: it gives HNDL protection now (against future quantum adversaries) without betting the system on the untested PQC primitive.

### 4.3 X.509 Certificate Handling

X.509 certificates with PQC public keys run into three concrete problems:

1. **Algorithm identifiers**: must use the new OIDs (`id-ml-kem-768`, `id-ml-dsa-65`, etc.). Many legacy parsers reject unknown OIDs.
2. **Signature algorithm on the cert itself**: the CA's signature on a PQC public key can be either classical (transitional) or PQ. A PQ-rooted chain (root signs intermediate with ML-DSA, intermediate signs leaf with ML-DSA) is the end state but requires every trust store to be updated.
3. **Chain size**: a 3-deep chain with SLH-DSA-192s signatures is ~50 KB. Middleboxes, IDS sensors, and some TLS libraries truncate or reject TLS handshakes that exceed historical size norms (~16 KB).

**X.509 alternative signature scheme** (X.509 AltSig, RFC 9417 / draft) addresses this by allowing **two** signatures on the same certificate -- one classical and one PQ -- with separate OIDs. Clients that understand both verify both; legacy clients use the classical signature. This is the CA's path to a non-disruptive transition.

### 4.4 Protocol Mismatches -- Concrete Cases

- **SSH**: `ssh-rsa` is being deprecated in favor of `rsa-sha2-256` / `ecdsa-sha2-nistp256` / `ssh-ed25519`. The new `ml-dsa-65` / `ml-dsa-87` key types require OpenSSH 9.x+ on both client and server. Legacy clients silently fall back, defeating the migration unless `PubkeyAcceptedAlgorithms` is hardened.
- **DNSSEC**: signature size directly affects whether responses fit in a 1232-byte UDP packet (the EDNS(0) buffer size most resolvers negotiate). SLH-DSA-192s signatures force TCP fallback, doubling lookup latency.
- **IKEv2**: CERTREQ payloads with PQC keys can exceed IKE fragment limits. RFC 9242 (Intermediate Exchange) and RFC 8781 (Multiple Key Exchanges) are required to compose PQC with classical ECDH.
- **JWT / COSE**: JWS `alg` registry needs new entries (`MLDSA65`, `SLHDSA192`). Many validators reject unknown algorithms as `alg:none`-equivalent, breaking authentication.

---

## 5. TLS 1.3 Post-Quantum Handshake Simulation (OQS-OpenSSL)

### 5.1 Installing OQS-OpenSSL

The Open Quantum Safe (OQS) project provides a fork of OpenSSL 3.x with PQC algorithms integrated into TLS 1.3 and X.509.

```bash
# Build OQS provider + OpenSSL 3.x fork
sudo apt install cmake ninja-build python3-pip libssl-dev

git clone --recurse-submodules https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/opt/oqs ..
ninja && sudo ninja install

# OQS-OpenSSL fork
git clone --recurse-submodules https://github.com/open-quantum-safe/openssl.git oqs-openssl
cd oqs-openssl && ./Configure --prefix=/opt/oqs-openssl \
  -DOQS_DEFAULT_GROUPS="x25519:kyber768:p256_kyber768" \
  -DOQS_KEM_GROUPS="kyber512:kyber768:kyber1024:p256_kyber512:p384_kyber768:p521_kyber1024"
make -j$(nproc) && sudo make install_sw install_ssldirs
```

### 5.2 Generating Hybrid and PQ Certificates

```bash
# Generate an ML-DSA-65 key + self-signed cert (pure PQ)
/opt/oqs-openssl/bin/openssl req -x509 -new -newkey ml-dsa-65 \
  -keyout mldsa_root.key -out mldsa_root.crt -nodes \
  -subj "/CN=PQ Test Root" -days 3650

# Generate a hybrid X25519+ML-KEM-768 KEM (no cert; ephemeral only)
# (KEM keys are usually ephemeral, not certified.)

# Generate a classical-leaf-signed-by-PQ-root cert
/opt/oqs-openssl/bin/openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout leaf.key -out leaf.csr -subj "/CN=leaf"
/opt/oqs-openssl/bin/openssl x509 -req -in leaf.csr \
  -CA mldsa_root.crt -CAkey mldsa_root.key -CAcreateserial \
  -out leaf.crt -days 365 -sha256
```

### 5.3 Running a TLS 1.3 PQ Handshake

```bash
# Terminal 1: server
/opt/oqs-openssl/bin/openssl s_server -accept 4433 \
  -cert leaf.crt -key leaf.key -CAfile mldsa_root.crt \
  -groups x25519_kyber768 -tls1_3 -www -curves x25519_kyber768

# Terminal 2: client
/opt/oqs-openssl/bin/openssl s_client -connect 127.0.0.1:4433 \
  -CAfile mldsa_root.crt -groups x25519_kyber768 -tls1_3 \
  </dev/null 2>&1 | grep -E "Server Temp Key|Cipher|Peer certificate"

# Expected output (excerpt):
# Server Temp Key: X25519Kyber768Draft00
# Cipher          : TLS_AES_256_GCM_SHA384
```

### 5.4 Inspecting the Handshake

```bash
# Capture and decode the ClientHello / ServerHello key_share
tcpdump -i lo -w pq_tls.pcap port 4433
tshark -r pq_tls.pcap -V -Y "tls.handshake.type == 1 || tls.handshake.type == 2" | \
  grep -A 30 "Key Share"

# Decode the NamedGroup of the share
# 0x0501 = x25519_kyber768 (older IETF draft)
# 0x11EC = x25519_mlkem768 (final assignment, RFC 9180 successor)
```

### 5.5 Troubleshooting Protocol Mismatches

| Symptom | Likely cause |
|---------|--------------|
| `tls: handshake failure` from a non-OQS client | Hybrid group not understood by the peer |
| Connection succeeds but `Server Temp Key: X25519` only | Hybrid group negotiated away; check `-groups` ordering |
| TLS handshake truncated, server never receives ClientKeyExchange | Middlebox (WAF, load balancer) fragmenting or rejecting oversized `key_share` |
| Cert verifies in OQS client but fails in OpenSSL 3.2+ stock | Stock OpenSSL lacks the OQS provider; install via `openssl provider load oqsprovider` |

---

## 6. Hybrid Mode Construction Pitfalls

### 6.1 Concatenation vs KDF

The naive construction `ss = classical_ss || pq_ss` is dangerous: a length extension or framing error can silently truncate one half. The standardized construction uses HKDF-Extract over the concatenation with explicit length-prefixing:

```python
# Correct hybrid (per draft-ietf-tls-hybrid-design)
import hashlib

def hybrid_shared_secret(classical_ss: bytes, pq_ss: bytes) -> bytes:
    # Length-prefix each component to avoid framing ambiguity
    classical_encoded = len(classical_ss).to_bytes(4, 'big') + classical_ss
    pq_encoded = len(pq_ss).to_bytes(4, 'big') + pq_ss
    combined = classical_encoded + pq_encoded
    return hashlib.sha3_256(combined).digest()
```

### 6.2 Order of Operations

Pitfalls seen in real implementations:

- **PQ-only when classical was intended**: misconfigured cipher string drops the X25519 share. Test with explicit `-groups x25519:kyber768` and verify both shares appear in `ServerHello.key_share`.
- **Authentication tied to the wrong share**: some early hybrids authenticated only the classical share, allowing an active attacker to strip the PQ share undetected. The share must be bound into the transcript hash.
- **Cross-protocol reuse**: the same ML-KEM keypair used in both a TLS and an IPsec context leaks cross-protocol attack surface (the original Kyber proof assumed per-protocol key derivation; cross-protocol attacks on Kyber were published by Bosc et al. 2023).

### 6.3 Negative Test Cases

Always verify these negative tests:

1. Mutate the PQ ciphertext byte 0 -- handshake MUST fail
2. Mutate the classical share -- handshake MUST fail
3. Downgrade: client offers hybrid only, server accepts classical only (no PQ) -- handshake MUST fail unless the policy explicitly allows classical-only fallback

---

## 7. X.509 and PKI Migration

### 7.1 Inventory of Cryptographic Assets

Before any migration, build an algorithm inventory:

```python
import subprocess, json, re
from pathlib import Path

def inventory_cert(path: Path) -> dict:
    out = subprocess.run(
        ["openssl", "x509", "-in", str(path), "-noout", "-text"],
        capture_output=True, text=True, check=True
    ).stdout
    info = {"path": str(path)}
    if "Public Key Algorithm: id-ecPublicKey" in out:
        info["pubkey_alg"] = "ECDSA"
    elif "Public Key Algorithm: rsaEncryption" in out:
        info["pubkey_alg"] = "RSA"
    elif "Public Key Algorithm: id-ml-kem" in out:
        info["pubkey_alg"] = "ML-KEM"
    elif "Public Key Algorithm: id-ml-dsa" in out:
        info["pubkey_alg"] = "ML-DSA"
    sig_match = re.search(r"Signature Algorithm: (\S+)", out)
    if sig_match:
        info["sig_alg"] = sig_match.group(1)
    return info

# Walk a directory of trusted root certs
certs = [inventory_cert(p) for p in Path("/etc/ssl/certs").glob("*.pem")]
print(json.dumps(certs, indent=2))
```

### 7.2 Path Building with Mixed Algorithms

OpenSSL 3.2+ and BoringSSL build chains algorithm-agnostic. Older libraries (OpenSSL 1.1.x, GnuTLS < 3.8) may refuse to chain a PQ-signed intermediate under a classical root, or vice versa. Test with the exact client stack that the production endpoint uses.

### 7.3 Hybrid X.509 (AltSig)

The alt-signature approach (one cert, two signatures) requires:

1. CA's issuing cert with two signatures, classical and PQ
2. Subject cert with two signatures, classical and PQ
3. Client library that verifies **both** signatures

Without #3, the alt-signature provides no security benefit -- a stripped cert with only the classical signature still verifies.

---

## 8. Side-Channel Analysis -- Taxonomy

Side channels leak secret information through **physical or microarchitectural observables** that correlate with secret-dependent values during computation.

| Channel | Observable | Typical Leakage | Required Equipment |
|---------|------------|-----------------|--------------------|
| **Timing** | Wall-clock duration | Branch on secret; non-constant-time math | Network connection or local timer |
| **Power (SPA / DPA)** | Instantaneous current draw | Hamming weight of registers / bus; multiply operations | Oscilloscope + shunt resistor or ChipWhisperer |
| **Electromagnetic (EMA)** | EM emanations near chip | Same as power, spatially resolved | Near-field EM probe + LNA + scope |
| **Acoustic** | Sound from capacitors / coils | Same as power, very low bandwidth | Microphone |
| **Cache-timing** | L1/L2 cache state observable via timing | Memory address depending on secret | Local code execution on same core |
| **Branch prediction / Spectre** | Speculative execution side effects | Secret-dependent memory access | Local code execution |
| **Fault injection** | Induced computation errors | Glitch on clock / power / laser | Glitcher (ChipWhisperer, Riscure VC Glitcher) |

### 8.1 Simple Power Analysis (SPA)

SPA reads **directly visible** features of a single trace: the shape of the power envelope reveals the sequence of operations (multiply vs square in RSA, conditional moves, key bit decisions). Defense: regularize the operation sequence so traces look identical regardless of secret.

### 8.2 Differential Power Analysis (DPA)

DPA is the workhorse of real-world SCA. The methodology:

1. Capture N (typically 1k - 1M) power traces of the target processing **different known inputs** with the **same secret key**
2. For each bit of a hypothesized subkey, partition the traces into two sets based on a leakage model (e.g., "the LSB of intermediate byte 0 after the first AES SBox is 1")
3. Compute the mean of each set; the difference-of-means is plotted. The correct subkey hypothesis produces a sharp spike at the time the leakage occurs; wrong hypotheses produce noise.

DPA defeats naïve constant-time coding because it averages out operation-order noise and isolates the data-dependent component.

### 8.3 Correlation Power Analysis (CPA)

CPA generalizes DPA: instead of partitioning on a single bit, correlate the entire power trace against a multi-bit leakage model (e.g., Hamming weight of `SubBytes(state) ^ key_guess`). CPA reaches the same answer with fewer traces (typically 100-10000 vs 10000-1M for DPA).

### 8.4 Template Attacks

Template attacks (theoretically optimal): build a multivariate Gaussian model of the leakage distribution at each sample point for several known keys, then apply maximum likelihood to recover the unknown key from a single trace. Practical with `lascar` or Riscure Inspector.

---

## 9. Power Analysis Lab Setup

### 9.1 Hardware -- ChipWhisperer Husky / Lite + STM32 Target

The NewAE ChipWhisperer is the de-facto entry-level SCA lab. The STM32F3 target (CW308 board, or CW303 STK) is the standard target for AES, Kyber, and Dilithium evaluation.

```
[ Host PC ] --USB-- [ ChipWhisperer Husy ]
                          |  (SMA: power trigger + analog)
                          v
                   [ CW308 UFO board ]
                          |
                   [ STM32F303 target ]
```

### 9.2 Software Stack

```bash
# ChipWhisperer framework
git clone https://github.com/newaetech/chipwhisperer.git
cd chipwhisperer
python3 -m pip install -e .
python3 -m pip install jupyter matplotlib numpy scipy

# Jupyter notebook environment for SCA
jupyter notebook  # opens the ChipWhisperer tutorials
```

### 9.3 Capturing a Power Trace -- Minimal Python

```python
import chipwhisperer as cw

# Connect to Husky + STMF3 target
scope = cw.scope()
target = cw.target(scope)
scope.default_setup()
target.output_fmt = "ser"  # serial output

# Program the target with the AES or Kyber firmware
cw.program_target(scope, cw.programmers.STM32FProgrammer,
                  "hardware/victims/firmware/simpleserial-aes/simpleserial-aes-CM3.hex")

# Capture one trace
key, text = b"\x00" * 16, b"\x01" * 16  # replace with real key/known plaintext
target.simpleserial_write("k", key)
target.simpleserial_write("p", text)
ret = cw.capture_trace(scope, target, text, key)
trace = ret.power  # np.ndarray of ~5000 samples

# Save for later analysis
import numpy as np
np.save("trace_0000.npy", trace)
```

### 9.4 Capturing a PQC Trace

Replace `simpleserial-aes` with `pqm4`-style simpleserial firmware. The `pqm4` project (https://github.com/mupq/pqm4) provides a uniform `simpleserial` interface for Kyber, Dilithium, and SPHINCS+ on Cortex-M4. The trigger point is the **NTT multiplication** (for Kyber/Dilithium) or the **WOTS+ chain** (for SPHINCS+).

```bash
# Build pqm4 firmware for CW308 + STM32F4
git clone https://github.com/mupq/pqm4.git
cd pqm4
make PLATFORM=cw308_stm32f4 ALG=kyber768
make PLATFORM=cw308_stm32f4 ALG=dilithium3
# Flash via ChipWhisperer programmer
```

---

## 10. Differential Power Analysis Attack on AES

### 10.1 The Classic CPA Workflow

```python
import numpy as np
import chipwhisperer as cw
from chipwhisperer.analyzer import cpa

# 1. Capture 5000 traces with random plaintexts, fixed key
scope = cw.scope()
target = cw.target(scope)
scope.default_setup()

ktp = cw.ktp.Basic()
ktp.key_len = 16
key, text = ktp.next()
target.simpleserial_write("k", key)

traces = []
textins = []
for _ in range(5000):
    key, text = ktp.next()
    ret = cw.capture_trace(scope, target, text, key)
    traces.append(ret.power)
    textins.append(ret.textin)

traces = np.array(traces)
textins = np.array(textins)

# 2. Define leakage model: HW of first SBox output
from chipwhisperer.analyzer.attacks.models import AES128_8bit
leakage_model = cw.AESL128SBox_output  # HW(AES_SBox(C0 ^ K0))

# 3. Run CPA
attack = cpa.CPA()
attack.set_analysis_model(cpa.leakage_models.AES_128_8BIT_SBOX_OUTPUT_LEAKAGE)
attack.set_traces(traces)
attack.set_textin_array(textins)
results = attack.run()

# 4. Recover best subkey guess per byte
best_guesses = np.argmax(np.max(np.abs(results), axis=1), axis=1)
print("Recovered key:", bytes(best_guesses).hex())
```

### 10.2 Interpreting the Output

For a correct subkey hypothesis, the correlation trace shows a clear spike at the time of the SBox lookup. Wrong hypotheses produce noise-level correlations (~ `1 / sqrt(N)` with N traces). Convergence usually requires 1000-5000 traces for software AES, 10000-100000 for hardware AES with masking countermeasures.

---

## 11. Timing and Cache-Timing Attacks

### 11.1 Constant-Time Programming -- the Discipline

A constant-time implementation has these properties:

1. **No secret-dependent branches**: branch conditions must not depend on secret data
2. **No secret-dependent memory accesses**: array indices must not depend on secret data
3. **No secret-dependent variable-time instructions**: avoid hardware multiply, divide, or float ops on secret data (these vary by operand on some ISAs)

Verification tools:

- `dudect` -- statistical timing detector for constant-time violations
- `ctgrind` (Valgrind plugin) -- marks secret-dependent memory accesses
- `binsec` -- static binary analysis for constant-time
- `ct-verif` (Certicrypt) -- formal verification

### 11.2 dudect -- Practical Timing Detection

```bash
# Build dudect
git clone https://github.com/oreparaz/dudect.git
cd dudect && make

# Wrap the candidate function with the dudect harness
# (see src/dudect.h for the API)
# Run: positive number of measurements -> non-constant-time detected
./dudect
# Output: "med" / "max" t-statistic > 4.5 -> leakage detected
```

### 11.3 Cache-Timing Attack on AES T-Tables

The classic Bernstein 2005 attack: AES T-table implementations access one of 4 1KB tables at indices that depend on `plaintext[i] ^ key[i]`. The cache state after the encryption therefore depends on the key. By measuring access time to a chosen memory location after the encryption, an attacker can recover the key byte-by-byte.

```python
# Pseudo-code for the eviction-based cache timing attack
# (requires shared-core execution with the victim)
def evict_and_probe(addr_victim_table):
    flush_cache(addr_victim_table)            # clflush on each cache line
    trigger_victim_encryption()               # victim accesses table at secret index
    for line in range(64):                    # 64 cache lines in a 1KB T-table
        t = time_access(addr_victim_table + line * 64)
        if t < THRESHOLD:                     # hit: the line was accessed by victim
            record_hit(line)
```

Modern mitigations: AES-NI (hardware constant-time instructions), bitsliced software AES, or constant-time bitsliced implementations.

---

## 12. PQC-Specific Side-Channel Attacks

### 12.1 Kyber -- Message Recovery via Compression Side-Channel

The Kyber `Compress` and `Decompress` functions multiply by a rational coefficient and round. Several published attacks (Bhasin et al. 2019, "First-Order Chosen-Ciphertext Attack on CCA-Secure NTRU / Kyber") show that single-trace EM on the NTT reveals the message `m` directly, allowing recovery of the encapsulated key.

```
Target operation:   v - s^T * u          (Kyber.CCPDecrypt core)
                      ^
                      secret-dependent subtraction
                      |
Side channel:        EM probe over ARM Cortex-M4 multiply-accumulate unit
                      |
Attack:              template attack on v - s^T * u -> recover s polynomial
                      |
Impact:              full secret-key recovery in 1 trace (worst case)
```

Defenses: higher-order masking (Reparaz et al.), shuffling the NTT butterfly order, applying the masked decapsulation (Ravi et al. 2022).

### 12.2 KyberSlash -- Division Timing Leakage

KyberSlash (Manganote et al., 2021) is a timing attack on reference Kyber implementations. The vulnerability: a divide instruction whose duration depended on a secret-dependent value (specifically, a step in the compression that involves `barrett_reduce`). A remote attacker measures response time of the decapsulation oracle and recovers the secret key in thousands of queries.

```python
# Pseudo-vulnerable pattern (conceptual)
def barrett_reduce_vulnerable(value):
    # Division / multiply-high duration depends on operand magnitude
    # value's magnitude depends on the secret s
    q = value // KYBER_Q  # <- NON-CONSTANT TIME
    return value - q * KYBER_Q

# Fix: ensure all intermediate values are in [-KYBER_Q, KYBER_Q]
# so q is in {-1, 0, 1}, then branch-free
```

Defenses (applied in FIPS 203): all reductions use Barrett or Montgomery form with input bounds enforced so the quotient is fixed. Auditing: scan assembly for `idiv` / `udiv` instructions on secret-derived data.

### 12.3 "Injecting Crystals" -- Dilithium Fault Attacks

Manganote et al. (2023) demonstrated that a single clock glitch during the `z = y + c*s1` step of Dilithium signing can produce an output `z'` that violates the rejection bound. Comparing `z'` to a legitimate `z` of the same message yields a linear equation in `s1`. A handful of faults recovers the full signing key.

Defense: signature verification **before release** (compute the signature, verify it under the public key, retry if verification fails). This neutralizes single-fault attacks. FIPS 204 mandates this "verify-before-release" step.

### 12.4 SPHINCS+ Forgery via State Recovery

SPHINCS+ is stateless, so the classical hash-based attack (state reuse) is not applicable. However, the WOTS+ leaf signing uses a chain: `h = H^w(x)` where `w` is the Winternitz parameter. A fault in one chain step (skipping an iteration) yields a hash that is one step "shorter" -- which an attacker can then extend to forge the same leaf for a different message.

Defense: fault-tolerant WOTS+ chains (Mouhartem et al.) -- double-compute each step and compare.

### 12.5 Crystal-Slinger and PQC Side-Channel Tools

The "Crystal-Slinger" framework (publicly released as a research PoC for evaluating CRYSTALS-Kyber/Dilithium on Cortex-M4 with ChipWhisperer) automates:

- Single-trace EM message recovery on Kyber
- Fault injection on Dilithium with verify-before-release bypass
- Side-channel-resilience scoring of masked implementations

GROUNDTRUTH (Mohagheshghi et al., 2024) is a reference dataset of ~1M EM traces from a ChipWhisperer + STM32F4 target running Kyber-768, with ground-truth labels for the message bits, intended for benchmarking machine-learning SCA attacks.

---

## 13. Tooling Reference

### 13.1 PQC Libraries and Frameworks

| Tool | Purpose | URL |
|------|---------|-----|
| **liboqs** | Reference C library of NIST PQC algorithms | github.com/open-quantum-safe/liboqs |
| **OQS-OpenSSL** | OpenSSL 3.x fork with PQC TLS | github.com/open-quantum-safe/openssl |
| **oqs-provider** | OpenSSL 3.x provider for stock OpenSSL | github.com/open-quantum-safe/oqs-provider |
| **pqm4** | PQC implementations for Cortex-M4 | github.com/mupq/pqm4 |
| **PQM4-Masked** | Masked PQC implementations | github.com/mupq/mupq |
| **PQClean** | Clean reference C implementations | github.com/PQClean/PQClean |
| **Botan PQ branch** | C++ crypto library with PQC | botan.randombit.net |
| **BoringSSL PQ** | Google's PQ experimentation branch | boringssl.googlesource.com |
| **Cloudflare CIRCL** | Go-native PQC primitives | github.com/cloudflare/circl |
| **LatticeReduce (SageMath)** | Lattice reduction (LLL/BKZ) for cryptanalysis | sagemath.org |

### 13.2 Side-Channel Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **ChipWhisperer** | Open-source SCA + glitching hardware + software | github.com/newaetech/chipwhisperer |
| **ChipWhisperer-Husky** | Next-gen CW hardware (1 GS/s, 14-bit) | newae.com |
| **Riscure Inspector** | Commercial SCA suite (power, EM, fault) | riscure.com |
| **Lascar** | Python SCA framework (CPA, template attacks) | github.com/Ledger-Donjon/lascar |
| **dudect** | Statistical constant-time verifier | github.com/oreparaz/dudect |
| **ctgrind** | Valgrind-based secret-dependent access detector | github.com/agl/ctgrind |
| **binsec** | Static binary analysis for constant-time | binsec.github.io |
| **GREATs** | Glitch + side-channel reverse engineering toolset | github.com/AlgoSync/GREATs |

### 13.3 LatticeReduce (SageMath) -- Lattice Reduction

For cryptanalysis (NOT for breaking FIPS PQC, which is infeasible, but for breaking toy implementations, malformed LWE instances, or recovering keys from partial leakage):

```python
# SageMath
from sage.all import matrix, ZZ, LLL

# Example: recover small-error LWE secret via LLL (toy params only)
# n = 64, q = 2^16, error bound eta = 3
# Given: A (m x n over Z_q), b = A*s + e (m x 1)
# Build lattice:
#   | q*I_m  0  |  *
#   |  A^T   I_n|
# and reduce; the short vector reveals (e, s)

A = matrix(ZZ, m, n, ...)  # fill from observations
b = vector(ZZ, m, ...)
M = block_matrix([[q * identity_matrix(ZZ, m), zero_matrix(ZZ, m, n)],
                  [A.T,                     identity_matrix(ZZ, n)]])
M_reduced = M.LLL()
# Look for a row of the form (e, s) with small entries in the rightmost n coords
```

This does **not** break production ML-KEM (params are tuned to make this infeasible) but is the right tool for evaluating under-parameterized implementations or partial-key-leak scenarios.

---

## 14. End-to-End Lab: STM32 Power Trace Capture of Kyber

A complete lab exercise that ties the preceding sections together.

### 14.1 Equipment Checklist

- ChipWhisperer Husky (or Lite/Nano for budget)
- CW308 UFO board + STM32F405 target (or CW303 STK with STM32F3)
- Host PC with Python 3.10+, ChipWhisperer Jupyter
- 30 minutes for setup, 1 hour for capture, 1 hour for analysis

### 14.2 Bring-Up

```bash
# 1. Verify hardware connection
python3 -c "import chipwhisperer as cw; s = cw.scope(); print(s)"

# 2. Flash Kyber-768 simpleserial firmware
cd pqm4 && make PLATFORM=cw308_stm32f4 ALG=kyber768
cw.program_target(scope, cw.programmers.STM32FProgrammer,
                  "bin/cw308_stm32f4_kyber768.bin")
```

### 14.3 Capture Script

```python
import chipwhisperer as cw
import numpy as np

scope = cw.scope()
target = cw.target(scope)
scope.default_setup()
scope.adc.samples = 24000          # capture the full NTT
scope.adc.offset = 0
scope.gain.db = 25
scope.trigger.triggers = "tio1"

keypair = target.simpleserial_write("g", b"")  # keygen command
pk = target.simpleserial_read("p", 1184)        # ML-KEM-768 pubkey

traces = []
cts = []
for i in range(1000):
    # Random ciphertext for decapsulation
    ct = bytes.fromhex(f"{i:08x}".rjust(2176, "0"))  # placeholder
    target.simpleserial_write("c", ct)
    cw.capture_trace(scope, target, ct, keypair)
    trace = scope.get_last_trace()
    traces.append(trace)
    cts.append(ct)
    if i % 100 == 0:
        print(f"captured {i}/1000")

np.save("kyber_traces.npy", np.array(traces))
np.save("kyber_cts.npy", np.array(cts))
```

### 14.4 Analysis -- Single-Trace Template Attack

```python
import numpy as np
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression

traces = np.load("kyber_traces.npy")        # (N, samples)
# Ground-truth labels: assume you control keypair, so you know message bits
labels = np.load("kyber_labels.npy")         # (N, 256) binary message bits

# PCA to compress samples -> features
pca = PCA(n_components=20)
X = pca.fit_transform(traces[:800])
X_test = pca.transform(traces[800:])

# Train per-bit classifier (here, just bit 0)
clf = LogisticRegression(max_iter=1000)
clf.fit(X, labels[:800, 0])
acc = clf.score(X_test, labels[800:, 0])
print(f"bit-0 recovery accuracy: {acc:.2%}")
# > 80% accuracy indicates exploitable single-trace leakage
```

### 14.5 Defenses Demonstrated

After demonstrating the attack, swap in the **masked** Kyber implementation from `pqm4-masked` and re-run. Correlation should drop to noise level (~50% accuracy), confirming the countermeasure.

---

## 15. Defense Perspective for PQC and Side-Channel

### 15.1 PQC Migration Defense Checklist

- [ ] Algorithm inventory complete: every long-term key, every signature location, every TLS / SSH / IPsec / VPN endpoint mapped
- [ ] Crypto-agility: no algorithm hardcoded; all primitives behind a pluggable API
- [ ] Hybrid mode (X25519 + ML-KEM-768) deployed for TLS / VPN endpoints with 10+ year data lifetime
- [ ] Test vectors from NIST CAVP / ACVP validate production implementation bit-for-bit
- [ ] X.509 certificates include alt-signature (hybrid) where supported by client stack
- [ ] Protocol-specific fragmentation: DNSSEC responses fit within negotiated EDNS(0) buffer (<= 1232 bytes); TLS handshake under 16 KB
- [ ] Downgrade-resistant: server rejects ClientHello that strips the PQ group
- [ ] Monitoring: TLS handshake logs capture the negotiated NamedGroup and reject unexpected downgrades

### 15.2 Side-Channel Defense Checklist

- [ ] All cryptographic libraries verified constant-time (`dudect`, `ctgrind`, `binsec`)
- [ ] Hardware acceleration used where available (AES-NI for AES, ARMv8 SHA for SHA-2/3)
- [ ] Secret-key operations run in isolated process / enclave with no local untrusted code
- [ ] Power / EM analysis performed on at least one production device (ChipWhisperer or Riscure Inspector)
- [ ] Masking applied to top-level secret-key operations on smartcard / HSM targets (order-1 minimum)
- [ ] Verify-before-release on all PQC signature implementations (defeats single-fault attacks)
- [ ] Side-channel fuzzing integrated into CI for cryptographic primitives (e.g., `cargo sidefuzz`)

### 15.3 Crypto-Agility Posture

Crypto-agility is the ability to swap algorithms without code changes or protocol breakage. The minimum requirements:

1. **Algorithm identifiers** as configurable strings, not hardcoded constants
2. **Key store** abstracted over algorithm (the key store must hold 5 KB PQ keys, not just 256-byte ECC keys)
3. **Signature verification** that dispatches on algorithm OID without ad-hoc dispatch logic
4. **Negotiation** that includes the algorithm in the transcript hash (so downgrade is detectable)
5. **Telemetry** that reports which algorithms are actually in use by which peers

The single biggest predictor of migration success is whether the team can change the algorithm in **one** config file rather than refactoring across the codebase.

---

## 16. Reporting PQC and Side-Channel Findings

### 16.1 Severity Calibration

| Finding | Severity | Rationale |
|---------|----------|-----------|
| TLS endpoint accepts classical-only when hybrid is required | High | HNDL exposure for long-lived data |
| PQC implementation non-constant-time (`dudect` positive) | Critical | Remote key recovery feasible |
| Kyber/Dilithium implementation skips verify-before-release | High | Single-fault key recovery |
| Hybrid construction does not bind PQ share into transcript | High | Active PQ-stripping downgrade |
| Side-channel DPA recovers AES key in < 10k traces | High (or Critical for HSM) | Physical key recovery |
| Cache-timing leakage on AES T-tables | Medium-High | Requires local code execution |
| DNSSEC signature forces TCP fallback for all responses | Medium | Availability / latency degradation |
| Algorithm inventory incomplete | Medium | Migration planning blocker |

### 16.2 Finding Template (PQC Side-Channel)

```markdown
### Title: ML-KEM-768 decapsulation on `<target>` leaks message bits via single-trace EM

**Severity**: Critical

**Description**:
The `<vendor>` `<product>` `<version>` implements ML-KEM-768 (FIPS 203) using a
non-masked NTT. A single EM trace collected with a ChipWhisperer Husky and a
near-field probe, acquired during the decapsulation of a chosen ciphertext,
allows recovery of 80%+ of the message bits via a template attack. Combined
with the Bleichenbacher-style oracle on the FO transform, this recovers the
session key.

**Reproduction**:
1. Acquire 1000 traces of decapsulation under known ciphertexts
2. Train per-bit logistic regression on PCA-compressed features
3. Apply to a held-out single trace; accuracy 80%+ on bit 0 confirms leakage

**Remediation**:
- Apply first-order masking (Reparaz et al. 2022) to the NTT
- Add message-randomization in the FO transform
- Re-verify with ChipWhisperer after deployment
```

### 16.3 Mapping to Standards

- **NIST SP 800-208** (Stateful Hash-Based Signatures) -- for LMS / XMSS deployments
- **NIST FIPS 203 / 204 / 205** -- PQC primitives
- **NSM CNSA 2.0** (US National Security Systems) -- mandates specific PQ algorithms for classified systems
- **ANSSI MQA** (French) -- PQC migration guidance for critical infrastructure
- **BSI TR-02102-1** (German) -- PQC migration roadmap for federal systems
- **ETSI TR 103 619** (EU) -- CYBER; Migration Strategies and Recommendations to Quantum Safe Schemes
- **OWASP A04:2021 Cryptographic Failures** -- the underlying framework

---

## 17. Real Research References and Case Studies

### 17.1 KyberSlash (2021)

- **What**: Timing attack on reference Kyber implementations
- **Vulnerability**: non-constant-time division in `barrett_reduce` / `compress` path
- **Impact**: remote recovery of Kyber secret key in tens of thousands of queries
- **Lesson**: lattice primitives need the same constant-time discipline as classical crypto; barrett / Montgomery reduction must enforce bounded input

### 17.2 Injecting Crystals (Manganote et al., 2023)

- **What**: Fault-injection attack on Dilithium signing
- **Vulnerability**: clock glitch during `z = y + c*s1` produces out-of-bound z
- **Impact**: handful of faults recovers the signing key
- **Lesson**: verify-before-release is mandatory (now codified in FIPS 204)

### 17.3 Crystal-Slinger (Research PoC)

- **What**: Open framework for evaluating CRYSTALS-Kyber / Dilithium on Cortex-M4 with ChipWhisperer
- **Capability**: automated single-trace message recovery + fault injection
- **Lesson**: side-channel evaluation must cover the full decapsulation / signing path, not just the symmetric primitive

### 17.4 GROUNDTRUTH (Mohagheshghi et al., 2024)

- **What**: Reference dataset of 1M+ EM traces from ChipWhisperer + STM32F4 running ML-KEM-768
- **Use**: benchmarking machine-learning SCA attacks on PQC; reproducible comparison of attacks
- **Lesson**: ML-based SCA is now the state of the art for single-trace attacks; countermeasures must hold against learned classifiers, not just CPA

### 17.5 Shor's Algorithm and ECC/RSA (Theoretical Baseline)

- **What**: Shor's algorithm on a CRQC solves IFP and ECDLP in polynomial time
- **Current state**: largest number factored by Shor is 21 (2022, IBM quantum hardware); scaling to RSA-2048 requires millions of physical qubits with current error correction overheads
- **Practical impact**: not zero-day, but justify the 10-30 year HNDL horizon

### 17.6 Cross-Protocol Attack on Kyber (Bosc et al., 2023)

- **What**: reusing a Kyber keypair across TLS and another protocol (e.g., signed-then-decapsulated challenge-response) leaks information
- **Lesson**: per-protocol key derivation (KEM -> KDF with domain separator) is mandatory

---

## 18. Common Pitfalls

- **Treating PQC as drop-in replacement**: protocols assume 256-byte keys; 1 KB+ PQ keys blow up message sizes and trigger middlebox failures. Always test against the actual production stack, not just the reference implementation.
- **Deploying pure PQC without hybrid**: betting the security of long-lived data on a less-tested primitive is the opposite of defense-in-depth. Hybrid (classical + PQ) is the recommended posture for at least the 2025-2030 transition window.
- **Assuming constant-time = side-channel-safe**: constant-time coding defeats timing and cache-timing channels, but does nothing against power / EM / fault. The latter require masking, hiding, and fault detection respectively.
- **Using unverified constant-time**: a constant-time claim without `dudect` / `ctgrind` / `binsec` evidence is unverifiable. Many "constant-time" libraries have later been found non-constant-time in some code path.
- **Skipping verify-before-release on PQC signatures**: this single step defeats the cheapest fault attacks. Skipping it (e.g., for performance in an embedded signer) is a critical error.
- **Confusing algorithm OID with key OID**: in X.509, the certificate's `SubjectPublicKeyInfo` and the certificate's `signatureAlgorithm` are independent. A cert can have an ML-DSA public key signed by an RSA root (transitional) or an ECDSA public key signed by an ML-DSA root. Inventory both.

---

## 19. Automation and Tooling Recipes

### 19.1 Automated Crypto-Agility Audit

```python
# Scan a codebase for cryptographic primitives and assess agility
import re, pathlib

HARDCODED_ALG_PATTERNS = [
    (r'\bAES[-_]?(128|256)\b', 'AES'),
    (r'\bRSA[-_]?(1024|2048|3072|4096)\b', 'RSA'),
    (r'\bECDH|ECDSA\b', 'ECC'),
    (r'\bSHA[-_]?(1|256|384|512)\b', 'SHA2'),
    (r'\bcrypt|scrypt|argon2', 'KDF'),
    (r'\bPBKDF2', 'KDF'),
    (r'\bEd25519\b', 'EdDSA'),
    (r'\bkyber|ML[-_]?KEM\b', 'PQC_KEM'),
    (r'\bdilithium|ML[-_]?DSA\b', 'PQC_SIG'),
    (r'\bSPHINCS|SLH[-_]?DSA\b', 'PQC_HASH_SIG'),
]

def scan_agility(repo_root: pathlib.Path) -> dict:
    findings = {}
    for src in repo_root.rglob("*"):
        if not src.is_file() or src.suffix not in {".py", ".go", ".c", ".h", ".java", ".ts", ".js"}:
            continue
        try:
            text = src.read_text(errors="ignore")
        except Exception:
            continue
        for pat, alg in HARDCODED_ALG_PATTERNS:
            matches = re.findall(pat, text, flags=re.IGNORECASE)
            if matches:
                findings.setdefault(alg, []).append({
                    "file": str(src.relative_to(repo_root)),
                    "count": len(matches),
                    "hardcoded": True,  # by definition: literal string in source
                })
    return findings

# Usage: audit = scan_agility(pathlib.Path("/srv/app"))
# A finding under every algorithm with hardcoded=True indicates a non-agile codebase
```

### 19.2 Automated Constant-Time CI Gate

```yaml
# .github/workflows/constant-time.yml (excerpt)
name: constant-time
on: [push, pull_request]
jobs:
  dudect:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - name: Build and run dudect
        run: |
          cd third_party/dudect
          make
          ./dudect --threshold 4.5 > result.txt
          if grep -q "leak" result.txt; then
            echo "::error::constant-time violation detected"
            cat result.txt
            exit 1
          fi
```

### 19.3 PQC TLS Scanner

```bash
# Scan a list of hosts for PQC TLS support
for host in $(cat targets.txt); do
  result=$(/opt/oqs-openssl/bin/openssl s_client -connect "$host:443" \
            -groups x25519_mlkem768 -tls1_3 </dev/null 2>&1 | \
            grep -E "Server Temp Key|Cipher" | tr '\n' '|')
  echo "$host|$result"
done | tee pqc_scan_$(date +%F).csv
```

---

## 20. Glossary

| Term | Definition |
|------|------------|
| **AEAD** | Authenticated Encryption with Associated Data; e.g., AES-GCM, ChaCha20-Poly1305 |
| **BKZ** | Block Korkine-Zolotarev lattice basis reduction algorithm |
| **CRQC** | Cryptographically Relevant Quantum Computer |
| **CPA** | Correlation Power Analysis |
| **DPA** | Differential Power Analysis |
| **EMA** | Electromagnetic Analysis |
| **FO transform** | Fujisaki-Okamoto transform; converts a weakly-secure PKE into a CCA-secure KEM |
| **HNDL** | Harvest Now, Decrypt Later |
| **HPKE** | Hybrid Public Key Encryption (RFC 9180) |
| **KEM** | Key Encapsulation Mechanism |
| **LWE / M-LWE** | (Module) Learning-With-Errors problem |
| **NTT** | Number Theoretic Transform (fast polynomial multiplication) |
| **OQS** | Open Quantum Safe project |
| **PQC** | Post-Quantum Cryptography |
| **SPA** | Simple Power Analysis |
| **WOTS+** | Winternitz One-Time Signature Plus |

---

## 21. References

### Standards and Specifications
- NIST FIPS 203 -- Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST FIPS 204 -- Module-Lattice-Based Digital Signature Standard
- NIST FIPS 205 -- Stateless Hash-Based Digital Signature Standard
- NIST SP 800-208 -- Recommendation for Stateful Hash-Based Signature Schemes
- NIST SP 800-227 (draft) -- Recommendations for Key-Encapsulation Mechanisms
- IETF draft-ietf-tls-hybrid-design -- Hybrid key exchange in TLS 1.3
- IETF RFC 8781 -- Multiple Key Exchanges in IKEv2
- IETF RFC 9180 -- Hybrid Public Key Encryption (HPKE)
- IETF draft-ietf-pquip-hybrid-signature-spectrums -- X.509 hybrid signature

### Side-Channel Analysis
- Kocher, Jaffe, Jun -- "Differential Power Analysis" (CRYPTO 1999)
- Brier, Clavier, Olivier -- "Correlation Power Analysis with a Leakage Model" (CHES 2004)
- Chari, Rao, Rohatgi -- "Template Attacks" (CHES 2002)
- Reparaz, Balasch, Verbauwhede -- "Detection and Prevention of Side-Channel Attacks" (IEEE D&T 2017)
- Bruneau et al. -- "Skylake Side-Channel: VFS-Node Introspection" (CHES 2018)

### PQC-Specific Side-Channel Research
- Bhasin et al. -- "First-Order Chosen-Ciphertext Attack on CCA-Secure NTRU / Kyber" (TCHES 2019)
- Ravi et al. -- "Generic Side-Channel Attacks on CCA-Secure Lattice-Based PKE and KEM" (TCHES 2020)
- Ravi et al. -- "Masked Implementations of Kyber" (TCHES 2022)
- Manganote et al. -- "KyberSlash: Exploiting Variable-Time Fisions in Post-Quantum Cryptography" (CHES 2021)
- Manganote et al. -- "Injecting Crystals: Single-Instruction Faults Enable Full Key Recovery of Dilithium" (TCHES 2023)
- Mohagheshghi et al. -- "GROUNDTRUTH: PQC Side-Channel Reference Dataset" (2024)
- Bosc et al. -- "Cross-Protocol Attacks on Kyber" (EUROCRYPT 2023)

### Library and Tool Documentation
- Open Quantum Safe project -- https://openquantumsafe.org/
- ChipWhisperer documentation -- https://wiki.newae.com/
- Riscure Inspector -- https://www.riscure.com/security-tools/inspector/
- SageMath LatticeReduce -- https://doc.sagemath.org/html/en/reference/matrices/sage/matrix/matrix_lll.html
- mupq / pqm4 -- https://github.com/mupq/pqm4
- dudect -- https://github.com/oreparaz/dudect

---

## Summary

Post-Quantum migration and side-channel analysis together cover the two largest emerging cryptographic attack surfaces. The migration is a multi-year engineering effort whose success depends less on the choice of primitive (NIST has decided for us) and more on **crypto-agility** -- the ability to swap algorithms without refactoring. The side-channel surface is universal: any device that performs secret-dependent computation leaks, and the attacker's job is to measure. The practical workflow for a Distinguished-tier crypto engagement:

1. **Inventory** every cryptographic asset (keys, algorithms, protocols, locations)
2. **Assess crypto-agility**: can algorithms be swapped via config, or is source modification required?
3. **Test PQC readiness**: deploy hybrid TLS in a canary path, measure middlebox compatibility
4. **Side-channel audit**: capture traces from at least one production-representative target, apply CPA on the secret-key path
5. **Report** with vendor-specific remediation, mapped to NIST / NSA CNSA / ANSSI / BSI guidance

The bar is rising: defenders who treat PQC as "the next decade's problem" are already behind, because HNDL adversaries are operating today. Defenders who treat side-channel analysis as exotic are leaving the cheapest real-world breaks on the table.
