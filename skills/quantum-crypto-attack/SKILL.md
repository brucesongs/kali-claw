---
name: quantum-crypto-attack
description: Post-quantum and modern national cryptography attack surface testing covering NIST PQC candidates (ML-KEM/ML-DSA/SLH-DSA), hybrid TLS analysis, QKD/BB84 protocol attacks, Chinese national crypto (SM2/SM3/SM4/SM9) implementation flaws, lattice/hashing signature probing, and quantum-vulnerable RSA/ECC asset discovery using liboqs, GmSSL, cloudflare/circl, OQS-OpenSSL, and PQCrypto-Break.
origin: github-trending-2026
version: 0.1.32
compatibility: ">=0.1.31"
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - WebFetch
metadata:
  domain: cryptography
  tool_count: 12
  guide_count: 2
  mitre: "T1040-Network Sniffing (crypto layer), T1573-Encrypted Channel (PQC analysis), forward-looking (no canonical MITRE mapping yet)"
  keywords:
    - post-quantum-cryptography
    - PQC
    - ML-KEM
    - ML-DSA
    - SLH-DSA
    - Kyber
    - Dilithium
    - SPHINCS
    - hybrid-TLS
    - QKD
    - BB84
    - photon-number-splitting
    - detector-blinding
    - SM2
    - SM3
    - SM4
    - SM9
    - GmSSL
    - Tongsuo
    - GM-SSL
    - GB/T-38636
    - RFC-8998
    - SNDL
    - store-now-decrypt-later
    - CNSA-2.0
    - NIST-800-227
    - FIPS-203
    - FIPS-204
    - FIPS-205
    - lattice-cryptography
    - NTT
    - side-channel
    - crypto-agility
    - ROCA
    - XMSS
    - LMS
---




# Skill: Post-Quantum & Modern National Cryptography Attack

> **Supplementary Files**:
> - `payloads.md` — Command catalogue for liboqs, OQS-OpenSSL, GmSSL, cloudflare/circl, PQCrypto-Break, plus PoC code for quantum-vulnerability inventory, Shor/Grover impact modelling, ML-KEM/ML-DSA probing, hybrid TLS analysis, BB84 photon-number-splitting, SM2 side-channel, SM4 cache timing, and crypto-agility stress tests — 19 sections with real OpenSSL/GmSSL commands.
> - `test-cases.md` — Structured test cases (RSA/ECC quantum exposure inventory, ML-KEM Kyber parameter audit, hybrid TLS handshake analysis, GmSSL SM2/SM3 review, QKD BB84 PNS PoC, lattice side-channel timing, crypto-agility failover drill, post-quantum migration roadmap) — 12 cases across 6 categories with verification / pass-criteria checklist.
> - `guides/quantum-crypto-attack-playbook.md` — End-to-end playbook: scoping → quantum exposure inventory → PQC config audit → national crypto testing → QKD/protocol attacks → migration roadmap. Includes pre-assessment checklist, NIST SP 800-208 / 800-227 mapping, hybrid TLS deployment matrix, and a prioritized migration report template. Adds Side-Channel Attack Labs and QKD Implementation Audits sections.
> - `guides/pqc-migration-assessment-playbook.md` — Post-quantum cryptography migration assessment playbook: regulatory landscape (NIST / CNSA 2.0 / ETSI / GB/T 38636), NIST PQC timeline and algorithm selection, SNDL threat modeling, hybrid TLS rollout, KEM/signature parameter selection, SM-series migration for China compliance, crypto-agility framework, and assessment deliverables template. Includes real-world case studies (Cloudflare KEMTLS, Google CECPQ2, Signal PQXDH, Apple PQ3).

## Summary

Post-quantum and modern national cryptography attack surface testing. This skill is **forward-looking and preparation-focused**: it does not assume a cryptographically relevant quantum computer (CRQC) exists today, but evaluates whether systems will survive the day one becomes available, and tests the implementation correctness of the post-quantum and national algorithms that defenders are racing to adopt.

**Tools**: liboqs, OQS-OpenSSL, GmSSL, cloudflare/circl, PQCrypto-Break, TNO Penguin, Qiskit (simulator), RsaCtfTool (ROCA), openssl s_client (TLS 1.3 groups), oqs-provider, sphincs-utils, gmssl-cli

**Domain**: cryptography

**MITRE ATT&CK**: T1040-Network Sniffing (crypto layer), T1573-Encrypted Channel (PQC analysis) — forward-looking, no canonical MITRE mapping yet

## Description

This skill tests three things that defenders must get right *before* a Cryptographically Relevant Quantum Computer (CRQC) is announced, and one thing they must get right today:

1. **Quantum exposure inventory** — Which RSA/ECC keys in the organization will become forgeable the day Shor's algorithm runs at scale? Long-lived CA keys, root signing keys, and identity-bound keys are most exposed. Data covered by "store-now-decrypt-later" (SNDL) collection is already lost if confidentiality depends on classical public-key encryption.
2. **Post-quantum cryptography (PQC) adoption correctness** — The NIST PQC standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) shipped in 2024. Real-world deployments use hybrid modes (classical + PQC) for transition safety. Implementation flaws — incorrect parameter sets, lattice side-channels, deterministic-signature nonce reuse, hybrid downgrade attacks — are the new attack surface.
3. **National cryptography implementation** — Chinese national cryptography (SM2/SM3/SM4/SM9, mandatory in PRC government, finance, and critical infrastructure), Russian GOST, and other national suites are required in their respective markets. Their mathematical foundations are sound, but implementations (GmSSL, Tongji SSL, BabaSSL) have shipped side-channel bugs, weak curve parameters, and TLS handshake divergences.
4. **QKD/BB84 protocol attack surface** — Quantum Key Distribution (BB84, E91, MDI-QKD) promises information-theoretic security but real-world deployments (commercial QKD boxes from ID Quantique, Chinese QKD backbones) have been broken by photon-number-splitting, detector blinding, and Trojan-horse attacks that exploit implementation gaps between the mathematical model and the hardware.

**Core Insight**: The threat model for this skill is not "an attacker breaks NIST Round 4 today." It is "a defender deploys ML-KEM-768 tomorrow and accidentally enables a downgrade-to-classical path, or ships SM4-ECB with a fixed key in a TLS stack that they believed was sound because it passed the certification." The attacker surface is *implementation* and *migration risk*, exactly as it has been for classical crypto. The math is hard; the bugs are familiar.

**Key Attack Surfaces**:

- **Shor-vulnerable asset inventory** — RSA-2048 and ECC P-256 keys become forgeable under a CRQC with ~20M physical qubits and hours of runtime. Anything that needs to remain confidential for >10 years and uses classical public-key encryption today is already exposed to SNDL collection.
- **Grover's effect on symmetric keys** — AES-128 offers ~64 bits of post-quantum security (Grover's quadratic speedup). NIST recommends AES-256 for long-term quantum-resistant confidentiality. SHA-256 offers ~128 bits post-quantum (still safe); SHA-1 is broken classically and post-quantum.
- **PQC parameter misuse** — ML-KEM-512 / ML-KEM-768 / ML-KEM-1024 have different security levels (NIST Levels 1/3/5). Picking the wrong one for the threat model, or shipping a development parameter set in production, is the equivalent of shipping RSA-512 in 2010.
- **Hybrid downgrade attacks** — A hybrid TLS handshake that offers `x25519+mlkem768` but the server also accepts plain `x25519` can be downgraded by an active MITM if the negotiation is not authenticated by the Finished message. This is the post-quantum equivalent of the POODLE/BAR-Mitzvah downgrade family.
- **Lattice side-channel** — ML-KEM (Kyber) decryption and ML-DSA (Dilithium) signing involve operations (NTT, rejection sampling) that have already been shown to leak timing and power information. Cache-timing attacks on matrix-vector multiplication are the new Bleichenbacher.
- **Hash-based signature state** — SLH-DSA (SPHINCS+) is stateless, but the older XMSS/LMS schemes are stateful — reusing a one-time signature key state is catastrophic. State management bugs in HSM-backed XMSS deployments are the post-quantum RNG-reuse bug.
- **QKD implementation attacks** — Photon-Number-Splitting (PNS), Detector Blinding, Trojan-Horse, and After-Pulse attacks break commercial QKD hardware by exploiting the gap between the idealized single-photon source and the real attenuated-laser/detector hardware. Academic demonstrations (Lydersen 2010, Weier 2011) are reproducible.
- **Chinese national crypto (SM2/SM3/SM4/SM9) flaws** — SM2 (EC-based, analogous to ECDSA+ECIES on a 256-bit curve), SM3 (256-bit hash, Merkle-Damgard like SHA-256), SM4 (128-bit block cipher, the AES counterpart), SM9 (identity-based encryption). Implementations (GmSSL, Tongji SSL, BabaSSL, Tongsuo) have shipped weak random generation, side-channel-leaky scalar multiplication, and TLS handshake incompatibilities.
- **ROCA and related RSA vulnerabilities** — CVE-2017-15361 (ROCA) affected Infineon-generated RSA keys where prime generation had a detectable fingerprint enabling factorization. Although classical, ROCA is the canonical example of "your RSA key is already weaker than you think" and is a model for PQC parameter-generation bugs.

**Difference from `crypto-attacks`**: Crypto-attacks covers *classical* cryptographic algorithm weaknesses (RSA, AES, ECDSA, padding oracles, JWT attacks, hash length extension). Quantum-crypto-attack covers *post-quantum* algorithms (ML-KEM, ML-DSA, SLH-DSA), *national* suites (SM2/SM3/SM4/SM9, GOST), *QKD protocols*, and the *migration risk* of moving from classical to post-quantum. The boundary: if the algorithm has been a NIST standard since the 1990s and is not a national suite, it belongs in crypto-attacks; if it is post-1995 lattice-based, hash-based signature, code-based, multivariate, QKD, or a national suite, it belongs here.

**Difference from `vpn-attack`**: VPN-attack covers TLS/IPsec at the network layer (cipher suite downgrade, IKE aggressive mode, weak DH groups, VPN client exploitation). Quantum-crypto-attack covers the *post-quantum* TLS extensions (hybrid key exchange, X25519+ML-KEM), the *national* TLS variants (GM SSL, Tongji SSL), and the QKD-as-key-source deployment model. Where vpn-attack finds a weak DH group, quantum-crypto-attack finds that the hybrid PQC handshake can be downgraded.

**Difference from `blockchain-web3`**: Blockchain-web3 covers smart contract and DeFi logic bugs. The cryptography behind modern blockchains (secp256k1, Ed25519, BLS) is classical and lives in crypto-attacks — but blockchains that adopt post-quantum signatures (e.g., hash-based signatures via QuipNetwork/hashsigs-solidity, lattice-based schemes in QRL) land here. The crossover case is auditing a bridge that uses a PQC signature scheme for validator consensus.

**Difference from `web-xss` / `web-sqli`**: Those skills cover application-layer injection. They are not cryptographic skills. The only overlap is when an XSS exfiltrates a long-lived RSA private key from the browser — at which point the *key exposure* (Shor-vulnerable asset loss) is a quantum-crypto-attack finding, even though the *vector* was XSS.

**Difference from `security-misconfiguration`**: Security-misconfiguration covers default credentials, verbose errors, missing headers. Quantum-crypto-attack covers algorithm-agility misconfiguration (server cannot switch algorithms in an emergency), wrong PQC parameter sets, and disabled hybrid modes — which is a specialized cryptographic misconfiguration with longer-term consequences.

---

## Use Cases

- **Post-quantum migration readiness assessment** — Inventory every long-lived RSA/ECC key across the estate (CA, root, signing, identity, code-signing), classify by Shor-vulnerability and remaining confidentiality lifetime, produce a prioritized migration roadmap aligned with NIST SP 800-227 and CNSA 2.0.
- **Hybrid TLS deployment validation** — Validate that a server advertising `x25519_kyber768` or `x25519_mlkem768` (draft-ietf-tls-hybrid-design) actually negotiates the hybrid group, rejects downgrades, and that the Finished message binds the negotiation. Used before flipping a hybrid TLS configuration to production.
- **ML-KEM / ML-DSA / SLH-DSA implementation audit** — Static and dynamic review of a vendor's FIPS 203/204/205 implementation: parameter sets in use, decapsulation constant-time behavior, signature nonce handling, deterministic vs randomized signature mode, key serialization.
- **Chinese national crypto compliance & flaw testing** — Test a GM SSL (GB/T 38636-2020) deployment for SM2/SM3/SM4 correctness, ECC scalar-multiplication side-channel, SM4 mode misuse (ECB with structured plaintext), and handshake divergence from RFC 8998 (TLS 1.3 with SM cipher suites).
- **QKD/BB84 protocol attack surface review** — For organizations deploying commercial QKD hardware (finance, government, defense), evaluate susceptibility to photon-number-splitting, detector blinding, Trojan-horse, and side-channel attacks; recommend decoy-state and device-independent countermeasures.
- **"Store-now-decrypt-later" risk assessment** — Identify data flows where long-term-confidential data (health, legal, M&A, state secrets) traverses classical public-key encryption, and quantify SNDL exposure against plausible CRQC timelines (NIST/ETSI/NSA estimates).
- **Crypto-agility stress test** — Verify that a system can switch algorithms in response to a "drop everything and migrate" emergency (the "Cryptopocalypse" exercise). Can the TLS stack disable RSA in 24 hours? Can the PKI reissue every certificate under a new algorithm? This is rarely tested and routinely fails.
- **Lattice side-channel lab assessment** — In an authorized lab setting, perform timing and power analysis on ML-KEM decapsulation / ML-DSA signing hardware (HSM, secure element) to detect non-constant-time NTT or rejection-sampling leakage.
- **Hash-based signature state-management audit** — Audit XMSS/LMS deployments (stateful hash-based signatures per RFC 8391/8554) for state-reuse risk in HSM-backed multi-signer setups; verify SLH-DSA (SPHINCS+) deployments are stateless and parameterized correctly.
- **PQC vulnerability disclosure triage** — When a new PQC implementation CVE lands (e.g., a Kyber decapsulation timing leak), rapidly determine which assets in the estate are affected and produce an emergency-patch priority list.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **liboqs** | Reference C library implementing all NIST PQC candidates; foundation for OQS-OpenSSL, oqs-provider | `git clone https://github.com/open-quantum-safe/liboqs && cmake -B build && cmake --build build` |
| **OQS-OpenSSL / oqs-provider** | OpenSSL 3.x provider enabling PQC algorithms in TLS (hybrid and pure-PQC handshakes) | `openssl list -providers -provider oqsprovider`; `openssl s_client -connect h:443 -groups x25519_kyber768` |
| **cloudflare/circl** | Go crypto library with Kyber, Dilithium, P-256+Kyber hybrid; used to test Cloudflare-style hybrid TLS edge | `go test -run Kyber ./crypto/kem/kyber/...` |
| **GmSSL** | Chinese national crypto implementation of SM2/SM3/SM4/SM9 + GM SSL (GB/T 38636); the canonical open-source 国密 stack | `gmssl sm2 -sign -in sm3.hash -key sm2.pem`; `gmssl s_client -connect h:443 -gmtls` |
| **Tongsuo / BabaSSL** | Alibaba/Tongsuo OpenSSL fork with SM and PQC support; production-deployed in Chinese cloud infra | `tongsuo s_server -accept 443 -tls1_3 -ciphersuites TLS_SM4_GCM_SM3` |
| **PQCrypto-Break / TNO Penguin** | Research tooling for lattice side-channel and parameter-set probing of PQC implementations | `./penguin --target kyber768 --mode timing --samples 100000` |
| **Qiskit** | IBM quantum simulator for modelling Shor/Grover cost on small problem instances (educational / capacity modelling) | `from qiskit.algorithms import Shor; Shor(N=15).run(...)` |
| **RsaCtfTool** (ROCA mode) | Classical tool; ROCA detection (`--attack roca`) flags Infineon-fingerprint RSA keys (CVE-2017-15361) | `RsaCtfTool --publickey pub.pem --attack roca --private` |
| **openssl s_client** (TLS 1.3 groups) | Standard OpenSSL; `-groups` selects key exchange including PQC hybrid once oqs-provider loaded | `openssl s_client -connect host:443 -tls1_3 -groups x25519_mlkem768 -msg` |
| **oqs-demos / oqs-test** | Test harness from Open Quantum Safe for probing which hybrid groups a public TLS server supports | `oqs-test --host h --port 443 --json` |
| **gmssl-cli / GmSSL Java** | CLI and Java bindings for scripting SM2/SM3/SM4 audit and cert generation | `gmssl genpkey -algorithm SM2 -out sm2key.pem` |
| **hash-sigs (XMSS/LMS) libs** | Reference stateful hash-based signature libraries (RFC 8391/8554) for state-mgmt audit | `xmss genkey --params XMSS-SHA2_10_256 -o xmss.key` |

Auxiliary tooling: **Wireshark** (PQC TLS handshake dissector), **sslscan/testssl.sh** (PQC group detection via OpenSSL backend), **侧信道 analyzers** (ChipWhisperer, Riscure Inspector for power side-channel lab work), **Wireshark QKD dissector** (commercial QKD key-sifting protocol).

---

## Methodology

### Attack Chain

```
[1] Quantum Exposure Inventory     [2] Shor/Grover Impact Modelling
  - RSA/ECC key discovery             - Per-key forgeability timeline
  - Key lifetime / purpose            - Symmetric key strength reduction
  - SNDL data-flow mapping            - Hash function collision horizon
  - CA / root / signing key map       - Stateful-sig state-reuse check
        |                                    |
        v                                    v
[3] PQC Config Audit                [4] National Crypto Testing
  - Hybrid TLS negotiation            - SM2/SM3/SM4/SM9 implementation
  - ML-KEM/ML-DSA/SLH-DSA params      - GM SSL / Tongji SSL handshake
  - Downgrade resistance              - Side-channel on scalar mult
  - Lattice side-channel (lab)        - SM4 mode / key hygiene
        |                                    |
        v                                    v
[5] QKD / Protocol Attacks           [6] Migration Roadmap & Reporting
  - BB84 PNS / detector blinding      - Prioritized key/cert replacement
  - Decoy-state verification          - Crypto-agility drill results
  - Side-channel on QKD hardware      - Hybrid → pure-PQC cutover plan
  - Key-sifting MITM                  - CNSA 2.0 / NIST SP 800-227 mapping
```

### Phase 1 — Quantum Exposure Inventory

Build a complete map of every long-lived asymmetric key in the estate. Sources: PKI inventory, internal CA database, code-signing cert list, SSH CA keys, KMS/HSM key attestation, certificate transparency logs. For each key, record: algorithm, key size, generation date, expected end-of-life, data it protects, and the remaining confidentiality lifetime of that data. The output is a Shor-exposure matrix that ranks keys by *risk = sensitivity × (remaining confidentiality lifetime − CRQC arrival estimate)*.

### Phase 2 — Shor / Grover Impact Modelling

For each inventoried key, classify its post-quantum fate. RSA and ECC (any practical size) are forgeable under a CRQC — these are Shor-vulnerable. DSA, ECDSA, EdDSA, Diffie-Hellman, ECDH all collapse. Symmetric keys: AES-128 → ~64-bit post-quantum (upgrade to AES-256), SHA-256 → ~128-bit post-quantum (acceptable), ChaCha20 → ~128-bit post-quantum (acceptable). Hash-based signatures (SLH-DSA, XMSS, LMS) are not weakened by Shor. Lattice-based (ML-KEM, ML-DSA) and code-based (Classic McEliece) are designed to be quantum-resistant. The deliverable is a per-asset quantum-risk classification.

### Phase 3 — PQC Configuration Audit

For systems already deploying PQC, verify the configuration is correct. Hybrid TLS: confirm the negotiated group is the hybrid (e.g., `x25519_mlkem768`), confirm the server rejects pure-classical downgrades, confirm the Finished message binds the group selection. Parameter sets: confirm ML-KEM-768 (NIST Level 3) or stronger is in use, not ML-KEM-512 for production. Signature schemes: confirm deterministic-mode ML-DSA is not leaking through side-channel; confirm SLH-DSA parameter sets match the threat model (fast vs small variants). Crypto-agility: confirm the system can disable an algorithm in 24 hours if a catastrophic PQC break is announced.

### Phase 4 — National Cryptography Testing

For SM2/SM3/SM4/SM9 deployments (mandatory in PRC government/finance/critical infrastructure per GB/T 38636-2020 and GB/T 32918/32905/32907): audit the implementation (GmSSL, Tongsuo, BabaSSL, Tongji SSL). Check SM2 scalar-multiplication constant-timeness, SM3 collision resistance implementation (length extension on Merkle-Damgard), SM4 mode usage (GCM/CTR, never ECB), SM9 master-secret handling. Verify GM SSL handshake (ECDHE-SM2 + SM3 + SM4-GCM) is negotiated per RFC 8998, and that the deployment is not silently falling back to TLS 1.2 with RSA.

### Phase 5 — QKD / Protocol Attacks

For QKD deployments (commercial ID Quantique Clavis^3, Chinese QKD backbones, quantum-secured metropolitan networks): model the BB84/E91/MDI-QKD attack surface. PNS attacks apply when the source is an attenuated laser (multi-photon pulses). Detector blinding applies to InGaAs APD detectors. Trojan-horse attacks inject light back into the source. Decoy-state protocols mitigate PNS — verify they are enabled and correctly parameterized. Device-independent QKD (DI-QKD) closes most implementation loopholes — verify whether the deployment is DI or only BB84. Note: QKD security is implementation-bound; even "mathematically proven" QKD is only as strong as its hardware.

### Phase 6 — Migration Roadmap & Reporting

Synthesize findings into a prioritized roadmap aligned with NIST SP 800-227 (PQC migration), CNSA 2.0 (NSA national-security suite), and any applicable national mandates (e.g., China's 国密 compliance schedule). Rank by: (1) Shor-exposed long-lived keys, (2) SNDL data flows, (3) PQC parameter-misuse findings, (4) National crypto implementation flaws, (5) Crypto-agility gaps. Provide a hybrid → pure-PQC cutover plan with rollback, and a post-quantum readiness score (0-100) comparable across business units.

### Defense Perspective

| Defense Measure | Description | Attack Types Countered |
|-----------------|-------------|----------------------|
| Hybrid TLS (X25519+ML-KEM) | Classical + PQC key exchange in a single handshake; PQC break does not collapse session | Pure-PQC lattice break, classical-only downgrade, SNDL on TLS sessions |
| ML-KEM-768 minimum parameter | NIST PQC Level 3 (AES-192-equivalent); rejects weak ML-KEM-512 production use | Parameter-set misuse, PQC level-1 downgrade |
| Crypto-agility infrastructure | Algorithm registry, cert auto-rotation, kill-switch to disable an algorithm in <24h | Any future catastrophic algorithm break (classical or PQC) |
| Constant-time lattice impl | Constant-time NTT, rejection sampling, matrix-vector multiply in ML-KEM/ML-DSA | Timing and cache side-channel on lattice operations |
| Decoy-state + DI-QKD | Decoy-state protocol closes PNS loophole; DI-QKD closes detector attacks | PNS, detector blinding, Trojan-horse on QKD hardware |
| SM2/SM3/SM4 with vetted libs | Use GmSSL/Tongsuo with constant-time SM2 scalar mult, SM4-GCM only, RFC 8998 TLS 1.3 | SM scalar-mult side-channel, SM4 ECB, GM TLS handshake downgrade |
| AES-256 for long-term data | Quadruples post-quantum brute-force cost vs AES-128 (Grover) | SNDL on symmetric-encrypted long-term data |
| HSM-backed XMSS state mgmt | Hardware-enforced monotonic state counter for stateful hash-based signatures | XMSS/LMS state-reuse catastrophic forgery |

---

## Practical Steps

### 1. Build the Quantum Exposure Inventory

```bash
# Enumerate every TLS certificate seen on the estate (CT logs + internal scan)
# Tools: crt.sh JSON API, ZMap + ZGrab2 TLS module
echo "target.com" | zgrab2 tls --port 443 --tls1-3 | jq '.data.tls.result.handshake_log.server_certificates'

# For each cert, extract pubkey and classify
openssl x509 -in cert.pem -noout -text | grep -E "Public Key Algorithm|RSA Public Key|Public-Key|ECDSA"

# Flag every RSA / ECDSA / Ed25519 / DSA key as Shor-vulnerable
# Cross-reference with KMS/HSM attestation for key provenance and lifetime
```

### 2. Probe Hybrid TLS on a Target

```bash
# Load oqs-provider into OpenSSL 3.x
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules
openssl list -providers -provider oqsprovider -verbose

# Negotiate hybrid group against the target
openssl s_client -connect target.example.com:443 -tls1_3 \
    -groups x25519_kyber768 -msg 2>&1 | grep -A2 "ServerHello"

# Confirm the negotiated group is the hybrid (not downgraded to plain x25519)
# If the server accepts the hybrid but the Finished MAC does not bind it,
# you have a downgrade-resistant finding.

# Scan for all PQC groups the server will negotiate
oqs-test --host target.example.com --port 443 --json | jq '.supported_groups'
```

### 3. Audit ML-KEM / ML-DSA Configuration

```bash
# Inspect a vendor's liboqs-linked binary for compiled-in parameter sets
strings vendor_crypto.so | grep -iE "ML-KEM-|KYBER|ML-DSA-|DILITHIUM|SLH-DSA|SPHINCS"

# Generate keys with each parameter set and confirm sizes match FIPS 203/204/205
openssl -provider oqsprovider -genpkey -algorithm mlkem768 -out mlkem768.pem
openssl pkey -in mlkem768.pem -noout -text | head

# Confirm decapsulation is constant-time (lab setting only)
# See payloads.md §11 for ChipWhisperer / timing-collection commands
```

### 4. Test Chinese National Crypto (SM2/SM3/SM4)

```bash
# Install GmSSL (open-source reference 国密 implementation)
git clone https://github.com/guanzhi/GmSSL
cd GmSSL && mkdir build && cd build && cmake .. && make && sudo make install

# Generate SM2 keypair, sign and verify
gmssl genpkey -algorithm SM2 -out sm2key.pem
echo -n "hello" | gmssl sm3 -out sm3.bin
gmssl sm2 -sign -in sm3.bin -key sm2key.pem -out sig.der
gmssl sm2 -verify -in sm3.bin -pubkey sm2pub.pem -sig sig.der

# SM4 (symmetric) — confirm GCM mode, never ECB
echo "secret" | gmssl sm4 -e -key $(openssl rand -hex 16) -iv $(openssl rand -hex 16) -out ct.bin
# If a vendor exposes sm4-ecb, that is a finding.

# Probe GM SSL (GB/T 38636) TLS handshake
gmssl s_client -connect target:443 -gmtls -msg 2>&1 | grep -E "ECC-SM2|SM4|SM3"
# Confirm RFC 8998 TLS 1.3 SM cipher suites negotiate correctly
```

### 5. Model QKD Attack Surface

```bash
# QKD is hardware; lab evaluation, not pure software.
# For a documented BB84 deployment, verify:
#   - Source: attenuated laser (multi-photon PNS risk) vs true single-photon
#   - Decoy-state protocol enabled (closes PNS)
#   - Detector: InGaAs APD (blinding risk) vs SNSPD (lower risk)
#   - DI-QKD mode (closes detector side-channels) vs standard BB84
#
# See payloads.md §7 for the academic reproducibility references
# (Lydersen 2010, Weier 2011, Gerhardt 2011).
```

### 6. Stress-Test Crypto Agility

```bash
# Scenario: a catastrophic break of Kyber is announced at 09:00 Monday.
# Can the org disable Kyber everywhere by 09:00 Tuesday?
#
# Test: disable ML-KEM in the TLS provider and measure breakage
# OpenSSL 3.x — remove group from config
sed -i 's/^Groups = .*/Groups = X25519/' /etc/ssl/openssl.cnf
systemctl reload nginx
# Measure: which clients fail? which internal services break? is there rollback?
```

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.**

---

## Common Pitfalls

- **Treating PQC deployment as a checkbox** — Adopting ML-KEM in TLS is a 2-week engineering task; getting hybrid-mode downgrade resistance, constant-time implementation, cert chain PQC support, and rollback working across a real estate is a multi-year program. Treating "we enabled Kyber" as "we are post-quantum ready" is the #1 cause of post-quantum findings.
- **Forgetting SNDL on data captured before migration** — Migrating TLS to hybrid PQC in 2027 does not protect traffic that was captured in 2022 and stored by an adversary. SNDL exposure must be assessed *as-of-collection-time*, not as-of-migration-time.
- **Assuming QKD is "provably secure"** — The security proof of BB84 assumes single photons, ideal detectors, and no side-channels. Real hardware violates all three. QKD deployments that pass certification can still be broken by PNS, detector blinding, or Trojan-horse attacks unless decoy-state + DI-QKD are deployed.
- **Picking ML-KEM-512 to save bandwidth** — ML-KEM-512 is NIST Level 1 (AES-128-equivalent, post-quantum ~64-bit). Production deployments should use ML-KEM-768 (Level 3) minimum; the bandwidth saving of 256 bytes per handshake is not worth halving the security level.
- **Overlooking national-crypto handshake divergence** — A server configured for both RFC 8998 (TLS 1.3 SM suites) and TLS 1.2 RSA can be silently downgraded to TLS 1.2 RSA by an active MITM if the negotiation is not authenticated. National-crypto deployments are not exempt from classical downgrade attacks.
- **Skipping crypto-agility drills** — Most organizations have never run a "drop this algorithm in 24 hours" exercise. When a real break is announced, the org discovers that the algorithm is hardcoded in 17 places, 4 HSMs, and a CA with a 10-year root. Drilling *before* the break is the only way to find these.

## Automation and Scripting

Automate quantum-exposure inventory by scripting CT-log pulls (crt.sh, Cloudflare Merkle Town) and internal cert scans (ZMap + ZGrab2) into a database keyed by public-key fingerprint, with columns for algorithm, key size,issuer, validity, and asset owner. Run a nightly job that flags any new Shor-vulnerable long-lived key issued since the last run. For hybrid-TLS validation, run `oqs-test` against every TLS endpoint weekly and diff the supported-group list — any endpoint that drops a hybrid group is a regression. For SM cipher audits, wrap GmSSL commands in a Python harness that exercises every code path (keygen, sign, verify, encrypt, decrypt, TLS handshake) and asserts constant-timeness using `dudect`. For QKD lab work, automate the photon-source characterization (mean photon number, multi-photon probability) using a Python + ChipWhisperer harness, and alert if multi-photon probability exceeds the decoy-state threshold.

## Reporting and Documentation

Quantum-crypto findings should be reported with explicit time horizons: "this RSA-2048 root CA key is forgeable under a CRQC estimated to arrive in 2030-2035 — replace by 2028 to maintain 2-year margin." Distinguish *current* risks (SM4-ECB misuse, hybrid downgrade, lattice side-channel in lab setting) from *future* risks (Shor breaking RSA). Map findings to NIST SP 800-227 (PQC migration), CNSA 2.0 (national-security suite), GB/T 38636-2020 (GM SSL), GB/T 32918 (SM2), GB/T 32905 (SM3), GB/T 32907 (SM4). For each finding include: affected assets, current algorithm, recommended algorithm, parameter set, migration window, and rollback plan. Include a post-quantum readiness score (0-100) computed from inventory coverage, hybrid-TLS coverage, crypto-agility drill results, national-crypto compliance, and QKD attack-surface posture.

## Legal and Ethical Considerations

Testing post-quantum and national-crypto deployments is generally non-intrusive (passive handshake observation, parameter-set inspection). Lab-based side-channel work on lattice implementations requires authorized hardware access and should never be performed on production HSMs without explicit written authorization — a power-analysis campaign against a production HSM can degrade its certification. QKD hardware testing (PNS, detector blinding) is invasive and should only be performed in an authorized lab; commercial QKD boxes are safety-class equipment in some jurisdictions. Do not store captured SNDL data beyond the engagement window. National-crypto compliance testing in mainland China is subject to the Cryptography Law (2020) — verify scope with local counsel before testing SM-suite deployments in PRC. When publishing PQC implementation findings, coordinate with the vendor under a coordinated disclosure timeline; PQC implementations are early in their lifecycle and a premature disclosure can set back industry migration.

## Integration with Other Tools

Quantum-crypto findings integrate with adjacent skills. Classical crypto-attacks feeds the quantum-exposure inventory (every RSA key found by RsaCtfTool ROCA mode is a Shor-vulnerable asset). VPN-attack informs which TLS endpoints should be tested for hybrid-PQC support. Web skills (web-xss, web-auth-bypass) identify exfiltration vectors for long-lived private keys (browser-resident CA keys, JWT signing keys) — when a key is exfiltrated, the *quantum-crypto* finding is the SNDL exposure of data signed by that key. Supply-chain-security informs which third-party TLS stacks (and their PQC providers) are in use. The crypto-agility drill output feeds into incident-response playbooks for the "drop-this-algorithm" scenario. Use burpsuite to observe hybrid-PQC TLS handshakes at the application layer, combining network-layer crypto analysis with application-layer testing.

## Case Studies and Examples

- **ROCA (CVE-2017-15361)** — Infineon's RSA key generation on TPM chips produced keys with a detectable fingerprint (primes clustered in a specific modular form), enabling factorization of RSA-2048 in ~$1 of compute. Although a classical attack, ROCA is the canonical "your RSA is already weaker than the algorithm spec" lesson and the model for PQC parameter-generation bugs. Estonian national ID cards had to be reissued.
- **Dragonblood (WPA3)** — Side-channel vulnerabilities (CVE-2019-9494) in the Dragonfly key exchange used by WPA3-SAE allowed password partitioning attacks via timing and cache. The lesson transfers directly to lattice PQC: the math is fine, the implementation leaks.
- **Kyber decapsulation timing (2022)** — Multiple research disclosures showed non-constant-time NTT in early Kyber implementations. The fix was straightforward (constant-time code) but required reissuing every Kyber-encrypted session and reauditing every deployment.
- **Tongji SSL SM2 side-channel (multiple CVEs)** — Implementations of SM2 scalar multiplication in Tongji SSL and BabaSSL shipped with non-constant-time code, allowing private-key recovery via timing. The fix is constant-time scalar multiplication; the lesson is that national crypto is not exempt from classical side-channel discipline.
- **ID Quantique Clavis^3 detector blinding (Lydersen 2010, industrial reproducibility 2011)** — Commercial QKD hardware was blinded by injecting continuous light into the detector, forcing it into a deterministic state and allowing the attacker to forge the key. The countermeasure (detector watchdog, decoy-state) is now standard, but older deployed QKD hardware remains vulnerable.

## Detection and Evasion

Defenders can detect quantum-crypto reconnaissance through several indicators: unusual TLS ClientHello patterns that probe every PQC group (oqs-test-style scanning), certificate inventory queries against internal PKI databases, and CT-log enumeration at scale. For lattice side-channel lab work, the hardware setup (oscilloscope, ChipWhisperer proximity to an HSM) is visible to physical security. For QKD hardware probing, detector-trip logs in commercial QKD boxes record anomalous photon-count patterns. To evade detection during authorized testing: spread PQC group probing across many ClientHellos over time, run CT-log pulls from distributed IPs, and conduct lab side-channel work in authorized physical facilities. The forward-looking nature of this skill means most testing is preparation-focused rather than exploitation-focused — there is often no "exploit traffic" to hide.

## Advanced Techniques

Beyond the core workflow, advanced quantum-crypto testing includes: (1) **fault injection on lattice signatures** — laser/clock-glitch fault attacks on ML-DSA signing that leak the secret polynomial through malformed outputs; (2) **stateful hash-sig state-reuse PoCs** — demonstrate XMSS key-state reuse in a multi-signer HSM scenario to motivate hardware-enforced state counters; (3) **multi-target side-channel on Kyber** — a single power trace analyzed across many decapsulation calls to amortize the attack cost; (4) **DI-QKD security proof verification** — for a deployment claiming DI-QKD security, verify the Bell inequality violation measurement is statistically significant, not an artifact of detector calibration; (5) **PQC cert chain analysis** — full PKI chain review where root, intermediate, and leaf each may use different PQC algorithms (e.g., SLH-DSA root for hash-agility, ML-DSA leaf for performance); (6) **SNDL data-flow modelling** — graph analysis of every data flow that crosses classical public-key encryption, weighted by data sensitivity and confidentiality lifetime, to prioritize migration.

## Tool Comparison Matrix

| Tool | Best For | Speed | Coverage | Skill Level |
|------|----------|-------|----------|-------------|
| **liboqs / oqs-provider** | Reference PQC implementation in OpenSSL | Fast | All NIST PQC candidates | Intermediate |
| **cloudflare/circl** | Go-language PQC + hybrid testing | Fast | Kyber, Dilithium, hybrids | Intermediate |
| **GmSSL** | SM2/SM3/SM4/SM9 reference + GM SSL | Moderate | Full 国密 suite | Beginner |
| **Tongsuo / BabaSSL** | Production Chinese cloud PQC + SM | Fast | SM + PQC, OpenSSL-compatible | Intermediate |
| **PQCrypto-Break / Penguin** | Lattice side-channel research | Slow (lab) | Kyber, Dilithium | Advanced |
| **Qiskit** | Quantum algorithm simulation / education | Slow (sim) | Shor, Grover, small N | Advanced |
| **RsaCtfTool (ROCA)** | Classical RSA + ROCA detection | Fast | RSA + ROCA | Intermediate |

## Performance and Remediation

PQC operations are CPU-heavier than classical equivalents: ML-KEM-768 keygen is ~5x slower than X25519; ML-DSA-65 signing is ~50x slower than ECDSA P-256; SLH-DSA signatures are kilobytes (not bytes). Plan capacity: a hybrid TLS edge can absorb a 30-50% CPU increase vs classical. National-crypto operations (SM2/SM4) are roughly comparable to their classical analogs. For remediation, prioritize: (1) **Long-lived Shor-vulnerable keys** — root CAs, code-signing, identity-bound; replace first, with multi-year overlap. (2) **SNDL data flows** — switch to hybrid PQC TLS where the data has >10-year confidentiality lifetime. (3) **Crypto-agility infrastructure** — build before you need it; the org that cannot drop an algorithm in 24 hours is the org that gets breached by the next algorithm break. (4) **National-crypto implementation flaws** — patch the lib, reissue affected certs. (5) **QKD hardware upgrades** — add decoy-state and detector watchdog; consider DI-QKD for new deployments.

## Hacker Laws

1. **First Principles** — Post-quantum migration is not "swap RSA for Kyber." It is "rebuild every cryptographic decision around the assumption that the adversary has a quantum computer and that any algorithm may be broken at any time." Without crypto-agility as a first principle, the migration is whack-a-mole.
2. **Defense in Depth** — Hybrid TLS (classical + PQC) is defense in depth at the algorithm layer. If Kyber falls, X25519 still protects the session; if X25519 falls to a CRQC, Kyber still protects. Pure-PQC early in the migration removes this safety net.
3. **Obscurity Is Not Security** — National crypto suites (SM2/SM4) are not "more secure because they are Chinese" or "less secure because they are not NIST." They are algorithms, subject to the same implementation discipline. Kerckhoffs' principle applies equally to 国密 and NIST.
4. **Assume Breach** — Assume SNDL collection is happening today against every classical-encrypted long-term-confidential data flow. The breach has not happened *yet*, but the data has already been captured. Design accordingly.

---

## Cross-References

- **`skills/crypto-attacks/SKILL.md`** — Classical cryptographic algorithm attacks (RSA, AES, ECDSA, padding oracles, JWT). The quantum-crypto exposure inventory starts from the classical key inventory this skill produces.
- **`skills/vpn-attack/SKILL.md`** — TLS/IPsec at the network layer. Hybrid-PQC TLS testing extends this skill's TLS handshake analysis into the post-quantum era.
- **`skills/blockchain-web3/SKILL.md`** — Smart contract and DeFi security. Blockchains adopting post-quantum signatures (QRL, hashsigs-solidity) land here; classical blockchain crypto stays in crypto-attacks.
- **`skills/web-xss/SKILL.md`** / **`skills/web-auth-bypass/SKILL.md`** — Application-layer exfiltration of long-lived private keys (browser-resident CA keys, JWT signing keys) creates quantum-crypto SNDL findings.
- **`skills/security-misconfiguration/SKILL.md`** — Crypto-agility misconfiguration (inability to switch algorithms) is a specialized cryptographic misconfiguration with longer-term consequences.
- **`skills/supply-chain-security/SKILL.md`** — Third-party TLS stacks and their PQC providers are part of the supply-chain attack surface for PQC migration.
- **`skills/digital-forensics/SKILL.md`** / **`skills/anti-forensics/SKILL.md`** — SNDL data captured today becomes forensically relevant when a CRQC arrives; the gap between collection time and break time is the SNDL window.
- **Workspace playbook**: `guides/quantum-crypto-attack-playbook.md` — End-to-end workflow from inventory to migration roadmap.
- **Workspace playbook**: `guides/pqc-migration-assessment-playbook.md` — PQC migration assessment playbook: regulatory alignment, hybrid TLS rollout, SM-series migration, assessment deliverables.

## Learning Resources

  **Supplementary files for this skill**: payloads.md, test-cases.md, guides/quantum-crypto-attack-playbook.md, guides/pqc-migration-assessment-playbook.md
  **Related skills**: skills/crypto-attacks/SKILL.md, skills/vpn-attack/SKILL.md, skills/blockchain-web3/SKILL.md, skills/web-xss/SKILL.md, skills/security-misconfiguration/SKILL.md
  **External resources**:
  - **NIST PQC Standardization**: https://csrc.nist.gov/projects/post-quantum-cryptography — FIPS 203/204/205 (ML-KEM, ML-DSA, SLH-DSA), final standards
  - **NIST SP 800-227**: https://csrc.nist.gov/pubs/sp/800/227/ipd — Recommendations for Key Establishment and/or Key Derivation (PQC migration guidance)
  - **CNSA 2.0 (NSA)**: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_ALGORITHMS_.PDF — Commercial National Security Algorithm Suite 2.0
  - **Open Quantum Safe (liboqs)**: https://github.com/open-quantum-safe/liboqs — Reference PQC library, 2.9k stars
  - **cloudflare/circl**: https://github.com/cloudflare/circl — Go crypto with PQC + hybrid, 1.7k stars
  - **GmSSL**: https://github.com/guanzhi/GmSSL — Chinese national crypto (SM2/SM3/SM4/SM9), 6.1k stars
  - **Tongsuo (BabaSSL)**: https://github.com/Tongsuo-Project/Tongsuo — Alibaba OpenSSL fork with SM + PQC
  - **ETSI Quantum-Safe Algorithms**: https://www.etsi.org/technologies/quantum-safe-cybersecurity — European PQC migration guidance
  - **GB/T 38636-2020 (GM SSL)**: Chinese national standard for TLS with SM cipher suites
  - **Lydersen et al. 2010 (QKD detector blinding)**: https://doi.org/10.1038/nphoton.2010.123 — Foundational QKD implementation attack
  - **QuipNetwork/hashsigs-solidity**: https://github.com/QuipNetwork/hashsigs-solidity — Hash-based signatures in Solidity, 11.3k stars
