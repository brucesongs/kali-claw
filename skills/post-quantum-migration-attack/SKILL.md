---
name: post-quantum-migration-attack
description: Attacks against cryptographic systems during the PQC migration period. Covers Harvest-Now-Decrypt-Later (SNDL/HNDL), hybrid PQC downgrade abuse, KEM combiner flaws, mixed-protocol failures, NIST PQC standard implementations (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+), and QKD infrastructure attacks. Use when reviewing cryptographic agility, hybrid deployments, or preparing for quantum threat readiness.
origin: kali-claw
version: "0.2.0.2"
compatibility:
  - kali-linux-2025-2-arm64
  - python-3.11+
  - openssl-3.x
  - oqs-provider
allowed-tools:
  - wireshark
  - tcpdump
  - openssl
  - python3
  - jq
  - curl
  - mitmproxy
  - ssh-audit
  - testssl.sh
  - oqs-provider
  - liboqs
  - thundercat
  - kalker
  - gpw
  - cryptoadvance
  - sagemath
  - sage
metadata:
  domain: post-quantum-cryptography
  tool_count: 17
  guide_count: 2
  mitre: "TA0006-Credential Access, TA0010-Exfiltration, TA0040-Impact, T1552, T1041, T1565, T1020"
  last_reviewed: "2026-07-26"
---

# Post-Quantum Migration Attack

## Summary

Attackers target cryptographic systems during the multi-year window before quantum computers break RSA/ECC but after adversaries begin capturing long-lived ciphertext ("Harvest Now, Decrypt Later"). The migration to Post-Quantum Cryptography (PQC) introduces new attack surfaces: hybrid PQC downgrade abuse, KEM combiner flaws, signature stripping in mixed protocols, side-channels in lattice implementation (MatrixVector multiplication timing), and Classical/Post-Quantum (CPQ) certificate chain inconsistencies. This domain covers red-teaming PQC deployments, auditing migration agility, and exploiting transition-period weaknesses in TLS 1.3 + Kyber, SSH + NTRU-Prime, X.509 + Dilithium, IPsec + McEliece, Signal + PQXDH, and QKD infrastructure (BB84/E91 protocols, trusted nodes, key relay).

## Use Cases

- **Audit PQC migration**: Validate that a TLS/SSH/IPsec deployment correctly uses hybrid PQC (e.g., X25519Kyber768Draft00) without downgrade
- **HNDL threat modeling**: Identify which captured ciphertext has decade-long confidentiality requirements (e.g., state secrets, genome data)
- **KEM combiner flaw testing**: Audit whether hybrid KEM concatenation is vulnerable to component compromise (e.g., XOR combiner)
- **Mixed-protocol downgrade**: Test whether active MITM can force a TLS client to negotiate classical-only X25519 instead of X25519Kyber768
- **PQC implementation side-channel**: Test lattice decapsulation for timing/cache/Rowhammer leakage
- **Quantum Key Distribution (QKD) attack**: Exploit trusted-node compromise, photon-number-splitting, detector blinding
- **Digital signature stripping**: Detect whether ML-DSA (Dilithium) signature is being stripped during transit or downgraded to RSA-PSS
- **Certificate chain inconsistency**: Test whether PQ-aware CAs issue chains mixing classical RSA and PQ-Dilithium in incompatible ways
- **PQC token validation**: Test JWT/PASETO/COSE with ML-DSA signatures — verify library handles alg confusion with PQ algs
- **Crypto agility assessment**: Verify that protocol negotiation can hot-swap algorithms without service interruption

## Core Tools

| Tool | Purpose |
|------|---------|
| `oqs-provider` | OpenSSL 3.x provider enabling ML-KEM/ML-DSA in TLS |
| `liboqs` | Reference C library for PQC algorithms |
| `oqs-openssl111` | OpenSSL 1.1.1 fork with PQC (legacy) |
| `testssl.sh` | TLS scanner with PQC cipher detection |
| `ssh-audit` | SSH server scanner with PQC kex detection |
| `Wireshark` | Packet analysis with PQC TLS dissectors |
| `PQCmule` | Hybrid PQC test server |
| `pqcrystals` | Reference Kyber/Dilithium/SPHINCS+ implementations |
| `SageMath` | Lattice reduction (BKZ, LLL) for cryptanalysis |
| `fpylll` | Python LLL library for lattice cryptanalysis |
| `ThunderKitten` | FPGA-based side-channel PQC test bench |
| `qkd-simulator` | BB84/E91 QKD protocol test simulator |
| `curl-oqs` | curl build with PQC TLS support |
| `nginx-oqs` | nginx build with PQC TLS |
| `mitmproxy` | MITM with custom PQC TLS handlers |
| `tcpdump` | Passive capture for HNDL analysis |
| `cryptoadvance/specter` | Bitcoin/script PQC migration testing |

## Methodology

### Phase 1 — Discovery & Inventory

Identify classical, hybrid, and PQ-only deployments. Map protocol → algorithm posture:

```bash
# TLS PQC cipher detection
testssl --wide --color 0 https://target.example.com | grep -iE "kyber|dilithium|pqc|x25519kyber|secp256r1kyber"

# SSH PQC kex detection
ssh-audit target.example.com | grep -iE "sntrup|pq|post-quantum"

# IPsec proposal audit (StrongSwan)
ipsec statusall | grep -iE "ike=|esp="
```

### Phase 2 — HNDL Threat Modeling

Identify data with long-lived confidentiality. Model SNDL capture points:

```bash
# Capture TLS handshakes (long-lived ciphertext source)
tcpdump -i eth0 -w hndl.pcap 'tcp port 443' &

# Identify encryption curves (Kyber hybrid vs classical)
tshark -r hndl.pcap -Y "tls.handshake.type == 2" \
  -T fields -e tls.handshake.extensions.supported_groups
```

### Phase 3 — Downgrade & Stripping Attacks

Test whether MITM can force classical-only:

```bash
# MITM with mitmproxy removing Kyber from supported_groups
mitmproxy --mode transparent \
  --set tls_versions="TLS1.3" \
  --script strip-kyber.py

# Or via Wireshark filter
tshark -r capture.pcap -Y "tls.handshake.extensions.supported_groups !contains 0x07e4"
```

### Phase 4 — KEM Combininer Flaw Analysis

Audit hybrid KEM combiner. XOR combiner is unsafe if any component is broken:

```python
# Verify combiner uses KDF (HKDF), not XOR
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Safe: HKDF(ct1 || ct2 || ss1 || ss2)
combined = HKDF(
    algorithm=hashes.SHA3_256(),
    length=32,
    salt=None,
    info=b"x25519-kyber768-combiner-v1"
).derive(x25519_ss + kyber768_ss)
```

### Phase 5 — PQC Implementation Cryptanalysis

Test lattice-based implementations for side-channels:

```bash
# Build liboqs with timing instrumentation
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -DOQS_ENABLE_KEM_CLASSICAL_MCELIECE=ON ..
make -j$(nproc)

# Run Kyber decaps with controlled inputs (cache timing)
python3 -c "
import time, oqs
kem = oqs.KeyEncapsulation('Kyber768')
pk = kem.generate_keypair()
ct_list = []
for _ in range(1000):
    ct, _ = kem.encap_secret(pk)
    ct_list.append(ct)
for ct in ct_list[:10]:
    t0 = time.perf_counter_ns()
    kem.decap_secret(ct)
    t1 = time.perf_counter_ns()
    print(t1 - t0)
"
```

### Phase 6 — Certificate Chain Inconsistency

Test X.509 chains mixing classical and PQ:

```bash
# Generate ML-DSA (Dilithium) root CA
openssl req -x509 -provider oqsprovider -provider default \
  -newkey dilithium3 -keyout root.key -out root.crt \
  -subj "/CN=PQ Root CA" -days 3650

# Issue leaf cert with classical RSA but chain to PQ root
openssl req -newkey rsa:2048 -keyout leaf.key -out leaf.csr \
  -subj "/CN=hybrid-leaf"
openssl x509 -req -in leaf.csr -CA root.crt -CAkey root.key \
  -CAcreateserial -out leaf.crt -days 365 \
  -CAcreateserial
```

### Phase 7 — Signal PQXDH Audit

Signal's PQXDH uses X3DH + Kyber. Audit the PQ layer:

```python
# Signal PQXDH: X25519 + Kyber-1024
# Verify Kyber ciphertext is checked for identity binding
# Failure mode: server returns Kyber-1024 ciphertext without identity key
# Server MUST sign PQ identity in prekey bundle

# Test: prekey bundle without PQ signature
import requests
bundle = requests.get('https://signal.example.com/v2/keys/100').json()
assert 'pqPreKeySignature' in bundle, "PQ signature missing"
```

### Phase 8 — QKD Infrastructure Attack

Test BB84/E91 QKD links:

```bash
# Detector blinding attack
# Many commercial QKD systems accept bright-light detector blinding
# Test: shine >1mW laser into fiber detector
# Vulnerable: detector enters linear mode → attacker controls all "quantum" bits

# Photon number splitting (PNS)
# Test: adversary with beam splitter captures multi-photon pulses
# Mitigation: decoy states

# Trusted node compromise
# Many commercial QKD networks use trusted relay (China: Beijing-Shanghai line)
# Test: compromise trusted node → recover all keys
```

### Phase 9 — Digital Signature Stripping

Test whether PQ signatures are stripped in transit:

```bash
# SSH: force RSA-only by removing sntrup761 from kex
ssh -o KexAlgorithms=curve25519-sha256@libssh.org \
    -o PubkeyAcceptedAlgorithms=ssh-rsa \
    user@target.example.com

# Test if server accepts (vulnerable to downgrade)
```

### Phase 10 — Reporting

Produce report covering:
- Classical posture inventory (RSA/ECDH hotspots)
- HNDL capture risk per data class
- Hybrid PQC coverage (and downgrade resistance)
- KEM combiner audit
- PQ certificate chain consistency
- QKD infrastructure findings
- Crypto agility gaps

## Practical Steps

### Step 1 — Inventory classical cryptography

```bash
# All RSA/ECC usage in target environment
grep -rnE "RSA_|ECC_|ecdh_|ecdsa_" /etc/ /opt/ /var/ 2>/dev/null | head

# TLS cert algorithm
echo | openssl s_client -connect target:443 2>/dev/null \
  | openssl x509 -noout -text | grep -E "Public Key Algorithm|Signature Algorithm"
```

### Step 2 — Test hybrid PQC negotiation

```bash
# Using oqs-provider-enabled openssl
openssl s_client -connect target:443 \
  -groups "x25519kyber768draft00:x25519:secp256r1" \
  -tls1_3 2>&1 | grep -E "Server Temp Key|Peer signature type|KEM"

# Verify negotiated group
echo | openssl s_client -connect target:443 \
  -groups "x25519kyber768draft00" -tls1_3 2>&1 \
  | grep "Server Temp Key"
```

### Step 3 — Attempt downgrade

```bash
# Try classical-only
echo | openssl s_client -connect target:443 \
  -groups "x25519" -tls1_3 2>&1 | grep "Server Temp Key"

# If server accepts both, test MITM downgrade feasibility
mitmproxy --mode regular -p 8080 \
  --set confdir=~/.mitmproxy \
  --script downgrade-to-classical.py
```

### Step 4 — Audit KEM combiner

```python
# Read TLS stack source
# Check combiner for XOR (unsafe) vs HKDF (safe)
# OpenSSL 3.x with oqs-provider uses NIST-compliant combiner

# Test combiner by observing key derivation via debugger
import subprocess
out = subprocess.check_output([
    'openssl', 's_client', '-connect', 'target:443',
    '-groups', 'x25519kyber768draft00',
    '-keylogfile', '/tmp/keylog'
])
# Verify keylog contains derived secret tied to both X25519 and Kyber
```

### Step 5 — Test certificate chain

```bash
# Generate test PQ root
openssl genpkey -provider oqsprovider -algorithm dilithium3 -out root.key
openssl req -x509 -provider oqsprovider -provider default \
  -key root.key -out root.crt -subj "/CN=PQ Root CA" -days 3650

# Test server rejects chain mixing PQ root + classical leaf
openssl verify -CAfile root.crt classical_leaf.crt
# Expected: error (signature algorithm mismatch)
# Vulnerable: OK (chain algorithm cross-talk bug)
```

### Step 6 — Audit JWT/COSE with PQ algorithms

```python
# Test JWT library with ML-DSA
import jwt
# Generate ML-DSA keypair
# Sign JWT
# Verify library rejects alg confusion (e.g., "ML-DSA-65" → "HS256")
```

### Step 7 — Capture for HNDL analysis

```bash
# Long-term capture of TLS handshakes (for retrospective decryption in ~10-15 years)
# Use Wireshark with keylog to identify which sessions are NOT forward-secret

tshark -i eth0 -f "tcp port 443" -w hndl-target.pcap \
  -T fields -e tls.handshake.type \
  -e tls.handshake.extensions.supported_groups \
  -e tls.handshake.certificate
```

### Defense Perspective

Defenders must assume:

1. **Adversary has 10-year-old ciphertext** — anything RSA/ECC-protected is at risk when CRQC arrives
2. **Crypto agility is mandatory** — protocols must hot-swap algorithms without breaking clients
3. **Hybrid is required for transition** — pure PQC algorithms have less battle-testing
4. **Side-channels in lattice implementations** are real (multiple academic papers, e.g., Cyril Bouyssou's 2024 RowHammer attack on Kyber)
5. **KEM combiners matter** — XOR combiners fail catastrophically; HKDF is safe
6. **PQ certificates** are huge (SPHINCS+ public keys are 2KB+, signatures 8KB+) — protocol MTU issues
7. **QKD is not a silver bullet** — has trusted-node vulnerabilities and limited distance
8. **Migration takes 5-15 years** — start now, even for "low-sensitivity" data

Key defensive controls:

- Enforce hybrid PQC (X25519 + Kyber-768) for all long-lived data channels
- Replace RSA/ECDH key exchange with hybrid PQC where data has >5 year confidentiality requirement
- Use HKDF combiner for hybrid KEMs (NOT XOR)
- Pin certificate algorithms to prevent stripping
- Validate PQ signature presence in prekey bundles (Signal PQXDH)
- Test QKD links with bright-light, PNS, and trusted-node attack scenarios
- Deploy crypto-agility framework (algorithm negotiation, hot-swap)
- Inventory all RSA/ECC usage; classify by HNDL risk tier
- Avoid classical-crypto-only fallback (no "negotiate down" path)
- Use short-lived certificates (<90 days) for forward secrecy
- Implement CT-log monitoring for unexpected PQ certificates

## Key Terms

| Term | Definition |
|------|------------|
| **CRQC** | Cryptographically Relevant Quantum Computer — breaks RSA-2048, ECC-256 |
| **HNDL / SNDL** | Harvest Now, Decrypt Later — passive capture of ciphertext for future decryption |
| **PQC** | Post-Quantum Cryptography — algorithms resistant to quantum attacks |
| **ML-KEM** | Module Lattice KEM (NIST FIPS 203, formerly Kyber) |
| **ML-DSA** | Module Lattice Digital Signature Algorithm (NIST FIPS 204, formerly Dilithium) |
| **SLH-DSA** | Stateless Hash-based DSA (NIST FIPS 205, formerly SPHINCS+) |
| **Hybrid PQC** | Classical + PQ algorithm in single primitive (e.g., X25519Kyber768) |
| **KEM combiner** | Function to derive final secret from multiple KEM components |
| **PQXDH** | Post-Quantum Extended Diffie-Hellman (Signal's PQ protocol) |
| **QKD** | Quantum Key Distribution — physical-layer key exchange via quantum states |
| **CNSA 2.0** | Commercial National Security Algorithm Suite (NSA, 2022) |
| **Crypto agility** | Ability to swap algorithms without protocol changes |

## Compliance & Regulatory Context

- **CNSA 2.0** (NSA, 2022): ML-KEM-1024, ML-DSA-87, SLH-DSA for NSS
- **ETSI TR 103 619** (EU): hybrid KEM mandatory during transition
- **ANSSI** (France): hybrid mandatory through 2030
- **BSI** (Germany): hybrid recommended; SLH-DSA preferred
- **CISA/NSA/NCSC Joint Statement** (2023): PQC migration by 2035
- **PCI DSS 4.0**: PQC readiness recommended for payment systems
- **FFIEC** (US banking): PQC planning required for 2025+

## Attack Surface Summary

| Surface | Attack | Reference |
|---------|--------|-----------|
| TLS 1.3 hybrid PQC | Downgrade (Kyber stripping) | payloads.md §3 |
| SSH PQ kex | Downgrade (curve25519 force) | payloads.md §3.3 |
| IPsec PQ ke | Classical DH force | payloads.md §3.4 |
| KEM combiner | XOR (unsafe) detection | payloads.md §4 |
| liboqs implementation | Timing / RowHammer / EM | payloads.md §5 |
| X.509 cert chain | PQ/classical cross-talk | payloads.md §6 |
| Signal PQXDH | PQ prekey stripping | payloads.md §7 |
| QKD infrastructure | Detector blind / PNS / trusted node | payloads.md §8 |
| JWT/COSE | PQ alg confusion | payloads.md §9 |
| Migration agility | Hot-swap race condition | payloads.md §10 |

## Engagement Workflow

1. **Scoping**: confirm protocols, libraries, QKD inclusion
2. **Discovery**: inventory classical / hybrid / PQ posture
3. **HNDL capture**: long-term passive collection
4. **Downgrade test**: MITM strip PQ
5. **KEM combiner audit**: source review
6. **Side-channel**: timing / EM / RowHammer (if in scope)
7. **Cert chain**: PQ/classical cross-talk
8. **PQXDH/QKD**: protocol-specific audits
9. **Reporting**: per-data-class migration roadmap

## Algorithm Choice Matrix

| Use case | Recommended | Backup | Avoid |
|----------|-------------|--------|-------|
| General KEM | ML-KEM-768 | X25519+Kyber-768 | Pure RSA |
| Long-term KEM | ML-KEM-1024 | X25519+Kyber-1024 | ECC-only |
| General sig | ML-DSA-65 | RSA-3072+Dilithium-3 | ECDSA-only |
| Long-term sig | SLH-DSA-192s | ML-DSA-87 | Ed25519-only |
| Code signing | SLH-DSA-256f | ML-DSA-87 + RSA | RSA-only |
| HSM-bound KEM | ML-KEM-1024 (Thales 7.13+) | RSA-4096 (transition) | ECC-only |

## Quantum Threat Timeline

- **2025-2027**: NISQ era, no crypto threat
- **2028-2030**: Early fault-tolerant QC (~100 logical qubits)
- **2030-2035**: CRQC possible (cryptographically relevant)
- **2035-2040**: RSA-2048 broken (likely)
- **2040+**: ECC-256 broken

## Migration Priorities by Data Class

| Data class | Migration target | Rationale |
|-----------|------------------|-----------|
| State secrets | 2028 | 30-year confidentiality, state-level HNDL |
| Biometric | 2028 | Lifetime of subject |
| Genome | IMMEDIATE | Lifetime of descendants |
| Long-term keys | 2028 | 5-yr rotation insufficient |
| PII / PHI | 2030 | 10-year regulatory retention |
| Financial | 2032 | Compliance + fraud window |
| Ephemeral | 2035 | Short-lived data |

## Detection Methods

### PQC Migration Audit
- **Hybrid TLS detection**: TLS handshakes using both classical and PQC algorithms; alert on unexpected configurations.
- **Algorithm downgrade**: PQC algorithm downgraded to classical; classical algorithm with weak key.
- **Certificate anomalies**: Certificate chain with mix of RSA/ECDSA and PQC signatures.

### SIEM Detection Rules
- **Splunk SPL**: `index=tls | where tls_version matches "TLSv1.3" AND cipher matches ".*Kyber.*" | stats count by client`
- **Custom monitoring**: TLS handshake analysis for PQC algorithm usage.

## Defense Evasion Techniques

### HNDL/SNDL (Harvest Now, Decrypt Later) Stealth
- **Passive capture only**: Don't trigger any alerts; just record encrypted traffic.
- **Long-term storage**: Store encrypted traffic indefinitely; wait for quantum computer availability.
- **Distribute storage**: Spread storage across multiple systems; reduces per-system anomaly.

### Hybrid PQC Downgrade
- **Force classical fallback**: If server supports both classical and PQC, force classical via manipulation.
- **Exploit KEM combiner flaws**: Some hybrid implementations use weak combiner (XOR vs HKDF).
- **Side-channel on Kyber**: RowHammer / EM / timing attacks on Kyber implementation.

### QKD (Quantum Key Distribution) Attack
- **Detector blinding**: Blind single-photon detector; forces predictable response.
- **Photon-number-splitting (PNS)**: Exploit weak coherent photon source; split off one photon.
- **Trusted node compromise**: QKD networks with trusted nodes; compromise node to break key exchange.

## References

- NIST PQC Standards (2024): FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- NIST PQC FAQ — https://csrc.nist.gov/projects/post-quantum-cryptography/faqs
- NSA CNSA 2.0 Suite — https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_ALGORITHMS_.PDF
- ENISA Post-Quantum Cryptography — https://www.enisa.europa.eu/publications/post-quantum-cryptography
- Cloudflare PQC Deployment — https://blog.cloudflare.com/pq-2024/
- Google Chrome PQC Rollout — https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-pqc.html
- AWS PQC Migration — https://aws.amazon.com/blogs/security/preparing-for-post-quantum-cryptography/
- Signal PQXDH Specification — https://signal.org/docs/specifications/pqxdh/
- IETF Hybrid Post-Quantum KEM — https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
- BAAI/Berlin "Quantum Threat Timeline" 2024
- "Quantum Computing Progress and Algorithms" (Bernstein, 2024)
- IBM Quantum Roadmap 2025-2033
- CISA/NSA/UK NCSC Joint Statement on PQC Migration — https://www.cisa.gov/sites/default/files/2023-08/Quantum_Readiness_Guidance_final.pdf
- Mozilla PQC Test — https://pq.cloudflareresearch.com/
- NIST PQC Standardization Conference 2024
- CryptoAction PQC Migration Working Group

