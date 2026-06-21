# Post-Quantum Cryptography Migration Assessment Playbook

> Deep-dive companion to `skills/quantum-crypto-attack/SKILL.md` and `guides/quantum-crypto-attack-playbook.md`.
>
> Audience: CISOs, PKI architects, crypto-audit leads, and regulators who must answer one question with evidence: *is this organization post-quantum ready, and if not, what exactly must change before a Cryptographically Relevant Quantum Computer (CRQC) is announced?*
>
> Scope: NIST FIPS 203/204/205 (ML-KEM, ML-DSA, SLH-DSA), NIST SP 800-227 migration guidance, CNSA 2.0 (US national-security suite), ETSI TR 103 619 (EU), and GB/T 38636-2020 (PRC GM SSL). Includes hybrid-TLS rollout, SM-series migration for China compliance, KEM/signature algorithm selection, store-now-decrypt-later (SNDL) threat modeling, and a defensible assessment deliverables template.

---

## 1. Introduction and Objective

A post-quantum migration assessment is **not** a penetration test in the classical sense. The adversary has not arrived yet (no CRQC exists publicly), most classical cryptosystems still resist classical attacks, and the math behind NIST PQC standards is sound. The objective is therefore **preparation under uncertainty**:

- Inventory every Shor-vulnerable asymmetric key and every Grover-attenuated symmetric primitive across the estate.
- Quantify the store-now-decrypt-later (SNDL) window for each long-term-confidential data flow.
- Verify that systems already deploying post-quantum cryptography (PQC) have configured hybrid TLS, parameter sets, and signing modes correctly.
- Verify national-crypto compliance where applicable (PRC GB/T 38636-2020, etc.).
- Produce a prioritized, standards-aligned migration roadmap that an auditor, regulator, or board can defend.

The deliverable is a **post-quantum readiness report** that survives scrutiny from NIST SP 800-227, CNSA 2.0, and ETSI TR 103 619 simultaneously. This guide is the step-by-step walkthrough to produce one.

---

## 2. Regulatory Landscape and Standards Alignment

Post-quantum migration has different timelines depending on the regulatory frame. An assessment must declare the frame up front and map every finding to the applicable standard.

### 2.1 NIST (US civilian, global de facto)

- **FIPS 203** (Aug 2024) — ML-KEM (Kyber-derived) for key encapsulation. Three parameter sets: ML-KEM-512 (Level 1), ML-KEM-768 (Level 3), ML-KEM-1024 (Level 5).
- **FIPS 204** (Aug 2024) — ML-DSA (Dilithium-derived) for digital signatures. Three parameter sets: ML-DSA-44/65/87.
- **FIPS 205** (Aug 2024) — SLH-DSA (SPHINCS+-derived) stateless hash-based signatures. Variants in SHA-2 and SHAKE families, "f" (fast) and "s" (small) flavors.
- **NIST SP 800-227** (Draft, 2023+) — Recommendations for Key Establishment. The canonical migration sequencing document.
- **NIST SP 800-208** — Stateful hash-based signatures (XMSS, LMS) for firmware signing.

### 2.2 CNSA 2.0 (US national security)

The Commercial National Security Algorithm Suite 2.0 mandates:

| Algorithm class | CNSA 2.0 algorithm | Timeline |
|----------------|-------------------|----------|
| Asymmetric key establishment | ML-KEM-1024 | 2025-2035 phased |
| Digital signature | ML-DSA-87 (or SLH-DSA-SHA2-256s for firmware) | 2025-2035 phased |
| Symmetric | AES-256 | Immediate |
| Hashing | SHA-384 / SHA-512 | Immediate |
| Elliptic curve (transition) | P-384 only (P-256 deprecated) | 2025-2030 |

**Key CNSA 2.0 nuance**: NSA mandates **Level 5 minimum** (ML-KEM-1024, ML-DSA-87), not the NIST civilian default of Level 3. A national-security system deployed at ML-KEM-768 is **non-compliant** even though it is cryptographically adequate.

### 2.3 ETSI (EU)

- **ETSI TR 103 619** — Quantum-Safe Algorithms guidance, similar to NIST SP 800-227 but with European regulatory flavor (GDPR data-lifetime considerations, eIDAS signing).
- **ETSI TS 103 744** — Hybrid Key Exchange specification, directly relevant to TLS deployments.

### 2.4 PRC GB/T 38636-2020 and the SM Suite

Mandatory in PRC government, finance, critical infrastructure, and any system subject to the **Cryptography Law (2020)**:

- **GB/T 32918** (SM2) — elliptic curve, 256-bit, ECDSA+ECIES analogue.
- **GB/T 32905** (SM3) — 256-bit Merkle-Damgard hash.
- **GB/T 32907** (SM4) — 128-bit block cipher (the AES counterpart).
- **GB/T 38636-2020** (GM SSL / TLCP) — TLS with SM cipher suites (RFC 8998 in TLS 1.3, NTLS in TLS 1.2).
- **GM/T 0008** (SM9) — identity-based encryption.

**Important**: SM2/SM3/SM4 are **Shor-vulnerable** in the same way their NIST analogs are. A PRC-regulated organization is not post-quantum ready just because it uses GM SSL. The migration path is SM-hybrid (SM2 + ML-KEM-768, SM3 + SLH-DSA) rather than the Western X25519 + ML-KEM pattern.

---

## 3. NIST PQC Timeline and Algorithm Selection

### 3.1 Standardized algorithms (post-Aug 2024)

| Use case | Standardized algorithm | Parameter sets | Recommended production minimum |
|----------|-----------------------|----------------|-------------------------------|
| Key encapsulation (TLS, KMS, email) | ML-KEM (FIPS 203) | 512, 768, 1024 | **ML-KEM-768** (civilian), ML-KEM-1024 (national-security) |
| General digital signature | ML-DSA (FIPS 204) | 44, 65, 87 | **ML-DSA-65** (civilian), ML-DSA-87 (national-security) |
| Stateless hash signature (root CA, firmware) | SLH-DSA (FIPS 205) | SHA-2/SHAKE, f/s, 128/192/256 | SLH-DSA-SHA2-128s (most uses), SLH-DSA-SHA2-256s (root) |
| Stateful hash signature (firmware) | XMSS (RFC 8391), LMS (RFC 8554) | Tree heights h=10/16/20 | XMSS-SHA2_16_256 or XMSSMT for long-lived |

### 3.2 Round-4 and future candidates (informational)

- **Classic McEliece** (code-based) — very large public keys (~1MB), considered conservative; suitable for long-term root signatures where bandwidth is not a concern.
- **HQC, BIKE** (code-based) — KEM alternatives, NIST Round 4.
- **Falcon** (lattice, Falcon-512/1024) — compact signatures, fast verification, but signing is implementation-fragile (floating-point NTT); not yet standardized but widely pre-deployed.

### 3.3 Selection decision tree

```text
Need key establishment?
├── TLS / VPN / general ────── ML-KEM-768 (civilian), ML-KEM-1024 (CNSA 2.0)
├── Constrained device ─────── ML-KEM-512 (with documented justification)
└── National-security (NSA) ── ML-KEM-1024 (mandated)

Need digital signature?
├── TLS leaf / JWT ─────────── ML-DSA-65
├── Code-signing (medium) ──── ML-DSA-65 (hybrid with RSA during transition)
├── Root CA / HSM master ───── SLH-DSA-SHA2-256s (hash-agile, conservative)
├── Firmware (stateful OK) ─── XMSS-SHA2_16_256 (RFC 8391)
└── National-security (NSA) ── ML-DSA-87

Already deployed on SM-stack?
├── TLS ────────────────────── SM2 hybrid + ML-KEM-768 (per draft China PQC guidance)
├── Code-signing ───────────── SM2 hybrid + ML-DSA-65
└── Long-term archive ──────── SM4-GCM wrapped by ML-KEM-1024
```

---

## 4. Phase A: PQC Readiness Audit

The first concrete deliverable is an audit of current cryptographic posture. Every later phase references it.

### 4.1 Asset inventory dimensions

For every cryptographic asset (key, cert, cipher suite, hash function, RNG seed) in the estate, record:

| Field | Source | Example |
|-------|--------|---------|
| `fingerprint` | SHA-256 of SubjectPublicKeyInfo | `a1b2c3...` |
| `algorithm` | cert / config / KMS describe | RSA-2048 |
| `purpose` | cert EKU / role | TLS server, code-signing, JWT verify |
| `issuer` | cert / CA inventory | Internal PKI root |
| `not_after` | cert | 2031-06-15 |
| `asset_owner` | CMDB | "edge-platform" team |
| `data_sensitivity` (1-5) | data classification API | 5 (state secret) |
| `remaining_confidentiality_lifetime_yrs` | data classification + business judgment | 25 |
| `shor_vulnerable` | algorithm-derived | true for RSA/ECC |
| `grover_attenuated` | algorithm-derived | true for AES-128 |

### 4.2 Inventory sources (walkthrough)

```bash
# Public cert surface via Certificate Transparency
domain="example.com"
curl -s "https://crt.sh/?q=%25.${domain}&output=json" \
    | jq -r '.[].id' > certids.txt
wc -l certids.txt

# Internal PKI (FreeIPA example)
ipa cert-find --all --sensitive | jq -r '.result[].serial_number'

# Cloud KMS / HSM
aws kms list-keys --output json | jq -r '.Keys[].KeyId' \
    | xargs -I{} aws kms describe-key --key-id {}

# SSH host keys (Shor-vulnerable: RSA, ECDSA)
for h in $(cat hosts.txt); do
    ssh-keyscan -t rsa,ecdsa "$h" 2>/dev/null | awk '{print $2, $3}' | head -1
done

# Code-signing certs (macOS / Windows / Java / GPG)
security find-identity -v -p codesigning                  # macOS
Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert       # Windows
jarsigner -verify -verbose -certs artifact.jar           # Java
gpg --list-secret-keys --with-colons | grep '^sec'       # GPG
```

### 4.3 Coverage thresholds

- **>95% cert coverage** of the public-facing estate (CT logs + ZGrab2 scan).
- **>99% key coverage** of HSM/KMS-backed assets (direct attestation).
- **>90% code-signing coverage** (often opaque to cert scans).
- Any gap below these thresholds is itself a finding — you cannot migrate what you cannot inventory.

---

## 5. Phase B: Store-Now-Decrypt-Later (SNDL) Threat Modeling

### 5.1 Why SNDL is the dominant risk

The threat model for long-term-confidential data is asymmetric: the adversary can record ciphertext today and wait a decade for a CRQC. Migration in 2030 does not protect data captured in 2024. The risk window is:

```text
SNDL_window = CRQC_year - current_year - data_confidentiality_lifetime_years
```

If `SNDL_window < 0`, the data is already considered lost under the central CRQC estimate. If `SNDL_window > 0`, the organization has that many years to migrate the protecting algorithm before the data falls.

### 5.2 CRQC arrival estimates (mid-2026 calibration)

| Source | Optimistic | Central | Conservative |
|--------|-----------|---------|--------------|
| NSA CNSA 2.0 schedule | 2030 | 2033 | 2035 |
| NIST "10-20 years from 2016" | 2026 | 2031 | 2036 |
| ETSI | 2026 | 2028 | 2032 |
| Gidney & Ekera 2019 (resource modelling) | n/a | 2030s | 2040s |
| **Consensus (this playbook)** | **2030** | **2033** | **2038** |

**Always report ranges**, never a point estimate. A central-estimate-only report is a finding against NIST SP 800-227.

### 5.3 Data classification inputs

SNDL is meaningless without data classification. Inputs:

- **HIPAA** health data — confidentiality lifetime: lifetime of patient + 50 years.
- **Attorney-client privileged** — lifetime of the matter + 6 years.
- **M&A non-public** — until deal closes + 2 years post-close (regulatory).
- **Trade secret** — indefinite.
- **State secret (PRC / classified US)** — 30+ years.

### 5.4 SNDL matrix computation

```python
#!/usr/bin/env python3
# sndl_matrix.py — Produce SNDL exposure matrix from inventory

CRQC_TIMELINE = {"optimistic": 2030, "central": 2033, "conservative": 2038}
CURRENT_YEAR = 2026

inventory = [
    {"asset": "Root CA", "lifetime": 25, "sensitivity": 5},
    {"asset": "Code-signing", "lifetime": 10, "sensitivity": 5},
    {"asset": "TLS leaf", "lifetime": 1, "sensitivity": 2},
    {"asset": "Long-term archive (HIPAA)", "lifetime": 80, "sensitivity": 5},
    {"asset": "JWT signing", "lifetime": 1, "sensitivity": 3},
]

for k in inventory:
    for scenario, crqc_year in CRQC_TIMELINE.items():
        window = crqc_year - CURRENT_YEAR - k["lifetime"]
        status = "ALREADY-EXPOSED" if window < 0 else f"{window}-year-margin"
        flag = "**" if (window < 0 and k["sensitivity"] >= 4) else ""
        print(f"{flag}{k['asset']:32} {scenario:13} → {status}{flag}")
```

**Output (truncated):**

```
Root CA                          optimistic    → ALREADY-EXPOSED
Root CA                          central       → ALREADY-EXPOSED
Root CA                          conservative  → ALREADY-EXPOSED
Long-term archive (HIPAA)        optimistic    → ALREADY-EXPOSED
Long-term archive (HIPAA)        central       → ALREADY-EXPOSED
Long-term archive (HIPAA)        conservative  → ALREADY-EXPOSED
JWT signing                      optimistic    → 3-year-margin
JWT signing                      central       → 6-year-margin
```

### 5.5 SNDL triage rule

Any (asset, scenario) pair where `window < 0` AND `sensitivity >= 4` is a **CRITICAL** finding in the assessment report, regardless of when the migration roadmap is scheduled. The data is already exposed in that scenario.

---

## 6. Phase C: Hybrid TLS Rollout

### 6.1 Why hybrid (not pure-PQC)

Pure-PQC TLS (e.g., `mlkem768` alone) was the early default. The 2022-2024 Kyber side-channel disclosures, the inherent youth of PQC implementations, and the lack of cert-chain PQC support pushed the IETF (draft-ietf-tls-hybrid-design) and CNSA 2.0 to mandate **hybrid** key exchange:

- `x25519_kyber768` (early hybrid, pre-standardization)
- `x25519_mlkem768` (current IETF draft, FIPS 203 derived)
- `secp256r1_mlkem768` (FIPS-compliant EC fallback)
- `x25519_mlkem1024` (CNSA 2.0 Level 5 hybrid)

A hybrid handshake provides security if **either** the classical or the PQC component holds. This is the cryptographic defense-in-depth principle applied to algorithm selection.

### 6.2 OpenSSL 3.x + oqs-provider setup

```bash
# Build liboqs (reference PQC C library)
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && cmake -GNinja -B build \
    -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_USE_OPENSSL=OFF
cmake --build build --parallel 8 && sudo cmake --install build

# Build oqs-provider (OpenSSL 3.x provider)
git clone --recurse-submodules https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider && cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 8 && sudo cmake --install build

# Load provider and enumerate available hybrid groups
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
openssl list -providers -provider oqsprovider -verbose
openssl list -groups -provider oqsprovider | grep -iE "mlkem|kyber|p256"
```

### 6.3 Server-side hybrid TLS configuration (nginx)

```nginx
# nginx.conf — hybrid-PQC TLS (requires nginx built against OpenSSL 3.x + oqs-provider)
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519:secp256r1:x25519_mlkem768:secp256r1_mlkem768;

# Bind the negotiated group into the Finished transcript (downgrade resistance)
ssl_conf_command Groups "X25519:x25519_mlkem768";

# Optional: enforce hybrid only (reject plain X25519 clients)
# ssl_conf_command Groups "x25519_mlkem768:secp256r1_mlkem768";
```

### 6.4 Server-side hybrid TLS configuration (Apache httpd)

```apache
# httpd-ssl.conf — hybrid-PQC TLS
SSLOpenSSLConfCmd Groups "X25519:x25519_mlkem768"
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2
SSLCipherSuite TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256
```

### 6.5 Client-side hybrid TLS validation

```bash
# Probe a server for hybrid-PQC support
target="cloudflare.com"
openssl s_client -connect ${target}:443 -tls1_3 \
    -groups x25519_mlkem768 -msg 2>&1 \
    | grep -A3 "ServerHello\|Supported Groups\|Negotiated group"

# All-hybrid scan
for grp in x25519_kyber768 x25519_mlkem768 secp256r1_mlkem768 x25519_mlkem1024; do
    result=$(echo | timeout 5 openssl s_client -connect ${target}:443 -tls1_3 \
        -groups "$grp" 2>&1 | grep -E "Cipher|protocol" | head -2 | tr '\n' '|')
    echo "${grp}: ${result}"
done

# Capture full handshake for transcript-binding verification
tshark -i eth0 -w hybrid.pcap 'tcp port 443 and host '${target}
tshark -r hybrid.pcap -Y 'tls.handshake.type == 20' \
    -T fields -e tls.handshake.finished_verify_data
```

### 6.6 Downgrade-resistance lab test

This is the post-quantum equivalent of POODLE/BAR-Mitzvah. Server offers hybrid + classical; attacker on path strips the hybrid extension; client must abort.

```python
#!/usr/bin/env python3
# mitmproxy_addon_strip_pqc.py — strips hybrid-PQC group from ClientHello
# Run with: mitmproxy -s mitmproxy_addon_strip_pqc.py --mode transparent

from mitmproxy import http

TARGET_GROUP = b"\x00\x00\x11\xec"  # x25519_mlkem768 group ID (example)

def tls_clienthello(data: http.TlsData) -> None:
    """Remove the hybrid group from the supported_groups extension."""
    if TARGET_GROUP in data.data:
        data.data = data.data.replace(TARGET_GROUP, b"")
        # Log: if the server still completes the handshake with plain x25519,
        # the downgrade succeeded — CRITICAL finding.
```

Expected lab result: client/server handshake **must fail** with a `handshake_failure` alert. If it succeeds, the Finished message does not bind the group — CRITICAL finding.

### 6.7 Real-world hybrid-TLS deployments (case studies)

- **Cloudflare (2022+)** — early adopter of X25519Kyber768Draft00 on the edge; published KEMTLS research and circl Go library. ~25% of TLS handshakes at the edge are hybrid-PQC.
- **Google Chrome (CECPQ2, 2019+)** — experimental hybrid (X25519 + HRSS) in Chrome to Cloud and Google services. Replaced with X25519+Kyber768 in 2023.
- **Amazon AWS (2024)** — KMS service supports ML-KEM-768 hybrid; AWS Certificate Manager adds ML-DSA to public certs.
- **Microsoft Azure (2024)** — Azure TLS supports hybrid groups for select endpoints; Azure AD signing keys move to ML-DSA-65 in 2025.
- **Apple iMessage PQ3 (2024)** — first mass-market deployment of post-quantum key establishment in messaging. Uses a custom ratcheting protocol with ML-KEM at the initial key exchange.
- **Signal PQXDH (2023)** — Signal messenger deployed X25519+ML-KEM-1024 hybrid for the X3DH key agreement.

---

## 7. Phase D: KEM and Signature Algorithm Selection

### 7.1 Key encapsulation (ML-KEM)

| Parameter | pk size | sk size | ciphertext size | shared secret | PQ level |
|-----------|---------|---------|-----------------|---------------|----------|
| ML-KEM-512 | 800 B | 1632 B | 768 B | 32 B | 1 (AES-128) |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B | 32 B | 3 (AES-192) |
| ML-KEM-1024 | 1568 B | 3168 B | 1568 B | 32 B | 5 (AES-256) |

**Production rule**: ML-KEM-768 minimum for civilian; ML-KEM-1024 for CNSA 2.0. ML-KEM-512 only on constrained devices with documented justification and never for long-term data.

### 7.2 General signatures (ML-DSA)

| Parameter | pk size | sig size | PQ level | Notes |
|-----------|---------|----------|----------|-------|
| ML-DSA-44 | 1312 B | 2420 B | 2 | 128-bit classical-parity gap; do not use for 128-bit-classical systems |
| ML-DSA-65 | 1952 B | 3309 B | 3 | Default civilian; TLS leaf, JWT |
| ML-DSA-87 | 2592 B | 4627 B | 5 | CNSA 2.0; code-signing |

### 7.3 Hash-based signatures (SLH-DSA, XMSS, LMS)

SLH-DSA is **stateless** (preferred for general deployment), but signatures are large (7-50 KB). XMSS/LMS are **stateful** (must enforce monotonic state counter, suitable for HSM-backed firmware signing).

| Variant | pk size | sig size | Sign time | Use case |
|---------|---------|----------|-----------|----------|
| SLH-DSA-SHA2-128s | 32 B | 7856 B | ~10 ms | General, conservative |
| SLH-DSA-SHA2-128f | 32 B | 17088 B | ~1 ms | Fast signing (larger sig) |
| SLH-DSA-SHA2-256s | 32 B | 29792 B | ~50 ms | Root CA, CNSA 2.0 |
| XMSS-SHA2_16_256 | 64 B | ~2.5 KB | ~5 ms | Firmware, stateful OK |
| LMS (RFC 8554) | 60 B | ~1.6 KB | ~3 ms | Firmware, stateful OK, simpler |

### 7.4 Deterministic vs randomized signing

ML-DSA supports both deterministic (default in FIPS 204) and randomized signing modes:

- **Deterministic** — reproducible signatures; preferred for test vectors and verifiability; vulnerable to fault-injection if attacker can inject a single fault.
- **Randomized** — non-reproducible; recommended for production code-signing where fault attacks are plausible.

Verify the deployed mode:

```bash
openssl -provider oqsprovider -pkeyutl -sign -inkey mldsa65-priv.pem \
    -in msg.txt -out sig1.bin
openssl -provider oqsprovider -pkeyutl -sign -inkey mldsa65-priv.pem \
    -in msg.txt -out sig2.bin
cmp sig1.bin sig2.bin
# Match → deterministic mode
# Differ → randomized mode
```

### 7.5 Algorithm-agility policy

A defensible post-quantum deployment has a **central algorithm registry** that can be flipped without touching individual services:

```json
{
  "tls": {
    "allowed_groups": ["X25519", "x25519_mlkem768"],
    "min_tls_version": "1.3"
  },
  "pkcs12": {
    "allowed_signatures": ["ML-DSA-65", "SLH-DSA-128s"]
  },
  "ssh": {
    "allowed_keys": ["ed25519", "RSA-4096"]
  },
  "jwt": {
    "allowed_algs": ["ML-DSA-65", "RS384"]
  }
}
```

Test the registry's agility by flipping a flag and measuring time-to-propagation (target: <1 hour).

---

## 8. Phase E: SM-Series Migration for China Compliance

### 8.1 Why the SM suite needs post-quantum migration too

SM2/SM3/SM4 are mathematically sound, but SM2 (ECDSA analogue) and SM4 (128-bit block cipher) are both post-quantum-weak:

- **SM2** — Shor-vulnerable; elliptic curve, same family as NIST P-256.
- **SM3** — 256-bit hash; Grover reduces to ~128-bit PQ. Acceptable.
- **SM4** — 128-bit key; Grover reduces to ~64-bit PQ. **Must upgrade** for long-term data.

### 8.2 SM-hybrid migration patterns

China-specific PQC migration (informed by GM/T 0008 / draft national standards) follows a hybrid pattern:

| Asset class | Current (PRC) | Hybrid target | Pure-PQC target |
|-------------|--------------|----------------|-----------------|
| TLS leaf | SM2 + ECDHE-SM2 | SM2 + ML-KEM-768 | ML-KEM-768 (after ~2030) |
| TLS cert chain | SM2-signed | SM2 + ML-DSA-65 hybrid | ML-DSA-65 (after ~2030) |
| Code-signing | SM2 | SM2 + ML-DSA-65 | ML-DSA-65 |
| Long-term archive | SM4-GCM | SM4-GCM wrapped by ML-KEM-768 | AES-256-GCM wrapped by ML-KEM-768 |
| Hashing | SM3 | SM3 / SHA-256 | SHA-256 (no SM3-specific PQ risk) |

### 8.3 GmSSL and Tongsuo PQC readiness

```bash
# GmSSL — build with PQC provider (Open Quantum Safe integration)
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL && mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DENABLE_PQC=ON
make -j8 && sudo make install

# Tongsuo (BabaSSL) — already integrates liboqs
git clone https://github.com/Tongsuo-Project/Tongsuo.git
cd Tongsuo && ./config --prefix=/usr/local/tongsuo \
    enable-ntls enable-ssl3 enable-ntls enable-quic \
    no-shared
make -j8 && sudo make install

# Probe Tongsuo for hybrid-SM-TLS support
/usr/local/tongsuo/bin/openssl list -groups | grep -iE "mlkem|sm2"
```

### 8.4 GM SSL compliance checklist (GB/T 38636-2020)

- [ ] Server offers `TLS_SM4_GCM_SM3` or `TLS_SM4_CCM_SM3` in TLS 1.3.
- [ ] Server certificate is SM2-signed (not RSA/ECDSA).
- [ ] ECDHE-SM2 key exchange is negotiated (not static SM2).
- [ ] CRL/OCSP responses are SM2-signed.
- [ ] No silent fallback to TLS 1.2 with RSA (CRITICAL if present).
- [ ] SM4 is in GCM or CTR mode (never ECB).
- [ ] SM2 scalar multiplication is constant-time (verify via dudect).
- [ ] SM3 is not used as a naive MAC (use HMAC-SM3 or SM3-KDF).

---

## 9. Phase F: Crypto-Agility Framework

### 9.1 Definition

Crypto agility is the ability to **add, remove, or change cryptographic algorithms across the estate within a defensible time window (target: <24 hours)**, in response to a catastrophic break announcement. The 2024 ROCA-style break of a NIST PQC candidate is the canonical scenario.

### 9.2 Agility infrastructure requirements

- **Central algorithm registry** (see §7.5) — single source of truth, versioned, propagates to all services.
- **Algorithm-tolerant protocol layers** — TLS 1.3 with negotiable groups; cert chains with OID-tagged algorithms; JWT with header-tagged algorithms.
- **Cert auto-rotation pipeline** — reissue under a new algorithm in <1 hour for the entire leaf-cert estate.
- **HSM key migration** — wrap-then-unwrap to re-key HSM masters without losing attestation.
- **Client compatibility telemetry** — know which client populations will break if an algorithm is removed.

### 9.3 The 24-hour crypto-agility drill

Scenario: at 09:00 Monday, "ML-KEM is broken." By 09:00 Tuesday, every system using ML-KEM must have switched to a fallback (X25519 alone for TLS, RSA for signing during emergency).

```bash
# Step 1: inventory every system using ML-KEM
grep -rl "mlkem\|ml-kem\|kyber" /etc/ /usr/local/etc/ 2>/dev/null > mlkem_systems.txt
wc -l mlkem_systems.txt

# Step 2: simulate kill-switch (OpenSSL 3.x config)
sudo cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.bak
sudo sed -i 's/^Groups = .*/Groups = X25519:P-256/' /etc/ssl/openssl.cnf
sudo systemctl reload nginx apache2

# Step 3: measure breakage
#   - Which clients fail to connect?
#   - Which internal services break?
#   - Is there rollback?
#   - How long did cert reissuance take?

# Step 4: time the drill
#   < 1 hour → A grade
#   1-4 hours → B
#   4-24 hours → C
#   > 24 hours → F (unacceptable)
```

### 9.4 Agility drill success criteria

| Grade | Time to disable | Rollback works | Production impact |
|-------|----------------|----------------|-------------------|
| A | <1 hour | Yes | None |
| B | 1-4 hours | Yes | <5% of clients fail |
| C | 4-24 hours | Partial | <20% of clients fail |
| F | >24 hours or no rollback | No | >20% of clients fail |

An F-grade drill is a CRITICAL finding in the assessment report.

---

## 10. Phase G: Assessment Deliverables

### 10.1 Required deliverables

A post-quantum migration assessment produces these artifacts:

1. **Post-quantum readiness report** (PDF, ~40-80 pages) — executive summary, findings, roadmap, references.
2. **Quantum exposure inventory** (CSV / database) — one row per asset, with all fields from §4.1.
3. **SNDL exposure matrix** (CSV) — one row per (asset, scenario) pair.
4. **PQC configuration findings** (markdown) — per-asset technical findings with CVSS-like severity.
5. **Crypto-agility drill report** — timing, breakage, rollback results.
6. **Prioritized migration roadmap** (Gantt chart + CSV) — P0/P1/P2/P3 with target algorithms and windows.
7. **Post-quantum readiness score** — 0-100, with breakdown by dimension.

### 10.2 Post-quantum readiness score formula

```python
def pq_readiness_score(
    inventory_coverage_pct,      # 0-100, from Phase A
    hybrid_tls_pct,              # 0-100, % of TLS endpoints offering hybrid
    agility_drill_grade,         # 'A'|'B'|'C'|'F'
    national_crypto_pct,         # 0-100, % of mandated SM-suite compliant
    sndl_mitigation_pct,         # 0-100, % of critical SNDL flows migrated
) -> tuple[int, str]:
    grade_to_score = {"A": 20, "B": 15, "C": 10, "F": 0}
    scores = [
        (inventory_coverage_pct / 100) * 20,
        (hybrid_tls_pct / 100) * 20,
        grade_to_score[agility_drill_grade],
        (national_crypto_pct / 100) * 20,
        (sndl_mitigation_pct / 100) * 20,
    ]
    total = int(sum(scores))
    if total >= 90:
        grade = "A"
    elif total >= 75:
        grade = "B"
    elif total >= 60:
        grade = "C"
    elif total >= 40:
        grade = "D"
    else:
        grade = "F"
    return total, grade
```

### 10.3 Report template (executive summary)

```markdown
# Post-Quantum Readiness Report — <Org Name>
## Engagement: <Date Range>

## 1. Executive Summary

<Post-quantum readiness score: X/100, grade Y>

The organization's post-quantum readiness posture is rated **<grade>**.
Under the central CRQC arrival estimate of **2033**, **<N>** long-lived
Shor-vulnerable keys and **<M>** SNDL-exposed long-term-confidential
data flows require remediation within the windows defined in §6 of this
report. The crypto-agility drill (§7) achieved grade **<A/B/C/F>** with
time-to-disable of **<Xh>**.

## 2. Quantum Exposure Inventory
## 3. SNDL Exposure Matrix
## 4. PQC Configuration Findings
## 5. National Crypto Compliance (where applicable)
## 6. Prioritized Migration Roadmap
## 7. Crypto-Agility Drill Results
## 8. References
```

---

## 11. Real-World Case Studies

### 11.1 Cloudflare — KEMTLS and X25519Kyber768

Cloudflare was the first major edge provider to deploy hybrid-PQC TLS at scale. Their 2022 rollout of `X25519Kyber768Draft00` to the Cloudflare edge handled ~25% of TLS handshakes as hybrid-PQC by 2024. Key learnings published by Cloudflare:

- **Latency**: hybrid adds ~5-15% to handshake time; negligible for most users.
- **Backwards compatibility**: clients without PQC support silently negotiate X25519 — downgrade resistance via Finished transcript is mandatory.
- **KEMTLS research**: Cloudflare's KEMTLS protocol removes an extra round trip vs the standard TLS 1.3 KEM integration; not yet standardized but informs future TLS 1.3 PQC work.

### 11.2 Google Chrome CECPQ2

Google deployed CECPQ2 (X25519 + HRSS, later X25519 + Kyber768) in Chrome to Google services in 2019. Findings:

- **Client deployment**: client-side PQC is gated by binary rollout (Chrome version). Server must serve both classical and hybrid for years.
- **Cert chain**: PQC cert chains are not yet supported; only the key exchange is hybridized in CECPQ2.
- **Telemetry**: Google published measured handshake latency distributions; the long tail (mobile, weak CPUs) was a deployment blocker until ML-KEM-768 became the default.

### 11.3 Signal PQXDH (2023)

Signal deployed X25519 + ML-KEM-1024 hybrid for the X3DH key agreement in PQXDH. Key design decisions:

- **Hybrid for forward secrecy** — the Signal protocol already has ratcheting FS; PQXDH adds quantum resistance to the initial key agreement.
- **Asynchronous messaging constraint** — KEM fits well because the recipient's public key is pre-published.
- **ML-KEM-1024 (not 768)** — Signal chose Level 5 because of the long lifetime of message confidentiality and the absence of a downgrade path.

### 11.4 Apple iMessage PQ3 (2024)

Apple's PQ3 protocol uses ML-KEM at the initial key exchange, then a symmetric ratchet for subsequent messages. PQ3 is the first mass-market deployment of post-quantum cryptography in a consumer messaging app and demonstrates that:

- **Hybrid is the only safe default** — Apple retained the existing Elliptic Curve component alongside ML-KEM.
- **Ratcheting re-key** — re-running the ratchet periodically refreshes the post-quantum security margin.
- **Operational maturity** — Apple needed to deploy PQC to billions of devices simultaneously; this is the canonical case study for large-scale client-side migration.

### 11.5 NIST PQC timeline (historical)

- **2016** — NIST PQC standardization call for submissions.
- **2017** — 69 first-round submissions.
- **2019** — 26 second-round candidates.
- **2020** — 15 third-round candidates; 7 finalists + 8 alternates.
- **2022** — Kyber, Dilithium, SPHINCS+ selected for standardization.
- **2023** — FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) drafts.
- **2024** — FIPS 203/204/205 finalized.
- **2025-2035** — CNSA 2.0 phased migration window.

---

## 12. Hands-on Lab Exercise

A 4-hour lab exercise for a team to internalize PQC migration workflow.

### Lab objective

Produce a defensible post-quantum readiness score for a simulated 100-asset estate.

### Lab materials

- A directory of 100 simulated certs (mix of RSA-2048, RSA-4096, ECDSA-256, Ed25519, ML-KEM, ML-DSA).
- A simulated SNDL matrix (10 long-term-confidential flows).
- OpenSSL 3.x + oqs-provider installed.
- GmSSL installed for SM-suite exercises.
- mitmproxy for downgrade-lab.

### Lab steps

1. **Inventory (45 min)** — write a Python script that reads all 100 certs and produces the inventory CSV with all fields from §4.1.
2. **SNDL matrix (30 min)** — classify each long-term-confidential flow against the 3-scenario CRQC timeline (§5.2).
3. **Hybrid-TLS probe (45 min)** — set up an nginx server with `x25519_mlkem768`, probe it with `openssl s_client`, capture the handshake with tshark.
4. **Downgrade lab (45 min)** — configure mitmproxy to strip the hybrid group, verify the handshake fails, document why.
5. **Crypto-agility drill (45 min)** — remove `x25519_mlkem768` from the server config, measure time-to-disable, grade the drill.
6. **Readiness score (30 min)** — compute the 0-100 score using the formula from §10.2, produce a one-page executive summary.

### Lab expected outcomes

Every team member should produce:

- A complete inventory CSV with >95% cert coverage.
- A SNDL matrix identifying all CRITICAL exposures.
- A working hybrid-TLS server configuration.
- A successful downgrade-lab demonstration.
- A crypto-agility drill grade of at least B.
- A defensible readiness score with breakdown by dimension.

---

## 13. Assessment Anti-Patterns

Common ways an assessment goes wrong:

- **"We enabled Kyber, we're post-quantum ready"** — hybrid-TLS is one piece; root CAs, code-signing, HSM masters, SNDL exposure, and crypto-agility are independently necessary.
- **Treating QKD as "provably secure"** — BB84's proof assumes ideal hardware; real QKD hardware has been broken by PNS, detector blinding, and Trojan-horse attacks.
- **Picking ML-KEM-512 for bandwidth** — the 256-byte saving per handshake is not worth halving the security level.
- **Forgetting SNDL on captured data** — migrating TLS in 2027 does not protect traffic captured in 2022.
- **Skipping the agility drill** — most orgs claim agility and never test it; the first time agility matters is the day a break is announced.
- **National crypto as "more secure" or "less secure"** — SM2/SM3/SM4 are algorithms subject to the same implementation discipline as NIST primitives; national origin does not change the math.
- **Reporting central-estimate-only SNDL** — a CRQC arrival estimate without a range is a finding against NIST SP 800-227.
- **Assuming downgrade resistance** — always test; the Finished message must bind the group selection.

---

## 14. References and Further Reading

### NIST standards

- **FIPS 203 (ML-KEM)** — https://csrc.nist.gov/pubs/fips/203/final
- **FIPS 204 (ML-DSA)** — https://csrc.nist.gov/pubs/fips/204/final
- **FIPS 205 (SLH-DSA)** — https://csrc.nist.gov/pubs/fips/205/final
- **NIST SP 800-227 (Key Establishment)** — https://csrc.nist.gov/pubs/sp/800/227/ipd
- **NIST SP 800-208 (Stateful Hash-Based Signatures)** — https://csrc.nist.gov/pubs/sp/800/208/final
- **NIST PQC Project** — https://csrc.nist.gov/projects/post-quantum-cryptography

### NSA / CNSA 2.0

- **CNSA 2.0 Algorithms** — https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_ALGORITHMS_.PDF
- **CNSA 2.0 FAQ** — https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF

### IETF RFCs

- **RFC 8391 (XMSS)** — https://www.rfc-editor.org/rfc/rfc8391
- **RFC 8554 (LMS)** — https://www.rfc-editor.org/rfc/rfc8554
- **RFC 8998 (TLS 1.3 SM cipher suites)** — https://www.rfc-editor.org/rfc/rfc8998
- **draft-ietf-tls-hybrid-design** — https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/

### Open-source libraries

- **Open Quantum Safe (liboqs)** — https://github.com/open-quantum-safe/liboqs
- **oqs-provider** — https://github.com/open-quantum-safe/oqs-provider
- **cloudflare/circl** — https://github.com/cloudflare/circl
- **GmSSL** — https://github.com/guanzhi/GmSSL
- **Tongsuo (BabaSSL)** — https://github.com/Tongsuo-Project/Tongsuo
- **cisco/hash-sigs (XMSS/LMS)** — https://github.com/cisco/hash-sigs

### PRC national standards

- **GB/T 38636-2020 (GM SSL / TLCP)** — Chinese national standard for TLS with SM cipher suites.
- **GB/T 32918 (SM2)** — elliptic curve algorithm.
- **GB/T 32905 (SM3)** — hash function.
- **GB/T 32907 (SM4)** — block cipher.
- **GM/T 0008 (SM9)** — identity-based encryption.
- **PRC Cryptography Law (2020)** — http://www.npc.gov.cn/npc/c2/c30834/201910/t20191026_12042881.html

### Research papers

- **Gidney & Ekera 2019 (Shor cost)** — https://doi.org/10.22331/q-2021-04-15-433
- **Lydersen et al. 2010 (QKD detector blinding)** — https://doi.org/10.1038/nphoton.2010.123
- **Weier et al. 2011 (QKD Trojan-horse)** — https://doi.org/10.1038/nphoton.2011.199
- **ROCA (CVE-2017-15361)** — https://crocs.fi.muni.cz/public/papers/rsa_ccs17
- **Dragonblood (WPA3)** — https://wpa3.mathyvanhoef.com/
- **Espitau et al. (Dilithium fault attack)** — https://eprint.iacr.org/2017/1023
- **Signal PQXDH (2023)** — https://signal.org/docs/specifications/pqxdh/
- **Apple PQ3 (2024)** — https://security.apple.com/blog/imessage-pq3/

### Industry guidance

- **ETSI Quantum-Safe Algorithms** — https://www.etsi.org/technologies/quantum-safe-cybersecurity
- **ETSI TR 103 619** — Migration strategies and recommendations.
- **Cloudflare post-quantum blog** — https://blog.cloudflare.com/tag/post-quantum/
- **Google CECPQ2 experiment** — https://blog.chromium.org/2019/10/helping-to-protect-chrome-with-post.html
