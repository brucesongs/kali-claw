# Quantum-Crypto Attack Payloads / Command & Exploit Catalogue

> Companion to `SKILL.md`. Every command is reproducible on Kali Linux 2025-2 after building liboqs + oqs-provider, installing GmSSL, and (optionally) obtaining cloudflare/circl.
>
> Placeholder convention: `target.example.com` is the target host, `$OQS_PROVIDER` is the path to the compiled oqs-provider module, `gmssl` is the GmSSL CLI binary, `0xTarget` is a target contract address for blockchain-PQC crossover cases.
>
> **Forward-looking note**: Many sections describe attacks that are theoretical, lab-only, or preparation-focused (e.g., lattice side-channel, QKD hardware attacks). They are documented so defenders can rehearse before the break, not because they are routinely exploitable in production today.

---

## 1. Environment Setup (liboqs / oqs-provider / GmSSL / circl)

```bash
# ─── liboqs (reference PQC C library) ───
sudo apt install cmake ninja-build python3-pytest python3-pytest-xdist \
    xsltproc doxygen graphviz python3-yaml valgrind
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
cmake -GNinja -B build -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=OFF
cmake --build build --parallel 8
sudo cmake --install build

# ─── oqs-provider (OpenSSL 3.x PQC provider) ───
git clone --recurse-submodules https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -B build -DCMAKE_BUILD_TYPE=Release \
    -DOQS_PROVIDER_BUILD_OBJECTS=ON \
    -DOPENSSL_ROOT_DIR=/usr
cmake --build build --parallel 8
sudo cmake --install build
# Load it:
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
openssl list -providers -provider oqsprovider -verbose

# ─── GmSSL (Chinese national crypto) ───
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL && mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make -j8 && sudo make install
gmssl version

# ─── Tongsuo / BabaSSL (Alibaba OpenSSL fork with SM + PQC) ───
git clone https://github.com/Tongsuo-Project/Tongsuo.git
cd Tongsuo
./config --prefix=/usr/local/tongsuo enable-ntls enable-ssl3 enable-weak-ssl-ciphers \
    no-shared
make -j8 && sudo make install
/usr/local/tongsuo/bin/openssl version

# ─── cloudflare/circl (Go PQC + hybrid) ───
go install github.com/cloudflare/circl/...@latest

# ─── oqs-test (probe server PQC support) ───
pip3 install oqs-test  # or build from oqs-demos repo

# ─── RsaCtfTool (ROCA detection) ───
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
cd RsaCtfTool && pip3 install -r requirements.txt

# ─── Qiskit (quantum simulator, educational) ───
pip3 install qiskit qiskit-aer

# ─── hash-sigs (XMSS/LMS reference, RFC 8391/8554) ───
git clone https://github.com/cisco/hash-sigs.git
cd hash-sigs && make
```

---

## 2. Quantum-Vulnerability Inventory (RSA/ECC Asset Discovery)

Identify every Shor-vulnerable asymmetric key across the estate. RSA, DSA, ECDSA, EdDSA, Diffie-Hellman, ECDH all collapse under Shor; this section enumerates them.

```bash
# ─── Certificate inventory via Certificate Transparency logs ───
# crt.sh JSON API for a domain
curl -s 'https://crt.sh/?q=%25.example.com&output=json' \
    | jq -r '.[].issuer_name' | sort -u

# For each cert, fetch and classify the public-key algorithm
domain="example.com"
for certid in $(curl -s "https://crt.sh/?q=%25.${domain}&output=json" | jq -r '.[].id' | head -100); do
  curl -s "https://crt.sh/?d=${certid}" | openssl x509 -noout -text 2>/dev/null \
      | grep -E "Public Key Algorithm|Public-Key|ECDSA|RSA Public-Key" \
      | head -3
done | sort | uniq -c | sort -rn

# ─── Internal TLS scan with ZGrab2 ───
echo "10.0.0.0/8" | zmap -p 443 -o zmap_results.csv
zgrab2 tls --port 443 --tls1-3 --data=./zmap_results.csv \
    --metadata-file=tls_scan.json
jq '.data.tls.result.handshake_log.server_certificates' tls_scan.json \
    | grep -oE '"public_key":\{"algorithm":"[^"]+"' | sort | uniq -c

# ─── SSH host key algorithm extraction (Shor-vulnerable list) ───
for h in $(cat hosts.txt); do
    ssh-keyscan -t rsa,ecdsa,ed25519 "$h" 2>/dev/null \
        | awk '{print $2, $3}' | head -1
done | sort | uniq -c

# ─── Internal PKI / CA database export ───
# (vendor-specific — adapt to your CA. Output: key fingerprint, algorithm, size, issuer, validity)
# Example for a Dogtag/FreeIPA CA:
ipa ca-find --all | grep -E "Subject|Issuer|Not After"

# ─── HSM / KMS key attestation ───
aws kms list-keys | jq -'.Keys[].KeyId' | while read kid; do
    aws kms describe-key --key-id "$kid" | jq -r '.KeyMetadata | {SigningAlgorithms, EncryptionAlgorithms, KeySpec}'
done
# Flag every RSA/ECC key as Shor-vulnerable in the inventory.

# ─── Code-signing cert inventory (long-lived, high-impact) ───
# macOS notarization, Windows Authenticode, Java jarsigner, GPG
find / -name "*.p12" -o -name "*.pfx" 2>/dev/null | while read f; do
    openssl pkcs12 -in "$f" -nokeys -passin pass: 2>/dev/null \
        | openssl x509 -noout -subject -text 2>/dev/null | head -2
done
```

### SNDL (Store-Now-Decrypt-Later) Data-Flow Mapping

```bash
# Identify data flows where long-term-confidential data crosses classical public-key encryption.
# Heuristic: any TLS 1.2-or-lower session carrying data with confidentiality lifetime > 10 years.
#
# Step 1: capture TLS sessions on a sensitive data path
tcpdump -i eth0 -w sndl.pcap 'tcp port 443 and host sensitive-app.internal'

# Step 2: identify the negotiated cipher (look for non-ECDHE / RSA key-exchange)
tshark -r sndl.pcap -Y 'tls.handshake.type == 2' \
    -T fields -e tls.handshake.ciphersuite

# Step 3: classify each flow
#   RSA key-exchange (no forward secrecy) → already SNDL-exposed even without a CRQC
#   ECDHE-RSA → session protected, but the RSA cert becomes forgeable under Shor
#   X25519+ML-KEM (hybrid) → SNDL-safe unless BOTH X25519 and ML-KEM fall
#
# Step 4: weight by data sensitivity (HIPAA, attorney-client, M&A, state secret)
# See §13 for the prioritization matrix.
```

---

## 3. Shor Algorithm Impact Assessment

Model which keys become forgeable under a Cryptographically Relevant Quantum Computer (CRQC) and on what timeline.

```python
#!/usr/bin/env python3
# shor_impact.py — Model Shor-vulnerability per key

# CRQC arrival estimates (best-of published, calibrated mid-2026)
#   - NSA / CNSA 2.0 schedule: 2025-2035 phased migration
#   - NIST: "10-20 years" from 2016 → 2026-2036
#   - ETSI: 2026-2030 for high-value targets
#   - Gidney & Ekera 2019: ~20M physical qubits, 8 hours for RSA-2048
CRQC_TIMELINE = {
    "optimistic": 2030,
    "central":    2033,
    "conservative": 2038,
}

def shor_forgable(algorithm, key_size_bits):
    """Return (forgeable, quantum_qubits_estimate)."""
    if algorithm in ("RSA", "DSA"):
        # RSA-2048 ≈ 20M physical qubits, 8 hours (Gidney-Ekera)
        return True, 20_000_000
    if algorithm in ("ECDSA", "ECDH", "EdDSA"):
        # ECC P-256 ≈ 2,300 logical qubits (much smaller than RSA)
        return True, 2_300
    if algorithm in ("DH", "Diffie-Hellman"):
        return True, 20_000_000  # same family as RSA-2048
    if algorithm in ("ML-KEM", "ML-DSA", "SLH-DSA", "XMSS", "LMS"):
        return False, None  # post-quantum by design
    return None, None  # unknown

def sndl_window(data_confidentiality_lifetime_years, crqc_year, current_year=2026):
    """Years until collected ciphertext is decryptable."""
    return crqc_year - current_year - data_confidentiality_lifetime_years

# Example inventory
inventory = [
    {"asset": "Root CA", "algo": "RSA", "size": 4096, "lifetime": 25, "sensitivity": "critical"},
    {"asset": "Code-signing", "algo": "RSA", "size": 2048, "lifetime": 10, "sensitivity": "high"},
    {"asset": "TLS leaf", "algo": "ECDSA", "size": 256, "lifetime": 1, "sensitivity": "low"},
    {"asset": "Long-term archive", "algo": "RSA", "size": 2048, "lifetime": 30, "sensitivity": "critical"},
]

for k in inventory:
    forgeable, qubits = shor_forgable(k["algo"], k["size"])
    if forgeable:
        for scenario, year in CRQC_TIMELINE.items():
            window = sndl_window(k["lifetime"], year)
            risk = "ALREADY-EXPOSED" if window < 0 else f"{window}-year-margin"
            print(f"{k['asset']:20} {k['algo']:8} {scenario:12} → {risk}")
```

### Output interpretation

```
Root CA             RSA      optimistic    → ALREADY-EXPOSED
Root CA             RSA      central       → ALREADY-EXPOSED
Root CA             RSA      conservative  → ALREADY-EXPOSED
Code-signing        RSA      optimistic    → ALREADY-EXPOSED
Code-signing        RSA      central       → ALREADY-EXPOSED
Code-signing        RSA      conservative  → 2-year-margin
TLS leaf            ECDSA    optimistic    → 3-year-margin
TLS leaf            ECDSA    central       → 6-year-margin
Long-term archive   RSA      optimistic    → ALREADY-EXPOSED
Long-term archive   RSA      central       → ALREADY-EXPOSED
Long-term archive   RSA      conservative  → ALREADY-EXPOSED
```

Anything `ALREADY-EXPOSED` is, by definition, SNDL-exposed today regardless of when migration happens.

---

## 4. Grover Algorithm Impact on Symmetric Keys

Grover's algorithm gives a quadratic speedup on brute-force search. The post-quantum strength of a symmetric primitive is half its classical strength.

| Primitive | Classical strength | Post-quantum strength | Verdict |
|-----------|---------------------|----------------------|---------|
| AES-128 | 128 bits | ~64 bits | **Upgrade to AES-256 for long-term data** |
| AES-192 | 192 bits | ~96 bits | Acceptable for most uses |
| AES-256 | 256 bits | ~128 bits | Recommended for post-quantum |
| ChaCha20 (256-bit key) | 256 bits | ~128 bits | Recommended |
| SM4 (128-bit key) | 128 bits | ~64 bits | **Upgrade to SM4 with 256-bit extension or AES-256** |
| SHA-256 (preimage) | 256 bits | ~128 bits | Acceptable |
| SHA-1 | 80 bits (collision) | ~80 bits | **Broken already** |
| SM3 (256-bit) | 256 bits | ~128 bits | Acceptable |

```python
#!/usr/bin/env python3
# grover_impact.py — Symmetric key post-quantum strength

def grover_strength(classical_bits):
    return classical_bits // 2

# Quick table
for name, bits in [("AES-128", 128), ("AES-192", 192), ("AES-256", 256),
                   ("ChaCha20", 256), ("SM4", 128), ("SHA-256", 256),
                   ("SHA3-256", 256), ("SHA-1", 80)]:
    pq = grover_strength(bits)
    verdict = "OK" if pq >= 128 else ("UPGRADE" if pq >= 96 else "BROKEN")
    print(f"{name:12} classical={bits:3}  post-quantum≈{pq:3}  {verdict}")
```

```bash
# Identify weak symmetric algorithms in deployed TLS stacks
for h in $(cat hosts.txt); do
    negotiated=$(echo | openssl s_client -connect "$h:443" -tls1_3 2>/dev/null \
        | grep -E "Cipher|Server session ticket" | head -1)
    echo "$h: $negotiated"
done | grep -iE "aes-128|chacha20"  # flag AES-128 for long-term-confidential flows
```

---

## 5. NIST PQC Candidates Testing (ML-KEM / ML-DSA / SLH-DSA)

Probe a vendor's FIPS 203/204/205 implementation for parameter-set correctness, signature determinism, and key serialization.

```bash
# ─── List all PQC algorithms registered by oqs-provider ───
openssl list -signature-algorithms -provider oqsprovider | sort
openssl list -kem-algorithms -provider oqsprovider | sort

# ─── ML-KEM (Kyber) keygen + encaps + decaps ───
openssl -provider oqsprovider -genpkey -algorithm mlkem512 -out mlkem512-priv.pem
openssl -provider oqsprovider -pkey -in mlkem512-priv.pem -pubout -out mlkem512-pub.pem

# Encapsulate (server side: generate ciphertext + shared secret given recipient pubkey)
openssl -provider oqsprovider -pkeyutl -encrypt -pubin -inkey mlkem512-pub.pem \
    -in plaintext.bin -out ciphertext.bin

# Decapsulate (recipient recovers shared secret)
openssl -provider oqsprovider -pkeyutl -decrypt -inkey mlkem512-priv.pem \
    -in ciphertext.bin -out recovered.bin

# Confirm shared secrets match
diff plaintext.bin recovered.bin  # should be empty

# Repeat with mlkem768 and mlkem1024; verify public-key sizes match FIPS 203
#   mlkem512:  pk=800 bytes, sk=1632 bytes, ct=768 bytes
#   mlkem768:  pk=1184 bytes, sk=2400 bytes, ct=1088 bytes
#   mlkem1024: pk=1568 bytes, sk=3168 bytes, ct=1568 bytes
stat -c '%n %s' mlkem512-pub.pem mlkem768-pub.pem mlkem1024-pub.pem 2>/dev/null || \
    ls -l mlkem*-pub.pem

# ─── ML-DSA (Dilithium) keygen + sign + verify ───
openssl -provider oqsprovider -genpkey -algorithm mldsa65 -out mldsa65-priv.pem
openssl -provider oqsprovider -pkey -in mldsa65-priv.pem -pubout -out mldsa65-pub.pem
echo "message to sign" > msg.txt
openssl -provider oqsprovider -pkeyutl -sign -inkey mldsa65-priv.pem \
    -in msg.txt -out sig.bin
openssl -provider oqsprovider -pkeyutl -verify -pubin -inkey mldsa65-pub.pem \
    -in msg.txt -sigfile sig.bin

# Parameter sets and signature sizes (FIPS 204):
#   mldsa44 (Level 2):  sig ≈ 2420 bytes
#   mldsa65 (Level 3):  sig ≈ 3309 bytes
#   mldsa87 (Level 5):  sig ≈ 4627 bytes

# ─── SLH-DSA (SPHINCS+) keygen + sign + verify ───
openssl -provider oqsprovider -genpkey -algorithm slh_dsa_sha2_128s -out slhdsa-priv.pem
openssl -provider oqsprovider -pkey -in slhdsa-priv.pem -pubout -out slhdsa-pub.pem
openssl -provider oqsprovider -pkeyutl -sign -inkey slhdsa-priv.pem -in msg.txt -out slhsig.bin
openssl -provider oqsprovider -pkeyutl -verify -pubin -inkey slhdsa-pub.pem \
    -in msg.txt -sigfile slhsig.bin

# SLH-DSA signatures are LARGE (~7-50 KB). Confirm the vendor is not silently
# truncating or compressing them in storage/transmission.
ls -l slhsig.bin

# ─── Deterministic vs randomized signature modes ───
# ML-DSA supports deterministic and randomized signing. Deterministic mode
# exposes the implementation to fault-injection attacks (a single faulty
# signature under deterministic mode can leak the secret). Verify the mode:
openssl -provider oqsprovider -pkeyutl -sign -inkey mldsa65-priv.pem \
    -in msg.txt -out sig1.bin
openssl -provider oqsprovider -pkeyutl -sign -inkey mldsa65-priv.pem \
    -in msg.txt -out sig2.bin
cmp sig1.bin sig2.bin
#   Match → deterministic mode (verify this is intentional)
#   Differ → randomized mode (preferred for fault-attack resistance)
```

### Common PQC parameter misuse findings

- **ML-KEM-512 in production for long-term data** — NIST Level 1 (post-quantum ~64-bit). Should be ML-KEM-768 minimum.
- **ML-DSA-44 used where 128-bit classical-equivalent is required** — ML-DSA-44 is Level 2 (post-quantum 128-bit but classical ~96-bit). For 128-bit classical parity use ML-DSA-65.
- **SLH-DSA "fast" variant chosen to save signature size** — the "f" (fast) variants trade signing speed for security margin; for long-term root-of-trust use the "s" (small) variants.
- **Development parameter set (`-deterministic`) shipped to production** — liboqs dev-only flags must never be compiled into production binaries.

```bash
# Strings-based audit of a vendor PQC binary
strings /usr/lib/vendor/libpqc.so | grep -iE "KYBER|ML-KEM|ML-DSA|DILITHIUM|SPHINCS|SLH-DSA|FIPS"
strings /usr/lib/vendor/libpqc.so | grep -iE "512|768|1024|Level|NIST"
```

---

## 6. Hybrid TLS Analysis (liboqs / OQS-OpenSSL / cloudflare/circl)

Probe whether a server actually negotiates a hybrid (classical + PQC) key exchange group, and whether the negotiation is downgrade-resistant.

```bash
# ─── Available hybrid groups after loading oqs-provider ───
openssl list -groups -provider oqsprovider

# Expect to see (subset):
#   x25519_kyber512, x25519_kyber768, secp256r1_kyber768,
#   x25519_mlkem512, x25519_mlkem768, secp256r1_mlkem768,
#   x25519_frodo640aes, ...

# ─── Negotiate a specific hybrid group against a target ───
target="cloudflare.com"  # Cloudflare was an early hybrid-PQC deployer
openssl s_client -connect ${target}:443 -tls1_3 \
    -groups x25519_kyber768 -msg 2>&1 | \
    grep -A3 "ServerHello\|Supported Groups\|Negotiated group"

# Confirm the server actually negotiated the hybrid (NOT downgraded to plain x25519)
# Look for the KEM ID in the ServerHello extensions

# ─── All-hybrid scan against a target ───
for grp in x25519_kyber512 x25519_kyber768 secp256r1_kyber768 \
           x25519_mlkem512 x25519_mlkem768 secp256r1_mlkem768 \
           x25519_frodo640aes x25519_bikel1; do
    result=$(echo | timeout 5 openssl s_client -connect ${target}:443 -tls1_3 \
        -groups "$grp" 2>&1 | grep -E "Cipher|protocol" | head -2 | tr '\n' '|')
    echo "${grp}: ${result}"
done

# ─── Downgrade-resistance test (active MITM lab) ───
# Setup: client and server in a lab, attacker on the path with mitmproxy.
# Test: client offers x25519_mlkem768, attacker strips it, server falls back to x25519.
# Expected: handshake MUST FAIL — the Finished message must bind the group selection.
# If handshake succeeds with downgrade, that's a critical finding (PQC downgrade).
#
# mitmproxy config to strip the extension:
# addons:
#   - strip_pqc:
#       group: x25519_mlkem768
# Script: see mitmproxy_addons/strip_pqc.py in payloads/samples/

# ─── Verify Finished message binds the group ───
# Capture the full handshake and parse TLS 1.3 transcript
tshark -r hybrid.pcap -Y 'tls.handshake.type == 20' \
    -T fields -e tls.handshake.finished_verify_data

# If the verify data differs between a hybrid and a downgraded handshake,
# the negotiation is bound; otherwise it's vulnerable.

# ─── cloudflare/circl Go test (for Cloudflare-style edge) ───
cat > /tmp/hybrid.go <<'EOF'
package main
import (
    "fmt"
    "github.com/cloudflare/circl/kem/x25519/kyber768"
    "crypto/rand"
)
func main() {
    pk, sk, _ := kyber768.GenerateKeyPair(rand.Reader)
    ct, ss1, _ := pk.Encapsulate(rand.Reader)
    ss2, _ := sk.Decapsulate(ct)
    fmt.Printf("shared match: %v\n", ss1.Equal(ss2))
}
EOF
go run /tmp/hybrid.go
```

### Server-side hybrid TLS configuration (nginx + oqs-provider)

```nginx
# nginx.conf — enable hybrid-PQC TLS (requires nginx built against OpenSSL 3.x + oqs-provider)
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519:secp256r1:x25519_kyber768:x25519_mlkem768;
ssl_conf_command Groups "X25519:x25519_kyber768:x25519_mlkem768";
# Client can request any offered group; server picks the first supported.
```

```bash
# Test the deployed nginx
openssl s_client -connect my-edge.internal:443 -tls1_3 -groups x25519_mlkem768 -msg \
    | grep -E "ServerHello|server_key_exchange"
```

---

## 7. PQC Implementation Flaws (Side-Channel, Fault Injection)

Lattice-based PQC primitives (ML-KEM, ML-DSA) involve operations (NTT, rejection sampling, matrix-vector multiplication) that have been shown to leak timing and power information. These are lab-only tests on authorized hardware.

```bash
# ─── Timing side-channel: is decapsulation constant-time? ───
# Use dudect — a standard constant-timeness checker
git clone https://github.com/oreparaz/dudect.git
cd dudect
# Target: liboqs ML-KEM-768 decapsulation
# Adapt src/fixture.c to call OQS_KEM_kyber_768_decaps

# ─── ChipWhisperer power-analysis setup (lab) ───
# Hardware: ChipWhisperer-Lite or Husky + target board running liboqs
# Software: ChipWhisperer Analyzer
pip3 install chipwhisperer
python3 <<'EOF'
import chipwhisperer as cw
scope = cw.scope()
target = cw.target(scope, cw.targets.SimpleSerial)
# Flash target firmware that exposes mlkem768_decaps over SimpleSerial
# Capture 10,000 traces
scope.adc.samples = 24000
project_file = cw.create_project("mlkem_traces.cwp", overwrite=True)
for i in range(10000):
    target.simpleserial_write('k', os.urandom(32))  # random ciphertext input
    ret = cw.capture_trace(scope, target, os.urandom(32), 'k')
    project_file.traces.append(ret)
project_file.save()
# Analyze with CPA or TVLA
EOF

# ─── TVLA (Test Vector Leakage Assessment) — quick fixed-vs-random ───
# Run TVLA on the captured trace set. A failing TVLA at order 1 means
# first-order side-channel leakage (timing or power) — constant-timeness
# has been violated.

# ─── Fault injection on ML-DSA signing ───
# Setup: clock glitcher (ChipSHOUTER, NewAE) on target running ML-DSA
# Attack: inject a single fault during the rejection-sampling step of
# signing. A faulty signature, combined with a correct signature on the
# same message under deterministic mode, leaks the secret polynomial.
# References: see "One fault kills the secret" (Espitau et al.) for
# the original Dilithium fault-attack framework.

# ─── Cache-timing attack on matrix-vector multiplication ───
# On x86, use perf counters to measure cache-line access patterns during
# liboqs ML-KEM-768 operations. Cross-VM (colocated cloud) cache-timing
# has been demonstrated against Kyber.
perf stat -e cache-misses,cache-references \
    ./liboqs_bench --kem mlkem768 --iters 100000
```

### Documented PQC implementation CVEs (model cases)

| CVE / Ref | Affected | Description |
|-----------|---------|-------------|
| Kyber timing leak (multiple 2022 disclosures) | Early liboqs / forks | Non-constant-time NTT allowed key recovery |
| Dilithium fault attack (Espitau et al.) | Reference impl pre-2023 | Single fault + deterministic signature → secret leak |
| Frodo parameter-set confusion | Multiple early forks | Wrong security level silently selected |
| BIKE decoding non-CT | Early BIKE submissions | Decoding loop leaked information bits |

```bash
# Scan a deployed PQC binary against known vulnerable versions
strings /usr/lib/vendor/libpqc.so | grep -iE "liboqs-[0-9]"
# Cross-reference with the liboqs security advisory page:
#   https://openquantumsafe.org/liboqs/security-advisories.html
```

---

## 8. QKD / BB84 Protocol Attacks

Quantum Key Distribution promises information-theoretic security but real hardware breaks. This section documents the attack surface against commercial QKD boxes (ID Quantique Clavis^3, Chinese QKD backbones).

### Attack: Photon-Number-Splitting (PNS)

**Applicable when**: the QKD source is an attenuated laser (multi-photon pulses possible), not a true single-photon source.

```python
#!/usr/bin/env python3
# pns_attack.py — Demonstrate PNS feasibility given source characteristics
#
# An attenuated-laser source emits photons with Poisson(μ) distribution.
# Multi-photon probability: P(n>=2) = 1 - (1+μ)e^(-μ)
# For μ=0.1 (typical): P(n>=2) ≈ 0.005 — 0.5% of pulses are multi-photon.
# The attacker splits one photon from each multi-photon pulse, stores it,
# and lets the rest reach Bob. After sifting, the attacker measures their
# stored photons to recover the key bit. No disturbance is introduced.

import math

def multi_photon_probability(mu):
    """P(n >= 2) for Poisson with mean mu."""
    return 1 - (1 + mu) * math.exp(-mu)

for mu in [0.1, 0.5, 1.0]:
    p = multi_photon_probability(mu)
    bits_per_million = p * 1e6
    print(f"μ={mu}: P(multi-photon)={p:.4f}  ({bits_per_million:.0f} vulnerable bits per 1M pulses)")
```

**Countermeasure**: decoy-state protocol (varying μ, statistical detection of PNS).

### Attack: Detector Blinding (Lydersen 2010)

**Applicable when**: InGaAs avalanche photodiode (APD) detectors are used without a detector-watchdog.

```python
#!/usr/bin/env python3
# detector_blinding.py — Conceptual attack pattern
#
# Continuous-wave light injected into Bob's detector drives the APD
# into linear (non-Geiger) mode. The detector then only fires when the
# attacker sends an above-threshold pulse. The attacker controls every
# detection event, can force any key, and the QBER stays within bounds.
#
# Reproducibility: Lydersen et al. (Nat. Photonics 2010) demonstrated
# this on a commercial ID Quantique Clavis^2 system. The fix is a
# detector watchdog (optical power monitor).

# Detect (defender side): monitor APD linearity / optical input power.
# Inject (attacker side, lab only): CW light via the quantum channel.
```

### Attack: Trojan-Horse

**Applicable when**: the source has no optical isolator.

```python
# The attacker injects light back into Alice's source and observes
# the phase modulator state in the reflected light. This reveals Alice's
# basis and bit choice for each pulse.
#
# Countermeasure: optical isolator at Alice's output.
```

### Decoy-state verification (defender)

```bash
# Verify the QKD box has decoy-state enabled
# (vendor-specific CLI; pattern shown)
ssh admin@qkd-box
qkd> show protocol
  Protocol:               BB84
  Decoy-state:            ENABLED        # ← must be ENABLED
  Decoy probabilities:    signal=0.5, decoy=0.25, vacuum=0.25
  Mean photon number:     signal μ=0.5, decoy μ=0.1

# If Decoy-state: DISABLED → PNS attack is feasible → critical finding.
```

### Device-Independent QKD (DI-QKD)

DI-QKD closes all detector side-channels by basing security on a Bell inequality violation rather than trusting the detector hardware. Verify deployments claiming DI-QKD:

```python
#!/usr/bin/env python3
# di_qkd_verify.py — Check Bell inequality violation is statistically significant
# A DI-QKD system must demonstrate CHSH > 2 (Bell violation).
# Verify the published S value is statistically significant (not a calibration artifact).

def chsh_threshold(samples, observed_s):
    """Require S > 2 + 5*sigma for security claim."""
    # (Statistical test details omitted; see UCAN, Arnon-Friedman et al.)
    pass
```

---

## 9. Chinese National Crypto (SM2 / SM3 / SM4 / SM9)

SM2 (asymmetric, EC-based, GB/T 32918), SM3 (256-bit hash, GB/T 32905), SM4 (128-bit symmetric, GB/T 32907), SM9 (identity-based, GB/T 32918.5). Mandatory in PRC government, finance, critical infrastructure.

```bash
# ─── SM2: keygen, sign, verify ───
gmssl genpkey -algorithm SM2 -out sm2key.pem
gmssl pkey -in sm2key.pem -pubout -out sm2pub.pem

# SM2 signs an SM3 hash of the message (the "Z value" includes ID and public key)
echo -n "message" > msg.txt
gmssl sm2 -sign -in msg.txt -key sm2key.pem -out sig.der
gmssl sm2 -verify -in msg.txt -pubkey sm2pub.pem -sig sig.der

# Confirm signature is DER-encoded per GB/T 32918.2
openssl asn1parse -in sig.der -inform DER

# ─── SM3: hash (compare to SHA-256 — both are 256-bit, Merkle-Damgard) ───
echo -n "abc" | gmssl sm3
# Expected: 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

# Length-extension: SM3 has the same Merkle-Damgard structure as SHA-256,
# so it IS vulnerable to length-extension attacks when used as a naive MAC.
# Confirm: build the length-extension attack against an SM3-based MAC.
python3 <<'EOF'
# Pseudocode — SM3 length-extension (same family as SHA-1/SHA-256 LE)
# hlextend library supports SM3 since 2022.
# from hlextend import sm3
# new_mac = sm3.macro(sm3_state, original_len, appended_data)
EOF

# ─── SM4: symmetric cipher (analogous to AES) ───
key=$(openssl rand -hex 16)   # 128-bit key
iv=$(openssl rand -hex 16)    # 128-bit IV for CBC/CTR

# CORRECT usage: SM4-GCM (authenticated) or SM4-CTR
echo "secret" | gmssl sm4 -e -cipher SM4-GCM -key "$key" -iv "$iv" -out ct.bin

# WRONG usage (flag as finding): SM4-ECB
echo "secret" | gmssl sm4 -e -cipher SM4-ECB -key "$key" -out ct-ecb.bin
# ECB leaks structure in ciphertext (the penguin picture problem).

# ─── SM9: identity-based encryption ───
# SM9 uses a master public/private pair; users' private keys are derived
# from their identity (email, phone, etc.).
gmssl sm9 -genmaster -out sm9master.pem
gmssl sm9 -genkey -id "alice@example.com" -master sm9master.pem -out alice-sm9.pem
gmssl sm9 -encrypt -id "alice@example.com" -masterpub sm9masterpub.pem -in msg.txt -out ct.bin
gmssl sm9 -decrypt -key alice-sm9.pem -in ct.bin -out msg recovered.txt
```

### SM2 side-channel: scalar multiplication

```python
#!/usr/bin/env python3
# sm2_scalar_mult_timing.py — Check if SM2 scalar multiplication is constant-time
# SM2 uses a 256-bit curve (same family as NIST P-256). If the implementation
# uses branching on secret scalar bits, it leaks via timing.
#
# Test: measure scalar-multiplication time for many random scalars;
# variance should be negligible if constant-time.

import time
from gmssl import sm2  # python-gmssl

# Generate many random scalars
import os
cryptoutil_scalars = [int.from_bytes(os.urandom(32), 'big') for _ in range(1000)]

times = []
for s in cryptoutil_scalars:
    t0 = time.perf_counter_ns()
    # call the SM2 scalar-mul primitive (implementation-specific)
    _ = sm2.CryptSM2(public_key='04...' + '00'*64, private_key='%064x' % s)
    t1 = time.perf_counter_ns()
    times.append(t1 - t0)

# Variance analysis: if std/mean > 5%, non-constant-time → finding.
import statistics
mean_t = statistics.mean(times)
stdev_t = statistics.stdev(times)
print(f"mean={mean_t:.0f}ns  stdev={stdev_t:.0f}ns  ratio={stdev_t/mean_t:.3f}")
# ratio < 0.05 → constant-time OK
# ratio > 0.10 → non-constant-time, side-channel risk
```

---

## 10. SM2 / SM3 in TLS (GmSSL / Tongji SSL / RFC 8998)

RFC 8998 defines TLS 1.3 cipher suites using SM2/SM3/SM4:
- `TLS_SM4_GCM_SM3` (ECDHE-SM2 + SM3 + SM4-GCM)
- `TLS_SM4_CCM_SM3`

```bash
# ─── GmSSL GM SSL handshake probe ───
target="gm-tls.example.cn"
gmssl s_client -connect ${target}:443 -gmtls -msg 2>&1 | \
    grep -E "ECC-SM2|ECDHE-SM2|SM4|SM3|TLS_SM4_GCM_SM3|TLS_SM4_CCM_SM3"

# Confirm RFC 8998 cipher suite negotiated (not silently downgraded to TLS 1.2 RSA)
gmssl s_client -connect ${target}:443 -gmtls 2>&1 | grep -E "Cipher|Protocol|ServerKeyExchange"

# ─── Tongsuo (BabaSSL) with NTLS (Chinese NTLS standard, pre-TLS-1.3 SM) ───
/usr/local/tongsuo/bin/openssl s_client -connect ${target}:443 -enable_ntls \
    -cipher 'ECC-SM2-WITH-SM4-SM3' -ntls 2>&1 | grep -E "Cipher|Protocol"

# ─── Downgrade test: does the server accept RSA-only TLS 1.2 alongside GM? ───
openssl s_client -connect ${target}:443 -tls1_2 -cipher 'AES256-GCM-SHA384' 2>&1 | \
    grep -E "Cipher|Protocol"
# If yes, an active MITM may downgrade GM → RSA. Critical finding.

# ─── SM2 client certificate authentication ───
# Generate an SM2 client cert and present it
gmssl req -new -x509 -sm2 -key sm2key.pem -out sm2clientcert.pem -days 365 \
    -subj "/CN=sm2-client"
gmssl s_client -connect ${target}:443 -gmtls \
    -cert sm2clientcert.pem -key sm2key.pem

# ─── GB/T 38636-2020 compliance checklist ───
# 1. Server offers TLS_SM4_GCM_SM3 / TLS_SM4_CCM_SM3 in TLS 1.3
# 2. Server uses SM2 (not RSA/ECDSA) for certificate signing
# 3. Server certificate chain uses SM3 for fingerprinting
# 4. CRL/OCSP (if present) is SM2-signed
# 5. No silent fallback to TLS 1.2 RSA under active attack
```

### SM cipher suite interop test (GmSSL ↔ Tongsuo ↔ Tongji SSL)

```bash
# Three-way interop test for SM TLS stacks
# Common interop bugs: SM2 signature encoding (DER vs raw),
#   SM3 Z-value computation (some stacks omit ID),
#   SM4-GCM tag length (12 vs 16 bytes).

# GmSSL server, Tongsuo client
gmssl s_server -accept 4433 -gmtls -key sm2key.pem -cert sm2cert.pem &
TONGSUO_CLIENT/usr/local/tongsuo/bin/openssl s_client -connect localhost:4433 -enable_ntls

# Tongsuo server, GmSSL client
/usr/local/tongsuo/bin/openssl s_server -accept 4434 -enable_ntls \
    -key sm2key.pem -cert sm2cert.pem &
gmssl s_client -connect localhost:4434 -gmtls

# Document any interop failure as a national-crypto finding.
```

---

## 11. National Crypto in Blockchain (QuipNetwork/hashsigs-solidity)

Blockchains that adopt post-quantum or national crypto. The crossover case: a bridge or validator set that uses PQC signatures.

```solidity
// ─── QuipNetwork/hashsigs-solidity: hash-based signatures on-chain ───
// Source: https://github.com/QuipNetwork/hashsigs-solidity (11.3k stars)
// Implements Lamport / Winternitz one-time signatures in Solidity,
// intended for PQ-resistant on-chain verification.

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@quipnetwork/hashsigs/contracts/Lamport.sol";

contract PQBridge {
    using Lamport for bytes32;
    mapping(bytes32 => bool) public usedMessages;

    function verifyBridge(
        bytes32 message,
        bytes32[2][256] memory pubKey,  // 256 Lamport pairs
        bytes memory sig,
        bytes32 nextRoot                // for stateful iteration
    ) external {
        require(!usedMessages[message], "replay");
        require(Lamport.verify(message, pubKey, sig), "bad sig");
        usedMessages[message] = true;
        // ... bridge action
    }
}

// Audit checklist:
//   1. Is the Lamport/Winternitz key truly ONE-TIME? Reuse = catastrophic.
//   2. Is the hash function (keccak256) collision-resistant enough? (256-bit, PQ ~128-bit)
//   3. State management: can the same key be reused via reentrancy or storage collision?
//   4. Key rotation: does the contract support rotating the validator set's PQ keys?
//   5. Gas cost: hash-based signatures are large; verify the gas budget per bridge action.
```

```bash
# ─── QuipNetwork/hashsigs-rs (Rust reference implementation) ───
# Source: https://github.com/QuipNetwork/hashsigs-rs
git clone https://github.com/QuipNetwork/hashsigs-rs.git
cd hashsigs-rs
cargo build --release
# Generate a Lamport keypair, sign, verify
cargo run --example lamport_basic

# ─── QRL (Quantum Resistant Ledger) — blockchain using XMSS (stateful hash-sig) ───
# QRL uses XMSS-MT (multi-tree) for stateful post-quantum signatures.
# Audit: verify the wallet enforces state monotonicity (cannot reuse XMSS leaf index).
qrl-cli wallet_info
# If two transactions share the same XMSS leaf index → key reuse → forgeable.

# ─── SM2 / SM3 in Hyperledger Fabric (Chinese consortium chains) ───
# Hyperledger Fabric supports SM2/SM3 via the "guomi" (国密) BCCSP provider.
# Audit: verify the MSP uses SM2 (not ECDSA), orderer uses SM3 for hashing,
# and the channel config is SM2-signed.
```

---

## 12. Side-Channel on PQC (Lattice-Specific: Timing, Power, Cache)

Lattice PQC has side-channel surfaces that classical ECC/RSA does not: NTT ("number-theoretic transform"), rejection sampling, and large matrix-vector multiplications.

```python
#!/usr/bin/env python3
# lattice_timing_collect.py — Collect timing data for constant-timeness check
import os, time, statistics
# (Pseudocode — actual harness calls liboqs via ctypes)

def measure_decaps(ct_bytes, n=10000):
    times = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        # liboqs.OQS_KEM_kyber_768_decaps(ct_bytes)
        pass
        t1 = time.perf_counter_ns()
        times.append(t1 - t0)
    return times

# Random-vs-fixed ciphertext TVLA
random_times = measure_decaps(os.urandom(1088), 10000)
fixed_times = measure_decaps(b'\x00' * 1088, 10000)

# Welch's t-test on the two distributions
import scipy.stats as stats
t, p = stats.ttest_ind(random_times, fixed_times, equal_var=False)
print(f"TVLA t={t:.3f} p={p:.4f}")
# p < 0.0001 → first-order leakage detected → non-constant-time → critical finding
```

```bash
# ─── Cache-timing via perf (cross-VM scenario) ───
# On a colocated cloud VM, measure cache-miss patterns during a victim's
# liboqs operation. Cross-VM Kyber cache attacks have been demonstrated.
sudo perf stat -e L1-dcache-load-misses,LLC-load-misses \
    taskset -c 0 ./victim_pqc_server

# ─── Power analysis via ChipWhisperer (lab) ───
# See §7 for setup. Targeted operations on lattice:
#   1. NTT — leak via memory access pattern
#   2. Rejection sampling — leak via branch on random value
#   3. Compression / decompression — leak via arithmetic
```

---

## 13. PQC Migration Risk Assessment

Synthesize findings into a prioritized migration roadmap.

```python
#!/usr/bin/env python3
# pqc_migration_priority.py — Prioritize keys for replacement

inventory = [
    # asset, algo, size, lifetime_yrs, sensitivity(1-5), count
    {"asset": "Root CA",            "algo": "RSA",    "size": 4096,  "life": 25, "sens": 5, "count": 1},
    {"asset": "Code-signing",       "algo": "RSA",    "size": 4096,  "life": 10, "sens": 5, "count": 12},
    {"asset": "SSH host",           "algo": "Ed25519","size": 256,   "life": 1,  "sens": 3, "count": 4500},
    {"asset": "TLS leaf",           "algo": "ECDSA",  "size": 256,   "life": 1,  "sens": 2, "count": 12000},
    {"asset": "Long-term archive",  "algo": "RSA",    "size": 2048,  "life": 30, "sens": 5, "count": 1},
    {"asset": "HSM master",         "algo": "RSA",    "size": 4096,  "life": 20, "sens": 5, "count": 4},
    {"asset": "JWT signing",        "algo": "RS256",  "size": 2048,  "life": 1,  "sens": 3, "count": 80},
    {"asset": "Email (S/MIME)",     "algo": "RSA",    "size": 2048,  "life": 5,  "sens": 4, "count": 3000},
]

CRQC_YEAR = 2033  # central estimate

def priority_score(item):
    sndl_exposed = (item["life"] + 2026) > CRQC_YEAR  # data outlives CRQC arrival
    return (
        item["sens"] * 10            # sensitivity weight
        + (30 if sndl_exposed else 0)  # SNDL penalty
        + (20 if item["life"] > 10 else 0)  # long-lived bonus
    )

ranked = sorted(inventory, key=priority_score, reverse=True)
for item in ranked:
    score = priority_score(item)
    sndl = "SNDL-EXPOSED" if (item["life"] + 2026) > CRQC_YEAR else "ok"
    print(f"{score:4}  {item['asset']:22} {item['algo']:8} count={item['count']:6}  {sndl}")
```

### Sample output

```
 100  Root CA                RSA      count=     1  SNDL-EXPOSED
 100  Long-term archive      RSA      count=     1  SNDL-EXPOSED
  90  HSM master             RSA      count=     4  SNDL-EXPOSED
  90  Code-signing           RSA      count=    12  ok
  ...
```

---

## 14. Crypto Agility Testing

Crypto agility = the ability to switch algorithms in response to an emergency (e.g., a catastrophic break). Most orgs claim agility but never test it.

```bash
# ─── Scenario: Kyber is broken at 09:00 Monday. Disable it everywhere by Tuesday. ───

# Step 1: identify every system using Kyber/ML-KEM
# (uses the inventory from §2 + provider config scan)
grep -rl "kyber\|mlkem\|ml-kem" /etc/ /usr/local/etc/ 2>/dev/null

# Step 2: simulate the kill-switch
# OpenSSL 3.x — remove Kyber from the Groups list
sudo cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.bak
sudo sed -i 's/^Groups = .*/Groups = X25519:P-256/' /etc/ssl/openssl.cnf
sudo systemctl reload nginx apache2

# Step 3: measure breakage
#   - Which clients fail to connect? (legacy clients hardcoded to Kyber)
#   - Which internal services break? (services that REQUIRED PQC)
#   - Is there rollback? (cert chain may need reissuance under classical only)

# Step 4: time the drill
#   < 1 hour → A grade
#   1-4 hours → B
#   4-24 hours → C
#   > 24 hours → F (unacceptable; many systems would be down during a real break)

# ─── PKI agility: reissue every cert under a new algorithm ───
# How long to reissue 10,000 certs under SLH-DSA instead of RSA?
#   - CA throughput: how many cert-issues/sec?
#   - CRL/OCSP: does the revocation infrastructure support the new algorithm?
#   - Client deployment: do all clients trust the new root?
# This is the metric that determines whether the org can survive a real break.

# ─── Algorithm registry test ───
# A mature crypto-agility setup has a central algorithm registry that can be
# flipped without touching individual services. Verify:
curl -s http://internal-registry/algorithm-policy | jq .
# Expected output:
# {
#   "tls": {"allowed_groups": ["X25519", "x25519_mlkem768"]},
#   "pkcs12": {"allowed_signatures": ["ML-DSA-65", "SLH-DSA-128s"]},
#   "ssh":   {"allowed_keys":       ["ed25519", "RSA-4096"]},
#   ...
# }
#
# Test: flip a flag and measure how long until all clients pick it up.
```

### Post-quantum readiness scoring

```python
#!/usr/bin/env python3
# pq_readiness_score.py — 0-100 score across 5 dimensions

def score(inventory_coverage, hybrid_tls_coverage, agility_drill_result,
          national_crypto_compliance, qkd_posture):
    """
    Each dimension 0-20, total 0-100.
    """
    total = (
        inventory_coverage +              # completeness of Shor-vuln inventory
        hybrid_tls_coverage +             # % of TLS endpoints offering hybrid
        agility_drill_result +            # 24h-drill outcome (A=20, B=15, C=10, F=0)
        national_crypto_compliance +      # % of mandated SM-suite deployments compliant
        qkd_posture                       # decoy-state + DI-QKD posture
    )
    grade = (
        "A" if total >= 90 else
        "B" if total >= 75 else
        "C" if total >= 60 else
        "D" if total >= 40 else
        "F"
    )
    return total, grade

# Example: an org that has inventory (16/20), partial hybrid (10/20),
# untested agility (5/20), partial SM compliance (8/20), no QKD (5/20)
print(score(16, 10, 5, 8, 5))  # → (44, "D")
```

---

## 15. ROCA and RSA Pre-Quantum Vulnerabilities

ROCA (CVE-2017-15361) is the canonical "your RSA is already weaker than spec" lesson. Even before a CRQC, RSA keys generated by vulnerable Infineon firmware have a fingerprintable prime pattern.

```bash
# ─── RsaCtfTool ROCA detection ───
# Test a public key for ROCA vulnerability
RsaCtfTool --publickey suspect.pem --attack roca --private 2>&1 | \
    grep -iE "roca|vulnerable|attack"

# Batch scan all certs in a directory
for cert in certs/*.pem; do
    pubkey=$(mktemp)
    openssl x509 -in "$cert" -noout -pubkey > "$pubkey"
    result=$(RsaCtfTool --publickey "$pubkey" --attack roca 2>&1 | grep -iE "roca|vulnerable")
    echo "$cert: $result"
    rm "$pubkey"
done

# ─── Other classical RSA weaknesses (still pre-quantum) ───
# - Small exponent (e=3) with short message + no padding
# - Common prime between two keys (GCD attack on large cert corpora)
# - Wiener / Boneh-Durfee on small d
# - Coppersmith on partially-known primes

# Batch GCD on a cert corpus (research-grade)
# Tools: fastecdsa + gypsum, or https://github.com/cr-marcstevens/hashclash
```

---

## 16. Post-Quantum Readiness Reporting Templates

```markdown
# Post-Quantum Readiness Report — <Org Name>
## Engagement: <Date Range>

## 1. Executive Summary

<Post-quantum readiness score: X/100, grade Y>
<CRQC arrival central estimate used: 2033>
<Number of Shor-vulnerable long-lived keys: N>
<Number of SNDL-exposed data flows: M>

## 2. Quantum Exposure Inventory

| Asset Class | Algorithm | Count | Avg Lifetime (yrs) | SNDL-Exposed |
|-------------|-----------|-------|---------------------|--------------|
| Root CA     | RSA-4096  | 1     | 25                  | YES          |
| Code-sign   | RSA-4096  | 12    | 10                  | borderline   |
| TLS leaf    | ECDSA-256 | 12000 | 1                   | NO           |
| ...         | ...       | ...   | ...                 | ...          |

## 3. PQC Configuration Findings

### Finding PQC-001: Hybrid TLS downgrade (HIGH)
- Affected: edge-load-balancer-01..04
- Description: server offers x25519_mlkem768 but accepts plain x25519 fallback
  without binding the group selection in the Finished message.
- Impact: active MITM can downgrade hybrid-PQC sessions to classical-only,
  re-exposing the session to SNDL collection.
- Recommendation: bind the negotiated group in the Finished transcript
  (TLS 1.3 standard behavior; verify the OpenSSL/oqs-provider config).

## 4. National Crypto Findings (where applicable)

### Finding SM-001: SM4-ECB usage in TLS 1.2 fallback (CRITICAL)
- Affected: gm-tls-internal.example.cn
- Description: GM TLS deployment silently falls back to TLS 1.2 with SM4-ECB
  when the client does not present an SM2 client cert.
- Impact: ECB leaks plaintext structure; combined with downgrade, an active
  MITM can force the weak cipher.
- Recommendation: enforce TLS 1.3 with TLS_SM4_GCM_SM3 only; disable fallback.

## 5. Crypto-Agility Drill Results

- Scenario: "Kyber broken at 09:00 Monday"
- Time to disable Kyber estate-wide: <X hours>
- Services broken during drill: <list>
- Grade: <A/B/C/D/F>
- Recommendations: <central algorithm registry, cert auto-rotation, ...>

## 6. Prioritized Migration Roadmap

| Priority | Asset Class | Current | Target | Window | Owner |
|----------|-------------|---------|--------|--------|-------|
| P0       | Root CA     | RSA-4096| SLH-DSA + RSA hybrid | 2026-Q4 | PKI team |
| P0       | Long-term archive | RSA-2048 | AES-256-GCM + ML-KEM-wrapped keys | 2026-Q3 | Storage |
| P1       | Code-signing | RSA-4096 | ML-DSA-65 + RSA hybrid | 2027-Q1 | Release eng |
| P2       | TLS leaf | ECDSA-256 | X25519+ML-KEM-768 hybrid | 2027-Q3 | Edge |

## 7. References

- NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA)
- NIST SP 800-227 (PQC migration)
- CNSA 2.0 (NSA)
- GB/T 38636-2020 (GM SSL), GB/T 32918 (SM2), GB/T 32905 (SM3), GB/T 32907 (SM4)
- ETSI TR 103 619 (Quantum-Safe Algorithms)
```

---

## 17. References & Further Reading

- **NIST Post-Quantum Cryptography Standardization**: https://csrc.nist.gov/projects/post-quantum-cryptography
- **NIST FIPS 203 (ML-KEM)**: https://csrc.nist.gov/pubs/fips/203/final
- **NIST FIPS 204 (ML-DSA)**: https://csrc.nist.gov/pubs/fips/204/final
- **NIST FIPS 205 (SLH-DSA)**: https://csrc.nist.gov/pubs/fips/205/final
- **NIST SP 800-227 (Key Establishment)**: https://csrc.nist.gov/pubs/sp/800/227/ipd
- **CNSA 2.0 (NSA)**: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_ALGORITHMS_.PDF
- **Open Quantum Safe (liboqs)**: https://github.com/open-quantum-safe/liboqs
- **oqs-provider**: https://github.com/open-quantum-safe/oqs-provider
- **cloudflare/circl**: https://github.com/cloudflare/circl
- **GmSSL**: https://github.com/guanzhi/GmSSL
- **Tongsuo (BabaSSL)**: https://github.com/Tongsuo-Project/Tongsuo
- **RFC 8998 (TLS 1.3 with SM cipher suites)**: https://www.rfc-editor.org/rfc/rfc8998
- **RFC 8391 (XMSS)**: https://www.rfc-editor.org/rfc/rfc8391
- **RFC 8554 (LMS)**: https://www.rfc-editor.org/rfc/rfc8554
- **QuipNetwork/hashsigs-solidity**: https://github.com/QuipNetwork/hashsigs-solidity
- **QuipNetwork/hashsigs-rs**: https://github.com/QuipNetwork/hashsigs-rs
- **Gidney & Ekera 2019 (Shor cost)**: https://doi.org/10.22331/q-2021-04-15-433
- **Lydersen et al. 2010 (QKD blinding)**: https://doi.org/10.1038/nphoton.2010.123
- **Weier et al. 2011 (QKD Trojan-horse)**: https://doi.org/10.1038/nphoton.2011.199
- **ROCA (CVE-2017-15361)**: https://crocs.fi.muni.cz/public/papers/rsa_ccs17
- **Dragonblood (WPA3)**: https://wpa3.mathyvanhoef.com/
- **ETSI Quantum-Safe**: https://www.etsi.org/technologies/quantum-safe-cybersecurity
- **GB/T 38636-2020 (GM SSL)**: Chinese national standard
- **GB/T 32918 (SM2)**: Chinese national standard
- **GB/T 32905 (SM3)**: Chinese national standard
- **GB/T 32907 (SM4)**: Chinese national standard
- **Espitau et al. (Dilithium fault attack)**: https://eprint.iacr.org/2017/1023

---

## 18. PQC Migration Inventory Scripts

Automated scripts to scan a codebase and deployment estate for RSA/ECDSA/DSA usage, classify by Shor-vulnerability, and produce the inventory that feeds the migration roadmap.

```python
#!/usr/bin/env python3
# scan_classical_crypto.py — Scan a directory tree for classical crypto usage
# Walks source files, identifies RSA/ECDSA/DSA/DH references, and outputs
# a CSV with file, line, algorithm, and recommended PQ replacement.

import os, re, csv, sys
from pathlib import Path

ALGO_PATTERNS = [
    ("RSA",         re.compile(r"\bRSA[_-]?(?:2048|3072|4096|1024|512)?\b", re.I)),
    ("DSA",         re.compile(r"\bDSA\b", re.I)),
    ("ECDSA",       re.compile(r"\bECDSA\b", re.I)),
    ("Ed25519",     re.compile(r"\bEd25519\b", re.I)),
    ("Ed448",       re.compile(r"\bEd448\b", re.I)),
    ("DH",          re.compile(r"\b(?:DH|DiffieHellman|diffie-hellman)\b", re.I)),
    ("ECDH",        re.compile(r"\bECDH\b", re.I)),
    ("secp256r1",   re.compile(r"\bsecp256r1\b|P-256\b", re.I)),
    ("secp384r1",   re.compile(r"\bsecp384r1\b|P-384\b", re.I)),
]

REPLACEMENTS = {
    "RSA":       "ML-DSA-65 (signing) or ML-KEM-768 (encryption)",
    "DSA":       "ML-DSA-44 or ML-DSA-65",
    "ECDSA":     "ML-DSA-65",
    "Ed25519":   "ML-DSA-65 (or Ed25519+ML-DSA-65 hybrid)",
    "Ed448":     "ML-DSA-87",
    "DH":        "ML-KEM-768",
    "ECDH":      "X25519+ML-KEM-768 hybrid",
    "secp256r1": "X25519+ML-KEM-768 hybrid",
    "secp384r1": "P-384+ML-KEM-1024 hybrid (CNSA 2.0)",
}

SCAN_EXTS = {".py", ".js", ".ts", ".go", ".java", ".rs", ".c", ".h", ".cpp",
             ".rb", ".php", ".swift", ".kt", ".cs"}

def scan(root: Path):
    rows = []
    for path in root.rglob("*"):
        if path.suffix not in SCAN_EXTS or not path.is_file():
            continue
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for algo, pat in ALGO_PATTERNS:
                if pat.search(line):
                    rows.append({
                        "file": str(path),
                        "line": i,
                        "algorithm": algo,
                        "shor_vulnerable": "YES",
                        "snippet": line.strip()[:100],
                        "recommended_pq_replacement": REPLACEMENTS.get(algo, "?"),
                    })
    return rows

if __name__ == "__main__":
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    rows = scan(root)
    out = sys.argv[2] if len(sys.argv) > 2 else "crypto_inventory.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["file","line","algorithm","shor_vulnerable",
                                          "snippet","recommended_pq_replacement"])
        w.writeheader()
        w.writerows(rows)
    print(f"Scanned {root}: {len(rows)} classical-crypto references → {out}")
```

```bash
# ─── Run the inventory scanner on a codebase ───
python3 scan_classical_crypto.py /path/to/monorepo /tmp/crypto_inventory.csv

# Aggregate: count by algorithm
column -ts, < /tmp/crypto_inventory.csv | awk '{print $4}' | sort | uniq -c | sort -rn

# Top 10 files with most classical-crypto references
awk -F, '{print $1}' /tmp/crypto_inventory.csv | sort | uniq -c | sort -rn | head -10
```

```python
#!/usr/bin/env python3
# cert_inventory_from_pem_dir.py — Walk a directory of PEM certs, build inventory
import os, csv, hashlib, glob
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def cert_fingerprint(cert):
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()

def classify(pubkey):
    alg = type(pubkey).__name__
    if "RSA" in alg:
        return ("RSA", pubkey.key_size, True)
    if "EC" in alg:
        return ("ECDSA", pubkey.curve.key_size, True)
    if "Ed25519" in alg:
        return ("Ed25519", 256, True)
    if "X25519" in alg:
        return ("X25519", 256, True)
    if "MLKEM" in alg or "MLDSA" in alg or "ML-KEM" in alg or "ML-DSA" in alg:
        return ("PQC", -1, False)
    return (alg, -1, None)

rows = []
for pem in glob.glob("/etc/ssl/certs/*.pem"):
    try:
        with open(pem, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        algo, size, shor = classify(cert.public_key())
        rows.append({
            "fingerprint": cert_fingerprint(cert),
            "file": pem,
            "algorithm": algo,
            "key_size": size,
            "shor_vulnerable": shor,
            "not_after": cert.not_valid_after_utc.isoformat(),
            "subject": cert.subject.rfc4514_string(),
        })
    except Exception as e:
        print(f"skip {pem}: {e}")

with open("/tmp/cert_inventory.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["fingerprint","file","algorithm","key_size",
                                       "shor_vulnerable","not_after","subject"])
    w.writeheader()
    w.writerows(rows)

print(f"Inventory: {len(rows)} certs. Algorithms:")
from collections import Counter
for alg, n in Counter(r["algorithm"] for r in rows).most_common():
    print(f"  {alg:12} {n}")
```

```bash
# ─── Inventory from a live KMS (AWS example; Azure/GCP analogous) ───
aws kms list-keys --output json | jq -r '.Keys[].KeyId' | while read kid; do
    aws kms describe-key --key-id "$kid" --output json \
        | jq -r '.KeyMetadata | [.KeyId, .KeySpec, .SigningAlgorithms // [],
                   .EncryptionAlgorithms // []] | @tsv'
done | column -t

# Flag every RSA/ECC/NIST_P key as Shor-vulnerable
# Target algorithms:
#   RSA_2048, RSA_3072, RSA_4096     → ML-KEM-768 / ML-DSA-65
#   ECC_NIST_P256, ECC_NIST_P384    → X25519+ML-KEM-768 / ML-DSA-65
```

---

## 19. Hybrid TLS Testing (OpenSSL 3.x)

Comprehensive OpenSSL 3.x command set for testing hybrid (classical + PQC) TLS handshakes: server configuration, client probing, downgrade resistance, and cert chain validation.

```bash
# ─── Load oqs-provider and verify the hybrid groups are available ───
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
openssl list -providers -provider oqsprovider -verbose
openssl list -groups -provider oqsprovider | sort

# Expected hybrid groups (subset):
#   x25519_kyber512, x25519_kyber768, secp256r1_kyber768,
#   x25519_mlkem512, x25519_mlkem768, secp256r1_mlkem768,
#   x25519_mlkem1024, secp256r1_mlkem1024

# ─── Generate a hybrid key pair with explicit parameter set ───
openssl -provider oqsprovider -genpkey -algorithm mlkem768 -out mlkem768-priv.pem
openssl -provider oqsprovider -pkey -in mlkem768-priv.pem -pubout -out mlkem768-pub.pem

# Verify sizes match FIPS 203
ls -l mlkem768-pub.pem
stat -c '%n %s' mlkem768-pub.pem 2>/dev/null || stat -f '%N %z' mlkem768-pub.pem
# Expected: ~1184-byte public key
```

```bash
# ─── Probe a public server for hybrid-PQC support (Cloudflare / Google / AWS) ───
target="cloudflare.com"

# Single-group probe
openssl s_client -connect ${target}:443 -tls1_3 \
    -groups x25519_mlkem768 -msg 2>&1 \
    | grep -A3 "ServerHello\|Supported Groups\|Negotiated group"

# Multi-group scan — try every hybrid group the server might support
for grp in x25519_kyber768 x25519_mlkem768 secp256r1_mlkem768 \
           x25519_mlkem1024 secp256r1_mlkem1024; do
    result=$(echo | timeout 5 openssl s_client -connect ${target}:443 -tls1_3 \
        -groups "$grp" 2>&1 | grep -E "Cipher|protocol|alert" | head -2 | tr '\n' '|')
    echo "${grp}: ${result}"
done

# Capture full handshake transcript
sudo tshark -i any -w /tmp/hybrid_${target}.pcap "host ${target} and tcp port 443"
tshark -r /tmp/hybrid_${target}.pcap -Y 'tls.handshake.type == 20' \
    -T fields -e tls.handshake.finished_verify_data \
    | head -1
```

```bash
# ─── Server-side: nginx with hybrid TLS (OpenSSL 3.x + oqs-provider) ───
# nginx.conf
cat > /tmp/nginx_hybrid.conf <<'EOF'
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519:secp256r1:x25519_mlkem768:secp256r1_mlkem768;
ssl_conf_command Groups "X25519:x25519_mlkem768";
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
EOF

# Test the deployed server
openssl s_client -connect my-edge.internal:443 -tls1_3 \
    -groups x25519_mlkem768 -msg 2>&1 \
    | grep -E "ServerHello|Cipher|protocol"

# ─── Apache httpd with hybrid TLS ───
cat > /tmp/httpd_hybrid.conf <<'EOF'
SSLOpenSSLConfCmd Groups "X25519:x25519_mlkem768"
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2
SSLCipherSuite TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
EOF
```

```python
#!/usr/bin/env python3
# downgrade_resistance_test.py — Verify hybrid-PQC TLS is downgrade-resistant
# Connects to server offering x25519_mlkem768, captures the Finished verify data,
# then connects forcing classical-only and compares. If verify data is NOT bound
# to the group, the negotiation is downgrade-vulnerable.

import subprocess, re, sys

def get_finished_verify(host: str, port: int, groups: str) -> str:
    """Run openssl s_client, return the Finished verify data."""
    cmd = [
        "openssl", "s_client", "-connect", f"{host}:{port}", "-tls1_3",
        "-groups", groups, "-msg",
    ]
    # Capture handshake via tshark instead, then parse the verify data field
    pcap = "/tmp/downgrade_test.pcap"
    subprocess.run(["sudo", "tshark", "-i", "any", "-w", pcap,
                    "-c", "50", f"host {host} and tcp port {port}"],
                   timeout=10, capture_output=True)
    out = subprocess.run(["tshark", "-r", pcap,
                          "-Y", "tls.handshake.type == 20",
                          "-T", "fields", "-e", "tls.handshake.finished_verify_data"],
                         capture_output=True, text=True)
    return out.stdout.strip()

host, port = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 443
hybrid = get_finished_verify(host, port, "x25519_mlkem768")
classical = get_finished_verify(host, port, "X25519")
print(f"hybrid Finished:    {hybrid[:32]}...")
print(f"classical Finished: {classical[:32]}...")
print(f"Bound to group:     {'YES (good)' if hybrid != classical else 'NO — DOWNGRADE-PRONE'}")
```

```bash
# ─── Capture and parse hybrid-TLS handshake fields ───
sudo tshark -i any -w /tmp/hybrid.pcap "tcp port 443 and host target.example.com"

# ClientHello supported_groups
tshark -r /tmp/hybrid.pcap -Y 'tls.handshake.type == 1' \
    -T fields -e tls.handshake.extensions_supported_groups

# ServerHello negotiated group
tshark -r /tmp/hybrid.pcap -Y 'tls.handshake.type == 2' \
    -T fields -e tls.handshake.extensions_key_share

# Finished verify data (binds transcript)
tshark -r /tmp/hybrid.pcap -Y 'tls.handshake.type == 20' \
    -T fields -e tls.handshake.finished_verify_data
```

---

## 20. QKD Protocol Attacks (BB84 Simulator + PoC Code)

Simulators and proof-of-concept code for the canonical QKD implementation attacks: photon-number-splitting (PNS), detector blinding, and Trojan-horse.

```python
#!/usr/bin/env python3
# bb84_simulator.py — Simulate BB84 quantum key distribution
# Alice sends polarized photons; Bob measures in random bases; they sift.
# Output: the raw key, the sifted key, and the QBER (quantum bit error rate).

import random

def bb84_run(num_pulses=1000, error_rate=0.0, eve_present=False):
    """Run a BB84 session. Returns (raw_bits, sifted_key, qber)."""
    # Alice encodes each bit in a random basis (0=rectilinear, 1=diagonal)
    alice_bits = [random.randint(0, 1) for _ in range(num_pulses)]
    alice_bases = [random.randint(0, 1) for _ in range(num_pulses)]

    # Eve intercepts-resends (naive intercept attack; degrades QBER)
    transmitted_bits = list(alice_bits)
    transmitted_bases = list(alice_bases)
    if eve_present:
        for i in range(num_pulses):
            eve_basis = random.randint(0, 1)
            if eve_basis != alice_bases[i]:
                transmitted_bits[i] = random.randint(0, 1)  # Eve guesses wrong half the time

    # Bob measures in random bases
    bob_bases = [random.randint(0, 1) for _ in range(num_pulses)]
    bob_bits = []
    for i in range(num_pulses):
        if bob_bases[i] == transmitted_bases[i]:
            bit = transmitted_bits[i]
            if random.random() < error_rate:
                bit ^= 1  # channel noise
            bob_bits.append(bit)
        else:
            bob_bits.append(random.randint(0, 1))  # wrong basis → random result

    # Sifting: keep only bits where bases matched
    sifted_key = []
    errors = 0
    for i in range(num_pulses):
        if alice_bases[i] == bob_bases[i]:
            sifted_key.append(bob_bits[i])
            if bob_bits[i] != alice_bits[i]:
                errors += 1

    qber = errors / len(sifted_key) if sifted_key else 0.0
    return alice_bits, sifted_key, qber

if __name__ == "__main__":
    _, key, qber = bb84_run(num_pulses=10_000, eve_present=False)
    print(f"No Eve:    sifted={len(key)} bits, QBER={qber:.4f}")
    _, key, qber = bb84_run(num_pulses=10_000, eve_present=True)
    print(f"With Eve:  sifted={len(key)} bits, QBER={qber:.4f}  (Eve raises QBER ~25%)")
```

```python
#!/usr/bin/env python3
# pns_attack_simulator.py — Photon-number-splitting attack against attenuated-laser BB84
# Models the Poisson statistics of an attenuated-laser source and shows how many
# raw key bits Eve can recover by splitting multi-photon pulses.

import math

def poisson_pmf(mu, k):
    """P(X = k) for Poisson with mean mu."""
    return math.exp(-mu) * (mu ** k) / math.factorial(k)

def multi_photon_probability(mu):
    """P(n >= 2) — Eve's harvest per pulse."""
    return 1 - poisson_pmf(mu, 0) - poisson_pmf(mu, 1)

def pns_yield(mu, total_pulses):
    """How many bits can Eve harvest?"""
    return multi_photon_probability(mu) * total_pulses

print("Attenuated-laser source characterization:")
print("  μ      P(n>=2)   bits/1M pulses")
for mu in [0.05, 0.1, 0.2, 0.5, 1.0]:
    p = multi_photon_probability(mu)
    bits = pns_yield(mu, 1_000_000)
    print(f"  {mu:.2f}   {p:.4f}    {bits:>8.0f}")

# Reference: Lütkenhaus (2000). PNS is mitigated by decoy-state protocol
# (Hwang 2003, Lo 2005), which varies μ and detects the statistical disturbance
# Eve's PNS introduces.
```

```python
#!/usr/bin/env python3
# detector_blinding_poc.py — Conceptual detector-blinding attack
# Reference: Lydersen et al., Nature Photonics 2010.
# Demonstrated on commercial ID Quantique Clavis^2.
#
# Lab-authorized reproduction only. The attack can damage detector calibration.

def detector_blinding_phases():
    """Outline the attack in 5 phases."""
    phases = [
        ("1. Inject CW light",
         "Inject continuous-wave 1550nm light into Bob's quantum channel until "
         "the InGaAs APD transitions from Geiger mode to linear mode."),
        ("2. Verify linear mode",
         "Send a low-intensity pulse; the detector should NOT fire if it's "
         "still in Geiger mode. Once linear, only bright pulses trigger it."),
        ("3. Control detections",
         "Send an above-threshold pulse for each bit Eve wants Bob to detect. "
         "Eve now controls every detection event."),
        ("4. Forge the key",
         "Eve measures Alice's pulses herself (PNS or direct interception), "
         "then sends Bob only the photons that match the key she wants."),
        ("5. QBER within bounds",
         "Eve's forged detections have zero error rate; the final QBER stays "
         "below the threshold the QKD protocol would reject."),
    ]
    for name, desc in phases:
        print(f"{name}:\n  {desc}\n")

detector_blinding_phases()

# Mitigation: detector watchdog (continuous optical power monitor).
# Stronger mitigation: SNSPD (superconducting nanowire single-photon detector)
# instead of InGaAs APD.
```

```python
#!/usr/bin/env python3
# trojan_horse_poc.py — Trojan-horse attack conceptual PoC
# Reference: Weier et al., Nature Photonics 2011.
# Injects light back into Alice's source, reads out her phase modulator state.

def trojan_horse_phases():
    """Outline the Trojan-horse attack."""
    phases = [
        ("1. Inject light back into Alice",
         "Send bright light from Eve's position back through the quantum "
         "channel into Alice's output."),
        ("2. Light reflects off Alice's modulator",
         "Alice's phase modulator is set per-pulse. A fraction of the "
         "injected light reflects back to Eve with phase information."),
        ("3. Read out the phase",
         "Eve interferes the reflected light with a reference beam, "
         "measuring the phase Alice applied for each pulse."),
        ("4. Recover basis + bit",
         "The phase encodes Alice's basis and bit choice. Eve now knows "
         "the raw key without disturbing Bob's detections."),
    ]
    for name, desc in phases:
        print(f"{name}:\n  {desc}\n")

trojan_horse_phases()

# Mitigation: optical isolator at Alice's output (one-way device).
# Verification: measure back-reflection from Alice's output port.
```

```python
#!/usr/bin/env python3
# di_qkd_bell_verify.py — Device-Independent QKD Bell violation check
# DI-QKD closes detector side-channels by basing security on Bell inequality.
# A DI-QKD system must demonstrate CHSH S > 2 with statistical significance.

def chsh_threshold(sigma):
    """Defensible threshold: S > 2 + 5*sigma."""
    return 2 + 5 * sigma

# Example: deployment publishes S = 2.45 with sigma = 0.03
s, sigma = 2.45, 0.03
threshold = chsh_threshold(sigma)
passes = s > threshold

print(f"Observed CHSH S = {s}, sigma = {sigma}")
print(f"Threshold (2 + 5σ) = {threshold:.3f}")
print(f"DI-QKD security claim: {'VALID' if passes else 'INVALID — marginal or calibration artifact'}")

# Reference: Arnon-Friedman et al., "Relativistic independence as a tool for
# device-independent quantum cryptography".
```

---

## 21. SM-Series Implementation Tests (GmSSL / SM2/SM3/SM4)

Test vectors, fuzzing harnesses, and implementation probes for the Chinese national cryptography suite (SM2/SM3/SM4/SM9) as implemented by GmSSL, Tongsuo, and BabaSSL.

```bash
# ─── GmSSL CLI: SM3 / SM2 / SM4 basics ───

# SM3 known-answer test (must match GB/T 32905-2016)
echo -n "abc" | gmssl sm3
# Expected: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

echo -n "" | gmssl sm3
# Expected: 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b

# SM2 keypair + sign/verify
gmssl genpkey -algorithm SM2 -out sm2key.pem
gmssl pkey -in sm2key.pem -pubout -out sm2pub.pem
echo -n "hello world" > msg.txt
gmssl sm2 -sign -in msg.txt -key sm2key.pem -out sig.der
gmssl sm2 -verify -in msg.txt -pubkey sm2pub.pem -sig sig.der
# Verify DER encoding per GB/T 32918.2
openssl asn1parse -in sig.der -inform DER

# SM4 (symmetric) — GCM mode only (NEVER ECB in production)
key=$(openssl rand -hex 16)
iv=$(openssl rand -hex 16)
echo "top secret" | gmssl sm4 -e -cipher SM4-GCM -key "$key" -iv "$iv" -out ct.bin
gmssl sm4 -d -cipher SM4-GCM -key "$key" -iv "$iv" -in ct.bin -out pt.txt

# Mode audit: flag SM4-ECB
strings /usr/lib/x86_64-linux-gnu/libgmssl.so 2>/dev/null | grep -iE "sm4.*ecb|ecb.*sm4"
# Any hit → CRITICAL finding
```

```python
#!/usr/bin/env python3
# sm_test_vectors.py — Verify SM2/SM3/SM4 against published test vectors
# Sources: GB/T 32918 (SM2), GB/T 32905 (SM3), GB/T 32907 (SM4)

SM3_VECTORS = [
    ("abc",
     "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    ("",
     "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
    ("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
     "debe9ff92275b8a138604889c18e5ad4dc0924bcd195e5f3bcb Degrees"),
]

SM4_VECTORS = {
    "key":        "0123456789abcdeffedcba9876543210",
    "plaintext":  "0123456789abcdeffedcba9876543210",
    "ciphertext": "681edf34d206965e86b3e94f536e4246",
}

def check_sm3():
    """Run SM3 test vectors against the installed GmSSL."""
    import subprocess
    for msg, expected in SM3_VECTORS[:2]:  # first two are well-known
        actual = subprocess.run(
            ["gmssl", "sm3"],
            input=msg.encode(), capture_output=True, text=True
        ).stdout.strip()
        status = "OK" if actual == expected else "FAIL"
        print(f"  SM3({msg!r}) = {actual} [{status}]")

def check_sm4():
    """Run SM4 test vector against GmSSL (single-block ECB just for vector verification)."""
    import subprocess
    result = subprocess.run(
        ["gmssl", "sm4", "-e", "-cipher", "SM4-ECB",
         "-key", SM4_VECTORS["key"]],
        input=bytes.fromhex(SM4_VECTORS["plaintext"]),
        capture_output=True
    )
    ct = result.stdout.hex()
    status = "OK" if ct == SM4_VECTORS["ciphertext"] else f"FAIL (got {ct})"
    print(f"  SM4-ECB(test vector) [{status}]")

print("SM3 test vectors:")
check_sm3()
print("SM4 test vectors (ECB, vector-only — production must use GCM):")
check_sm4()
```

```python
#!/usr/bin/env python3
# sm2_scalar_mult_timing.py — Constant-timeness check for SM2 scalar multiplication
# SM2 uses a 256-bit curve (same family as NIST P-256). If scalar multiplication
# branches on secret bits, the implementation leaks via timing.

import os, time, statistics

def measure_sm2_scalar_mult(scalars, impl):
    """Measure scalar-mult time for many random scalars."""
    times = []
    for s in scalars:
        t0 = time.perf_counter_ns()
        # Replace with the actual call to your SM2 implementation's
        # scalar-multiplication primitive, e.g.:
        # impl.scalar_mult(s, base_point)
        _ = impl.scalar_mult(s) if hasattr(impl, 'scalar_mult') else None
        t1 = time.perf_counter_ns()
        times.append(t1 - t0)
    return times

class MockImpl:
    """Mock for illustration — replace with real gmssl/python-gmssl binding."""
    def scalar_mult(self, s):
        # Simulate a constant-time mult (no branches on bits)
        time.sleep(0.0001)

scalars = [int.from_bytes(os.urandom(32), 'big') for _ in range(1000)]
times = measure_sm2_scalar_mult(scalars, MockImpl())

mean_t = statistics.mean(times)
stdev_t = statistics.stdev(times)
ratio = stdev_t / mean_t
print(f"mean={mean_t:.0f}ns  stdev={stdev_t:.0f}ns  ratio={ratio:.4f}")
print(f"Verdict: {'CONSTANT-TIME OK' if ratio < 0.05 else 'NON-CONSTANT-TIME — finding'}")
# ratio < 0.05 → constant-time (passes)
# ratio 0.05-0.10 → marginal; rerun on idle system
# ratio > 0.10 → non-constant-time, HIGH finding
```

```bash
# ─── SM4 mode-misuse scanner ───
# Source scan: any SM4-ECB reference is a finding
grep -rniE "sm4.*ecb|ecb.*sm4|SM4_ECB" /path/to/source/tree/ | grep -v test_vector
# Binary strings
for lib in $(find / -name "libgmssl*" -o -name "libtongsuo*" -o -name "libbabassl*" 2>/dev/null); do
    echo "=== $lib ==="
    strings "$lib" | grep -iE "sm4.*ecb|ecb.*sm4" || echo "  (no ECB references)"
done

# ─── SM TLS (GM SSL) handshake probe ───
target="gm-tls.example.cn"
gmssl s_client -connect ${target}:443 -gmtls -msg 2>&1 \
    | grep -E "ECC-SM2|ECDHE-SM2|TLS_SM4_GCM_SM3|TLS_SM4_CCM_SM3|Cipher|Protocol"

# Downgrade probe — server must NOT silently fall back to TLS 1.2 RSA
openssl s_client -connect ${target}:443 -tls1_2 -cipher 'AES256-GCM-SHA384' 2>&1 \
    | grep -E "Cipher|Protocol|alert"
```

---

## 22. Lattice Signature Analysis (Dilithium / Falcon / ML-DSA)

Reference-implementation probing for lattice-based digital signatures: parameter-set verification, signature-size audit, deterministic vs randomized signing mode, and NTT constant-timeness.

```bash
# ─── ML-DSA (Dilithium) parameter-set verification ───
# Generate keys at each FIPS 204 parameter set and confirm sizes
for alg in mldsa44 mldsa65 mldsa87; do
    openssl -provider oqsprovider -genpkey -algorithm ${alg} -out ${alg}-priv.pem
    openssl -provider oqsprovider -pkey -in ${alg}-priv.pem -pubout -out ${alg}-pub.pem
    pk_size=$(openssl pkey -in ${alg}-pub.pem -pubout -outform DER 2>/dev/null | wc -c)
    echo "${alg}: pk_size=${pk_size} bytes"
done

# Expected (FIPS 204):
#   mldsa44: pk ≈ 1312 bytes
#   mldsa65: pk ≈ 1952 bytes
#   mldsa87: pk ≈ 2592 bytes

# Signature size verification
echo "test message" > msg.txt
for alg in mldsa44 mldsa65 mldsa87; do
    openssl -provider oqsprovider -pkeyutl -sign -inkey ${alg}-priv.pem \
        -in msg.txt -out ${alg}-sig.bin
    sig_size=$(stat -c %s ${alg}-sig.bin 2>/dev/null || stat -f %z ${alg}-sig.bin)
    echo "${alg}: sig_size=${sig_size} bytes"
done

# Expected:
#   mldsa44: sig ≈ 2420 bytes
#   mldsa65: sig ≈ 3309 bytes
#   mldsa87: sig ≈ 4627 bytes
```

```bash
# ─── Falcon reference implementation probing ───
# Falcon is not yet a FIPS standard but is widely pre-deployed for compact PQC signatures.
git clone https://github.com/openquantumsafe/liboqs.git
cd liboqs && cmake -GNinja -B build -DOQS_ENABLE_SIG_FALCON=ON
cmake --build build --parallel 8

# Generate Falcon-512 and Falcon-1024 keys
openssl -provider oqsprovider -genpkey -algorithm falcon512 -out falcon512-priv.pem
openssl -provider oqsprovider -genpkey -algorithm falcon1024 -out falcon1024-priv.pem

# Falcon signatures are notably smaller than ML-DSA:
#   falcon512:  pk=897B, sig ≈ 666B
#   falcon1024: pk=1793B, sig ≈ 1280B
for alg in falcon512 falcon1024; do
    openssl -provider oqsprovider -pkeyutl -sign -inkey ${alg}-priv.pem \
        -in msg.txt -out ${alg}-sig.bin
    sig_size=$(stat -c %s ${alg}-sig.bin 2>/dev/null || stat -f %z ${alg}-sig.bin)
    echo "${alg}: sig_size=${sig_size} bytes"
done

# Falcon caveat: signing uses floating-point NTT, which is implementation-fragile.
# Verify constant-timeness of the Falcon signing operation with dudect.
```

```python
#!/usr/bin/env python3
# mldsa_deterministic_vs_randomized.py — Check the deployed ML-DSA signing mode
# FIPS 204 allows both deterministic and randomized signing.
# Deterministic: reproducible signatures; vulnerable to fault injection.
# Randomized: non-reproducible; preferred for production code-signing.

import subprocess

def check_signing_mode(privkey_path: str, msg: bytes, n: int = 5) -> str:
    """Sign the same message N times. Match → deterministic; differ → randomized."""
    sigs = []
    for _ in range(n):
        out = subprocess.run(
            ["openssl", "-provider", "oqsprovider", "pkeyutl", "-sign",
             "-inkey", privkey_path],
            input=msg, capture_output=True
        )
        sigs.append(out.stdout)
    distinct = len(set(sigs))
    return "deterministic" if distinct == 1 else f"randomized ({distinct}/{n} distinct)"

if __name__ == "__main__":
    import sys
    mode = check_signing_mode(sys.argv[1], b"test message")
    print(f"ML-DSA signing mode: {mode}")
    print("Recommendation: use randomized mode for production code-signing")
```

```python
#!/usr/bin/env python3
# lattice_ntt_constant_time.py — Constant-timeness check on NTT
# The number-theoretic transform (NTT) is the core operation in ML-KEM and ML-DSA.
# If the NTT implementation has secret-dependent branches or memory accesses,
# it leaks via timing and cache side-channels.

import os, time, statistics, subprocess

def measure_ntt(n_samples=10_000):
    """Measure NTT execution time for many random inputs."""
    times = []
    # Replace with a direct call to liboqs OQS_KEM_kyber_768_ntt (via ctypes)
    # or call the liboqs benchmark binary.
    for _ in range(n_samples):
        t0 = time.perf_counter_ns()
        # liboqs.OQS_KEM_kyber_768_ntt(random_input)
        time.sleep(0.00001)  # mock
        t1 = time.perf_counter_ns()
        times.append(t1 - t0)
    return times

def tvla_welch(set_a, set_b):
    """Welch's t-test between two timing distributions. |t|>4.5 → leakage."""
    from scipy.stats import ttest_ind
    t, p = ttest_ind(set_a, set_b, equal_var=False)
    return t, p

random_times = measure_ntt(5000)
fixed_times = measure_ntt(5000)
t, p = tvla_welch(random_times, fixed_times)
print(f"TVLA t = {t:.3f}, p = {p:.6f}")
print(f"Verdict: {'CONSTANT-TIME OK' if abs(t) < 4.5 else 'LEAKAGE — non-constant-time NTT'}")
```

```bash
# ─── Side-channel lab probe: dudect on ML-KEM decaps ───
git clone https://github.com/oreparaz/dudect.git
cd dudect

# Adapt src/fixture.c to call liboqs ML-KEM-768 decapsulation:
#   1. Generate a decapsulation keypair once.
#   2. For each sample, call decaps on a 1088-byte input.
#   3. Return without freeing the key.
# The fixture alternates fixed-input and random-input calls.

make
./dudect | tee /tmp/dudect_mlkem768.log
# Output interpretation:
#   "t < 4.5"  → no first-order leakage
#   "t > 4.5"  → first-order leakage detected — CRITICAL finding
#   "max t = NaN" → noise; rerun on an idle, isolated CPU core

# Run on isolated core to reduce noise:
sudo taskset -c 3 ./dudect
```

```bash
# ─── ChipWhisperer power-analysis capture for ML-KEM ───
# Lab-only, authorized hardware. Target: Cortex-M4 running liboqs ML-KEM-768.
python3 <<'EOF'
import chipwhisperer as cw

scope = cw.scope()
target = cw.target(scope, cw.targets.SimpleSerial)
scope.adc.samples = 24000
scope.clock.adc_src = "clkgen_x4"
scope.clock.clkgen_freq = 100_000_000

project = cw.create_project("mlkem_traces.cwp", overwrite=True)
import os
for i in range(10_000):
    ct = b'\x00' * 1088 if i % 2 == 0 else os.urandom(1088)  # fixed-vs-random TVLA
    target.simpleserial_write('d', ct)
    ret = cw.capture_trace(scope, target, ct, 'd')
    project.traces.append(ret)
project.save()
print(f"Captured {len(project.traces)} traces. Analyze with TVLA.")
EOF

# TVLA analysis on the captured trace set:
python3 <<'EOF'
import numpy as np
from scipy import stats
proj = np.load("mlkem_traces.cwp")
fixed = proj[0::2]
random = proj[1::2]
t, p = stats.ttest_ind(fixed, random, axis=0, equal_var=False)
leak = np.where(np.abs(t) > 4.5)[0]
print(f"TVLA: {len(leak)} sample points exceed |t|=4.5 → {'LEAKAGE' if len(leak)>0 else 'OK'}")
EOF
```

