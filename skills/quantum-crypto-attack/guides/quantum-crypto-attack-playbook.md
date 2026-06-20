# Quantum-Crypto Attack Playbook — End-to-End Workflow Guide

> Deep-dive companion to `skills/quantum-crypto-attack/SKILL.md`.
>
> Audience: security engineers, PKI operators, and crypto auditors who know what RSA, AES, and TLS do, and want a battle-tested playbook for taking an organization from "we use classical crypto" to "we have a defensible post-quantum readiness posture" — without missing the long-lived key that becomes a catastrophic loss the day a CRQC is announced.

---

## 1. Why a Workflow, Not Just Commands

Running `openssl s_client -groups x25519_mlkem768` against a server takes 5 seconds. The trap is treating that one command as the assessment. A defensible post-quantum assessment requires:

1. **Inventory completeness** — have you found every long-lived RSA/ECC key, including SSH host keys, code-signing certs, internal CA roots, HSM masters, and KMS keys?
2. **SNDL exposure modelling** — for each long-term-confidential data flow, is the data already exposed to store-now-decrypt-later collection?
3. **PQC correctness** — for systems already deploying ML-KEM/ML-DSA, are parameter sets, signing modes, and side-channel postures correct?
4. **National-crypto compliance** — for SM-suite deployments (mandatory in PRC), are SM2/SM3/SM4 implementations sound and GB/T 38636-2020 compliant?
5. **QKD posture** — for QKD deployments, are the implementation attacks (PNS, detector blinding, Trojan-horse) mitigated?
6. **Crypto agility** — can the org actually disable an algorithm in 24 hours when the next break is announced?

This guide walks through all six, in order, with the exact commands and decision points.

---

## 2. Pre-Flight: Scope & Authorization

Before any analysis, answer these — in writing:

- **What's in scope?** Domains, IP ranges, internal PKI, KMS/HSM, code-signing infrastructure, QKD hardware, blockchain PQ contracts. Out-of-scope items (e.g., third-party SaaS) should be listed explicitly.
- **What's the regulatory frame?** Is the org subject to NIST/CNSA 2.0 (US federal/national security), GB/T 38636 (PRC), ETSI (EU), or industry-specific crypto mandates (PCI DSS, HIPAA)? Each sets different timelines and requirements.
- **What's the data sensitivity distribution?** The post-quantum risk profile is dominated by *data lifetime*, not algorithm strength. A 1-year TLS leaf cert on a low-sensitivity API is a low PQ priority; a 25-year root CA signing high-sensitivity data is a P0 priority.
- **What's the deployment state?** Pure classical (assessment focuses on inventory + roadmap)? Hybrid-PQC in pilot (focus on downgrade + parameter audit)? Pure-PQC in production (focus on side-channel + fault)?
- **What's the deliverable?** Internal readiness report? Regulatory compliance filing? Board-level briefing? Each has different framing and severity rubrics.
- **What's the timeline?** A 2-week triage produces a different artifact than a 6-month program assessment.

If any of these are unclear, stop and resolve before proceeding.

### Legal / ethical checkpoints

- **PRC Cryptography Law (2020)** — testing SM-suite deployments in mainland China requires local counsel review. The law mandates SM crypto in government/finance/critical infrastructure; uncoordinated testing can trigger regulatory action.
- **HSM access** — lab-based side-channel work on production HSMs can degrade their certification. Never run power-analysis or fault-injection on a production HSM without explicit written authorization from the HSM owner.
- **QKD hardware** — commercial QKD boxes are safety-class equipment in some jurisdictions. Detector-blinding and Trojan-horse testing must be done on dedicated test units, not production links.
- **SNDL data** — captured ciphertext destined for future decryption should not be stored beyond the engagement window. SNDL exposure is a *planning finding*, not a captured artifact to retain.

---

## 3. Phase 1 — Quantum Exposure Inventory

The inventory is the foundation. Every later phase references it. Get it wrong, and the entire roadmap is built on a gap.

### 3.1 External inventory (Certificate Transparency)

```bash
# Pull every cert ever issued for owned domains from CT logs
domain="example.com"
curl -s "https://crt.sh/?q=%25.${domain}&output=json" | jq -r '.[].id' > certids.txt
wc -l certids.txt  # may be tens of thousands for large orgs

# Fetch and classify each cert
while read id; do
    der=$(curl -s "https://crt.sh/?d=${id}")
    algo=$(echo "$der" | openssl x509 -noout -text 2>/dev/null \
        | grep -oE "Public Key Algorithm: \w+|\(2048 bit\)|\(4096 bit\)|\(256 bit\)" \
        | tr '\n' ' ')
    echo "${id} ${algo}"
done < certids.txt > cert_inventory.txt

# Aggregate: which algorithms are in use?
awk '{print $2, $3, $4}' cert_inventory.txt | sort | uniq -c | sort -rn
```

### 3.2 Internal inventory (PKI, KMS, HSM)

The external CT scan catches certs that are publicly visible. Internal PKI (private CAs issuing internal-only certs) is invisible to CT and requires direct query.

```bash
# FreeIPA / Dogtag CA
ipa ca-find --all | grep -E "Subject|Not After"
ipa cert-find --all --sensitive | jq -r '.result[].serial_number'

# Active Directory Certificate Services
certutil -view  # requires Windows admin

# HashiCorp Vault PKI
vault list pki/certs

# AWS KMS
aws kms list-keys | jq -r '.Keys[].KeyId' | while read kid; do
    aws kms describe-key --key-id "$kid" \
        | jq -r '.KeyMetadata | [.KeyId, .KeySpec, .SigningAlgorithms, .EncryptionAlgorithms] | @tsv'
done

# HSM (Thales / Entrust / Utimaco — vendor-specific)
# Pattern: export a key-attestation report listing every key with algorithm + size.
```

### 3.3 SSH and code-signing inventory

```bash
# SSH host keys (Shor-vulnerable: RSA, ECDSA; NOT Shor-vulnerable: none in common use today)
for h in $(cat hosts.txt); do
    ssh-keyscan -t rsa,ecdsa,ed25519 "$h" 2>/dev/null | awk '{print $2, $3, $4}' | head -1
done | sort | uniq -c

# Code-signing certs (macOS notarization, Windows Authenticode, Java jarsigner, GPG)
# macOS
security find-identity -v -p codesigning
# Windows
Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
# Java
jarsigner -verify -verbose -certs myapp.jar
# GPG
gpg --list-secret-keys --with-colons | grep '^sec'
```

### 3.4 Inventory output schema

```
fingerprint, algorithm, key_size_bits, issuer, not_before, not_after,
asset_owner, data_sensitivity(1-5), remaining_confidentiality_lifetime_yrs,
shor_vulnerable(bool)
```

Coverage target: >95% of all issued certs in the estate. Any gap is itself a finding (you cannot migrate what you cannot inventory).

---

## 4. Phase 2 — Shor / Grover Impact Modelling

For each inventoried asset, classify its post-quantum fate.

### 4.1 Shor-vulnerable algorithms (all become forgeable under CRQC)

- RSA (any practical size)
- DSA
- ECDSA (any curve)
- EdDSA (Ed25519, Ed448)
- Diffie-Hellman (any group)
- ECDH (any curve)

### 4.2 Symmetric primitives under Grover

| Primitive | Post-quantum strength | Verdict |
|-----------|----------------------|---------|
| AES-128 | ~64 bits | Upgrade to AES-256 for long-term data |
| AES-256 | ~128 bits | Recommended |
| ChaCha20 | ~128 bits | Recommended |
| SM4 | ~64 bits | Upgrade (SM4 with 256-bit extension or AES-256) |
| SHA-256 (preimage) | ~128 bits | OK |
| SHA-1 | broken classically | Replace regardless of PQ |
| SM3 | ~128 bits | OK |

### 4.3 Post-quantum-safe algorithms (by design)

- ML-KEM (FIPS 203, Kyber)
- ML-DSA (FIPS 204, Dilithium)
- SLH-DSA (FIPS 205, SPHINCS+)
- XMSS (RFC 8391, stateful)
- LMS (RFC 8554, stateful)
- Classic McEliece (code-based)
- HQC, BIKE (code-based, Round 4 candidates)

### 4.4 SNDL window computation

For each (asset, data-flow) pair:

```
sndl_window = CRQC_year - current_year - data_confidentiality_lifetime_yrs
```

If `sndl_window < 0`, the data is already exposed regardless of when migration happens. If `sndl_window > 0`, the org has that many years to migrate before the data falls.

Use CRQC estimates from multiple sources (NSA CNSA 2.0, NIST, ETSI) and report a range, not a point estimate. Central estimate 2033, optimistic 2030, conservative 2038.

---

## 5. Phase 3 — PQC Configuration Audit

For systems already deploying PQC, verify the deployment is correct.

### 5.1 Hybrid TLS negotiation

```bash
# Load oqs-provider
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
openssl list -providers -provider oqsprovider -verbose

# Enumerate offered groups
openssl list -groups -provider oqsprovider

# Negotiate a specific hybrid group against the target
openssl s_client -connect target:443 -tls1_3 \
    -groups x25519_mlkem768 -msg 2>&1 | \
    grep -A3 "ServerHello\|server_key_exchange"

# Verify the negotiated group is the hybrid (not silently downgraded)
# Look for the ML-KEM public key in the ServerKeyExchange / KeyShare extension
```

### 5.2 Downgrade-resistance test

```bash
# Capture the full handshake
tshark -i eth0 -w hybrid.pcap 'tcp port 443 and host target'

# Extract the Finished verify data
tshark -r hybrid.pcap -Y 'tls.handshake.type == 20' \
    -T fields -e tls.handshake.finished_verify_data

# Lab MITM test: configure mitmproxy to strip the hybrid extension
# The handshake MUST FAIL — the Finished message binds the group selection.
# If it succeeds under downgrade, that's a CRITICAL finding.
```

### 5.3 Parameter-set audit

```bash
# Generate keys at each parameter set and verify sizes
for alg in mlkem512 mlkem768 mlkem1024; do
    openssl -provider oqsprovider -genpkey -algorithm $alg -out ${alg}.pem
    size=$(openssl pkey -in ${alg}.pem -pubout -outform DER 2>/dev/null | wc -c)
    echo "${alg}: pubkey_der_size=${size}"
done

# Expected sizes per FIPS 203:
#   mlkem512:  pk ≈ 800 bytes
#   mlkem768:  pk ≈ 1184 bytes
#   mlkem1024: pk ≈ 1568 bytes
```

Production policy: ML-KEM-768 (NIST Level 3) minimum. ML-KEM-512 is for constrained devices only and must be documented.

### 5.4 Side-channel audit (lab only)

For deployments on hardware (HSM, secure element):

```bash
# Timing side-channel via dudect
git clone https://github.com/oreparaz/dudect.git
# Adapt fixture to call liboqs OQS_KEM_kyber_768_decaps
# Compile, run, examine the t-test output
# p < 0.0001 → first-order leakage → CRITICAL finding

# Power side-channel via ChipWhisperer (Husky or Lite)
# Target: liboqs ML-KEM-768 decapsulation on a Cortex-M4
# Capture 10,000 traces, run CPA or TVLA
# TVLA failure at order 1 → finding
```

---

## 6. Phase 4 — National Cryptography (SM Suite) Testing

### 6.1 SM2 / SM3 / SM4 implementation correctness

```bash
# SM3 test vector (must produce the known hash)
echo -n "abc" | gmssl sm3
# Expected: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

# SM2 sign / verify
gmssl genpkey -algorithm SM2 -out sm2key.pem
gmssl pkey -in sm2key.pem -pubout -out sm2pub.pem
echo -n "message" | gmssl sm2 -sign -key sm2key.pem -out sig.der
gmssl sm2 -verify -in msg.txt -pubkey sm2pub.pem -sig sig.der

# SM4 mode check — GCM or CTR is OK; ECB is a finding
echo "secret" | gmssl sm4 -e -cipher SM4-GCM -key $KEY -iv $IV -out ct.bin
# If the vendor exposes sm4-ecb, flag immediately
```

### 6.2 SM2 scalar-multiplication constant-timeness

```python
# Adapt sm2_scalar_mult_timing.py from payloads.md §9
# Variance ratio (std/mean) > 0.10 → non-constant-time → HIGH finding
```

### 6.3 GM SSL (GB/T 38636-2020) handshake

```bash
# Negotiate RFC 8998 cipher suite
gmssl s_client -connect target:443 -gmtls -msg 2>&1 | \
    grep -E "TLS_SM4_GCM_SM3|TLS_SM4_CCM_SM3|ECC-SM2"

# Downgrade test — does the server also accept RSA-only TLS 1.2?
openssl s_client -connect target:443 -tls1_2 -cipher 'AES256-GCM-SHA384'
# If yes, MITM can downgrade. CRITICAL.
```

### 6.4 Compliance checklist (GB/T 38636-2020 / GB/T 32918/32905/32907)

- [ ] TLS 1.3 with TLS_SM4_GCM_SM3 or TLS_SM4_CCM_SM3 negotiated
- [ ] Server cert SM2-signed
- [ ] ECDHE-SM2 key exchange
- [ ] No silent fallback to TLS 1.2 RSA
- [ ] CRL/OCSP SM2-signed
- [ ] SM4 in GCM or CTR mode (never ECB)
- [ ] SM2 scalar-multiplication constant-time
- [ ] SM3 not used as naive MAC (use HMAC-SM3)

---

## 7. Phase 5 — QKD / Protocol Attacks

### 7.1 Source characterization

```bash
# Identify source type via vendor CLI
ssh admin@qkd-box
qkd> show protocol
  Protocol:               BB84
  Decoy-state:            ENABLED     # ← must be ENABLED
  Mean photon number:     signal μ=0.5, decoy μ=0.1
  Source type:            attenuated laser
```

If source is attenuated laser AND decoy-state is DISABLED, PNS attack is feasible. CRITICAL.

### 7.2 Detector type and watchdog

```bash
qkd> show hardware
  Detector:               InGaAs APD
  Detector watchdog:      ENABLED     # ← must be ENABLED
  Optical isolator:       PRESENT     # ← Trojan-horse countermeasure
```

InGaAs APD without watchdog → detector blinding attack feasible. HIGH finding.

### 7.3 DI-QKD verification

For deployments claiming DI-QKD:

```python
# Verify the Bell inequality violation (CHSH > 2) is statistically significant
# Reference: Arnon-Friedman et al. "Relativistic independence..."
# A statistically marginal CHSH value can be a calibration artifact.
```

### 7.4 Lab reproduction (authorized only)

Lydersen-style detector blinding is reproducible on commercial QKD test units. Only attempt with explicit authorization; the attack can damage detector calibration.

---

## 8. Phase 6 — Migration Roadmap & Reporting

### 8.1 Priority computation

```python
# See payloads.md §13 for the full implementation
def priority_score(item):
    sndl_exposed = (item["life"] + 2026) > CRQC_YEAR
    return (
        item["sens"] * 10 +
        (30 if sndl_exposed else 0) +
        (20 if item["life"] > 10 else 0)
    )
```

### 8.2 Migration windows

- **P0 (6 months)**: root CAs, code-signing, HSM masters, long-term-confidential archives that are SNDL-exposed
- **P1 (12 months)**: code-signing for medium-lifetime data, internal CA intermediates, KMS master keys
- **P2 (18 months)**: TLS leaf certs (short-lived, low sensitivity), JWT signing keys
- **P3 (24 months)**: low-sensitivity internal services

### 8.3 Target algorithms by asset class

| Asset class | Current | Target | Hybrid overlap |
|-------------|---------|--------|----------------|
| Root CA | RSA-4096 | SLH-DSA-256s (hash-agile) + RSA hybrid | 5 years |
| Code-signing | RSA-4096 | ML-DSA-65 + RSA hybrid | 3 years |
| TLS leaf | ECDSA-256 | X25519+ML-KEM-768 hybrid | indefinite hybrid |
| JWT signing | RS256 | ML-DSA-65 | 2 years |
| Long-term archive | RSA-wrapped AES | ML-KEM-wrapped AES-256 | n/a |
| HSM master | RSA-4096 | SLH-DSA-256s | 5 years |

### 8.4 Crypto-agility drill

Run TC-QC-010 quarterly. Track the time-to-disable-metric. A grade target: <1h. The drill exposes the gap between "we have agility in theory" and "we have agility in practice."

### 8.5 Post-quantum readiness score

```python
# See payloads.md §14
def score(inventory, hybrid_tls, agility_drill, national_crypto, qkd):
    return sum([inventory, hybrid_tls, agility_drill, national_crypto, qkd])
    # Each dimension 0-20, total 0-100
```

A defensible readiness posture is ≥75 (Grade B). Below 60 (Grade C) means a real CRQC announcement would cause significant disruption.

### 8.6 Report template

See payloads.md §16. Key sections:

1. Executive summary with readiness score
2. Quantum exposure inventory table
3. PQC configuration findings (per-asset)
4. National crypto findings (where applicable)
5. Crypto-agility drill results
6. Prioritized migration roadmap
7. Standards references (NIST FIPS 203/204/205, SP 800-227, CNSA 2.0, GB/T 38636, RFC 8998)

---

## 9. Common Pitfalls & Anti-Patterns

### 9.1 "We enabled Kyber, we're post-quantum ready"

Hybrid-PQC TLS is one part of a posture. Long-lived root CAs, code-signing, HSM masters, SNDL-exposed data flows, and crypto-agility are all independently necessary. "We did the easy part" is not readiness.

### 9.2 Treating QKD as "provably secure"

BB84's security proof assumes single photons, ideal detectors, no side-channels. Real hardware violates all three. A QKD deployment without decoy-state + DI-QKD is implementation-attack-vulnerable regardless of the mathematical proof.

### 9.3 Picking ML-KEM-512 for bandwidth

The 256-byte saving per handshake is not worth halving the security level. Production uses ML-KEM-768 minimum.

### 9.4 Forgetting SNDL on captured data

Migrating TLS to hybrid PQC in 2027 does not protect traffic captured in 2022. SNDL exposure must be assessed as-of-collection-time. For data with >10-year confidentiality lifetime crossing classical public-key encryption today, the data is already lost if the adversary has a CRQC in 10 years.

### 9.5 Skipping the crypto-agility drill

Most orgs claim agility and never test it. The first time agility matters is the day a break is announced. Without drilling, the org discovers hardcoded algorithm references, cert reissuance bottlenecks, and missing central registries when the break is already public.

### 9.6 National crypto as "more secure" or "less secure"

SM2/SM3/SM4 are algorithms, subject to the same implementation discipline as NIST primitives. Neither inherently stronger nor weaker. Implementation discipline, parameter selection, and side-channel posture matter — not the national origin.

### 9.7 Downgrade-resistance assumed

A server offering both hybrid-PQC and classical can be downgraded by an active MITM unless the Finished message binds the negotiation. This is the post-quantum POODLE. Always test.

---

## 10. Tooling Decision Matrix

| Need | First-choice tool | Alternative |
|------|-------------------|-------------|
| PQC keygen / sign / verify | openssl + oqs-provider | liboqs directly; cloudflare/circl (Go) |
| Hybrid TLS probing | openssl s_client -groups | oqs-test; cloudflare/circl test harness |
| SM2/SM3/SM4 testing | GmSSL | Tongsuo; BabaSSL |
| GM SSL handshake | gmssl s_client -gmtls | tongsuo s_client -enable_ntls |
| ROCA detection | RsaCtfTool --attack roca | python implementation |
| Quantum simulation (edu) | Qiskit | Cirq (Google) |
| Constant-timeness | dudect | valgrind --tool=memcheck (coarse) |
| Power side-channel | ChipWhisperer | Riscure Inspector |
| QKD vendor CLI | vendor-provided | n/a |
| Blockchain PQ-sig audit | slither (on hashsigs-solidity) | mythril |
| XMSS/LMS reference | cisco/hash-sigs | python-xmss |

---

## 11. Integration with Adjacent Skills

### 11.1 crypto-attacks (classical sibling)

The quantum exposure inventory in §3 starts from the classical key inventory. ROCA detection (TC-QC-012) extends RsaCtfTool usage that originates in crypto-attacks. Any classical padding-oracle or hash-length-extension finding implies the affected key is Shor-vulnerable in addition to its classical flaw.

### 11.2 vpn-attack (TLS at network layer)

Hybrid-PQC TLS analysis extends vpn-attack's TLS handshake probing into the post-quantum era. A vpn-attack finding (weak DH group) becomes a quantum-crypto finding (the same group is Shor-vulnerable) when the assessment scope expands to PQ.

### 11.3 blockchain-web3

Blockchains adopting PQ signatures (QRL, hashsigs-solidity) land here. Classical blockchain crypto (secp256k1, Ed25519) stays in crypto-attacks. The crossover case is a bridge using PQ signatures for validator consensus — audit the contract in blockchain-web3 skills, audit the PQ sig implementation here.

### 11.4 web-xss / web-auth-bypass

When an XSS exfiltrates a long-lived RSA private key (CA root, code-signing, JWT signing) from the browser, the *quantum-crypto* finding is the SNDL exposure of data signed by that key, even though the *vector* was XSS. Both findings belong in the report.

### 11.5 security-misconfiguration

Crypto-agility misconfiguration (inability to switch algorithms, hardcoded algorithm references, missing central registry) is a specialized cryptographic misconfiguration with longer-term consequences. It overlaps with security-misconfiguration but the PQ context amplifies severity.

### 11.6 digital-forensics / anti-forensics

SNDL data captured today becomes forensically relevant when a CRQC arrives. The window between collection time and break time is the SNDL exposure window. Forensic teams should preserve high-value ciphertext artifacts with this future-decryptability in mind.

---

## 12. Pre-Assessment Checklist

Before kicking off a post-quantum assessment engagement:

- [ ] Scope confirmed in writing (domains, IP ranges, PKI, KMS/HSM, QKD, blockchain)
- [ ] Regulatory frame identified (NIST / CNSA 2.0 / GB / ETSI / industry)
- [ ] Data sensitivity classification available
- [ ] CT log access working (crt.sh or internal)
- [ ] Internal PKI query access (FreeIPA / AD CS / Vault / vendor CA)
- [ ] KMS/HSM attestation access (AWS / Azure / GCP / on-prem HSM)
- [ ] SSH access to hosts for ssh-keyscan
- [ ] GmSSL + Tongsuo + oqs-provider installed on assessment workstation
- [ ] For lab side-channel: ChipWhisperer + target hardware authorized
- [ ] For QKD: vendor CLI access + authorization for source/detector characterization
- [ ] For blockchain: contract addresses + RPC endpoints + slither installed
- [ ] Report template (payloads.md §16) reviewed with sponsor
- [ ] Crypto-agility drill window scheduled (if included)
- [ ] PRC Cryptography Law review (if testing SM-suite in mainland China)
- [ ] HSM testing authorization (if any lab work on production HSM)

---

## 13. References & Further Reading

- **NIST PQC Standardization**: https://csrc.nist.gov/projects/post-quantum-cryptography
- **NIST FIPS 203 (ML-KEM)**: https://csrc.nist.gov/pubs/fips/203/final
- **NIST FIPS 204 (ML-DSA)**: https://csrc.nist.gov/pubs/fips/204/final
- **NIST FIPS 205 (SLH-DSA)**: https://csrc.nist.gov/pubs/fips/205/final
- **NIST SP 800-227**: https://csrc.nist.gov/pubs/sp/800/227/ipd
- **CNSA 2.0 (NSA)**: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_ALGORITHMS_.PDF
- **ETSI Quantum-Safe**: https://www.etsi.org/technologies/quantum-safe-cybersecurity
- **Open Quantum Safe (liboqs)**: https://github.com/open-quantum-safe/liboqs
- **oqs-provider**: https://github.com/open-quantum-safe/oqs-provider
- **cloudflare/circl**: https://github.com/cloudflare/circl
- **GmSSL**: https://github.com/guanzhi/GmSSL
- **Tongsuo (BabaSSL)**: https://github.com/Tongsuo-Project/Tongsuo
- **RFC 8998 (TLS 1.3 SM)**: https://www.rfc-editor.org/rfc/rfc8998
- **RFC 8391 (XMSS)**: https://www.rfc-editor.org/rfc/rfc8391
- **RFC 8554 (LMS)**: https://www.rfc-editor.org/rfc/rfc8554
- **QuipNetwork/hashsigs-solidity**: https://github.com/QuipNetwork/hashsigs-solidity
- **QuipNetwork/hashsigs-rs**: https://github.com/QuipNetwork/hashsigs-rs
- **Gidney & Ekera 2019**: https://doi.org/10.22331/q-2021-04-15-433
- **Lydersen et al. 2010 (QKD blinding)**: https://doi.org/10.1038/nphoton.2010.123
- **Weier et al. 2011 (QKD Trojan-horse)**: https://doi.org/10.1038/nphoton.2011.199
- **ROCA (CVE-2017-15361)**: https://crocs.fi.muni.cz/public/papers/rsa_ccs17
- **Dragonblood (WPA3)**: https://wpa3.mathyvanhoef.com/
- **Espitau et al. (Dilithium fault)**: https://eprint.iacr.org/2017/1023
- **GB/T 38636-2020 (GM SSL)**, **GB/T 32918 (SM2)**, **GB/T 32905 (SM3)**, **GB/T 32907 (SM4)**: Chinese national standards
