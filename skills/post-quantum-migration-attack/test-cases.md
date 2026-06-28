# Post-Quantum Migration Attack — Test Cases

> Structured test case templates for validating PQC migration attack coverage. **Objective**: produce reproducible evidence of HNDL risk, downgrade vulnerability, KEM combiner flaw, and PQ implementation weakness across TLS / SSH / IPsec / X.509 / Signal / QKD surface.

## Conventions

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Prerequisites**: Required access, tooling, certs
- **Objective**: Per-case attack goal
- **Reference**: Pointer to `payloads.md` section

---

## A. Discovery & Inventory

### TC-PQ-001 — TLS PQC Cipher Discovery

**Severity**: LOW
**Prerequisites**: Network access to target TLS service
**Objective**: Identify whether target supports hybrid or PQ-only TLS

**Test Steps**:
1. `testssl --wide https://target.example.com | grep -iE "kyber|dilithium|pqc"`
2. `echo | openssl s_client -connect target:443 -groups "x25519kyber768draft00:x25519mlkem768" -tls1_3`
3. Note negotiated group in "Server Temp Key"
4. Repeat for PQ-only group `kyber768`

**Expected Results**:
- Hybrid PQC: "Server Temp Key: X25519Kyber768"
- PQ-only: "Server Temp Key: Kyber768"
- Classical only: "Server Temp Key: X25519" or "P-256"

**Remediation**:
- Deploy oqs-provider with X25519Kyber768 hybrid

**Pass Criteria**: Documented PQ posture
**Reference**: payloads.md §1.1

---

### TC-PQ-002 — SSH PQC Kex Discovery

**Severity**: LOW
**Prerequisites**: Network access to SSH service
**Objective**: Identify whether SSH offers PQ kex

**Test Steps**:
1. `ssh-audit target.example.com | grep -iE "sntrup|pq|post-quantum"`
2. `ssh -vv target.example.com 2>&1 | grep "kex: algorithm:"`
3. Verify sntrup761x25519-sha64 is offered
4. Note negotiated kex

**Expected Results**:
- PQ SSH: sntrup761x25519-sha64 negotiated
- Classical SSH: curve25519-sha256 negotiated

**Remediation**:
- Add `KexAlgorithms sntrup761x25519-sha64@openssh.com` to sshd_config

**Pass Criteria**: Documented PQ SSH posture
**Reference**: payloads.md §1.2

---

### TC-PQ-003 — IPsec PQC Proposal Audit

**Severity**: LOW
**Prerequisites**: Access to StrongSwan/libreswan config
**Objective**: Identify whether IPsec uses PQ ke

**Test Steps**:
1. `ipsec statusall | grep -iE "ike=|esp="`
2. `ipsec listalgs | grep -iE "ke=|dh="`
3. Identify if PQ proposals are listed

**Expected Results**:
- PQ IPsec: `ike=aes256gcm16-prfsha256-ke-kyber768`
- Classical: `ike=aes256gcm16-prfsha256-ke-modp2048`

**Remediation**:
- Add PQ proposals to `swanctl.conf`

**Pass Criteria**: Documented PQ IPsec posture
**Reference**: payloads.md §1.3

---

## B. HNDL / SNDL Capture

### TC-PQ-004 — Long-term Ciphertext Capture

**Severity**: HIGH
**Prerequisites**: Network tap position, persistent storage
**Objective**: Capture ciphertext for retrospective decryption post-CRQC

**Test Steps**:
1. `tcpdump -i eth0 -w hndl.pcap 'tcp port 443'`
2. Wait 24 hours (capture window)
3. Verify capture contains TLS handshakes
4. Identify which sessions have keylog (forward-secret) vs not

**Expected Results**:
- HNDL capture contains RSA key exchange (forward-secret failure)
- HNDL capture contains static RSA ciphertext blobs
- Classical ECDH captured: vulnerable to Shor's algorithm post-CRQC

**Remediation**:
- Deploy hybrid PQC for all long-lived data
- Use short-lived certs (<90 days)
- Eliminate static RSA key exchange

**Pass Criteria**: HNDL capture documented
**Reference**: payloads.md §2.1

---

### TC-PQ-005 — Data HNDL Risk Tiering

**Severity**: MEDIUM
**Prerequisites**: Access to data store classification
**Objective**: Classify data by HNDL risk

**Test Steps**:
1. Inventory RSA/ECC-encrypted data stores
2. Tag each by data class (genome, PII, state secret, financial)
3. Cross-reference with HNDL_TIERS dict
4. Output: Critical/High/Medium/Low breakdown

**Expected Results**:
- Critical (must migrate now): state secrets, genome
- High (migrate <1 year): PII, PHI, key material
- Medium (migrate <3 years): financial records

**Remediation**:
- Migrate Critical tier immediately
- Migrate High tier by 2027
- Migrate Medium tier by 2030

**Pass Criteria**: Risk tier report produced
**Reference**: payloads.md §2.2

---

### TC-PQ-006 — Vault/KMS Ciphertext Capture

**Severity**: HIGH
**Prerequisites**: API access to KMS, ability to log
**Objective**: Capture KMS ciphertext for retrospective decryption

**Test Steps**:
1. `aws kms encrypt --key-id alias/hndl --plaintext "TEST" --output text > captured.blob`
2. Capture in API logs: ciphertext-blob field
3. Identify which keys wrap long-lived secrets
4. Document key ID and algorithm

**Expected Results**:
- AWS KMS uses RSA-4096 (HNDL vulnerable)
- HashiCorp Vault transit uses AES-256-GCM (NOT HNDL vulnerable, but key wrap is RSA)
- Azure Key Vault supports RSA + ECC (HNDL vulnerable)

**Remediation**:
- Use KMS with hybrid PQC envelope encryption
- Rotate master keys annually

**Pass Criteria**: KMS posture documented
**Reference**: payloads.md §2.3

---

## C. Hybrid PQC Downgrade

### TC-PQ-007 — MITM Kyber Stripping

**Severity**: CRITICAL
**Prerequisites**: MITM position (ARP spoof, transparent proxy)
**Objective**: Force classical-only TLS by stripping Kyber from ClientHello

**Test Steps**:
1. Deploy mitmproxy with strip-kyber.py addon
2. Client connects to target (hybrid PQ support)
3. mitmproxy removes 0x07e4 (X25519Kyber768) from supported_groups
4. Observe negotiated group

**Expected Results**:
- Vulnerable: Server negotiates X25519 (classical only)
- Resistant: Server aborts handshake (no common group)
- Hybrid enforcement: Server config requires Kyber

**Remediation**:
- Server-side config: `require_pq_groups=true`
- Disable classical-only cipher suites
- Monitor CT for classical-only handshakes

**Pass Criteria**: Downgrade either succeeds (vuln) or fails (resistant)
**Reference**: payloads.md §3.1

---

### TC-PQ-008 — SSH Downgrade

**Severity**: HIGH
**Prerequisites**: Network MITM position
**Objective**: Force SSH classical kex

**Test Steps**:
1. `ssh -o KexAlgorithms=curve25519-sha256 -o PubkeyAcceptedAlgorithms=ssh-rsa user@target`
2. Observe negotiated kex
3. Test if server accepts classical-only

**Expected Results**:
- Vulnerable: SSH session established with curve25519 only
- Resistant: SSH aborts (no common kex)

**Remediation**:
- `KexAlgorithms sntrup761x25519-sha64@openssh.com,curve25519-sha256`
- `KexAlgorithms sntrup761x25519-sha64@openssh.com` (PQ-only)

**Pass Criteria**: Documented downgrade resistance
**Reference**: payloads.md §3.3

---

### TC-PQ-009 — IPsec IKEv2 Downgrade

**Severity**: HIGH
**Prerequisites**: Network MITM, IPsec gateway access
**Objective**: Force classical DH group

**Test Steps**:
1. Connect to IPsec gateway with classical ke only: `swanctl --initiate --ike target --ke modp2048`
2. Observe negotiated proposal
3. Test if PQ ke is enforced

**Expected Results**:
- Vulnerable: IKE SA established with modp2048 only
- Resistant: IKE SA requires kyber768 ke

**Remediation**:
- Configure `ke = kyber768+modp2048` (hybrid)
- Disable `ke = modp2048` (classical-only)

**Pass Criteria**: Documented PQ enforcement
**Reference**: payloads.md §3.4

---

## D. KEM Combiner Flaws

### TC-PQ-010 — XOR Combiner Detection

**Severity**: CRITICAL
**Prerequisites**: Source code access to TLS stack
**Objective**: Verify hybrid KEM uses HKDF (not XOR)

**Test Steps**:
1. Inspect oqs-provider combiner source
2. `grep -rn "XOR\|hkdf\|HKDF" oqs-provider/oqsprov/`
3. Identify combiner formula
4. Test: derive key with broken X25519 component

**Expected Results**:
- Safe: `combined = HKDF(x25519_ss || kyber_ss)`
- Unsafe: `combined = x25519_ss XOR kyber_ss`
- Custom: documented and reviewed

**Remediation**:
- Replace XOR with HKDF-SHA3-256
- Use NIST SP 800-56C rev 2 combiner

**Pass Criteria**: Combiner audit documented
**Reference**: payloads.md §4.1

---

### TC-PQ-011 — Component Compromise Simulation

**Severity**: HIGH
**Prerequisites**: Test environment with key generation access
**Objective**: Verify KEM holds when one component broken

**Test Steps**:
1. Generate hybrid KEM (X25519 + Kyber)
2. Break X25519 (zero secret)
3. Attempt decapsulation
4. Verify combined secret is still random

**Expected Results**:
- HKDF: combined secret is random (Kyber protects)
- XOR: combined secret = Kyber secret (broken)

**Remediation**:
- Use HKDF combiner

**Pass Criteria**: Component compromise test
**Reference**: payloads.md §4.3

---

## E. PQC Implementation Side-Channels

### TC-PQ-012 — Kyber Timing Analysis

**Severity**: HIGH
**Prerequisites**: liboqs access, timing instrumentation
**Objective**: Detect secret-dependent branches in Kyber

**Test Steps**:
1. Build liboqs with timing instrumentation
2. Run Kyber decaps with 10000 random ciphertexts
3. Measure timing per decapsulation
4. Compute variance / stddev

**Expected Results**:
- Safe: stddev < 1% of mean
- Vulnerable: stddev > 5% of mean (secret-dependent)

**Remediation**:
- Constant-time NTT (constant-time butterfly)
- Masked implementation
- Use verified constant-time library

**Pass Criteria**: Timing analysis report
**Reference**: payloads.md §5.1

---

### TC-PQ-013 — RowHammer Attack

**Severity**: CRITICAL
**Prerequisites**: Vulnerable DRAM, root access
**Objective**: Recover Kyber secret via RowHammer

**Test Steps**:
1. Identify adjacent rows to Kyber secret memory
2. Use DRAMoscope to hammer
3. Read bit flips in Kyber secret
4. Verify recovered secret matches

**Expected Results**:
- Vulnerable DRAM: bit flips occur, secret recovered
- ECC DRAM: no exploitable flips

**Remediation**:
- ECC DRAM
- Refresh frequency increase
- Constant-time + masked Kyber (reduces secret memory exposure)

**Pass Criteria**: RowHammer test report
**Reference**: payloads.md §5.2

---

### TC-PQ-014 — Dilithium Fault Injection

**Severity**: CRITICAL
**Prerequisites**: Hardware fault injection rig
**Objective**: Recover Dilithium signing key via fault

**Test Steps**:
1. Generate Dilithium signing key on chip
2. Sign multiple messages with EM fault injected
3. Compare faulty signatures with valid
4. Reconstruct secret key z from faulty outputs

**Expected Results**:
- Vulnerable: secret key recovered from ~10 faulty signatures
- Resistant: faulty signatures detected and rejected

**Remediation**:
- Fault-detecting Dilithium (BCounter, redundancy)
- Hardware fault detection
- Use SLH-DSA (no algebraic fault attacks)

**Pass Criteria**: Fault attack report
**Reference**: payloads.md §5.3

---

### TC-PQ-015 — Electromagnetic Side-Channel

**Severity**: HIGH
**Prerequisites**: ChipWhisperer or equivalent
**Objective**: Recover Kyber secret via EM emanation

**Test Steps**:
1. Capture 10000 EM traces during Kyber decaps
2. Align traces by NTT trigger
3. Correlation analysis: TVLA or CPA
4. Recover secret key bytes

**Expected Results**:
- Vulnerable: TVLA shows >4σ divergence
- Resistant: TVLA shows <2σ divergence

**Remediation**:
- Masked implementation (order-2+)
- Random delay insertion
- Hardware shuffle

**Pass Criteria**: EM side-channel report
**Reference**: payloads.md §5.4

---

## F. Certificate Chain Inconsistency

### TC-PQ-016 — Mixed PQ/Classical Chain Test

**Severity**: HIGH
**Prerequisites**: oqs-provider, OpenSSL 3.x
**Objective**: Verify cert validation rejects PQ+classical mix

**Test Steps**:
1. Generate ML-DSA root CA
2. Issue classical RSA leaf signed by PQ root
3. Attempt verification

**Expected Results**:
- Vulnerable: chain validates (cross-talk bug)
- Resistant: chain fails (algorithm mismatch)

**Remediation**:
- Strict algorithm validation in cert chain
- Reject mixed chains by default
- Use algorithm-locked chain

**Pass Criteria**: Chain algorithm test
**Reference**: payloads.md §6.2

---

### TC-PQ-017 — CT Log PQ Cert Audit

**Severity**: MEDIUM
**Prerequisites**: CT log API access
**Objective**: Detect unexpected PQ certificates in CT

**Test Steps**:
1. Query CT logs for ML-DSA signatures
2. Identify issuers
3. Cross-reference with known PQ CAs
4. Flag anomalies

**Expected Results**:
- Expected: no ML-DSA certs (most CAs haven't deployed)
- Anomaly: unexpected ML-DSA cert (potential supply chain attack)

**Remediation**:
- Monitor CT for unauthorized PQ CA activity
- Deploy CT log monitoring

**Pass Criteria**: CT audit report
**Reference**: payloads.md §6.4

---

## G. Signal PQXDH

### TC-PQ-018 — Prekey Bundle Signature Audit

**Severity**: HIGH
**Prerequisites**: Signal server API access
**Objective**: Verify PQ prekey signature in bundle

**Test Steps**:
1. Fetch prekey bundle from server
2. Verify `pqPreKeySignature` field present
3. Validate signature with identity key
4. Test: bundle without PQ signature

**Expected Results**:
- Safe: pqPreKeySignature present and valid
- Vulnerable: signature missing OR forgeable

**Remediation**:
- Enforce PQ signature on server
- Client: reject bundle without PQ sig

**Pass Criteria**: PQXDH signature audit
**Reference**: payloads.md §7.1

---

### TC-PQ-019 — PQ Prekey Stripping

**Severity**: HIGH
**Prerequisites**: MITM position, Signal client
**Objective**: Test if PQ prekey can be stripped during fetch

**Test Steps**:
1. MITM prekey fetch with Frida
2. Remove pqPreKey from bundle
3. Test if client proceeds (downgrade)
4. Test if server enforces PQXDH

**Expected Results**:
- Vulnerable: client falls back to X3DH (no PQ)
- Resistant: client aborts

**Remediation**:
- Server: require PQXDH for new sessions
- Client: enforce PQ layer

**Pass Criteria**: PQ stripping resistance
**Reference**: payloads.md §7.2

---

## H. QKD Infrastructure

### TC-PQ-020 — BB84 Detector Blinding

**Severity**: CRITICAL
**Prerequisites**: Physical fiber access, bright laser
**Objective**: Test QKD detector blinding attack

**Test Steps**:
1. Identify QKD receiver fiber
2. Inject bright (>1mW) light into fiber
3. Observe if detector enters linear mode
4. Test attacker-controlled detection

**Expected Results**:
- Vulnerable: detector blinded, attacker controls all bits
- Resistant: bright-light detection, link aborts

**Remediation**:
- Bright-light detection circuit
- Decoy-state modulation
- Hardware-attested detector

**Pass Criteria**: Detector blinding test report
**Reference**: payloads.md §8.1

---

### TC-PQ-021 — Photon Number Splitting

**Severity**: HIGH
**Prerequisites**: Beam splitter, fiber tap
**Objective**: Test PNS attack on weak coherent pulse BB84

**Test Steps**:
1. Identify WCP source on QKD link
2. Tap fiber with beam splitter
3. Capture multi-photon pulses
4. Verify attacker recovers bits

**Expected Results**:
- Vulnerable: PNS attack recovers bits
- Resistant: decoy-state modulation prevents PNS

**Remediation**:
- Decoy-state BB84
- True single-photon source

**Pass Criteria**: PNS test report
**Reference**: payloads.md §8.2

---

### TC-PQ-022 — Trusted Node Compromise

**Severity**: CRITICAL
**Prerequisites**: Trusted node shell access
**Objective**: Recover QKD keys from trusted node

**Test Steps**:
1. Identify trusted node in QKD relay (e.g., Beijing-Shanghai backbone)
2. Gain root on trusted node
3. Read raw keys in memory/disk
4. Verify keys decrypt end-to-end traffic

**Expected Results**:
- Vulnerable: raw keys in plaintext in trusted node
- Resistant: trusted node uses HSM-backed key wrapping

**Remediation**:
- HSM-backed trusted nodes
- Reduce trusted node count (satellite QKD)

**Pass Criteria**: Trusted node test report
**Reference**: payloads.md §8.3

---

## I. PQC Token / JWT

### TC-PQ-023 — JWT ML-DSA Algorithm Confusion

**Severity**: HIGH
**Prerequisites**: JWT library with PQ support
**Objective**: Test if library confuses ML-DSA with HS256

**Test Steps**:
1. Generate ML-DSA keypair
2. Sign JWT with ML-DSA-65
3. Verify token with library
4. Tamper header: alg=HS256, key=public key
5. Test if library accepts

**Expected Results**:
- Vulnerable: library accepts HS256 with public key as HMAC secret
- Resistant: library rejects alg confusion

**Remediation**:
- Use library with strict alg validation
- Pin algorithm per key

**Pass Criteria**: Algorithm confusion test
**Reference**: payloads.md §9.1

---

### TC-PQ-024 — COSE with PQ Algorithm

**Severity**: MEDIUM
**Prerequisites**: COSE library with PQ support
**Objective**: Verify COSE rejects PQ alg confusion

**Test Steps**:
1. Generate ML-DSA-65 key
2. Sign COSE message with kty=OKP alg=ML-DSA-65
3. Verify
4. Tamper: kty=EC, alg=ES256 (classical)
5. Test acceptance

**Expected Results**:
- Vulnerable: cross-algorithm acceptance
- Resistant: kty/alg binding enforced

**Remediation**:
- Strict kty/alg binding
- Algorithm allowlist

**Pass Criteria**: COSE test report
**Reference**: payloads.md §9.2

---

## J. Migration Agility

### TC-PQ-025 — Hot-swap Algorithm Test

**Severity**: MEDIUM
**Prerequisites**: Server with admin access
**Objective**: Verify crypto agility — algorithm swap without restart

**Test Steps**:
1. Connect client with X25519Kyber768
2. Update server config to X25519MLKEM768
3. Re-connect same client
4. Verify no service interruption

**Expected Results**:
- Agile: handover works, both algorithms served
- Rigid: requires restart, downtime

**Remediation**:
- Implement crypto agility framework
- Hot-reload config

**Pass Criteria**: Hot-swap test
**Reference**: payloads.md §10.1

---

### TC-PQ-026 — Algorithm Negotiation Race

**Severity**: MEDIUM
**Prerequisites**: Server with concurrent connections
**Objective**: Detect race condition in algorithm negotiation

**Test Steps**:
1. Open 10 concurrent TLS connections with different groups
2. Observe server state during transitions
3. Look for inconsistent negotiation

**Expected Results**:
- Vulnerable: mixed state, incorrect negotiation
- Resistant: deterministic per-connection

**Remediation**:
- Per-connection state machine
- Atomic algorithm negotiation

**Pass Criteria**: Race condition test
**Reference**: payloads.md §10.2

---

## K. Library Bugs & Compliance

### TC-PQ-027 — liboqs CVE Check

**Severity**: HIGH
**Prerequisites**: liboqs in production
**Objective**: Verify no known CVEs in liboqs version

**Test Steps**:
1. `pkg-config --modversion liboqs`
2. Cross-reference with CVE database
3. Test malformed input DoS

**Expected Results**:
- Compliant: version patched, no DoS
- Vulnerable: known CVEs, accepts malformed

**Remediation**:
- Patch to latest liboqs
- Fuzz testing in CI

**Pass Criteria**: CVE audit report
**Reference**: payloads.md §11.1

---

### TC-PQ-028 — CNSA 2.0 Compliance

**Severity**: MEDIUM
**Prerequisites**: Target is US National Security System
**Objective**: Verify CNSA 2.0 compliance

**Test Steps**:
1. Verify KEM uses ML-KEM-1024 (not ML-KEM-768)
2. Verify signature uses ML-DSA-87 (not ML-DSA-65)
3. Verify backup signature uses SLH-DSA-256s
4. Verify no RSA / ECC (post-migration)

**Expected Results**:
- Compliant: ML-KEM-1024, ML-DSA-87, SLH-DSA-256s
- Non-compliant: ML-KEM-768, RSA, ECC

**Remediation**:
- Upgrade to CNSA 2.0 algorithms
- Document exceptions

**Pass Criteria**: CNSA 2.0 compliance report
**Reference**: payloads.md §19

---

## L. Detection Engineering

### TC-PQ-029 — Downgrade Detection Rule

**Severity**: MEDIUM
**Prerequisites**: TLS logging in SIEM
**Objective**: Validate downgrade detection rule

**Test Steps**:
1. Deploy Sigma rule for hybrid PQC downgrade
2. Simulate downgrade (TC-PQ-007)
3. Verify SIEM alert fires
4. Test false positive rate

**Expected Results**:
- Detect: ClientHello has Kyber group, ServerHello has classical
- Alert: high confidence
- FP rate: <0.1%

**Remediation**:
- Deploy detection in production

**Pass Criteria**: Detection rule validated
**Reference**: payloads.md §12.1

---

### TC-PQ-030 — HNDL Capture Anomaly Detection

**Severity**: MEDIUM
**Prerequisites**: Network flow logging
**Objective**: Detect mass HNDL capture activity

**Test Steps**:
1. Deploy Splunk/KQL query for classical-only TLS
2. Identify IPs with sustained TLS handshakes
3. Flag for investigation

**Expected Results**:
- Anomaly: single src captures 1000+ classical TLS/day
- Alert: SOC investigation

**Remediation**:
- Alert on bulk classical TLS
- Mandatory hybrid PQC for new TLS

**Pass Criteria**: Anomaly detection validated
**Reference**: payloads.md §12.2

---

## M. Hardware Token / HSM

### TC-PQ-031 — HSM PQC Support Audit

**Severity**: MEDIUM
**Prerequisites**: HSM access (Thales, YubiHSM, AWS CloudHSM)
**Objective**: Verify HSM supports PQC algorithms

**Test Steps**:
1. `yubihsm-shell -a generate-asymmetric-key -A mlkem768`
2. Test Thales Luna: `lunacm -c partitionLogin` then `cmu generate -alg MLKEM768`
3. Test AWS CloudHSM via PKCS#11
4. Identify PQ algorithm support

**Expected Results**:
- Thales Luna 7.13.0+: supports ML-KEM, ML-DSA
- YubiHSM 2: no PQ support (as of 2025)
- AWS CloudHSM: no PQ support (as of 2025)
- FutureLogic NCipher nShield 5: supports ML-KEM, SLH-DSA

**Remediation**:
- Upgrade HSM firmware for PQ support
- Use HSM-backed hybrid

**Pass Criteria**: HSM PQ support documented
**Reference**: payloads.md §17

---

## N. PQC Migration Project

### TC-PQ-032 — Migration Timeline Validation

**Severity**: LOW
**Prerequisites**: Migration plan document
**Objective**: Verify migration timeline aligns with threat model

**Test Steps**:
1. Review migration plan
2. Cross-reference with BAAI Quantum Threat Timeline
3. Verify Critical tier migration by 2027
4. Verify High tier migration by 2030

**Expected Results**:
- Compliant: Critical by 2027, High by 2030
- Non-compliant: migration slips past CRQC

**Remediation**:
- Accelerate migration
- Allocate budget for HSM upgrade

**Pass Criteria**: Timeline validation report
**Reference**: payloads.md §18.2

---

## O. Cross-Protocol Variant

### TC-PQ-033 — Multi-protocol PQ Audit

**Severity**: MEDIUM
**Prerequisites**: Multiple services (TLS, SSH, IPsec, Signal)
**Objective**: Verify consistent PQ posture across protocols

**Test Steps**:
1. Audit TLS posture (TC-PQ-001)
2. Audit SSH posture (TC-PQ-002)
3. Audit IPsec posture (TC-PQ-003)
4. Audit Signal posture (TC-PQ-018)
5. Compare postures

**Expected Results**:
- Consistent: all protocols hybrid PQ
- Inconsistent: some classical (HNDL risk)

**Remediation**:
- Standardize PQ policy across all protocols

**Pass Criteria**: Cross-protocol audit
**Reference**: payloads.md §15

---

## References

- payloads.md — full payload list
- guides/post-quantum-migration-attack-playbook.md — operator playbook
- guides/real-world-incident-case-studies.md — historical incidents
