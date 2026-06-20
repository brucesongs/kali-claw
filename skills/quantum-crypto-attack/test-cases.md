# Quantum-Crypto Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> Many test cases are **forward-looking** (SNDL modelling, migration prioritization, crypto-agility drills) — they produce planning artifacts rather than immediate exploits. Others (SM4-ECB misuse, hybrid-TLS downgrade, ROCA detection) are exploitable today.
> All commands assume authorized access to target systems; PQC side-channel lab cases (TC-QC-011, TC-QC-007) require explicit hardware authorization.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Quantum Exposure & Inventory | 2 | HIGH - CRITICAL |
| B. PQC Configuration Audit | 3 | MEDIUM - CRITICAL |
| C. National Crypto (SM Suite) | 3 | MEDIUM - CRITICAL |
| D. QKD / Protocol Attacks | 1 | HIGH |
| E. Crypto Agility & Migration | 2 | HIGH |
| F. Classical Crossover (ROCA, blockchain-PQC) | 1 | MEDIUM |
| **Total** | **12** | **MEDIUM - CRITICAL** |

---

## A. Quantum Exposure & Inventory

### TC-QC-001: Shor-Vulnerable RSA/ECC Asset Inventory

| Field | Value |
|------|-----|
| **ID** | TC-QC-001 |
| **Name** | Shor-Vulnerable RSA/ECC Asset Inventory |
| **Severity** | HIGH |
| **Category** | Quantum Exposure & Inventory |
| **Objective** | Build a complete inventory of every long-lived asymmetric key in the estate, classified by Shor-vulnerability and remaining confidentiality lifetime, to prioritize post-quantum migration. |
| **Prerequisites** | Certificate Transparency log access (crt.sh or internal), ZMap+ZGrab2 for internal scanning, access to internal PKI/CA database, KMS/HSM key attestation. |
| **Tools** | openssl, zgrab2, jq, crt.sh API, ipa ca-find (or vendor CA CLI) |
| **Test Steps** | 1. Pull all certs from CT logs for owned domains: `curl -s 'https://crt.sh/?q=%25.example.com&output=json' \| jq -r '.[].id'`<br>2. For each cert, fetch and extract public-key algorithm: `openssl x509 -noout -text \| grep -E "Public Key Algorithm\|RSA\|ECDSA"`<br>3. Internal scan: `zmap -p 443` then `zgrab2 tls --tls1-3` to capture every TLS leaf cert<br>4. Query internal CA: `ipa ca-find --all` (or vendor equivalent) for issuing CAs and root<br>5. For each key, record: algorithm, key size, issuer, validity, asset owner, data sensitivity, remaining confidentiality lifetime<br>6. Flag every RSA/DSA/ECDSA/EdDSA/DH/ECDH key as Shor-vulnerable<br>7. Cross-reference against KMS/HSM attestation: `aws kms describe-key` / vendor CLI<br>8. Produce the inventory CSV consumed by TC-QC-002 |
| **Expected Results** | Complete CSV keyed by public-key fingerprint, with columns for algorithm, size, lifetime, sensitivity, Shor-vulnerable flag. Coverage >95% of issued certs; any CA-issued cert missing from the inventory is a finding. |
| **False Positive Risk** | LOW — algorithm classification is deterministic from the cert's SubjectPublicKeyInfo. |
| **Cleanup** | No cleanup; inventory is a planning artifact. |
| **References** | NIST SP 800-227; CNSA 2.0; payloads.md §2 |

### TC-QC-002: SNDL (Store-Now-Decrypt-Later) Risk Modelling

| Field | Value |
|------|-----|
| **ID** | TC-QC-002 |
| **Name** | SNDL Risk Modelling for Long-Term Confidential Data |
| **Severity** | CRITICAL |
| **Category** | Quantum Exposure & Inventory |
| **Objective** | Identify data flows where long-term-confidential data crosses classical public-key encryption, and quantify SNDL exposure against plausible CRQC timelines. |
| **Prerequisites** | TC-QC-001 inventory complete; data-sensitivity classification map; CRQC arrival estimates (NIST/NSA/ETSI). |
| **Tools** | tcpdump, tshark, python3 (see payloads.md §3 `shor_impact.py`), internal data-classification API |
| **Test Steps** | 1. For each asset in the TC-QC-001 inventory, identify the data flows it protects<br>2. Capture representative TLS sessions: `tcpdump -i eth0 -w sndl.pcap 'tcp port 443 and host <asset>'`<br>3. Identify negotiated cipher: `tshark -r sndl.pcap -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.ciphersuite`<br>4. Classify each flow: RSA key-exchange (no PFS, already SNDL-exposed without CRQC), ECDHE-RSA (session PFS but RSA cert becomes forgeable under Shor), X25519+ML-KEM hybrid (SNDL-safe unless BOTH fall)<br>5. Compute SNDL window per flow: `CRQC_year - 2026 - data_lifetime_years`; negative = already exposed<br>6. Prioritize by sensitivity × (negative window)<br>7. Produce SNDL exposure matrix |
| **Expected Results** | Each long-term-confidential data flow classified by SNDL risk; any flow with `window < 0` for high-sensitivity data is a CRITICAL finding requiring immediate migration to hybrid-PQC TLS. |
| **False Positive Risk** | MEDIUM — CRQC timeline estimates are inherently uncertain; central estimate (2033) may shift. Report ranges, not point estimates. |
| **Cleanup** | Delete captured pcap files after analysis (they may contain sensitive payload data). |
| **References** | NIST SP 800-227; payloads.md §2, §3 |

---

## B. PQC Configuration Audit

### TC-QC-003: Hybrid TLS Handshake Negotiation & Downgrade Resistance

| Field | Value |
|------|-----|
| **ID** | TC-QC-003 |
| **Name** | Hybrid TLS Handshake Negotiation & Downgrade Resistance |
| **Severity** | CRITICAL |
| **Category** | PQC Configuration Audit |
| **Objective** | Verify that a server advertising hybrid-PQC key exchange (e.g., `x25519_mlkem768`) actually negotiates the hybrid group and rejects MITM-forged downgrades to plain classical groups. |
| **Prerequisites** | OpenSSL 3.x with oqs-provider loaded; target server advertises hybrid groups in supported_groups. |
| **Tools** | openssl s_client, oqs-test, tshark, mitmproxy (lab downgrade test) |
| **Test Steps** | 1. `openssl list -providers -provider oqsprovider -verbose` — confirm oqs-provider loaded<br>2. Enumerate offered groups: `openssl list -groups -provider oqsprovider`<br>3. Negotiate each hybrid group: `openssl s_client -connect h:443 -tls1_3 -groups x25519_mlkem768 -msg` and inspect ServerHello<br>4. Confirm the negotiated group matches the requested hybrid (not silently downgraded to x25519)<br>5. Capture full handshake: `tshark -r hybrid.pcap -Y 'tls.handshake.type == 20' -T fields -e tls.handshake.finished_verify_data`<br>6. Lab downgrade test: configure mitmproxy to strip the hybrid extension; client should FAIL the handshake (Finished message binds the group). If handshake succeeds under downgrade, that is a CRITICAL finding. |
| **Expected Results** | Server negotiates hybrid group when offered; Finished message binds the group; downgrade to plain x25519 fails with handshake_failure alert. |
| **False Positive Risk** | LOW — handshake behavior is deterministic. |
| **Cleanup** | Restore any modified server config; remove lab mitmproxy setup. |
| **References** | draft-ietf-tls-hybrid-design; payloads.md §6 |

### TC-QC-004: ML-KEM / ML-DSA / SLH-DSA Parameter Set Audit

| Field | Value |
|------|-----|
| **ID** | TC-QC-004 |
| **Name** | ML-KEM / ML-DSA / SLH-DSA Parameter Set Audit |
| **Severity** | HIGH |
| **Category** | PQC Configuration Audit |
| **Objective** | Verify that a deployed PQC implementation uses parameter sets appropriate for the threat model, and that key/signature sizes match FIPS 203/204/205 specifications. |
| **Prerequisites** | Target PQC binary or service accessible; reference liboqs + oqs-provider installed for size comparison. |
| **Tools** | openssl (with oqs-provider), strings, stat/ls |
| **Test Steps** | 1. Inspect the vendor's PQC binary for compiled-in parameter sets: `strings /usr/lib/vendor/libpqc.so \| grep -iE "ML-KEM-\|KYBER\|ML-DSA-\|DILITHIUM\|SLH-DSA\|SPHINCS"`<br>2. Generate keys at each parameter set: `openssl -provider oqsprovider -genpkey -algorithm mlkem512\|mlkem768\|mlkem1024 -out ...`<br>3. Verify key sizes match FIPS 203: mlkem512 pk=800B, mlkem768 pk=1184B, mlkem1024 pk=1568B<br>4. Generate ML-DSA signatures at each level; verify sig sizes match FIPS 204: mldsa44≈2420B, mldsa65≈3309B, mldsa87≈4627B<br>5. Generate SLH-DSA signatures; confirm 7-50KB size range<br>6. Verify deterministic vs randomized signing mode: sign same message twice, compare<br>7. Flag any deployment using ML-KEM-512 for long-term data (should be ML-KEM-768 minimum) |
| **Expected Results** | All key/signature sizes match FIPS specs; production uses ML-KEM-768 (Level 3) or stronger; ML-DSA at minimum Level 2 for 128-bit-classical-parity; deterministic mode used only where intentional. |
| **False Positive Risk** | LOW — parameter sets are deterministic. |
| **Cleanup** | No cleanup; keygen is local. |
| **References** | FIPS 203, 204, 205; payloads.md §5 |

### TC-QC-005: Hash-Based Signature (XMSS/LMS/SLH-DSA) State-Management Audit

| Field | Value |
|------|-----|
| **ID** | TC-QC-005 |
| **Name** | Hash-Based Signature State-Management Audit |
| **Severity** | HIGH |
| **Category** | PQC Configuration Audit |
| **Objective** | Verify that stateful hash-based signature deployments (XMSS per RFC 8391, LMS per RFC 8554) enforce state monotonicity; that SLH-DSA deployments are stateless and correctly parameterized. |
| **Prerequisites** | Target HSM or signer daemon supporting XMSS/LMS; reference hash-sigs library installed. |
| **Tools** | xmss CLI (from cisco/hash-sigs), HSM admin console, audit log access |
| **Test Steps** | 1. Identify stateful hash-sig deployments: SSH signers, code-signing CAs, root CAs<br>2. For each XMSS signer, verify state counter: must be monotonic per key<br>3. Attempt to sign two messages with the same leaf index (in a test environment) — must fail with state-reuse error<br>4. Verify HSM-backed signers store the state in non-volatile memory with hardware-enforced monotonicity<br>5. For SLH-DSA deployments, confirm statelessness: sign same message from two signer instances — both must succeed without coordination<br>6. Verify XMSS parameter set: minimum XMSS-SHA2_10_256 for short-lived, XMSS-SHA2_16_256 or XMSSMT for long-lived<br>7. Review key archival: a backed-up XMSS private key with the same state can produce duplicate signatures → catastrophic forgery risk |
| **Expected Results** | Every XMSS/LMS signer enforces state monotonicity; no backups that could produce duplicate states; SLH-DSA deployments stateless; parameter sets appropriate. |
| **False Positive Risk** | LOW — state monotonicity is verifiable by direct test. |
| **Cleanup** | No cleanup (test signatures are harmless). |
| **References** | RFC 8391 (XMSS), RFC 8554 (LMS), FIPS 205 (SLH-DSA); payloads.md §1 |

---

## C. National Crypto (SM Suite)

### TC-QC-006: SM2/SM3/SM4 Implementation Audit (GmSSL / Tongsuo)

| Field | Value |
|------|-----|
| **ID** | TC-QC-006 |
| **Name** | SM2/SM3/SM4 Implementation Audit |
| **Severity** | HIGH |
| **Category** | National Crypto (SM Suite) |
| **Objective** | Audit a deployed Chinese national cryptography implementation (GmSSL, Tongsuo, BabaSSL, Tongji SSL) for correctness, side-channel resistance, and mode misuse. |
| **Prerequisites** | Target service uses SM2/SM3/SM4; GmSSL CLI installed; source access for the implementation under test. |
| **Tools** | gmssl, openssl, python3 (for SM2 scalar-mult timing), dudect |
| **Test Steps** | 1. Verify SM3 hash correctness: `echo -n "abc" \| gmssl sm3` must produce the known value `66c7f0f4...`<br>2. Generate SM2 keypair: `gmssl genpkey -algorithm SM2 -out sm2.pem`; sign and verify<br>3. SM4 mode audit: confirm SM4-GCM (or SM4-CTR) in use; SM4-ECB is a CRITICAL finding<br>4. SM2 scalar-multiplication constant-timeness: run `sm2_scalar_mult_timing.py` from payloads.md §9; variance ratio >0.10 is non-constant-time<br>5. SM3 length-extension: confirm SM3 is not used as a naive MAC (use HMAC-SM3 or SM3-KDF instead)<br>6. SM9 master-secret handling: verify master private key is HSM-backed, not in software<br>7. Strings audit: `strings libgmssl.so \| grep -iE "ECB\|CBC\|GCM\|CTR"` to identify compiled-in SM4 modes |
| **Expected Results** | SM3 produces known test vectors; SM4-GCM or SM4-CTR in use (never ECB); SM2 scalar multiplication constant-time (ratio <0.05); SM9 master in HSM; no SM3-as-MAC. |
| **False Positive Risk** | MEDIUM — scalar-multiplication timing variance can be noise-induced; run on idle system and average. |
| **Cleanup** | No cleanup. |
| **References** | GB/T 32918 (SM2), GB/T 32905 (SM3), GB/T 32907 (SM4); payloads.md §9 |

### TC-QC-007: GM SSL (GB/T 38636-2020) TLS Handshake Review

| Field | Value |
|------|-----|
| **ID** | TC-QC-007 |
| **Name** | GM SSL Handshake & Downgrade Review |
| **Severity** | CRITICAL |
| **Category** | National Crypto (SM Suite) |
| **Objective** | Verify that a GM SSL deployment (RFC 8998 cipher suites: TLS_SM4_GCM_SM3, TLS_SM4_CCM_SM3) negotiates correctly and is not silently downgraded to TLS 1.2 with RSA. |
| **Prerequisites** | GmSSL or Tongsuo client installed; target server deployed per GB/T 38636-2020. |
| **Tools** | gmssl s_client, tongsuo openssl, openssl s_client (for downgrade probe) |
| **Test Steps** | 1. Connect via GM TLS: `gmssl s_client -connect target:443 -gmtls -msg`<br>2. Confirm cipher `TLS_SM4_GCM_SM3` or `TLS_SM4_CCM_SM3` negotiated (not silently downgraded)<br>3. Confirm server certificate is SM2-signed (not RSA/ECDSA)<br>4. Confirm ECDHE-SM2 key exchange (not static SM2)<br>5. Downgrade test: `openssl s_client -connect target:443 -tls1_2 -cipher 'AES256-GCM-SHA384'` — should fail or warn<br>6. If server accepts RSA-only TLS 1.2 alongside GM, an active MITM can downgrade — CRITICAL<br>7. SM2 client cert auth: present an SM2 client cert; verify server accepts and validates<br>8. Interop test: GmSSL ↔ Tongsuo ↔ Tongji SSL handshakes (document any incompatibility) |
| **Expected Results** | Server negotiates TLS_SM4_GCM_SM3 over TLS 1.3; server cert is SM2-signed; no silent downgrade to TLS 1.2 RSA; interop across major SM TLS stacks works. |
| **False Positive Risk** | LOW — handshake behavior is deterministic. |
| **Cleanup** | No cleanup. |
| **References** | RFC 8998; GB/T 38636-2020; payloads.md §10 |

### TC-QC-008: SM4 Mode Misuse Detection (ECB / Fixed Key / Fixed IV)

| Field | Value |
|------|-----|
| **ID** | TC-QC-008 |
| **Name** | SM4 Mode Misuse Detection |
| **Severity** | HIGH |
| **Category** | National Crypto (SM Suite) |
| **Objective** | Detect SM4-ECB usage, fixed-key SM4, or fixed-IV SM4-CBC/CTR — the SM-suite equivalent of the classical ECB/padding-oracle family. |
| **Prerequisites** | Source access to applications calling SM4; or runtime access to inspect SM4 parameters. |
| **Tools** | grep, gmssl, code review |
| **Test Steps** | 1. Source scan: `grep -rn "SM4.*ECB\|sm4-ecb\|ECB.*SM4" src/` — any hit is a finding<br>2. Binary strings: `strings app.so \| grep -iE "sm4.*ecb\|ecb.*sm4"`<br>3. Fixed-key detection: look for SM4 key literals (`key = "..."`, `KEY=`) — keys must come from KMS/HSM<br>4. Fixed-IV detection: SM4-CBC/CTR with a constant IV is a finding<br>5. Behavioral test: encrypt two identical plaintext blocks; if ciphertext blocks are identical → ECB mode in use<br>6. Confirm SM4-GCM preferred; SM4-CTR acceptable with random IV; SM4-CBC acceptable with random IV + MAC |
| **Expected Results** | No SM4-ECB; SM4 keys from KMS/HSM; random IVs per encryption. |
| **False Positive Risk** | LOW — ECB detection is deterministic via the identical-block test. |
| **Cleanup** | No cleanup. |
| **References** | GB/T 32907 (SM4); payloads.md §9 |

---

## D. QKD / Protocol Attacks

### TC-QC-009: QKD BB84 Attack Surface Review (PNS / Detector Blinding / Trojan-Horse)

| Field | Value |
|------|-----|
| **ID** | TC-QC-009 |
| **Name** | QKD BB84 Attack Surface Review |
| **Severity** | HIGH |
| **Category** | QKD / Protocol Attacks |
| **Objective** | Evaluate a commercial QKD deployment (ID Quantique, Chinese QKD backbone) for susceptibility to photon-number-splitting, detector blinding, and Trojan-horse attacks; recommend countermeasures. |
| **Prerequisites** | Authorized physical access to QKD endpoints; documentation of source/detector hardware; vendor CLI access. |
| **Tools** | vendor CLI (qkd>), photon source characterization (lab), Lydersen-style attack rig (lab only) |
| **Test Steps** | 1. Identify source type: attenuated laser (multi-photon risk) vs true single-photon source<br>2. Compute multi-photon probability: `P(n>=2) = 1 - (1+μ)e^(-μ)` for mean photon number μ<br>3. Verify decoy-state protocol enabled: `qkd> show protocol` — must show `Decoy-state: ENABLED`<br>4. Identify detector type: InGaAs APD (blinding risk) vs SNSPD (lower risk)<br>5. Verify detector watchdog (optical power monitor) active<br>6. Check for optical isolator at Alice's output (Trojan-horse countermeasure)<br>7. Determine if deployment is DI-QKD (closes detector side-channels) or only BB84<br>8. For DI-QKD, verify published Bell violation (CHSH > 2) is statistically significant<br>9. Lab reproduction (authorized only): attempt Lydersen-style detector blinding on a test unit |
| **Expected Results** | Deployment uses decoy-state; detector watchdog active; optical isolator present; or deployment is DI-QKD with statistically significant Bell violation. |
| **False Positive Risk** | MEDIUM — lab reproduction results are vendor- and firmware-specific. |
| **Cleanup** | Restore QKD box to normal operation; document any detector recalibration performed. |
| **References** | Lydersen 2010; Weier 2011; payloads.md §8 |

---

## E. Crypto Agility & Migration

### TC-QC-010: Crypto-Agility "Drop-This-Algorithm" Drill

| Field | Value |
|------|-----|
| **ID** | TC-QC-010 |
| **Name** | Crypto-Agility 24-Hour Algorithm-Switch Drill |
| **Severity** | HIGH |
| **Category** | Crypto Agility & Migration |
| **Objective** | Verify that the organization can disable a cryptographic algorithm estate-wide within 24 hours, simulating a catastrophic break announcement. |
| **Prerequisites** | Test environment or maintenance window; coordination with service owners; rollback plan. |
| **Tools** | algorithm registry (if exists), service management tools (systemctl, ansible), timing harness |
| **Test Steps** | 1. Select a target algorithm to "break": ML-KEM (realistic future scenario)<br>2. Inventory every system using it: `grep -rl "kyber\|mlkem" /etc/ /usr/local/etc/`<br>3. Simulate the kill-switch: `sudo sed -i 's/^Groups = .*/Groups = X25519:P-256/' /etc/ssl/openssl.cnf; sudo systemctl reload nginx apache2`<br>4. Start the clock; reload every dependent service<br>5. Measure: which clients fail (legacy hardcoded), which internal services break (services requiring PQC), is there rollback<br>6. Test rollback: revert the change, confirm services recover<br>7. Grade: A (<1h), B (1-4h), C (4-24h), F (>24h or no rollback)<br>8. Document findings: missing algorithm registry, hardcoded algorithm references, cert reissuance bottlenecks |
| **Expected Results** | Time-to-disable <24h; all critical services recoverable; rollback works. Grade A or B is target. |
| **False Positive Risk** | HIGH — drill outcomes depend on environment; a failed drill in test does not necessarily mean prod fails. |
| **Cleanup** | Revert all config changes; restore services. |
| **References** | NIST SP 800-227; payloads.md §14 |

### TC-QC-011: Prioritized Post-Quantum Migration Roadmap Generation

| Field | Value |
|------|-----|
| **ID** | TC-QC-011 |
| **Name** | Prioritized PQ Migration Roadmap Generation |
| **Severity** | HIGH |
| **Category** | Crypto Agility & Migration |
| **Objective** | Synthesize TC-QC-001 through TC-QC-010 findings into a prioritized migration roadmap aligned with NIST SP 800-227 and CNSA 2.0. |
| **Prerequisites** | TC-QC-001 inventory complete; TC-QC-002 SNDL matrix complete; TC-QC-010 drill result available. |
| **Tools** | python3 (`pqc_migration_priority.py` from payloads.md §13), report templates |
| **Test Steps** | 1. Load the TC-QC-001 inventory into `pqc_migration_priority.py`<br>2. Compute priority score per asset: sensitivity × 10 + SNDL penalty + long-lived bonus<br>3. Rank assets; assign migration windows based on priority (P0: 6 months, P1: 12 months, P2: 18 months)<br>4. For each priority class, specify target algorithm (SLH-DSA for root, ML-DSA-65 for code-sign, X25519+ML-KEM-768 for TLS leaf, AES-256 for symmetric)<br>5. Specify hybrid overlap period (recommend 2 years of classical+PQC parallel operation)<br>6. Include rollback plan for each migration step<br>7. Compute post-quantum readiness score (0-100) using `pq_readiness_score.py`<br>8. Produce report per payloads.md §16 template |
| **Expected Results** | Prioritized roadmap with at least P0/P1/P2 classes; readiness score with breakdown by dimension; alignment with NIST/CNSA/GB standards documented. |
| **False Positive Risk** | LOW — synthesis is deterministic given inputs. |
| **Cleanup** | No cleanup; roadmap is a planning artifact. |
| **References** | NIST SP 800-227; CNSA 2.0; GB/T 38636-2020; payloads.md §13, §14, §16 |

---

## F. Classical Crossover

### TC-QC-012: ROCA (CVE-2017-15361) Detection & Blockchain PQ-Signature Audit

| Field | Value |
|------|-----|
| **ID** | TC-QC-012 |
| **Name** | ROCA Detection & Blockchain PQ-Signature Audit |
| **Severity** | MEDIUM |
| **Category** | Classical Crossover (ROCA, blockchain-PQC) |
| **Objective** | Detect ROCA-vulnerable RSA keys (CVE-2017-15361) in the inventory; for blockchain deployments, audit PQ-signature schemes (Lamport/XMSS via QuipNetwork/hashsigs-solidity, QRL XMSS) for state-management and one-time-key correctness. |
| **Prerequisites** | RsaCtfTool installed; access to blockchain contracts using PQ signatures; QRL wallet access (where applicable). |
| **Tools** | RsaCtfTool, slither (for hashsigs-solidity), qrl-cli |
| **Test Steps** | 1. For each RSA public key in the TC-QC-001 inventory: `RsaCtfTool --publickey pub.pem --attack roca`<br>2. Flag any ROCA-positive key (CRITICAL pre-quantum finding; also Shor-vulnerable)<br>3. For blockchain deployments using QuipNetwork/hashsigs-solidity: run `slither .` on the contract; verify the Lamport/Winternitz key is enforced one-time (mapping tracks used messages)<br>4. Verify state management: reentrancy / storage collision cannot reuse a one-time key<br>5. Verify hash function (keccak256) used for Lamport is collision-resistant (256-bit, PQ ~128-bit OK)<br>6. For QRL wallets: `qrl-cli wallet_info` and inspect XMSS leaf index monotonicity<br>7. Audit key rotation mechanism: can the contract rotate validator PQ keys?<br>8. Check gas cost: hash-based signatures are large; verify gas budget per bridge action |
| **Expected Results** | No ROCA-positive RSA keys; blockchain PQ-sig contracts enforce one-time keys; QRL wallets show monotonic XMSS state; gas budget accommodates PQ sig sizes. |
| **False Positive Risk** | LOW — ROCA test is deterministic; slither findings on one-time enforcement are reproducible. |
| **Cleanup** | No cleanup. |
| **References** | CVE-2017-15361 (ROCA); QuipNetwork/hashsigs-solidity; QRL; payloads.md §11, §15 |

---

## Appendix: Severity Rubric

| Severity | Definition | Examples in this skill |
|----------|-----------|------------------------|
| **CRITICAL** | Imminent exploitability or catastrophic long-term data exposure | Hybrid TLS downgrade (TC-QC-003); GM SSL silent downgrade to RSA (TC-QC-007); SNDL-exposed long-term-confidential flows (TC-QC-002) |
| **HIGH** | Significant risk requiring near-term remediation | Shor-vulnerable root CA (TC-QC-001); ML-KEM-512 in production (TC-QC-004); SM4-ECB (TC-QC-008); failed crypto-agility drill (TC-QC-010) |
| **MEDIUM** | Real but lower-priority risk | XMSS state mgmt gap (TC-QC-005); QKD without decoy-state (TC-QC-009); ROCA in test-only key (TC-QC-012) |
| **LOW** | Informational / hardening opportunity | Documentation gaps; parameter-set recommendations |

---

## Appendix: Cross-References

- **crypto-attacks** (TC-CR-*): classical crypto siblings (RSA, AES, ECDSA, padding oracle, JWT)
- **vpn-attack** (TC-VPN-*): TLS/IPsec at network layer; hybrid-PQC extends this
- **blockchain-web3** (TC-BW-*): smart contract logic; PQ-sig in bridges is the crossover
- **security-misconfiguration**: crypto-agility misconfiguration overlaps here
- **digital-forensics / anti-forensics**: SNDL data captured today becomes forensically relevant when CRQC arrives
