# Kyber Ransomware: 2026-03 Event Retrospective & PQC Implementation Attack Surface

> Guide for `pqc-implementation-attack`. Part 1 reconstructs the March 2026 Kyber-ransomware wave and its operational lessons; Part 2 surveys the broader PQC implementation attack surface this skill covers.
> Depth references: `payloads.md` §9-§10 (triage and recovery workflows), `test-cases.md` TC-PQI-005.

---

## Part 1 — The 2026-03 Kyber Ransomware Wave

### 1.1 What the advisory said

On 2026-03, CISA — jointly with international partners — published an advisory documenting the first operationally significant ransomware families wrapping session keys with **ML-KEM-768** (the FIPS 203 instantiation of Kyber). The advisory followed months of escalating indicators:

| Time | Signal |
|------|--------|
| 2025 Q3 | Malware trackers first flagged ML-KEM symbols in low-volume encryptor builds ("proof-of-quantum" claims by then-minor affiliates) |
| 2025 Q4 | First victim-side incident reports where RSA key-recovery tooling failed against the wrap layer |
| 2026-01 | A major EDR vendor published YARA for `mlkem768` keygen imports in encryptor stages |
| 2026-03 | CISA advisory: multiple RaaS families shipping ML-KEM-768 wraps as default; legacy RSA layers kept only for older victims |

### 1.2 Why classical playbooks died

Classical ransomware recovery had three crutches, all broken by the PQC wrap:

1. **Key-size shortcuts** — RSA-2048/4096 wraps were sometimes recoverable via factorization-era weaknesses (shared primes, ROCA-class keygen flaws). ML-KEM keys have no factoring shortcut, full stop.
2. **ECIES nonce reuse** — deterministic-nonce bugs in ECIES layers historically yielded free decryption. ML-KEM encapsulation has no nonce to misuse — *if implemented correctly*.
3. **Symmetric-layer-only analysis** — analysts could sometimes recover session keys from memory-scraping or weak key derivation. The dual-layer structure (§1.3) now separates session-key handling cleanly.

The net effect: **recovery probability collapsed from "sometimes" to "only when the implementation is defective."**

### 1.3 Family structure observed in the wild

```text
┌─────────────────────────────────────────────────────────┐
│ Per-victim encryption                                    │
│   files ← ChaCha20-Poly1305 or AES-256-GCM (session K)  │
│   K wrapped by: ML-KEM-768 (ek_victim)   ← new default  │
│   legacy victims: RSA-OAEP-4096 layer    ← kept for old │
│   affiliate builder mints ek/sk; sk held by affiliate   │
│   victim note: kem ciphertext c_i + victim ID derivation │
└─────────────────────────────────────────────────────────┘
```

Notable observed properties:

- **Builder-provided libraries**: most families statically link liboqs forks rather than OS crypto stacks — version drift is large and old builds persist (the same property that keeps KyberSlash-class bugs alive in firmware).
- **Per-victim uniqueness claims**: builders advertise "quantum-safe unique keys per victim" — early samples partially delivered this, and the gap between claim and implementation became the recovery surface (§1.4).
- **Speed**: ML-KEM-768 encapsulation is microseconds; encryptors lost no throughput vs RSA — no operational reason for affiliates to stay classical.

### 1.4 Defect classes actually found

Field triage across 2026 incidents converged on four defect classes (recovery value ordered):

1. **Cross-victim key reuse** — an affiliate builder bug minted identical session-wrap keys for victims created in the same builder session. One recovered sample cluster decrypted wholesale. (Rarest, highest value.)
2. **Deterministic ephemerals** — a fork seeded ML-KEM encapsulation randomness from a time-derived PRNG; kem ciphertexts shared structure across victims. Recoverable once the PRNG state was inferred.
3. **Keygen entropy failures** — encryptors running in containers before host entropy was ready produced low-entropy ML-KEM keys on some hosts; cross-host key equality checks (the skill's §7 workflow, inverted) exposed them.
4. **Half-broken hybrids** — one family's "hybrid" mode concatenated instead of hashing both legs into the KDF; stripping the classical leg at an intermediary reduced the wrap to the (then-vulnerable) classical implementation.

### 1.5 Response playbook changes

- **Triage before payment** — the advisory explicitly recommended defect-based triage (this skill's TC-PQI-005) before payment decisions, citing the §1.4 class-1 case where payment was avoided.
- **Sample clustering** — ISACs began correlating kem-ciphertext hashes across victims; responders should submit markers (never plaintext victim data) to enable cluster detection.
- **Economic note**: the advisory's moral hazard argument — paying for ML-KEM-wrapped data without triage subsidizes the R&D that made the wrap viable.

### 1.6 Lessons for defenders (pre-incident)

1. **Assume the adversary's crypto is good; verify the implementation** — the recovery cases all came from implementation defects, exactly the asymmetry this skill systematizes.
2. **Inventory your own PQC stack first** — the same defect classes (§1.4) apply to defensive ML-KEM deployments; run the §11 audit checklist on your own estate before attackers demo it for you.
3. **Backups remain the only guaranteed recovery** — ML-KEM changed key recovery economics, not backup economics.

---

## Part 2 — PQC Implementation Attack Surface Survey

The event in Part 1 is one instance of a general pattern: **the protocol is strong, the code is young.** This survey maps where implementation-layer defects concentrate, cross-referencing the skill's payloads.

### 2.1 Surface map

| Surface | Defect concentration | Skill coverage |
|---------|---------------------|----------------|
| TLS terminators (oqs-provider, vendor stacks) | Group negotiation bugs, stale liboqs links, combiner mistakes | §1, §3, §8 |
| Firmware/embedded (pqm4, PQClean ports) | Variable-time reductions, unmasked decoders, fault-sensitive checks | §2, §4, §5, §6 |
| Key generation paths | Entropy failures at boot, factory-reset determinism | §7 |
| Custom hybrid stacks | Single-leg KDFs, transcript-binding omissions | §8 |
| Weaponized PQC (ransomware) | Builder bugs: key reuse, deterministic ephemerals | §9, §10 |

### 2.2 Why ML-KEM implementation security is harder than ECC

- **Lattice decoder branching** is key-dependent through many intermediate steps — richer single-trace leakage than most ECC scalar multiplications.
- **Implicit rejection** creates a fault target (the re-encryption check) with no classical analogue in X25519.
- **Young code ecosystems** — liboqs/oqs-provider API churn through 2024-2026 encouraged forks; forks stop tracking advisories (KyberSlash persistence in the wild is the canonical evidence).
- **Embedded adoption outpaced hardening** — pqm4-style deployments ship speed-optimized variants without masking; certification (TVLA-class) lags deployment.

### 2.3 Attack-cost ladder (for engagement scoping)

| Capability | Access required | Cost bar |
|-----------|----------------|----------|
| Remote timing (KyberSlash-class) | Network, authorized | Low |
| Hybrid downgrade / combiner abuse | Network + client control | Low |
| Fault injection key recovery | Physical, owned identical hardware | Medium (equipment) |
| Single-trace SCA recovery | Profiling access + identical hardware | Medium-high (expertise) |
| RNG/keygen flaw exploitation | Sample cluster or device access | Low once detected |

Report findings with the ladder position stated — it frames both severity and remediation priority honestly.

### 2.4 Where this skill draws the line

- Protocol-design attacks and algorithm impact: `quantum-crypto-attack`
- Migration-program attacks (SNDL ops, org-level downgrades): `post-quantum-migration-attack`
- **This skill**: the build in front of you — fingerprint it, break its implementation (authorized), triage its weaponized outputs.

---

## Appendix: Citation & Verification Notes

- The 2026-03 advisory is tracked in this workspace via the v0.2.5.4 finding F-QC-001 (quantum-crypto-attack payloads). When citing externally, pull the current advisory text from CSA/CISA publications and record the retrieval date — advisory pages are updated in place.
- Every implementation CVE referenced in this guide's workflows must pass the payloads.md §2.3 NVD gate before appearing in a customer-facing report.
- KyberSlash affected-version lists: verify at the advisory site, not from secondary writeups.
