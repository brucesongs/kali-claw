---
name: pqc-implementation-attack
description: "Post-quantum cryptography implementation-layer attacks — ML-KEM/Kyber side channels (KyberSlash-class timing, single-trace power/EM, template and deep-learning SCA), fault injection on decapsulation, RNG/keygen weaknesses in liboqs/oqs-provider/PQClean/pqm4, hybrid KEM combiner implementation flaws, and Kyber ransomware sample triage with implementation-defect recovery paths."
origin: kali-claw
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Python
  - WebSearch
  - WebFetch
metadata:
  domain: crypto
  category: post-quantum
  tool_count: 10
  guide_count: 2
  mitre: "T1600-Weaken Encryption, T1600.001-Reduce Key Space, T1110.002-Password Cracking, T1486-Data Encrypted for Impact, T1040-Network Sniffing"
  owasp: "N/A — cryptographic implementation class (A02:2021 Cryptographic Failures adjacent)"
  keywords:
    - ML-KEM
    - Kyber
    - KyberSlash
    - liboqs
    - oqs-provider
    - pqm4
    - side-channel
    - fault-injection
    - KEM-combiner
    - pqc-ransomware
    - FIPS-203
    - crypto-agility
  last_reviewed: "2026-09-04"
---

# Skill: PQC Implementation Attack

> **Supplementary Files**:
> - `payloads.md` — fingerprinting probes, side-channel and fault-injection lab workflows, RNG flaw checks, Kyber ransomware triage commands
> - `test-cases.md` — 5 structured test cases (library fingerprint, remote timing, hybrid downgrade, ransomware triage, SCA lab)
> - `guides/kyber-ransomware-retrospective.md` — Kyber ransomware event retrospective + PQC implementation attack surface survey

## Summary

Post-quantum cryptography (PQC) **implementation-layer** attack domain. FIPS 203 (ML-KEM/Kyber), ML-DSA, and their library implementations (liboqs, oqs-provider, PQClean, pqm4, vendor TLS stacks) carry a new class of exploitable implementation defects: variable-time arithmetic (KyberSlash-class division leaks), single-trace-friendly lattice decoding, fault-sensitive implicit rejection, and entropy failures in keygen. This skill covers the full attack chain — library fingerprinting, side-channel and fault-injection exploitation under authorized lab conditions, RNG/keygen flaw analysis, hybrid KEM combiner implementation defects — plus the operational side: **Kyber ransomware** sample triage and implementation-defect-based recovery assessment.

**Domain**: crypto | **Standard**: FIPS 203 / ML-KEM (Kyber) | **Layer**: implementation (not protocol design)

## Description

NIST finalized FIPS 203 (ML-KEM, derived from CRYSTALS-Kyber) in August 2024, and hybrid deployments (X25519MLKEM768) became default in major browsers and CDNs through 2025-2026. The protocol mathematics is considered strong — but **implementations are young**. The 2024 KyberSlash disclosures showed that division-based Barrett reduction in widely-deployed Kyber code produced remotely-observable timing differences, letting an attacker recover secrets from a vulnerable server. This is the pattern this skill systematizes: **the math is post-quantum, the code is not**.

The 2026-03 CSA advisory on Kyber-based ransomware (see `guides/kyber-ransomware-retrospective.md`) confirmed a second operational reality: adversaries now use ML-KEM in payloads to wrap session keys, defeating classical key-recovery shortcuts that worked against RSA/ECIES-based ransomware. Recovery now depends on finding **implementation defects** — key reuse, deterministic nonces, flawed RNG — rather than factoring.

### Skill Identity

| Aspect | Value |
|--------|-------|
| Type | Implementation-layer cryptographic attack + ransomware triage |
| Distinguishing feature | Attacks the *code that implements* PQC, not the protocol or the migration program |
| Adjacent skills | `quantum-crypto-attack` (algorithm impact, tooling), `post-quantum-migration-attack` (SNDL, downgrade, migration ops) |
| Distinct from adjacent | This skill runs lab-grade side-channel/fault exploitation and ransomware sample triage; adjacent skills inventory and strategize |

### Why this skill exists (2026)

1. **KyberSlash (2024) proved remote exploitation of PQC implementation timing.** Patched versions persist in the wild; embedded copies (pqm4, vendor forks) often never update.
2. **ML-KEM's decoding structure is single-trace friendly.** Compared to ECC, lattice key-dependent branching leaks in one power/EM trace under template and deep-learning attacks — a lower bar for lab adversaries.
3. **Kyber ransomware is operational.** Since 2026-03, documented families wrap session keys with ML-KEM-768; responders need triage and defect-based recovery methods, which do not exist in classical ransomware playbooks.
4. **Implicit rejection is fault-sensitive.** A skipped or faulted re-encryption check converts a CCA-secure KEM into a key-recovery oracle with a handful of faults.

### Differentiation from sibling quantum skills

| Dimension | `quantum-crypto-attack` | `post-quantum-migration-attack` | This skill |
|-----------|-------------------------|--------------------------------|------------|
| Focus | Algorithm impact (Shor/Grover), PQC candidates testing, national crypto | SNDL capture, hybrid downgrade, migration program attacks | **Implementation code defects + weaponized PQC (ransomware)** |
| Depth on SCA | Overview snippets (dudect, TVLA, ChipWhisperer basics in §7/§12) | Section-level overview (§5: timing/RowHammer/EM) | **Full attack chain to secret recovery** (template, DL-SCA, fault parameters) |
| Ransomware | — | — | **Dedicated triage + recovery** |
| Deliverable | Exposure inventory, readiness report | Migration risk, agility drill results | Side-channel lab report, ransomware triage report, recovery feasibility |

Use the siblings for protocol/migration context; use this skill when the target is a **specific library build** or a **concrete sample**.

## Use Cases

1. **Library version audit** — fingerprint which PQC library and version a TLS endpoint or embedded firmware uses (liboqs/oqs-provider/PQClean/pqm4/vendor fork), map to known implementation CVEs
2. **Remote timing assessment** — detect KyberSlash-class variable-time decapsulation on an authorized public endpoint without touching the host
3. **Authorized lab side-channel engagement** — recover ML-KEM secrets from a target board via single-trace power/EM analysis (template or deep-learning SCA), with full equipment and trace-workflow
4. **Fault-injection assessment** — glitch the decapsulation re-encryption check on a microcontroller target and demonstrate key recovery with fault counts
5. **RNG/keygen flaw analysis** — test a product's ML-KEM keygen for deterministic output, weak entropy, or repeated keys across reboits/factory resets
6. **Hybrid KEM combiner implementation review** — verify a vendor's X25519MLKEM768 stack rejects stripped/downgraded groups and correctly concatenates shared secrets
7. **Kyber ransomware sample triage** — identify scheme/parameters, extract the symmetric layer structure, check for key reuse, deterministic nonces, and reusable ciphertexts across victims
8. **Recovery feasibility assessment** — determine whether an incident's encrypted data is recoverable via implementation defect (vs. requiring the adversary's key)

## Core Tools

| Tool | Category | Purpose | License |
|------|----------|---------|---------|
| **liboqs** | Target library | Reference + common deployment of ML-KEM/ML-DSA; version pinning and diffing | MIT |
| **oqs-provider** | Target library | OpenSSL 3 provider exposing PQC in TLS; group negotiation behavior | MIT/Apache 2.0 |
| **PQClean / pqm4** | Target library | Clean + ARM Cortex-M implementations; embedded attack surface | MIT |
| **OQS-OpenSSL (3.x demo)** | Test client/server | Endpoint for handshake downgrade and fingerprint tests | Apache 2.0 |
| **dudect** | Constant-time checker | Statistical fixed-vs-random timing comparison on any build | MIT |
| **ChipWhisperer (Lite/Husky)** | SCA hardware | Power/EM capture for microcontroller targets (lab) | BSD-like |
| **ChipWhisperer Analyzer + custom trace scripts** | Trace analysis | CPA, TVLA, template matching on captured traces | BSD-like |
| **lascar / scaaml** | Trace analysis (Python) | Template and deep-learning side-channel attacks on ML-KEM traces | GPL/MIT |
| **binwalk / Ghidra** | Firmware triage | Extract PQC library versions from firmware images | GPL/Apache 2.0 |
| **CyberChef + entropy tools** | Ransomware triage | Entropy analysis, structure carving in ransomware samples | MIT |

## Methodology

### Phase 1: Target Identification

Identify the exact PQC implementation: TLS group negotiation fingerprints (`openssl s_client -groups`), library banners in firmware strings, symbol diffing against upstream tags (liboqs release tags, PQClean commit hashes). Output: candidate version + known-CVE mapping (start from KyberSlash advisory lists; verify every ID against NVD).

### Phase 2: Remote Pre-Screening

Without host access: statistical timing on decapsulation-facing endpoints (KEM TLS handshakes, KEM-encrypted APIs), hybrid group negotiation matrix (does the server accept classical-only fallback?), certificate chain PQC/classical inconsistency. Establishes whether implementation-layer attack surface is reachable.

### Phase 3: Lab Exploitation (authorized hardware)

On identical hardware (procured/factory-reset): constant-time verification (dudect) → trace capture (ChipWhisperer, ≥10k traces for CPA; 1 trace per attack for template/DL) → secret recovery against the same firmware build → fault injection (voltage/clock glitch on re-encryption check; log fault count vs. key bytes recovered). Every step recorded for the lab report.

### Phase 4: Defect-Based Recovery (incident support)

For ransomware incidents: sample triage (scheme/parameter identification, dual-layer structure extraction) → defect checks in order of recovery value: (1) key reuse across victims, (2) deterministic nonces / repeated ciphertexts, (3) flawed RNG in keygen, (4) downgrade-able hybrid layer. Produce recovery feasibility verdict with evidence.

### Phase 5: Reporting

Deliverables: implementation audit table (version → CVE → reachability), lab attack chain with trace evidence, ransomware triage report, prioritized remediation (patch pins, constant-time verification in CI, entropy source audit, crypto-agility).

### Defense Perspective

| Defense Layer | Control | Detects/Prevents |
|---------------|---------|------------------|
| Perimeter | WAF/TLS terminator with strict group policy (hybrid-only, no classical fallback) | Downgrade stripping (T1600.001-adjacent) |
| Library | Pin patched liboqs/oqs-provider; subscribe to KyberSlash-class advisories; reproducible builds | Known implementation CVEs |
| CI/CD | dudect/valgrind-based constant-time gates on every PQC build; diff vs. upstream | Regressions introducing variable-time code |
| Host/Edge | Monitor handshake timing distributions; anomaly alerts on decapsulation latency | Remote timing exploitation |
| Hardware | Masked/hardened ML-KEM IPs; glitch sensors; TVLA certification for embedded products | Power/EM/fault attacks |
| IR/Response | Kyber ransomware triage playbook (key-reuse checks before paying) | Defect-based recovery opportunities |

## Detection Methods

**SIEM (Splunk SPL)** — TLS handshake group logging:

```spl
index=tls sourcetype=ssl_handshake
| where group_id IN ("4588","4589","25497") AND fallback_group="x25519"
| stats count perc95(duration_ms) by src, dest, group_id, fallback_group
```
Classical-only fallback from a PQC-capable client indicates stripping; latency clusters per destination feed timing-attack detection.

**Sysmon** — endpoint decapsulation service anomalies: EID 1 process spawns of crypto services with abnormal CPU-time-per-operation deltas (timing leak exploitation leaves measurable request-duration skew).

**Sigma** — ransomware stage (MITRE T1486):

```yaml
title: Kyber Ransomware Keygen Marker
logsource: { category: process_creation, product: windows }
detection:
    selection:
        CommandLine|contains|all:
            - 'mlkem768'
            - '--wrap-session-keys'
    condition: selection
```

**Falco** — container runtime:

```yaml
- rule: PQC Library Loaded from Unexpected Path
  desc: liboqs loaded outside system package paths (supply-chain implant)
  condition: open_read and fd.name endswith liboqs.so and not fd.name startswith /usr/lib
```

**Audit/auditd** — entropy source health: log `/dev/hwrng` and `getrandom()` syscall failure bursts preceding PQC keygen (RNG flaw precursor).

## Defense Evasion Techniques

*(For red-team awareness — each has a detection counterpart above.)*

1. **Timing-oracle pacing** — slow-rate timing queries indistinguishable from normal handshakes; pacing below per-source rate thresholds. Counterpart: aggregate duration-distribution monitoring (not per-request thresholds).
2. **Trace capture via idle lab replicas** — attackers buy identical hardware instead of touching production; only build/version pinning and reproducible-build attestation closes this.
3. **Fault-injection via thermal/voltage margining** — non-invasive glitching avoids tamper evidence. Counterpart: glitch sensors, voltage-margin monitoring.
4. **Ransomware key-reuse camouflage** — per-victim unique nonces with a shared flawed RNG state defeats naive nonce-diff checks; requires cross-victim key-reuse entropy tests in triage.
5. **Hybrid-strip at middlebox** — downgrading at an enterprise middlebox (not the endpoint) evades endpoint-side group logging; requires end-to-end group attestation (TLS telemetry at both ends).
6. **Downgrade-only exploitation** — maintaining PQC on the wire while exploiting the classical leg of a badly-combined hybrid (weak combiner) — group negotiation looks healthy; requires combiner implementation review, not just protocol checks.

## Practical Steps

### Step 1: Fingerprint the implementation

Run payloads.md §1 probes against the target endpoint/firmware; record library, version, and build provenance.

### Step 2: Map known defects

Match fingerprint against the known-defect table (§2); verify each CVE ID on NVD; note embedded/unpatchable copies.

### Step 3: Pre-screen remotely (timing + downgrade)

Run §3 remote timing harness and §8 downgrade matrix within authorized scope; decide lab-go/no-go.

### Step 4: Lab side-channel / fault chain

Replicate target build on identical hardware; execute §4-§6 capture-and-recover workflow; document trace counts and recovery material.

### Step 5: RNG/keygen defect checks

Run §7 entropy tests (reboot loops, factory-reset clones, cross-device key equality).

### Step 6: Triage and report

For incident work, run §9-§10 ransomware triage; assemble the Phase 5 report pack.

## Common Pitfalls

- **Confusing protocol-level with implementation-level findings** — "Kyber is quantum-safe" answers nothing about a KyberSlash-vulnerable build; keep the layers separate in reporting.
- **CVE over-claiming** — implementation-layer advisories are often library-and-version specific; never generalize a liboqs CVE to "all Kyber" (verify on NVD, cite the affected-version range).
- **Lab-to-prod gap** — traces from a different silicon revision than production may invalidate single-train template attacks; procure identical hardware/revision before claiming exploitability.
- **Single-trace hype** — template/DL-SCA requires profiling access; do not report "1-trace recovery" as remotely exploitable.
- **Ransomware: paying before triage** — key-reuse or deterministic-nonce defects have historically enabled free recovery; always run defect triage before payment decisions.
- **Ignoring the classical leg** — hybrid deployments fail at the combiner; auditing only the PQC half misses the most common real-world flaw.

## Cross-Reference to Related Skills

- `quantum-crypto-attack` §7/§12 — dudect basics, TVLA, ChipWhisperer capture snippets, lattice SCA overview
- `post-quantum-migration-attack` §3/§4/§5/§11 — hybrid downgrade ops, KEM combiner flaws catalog, RowHammer, Dilithium fault, liboqs/oqs-provider issue lists
- `crypto-attacks` — classical primitives, offline cracking tooling
- `anti-forensics` / `digital-forensics` — ransomware IR chain of custody

## Hacker Laws Alignment

- **Law 1 (Trust nothing, verify everything)** — every build is its own vulnerability surface; fingerprint, don't assume.
- **Law 4 (Move silently)** — remote timing work must be paced and statistically sound, not noisy.
- **Law 7 (The defender's code is the attack surface)** — FIPS 203 is strong; its implementations are where engagements are won.
- **Law 11 (Documentation is a weapon)** — lab-grade evidence (trace plots, fault logs) is what turns a side-channel observation into an accepted finding.

## References

- FIPS 203 (ML-KEM) — NIST, Aug 2024 — https://csrc.nist.gov/pubs/fips/203/final
- KyberSlash advisory & affected implementations — https://kyberslash.cr.yp.to
- liboqs releases & security advisories — https://github.com/open-quantum-safe/liboqs
- oqs-provider — https://github.com/open-quantum-safe/oqs-provider
- pqm4 (ML-KEM on ARM Cortex-M) — https://github.com/mupq/pqm4
- PQClean — https://github.com/PQClean/PQClean
- Cloudflare PQ deployment notes — https://blog.cloudflare.com
- IACR ePrint (search: Kyber side-channel, fault attack ML-KEM) — https://eprint.iacr.org
- CSA advisory on PQC-enabled ransomware (2026-03) — https://www.cisa.gov (see guide for full citation)
- NVD CVE verification — https://nvd.nist.gov

## Attribution

Created in v0.3.0 (2026-09-04) from the 2026-08-06 minor-candidate evaluation (two P1 candidates at 36/75 each: "PQC implementation-layer attack" and "Kyber ransomware"). Implementation-layer focus cross-references `quantum-crypto-attack` and `post-quantum-migration-attack`; neither covers lab-grade SCA exploitation chains or ransomware triage.
