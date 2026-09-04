# PQC Implementation Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases for PQC implementation-layer assessment.
> All commands assume an authorized engagement scope or owned lab hardware. Never run active probes against systems without written authorization.

---

## Statistics

| Category | Count | Severity Distribution |
|------|------|-------------|
| A. Reconnaissance & Fingerprinting | 2 | Medium: 2 |
| B. Remote Implementation Pre-Screen | 3 | High: 2, Medium: 1 |
| C. Authorized Lab Exploitation | 3 | Critical: 1, High: 2 |
| D. Incident Support (Ransomware) | 2 | High: 2 |
| **Total** | **10** | **Critical: 1, High: 6, Medium: 3** |

---

## A. Reconnaissance & Fingerprinting

### TC-PQI-001: PQC Library Fingerprint & Version Audit

| Field | Value |
|------|-----|
| **Test ID** | TC-PQI-001 |
| **Severity** | Medium |
| **Category** | Reconnaissance & Fingerprinting |
| **Objective** | Verify that TLS probing and firmware string/symbol analysis identify the exact PQC library, version, and build provenance of the target, enabling known-defect mapping. |
| **Prerequisites** | Authorized scope covering the target endpoint or firmware image; openssl 3.x with hybrid group support; binwalk, strings, nm available. |
| **Tools** | openssl, curl, binwalk, strings, nm, git |
| **Test Steps** | 1. Run the group-acceptance matrix from payloads.md §1.1 against the TLS endpoint (`X25519MLKEM768`, raw `MLKEM768`, `secptrp256`, classical-only) and record which succeed |
| | 2. For firmware targets, extract and run the §1.2 string probes (`liboqs`, `oqs-provider`, `pqclean`, `mlkem768` markers, version pins) |
| | 3. Symbol-diff extracted libraries against upstream release tags (§1.2) to detect fork drift |
| | 4. Map the fingerprint against the §2 defect class table and the KyberSlash advisory affected-version list |
| | 5. Gate every candidate CVE through the NVD verification protocol (§2.3) |
| **Expected Results** | A recorded fingerprint tuple (library, version, optimization variant, provenance); a defect-exposure table where every cited CVE has passed the NVD gate for the identified version range; unidentifiable builds flagged for lab procurement. |
| **False Positive Verification** | Confirm the negotiated group actually exercises ML-KEM (handshake transcript size +1184 bytes keyshare), not merely an advertising banner; re-run symbol diff against the correct upstream tag. |

---

## B. Remote Implementation Pre-Screen

### TC-PQI-002: Remote Timing Side-Channel Detection (KyberSlash-Class)

| Field | Value |
|------|-----|
| **Test ID** | TC-PQI-002 |
| **Severity** | High |
| **Category** | Remote Implementation Pre-Screen |
| **Objective** | Verify that statistical handshake-timing comparison detects variable-time ML-KEM decapsulation on an authorized remote endpoint without host access. |
| **Prerequisites** | Written authorization for active testing; controlled network position with stable RTT (co-located VPS preferred); python3 with scipy. |
| **Tools** | openssl s_client, python3 (timing_probe.py harness, payloads.md §3.1), scipy |
| **Test Steps** | 1. Capture n=2000+ handshake timings under `X25519MLKEM768` (exercises ML-KEM decapsulation path) |
| | 2. Capture n=2000+ timings under `X25519`-only (classical baseline) |
| | 3. Trim slowest 5% of each sample (network noise), run Welch's t-test and report effect size (§3.2) |
| | 4. Repeat the full measurement at a different time-of-day to rule out load artifacts |
| | 5. If a persistent significant gap exists, cross-check the fingerprinted version (TC-PQI-001) against the KyberSlash affected list |
| **Expected Results** | Either (a) no statistically significant difference between groups (informational — no timing signal at this sample size) or (b) a persistent gap with p<0.01 and documented effect size correlating with a fingerprinted vulnerable version (High — escalate to remediation; lab confirmation optional). |
| **False Positive Verification** | Verify the delta survives time-of-day repeats and co-located vantage points; ensure the baseline group truly bypasses the ML-KEM code path (no server-side hybrid-only policy silently mapping groups). |

### TC-PQI-003: Hybrid KEM Downgrade & Combiner Implementation Test

| Field | Value |
|------|-----|
| **Test ID** | TC-PQI-003 |
| **Severity** | High |
| **Category** | Remote Implementation Pre-Screen |
| **Objective** | Verify that the target's hybrid X25519MLKEM768 stack correctly rejects stripped or downgraded keyshare sets, and that both combiner legs contribute to the session key. |
| **Prerequisites** | Authorized testing scope; openssl 3.x with per-group control; access to application source or binary for combiner review (part 3). |
| **Tools** | openssl s_client, bash matrix script (payloads.md §8.1), static analysis (Ghidra/grep on KDF call sites) |
| **Test Steps** | 1. Run the §8.1 negotiation matrix; record success/negotiated-group/fallback behavior for each offered set |
| | 2. Submit stripped keyshare variants (classical-only from a PQC-advertised client) — the target must abort, not silently downgrade |
| | 3. Where source/binary access exists, run the §8.2 combiner review: concatenation order, transcript binding, KDF call sites (both legs hashed?) |
| | 4. Test session resumption across group changes for transcript-binding failures |
| **Expected Results** | Either (a) strict group policy: stripped sets rejected, both combiner legs verified contributing (informational — hardened) or (b) silent classical fallback accepted from a hybrid-capable client, or single-leg KDF discovered (High — the encrypted channel is only as strong as its weakest implementation). |
| **False Positive Verification** | Distinguish server policy (intentional classical support) from implementation downgrade: confirm from server config/documentation that classical-only acceptance is unintended; for combiner findings, verify at KDF call-site level, not documentation claims. |

---

## C. Authorized Lab Exploitation

### TC-PQI-004: Single-Trace Power SCA Recovery (Template/DL)

| Field | Value |
|------|-----|
| **Test ID** | TC-PQI-004 |
| **Severity** | Critical |
| **Category** | Authorized Lab Exploitation |
| **Objective** | Verify the full lab attack chain: capture profiling traces from the target build on identical hardware, train template or deep-learning model, and recover the ML-KEM-768 secret from a single attack trace. |
| **Prerequisites** | Owned lab hardware identical to production (same silicon revision); ChipWhisperer-Husky/Lite; target firmware build with SimpleSerial-wrapped decapsulation (payloads.md §6); profiling budget ~5k traces. |
| **Tools** | ChipWhisperer toolchain, lascar/scaaml, target board (pqm4 or vendor build) |
| **Test Steps** | 1. Build and flash the attack firmware; record commit hash, compiler flags, optimization variant |
| | 2. Capture profiling set (~5k traces) varying the secret with fixed message; label the target intermediate (decoder output) |
| | 3. Compute per-intermediate SNR; select points of interest (§4.2) |
| | 4. Train template / MLP classifier; validate on held-out profiling traces |
| | 5. Attack phase: capture a single trace with an unknown key; run the model; report recovered secret and key-rank statistics |
| | 6. Document the exact hardware revision and state the profiling-access caveat in the report |
| **Expected Results** | Full 32-byte shared-secret recovery from one attack trace with reported key-rank (or documented failure at this trace budget); evidence pack per §4.4 (scope config, SNR plot, accuracy, key-rank plot); explicit non-remote-exploitability statement. |
| **False Positive Verification** | Re-run the attack on a second unit of the same hardware revision with a fresh key (recovery must reproduce); verify a patched/masked reference build does NOT recover at the same trace count. |

---

## D. Incident Support (Ransomware)

### TC-PQI-005: Kyber Ransomware Sample Triage & Recovery Feasibility

| Field | Value |
|------|-----|
| **Test ID** | TC-PQI-005 |
| **Severity** | High |
| **Category** | Incident Support (Ransomware) |
| **Objective** | Verify the triage workflow on a Kyber-based ransomware sample or incident artifact set: identify the scheme and parameters, map the dual-layer structure, and run defect-based recovery checks in priority order. |
| **Prerequisites** | Sample(s) obtained legally (incident response engagement, threat-intel sharing); isolated detonation/analysis VM; hashes recorded before analysis (chain of custody). |
| **Tools** | strings, python3 (entropy mapper, payloads.md §9.2), CyberChef, sample collection from multiple victims where available |
| **Test Steps** | 1. Hash and archive samples; record provenance |
| | 2. Identify scheme/parameters via §9.2 markers (`mlkem768` strings, 1184-byte keyshare blobs, note/config extraction) |
| | 3. Run the entropy map to segment symmetric-encrypted regions vs wrapped-key material |
| | 4. Execute the §10.1 recovery checks in order: cross-victim ciphertext equality, deterministic nonces (identical kem-ciphertext prefixes), keygen RNG flaw (entropy analysis across victim clusters), hybrid-layer downgradeability |
| | 5. Produce the §10.2 recovery feasibility verdict with evidence and confidence statement |
| **Expected Results** | A completed triage report: scheme identification with marker evidence, structural map, and a recovery verdict of RECOVERABLE (free, defect class named), RECOVERABLE (defect exploit required), or ADVERSARY-KEY-REQUIRED — each with evidence hashes and a confidence interval, issued before any payment decision. |
| **False Positive Verification** | Confirm "key reuse" findings across full ciphertext comparisons (not just prefixes); rule out legitimate per-victim structure (victim-ID derivation) explaining prefix similarity before declaring reuse. |

---

### TC-PQI-006: Firmware PQC Library Extraction & Symbol Diff

| Field | Value |
|------|-----|
| **Test ID** | TC-PQI-006 |
| **Severity** | Medium |
| **Category** | Reconnaissance & Fingerprinting |
| **Objective** | Verify that firmware-image analysis extracts the exact PQC library, version pins, and fork drift versus upstream tags, closing the fingerprint chain for embedded targets. |
| **Prerequisites** | Legally obtained firmware image (engagement artifact or owned device dump); binwalk, strings, nm, and upstream tag clones per payloads.md §1.2. |
| **Tools** | binwalk, strings, nm, git |
| **Test Steps** | 1. `binwalk -e firmware.bin` and run the §1.2 string probes over the extracted tree (`liboqs`, `oqs-provider`, `pqclean`, `mlkem768`, version pins) |
| | 2. Locate extracted shared objects/static archives; record hashes |
| | 3. Symbol-diff each against the closest upstream tag (`nm -D` comparison, §1.2) to quantify fork drift |
| | 4. Map the resolved fingerprint through the §2 defect table and the KyberSlash advisory affected-version list |
| **Expected Results** | A fingerprint tuple (library, version, variant, fork-drift summary) recorded with evidence hashes; builds that cannot be resolved to an upstream tag flagged for lab procurement (feeds TC-PQI-004). |
| **False Positive Verification** | Re-run the symbol diff against the second-closest tag; version strings alone (without symbol corroboration) are treated as unconfirmed. |

### TC-PQI-007: Local Constant-Time Verification (dudect)

| Field | Value |
|------|-----|
| **Test ID** | TC-PQI-007 |
| **Severity** | Medium |
| **Category** | Remote Implementation Pre-Screen |
| **Objective** | Verify statistically whether the target build's decapsulation path is constant-time with respect to secret-dependent inputs, using the dudect fixed-vs-random harness. |
| **Prerequisites** | Buildable target source (or provided binary + harness fixture); dudect cloned; ability to call the decapsulation API from the fixture. |
| **Tools** | dudect, gcc/clang |
| **Test Steps** | 1. Adapt `src/fixture.c` to call the target decapsulation (liboqs `OQS_KEM_ml_kem_768_decaps` / PQClean equivalent) with fixed vs random ciphertexts |
| | 2. Build and run per payloads.md §3.3 for ≥3 independent runs |
| | 3. Record the t-test evolution per percentile class; note compiler flags used |
| **Expected Results** | All classes remain within ±5 across runs (constant-time with respect to tested input class) or a persistent >5 class identifies leakage (escalate to TC-PQI-002-style remote timing assessment and §4 lab chain). Compiler-flag sensitivity (-O2 vs -O3) recorded. |
| **False Positive Verification** | Re-run with a known-leaky reference build (deliberately unpatched snippet) to confirm the harness detects; verify the fixture exercises decapsulation, not encapsulation. |

### TC-PQI-008: Fault Budget Quantification on pqm4 Target

| Field | Value |
|------|-----|
| **Test ID** | TC-PQI-008 |
| **Severity** | High |
| **Category** | Authorized Lab Exploitation |
| **Objective** | Quantify the number of voltage-glitch faults required to convert ML-KEM decapsulation into a key-recovery oracle on the target build (re-encryption-check skip model). |
| **Prerequisites** | Owned pqm4/STM32 target with SimpleSerial decap wrapper (payloads §6); ChipWhisperer; crafted non-canonical ciphertext corpus. |
| **Tools** | ChipWhisperer toolchain, pqm4 |
| **Test Steps** | 1. Sweep glitch width/offset grid per payloads §5.2 while submitting crafted ciphertexts |
| | 2. Classify every outcome: valid-share leak (FAULT), implicit rejection (clean), crash |
| | 3. Count faults until full 32-byte secret recovery; log the fault counter per payloads §5.3 |
| | 4. Compare observed budget against the literature range (2^13..2^16) |
| **Expected Results** | Key recovered with a logged fault count (finding with exploitability framing: physical access required) or no stable fault window in the swept grid (documented negative with grid coverage). |
| **False Positive Verification** | Recovery must reproduce on a second identical board; a patched build (check restored) must return to clean rejections. |

### TC-PQI-009: Keygen RNG Defect — Reboot & Factory-Reset Equality

| Field | Value |
|------|-----|
| **Test ID** | TC-PQI-009 |
| **Severity** | High |
| **Category** | Authorized Lab Exploitation |
| **Objective** | Detect deterministic or low-entropy ML-KEM key generation on embedded products via reboot loops, factory resets, and cross-unit comparison. |
| **Prerequisites** | Owned device(s) of the target model (≥2 units for cross-device checks); lab power relay/reset control; payloads.md §7 workflows. |
| **Tools** | ssh/serial console, scripting for pubkey capture, sort/uniq |
| **Test Steps** | 1. Capture the device's PQC public key; reboot via power relay ×50, capturing the key after each boot (§7.1) |
| | 2. Factory-reset cycle ×10 with key capture |
| | 3. Cross-device: capture first-boot keys from all available units (§7.2) |
| | 4. Hash-compare the collected keys; for near-misses, run entropy-health analysis on the pre-keygen RNG stream (§7.3) |
| **Expected Results** | Zero duplicate keys across all conditions (hardened) or any duplicate/repeated key (Critical finding: full key-recovery exposure — ML-KEM collapses to plaintext). Report the exact repro condition (reboot vs reset vs cross-unit). |
| **False Positive Verification** | Confirm key-reading paths read fresh generation, not a cached/static stored key (check generation timestamps/serial output); duplicates must survive independent extraction re-runs. |

### TC-PQI-010: Cross-Victim Key Reuse Detection (Ransomware Cluster)

| Field | Value |
|------|-----|
| **Test ID** | TC-PQI-010 |
| **Severity** | High |
| **Category** | Incident Support (Ransomware) |
| **Objective** | Determine whether a cluster of Kyber-ransomware samples from multiple victims shares wrapped session keys, enabling wholesale free decryption (defect class 1 of payloads §10.1). |
| **Prerequisites** | Samples/notes from ≥2 victims of the same family (legal provenance); isolated analysis VM; hashes recorded. |
| **Tools** | python3, sha256sum, CyberChef |
| **Test Steps** | 1. Extract the kem-ciphertext region from each victim's note/sample (§9.2 markers) |
| | 2. Hash-compare the extracted regions across victims; for structural similarity, compare prefix windows at increasing lengths |
| | 3. For any match, extract the corresponding session-key-wrapped file header from both victims and test decryption of victim B's file with victim A's recovered key material (if class-2 deterministic nonce is indicated, derive per §10.1 order) |
| | 4. Record evidence hashes and the recovery verdict per §10.2 |
| **Expected Results** | Zero cross-victim collisions (verdict: ADVERSARY-KEY-REQUIRED for this defect class) or identical wrapped keys confirmed across victims (verdict: RECOVERABLE free — highest-value incident finding; immediately informs payment decision). |
| **False Positive Verification** | Prefix similarity alone is insufficient — require full-region hash equality or successful cross-decryption; rule out legitimate per-victim ID derivation explaining repeated prefixes (§9.3). |

---

## Appendix: Severity Calibration

| Severity | Definition | Example |
|----------|------------|---------|
| **Critical** | Full secret recovery demonstrated with reproducible evidence (lab conditions). | TC-PQI-004 (single-trace SCA recovery) |
| **High** | Confirmed implementation weakness enabling downgrade, remote exploitation signal, or incident recovery impact. | TC-PQI-002 (remote timing), TC-PQI-003 (combiner/downgrade), TC-PQI-005 (ransomware triage), TC-PQI-008 (fault budget), TC-PQI-009 (keygen RNG defect), TC-PQI-010 (cross-victim key reuse) |
| **Medium** | Reconnaissance or local verification enabling defect mapping; no direct impact alone. | TC-PQI-001 (fingerprint audit), TC-PQI-006 (firmware symbol diff), TC-PQI-007 (dudect) |

## Appendix: Scope & Authorization Notes

- TC-PQI-002/003 are **active remote tests** — same authorization bar as vulnerability scanning; pace requests to stay within engagement rules.
- TC-PQI-004 requires **owned identical hardware**; results must not be generalized across silicon revisions.
- TC-PQI-005 operates on **incident artifacts**: preserve evidentiary chain; recovery verdicts feed payment decisions — report confidence, never certainty.
