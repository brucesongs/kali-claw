# PQC Implementation Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases for PQC implementation-layer assessment.
> All commands assume an authorized engagement scope or owned lab hardware. Never run active probes against systems without written authorization.

---

## Statistics

| Category | Count | Severity Distribution |
|------|------|-------------|
| A. Reconnaissance & Fingerprinting | 1 | Medium: 1 |
| B. Remote Implementation Pre-Screen | 2 | High: 2 |
| C. Authorized Lab Exploitation | 1 | Critical: 1 |
| D. Incident Support (Ransomware) | 1 | High: 1 |
| **Total** | **5** | **Critical: 1, High: 3, Medium: 1** |

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

## Appendix: Severity Calibration

| Severity | Definition | Example |
|----------|------------|---------|
| **Critical** | Full secret recovery demonstrated with reproducible evidence (lab conditions). | TC-PQI-004 (single-trace SCA recovery) |
| **High** | Confirmed implementation weakness enabling downgrade, remote exploitation signal, or incident recovery impact. | TC-PQI-002 (remote timing), TC-PQI-003 (combiner/downgrade), TC-PQI-005 (ransomware triage) |
| **Medium** | Reconnaissance enabling defect mapping; no direct impact alone. | TC-PQI-001 (fingerprint audit) |

## Appendix: Scope & Authorization Notes

- TC-PQI-002/003 are **active remote tests** — same authorization bar as vulnerability scanning; pace requests to stay within engagement rules.
- TC-PQI-004 requires **owned identical hardware**; results must not be generalized across silicon revisions.
- TC-PQI-005 operates on **incident artifacts**: preserve evidentiary chain; recovery verdicts feed payment decisions — report confidence, never certainty.
