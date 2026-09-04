# Test Cases — hardware-side-channel-advanced

> Structured test cases for hardware-side-channel-advanced.

## TC-001: DPA Resistance

**Objective**: Verify AES implementation resists DPA.

**Arrange**: Capture 10K power traces.

**Act**: Run DPA attack.

**Assert**: Key not recovered within 1M traces.

---

## TC-002: Glitch Resistance

**Objective**: Verify device resists voltage glitch.

**Arrange**: Apply glitch at various offsets/widths.

**Act**: Attempt secure boot bypass.

**Assert**: No bypass within 10K glitch attempts.

---

## TC-003: Cache-timing Resistance

**Objective**: Verify SGX enclave resists cache-timing.

**Arrange**: Run cache-timing attack from outside enclave.

**Act**: Attempt secret recovery.

**Assert**: Secret not recovered.


---

## TC-004: Reconnaissance Detection

**Objective**: Verify monitoring detects reconnaissance.

**Arrange**: Run scanning tools.

**Act**: Execute scan against target.

**Assert**: Monitoring alert within 5 minutes.

---

## TC-005: Defense Bypass

**Objective**: Verify defense bypass is detected.

**Arrange**: Attempt to bypass primary control.

**Act**: Execute bypass technique.

**Assert**: Secondary control catches attempt.

---

## TC-006: Full-Key CPA Recovery Against Target Firmware

**Objective**: Demonstrate (or bound) AES key recovery via correlation power analysis on the engagement's target build.

**Arrange**: Owned target board with SimpleSerial-AES (or instrumented product firmware), ChipWhisperer capture at the settings of payloads §2; fixed-key campaign prepared.

**Act**: Capture 5000 traces; run CPA per subkey; record per-byte correlation evolution and trace count at which each subkey stabilizes.

**Assert**: Full 16-byte key recovered with N traces (finding, severity by access model) or no subkey converges within 10x the campaign size (hardened / masked — escalate to 2nd-order CPA per payloads §10 before clearing).

---

## TC-007: Template Attack with Profiling Device

**Objective**: Recover the key with ≤5 attack traces using templates built on an identical profiling device.

**Arrange**: Two identical units (profiler + victim); 10k profiling traces with rotating keys; SNR-based POI selection per payloads §3.

**Act**: Build multivariate Gaussian templates per SBox output; capture 5 victim traces with an unknown fixed key; run max-likelihood classification.

**Assert**: Full key from ≤5 traces (strongest result class — requires identical hardware possession) or documented rank-deficit at 5 traces. Report must state the profiling-access caveat.

---

## TC-008: Flush+Reload Cross-VM Secret Observation

**Objective**: Verify cache-partitioning effectiveness by observing victim crypto access patterns from a co-located context.

**Arrange**: Authorized private-cloud host; victim VM performing AES T-table operations on a shared page setup (lab dual-VM); eviction/CAT policy active as deployed.

**Act**: Build Flush+Reload monitor per payloads §6; record hit-pattern timing series during 100 victim operations; reconstruct the accessed table indices.

**Assert**: Index pattern indistinguishable from idle baseline (hardened) or the victim's key-schedule-dependent access sequence is observable (finding: cross-VM cache channel; cite colocation conditions and CPU family).

---

## TC-009: Enclave Fault via Voltage Underscaling (Plundervolt class)

**Objective**: Assess whether voltage-control interfaces can fault computation inside an SGX enclave (CVE-2019-11157 class) on authorized lab silicon.

**Arrange**: Lab SGX-capable host with RAPL/voltage interface accessible (pre-lockdown firmware); enclave running AES-GCM self-check loop with known answer.

**Act**: Step core voltage down in 5 mV increments while the enclave runs; log every self-check mismatch with its voltage setting (payloads §7).

**Assert**: Zero mismatches down to the stability floor (interface locked/hardened) or reproducible enclave-internal faults at recorded voltage points (finding: Plundervolt-class; recommend interface lockdown).

---

## TC-010: Differential Fault Analysis on AES

**Objective**: Recover the AES key from faulty ciphertexts produced by injected last-round faults.

**Arrange**: Target with fault primitive available (clock glitch per payloads §8 or laser on decapped lab unit); correct ciphertext C captured; phoenixAES installed.

**Act**: Inject faults into round 9 across N attempts; collect faulty ciphertexts C'; run `phoenixAES.crack(C, C')` per candidate pair.

**Assert**: Key recovered from ≤4 faulty ciphertexts with fault parameters recorded (finding: full DFA chain demonstrated) or no stable fault window found in the swept grid (documented negative with sweep coverage).

---

## Test Suite Summary

10 test cases: defensive-verification stubs (TC-001..005) plus offensive AAA cases (TC-006..010) mapping to payloads §2/§3/§6/§7/§8 (CPA full recovery, template attack, cross-VM Flush+Reload, enclave undervolting fault, DFA on AES).

