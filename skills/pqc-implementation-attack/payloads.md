# PQC Implementation Attack Payload Collection

> Companion to `SKILL.md`. Implementation-layer attack workflows for ML-KEM/Kyber ecosystems (liboqs, oqs-provider, PQClean, pqm4, vendor stacks) plus Kyber ransomware triage.
> All active testing requires written authorization. Lab sections assume owned hardware.

---

## Index

1. [Implementation Fingerprinting](#1-implementation-fingerprinting)
2. [Known Defects & Advisory Mapping](#2-known-defects--advisory-mapping)
3. [Remote Timing Pre-Screen](#3-remote-timing-pre-screen)
4. [Single-Trace Power/EM SCA Lab](#4-single-trace-powerem-sca-lab)
5. [Fault Injection on Decapsulation](#5-fault-injection-on-decapsulation)
6. [Microcontroller Targets (pqm4)](#6-microcontroller-targets-pqm4)
7. [RNG / Keygen Defects](#7-rng--keygen-defects)
8. [Hybrid Combiner Review & Downgrade Matrix](#8-hybrid-combiner-review--downgrade-matrix)
9. [Kyber Ransomware — Family Structure & Triage](#9-kyber-ransomware--family-structure--triage)
10. [Kyber Ransomware — Defect-Based Recovery](#10-kyber-ransomware--defect-based-recovery)
11. [Implementation Audit Checklist](#11-implementation-audit-checklist)
12. [Legal Boundaries & Lab Safety](#12-legal-boundaries--lab-safety)

---

## 1. Implementation Fingerprinting

### 1.1 TLS endpoint group fingerprint (oqs-provider / OQS-OpenSSL / vendor stacks)

```bash
# Enumerate offered groups and detect PQC support
openssl s_client -connect target.example.com:443 -groups "X25519MLKEM768:X25519" -tls1_3 </dev/null 2>/dev/null \
  | grep -E "Negotiated TLS1.3 group|Server Temp Key"

# Probe ML-KEM-only (no classical fallback offered)
openssl s_client -connect target.example.com:443 -groups "X25519MLKEM768" -tls1_3 </dev/null 2>/dev/null \
  | grep -c "HTTP" # empty reply = group refused or stack crashed

# Compare handshake transcript sizes: ML-KEM-768 adds ~1184-byte keyshare
openssl s_client -connect target.example.com:443 -groups "X25519MLKEM768" -tls1_3 </dev/null 2>/dev/null \
  | grep -A2 "ClientHello"
```

Differential matrix: which of {X25519MLKEM768, MLKEM768 (raw), secptrp256 (SecP256r1MLKEM768)} succeed separates oqs-provider versions and vendor stacks (group IDs evolved across drafts — the *set* of accepted names fingerprints the build).

### 1.2 Firmware string & symbol fingerprint

```bash
# Extract PQC library markers from firmware image
binwalk -e firmware.bin
strings -n 8 _firmware.bin.extracted/ | grep -iE "liboqs|oqs-provider|pqclean|ml-kem|kyber[0-9]|mlkem[0-9]{3}" | sort -u

# Version pins embedded in builds
strings _firmware.bin.extracted/squashfs-root/usr/lib/liboqs.so* | grep -E "^0\\.[0-9]+|liboqs-[0-9]"

# Symbol diff against upstream tags (identifies fork drift)
nm -D liboqs.so.0.13 2>/dev/null | grep -i kem > target.syms
git clone --depth 1 -b 0.13.0 https://github.com/open-quantum-safe/liboqs /tmp/liboqs-0.13
nm -D /tmp/liboqs-0.13/build/lib/liboqs.so | grep -i kem > ref.syms
diff target.syms ref.syms | head -40
```

### 1.3 Banner side-channels

```bash
# oqs-provider advertises itself in some builds' ALPN/error paths
curl -sv https://target.example.com --tlsv1.3 -o /dev/null 2>&1 | grep -iE "provider|oqs|openssl 3"
```

---

## 2. Known Defects & Advisory Mapping

### 2.1 KyberSlash (2024) — variable-time division

Class defect: Barrett/division-based reductions executed variable time on secrets → remote timing recovery of ML-KEM secrets. Tracked per-project via the advisory site (no single consolidated CVE); **always verify affected versions against the advisory + NVD before citing**.

```bash
# Advisory-grounded check (do NOT trust memory for CVE IDs)
curl -s https://kyberslash.cr.yp.to/ | grep -iE "affected|patched|commit"
# Then cross-check any candidate IDs:
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=kyberslash" | jq '.totalResults'
```

### 2.2 Defect class table (what to look for in any build)

| Class | Root cause | Exploitation | Where it shows up |
|-------|-----------|--------------|-------------------|
| Variable-time reduction | Divisions/barretts on secret data | Remote timing (§3) | Old Kyber code, forks, courseware ports |
| Secret-dependent branching | Decoder/ntt compare chains | Single-trace SCA (§4) | All software ML-KEM without masking |
| Implicit-rejection faults | Skipped re-encryption check | Fault → key oracle (§5) | Embedded, IoT builds |
| Entropy failure at keygen | getrandom()/RNG misuse | Key reuse/collision (§7) | Constrained devices, vendor forks |
| Combiner mistakes | Concat order, KDF skipped | Break weakest leg (§8) | Custom hybrid stacks |

### 2.3 NVD verification protocol (mandatory for reports)

```bash
# Rule: every CVE written into a report must pass this gate
verify_cve() {
  curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$1" \
    | jq -r '.vulnerabilities[0].cve.id + " " + (.vulnerabilities[0].cve.descriptions[0].value // "NOT FOUND")'
}
# If NOT FOUND or the affected-product range does not include the fingerprinted build -> do not cite.
```

---

## 3. Remote Timing Pre-Screen

### 3.1 Handshake-duration harness (authorized scope only)

```python
#!/usr/bin/env python3
# timing_probe.py — statistical handshake timing under two group settings
import subprocess, statistics, time, sys

def sample(host, group, n=2000):
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        subprocess.run(["openssl", "s_client", "-connect", host, "-groups", group,
                        "-tls1_3"], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ts.append(time.perf_counter() - t0)
    return ts

if __name__ == "__main__":
    host = sys.argv[1]
    a = sample(host, "X25519MLKEM768")   # exercises ML-KEM path
    b = sample(host, "X25519")           # classical baseline
    print(f"hybrid  med={statistics.median(a)*1000:.2f}ms p99={sorted(a)[int(.99*len(a))]*1000:.2f}ms")
    print(f"classic  med={statistics.median(b)*1000:.2f}ms p99={sorted(b)[int(.99*len(b))]*1000:.2f}ms")
    # Persistent p99 gap between runs is a signal; escalate to Welch's t-test per §3.2
```

### 3.2 Statistics that survive review

```python
from scipy import stats
# Use Welch's t-test on trimmed samples (drop slowest 5% — network noise)
t, p = stats.ttest_ind(trim(a), trim(b), equal_var=False)
# Report: t, p, effect size (Cohen's d), n, and the version hypothesis it supports
```

### 3.3 Local constant-time verification (dudect)

```bash
git clone --depth 1 https://github.com/oreparaz/dudect /tmp/dudect
# Fixture: call the target's decapsulation with fixed vs random ciphertexts
# (liboqs: OQS_KEM_ml_kem_768_decaps; PQClean: PQCLEAN_MLKEM768_clean_crypto_kem_dec)
cd /tmp/dudect && make
./dudect-fixedvsrandom  # t-test per percentile class; persistent >5 signals leakage
```

Cross-ref: `quantum-crypto-attack` payloads §7 has the initial dudect fixture pattern; this section adds the remote harness and statistics.

---

## 4. Single-Trace Power/EM SCA Lab

### 4.1 Equipment & capture

```bash
# Hardware: ChipWhisperer-Husky (or Lite) + target board with pqm4/PQClean ML-KEM-768
# Firmware: SimpleSerial wrapper exposing crypto_kem_dec (see §6)
cd chipwhisperer
python3 -c "
import chipwhisperer as cw
scope = cw.scope(); target = cw.target(scope)
scope.gain.db = 30; scope.adc.samples = 5000; scope.adc.offset = 0
# Arm-trigger on decapsulation start (GPIO from target)
"
```

### 4.2 Profiling (template attack)

```python
# lascar template attack sketch — profile N=5k traces, attack with 1 trace
from lascar import Session
# 1) Capture profiling set: vary secret key + fixed message → label intermediate (decoder output)
# 2) Build per-bundle SNR; select 256 points of interest per subsecret
# 3) Attack: single trace → per-bundle max-likelihood → error-correct via ML-KEM structure
# Success criterion: full 32-byte secret from ONE attack trace, reported with rank stats
```

### 4.3 Deep-learning SCA (scaaml-style)

```python
# MLP/CNN on raw power traces, per-key-byte classification
# Train on-device (profiling identical build), validate cross-device at same silicon rev
# Report: key-rank curves vs number of attack traces (1-10)
```

### 4.4 Lab report evidence pack

- scope config, firmware commit hash, board revision photo
- SNR plot per selected intermediate; template accuracy; attack key-rank plot
- explicit statement: profiling access required (not remotely exploitable)

Cross-ref: `post-quantum-migration-attack` §5.4 covers EM overview; this section is the full recovery chain.

---

## 5. Fault Injection on Decapsulation

### 5.1 Target: the re-encryption check

ML-KEM decapsulation re-encrypts the decrypted message and compares with the received ciphertext (implicit rejection on mismatch). Skipping the comparison via glitch → attacker submits malformed ciphertexts and reads the oracle.

### 5.2 Voltage glitch loop (ChipWhisperer)

```python
import chipwhisperer as cw
# Sweeps: voltage glitch width 0-10% of clock, offset across decap window
for width in range(1, 41):
    for offset in range(0, 200, 4):
        scope.glitch.width = width; scope.glitch.offset = offset
        scope.glitch.repeat = 1; scope.glitch.trigger_src = "manual"
        # send crafted ciphertext (non-canonical encodings) via SimpleSerial
        # classify response: valid_share (FAULT) vs reject (clean) vs crash
```

### 5.3 Fault budget math

```text
Classic result class: O(2^13 .. 2^16) faults for full ML-KEM-768 key
under the re-encryption-skip model — count your faults, report the
observed budget vs literature. A lab demo recovering the key with the
fault counter logged is the accepted evidence format.
```

### 5.4 Safe-error variants

Clock-stretching on the NTT; laser fault on the compare instruction (decapped parts); EM pulse injection. Each has different equipment bars — list what was used; do not generalize.

---

## 6. Microcontroller Targets (pqm4)

```bash
git clone --depth 1 https://github.com/mupq/pqm4 /tmp/pqm4
cd /tmp/pqm4 && make PLATFORM=stm32f4 CLEANUP=1 flash-test
# Attack build: wrap crypto_kem_dec with SimpleSerial v2
# - 'p' cmd: load ciphertext, trigger high, run decap, trigger low, return shared secret hash
# Deterministic keys via fixed PRNG seed to make profiling reproducible
```

Watch for: compiler auto-vectorization silently reintroducing variable-time code between -O2/-O3; record exact flags. pqm4 optimization variants (speed/clean/m4f) have different leakage profiles — fingerprint which variant the target ships.

---

## 7. RNG / Keygen Defects

### 7.1 Reboot-loop key equality

```bash
# Factory image, deterministic boot → keygen before entropy ready?
for i in $(seq 1 50); do
  reboot_target            # via lab power relay / hw reset
  sshpass ssh root@192.168.4.2 "cat /etc/pqc/pubkey" >> keys.txt
done
sort keys.txt | uniq -d | wc -l   # any duplicate = critical finding
```

### 7.2 Cross-device / factory-reset equality

```bash
# Same model, multiple units, first-boot keys
for unit in dev1 dev2 dev3 dev4 dev5; do get_pubkey $unit; done | sort | uniq -c | sort -rn | head
```

### 7.3 Entropy source health (SP 800-90B lens)

```bash
# Feed the device RNG stream through health checks before keygen
cat /dev/hwrng | rngtest -c 1000     # FIPS 140-2 style
# Repetition-count / adaptive-proportion tests on boot-captured streams
```

Report both the defect and the blast radius: keygen RNG flaws collapse ML-KEM to plaintext exposure — highest-severity finding class in this skill.

---

## 8. Hybrid Combiner Review & Downgrade Matrix

### 8.1 Negotiation matrix

```bash
#!/bin/bash
# For each offered-group set, record: success, negotiated group, session resumption behavior
for groups in "X25519MLKEM768" "X25519" "secptrp256" "X25519MLKEM768:X25519" "X25519P256"; do
  echo "== $groups =="
  openssl s_client -connect "$1" -groups "$groups" -tls1_3 </dev/null 2>/dev/null \
    | grep -E "group|HTTP/" | head -2
done
```

### 8.2 Combiner implementation review (code-level)

- Concatenation order matches the negotiated transcript binding (draft-ietf-tls-ecdhe-mlkem)
- Both legs actually contribute (grep the KDF call sites; a "hybrid" that hashes only one leg is the classic find)
- Stripped-group rejection: middlebox-stripped keyshares must abort, not silently fall back

Cross-ref: downgrade **operations** are `post-quantum-migration-attack` §3; combiner flaw catalog §4. This section is the implementation review checklist.

---

## 9. Kyber Ransomware — Family Structure & Triage

### 9.1 Dual-layer structure (what 2026 families look like)

```text
victim files  ← AES-256-CTR/ChaCha20 (session key K)
session key K ← wrapped twice: ML-KEM-768 (per-victim ek) + optional RSA-4096 legacy layer
per-victim:   fresh kem ciphertext c_i, nonce; key material NOT derivable without sk
```

The ML-KEM wrap is what kills classical recovery (RSA factorization shortcuts, ECIES nonce reuse). Triage must therefore target the *implementation*.

### 9.2 Triage workflow

```bash
# 1) Identify scheme & parameters from sample markers
strings sample.bin | grep -iE "mlkem|kyber|kem768|kem1024|FIPS 203"
# 2) Entropy map — locate the symmetric vs wrapped-key regions
python3 - <<'EOF'
import math
data = open("sample.bin","rb").read()
for off in range(0, min(len(data), 4096), 256):
    chunk = data[off:off+256]
    H = -sum((c/256)*math.log2(c/256) for c in [chunk.count(b)/256 for b in set(chunk)] if c>0)
    print(f"{off:#06x}  H={H:.2f}")
EOF
# 3) Extract note/config: ek fingerprints, victim ID derivation, nonce policy
# 4) Key-reuse checks across victims (see §10)
```

### 9.3 Sample markers table

| Marker | Meaning |
|--------|---------|
| `mlkem768` / `kyber768` string or 1184-byte keyshare blob | ML-KEM-768 layer |
| Repeated 32-byte blocks across victim samples | Session-key reuse (§10.1 jackpot) |
| Identical kem ciphertext prefix across victims | Fixed ephemeral / deterministic nonce |
| AES-GCM with zero IV increments | Nonce management flaw → keystream reuse |

---

## 10. Kyber Ransomware — Defect-Based Recovery

### 10.1 Recovery checks in priority order

```text
1. Cross-victim ciphertext equality   — same wrapped session key = free decryption for all
2. Deterministic nonces               — ephemeral replay defeats forward secrecy of the wrap
3. Keygen RNG flaw                    — device/host entropy defect (§7 methods applied to sample clusters)
4. Half-broken hybrid                 — classical leg downgradeable (§8) = classical attacks apply
5. Downgrade to legacy RSA layer      — old recovery tooling may still work
```

### 10.2 Recovery verdict template

```markdown
## Recovery Feasibility
- Defect class: <cross-victim key reuse | deterministic nonce | RNG flaw | none found>
- Evidence: <hash overlaps, nonce deltas, entropy analysis>
- Verdict: RECOVERABLE (free) / RECOVERABLE (with defect exploit) / ADVERSARY-KEY-REQUIRED
- Recommended next step before any payment decision: <re-test scope, more samples>
```

Full event analysis: `guides/kyber-ransomware-retrospective.md`.

---

## 11. Implementation Audit Checklist

| # | Check | Tool/Method | Pass condition |
|---|-------|-------------|----------------|
| 1 | Library & version fingerprinted | §1 | Exact version + provenance recorded |
| 2 | Known-defect mapping | §2 + NVD gate | Every cited CVE verified in NVD range |
| 3 | Constant-time gate in CI | dudect/valgrind | Fails build on leakage |
| 4 | Group policy strict | §8 matrix | No classical-only fallback accepted |
| 5 | Combiner reviewed | §8.2 | Both legs contribute; transcript-bound |
| 6 | Entropy at keygen | §7 | No duplicate keys under reboot/factory-reset |
| 7 | Embedded build variant known | §6 | Optimization variant + flags recorded |
| 8 | Glitch/tamper countermeasures | §5 defense side | Sensor coverage documented |

---

## 12. Legal Boundaries & Lab Safety

- Remote timing tests are active scanning: same authorization bar as vulnerability scanning (CFAA/UK CMA equivalents).
- Fault injection and decapping void warranties and may destroy owned hardware — budget sacrificial units.
- Profiling SCA requires identical hardware possession; do not claim exploitability of production from different-rev lab results.
- Ransomware triage on live incidents: preserve evidentiary chain (hash before analysis); recovery verdicts influence payment decisions — state confidence intervals, not certainties.
- PQC ransomware analysis may involve malware execution: use the same isolated detonation standards as classical ransomware work.

---

## Report Template Skeleton

```markdown
# PQC Implementation Attack Assessment
1. Executive summary (fingerprint → defect exposure → verdict)
2. Target identification (library/version/build evidence)
3. Defect mapping (advisory/NVD-verified table)
4. Remote pre-screen results (timing stats, downgrade matrix)
5. Lab exploitation (trace/fault evidence, recovery material)
6. RNG/keygen findings
7. Ransomware triage (if incident scope)
8. Remediation priorities (patch pins, CI gates, hardware roadmap)
9. References (advisory URLs, NVD IDs)
```

---

## References

- FIPS 203 — https://csrc.nist.gov/pubs/fips/203/final
- KyberSlash advisory — https://kyberslash.cr.yp.to
- liboqs / oqs-provider / pqm4 / PQClean repositories — https://github.com/open-quantum-safe, https://github.com/mupq/pqm4, https://github.com/PQClean/PQClean
- dudect — https://github.com/oreparaz/dudect
- lascar — https://github.com/LederWorks/lascar
- NVD API — https://services.nvd.nist.gov/rest/json/cves/2.0
- IACR ePrint (Kyber SCA/fault literature) — https://eprint.iacr.org
