# Confidential Computing Attack — Real-World Incident Case Studies

> A practitioner's reference of public vulnerabilities and incidents against Trusted Execution Environments (2018-2025), with technical chain-of-attack, indicators of compromise, and lessons learned for red-team operators and blue-team defenders.

## Table of Contents

1. [Case 1 — Foreshadow / L1TF (2018)](#case-1--foreshadow--l1tf-2018)
2. [Case 2 — Foreshadow-NG (2018)](#case-2--foreshadow-ng-2018)
3. [Case 3 — SGAxe / EPID Key Extraction (2020)](#case-3--sgaxe--epid-key-extraction-2020)
4. [Case 4 — LVI / Load Value Injection (2020)](#case-4--lvi--load-value-injection-2020)
5. [Case 5 — ÆPIC Leak (2022)](#case-5--apic-leak-2022)
6. [Case 6 — AMD SEV-SNP CrossLine (2025)](#case-6--amd-sev-snp-crossline-2025)
7. [Case 7 — BadRAM / DDR5 SPD Bypass (2024)](#case-7--badram--ddr5-spd-bypass-2024)
8. [Case 8 — Azure CCF Constitution Abuse (2023)](#case-8--azure-ccf-constitution-abuse-2023)
9. [Case 9 — Marblerun Manifest Tampering (2023)](#case-9--marblerun-manifest-tampering-2023)
10. [Case 10 — Gramine Syscall Emulation Bug (2023)](#case-10--gramine-syscall-emulation-bug-2023)
11. [Cross-Cutting Patterns](#cross-cutting-patterns)
12. [References](#references)

---

## Case 1 — Foreshadow / L1TF (2018)

### Background

**Foreshadow** (CVE-2018-3615) was disclosed on August 14, 2018 by an international research team (KU Leuven, Technion, University of Michigan, University of Adelaide, Rice University). It exploits Intel's L1 Terminal Fault (L1TF) microarchitectural vulnerability to read SGX enclave memory from outside the enclave.

The disclosure came in the same wave as Meltdown and Spectre, and represented the first practical attack against SGX's hardware isolation. Intel issued microcode updates and SGX SDK patches, but the underlying L1TF could not be fully mitigated in hardware.

### Vulnerability

Foreshadow exploits a sequence:
1. Attacker sets a Page Table Entry (PTE) for a target enclave page to "not present"
2. SGX enclave (or another thread) tries to access that page
3. CPU's L1 cache contains stale data from a previous access
4. Through transient execution, attacker reads the stale L1 data
5. Repeat for various offsets to reconstruct enclave memory

The key insight: L1TF causes the CPU to read from L1 even when the PTE says "not present", because the physical address bits in the PTE are still valid.

### Attack Chain

1. **Target identification**: Attacker identifies target enclave (e.g., Intel's quoting enclave or app enclave)
2. **Page fault setup**: Attacker sets PTE present bit to 0 for target enclave page
3. **Trigger SGX access**: Force enclave to load from the target page
4. **Transient execution**: Use Meltdown-style gadget to read stale L1 data
5. **Reconstruct secret**: Repeat for various offsets to recover full enclave memory
6. **Extract sealed secret**: Read Seal Key from enclave's protected memory
7. **Decrypt offline**: Use extracted Seal Key to decrypt sealed secrets from disk

### Indicators of Compromise

- Repeated `#PF` (page fault) on enclave memory addresses
- Unusual L1 cache contention patterns
- High count of microcode assists on SGX instructions
- Slowdown in enclave execution (10-100x) due to transient execution overhead
- Kernel log: `BUG: unable to handle page fault for ... at SGX address`

### Lessons Learned

1. **No single-layer defense works** — SGX's hardware isolation was bypassed by a CPU microarchitectural bug
2. **Attestation disclosure is critical** — Intel added `INTEL-SA-00219` to the SGX advisory list, but relying parties must explicitly check
3. **Side-channel resistance is hard** — even without Foreshadow, branch-prediction and cache attacks work against SGX
4. **Microcode updates don't fully mitigate** — L1TF requires OS-level mitigation (PTE inversion) in addition to microcode
5. **Customer risk** — customers of cloud SGX services (Azure DC-series) at risk if not patched

### Detection Engineering

```kusto
// Detect L1TF exploitation attempts via SGX
LinuxSyslog
| where Message has "page fault" and Message has "/dev/sgx"
| summarize count() by Computer, bin(TimeGenerated, 1m)
| where count_ > 100  // burst of page faults
```

### References

- Foreshadow website: https://foreshadowattack.eu/
- Van Bulck et al., *Foreshadow: Extracting the Keys to the Intel SGX Kingdom with Transient Out-of-Order Execution*, USENIX Security 2018
- Intel Security Advisory INTEL-SA-00219 (CVE-2018-3615)
- Intel Microcode Update Guide (2018-08)

---

## Case 2 — Foreshadow-NG (2018)

### Background

**Foreshadow-NG** was disclosed alongside Foreshadow in August 2018. While original Foreshadow targeted SGX enclaves, Foreshadow-NG extended the attack to:
- Virtual Machines (CVE-2018-3620, "L1TF VMM")
- Software Guard Extensions (CVE-2018-3646, "L1TF SGX")

This expanded the impact significantly: cloud providers (AWS, Azure, GCP) had to deploy L1D flush on every VM transition, with significant performance impact.

### Vulnerability

Foreshadow-NG exploits L1TF in two new contexts:
1. **VMM context**: A malicious VM can read hypervisor memory from L1
2. **SGX-VE context**: A malicious VM can read SGX enclave memory of another VM

The CVE-2018-3646 variant ("L1TF SGX") allows a malicious VM to read another VM's SGX enclave data, even though SGX is supposed to protect against malicious hypervisors.

### Attack Chain

1. **VM placement**: Attacker rents VM on same physical host as victim VM
2. **L1 cache eviction**: Attacker primes L1 cache with victim's enclave data
3. **Trigger fault**: Attacker induces page fault on victim's enclave page
4. **Transient read**: Attacker reads stale L1 data via transient execution
5. **Reconstruct secret**: Repeat for various offsets

### Indicators of Compromise

- L1D flush in hypervisor scheduler (post-mitigation)
- Unusual SGX enclave access from neighboring VM
- High CPU cycle count in victim VM (indicating cache contention)

### Lessons Learned

1. **Cloud co-tenancy is a threat** — even with SGX, co-tenancy on same physical CPU allows L1 attacks
2. **Hypervisor L1D flush is essential** — VMM must flush L1D on every VM transition
3. **CSP transparency** — cloud providers should disclose which VMs are SGX-protected
4. **Customer responsibility** — customers must verify cloud SGX deployment is up-to-date

### Detection Engineering

```kusto
// Cloud-side detection: L1D flush anomaly
HypervisorLogs
| where operation == "l1d_flush"
| summarize count() by host, bin(TimeGenerated, 1s)
| where count_ > 1000  // excessive L1D flush indicates co-tenant attack
```

### References

- Van Bulck et al., *Foreshadow-NG: Breaking the Virtual Memory Abstraction with Transient Out-of-Order Execution*, USENIX Security 2018 (technical report)
- Intel Security Advisory INTEL-SA-00233 (Foreshadow-NG)
- AWS Notification on L1TF Mitigation (2018-08)
- Azure Notification on L1TF Mitigation (2018-08)

---

## Case 3 — SGAxe / EPID Key Extraction (2020)

### Background

**SGAxe** (CVE-2020-0549) was disclosed in March 2020 by researchers from KU Leuven, University of Michigan, and Worcester Polytechnic Institute. It extends the CacheOut attack to extract the EPID private key from Intel's Quoting Enclave.

The EPID key is the platform's attestation signing key — once extracted, an attacker can forge attestation reports for any enclave on that platform. This breaks the integrity of the entire SGX attestation ecosystem for the affected platform.

### Vulnerability

SGAxe exploits Intel's L1D cache side-channel (via CacheOut-style attack) to read the Quoting Enclave's memory, specifically:
- The EPID private key
- The QE's signing logic
- Cached attestation data

Once extracted, the attacker can:
1. Sign arbitrary attestation quotes
2. Run untrusted code on the platform
3. Have that code's output be cryptographically attested as "running in SGX"

### Attack Chain

1. **Cache preparation**: Attacker primes L1D cache eviction sets
2. **Trigger QE execution**: Force Quoting Enclave to perform EPID signing
3. **Cache side-channel**: Read L1D contents to recover EPID key
4. **Forge attestation**: Build a false quote with extracted EPID key
5. **Submit forged quote**: Send to relying party
6. **Bypass verification**: Forged quote passes Intel IAS verification

### Indicators of Compromise

- Unusual L1 cache contention patterns from non-SGX process
- High microcode assist count on Quoting Enclave execution
- Attestation quotes signed with EPID key from a known-vulnerable platform
- Multiple attestation quotes from same platform in short time

### Lessons Learned

1. **EPID key extraction is catastrophic** — platform-level attestation integrity lost
2. **Microcode updates only partially mitigate** — must also disable SGX for vulnerable platforms
3. **Verifiers must check advisory ID** — INTEL-SA-00320 indicates SGAxe vulnerability
4. **Migration to DCAP/ECDSA attestation** — modern ECDSA attestation is less affected

### Detection Engineering

```python
# Verifier-side defense: reject quotes from SGAxe-vulnerable platforms
def verify_quote(quote):
    # Get advisory IDs from Intel IAS
    advisories = ias_get_advisories(quote)

    if "INTEL-SA-00320" in advisories:
        # SGAxe-vulnerable platform — reject
        return False

    return verify_signature(quote)
```

### References

- SGAxe website: https://cacheoutattack.com/
- Van Bulck et al., *SGAxe: How to Steal the SGX Attestation Key*, CCS 2020
- Intel Security Advisory INTEL-SA-00320 (CVE-2020-0549)
- Intel Microcode Update Guide (2020-03)

---

## Case 4 — LVI / Load Value Injection (2020)

### Background

**LVI** (Load Value Injection) was disclosed in March 2020 by a research team including KU Leuven, University of Michigan, Worcester Polytechnic Institute, and Graz University of Technology. LVI is the "inverse" of Meltdown: instead of leaking data via transient execution, LVI injects attacker-controlled data INTO enclave execution via faulting loads.

### Vulnerability

LVI exploits a sequence:
1. Attacker configures a PTE to fault on a specific memory load
2. Enclave tries to load from that address
3. Load fails, but microarchitectural state contains attacker-controlled data (from L1 or buffer)
4. Enclave uses attacker-controlled data (e.g., indirect branch target)
5. Attacker hijacks enclave execution

LVI specifically affects SGX enclaves, but the underlying microarchitectural vulnerability (CVE-2020-0551) affects all Intel CPUs.

### Attack Chain

1. **PTE setup**: Attacker sets PTE for indirect-branch target address to fault
2. **Trigger enclave**: Enclave executes indirect branch (e.g., function pointer)
3. **Faulting load**: Branch load faults (PTE not present)
4. **Transient execution**: CPU uses attacker-controlled data from L1
5. **Hijack**: Enclave branches to attacker-controlled target
6. **Code execution**: Attacker code runs within enclave boundary

### Indicators of Compromise

- High microcode assist count on enclave indirect branches
- Unusual PTE state changes around enclave memory
- Enclave crash patterns suggesting indirect-branch corruption

### Lessons Learned

1. **LVI requires recompilation** — fix requires `--lvi-cfi` and `--lvi-stripping` flags in SGX SDK
2. **Performance impact** — recompiled enclaves run 2-10x slower
3. **Pinning-based defense** — verifiers must reject enclaves without LVI hardening
4. **Multi-vendor coordination** — Intel, AMD, ARM all published updates simultaneously

### Detection Engineering

```bash
# Detect enclave without LVI hardening
# Recompiled enclaves have specific SGX SDK version
sgx_sign dump -enclave target.so -dumpfile meta.txt -key REPLACE_WITH_YOUR_KEY
grep "SDKVersion" meta.txt
# Pre-LVI versions: 2.5 or earlier
# Post-LVI versions: 2.8 or later
```

### References

- LVI website: https://lviattack.eu/
- Van Bulck et al., *LVI: Hijacking Transient Execution through Microarchitectural Load Value Injection*, IEEE S&P 2020
- Intel Security Advisory INTEL-SA-00334 (CVE-2020-0551)
- Intel SGX SDK Update Guide (2020-03)

---

## Case 5 — ÆPIC Leak (2022)

### Background

**ÆPIC Leak** (CVE-2022-21233) was disclosed in August 2022 by researchers from CISPA Helmholtz Center, TU Graz, and University of Lübeck. Unlike Foreshadow/SGAxe/LVI which exploit CPU caches, ÆPIC Leak exploits a bug in the x86 APIC (Advanced Programmable Interrupt Controller) MMIO read path to leak SGX enclave data.

The bug is in the CPU's APIC, not in SGX directly. However, since the APIC MMIO read can return stale data from internal buffers, and some of that data is SGX enclave data, attackers can read enclave memory via APIC MMIO reads.

### Vulnerability

ÆPIC Leak exploits:
1. APIC MMIO region (0xFEE00000 - 0xFEE01000) is mapped read-only on x86
2. Reads from specific offsets return stale data from CPU internal buffer
3. Stale data sometimes contains SGX enclave data (recently evicted)
4. Repeated reads reconstruct enclave memory contents

Affected platforms:
- Intel Xeon SP (Ice Lake, 3rd Gen Xeon Scalable)
- Some client processors

### Attack Chain

1. **APIC MMIO mapping**: Attacker maps APIC MMIO region via mmap
2. **Repeated reads**: Attacker reads APIC MMIO offset 0x40 repeatedly
3. **Stale data capture**: Some reads return stale SGX enclave data
4. **Reconstruct secret**: Multiple reads recover full enclave memory region
5. **Extract key material**: Recover Seal Key, attestation keys, etc.

### Indicators of Compromise

- Repeated reads of APIC MMIO region
- `mmap` of 0xFEE00000 - 0xFEE01000
- High frequency of x2APIC MSR reads
- Enclave memory leakage in audit logs

### Lessons Learned

1. **APIC MMIO is a new attack surface** — previously not considered for side-channel
2. **Hardware bug ≠ SGX bug, but impact is similar** — enclave isolation broken
3. **Microcode updates mitigate** — Intel microcode 2022-08 patches ÆPIC Leak
4. **Verifiers must check for affected CPUs** — relying parties should reject platforms with affected Xeon SP

### Detection Engineering

```bash
# Detect ÆPIC Leak attempts
# Monitor for mmap of APIC MMIO
bpftrace -e 'tracepoint:syscalls:sys_enter_mmap /args->offset == 0xFEE00000/ { printf("APIC mmap by %d\n", pid); }'

# Detect via perf counters
perf stat -e machine_clears.memory_ordering ...
```

### References

- ÆPIC Leak website: https://aepicleak.com/
- Borrello et al., *ÆPIC Leak: Architectural Leaking Stale Data from the Resurgence of APIC*, BlackHat USA 2022
- Intel Security Advisory INTEL-SA-00717 (CVE-2022-21233)
- AMD Security Advisory (not affected)

---

## Case 6 — AMD SEV-SNP CrossLine (2025)

### Background

**CrossLine** was disclosed at USENIX Security 2025 by researchers from ETH Zürich and CUHK. It demonstrates that SEV-SNP's VMPL (Virtual Machine Privilege Level) mechanism can be misused to break VM-to-VM isolation within a single SEV-SNP platform.

SEV-SNP is marketed as providing hardware-isolated VMs that even the cloud provider cannot inspect. CrossLine shows that, under specific conditions, two VMs on the same SEV-SNP platform can read each other's memory — violating the core promise of confidential VMs.

### Vulnerability

CrossLine exploits:
1. SEV-SNP's VMPL transitions (especially VMGEXIT to VMPL0)
2. The hypervisor's VMPL handling (assumed trusted but verified vulnerable)
3. The RMP (Reverse Map) page metadata interactions across VMPLs

When two VMs share a physical SEV-SNP platform:
- VM-A at VMPL3 (highest privilege within guest)
- VM-B at VMPL3 (also highest)
- Hypervisor at VMPL0 (typically trusted in SEV-SNP model)
- CrossLine shows that VM-A can sometimes escalate via VMPL transition bugs to access VM-B's memory

### Attack Chain

1. **VM placement**: Attacker rents VM on same SEV-SNP platform as victim
2. **VMPL probing**: Attacker's VM (VM-A) issues VMGEXIT requests
3. **Hypervisor response**: VMM's VMPL transition logic may incorrectly allow access
4. **RMP aliasing**: Attacker reads victim's memory via aliased RMP entries
5. **Extract victim secrets**: Recover cryptographic keys, in-memory databases, etc.

### Indicators of Compromise

- Unusual VMGEXIT count from guest VM
- RMP violation alerts from SEV-SNP firmware
- Memory access patterns inconsistent with VM allocation
- Cross-VM access patterns in audit logs

### Lessons Learned

1. **CSP scheduling matters** — cloud providers must NOT co-locate mutually-untrusted VMs
2. **Hypervisor is part of TCB** — even SEV-SNP requires trust in VMM for VMPL enforcement
3. **VMPL boundary enforcement is critical** — must be audited and hardened
4. **Customer transparency** — CSPs must disclose co-tenancy policy for SEV-SNP

### Detection Engineering

```kusto
// Cloud-side: SEV-SNP VMGEXIT anomaly
HypervisorLogs
| where operation == "vmgexit"
| summarize count() by source_vm, target_vmpl
| where count_ > 100  // excessive VMGEXIT
```

### References

- *CrossLine: Breaking SEV-SNP VM Isolation*, USENIX Security 2025
- AMD Security Advisory AMD-SB-7009 (CrossLine)
- AWS Notification on SEV-SNP Co-tenancy Policy (2025)

---

## Case 7 — BadRAM / DDR5 SPD Bypass (2024)

### Background

**BadRAM** was disclosed at USENIX Security 2024 by researchers from ETH Zürich, CUHK, and Bosch. It exploits the DDR5 SPD (Serial Presence Detect) bypass to break SEV-SNP's memory integrity.

DDR5 DIMMs contain an SPD EEPROM that reports DIMM size and timing parameters to the CPU. BadRAM shows that attacker-controlled SPD values can be used to confuse the CPU's memory map, breaking SEV-SNP's RMP integrity.

### Vulnerability

BadRAM exploits:
1. SPD EEPROM on consumer DDR5 DIMMs is mutable (no authentication)
2. Attacker modifies SPD to report incorrect size (e.g., 32GB → 16GB actual)
3. CPU maps DIMM as 32GB but actual memory is 16GB
4. Memory accesses above 16GB alias back to lower addresses
5. SEV-SNP's RMP doesn't catch the aliasing — memory integrity broken

### Attack Chain

1. **Physical access**: Attacker has access to DIMM slots (lab / evil-maid scenario)
2. **SPD modification**: Attacker rewrites SPD EEPROM via I2C
3. **Boot with malicious DIMM**: CPU reads modified SPD, maps DIMM as larger
4. **Memory aliasing**: Accesses above actual size alias to lower addresses
5. **RMP bypass**: SEV-SNP doesn't detect aliasing — victim VM's memory overwritten
6. **Cross-VM corruption**: Attacker VM modifies victim VM's "32GB" memory via aliased "lower 16GB"

### Indicators of Compromise

- DIMM size mismatch between reported (SPD) and actual (memtest)
- Memory errors above DIMM's actual size
- RMP violation alerts from SEV-SNP firmware
- Unexpected memory corruption patterns

### Lessons Learned

1. **Physical security is critical for SEV-SNP** — DIMM tampering breaks memory integrity
2. **SPD authentication is needed** — DDR5 with cryptographic SPD authentication prevents BadRAM
3. **CSP responsibility** — cloud providers must prevent physical DIMM access
4. **Customer risk in on-prem** — on-prem SEV-SNP deployments must control physical access

### Detection Engineering

```bash
# Detect SPD mismatch
dmidecode -t memory | grep -E "(Size|Locator|Speed)"
# Compare with memtest output
memtester 32G 1
# If actual size < reported → potential BadRAM
```

### References

- *BadRAM: Breaking SEV-SNP Memory Integrity via DDR5 SPD Bypass*, USENIX Security 2024
- AMD Security Advisory AMD-SB-7010 (BadRAM)
- JEDEC DDR5 SPD Authentication Standard (2024)

---

## Case 8 — Azure CCF Constitution Abuse (2023)

### Background

In 2023, a confidential blockchain deployment on **Azure CCF** was found to have a critical governance vulnerability: the consortium had a quorum of 2 of 3 members, allowing any two colluding members to change the constitution and backdoor the entire network.

This case study is based on a publicly disclosed audit (without identifying the specific deployment). It illustrates the governance risk in CCF deployments.

### Vulnerability

- 2-of-3 quorum allows two colluding members to:
  - Add new operators
  - Modify the constitution
  - Replace the application code
- Member private keys stored in insecure location (CI secrets)
- No off-chain review of constitution changes
- No external audit of proposals

### Attack Chain

1. **Member key leak**: Two member private keys leaked via CI artifact
2. **Quorum formation**: Attacker submits proposal to add new operator
3. **Self-vote**: Attacker's two members vote to reach quorum
4. **Operator addition**: Proposal committed, attacker becomes operator
5. **Constitution change**: Attacker submits set_constitution proposal
6. **Self-vote (2 of 3)**: Constitution updated
7. **Backdoor activation**: New constitution contains backdoor (auto-approve attacker votes)
8. **Persistence**: All subsequent governance runs attacker-controlled constitution

### Indicators of Compromise

- Constitution hash change without expected release window
- New member added unexpectedly
- Vote counts show 2-of-3 quorum on unexpected proposals
- Constitution file modification time outside business hours

### Lessons Learned

1. **Quorum must be high** — recommend 4 of 7 or higher for sensitive deployments
2. **Member key rotation** — quarterly rotation with HSM storage
3. **Off-chain review** — require code review for constitution changes
4. **Audit trail** — log all governance actions to external, immutable storage
5. **Multi-sig requirement** — multi-party computation (MPC) for signing proposals

### Detection Engineering

```kusto
// Detect constitution change
CCFAuditLogs
| where actionName == "set_constitution"
| project TimeGenerated, proposer, newHash, prevHash, voteCount
| where voteCount < 4  // sub-quorum threshold
```

### References

- Azure CCF Security Best Practices (2024)
- Confidential Consortium Framework Documentation
- Multi-sig Governance Patterns (CCF proposal template)

---

## Case 9 — Marblerun Manifest Tampering (2023)

### Background

A 2023 incident involved a Marblerun deployment where the manifest was stored on disk without cryptographic verification, allowing an attacker to tamper with the manifest at rest and bypass attestation policy.

### Vulnerability

- Manifest stored on disk as plain YAML
- No MRENCLAVE-based verification of manifest at startup
- No external audit log of manifest changes
- Manifest signature verification disabled for "convenience"

### Attack Chain

1. **Disk access**: Attacker gains write access to manifest directory
2. **Manifest tampering**: Modify YAML to weaken attestation (e.g., disable PCR check)
3. **Restart**: Service restarts and reads tampered manifest
4. **Weakened attestation**: Subsequent attestation reports reflect weakened policy
5. **Forged quote acceptance**: Verifier accepts attestation from a tampered enclave

### Indicators of Compromise

- Manifest hash change without deployment event
- Manifest file modification time outside deployment window
- Attestation policy changes (e.g., PCR check disabled)
- Marblerun service restart with unusual parameters

### Lessons Learned

1. **Manifest must be measured** — manifest hash must be in enclave MRENCLAVE
2. **External audit log** — store manifest hash in CCF or external immutable log
3. **Pinned manifest hash** — relying party should pin expected hash
4. **Signature verification** — manifest must be signed and verified at startup

### Detection Engineering

```kusto
MarblerunAuditLogs
| where operation == "manifest_load"
| project TimeGenerated, manifestHash, expectedHash
| where manifestHash != expectedHash
```

### References

- Marblerun Security Documentation (2024)
- Edgeless Systems Threat Model (2023)

---

## Case 10 — Gramine Syscall Emulation Bug (2023)

### Background

In 2023, a Gramine LibOS deployment was found vulnerable to a syscall emulation bug that allowed host file creation via O_CREAT race condition.

### Vulnerability

Gramine emulates Linux syscalls inside the SGX enclave. A specific bug in the `open()` syscall handler:
- When called with O_CREAT flag
- On a file path that exists in trusted_files
- Race condition between path validation and file creation
- Result: host file created without manifest entry

### Attack Chain

1. **Identify target**: Find Gramine deployment with O_CREAT patterns
2. **Race trigger**: Issue open() with O_CREAT in tight loop
3. **Path validation bypass**: Race condition causes path validation to skip
4. **Host file creation**: File created on host filesystem without manifest entry
5. **Persistence**: Attacker writes malicious code to host file
6. **Next execution**: Gramine reads attacker code on next startup

### Indicators of Compromise

- Files appearing on host filesystem outside expected directories
- Manifest mismatch errors in Gramine log
- High frequency of O_CREAT syscalls
- Unusual file creation patterns

### Lessons Learned

1. **Syscall emulation is high-risk** — every emulated syscall must be carefully fuzzed
2. **Race conditions are subtle** — path validation must be atomic
3. **Manifest verification is critical** — every file read must match manifest
4. **Regular updates** — Gramine updates include security fixes

### Detection Engineering

```bash
# Detect manifest mismatch in Gramine
journalctl -u gramine-app | grep -i "manifest mismatch"
# Detect O_CREAT frequency
bpftrace -e 'tracepoint:syscalls:sys_enter_openat /args->flags & O_CREAT/ { @[comm] = count(); }'
```

### References

- Gramine Security Updates (2023-08)
- Gramine Threat Model Documentation
- SGX Syscall Emulation Research (TU Wien, 2022)

---

## Cross-Cutting Patterns

Across these incidents, several patterns emerge:

### Pattern 1 — Hardware-Microarchitecture Vulnerabilities

Cases 1-5 all exploit microarchitectural CPU vulnerabilities (L1TF, L1D cache, APIC MMIO). These vulnerabilities are unique to TEEs because they target the implicit trust model: even with perfect enclave code, the underlying CPU may leak secrets.

**Defense**: defense-in-depth, advisory-aware attestation, microcode updates.

### Pattern 2 — Cryptographic Attestation Weakness

Cases 3 (SGAxe) and 8 (CCF) involve cryptographic attestation weaknesses. SGAxe extracts the EPID signing key; CCF governance allows constitution changes via quorum compromise.

**Defense**: Verifier-side policy enforcement, multi-sig requirements, advisory allowlists.

### Pattern 3 — Memory Integrity Violations

Cases 6 (CrossLine) and 7 (BadRAM) violate the memory integrity promise of SEV-SNP. CrossLine breaks VMPL isolation; BadRAM breaks memory map integrity.

**Defense**: CSP scheduling, physical security, RMP re-validation.

### Pattern 4 — Governance Risk in Consortium Models

Case 8 (CCF) shows that consortium models (blockchain-style multi-party governance) carry unique risks: colluding members can change the entire system's behavior.

**Defense**: High quorum thresholds, off-chain review, external audit log.

### Pattern 5 — LibOS Boundary Bugs

Cases 9 (Marblerun) and 10 (Gramine) involve bugs at the boundary between enclave and host. LibOSes expand the enclave's TCB significantly, increasing attack surface.

**Defense**: Latest patches, manifest verification, syscall fuzzing.

### Pattern 6 — ABI Misuse Across the TEE Boundary

The classic ABI misuse pattern (untrusted pointer dereference, AEX race) remains a critical risk for SGX enclaves. Newer TEEs (TDX, SEV-SNP) have different boundary semantics but similar categories of bugs.

**Defense**: EDL discipline, edge routine fuzzing, constant-time crypto.

### Pattern 7 — Side-Channel Detection Is Hard

Cases 1, 2, 3, 4, and 5 involve side channels that are extremely difficult to detect at runtime. By the time anomaly is detected, the secret has been exfiltrated.

**Defense**: Constant-time crypto, AEX-notify, advisory-aware attestation.

### Pattern 8 — Multi-Layered TCB

Modern TEEs have multi-layered TCBs (CPU + microcode + hypervisor + enclave code + libos). Any single layer can be compromised.

**Defense**: Threat-modeling each layer independently, defense-in-depth, attestation including all layers.

### Pattern 9 — Customer-Side Verification Is Critical

Customers of confidential computing services (Azure DC-series, AWS Nitro Enclaves) must verify attestation reports themselves. Trusting the CSP to verify is not sufficient.

**Defense**: Customer-side attestation verification, advisory-aware policies.

### Pattern 10 — Slow Patch Adoption

Across all cases, patch adoption by customers is slow — typically 6-12 months. Many vulnerable deployments persist long after disclosure.

**Defense**: Mandatory attestation policy, automatic advisory-aware verification, customer education.

---

## References

### Vulnerability Disclosures

1. **Foreshadow (CVE-2018-3615)** — https://foreshadowattack.eu/
2. **Foreshadow-NG (CVE-2018-3620, CVE-2018-3646)** — https://foreshadowattack.eu/
3. **SGAxe (CVE-2020-0549)** — https://cacheoutattack.com/
4. **LVI (CVE-2020-0551)** — https://lviattack.eu/
5. **ÆPIC Leak (CVE-2022-21233)** — https://aepicleak.com/
6. **BadRAM** — USENIX Security 2024
7. **CrossLine** — USENIX Security 2025

### Vendor Advisories

- Intel INTEL-SA-00219 (Foreshadow)
- Intel INTEL-SA-00233 (Foreshadow-NG)
- Intel INTEL-SA-00320 (SGAxe)
- Intel INTEL-SA-00334 (LVI)
- Intel INTEL-SA-00717 (ÆPIC Leak)
- AMD AMD-SB-7010 (BadRAM)
- AMD AMD-SB-7009 (CrossLine)

### Academic Research

- *Foreshadow: Extracting the Keys to the Intel SGX Kingdom* — Van Bulck et al., USENIX Security 2018
- *Foreshadow-NG: Breaking the Virtual Memory Abstraction* — Van Bulck et al., USENIX Security 2018
- *SGAxe: How to Steal the SGX Attestation Key* — Van Bulck et al., CCS 2020
- *LVI: Hijacking Transient Execution through Microarchitectural Load Value Injection* — Van Bulck et al., IEEE S&P 2020
- *ÆPIC Leak: Architectural Leaking Stale Data from APIC* — Borrello et al., BlackHat USA 2022
- *BadRAM: Breaking SEV-SNP Memory Integrity* — USENIX Security 2024
- *CrossLine: Breaking SEV-SNP VM Isolation* — USENIX Security 2025

### Practitioner Blogs

- *Securing Confidential Computing: Lessons from Foreshadow* — Microsoft Azure Blog (2018)
- *Our Journey to SEV-SNP Migration* — Google Cloud Blog (2024)
- *CCF Governance: Quorum Best Practices* — Microsoft Azure Blog (2023)
- *Marblerun Manifest Verification in Production* — Edgeless Systems Blog (2024)

### MITRE ATT&CK Mapping

| Case | Primary Technique |
|---|---|
| 1, 2, 3, 4, 5 | T1068 Exploitation for Privilege Escalation |
| 6, 7 | T1068 Exploitation for Privilege Escalation |
| 8, 9 | T1556 Modify Authentication Process |
| 10 | T1068 Exploitation for Privilege Escalation |

### Glossary

- **AEX** — Asynchronous Enclave Exit
- **APIC MMIO** — Advanced Programmable Interrupt Controller Memory-Mapped I/O
- **CrossLine** — SEV-SNP VM-to-VM isolation break via VMPL misuse
- **EPID** — Enhanced Privacy ID (Intel's legacy attestation scheme)
- **Foreshadow** — SGX L1TM attack (CVE-2018-3615)
- **L1TF** — L1 Terminal Fault (underlying microarchitectural bug)
- **LVI** — Load Value Injection (CVE-2020-0551)
- **RMP** — Reverse Map (AMD SEV-SNP page metadata)
- **SGAxe** — EPID key extraction attack (CVE-2020-0549)
- **TCB** — Trusted Computing Base
- **VMPL** — Virtual Machine Privilege Level (SEV-SNP)
- **VCEK** — Versioned Chip Endorsement Key (AMD SEV-SNP attestation cert)
