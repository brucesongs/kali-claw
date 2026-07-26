---
name: confidential-computing-attack
description: "Attacks against Trusted Execution Environments (TEEs) and confidential computing platforms — Intel SGX (Foreshadow/SGAxe/LVI/ÆPIC Leak), Intel TDX, AMD SEV/SEV-ES/SEV-SNP (CrossLine/BadRAM), Azure CCF, Marblerun, and Gramine/Occlum libos enclaves. Covers side-channel leakage, attestation forgery, ABI misuse, host-to-enclave breakout, enclave-to-host escape, and recovery of sealed secrets. Distinct from hardware-security (broad hardware attacks) and firmware-reverse (UEFI/BIOS)."
origin: openclaw
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
  - WebSearch
  - WebFetch
metadata:
  domain: confidential-computing
  tool_count: 14
  guide_count: 2
  mitre: "T1046-Network Service Discovery, T1602-Data from Configuration Repository"
  last_reviewed: "2026-07-26"
---

# Confidential Computing Attack

> **Supplementary Files**:
> - `payloads.md` — Attack payloads organized by TEE: Intel SGX (Foreshadow/SGAxe/LVI/ÆPIC Leak), Intel TDX, AMD SEV-SNP (CrossLine/BadRAM), Azure CCF, Marblerun, Gramine/Occlum
> - `test-cases.md` — 18 structured test cases covering attestation forgery, side-channel leakage, ABI misuse, host-to-enclave breakout, and sealed-secret recovery
> - `guides/confidential-computing-attack-playbook.md` — End-to-end playbook with engagement scoping, lab setup (QEMU with SGX/SEV emulation), attestation workflow attacks, enclave breakout methodology, and blue-team detection
> - `guides/real-world-incident-case-studies.md` — Eight case studies including SGX Foreshadow (2018), SGAxe (2020), LVI (2020), ÆPIC Leak (2022), AMD SEV CrossLine (2025), BadRAM (2024), and Gramine ABI abuse

## Summary

This skill targets confidential computing — the technology that protects data in *use* via hardware-isolated enclaves. While at-rest and in-transit encryption are well-understood, TEEs introduce a new attack surface: **enclave attestation forgery, microarchitectural side channels, ABI misuse between enclave and untrusted host, and host-to-enclave breakout**.

**Tools**: sgx-step, sgvisor, sev-tool, snp-lab, marblerun-cli, ccf-client, occlum-tools, gramine-direct, rust-sgx, edgelessrt, intel-sgx-sdk, sgxs-tools, libsgx, sgx_emulate

**Domain**: confidential-computing

**MITRE ATT&CK**: T1046 Network Service Discovery · T1602 Data from Configuration Repository · T1068 Exploitation for Privilege Escalation · T1556 Modify Authentication Process

## Description

Attacks against Trusted Execution Environments (TEEs) and confidential computing platforms — Intel SGX (Foreshadow/SGAxe/LVI/ÆPIC Leak), Intel TDX, AMD SEV/SEV-ES/SEV-SNP (CrossLine/BadRAM), Azure CCF, Marblerun, and Gramine/Occlum libos enclaves.

Confidential computing assumes a strong threat model: the OS, hypervisor, BIOS, and even physical DRAM are untrusted. Only the TEE itself (the CPU enclave) is trusted. Attacks against this model fall into four broad categories:

1. **Microarchitectural side channels** — exploiting CPU cache, branch predictor, TLB, or memory bus behavior to leak enclave secrets
2. **Attestation forgery** — bypassing or faking attestation reports to make untrusted code appear trusted
3. **ABI misuse** — abusing the carefully-specified boundary between enclave and untrusted host to corrupt enclave state
4. **Host-to-enclave breakout** — escaping from an enclave back to the host, or vice versa

This skill is distinct from:
- **hardware-security** — which targets physical hardware attacks (JTAG, side-channel on chips, fault injection)
- **firmware-reverse** — which targets UEFI/BIOS, not runtime enclaves
- **container-security** — which targets container runtimes, not hardware isolation
- **cloud-security** — which targets cloud control planes broadly

Where container-security asks "can I escape this container?", confidential-computing-attack asks "given that this enclave is supposed to be impenetrable even to a malicious cloud provider, what corner cases let me violate that promise?"

## Use Cases

- **SGX attestation forgery** — craft an IAS/DCAP attestation report that appears valid but represents untrusted code (e.g., for OCSP relay attacks)
- **SGX sealed-secret recovery** — extract the `Seal Key` from a compromised platform to decrypt sealed secrets offline
- **Foreshadow (L1TF) attack** — read enclave memory from a sibling thread via L1 Terminal Fault
- **SGAxe attack** — extract the platform's EPID group key, allowing attestation forgery for any enclave on that platform
- **LVI attack** — inject faulting load operations to hijack enclave execution
- **ÆPIC Leak** — exploit APIC MMIO read to leak SGX enclave data
- **AMD SEV-SNP attestation forgery** — tamper with VLEK/VCEK signed attestation reports
- **AMD CrossLine attack** — break VM-to-VM isolation within SEV-SNP
- **BadRAM attack** — exploit DDR5 SPD SPD-Bypass on consumer DIMMs to break SEV-SNP guest memory integrity
- **TDX attestation abuse** — manipulate TDREPORT to make untrusted VM appear as trusted
- **Azure CCF governance attack** — abuse the consortium governance model to add a malicious node
- **Marblerun manifest tamper** — exploit weak EManifest validation to alter marble policy at runtime
- **Gramine/Occlum libos escape** — exploit syscall-emulation bugs to escape the libos back to host

## Differentiation from Adjacent Skills

| Skill | Target | Boundary | Typical entry |
|---|---|---|---|
| `hardware-security` | Physical chips, IoT devices | Physical access | JTAG, glitching |
| `firmware-reverse` | UEFI/BIOS, Option ROM | Boot-time | DMA attacks, SMM |
| `container-security` | OCI, K8s, containerd | Kernel namespace | Container escape |
| `confidential-computing-attack` (this) | TEEs (SGX, TDX, SEV-SNP, CCF) | CPU enclave boundary | Side channel, attestation abuse |
| `cloud-security` | CSP control plane | Cloud IAM | IAM enumeration |
| `kernel-exploitation` | OS kernel | User/kernel boundary | Syscall misuse |

## Core Tools

### Intel SGX
- **Intel SGX SDK** — official SDK; includes `sgx_sign`, `sgx_edger8r`
- **sgx-step** — single-step enclave execution, page-fault side channels (Ard et al., TU Wien)
- **sgvisor** — enclave hypervisor framework for research
- **sgxs-tools** — Rust utilities for SGX enclave file manipulation
- **Foreshadow PoC** — academic PoC for L1TF (Wikipedia: Foreshadow)
- **SGAxe PoC** — academic PoC for EPID key extraction
- **LVI PoC** — academic PoC for Load Value Injection
- **ÆPIC Leak PoC** — CVE-2022-21233 PoC

### Intel TDX
- **tdx-tools** — Intel TDX development kit
- **tdquote** — TDX attestation quote generation
- **QEMU with TDX support** — confidential VM testing

### AMD SEV / SEV-ES / SEV-SNP
- **amdSEVTool** — SEV/SEV-SNP attestation utilities
- **sev-snp-lab** — local CVM testing harness
- **SEV-SNP guest tools** — guest-side attestation helper
- **CrossLine PoC** — research tooling for SEV-SNP VM isolation attacks

### Azure CCF
- **ccf-cli** — CCF consortium governance CLI
- **ccf-client** — RPC client for CCF nodes
- **ccf-recovery** — disaster recovery tooling

### Marblerun
- **marblerun-cli** — manifest management
- **edgelessrt** — runtime SDK

### LibOS Enclaves
- **gramine-direct** — Gramine libos CLI
- **occlum-tools** — Occlum libos CLI
- **sgx-lkl** — SGX-LKL libos

## Methodology

### Phase 1 — Reconnaissance
- Identify SGX/TDX/SEV-SNP usage in target (binary inspection for SGX instructions like `encls`, `enclu`, `enclv`)
- Identify attestation provider (Intel IAS, Intel DCAP, AMD VCEK, Azure CCF, custom attestation service)
- Map enclave binary: identify ECALLs, OCALLs, edge routines
- Identify attestation report format (EPID, DCAP, ECDSA)
- Identify sealed-secret storage locations

### Phase 2 — Attestation Attacks
- Replay old attestation reports
- Forge attestation reports via IAS/DCAP compromise
- Exploit weak quote verification (date, nonce, key)
- Abuse advisory (allow-list) policies on outdated enclave versions
- Apply CCF governance attack to add malicious node

### Phase 3 — Microarchitectural Side Channels
- Identify secret-dependent branches in enclave
- Deploy cache timing attacks (Prime+Probe, Flush+Reload)
- Deploy branch prediction attacks (Spectre variant in enclave)
- Deploy SGX-Step for single-step page-fault side channels
- Apply Foreshadow (L1TM) for enclave memory reads
- Apply SGAxe for EPID key extraction

### Phase 4 — ABI Misuse
- Review ECALL/OCALL signatures for untrusted-pointer dereferences
- Identify buffer overflows in edge routines
- Identify integer overflows in array length checks
- Exploit missing check_*
- Race-condition in asynchronous edge calls (AEX race)

### Phase 5 — Enclave Breakout / Escape
- Identify libos syscall-emulation bugs (Gramine, Occlum)
- Exploit memory layout assumptions (TLS region, stack)
- Forge shared memory mappings between enclave and host
- Abuse insecure key derivation for sealed secrets

### Phase 6 — Sealed Secret Recovery
- Extract `Seal Key` derivation parameters from platform
- Compute Seal Key offline using leaked `CPU_SIG` or fused key
- Decrypt sealed secrets from disk
- Pivot to enclave's persisted state

### Phase 7 — TEE Host Compromise
- Compromise host kernel to feed malicious SGX instructions
- Use AEX notify to time enclave execution
- Deploy ÆPIC Leak (CVE-2022-21233) for APIC-based read
- Deploy LVI (CVE-2020-0551) for faulting-load injection

### Phase 8 — TDX / SEV-SNP Specific
- TDX: abuse TDREPORT signing
- SEV-SNP: exploit VCEK key reuse
- SEV-SNP: apply CrossLine for VM-to-VM isolation break
- SEV-SNP: apply BadRAM for DDR5 SPD-bypass memory integrity break

## Defense Perspective

### Core Principles
1. **Defense in depth** — assume any single TEE may be compromised; layer attestation, code signing, and runtime checks
2. **Quote verification is critical** — never accept attestation reports without verifying signature, freshness, and nonce
3. **Advisory policy is policy** — Intel's "advisory allowlist" lets unpatched enclaves still attest; decide explicitly
4. **Sealed secrets require key rotation** — rotate Seal Key after platform firmware updates
5. **Side-channel resistance is hard** — assume data-dependent branches leak; use constant-time crypto

### Hardening Checklist
- [ ] Require attestation quote verification (signature, nonce, freshness) at every RPC
- [ ] Apply Intel advisory policy explicitly (e.g., reject reports with vulnerable advisory IDs)
- [ ] Use ECDSA attestation (DCAP) over EPID where possible
- [ ] Use SEV-SNP over SEV/SEV-ES for new deployments
- [ ] Apply page-fault side-channel defenses (occlum/gramine mitigations)
- [ ] Use constant-time crypto primitives (libsodium, OpenSSL CT)
- [ ] Rotate Seal Keys after firmware updates
- [ ] Audit attestation reports in tamper-evident log (CCF)

### Detection
- Attestation report anomaly detection (new advisory IDs, new MRENCLAVE)
- Side-channel detection via performance counter anomalies
- Sealed-secret decryption anomaly rate
- TEE error injection attempts (enclave CPUID mismatch)

## Practical Steps

### SGX Recon
1. `nm enclave.signed.so | grep -E "sgx_|ecall"` to find entry points
2. `objdump -d enclave.signed.so` for SGX instruction patterns (`enclu`, `encls`)
3. `sgx_sign dump -key ... -enclave ... -dumpfile ...` for metadata

### SGX Attestation Replay
1. Capture a valid attestation report (older or from compromised platform)
2. Replay to relying party without fresh nonce
3. If relying party doesn't verify nonce → accept stale report

### SGX Foreshadow (L1TM) Recovery
1. Deploy sibling thread that triggers enclave page fault
2. Use `sgx-step` to single-step enclave execution
3. Apply L1 Terminal Fault to leak enclave cache lines
4. Reconstruct secret from cache line samples

### AMD SEV-SNP Attestation Audit
1. `sev-tool --get_vcek` to fetch the platform's VCEK certificate
2. Verify attestation report signature against VCEK
3. Check policy fields (abi_major, abi_minor, smt)
4. Compare MEASUREMENT field against expected guest measurement

### Azure CCF Governance Attack
1. Identify network consortium (config.json: members, certificates)
2. Compromise a member's private key (or social-engineer a quorum member)
3. Submit `set_constitution` proposal to add malicious operator
4. If accepted → malicious node joins network

### Gramine LibOS Recon
1. `gramine-sgx-sign --manifest app.manifest` to inspect manifest
2. `gramine-sgx-token` to generate runtime measurement
3. Identify syscall emulation bugs via fuzzing (e.g., `gramine-sgx-direct --trace-syscalls`)

## Detection Methods

### TEE Audit Logging
- **SGX attestation logs**: Failed attestation attempts; quote verification failures.
- **AMD SEV-SNP logs**: VMPL switch anomalies; TCB mismatch events.
- **Intel TDX logs**: TD exit reasons; malicious TD guest indicators.

### Side-Channel Detection
- **Cache timing anomalies**: Process exhibiting consistent timing patterns (signature of cache attack).
- **Page fault patterns**: Single process causing high page fault rate on shared memory.
- **Power analysis signatures**: Hardware-level monitoring detects DPA/CPA attack patterns.

### SIEM Detection Rules
- **Splunk SPL**: `index=tee sourcetype=sgx_attest | where status="failed" | stats count by enclave_id`
- **Custom HSM monitoring**: Detect anomalous command sequences to HSM (key extraction attempts).

## Defense Evasion Techniques

### Attestation Bypass
- **Attestation spoofing**: Replay legitimate attestation quote (some implementations don't bind nonce to enclave state).
- **Outdated TCB**: Target enclaves with old TCB; vulnerabilities known but not patched.
- **Side-channel tolerance**: Use tolerated side-channels (Foreshadow, Spectre); not flagged by enclave.

### TEE Escape Stealth
- **CVE selection**: Use newer CVEs (CVE-2022-40982, CVE-2023-23583) before detection rules updated.
- **Cross-enclave attacks**: Use compromised enclave to attack others; appears as legitimate communication.
- **Memory disclosure via side-channel**: No direct vulnerability exploited; harder to attribute.

### Cloud Confidential VM Attacks
- **Snapshot abuse**: Snapshot CVM disk, restore outside CVM, mount to read encrypted data.
- **VBS (Virtualization-Based Security) escape**: Target Windows VBS flaws; bypass Credential Guard.
- **SEV-SNP VMPL confusion**: Abuse VMPL levels to escalate privileges within SEV-SNP guest.

## Cross-References
- `skills/hardware-security/SKILL.md` — physical hardware attacks (JTAG, fault injection)
- `skills/firmware-reverse/SKILL.md` — UEFI/BIOS / SMM attacks
- `skills/binary-reverse/SKILL.md` — enclave binary static analysis
- `skills/crypto-attacks/SKILL.md` — attestation report cryptography analysis
- `skills/cloud-security/SKILL.md` — confidential VMs in cloud (Azure DCsv3, AWS Nitro Enclaves)
- `skills/container-security/SKILL.md` — confidential containers (Kata + SGX)

## References

- Intel — *Intel SGX Developer Reference* (2024)
- AMD — *SEV-SNP Firmware ABI Specification* (2024)
- Microsoft — *Azure Confidential Cloud (CCF) Documentation* (2024)
- Foreshadow — *Masters of SGX* (USENIX Security 2018)
- SGAxe — *How to Steal the SGX Attestation Key* (CCS 2020)
- LVI — *Load Value Injection* (IEEE S&P 2020)
- ÆPIC Leak — *CVE-2022-21233* (BlackHat USA 2022)
- CrossLine — *Breaking SEV-SNP VM Isolation* (USENIX Security 2025)
- BadRAM — *DDR5 SPD Bypass* (USENIX Security 2024)
- Gramine — *Documentation and Threat Model* (2024)
- Occlum — *Threat Model Paper* (IEEE S&P 2021)
