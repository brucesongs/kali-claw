# Confidential Computing Attack — Test Cases

> Structured test case templates for validating confidential computing attack coverage. Each case includes severity, prerequisites, test steps, expected results, remediation, pass criteria, and reference payload.

## Conventions

- **Severity**: Critical (CRITICAL) / High (HIGH) / Medium (MEDIUM) / Low (LOW)
- **Prerequisites**: Required hardware, software, or pre-conditions
- **Pass Criteria**: Objective conditions that indicate the test passes
- **Reference**: Pointer to the specific section in `payloads.md`

**Important**: Side-channel and TEE attacks require careful authorization scope. Never run these against production systems without written authorization.

---

## A. Reconnaissance & Discovery

### TC-CC-001 — SGX Binary Detection

**Severity**: LOW
**Prerequisites**: Target binary; static analysis tools
**Objective**: Determine if target uses Intel SGX

**Test Steps**:
1. `objdump -d target.so | grep -E "(enclu|encls|enclv)"`
2. `nm -D target.so | grep -i sgx | head -20`
3. `strings target.so | grep -iE "(MRENCLAVE|MRSIGNER|sgx_)"`
4. Try `sgx_sign dump -enclave target.so -dumpfile meta.txt -key REPLACE_WITH_YOUR_KEY`

**Expected Results**:
- SGX binaries contain `enclu` instructions (user mode)
- Symbols include `ecall_*`, `ocall_*`, `sgx_*`
- SGX metadata signature matches Intel SDK format

**Remediation**:
- Strip symbols from production enclaves
- Use opaque function names
- Sign with non-public MRSIGNER

**Pass Criteria**: Identified ≥3 SGX indicators (instructions, symbols, metadata)

**Reference**: payloads.md §1, §2

---

### TC-CC-002 — SEV-SNP / TDX Platform Detection

**Severity**: LOW
**Prerequisites**: Access to target VM

**Test Steps**:
1. `dmesg | grep -iE "(sev|tdx|snp)"`
2. `cpuid | grep -iE "(SEV|TDX|SGX)"`
3. `ls /dev/ | grep -iE "(sev|tdx|sgx|nsm|nitro)"`
4. Cloud metadata: `curl -s -H Metadata:true "http://169.254.169.254/metadata/instance" | jq`

**Expected Results**:
- SEV-SNP: dmesg shows `ccp`, `/dev/sev` exists
- TDX: dmesg shows `tdx`, `/dev/tdx-guest` exists
- AWS Nitro: `/dev/nitro_enclaves/`, `/dev/nsm/`
- VM size in metadata reveals confidential VM type

**Remediation**:
- Disable confidential VM if not needed
- Restrict dmesg access for non-root users

**Pass Criteria**: Identified TEE type and version

**Reference**: payloads.md §1

---

### TC-CC-003 — Attestation Provider Discovery

**Severity**: LOW
**Prerequisites**: Access to target / network visibility

**Test Steps**:
1. `grep -rE "attest.*\..*" /etc /opt 2>/dev/null`
2. `grep -rE "trustedexecution" /etc /opt 2>/dev/null`
3. Capture network traffic; identify attestation endpoints
4. Review IAM / OAuth flows to identify attestation service

**Expected Results**:
- Identify provider (Intel IAS, DCAP, Azure Attestation, custom)
- Identify attestation endpoints and signing certs
- Identify client-side attestation libraries (libsgx_urts, sev_guest)

**Remediation**:
- Use modern DCAP attestation over EPID
- Pin attestation service certificate
- Hide attestation service behind authenticated proxy

**Pass Criteria**: Identified attestation provider and certificate chain

**Reference**: payloads.md §1

---

## B. SGX Attestation Attacks

### TC-CC-004 — Attestation Quote Replay

**Severity**: HIGH
**Prerequisites**: Network MITM access to attestation flow

**Test Steps**:
1. Capture a valid attestation quote (via pcap or proxy)
2. Identify the verifier endpoint (e.g., `POST /attest`)
3. Replay captured quote:
   ```bash
   curl -X POST https://target/attest \
     -d @quote.json
   ```
4. Observe whether verifier accepts stale quote

**Expected Results**:
- Hardened verifier: rejects with "nonce mismatch" or "stale timestamp"
- Weak verifier: accepts and grants access

**Remediation**:
- Verifier MUST issue nonce and verify freshness
- Verifier MUST consume nonce on use (single-use)
- Verifier MUST reject quotes older than 60 seconds

**Pass Criteria**: Successfully replayed stale quote (in weak verifier)

**Reference**: payloads.md §3, §4

---

### TC-CC-005 — Advisory Policy Bypass

**Severity**: HIGH
**Prerequisites**: Target enclave on vulnerable Intel SGX platform

**Test Steps**:
1. Identify Intel advisory IDs from quote via Intel IAS
2. Review verifier's advisory policy
3. If policy allows vulnerable advisories → submit attestation with vulnerable enclave
4. Verify access granted

**Expected Results**:
- Verifier with strict policy rejects
- Verifier with permissive policy accepts

**Remediation**:
- Maintain blocked-advisory list
- Reject attestation with vulnerable ISVSVN
- Pin minimum allowed TCB level

**Pass Criteria**: Confirmed advisory policy misconfiguration

**Reference**: payloads.md §5

---

### TC-CC-006 — EPID Signature Validation Weakness

**Severity**: MEDIUM
**Prerequisites**: Verifier source or accessible binary

**Test Steps**:
1. Extract EPID public key from Intel's published root cert
2. Inspect verifier's certificate validation logic
3. Test with expired or revoked EPID chain
4. Test with self-signed cert (should fail)

**Expected Results**:
- Verifier validates full chain to Intel root
- Verifier rejects expired or revoked chains
- Verifier rejects self-signed certs

**Remediation**:
- Use Intel's official DCAP verifier code
- Pin Intel root cert
- Enable OCSP/CRL checks

**Pass Criteria**: Identified weakness in EPID validation

**Reference**: payloads.md §3, §5

---

## C. SGX Side-Channel Attacks

### TC-CC-007 — SGX-Step Single-Step Trace

**Severity**: HIGH
**Prerequisites**: SGX-Step installed; SGX-enabled host

**Test Steps**:
1. Build SGX-Step: `cd sgx-step && make`
2. Run against target enclave:
   ```bash
   ./app/sgx-step-target --single-step
   ```
3. Capture trace
4. Analyze for secret-dependent patterns

**Expected Results**:
- Per-instruction trace captured
- Variable instruction counts reveal secret-dependent branches

**Remediation**:
- Use constant-time crypto
- Apply page-fault side-channel defenses
- Use AEX-notify (SGX2) to detect attacks

**Pass Criteria**: Recovered ≥1 byte of secret via instruction count analysis

**Reference**: payloads.md §10

---

### TC-CC-008 — Foreshadow (L1TF) Read

**Severity**: CRITICAL
**Prerequisites**: Pre-2018 Intel CPU without microcode patch

**Test Steps**:
1. Verify vulnerability: `cat /sys/devices/system/cpu/vulnerabilities/l1tf`
2. Deploy Foreshadow PoC (academic, simplified)
3. Run against target enclave
4. Reconstruct secret from cache line samples

**Expected Results**:
- L1TM allows reading enclave memory
- Reconstructed secret matches known value

**Remediation**:
- Apply microcode update
- Apply kernel L1TF mitigation
- Use SGX2 with AEX-notify

**Pass Criteria**: Recovered ≥64 bytes of enclave secret

**Reference**: payloads.md §7

---

### TC-CC-009 — ÆPIC Leak (APIC MMIO Read)

**Severity**: CRITICAL
**Prerequisites**: Affected Intel Xeon SP platform (Ice Lake)

**Test Steps**:
1. Verify platform: `cat /proc/cpuinfo | grep "model name"`
2. Apply ÆPIC Leak PoC
3. Read APIC MMIO region repeatedly
4. Reconstruct SGX enclave data from leaked bytes

**Expected Results**:
- APIC MMIO reads return stale SGX data
- Reconstructed data contains enclave secrets

**Remediation**:
- Apply microcode update
- Disable APIC MMIO via kernel parameter

**Pass Criteria**: Recovered ≥16 bytes of enclave secret

**Reference**: payloads.md §9

---

## D. SGX ABI Misuse

### TC-CC-010 — Untrusted Pointer Dereference

**Severity**: HIGH
**Prerequisites**: Target enclave binary; fuzzing harness

**Test Steps**:
1. Identify ECALL with `[user_check]` parameter
2. Craft malicious input pointer (e.g., pointing to enclave-protected memory)
3. Trigger ECALL
4. Observe whether output contains enclave memory contents

**Expected Results**:
- Hardened enclave: validates pointer before deref
- Vulnerable enclave: returns enclave memory to attacker

**Remediation**:
- Mark all incoming pointers with `[in]`, `[out]`, or `[in, out]`
- Use `sgx_is_within_enclave()` check before deref
- Fuzz enclave ABI

**Pass Criteria**: Confirmed untrusted-pointer dereference bug

**Reference**: payloads.md §12

---

### TC-CC-011 — AEX Race Condition

**Severity**: MEDIUM
**Prerequisites**: SGX enclave with non-atomic read-modify-write

**Test Steps**:
1. Identify enclave code with RMW pattern
2. Trigger AEX via APIC timer at precise moment
3. Modify underlying memory during AEX
4. Observe whether enclave continues with stale data

**Expected Results**:
- Hardened enclave: uses atomic ops or disables interrupts
- Vulnerable enclave: continues with stale data, leading to corruption

**Remediation**:
- Use `__sync_synchronize()` or `std::atomic`
- Use Intel TSX for transactional atomicity
- Re-validate state after every OCALL

**Pass Criteria**: Demonstrated AEX-induced corruption

**Reference**: payloads.md §13

---

## E. Sealed Secret Recovery

### TC-CC-012 — Seal Key Recovery from Compromised Platform

**Severity**: CRITICAL
**Prerequisites**: Root on SGX-enabled platform; enclave binary

**Test Steps**:
1. Locate sealed secret files on disk
2. Identify enclave binary (for MRENCLAVE)
3. Extract CPU SVN from platform
4. Run EGETKEY from within enclave:
   ```c
   sgx_get_key(&key_request, &seal_key);
   ```
5. Decrypt sealed secrets offline

**Expected Results**:
- Seal Key derived successfully
- Sealed secrets decrypt to plaintext

**Remediation**:
- Rotate Seal Key after firmware updates
- Use MRSIGNER seal policy with vendor-controlled MRSIGNER
- Apply hardware root of trust (TPM-measured attestation)

**Pass Criteria**: Decrypted ≥1 high-value sealed secret

**Reference**: payloads.md §11

---

## F. AMD SEV-SNP Attacks

### TC-CC-013 — SEV-SNP Attestation Verification Weakness

**Severity**: HIGH
**Prerequisites**: SEV-SNP platform access

**Test Steps**:
1. Get attestation report via `/dev/sev-guest`
2. Fetch VCEK cert from AMD KDS
3. Inspect verifier's validation logic
4. Test with reports that have:
   - Stale nonce
   - Expired VCEK cert
   - Mismatched measurement

**Expected Results**:
- Hardened verifier: rejects all invalid reports
- Weak verifier: accepts at least one invalid report type

**Remediation**:
- Verify full VCEK chain to AMD root
- Pin minimum TCB version
- Reject reports with stale nonce

**Pass Criteria**: Confirmed weakness in attestation validation

**Reference**: payloads.md §17

---

### TC-CC-014 — CrossLine VM-to-VM Isolation Break

**Severity**: CRITICAL
**Prerequisites**: Two VMs on same SEV-SNP platform (one attacker, one victim)

**Test Steps**:
1. Deploy attacker VM-A on SEV-SNP platform
2. Identify victim VM-B on same platform
3. Apply CrossLine PoC to access VM-B memory via VMPL misuse
4. Read VM-B secrets (e.g., memory dump)

**Expected Results**:
- VMPL isolation broken
- VM-B secrets accessible to VM-A

**Remediation**:
- Cloud provider schedules mutually-untrusted VMs on separate platforms
- Hypervisor enforces VMPL boundaries
- Monitor for VMPL transition anomalies

**Pass Criteria**: Read ≥4KB of VM-B memory from VM-A

**Reference**: payloads.md §18

---

## G. Azure CCF Attacks

### TC-CC-015 — Consortium Member Key Discovery

**Severity**: HIGH
**Prerequisites**: Access to CCF node or operator workstation

**Test Steps**:
1. Search for member private keys:
   ```bash
   find / -name "*member*priv*" 2>/dev/null
   find / -name "*member*pem*" 2>/dev/null
   grep -r "MEMBER_PRIV_KEY" /etc /opt 2>/dev/null
   ```
2. Inspect CCF node config
3. Check CI/CD artifacts for member keys

**Expected Results**:
- Member private keys found in:
  - `/opt/ccf/member/privk.pem`
  - CI artifact
  - Backup location

**Remediation**:
- Store member keys in HSM
- Rotate on personnel change
- Use short-lived member certificates

**Pass Criteria**: Located ≥1 valid member private key

**Reference**: payloads.md §20, §21

---

### TC-CC-016 — Constitution Amendment via Compromised Member

**Severity**: CRITICAL
**Prerequisites**: Member private key + quorum

**Test Steps**:
1. Submit malicious proposal:
   ```bash
   ccf-cli proposal create \
     --url https://ccf.target.example \
     --member-key member_privk.pem \
     --proposal set_constitution \
     --param '{"constitution":"<backdoor_constitution>"}'
   ```
2. Vote from compromised members to reach quorum
3. Verify new constitution is committed
4. Test backdoor (e.g., self-granting operator role)

**Expected Results**:
- Constitution updated
- Backdoor grants attacker persistent control

**Remediation**:
- Strict quorum (e.g., 4 of 7)
- Off-chain review for constitution changes
- Audit constitution hash

**Pass Criteria**: Backdoor provisioned and verified

**Reference**: payloads.md §22

---

## H. Marblerun & LibOS Attacks

### TC-CC-017 — Marblerun Manifest Tampering

**Severity**: HIGH
**Prerequisites**: Access to manifest storage; weak signature verification

**Test Steps**:
1. Locate manifest: `find / -name "*.manifest" 2>/dev/null`
2. Modify manifest to weaken attestation
3. Re-sign with attacker key (if signature verification is weak)
4. Restart service with tampered manifest
5. Verify service starts with modified policy

**Expected Results**:
- Hardened deployment: signature verification fails, service doesn't start
- Weak deployment: service starts with tampered manifest

**Remediation**:
- Pin manifest hash in relying party
- Verify manifest signature matches MRENCLAVE in quote
- Audit manifest changes in CCF or external log

**Pass Criteria**: Tampered manifest accepted by deployment

**Reference**: payloads.md §23

---

### TC-CC-018 — Gramine LibOS Syscall Escape

**Severity**: CRITICAL
**Prerequisites**: Target app running in Gramine; fuzzing harness

**Test Steps**:
1. Run target with syscall tracing:
   ```bash
   gramine-sgx --log-file=gramine.log --syslog-level=debug target-app
   ```
2. Identify syscall emulation bugs
3. Craft input that triggers vulnerable syscall
4. Observe whether attacker achieves code execution outside enclave

**Expected Results**:
- Hardened libos: input validated, no escape
- Vulnerable libos: code execution in host

**Remediation**:
- Use latest Gramine version
- Apply Gramine's security mitigations
- Audit syscall emulation code

**Pass Criteria**: Demonstrated escape from enclave to host

**Reference**: payloads.md §24, §25

---

## I. AWS Nitro Enclaves

### TC-CC-019 — Nitro Attestation Document Replay

**Severity**: MEDIUM
**Prerequisites**: Captured valid attestation document

**Test Steps**:
1. Capture attestation document via network proxy
2. Identify verifier endpoint
3. Replay captured document:
   ```bash
   curl -X POST https://target/verify \
     --data-binary @attestation.cbor
   ```
4. Observe verifier's behavior

**Expected Results**:
- Hardened verifier: rejects stale document (timestamp, nonce)
- Weak verifier: accepts and grants access

**Remediation**:
- Verifier MUST verify timestamp within 60s window
- Verifier MUST verify server-supplied nonce
- Verifier MUST verify PCR values match expected

**Pass Criteria**: Successfully replayed stale document

**Reference**: payloads.md §28

---

### TC-CC-020 — Nitro PCR Mismatch Detection

**Severity**: MEDIUM
**Prerequisites**: Attacker-controlled enclave binary

**Test Steps**:
1. Build attacker enclave with different binary
2. Request attestation document from attacker enclave
3. Submit to verifier
4. Verify PCR values

**Expected Results**:
- Hardened verifier: rejects due to PCR mismatch
- Weak verifier: accepts with attacker-controlled PCR

**Remediation**:
- Pin PCR values for each deployment
- Verify all 8 PCRs
- Update PCR allowlist via signed deployment pipeline

**Pass Criteria**: PCR mismatch detected and rejected (or bypassed in weak verifier)

**Reference**: payloads.md §28

---

## Aggregate Pass Criteria

A successful engagement covers at minimum:
- **≥6 test cases passed across ≥3 TEE types** (SGX, SEV-SNP, TDX, Nitro, CCF, Marblerun)
- **≥1 CRITICAL case demonstrating full breach chain** (side channel, attestation forgery, or breakout)
- **≥1 attestation-related finding** with verifier-side detection rule
- **≥1 ABI misuse or libos escape finding** with upstream remediation guidance
- **Blue-team detection rule** (Sigma / Splunk / KQL) for at least one demonstrated attack
- **Sealed-secret recovery** demonstrated if SGX is in scope

---

## Reporting Template (per test case)

```markdown
### TC-CC-XXX — <Case Title>

**Status**: PASS / FAIL / PARTIAL
**Target**: <platform / enclave / CCF network>
**Window**: <start> - <end> UTC
**Operator**: <name>

**Findings**:
- <bullet points of what was confirmed>

**Evidence**:
- Enclave binary: <hash>
- Attestation quote: <path>
- Side-channel trace: <path>
- Audit log entry: <REDACTED>

**Impact**:
- <secrets exposed>
- <TEE isolation violated>
- <attestation integrity broken>

**Remediation**:
1. <short-term>
2. <medium-term>
3. <long-term>

**Detection Rule**:
```kusto
// Sigma / KQL / Splunk SPL for detecting this attack
```

**References**:
- CVE: <CVE-ID>
- Academic paper: <reference>
- MITRE ATT&CK: <technique>
```

---

## References

- Foreshadow — *Masters of SGX* (USENIX Security 2018)
- SGAxe — *How to Steal the SGX Attestation Key* (CCS 2020)
- LVI — *Load Value Injection* (IEEE S&P 2020)
- ÆPIC Leak — CVE-2022-21233 (BlackHat USA 2022)
- CrossLine — *Breaking SEV-SNP VM Isolation* (USENIX Security 2025)
- BadRAM — USENIX Security 2024
- MITRE ATT&CK — T1068 Exploitation for Privilege Escalation, T1556 Modify Authentication Process
- Intel SGX Developer Reference (2024)
- AMD SEV-SNP ABI Specification (2024)
- Microsoft Azure CCF Documentation (2024)
- AWS Nitro Enclaves Documentation (2024)
- Marblerun Documentation (2024)
- Gramine Documentation (2024)
- Occlum Documentation (2024)
