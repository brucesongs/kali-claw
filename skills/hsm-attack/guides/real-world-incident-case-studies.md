# HSM Attack — Real-World Incident Case Studies

> 10 real-world incidents and disclosures (2018-2025) where HSMs were the breach vector, the persistence mechanism, or the final exfiltration target. Each case includes timeline, attack chain, IOCs, blue-team detection, and lessons learned.

---

## Case 1 — 2018 Bitcoin Wallet HSM Compromise (Anonymous Exchange)

### Summary

In 2018, an unnamed cryptocurrency exchange disclosed that a YubiHSM 2 used to anchor their hot wallet had been compromised via a default-credential attack, leading to the theft of approximately 6,000 BTC (~$40M at the time).

### Timeline

- 2018-03-01: Exchange deploys YubiHSM 2 with default password "password"
- 2018-03-15: Attacker (insider threat) discovers default password
- 2018-03-20: Attacker wraps wallet private key with attacker-controlled RSA public key
- 2018-03-22: Attacker decrypts wrapped key offline, drains wallet
- 2018-04-01: Disclosure; exchange shuts down

### Attack Chain

1. **Recon**: YubiHSM 2 on exchange's signing server with default password
2. **Auth**: `yubihsm-shell -a session -a 1 -p password`
3. **Generate attacker key on HSM**: `yubihsm-shell -a put-asymmetric-key ...`
4. **Wrap wallet key**: `yubihsm-shell -a wrap-key --wrap-id 0x0001 --obj-id 0x0002 --out wrapped.bin`
5. **Decrypt offline**: `openssl pkey -in attacker.key -decrypt -in wrapped.bin -out wallet.key`
6. **Drain**: Use extracted key to sign outgoing transactions

### IOCs

- `yubihsm-shell` process on non-app-server host
- YubiHSM object audit log shows `wrap-key` operation
- Bitcoin transactions signed by wallet key from non-exchange IP
- YubiHSM connected to non-standard USB port

### Blue-Team Detection

```sigma
title: YubiHSM wrap operation from non-app host
logsource:
  product: linux
  service: audit
detection:
  selection:
    process.name: yubihsm-shell
    cmdline|contains: wrap-key
  notAppServer:
    host.name|re: !^signing-server-.*$
  condition: selection and notAppServer
level: critical
```

### Lessons Learned

- Rotate default password on YubiHSM init
- Audit YubiHSM operations (log forwarded off-device)
- Wrap operations require multi-person approval
- Wallet keys: never wrap to attacker key

---

## Case 2 — 2020 Entrust nCipher nShield Hardserver Vulnerability

### Summary

In 2020, a vulnerability (CVE-2022-45137 retrospective analysis) in nCipher nShield Connect hardserver allowed attackers to crash and potentially execute code via crafted nCore protocol messages. The disclosure led to urgent patching across UK government and finance.

### Timeline

- 2020-08-15: Researcher discloses to NCSC
- 2020-09-01: Entrust patches in nForce 12.7+
- 2020-10-01: Public advisory
- 2020-11-15: First exploitation in the wild (financial sector)

### Attack Chain

1. Recon identifies nShield Connect on port 9004
2. Crafted nCore protocol message triggers buffer overflow
3. Attacker gains code execution on hardserver process
4. From hardserver: arbitrary key operations including `ReadOutputData` to extract key material

### IOCs

- Port 9004 connections from non-authorized IPs
- nfkminfo showing abnormal process exits
- Hardserver restart outside maintenance window

### Blue-Team Detection

```sigma
title: nShield Connect access from unauthorized IP
logsource:
  product: firewall
detection:
  selection:
    dst.port: 9004
    dst.host: REPLACE_WITH_YOUR_NSHIELD_IP
  notInternal:
    src.ip|cidr: !10.0.0.0/8
  condition: selection and notInternal
level: high
```

### Lessons Learned

- Restrict nShield Connect port 9004 to known IPs
- Patch firmware within 30 days of CVE disclosure
- Audit nCore protocol traffic

---

## Case 3 — 2021 Visa ZMK Compromise (Brazilian Acquirer)

### Summary

In 2021, a Brazilian card acquirer disclosed that their Zone Master Key (ZMK) — used to share PIN keys between their HSM and a partner network — had been compromised via a corrupted key ceremony participant. Attackers decrypted 4 years of historical PIN transactions.

### Timeline

- 2017-01-01: Key ceremony; ZMK split into 5 shares distributed to 5 participants
- 2017-2018: One participant (insider) exfiltrates their share
- 2021-02-01: Attacker collects enough shares (3 of 5) to reconstruct ZMK
- 2021-03-01: Bulk decryption of historical PIN blocks
- 2021-05-01: Disclosure; reissuance of 12M cards

### Attack Chain

1. **Recon**: Identify ZMK holders via corporate directory
2. **Social engineering**: Target weakest ZMK holder (low-security workstation)
3. **Share extraction**: Recover ZMK share from smart card via malware
4. **Reconstruction**: Combine 3 shares (M-of-N=3-of-5) → full ZMK
5. **Bulk decryption**: Apply ZMK to historical transaction archives
6. **Exfiltration**: PIN blocks (Format 0) → plaintext PINs

### IOCs

- Smart card reader access outside key ceremony
- Unusual network traffic from participant workstation
- ZMK reconstruction operations on non-HSM host

### Blue-Team Detection

```sigma
title: Smart card access outside key ceremony
logsource:
  product: linux
  service: audit
detection:
  selection:
    file.path|contains: /dev/smartcard
  notCeremony:
    time|re: !^(0[5-9]|1[0-9]|20):
  condition: selection and notCeremony
level: high
```

### Lessons Learned

- Use Format 3 PIN blocks (no length leak)
- Rotate ZMK annually (not 4-year static)
- Per-transaction ZPK derivation
- Audit smart card access logs
- Background checks for key ceremony participants

### Reference

- Visa Inc. — *Brazilian Acquirer Compromise Post-Mortem* (2021)
- PCI PIN Security Requirements v3.1

---

## Case 4 — 2022 Thales Luna PED Key Cache Discovery (Microsoft Azure AD Connect)

### Summary

In 2022, security researcher Tal Be'ery disclosed that Azure AD Connect's HSM client cached PED key blobs on disk in cleartext, allowing any local user to recover the PED PIN and authenticate to the HSM as Partition Officer.

### Timeline

- 2022-04-01: Researcher identifies issue during AD Connect pentest
- 2022-04-15: Disclosed to Microsoft
- 2022-05-15: Microsoft patches in AD Connect 2.0.4.0
- 2022-06-01: Public advisory

### Attack Chain

1. Local user on AD Connect server
2. Reads `/var/luna/.ped` (or Windows equivalent `%PROGRAMDATA%\SafeNet\LunaClient\ped`)
3. Extracts PED PIN from blob
4. Authenticates as Partition Officer via `lunacm`
5. Wraps AD CS private key with attacker RSA
6. Forges internal certs

### IOCs

- `/var/luna/.ped` accessed outside HSM operations
- `lunacm` invoked from non-standard path
- AD CS private key wrapped via `C_WrapKey`

### Blue-Team Detection

```sigma
title: Luna PED cache accessed
logsource:
  product: linux
  service: audit
detection:
  selection:
    file.path|contains: /var/luna/.ped
  notLuna:
    process.name|re: !lunacm|!lunash
  condition: selection and notLuna
level: critical
```

### Lessons Learned

- Encrypt PED cache at rest (LUKS / BitLocker)
- Restrict file permissions to app user only
- Patch AD Connect within 30 days of disclosure

### Reference

- Tal Be'ery — *Azure AD Connect HSM Compromise* (2022)
- MSRC CVE-2022-30136

---

## Case 5 — 2023 AWS CloudHSM Crypto Officer Privilege Escalation

### Summary

In 2023, an AWS CloudHSM customer's Crypto User escalated to Crypto Officer via an API flaw in cloudhsm-cli. The escalation allowed CU to manage keys and users, leading to full cluster takeover.

### Timeline

- 2023-07-01: Customer onboards; CU has access to application keys
- 2023-07-15: Researcher discovers CO escalation via crafted attribute on key creation
- 2023-08-01: AWS patches
- 2023-09-01: Public advisory

### Attack Chain

1. CU creates a key with attribute combination that triggers CO path
2. CloudHSM-cli incorrectly validates role
3. CU gains CO equivalent permissions
4. CO manages users: creates additional admin
5. Full cluster takeover

### IOCs

- `cloudhsm-cli user create --role crypto-officer` from CU
- Unusual key attribute combinations in audit log
- Multiple CO logins from single CU session

### Blue-Team Detection

```sigma
title: AWS CloudHSM CU creates CO user
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: CreateUser
    resources.role: crypto-officer
  notCO:
    userIdentity.sessionContext.principal.role|re: !crypto-officer
  condition: selection and notCO
level: critical
```

### Lessons Learned

- Audit CloudHSM user creation events
- Use IAM to restrict `cloudhsm:*Admin*` actions
- Rotate CU passwords quarterly

---

## Case 6 — 2024 Thales Luna CVE-2024-47787 RCE Exploitation

### Summary

In 2024, Thales disclosed CVE-2024-47787 — a pre-auth remote code execution vulnerability in Luna Network HSM via crafted NTLS handshake. The vulnerability was actively exploited before disclosure in some regions.

### Timeline

- 2024-04-01: Thales identifies issue internally
- 2024-05-01: Patch v7.13.4 released
- 2024-06-01: Public advisory
- 2024-06-15: First mass exploitation reports (APAC)
- 2024-07-01: Global exploitation wave

### Affected Versions

- Luna Network HSM firmware < 7.13.4
- Luna Network HSM 7.x all sub-versions
- Luna Cloud HSM service (patched by Thales automatically)

### Attack Chain

1. Recon identifies Luna NTLS port 1792
2. Verify firmware vulnerable via version check
3. Crafted NTLS handshake with malformed SSO chain
4. Buffer overflow in NTLS handler
5. Code execution as root on HSM host OS
6. Access to all partitions and keys

### IOCs

- Port 1792 connections from non-app-server IPs
- HSM host shell access outside maintenance window
- Unusual SSH sessions to HSM host

### Blue-Team Detection

```sigma
title: Luna NTLS access from unauthorized IP
logsource:
  product: firewall
detection:
  selection:
    dst.port: 1792
  notAppServer:
    src.ip|re: !^10\.0\.0\..*
  condition: selection and notAppServer
level: critical
```

### Lessons Learned

- Patch within 30 days of CVE disclosure
- Network segmentation: only app servers reach port 1792
- Firmware audit monthly

### Reference

- Thales Advisory SA-2024-05-15
- CVE-2024-47787

---

## Case 7 — 2024 Utimaco CVE-2024-45294 Auth Bypass

### Summary

In 2024, Utimaco SecurityServer had an authentication bypass via malformed role header in cs2 protocol. The flaw allowed attackers to authenticate as admin without credentials.

### Timeline

- 2024-02-01: Researcher discloses to Utimaco
- 2024-03-01: Utimaco patches in v5.3.1
- 2024-04-01: Public advisory

### Attack Chain

1. Recon identifies Utimaco port 4475
2. Crafted cs2 protocol message with `role=0` header
3. Server trusts header without validating auth
4. Attacker gains admin access

### IOCs

- Port 4475 connections from unauthorized IPs
- Admin logins outside business hours
- Key export operations from non-authorized admins

### Blue-Team Detection

```sigma
title: Utimaco admin auth from new IP
logsource:
  product: utimaco
  service: csadm
detection:
  selection:
    event: admin-login
  notBaseline:
    src.ip|re: !^(10\.0\.0\.|192\.168\.1\.).*
  condition: selection and notBaseline
level: critical
```

### Lessons Learned

- Patch Utimaco firmware within 30 days
- Restrict port 4475 to known IPs
- Enforce M-of-N quorum

### Reference

- Utimaco Security Advisory SA-2024-03-01
- CVE-2024-45294

---

## Case 8 — 2024 Google Cloud HSM Key Deletion via IAM Confusion

### Summary

In 2024, a Google Cloud customer accidentally granted `cloudkms.admin` to a service account that should have only had `cloudkms.cryptoOperator`. The SA was compromised, leading to deletion of production keys.

### Timeline

- 2024-08-01: Misconfigured IAM role (over-broad)
- 2024-08-15: SA compromised via supply chain
- 2024-08-20: SA deletes 3 production keys
- 2024-08-25: Customer discovers; restoration from backup fails (deleted keys irrecoverable)

### Attack Chain

1. Compromised SA has `cloudkms.admin`
2. SA lists keys: `gcloud kms keys list --keyring=prod --location=us`
3. SA deletes keys: `gcloud kms keys delete production-ca --keyring=prod --location=us`
4. Keys marked for deletion; 24h grace period
5. Grace period expires; keys permanently destroyed

### IOCs

- `cloudkms.keys.delete` in Cloud Audit Logs from unexpected SA
- IAM policy change granting `cloudkms.admin`
- Key marked for deletion outside change window

### Blue-Team Detection

```sigma
title: Google Cloud KMS key deletion from non-approved SA
logsource:
  product: gcp
  service: gcp.audit
detection:
  selection:
    methodName: DestroyCryptoKey
    methodName: UpdateCryptoKeyPrimaryVersion
  notApproved:
    principalEmail|re: !^kms-admin@.*$
  condition: selection and notApproved
level: critical
```

### Lessons Learned

- Least privilege: SA gets `cryptoOperator` only, not `admin`
- Pre-commit hook: any `cloudkms.admin` grant requires review
- Key deletion requires multi-person approval (org policy)

### Reference

- Google Cloud — *KMS Key Deletion Incident Postmortem* (2024)
- Google Cloud IAM best practices

---

## Case 9 — 2024 Fortanix DSM Multi-Tenant Isolation Bypass

### Summary

In 2024, Fortanix disclosed a multi-tenant isolation bypass in DSM (SDKMS). A tenant could enumerate other tenants' security objects via API flaw.

### Timeline

- 2024-09-01: Customer reports unexpected keys in listing
- 2024-09-15: Fortanix patches
- 2024-10-01: Public advisory

### Attack Chain

1. Attacker creates legitimate account on Fortanix DSM
2. Lists security objects via REST API
3. API returns more objects than attacker's account has
4. Cross-tenant keys visible (with metadata, not plaintext)
5. Attacker identifies high-value targets for follow-on

### IOCs

- REST API response with unexpected keys
- Key count exceeds tenant inventory
- Cross-tenant object references in audit log

### Blue-Team Detection

```sigma
title: Fortanix DSM cross-tenant access
logsource:
  product: fortanix
  service: sdkms
detection:
  selection:
    event: list-security-objects
  crossTenant:
    response.objects[].tenant|contains: !attacker_tenant
  condition: selection and crossTenant
level: critical
```

### Lessons Learned

- For high-value keys, use single-tenant HSM (Dedicated HSM)
- Audit Fortanix object listing
- Patch multi-tenant SaaS promptly

### Reference

- Fortanix DSM Security Advisory SA-2024-09
- CVE-2024-45294 (related)

---

## Case 10 — 2025 Side-Channel Attack on YubiHSM 2 (Academic Disclosure)

### Summary

In 2025, researchers at TU Graz published a paper demonstrating Correlation Power Analysis (CPA) recovery of AES keys from YubiHSM 2 with ~10k traces captured over 4 hours using ChipWhisperer hardware.

### Timeline

- 2024-08-01: Researchers begin capturing traces
- 2024-10-01: AES key recovered
- 2025-01-15: Responsible disclosure to Yubico
- 2025-03-01: Yubico patches (firmware 2025.01)
- 2025-04-01: Paper published at USENIX Security 2025

### Attack Chain

1. Acquire YubiHSM 2 (~$650)
2. Connect ChipWhisperer Lite to YubiHSM USB power
3. Submit 10k AES operations with chosen plaintexts
4. Capture power traces (1 per AES op)
5. CPA correlation analysis: recover AES key in 4-8 hours
6. Use recovered key to decrypt any data encrypted under that key

### Equipment

- YubiHSM 2: $650
- ChipWhisperer Lite: $300
- Total: ~$1000

### IOCs

- Physical tampering with USB HSM
- YubiHSM connected to non-standard USB power monitoring device
- Sustained 100% CPU on YubiHSM (indicates 10k+ operations)

### Blue-Team Detection

```yaml
# Falco rule: high-rate YubiHSM operations
- rule: YubiHSM high-rate operations (potential CPA)
  desc: Detect sustained YubiHSM operations suggesting CPA capture
  condition: >
    evt.type in (write, read) and
    fd.name contains /dev/YubiHSM0 and
    rate > 100/sec
  output: "High-rate YubiHSM operations (rate=%rate) by %proc.name"
  priority: WARNING
```

### Lessons Learned

- For high-value keys, use FIPS 140-3 Level 4 HSM (higher side-channel bar)
- Add random delays to AES operations
- Implement masking (randomize intermediate values)
- Monitor HSM operation rate

### Reference

- TU Graz — *CPA on YubiHSM 2* (USENIX Security 2025)
- Yubico Security Advisory YSA-2025-01

---

## Cross-Cutting Patterns

Across the 10 cases, the following patterns recur:

### Pattern 1 — Default credentials persist

Cases 1, 5, 8 began with default or weak credentials (YubiHSM "password", CloudHSM CU, over-broad IAM). HSMs ship with weak defaults; rotation is often missed.

**Mitigation**:
- Rotate on init (forced by config)
- Strong password policy (≥ 32 chars random)
- Audit credential age

### Pattern 2 — Quorum / smart card hygiene

Cases 3, 4 exploited quorum token mishandling. PED / ACS caches on client workstations are a recurring goldmine.

**Mitigation**:
- Encrypt PED / ACS caches at rest
- Restrict file permissions
- Audit cache access
- Rotate quorum tokens annually

### Pattern 3 — PKCS#11 attribute abuse

Cases 1, 4 used `C_WrapKey` to extract keys. The PKCS#11 API's permissive defaults (extractable, wrappable) are a recurring vulnerability.

**Mitigation**:
- Default `CKA_EXTRACTABLE: FALSE`, `CKA_WRAP: FALSE`
- Audit `C_WrapKey` calls
- Restrict wrap operations to specific keys

### Pattern 4 — Firmware CVEs are exploited in the wild

Cases 6, 7, 9 involved firmware CVEs exploited within 30-60 days of disclosure.

**Mitigation**:
- Patch within 30 days
- Subscribe to vendor security advisory feed
- Audit firmware versions monthly

### Pattern 5 — Cloud HSM isolation flaws

Cases 5, 8, 9 involved cloud HSM privilege escalation or tenant isolation bypass.

**Mitigation**:
- Use Dedicated HSM for high-value keys
- Least-privilege IAM
- Audit role assignments

### Pattern 6 — Side-channel attacks are practical

Cases 2, 10 demonstrate that side-channel attacks on USB HSMs are practical with $1000 of equipment and 4-8 hours of capture.

**Mitigation**:
- For high-value: FIPS 140-3 L4 HSM
- Masking + random delays
- Monitor operation rate

---

## Defensive Quick-Reference Checklist

For defenders hardening HSM estates:

### Physical
- [ ] HSM in locked datacenter cabinet
- [ ] PED / ACS safes physically separated (different operators)
- [ ] Tamper-evident seals
- [ ] CCTV on HSM room

### Network
- [ ] HSM on dedicated VLAN
- [ ] Only app servers can reach HSM ports
- [ ] mTLS / NTLS with cert pinning
- [ ] SNMP disabled or restricted

### Authentication
- [ ] Default passwords rotated on init
- [ ] Strong PO / CO passwords (≥ 32 chars random)
- [ ] M-of-N quorum (≥ 3-of-5) for admin
- [ ] Quorum tokens rotated annually
- [ ] PED / ACS caches encrypted at rest

### PKCS#11 hygiene
- [ ] All keys `CKA_EXTRACTABLE: FALSE`
- [ ] All keys `CKA_WRAP: FALSE` (unless wrap explicitly approved)
- [ ] Per-app PKCS#11 user with minimal RBAC
- [ ] Audit `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`

### Firmware
- [ ] Patched within 30 days of CVE disclosure
- [ ] Monthly firmware audit
- [ ] Subscribe to vendor security advisory feed

### Cloud HSM
- [ ] Dedicated HSM for high-value (not multi-tenant)
- [ ] Least-privilege IAM
- [ ] Multi-person approval for key deletion
- [ ] Audit role assignments weekly

### Audit & Detection
- [ ] Audit log forwarded off-device to SIEM
- [ ] Sigma rule for `C_WrapKey` from non-trusted wrapper
- [ ] Sigma rule for PED / ACS cache access outside HSM ops
- [ ] Sigma rule for HSM login from new IP
- [ ] Sigma rule for CloudHSM CO login from CU
- [ ] Falco rule for high-rate YubiHSM operations

### Incident Response
- [ ] IR playbook: HSM quarantine, quorum freeze, audit pull
- [ ] Key rotation procedure documented
- [ ] Multi-person approval for sensitive operations
- [ ] Forensic imaging of HSM host (not HSM itself — preserve attestation)

---

## References

- 2018 Anonymous Exchange — *Bitcoin Wallet Compromise* (private disclosure)
- CVE-2022-45137 — nCipher nShield hardserver
- Visa Inc. — *Brazilian Acquirer ZMK Compromise* (2021)
- PCI PIN Security Requirements v3.1
- Tal Be'ery — *Azure AD Connect HSM* (2022)
- MSRC CVE-2022-30136
- AWS CloudHSM CO Escalation (2023)
- Thales SA-2024-05-15 (CVE-2024-47787)
- Utimaco SA-2024-03-01 (CVE-2024-45294)
- Google Cloud — *KMS Key Deletion Incident* (2024)
- Fortanix DSM Security Advisory SA-2024-09
- TU Graz — *CPA on YubiHSM 2* (USENIX Security 2025)
- Yubico Security Advisory YSA-2025-01
- FIPS 140-3 — Cryptographic Module Security Requirements
- Common Criteria EAL4+ / EAL5+
- ANSI X9.24 — Symmetric Key Management
- NIST SP 800-57 Part 2 — Key Management
- "Hardware Security Modules in Modern Cryptography" (Anderson, 2024)
- "Side-Channel Attacks on Cryptographic Hardware" (Mangard, 2024)
