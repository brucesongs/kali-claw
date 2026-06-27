# AD CS Detection, Hardening, and Operational Tradecraft

> A defensive-focused companion to `ad-cs-abuse-playbook.md`.
> Covers detection engineering, hardening recipes, ESC1-ESC15 remediation matrix, OPSEC tradecraft for red team operators, and real-world incident post-mortems.
> All telemetry and hardening guidance is documented for **authorized security testing** and blue-team consumption.

---

## 1. Introduction and Threat Model

This guide is the defensive mirror to the offensive playbook. Where the playbook teaches how to enumerate, exploit, and persist via AD CS, this guide teaches how to **detect** the abuse in real time, **harden** the PKI against the ESC1-ESC15 matrix, and **operate** with disciplined OPSEC so that authorized assessments produce clean, well-timed, and well-evidenced results.

### 1.1 Why AD CS Defenses Lag

Three structural factors make AD CS a durable attack surface:

1. **PKI is treated as background infrastructure.** Most enterprises stand up AD CS for a single use case (802.1X, SCCM client auth, S/MIME) and then leave the configuration untouched for years. Templates accumulate; ACLs drift; Web Enrollment stays enabled.
2. **The ESC1-ESC15 catalogue is dense.** Fifteen distinct misconfiguration classes mean defenders must audit fifteen orthogonal attributes (flags, EKUs, ACLs, CA registry, registry on the DC, IIS settings). Most teams only patch the headline CVEs (PetitPotam, Certifried) and miss the operational hardening.
3. **Detection telemetry is split across three log sources.** CA-side events (4886/4887) live on the CA server; DC-side events (4768/4769/4624) live on the DC; AD modification events (4662/5136) live on the DC that holds the role. Correlating these in a SIEM requires deliberate engineering.

### 1.2 Threat Model

This guide assumes a threat actor who:

- Has a foothold inside the network (phishing, VPN CVE, exposed service)
- Holds at least one domain user credential (or can coerce NTLM)
- Is targeting Domain Admin, Enterprise Admin, or Admins of the forest root
- Will use PKINIT-based authentication to bypass DCSync-class detection rules
- May have time-on-target of weeks (advanced persistent threat) or hours (opportunistic ransomware operator)

The defensive controls below are calibrated against this threat model.

---

## 2. Detection Engineering Foundations

### 2.1 Log Sources You Must Collect

A defensible AD CS deployment requires forwarding the following logs to a SIEM (Microsoft Sentinel, Splunk, Elastic, QRadar) from every CA and every DC:

| Host | Log Channel | Event IDs of Interest |
|------|-------------|------------------------|
| CA server | Security | 4886, 4887, 48868, 48869, 48865, 5125, 5136, 5137, 5141 |
| CA server | Application | CA shutdown (Event 4880), CA start (Event 4881), cert row revoke |
| CA server | IIS W3SVC* | All requests to `/certsrv/` (Web Enrollment) |
| DC | Security | 4624, 4625, 4662, 4768, 4769, 4771, 5136 |
| DC | Kerberos | PKINIT pre-auth events (event 4768 with `PreAuthenticationType=16`) |
| DC | System | Kerberos PAC validation failures |
| Network | DNS | Recursive lookups for `certsrv-*`, `_ldap._tcp.pki.*` |
| Network | SMB | DC-initiated outbound SMB sessions (rare in healthy networks) |

If any of these are not forwarded, the corresponding ESC class becomes a blind spot. The single most common gap is the **CA server's Security log** — many SIEM onboarding runbooks cover DCs but miss the CA because the CA is not a DC.

### 2.2 Baseline Before You Detect

Before deploying detection rules, capture a 30-day baseline of:

- Median daily count of Event 4886 (cert requests) per CA
- Top 10 templates by issuance volume
- Top 10 requestor accounts
- PKINIT TGT volume per hour (Event 4768 pre-auth 16)
- Geographic / subnet origin of cert requests

Any detection threshold you set without this baseline will either false-positive on normal business cycles (Monday-morning enrollment spikes) or false-negative on slow-and-quiet attackers.

### 2.3 The Detection Priority Pyramid

Not all detections are equal. Prioritize as follows:

1. **Tier 1 (Must-have, high signal)**: Shadow Credentials writes (4662 on KeyCredentialLink), PetitPotam-class anonymous coercion, PKINIT TGT for privileged accounts, SAN mismatch on issued certs.
2. **Tier 2 (Should-have, medium signal)**: Template ACL modification (5136 on `pKICertificateTemplate`), CA registry modification (4657 on `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc`), Web Enrollment from a new subnet.
3. **Tier 3 (Nice-to-have, low signal)**: Volume-based anomaly detection on 4886, failed enrollment spikes, certificate serial-number gaps indicating forgery.

---

## 3. Detection Rule Library

This section provides ready-to-deploy detection rules for the major AD CS attack patterns. Rules are provided in KQL (Microsoft Sentinel / Azure Monitor), Splunk SPL, and Sigma (generic).

### 3.1 Shadow Credentials -- msDS-KeyCredentialLink Write

The highest-signal single detection in the AD CS space. Any write to `msDS-KeyCredentialLink` outside of a documented Windows Hello for Business enrollment is suspicious.

**KQL (Sentinel)**:

```kusto
// Title: Shadow Credentials - KeyCredentialLink Write
// Severity: High
// MITRE: T1552.004 / T1606
let KeyCredentialLinkGuid = "5cb47ed8-8b67-4947-b91e-5f6e0bbe2c1a";
SecurityEvent
| where EventID == 4662
| where Properties has KeyCredentialLinkGuid
| where AccessMask has "0x10000" or AccessMask has "WRITE" or AccessMask has "WRITE_PROPERTY"
// Exclude legitimate Windows Hello for Business sources by user-agent / SPN pattern
| where not(Account startswith "MSOL_" or Account startswith "AAD_")
| join kind=leftouter (
    IdentityDirectoryEvents
    | where ActionType == "Directory object updated"
    | where AdditionalFields has "msDS-KeyCredentialLink"
    | project TimeGenerated, TargetAccount=TargetAccountName
) on TimeGenerated
| project TimeGenerated, Account, Computer, TargetAccount, Activity, Properties
```

**Splunk SPL**:

```splunk-spl
index=windows source="WinEventLog:Security" EventCode=4662
(`comment("Filter for KeyCredentialLink attribute GUID")`)
Properties="*5cb47ed8-8b67-4947-b91e-5f6e0bbe2c1a*"
AccessList="*WRITE*"
| stats count by _time, Computer, Account, TargetAccount, Properties
| rename Account as SourceAccount
| eval risk_score=90
| search SourceAccount!="MSOL_*" AND SourceAccount!="AAD_*"
```

**Sigma**:

```yaml
title: Shadow Credentials KeyCredentialLink Write
id: REPLACE_WITH_YOUR_UUID
status: experimental
description: Detects writes to msDS-KeyCredentialLink attribute, indicative of Shadow Credentials abuse
references:
    - https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8221a53766ac
author: kali-claw
date: 2026/06/27
tags:
    - attack.credential_access
    - attack.t1552.004
    - attack.t1606
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains: "5cb47ed8-8b67-4947-b91e-5f6e0bbe2c1a"
    filter_whfb:
        Account|startswith:
            - "MSOL_"
            - "AAD_"
            - "AZUREAD_"
    condition: selection and not filter_whfb
falsepositives:
    - Windows Hello for Business enrollment
    - FIDO2 key registration
    - Azure AD Connect sync
level: high
```

### 3.2 PetitPotam -- Anonymous NTLM Coercion

Anonymous logon (type 3) from a DC is a classic PetitPotam tell. Healthy DCs should never originate anonymous SMB/RPC sessions to internal hosts.

**KQL**:

```kusto
// Title: PetitPotam - DC-originated anonymous logon
// Severity: High
// MITRE: T1557.001 / T1550.002
let DCNames = dynamic(["DC01$", "DC02$", "DC03$"]); // REPLACE_WITH_YOUR_DC_LIST
SecurityEvent
| where EventID == 4624
| where TargetUserName =~ "ANONYMOUS LOGON"
| where LogonType == 3
| where Computer in (DCNames) or Computer hasprefix "DC"
| project TimeGenerated, Computer, IpAddress, IpPort, TargetUserName, LogonType, AuthenticationPackageName
```

**Splunk SPL**:

```splunk-spl
index=windows source="WinEventLog:Security" EventCode=4624
TargetUserName="ANONYMOUS LOGON" LogonType=3
(host=DC01 OR host=DC02 OR host=DC03 OR host="DC*")
| stats count by _time, host, Source_Network_Address, AuthenticationPackageName
| eval risk_score=85
```

### 3.3 PKINIT TGT for Privileged Account

PKINIT (pre-auth type 16) is rare in non-smart-card environments. A PKINIT TGT for Administrator, krbtgt, or any Domain Admin account is high-signal.

**KQL**:

```kusto
// Title: PKINIT TGT for privileged account
// Severity: Critical
// MITRE: T1550.004 / T1606
let PrivilegedAccounts = dynamic(["Administrator", "krbtgt", "Enterprise Admins"]);
let SmartCardUsers = dynamic(_GetWatchlist("SmartCardUsers") | project Account); // REPLACE_WITH_YOUR_WATCHLIST
SecurityEvent
| where EventID == 4768
| where PreAuthenticationType == 16
| where TargetUserName in (PrivilegedAccounts) or TargetUserName endswith "$" // machine accounts
| where TargetUserName !in (SmartCardUsers)
| project TimeGenerated, TargetUserName, ClientIpAddress, ClientPort, TicketEncryptionType, PreAuthenticationType, CertThumbprint
```

**Splunk SPL**:

```splunk-spl
index=windows source="WinEventLog:Security" EventCode=4768
Pre_Authentication_Type=16
(TargetUserName="Administrator" OR TargetUserName="krbtgt" OR TargetUserName="*Admin" OR match(TargetUserName, "\$$"))
| stats count, values(Client_Address) as src_ips by TargetUserName, _time
| eval risk_score=95
| search NOT [ | inputlookup smartcard_users.csv | fields user ]
```

### 3.4 ESC1 / ESC6 -- SAN Mismatch Between Requestor and Issued Subject

A high-fidelity CA-side detection: the account requesting the cert differs from the certificate's SAN value.

**KQL (against CA Security log forwarded to Sentinel)**:

```kusto
// Title: AD CS SAN mismatch (ESC1 / ESC6 indicator)
// Severity: High
Event
| where EventLog == "Security" and EventID in (4887, 48869)
| parse Message with * "Requester: " RequesterName * "Subject: " Subject * "Template: " Template * "SAN: " SAN *
| extend RequesterSAN = strcat(RequesterName)
| where isnotempty(SAN)
| where SAN !contains RequesterName
| project TimeGenerated, RequesterName, Subject, SAN, Template, Computer
```

**Splunk SPL**:

```splunk-spl
index=adcs source="WinEventLog:Security" (EventCode=4887 OR EventCode=48869)
| rex field=_raw "Requester:\s+(?<requester>[^\r\n]+)"
| rex field=_raw "Subject:\s+(?<subject>[^\r\n]+)"
| rex field=_raw "Template:\s+(?<template>[^\r\n]+)"
| rex field=_raw "Alternative Name:\s+(?<san>[^\r\n]+)"
| where isnotnull(san) and san != "" and !like(san, "%" . requester . "%")
| stats count by _time, host, requester, subject, san, template
| eval risk_score=80
```

### 3.5 ESC8 -- NTLM Relay to Web Enrollment

Web Enrollment access from a non-typical source, especially in close temporal proximity to a coercion event.

**KQL (IIS logs forwarded to Sentinel)**:

```kusto
// Title: ESC8 - NTLM auth to AD CS Web Enrollment
// Severity: High
W3CIISLog
| where csHost has "certsrv"
| where sPort in ("80", "443")
| where csUriStem has "certfnsh.asp" or csUriStem has "certrsis.asp" or csUriStem has "certrsms.asp"
| where csUserAgent !has "Microsoft-CryptoAPI"  // legitimate enrollment uses CryptoAPI
| project TimeGenerated, sIPAddress, csUriStem, csUserAgent, csUserName, scStatus
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 3
    | where AuthenticationPackageName == "NTLM"
    | project TimeGenerated, IpAddress, TargetUserName, Computer
) on $left.sIPAddress == $right.IpAddress
```

**Splunk SPL**:

```splunk-spl
index=iis sourcetype=iis cs_host="*certsrv*"
(cs_uri_stem="*/certfnsh.asp" OR cs_uri_stem="*/certrsis.asp")
| search NOT (cs_user_agent="*CryptoAPI*" OR cs_user_agent="*certenroll*")
| stats count, values(cs_username) as user by c_ip, cs_uri_stem, _time
| join c_ip [ search index=windows EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
              | stats count by Source_Network_Address | rename Source_Network_Address as c_ip ]
| eval risk_score=85
```

### 3.6 ESC4 / ESC5 / ESC7 -- Template or CA ACL Modification

Modification of PKI AD objects is rare and almost always operational.

**KQL**:

```kusto
// Title: PKI object modification (ESC4/5/7)
// Severity: Medium
let PKIDNs = dynamic(
    [
    "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration",
    "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration",
    "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration"
    ]);
SecurityEvent
| where EventID == 5136
| where ObjectDN has any (PKIDNs)
| where ObjectClass in ("pKICertificateTemplate", "certificationAuthority", "serviceClass")
| project TimeGenerated, ObjectDN, AttributeLDAPDisplayName, AttributeValue, OpCorrelationID, SubjectUserName
```

### 3.7 ESC11 -- Unauthenticated ICPR Relay

The ICPR (RPC) interface accepting unauthenticated sessions is the prerequisite for ESC11. Detect the precondition.

**KQL (network telemetry)**:

```kusto
// Title: ESC11 - Anonymous bind to ICPR endpoint on CA
// Severity: Medium
AzureNetworkAnalytics
| where DestinationPort in (135, 445)
| where DestinationIP in (CA_IP_LIST) // REPLACE_WITH_YOUR_CA_IPS
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and TargetUserName =~ "ANONYMOUS LOGON"
    | project TimeGenerated, IpAddress
) on $left.TimeWindow == $right.TimeGenerated
```

### 3.8 Golden Certificate -- Cert Presented but Not in CA Database

A PKINIT-presented certificate whose serial number does not appear in `certsrv.edb` is a forgery indicator.

**Splunk SPL (correlating Kerberos with CA DB export)**:

```splunk-spl
`comment("Compare PKINIT-presented serials with CA database")
| inputlookup ca_database_export.csv
| dedup SerialNumber
| eval in_ca_db = "true"
| append [
    search index=windows EventCode=4768 Pre_Authentication_Type=16
    | rex "Certificate Serial Number:\s+(?<SerialNumber>[0-9A-Fa-f]+)"
    | eval in_ca_db = "false"
]
| stats values(in_ca_db) as seen_by SerialNumber
| where seen_by == "false"
```

### 3.9 Certifried -- Machine dNSHostName Collision

Machine-account `dNSHostName` modification is rare and almost always adversarial.

**KQL**:

```kusto
// Title: Certifried - machine dNSHostName modification
// Severity: High
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName == "dNSHostName"
| where ObjectClass == "computer"
| where SubjectUserName !endswith "$"  // machine self-modification is unusual
| project TimeGenerated, ObjectDN, SubjectUserName, OldValue, NewValue
```

### 3.10 Volume Anomaly -- Burst of Certificate Requests

A sudden spike in 4886 events may indicate enumeration or batch enrollment.

**KQL (using series_decompose_anomalies)**:

```kusto
// Title: AD CS - certificate request volume anomaly
// Severity: Low
let threshold = 3.0; // REPLACE_WITH_YOUR_TUNED_THRESHOLD
SecurityEvent
| where EventID == 4886
| make-series count = count() on TimeGenerated from ago(14d) to now() step 1h default = 0
| extend anomalies = series_decompose_anomalies(count, threshold, 'linefit', 1, 'spack', -1, 'spack')
| extend is_anomaly = series_multiply(anomalies, count)
| where series_has_true(is_anomaly, true())
```

---

## 4. Microsoft Defender for Identity Detection Coverage

Microsoft Defender for Identity (MDI) is Microsoft's cloud-based UEBA for on-prem AD. It raises built-in alerts for several AD CS patterns. As of mid-2026, the relevant alerts are:

### 4.1 Built-in Alerts to Enable

| MDI Alert | Attack Pattern | Default State |
|-----------|----------------|---------------|
| Suspicious modification of a KeyCredentialLink | Shadow Credentials | Enabled |
| Suspected NTLM relay attack (exchange server) | PetitPotam / NTLM relay | Enabled |
| Suspected use of Metasploit LT | Generic credential theft | Enabled |
| Suspected Golden Ticket usage | PKINIT-derived TGT abuse | Enabled |
| Suspected DCShadow attack | PKI object modification (sometimes correlates) | Enabled |
| Suspicious service account behavior | Service account PKINIT | Enabled |
| Unusual protocol implementation | Non-standard enrollment clients | Enabled |

### 4.2 MDI Sensor Placement

Install MDI sensors on **every DC** and on **every AD CS server** that is also a member server. Standalone CAs in a workgroup are out of MDI scope; rely on SIEM rules for those.

### 4.3 Tuning Recommendations

- Add service accounts (those expected to enroll certificates via PKINIT for automation) to the **tagged service accounts** list in MDI. This reduces false positives on legitimate PKINIT.
- Document any change-management activity in MDI's activity tag system. Template ACL changes outside change windows will then alert cleanly.

---

## 5. Open Source Detection Tools

The GitHub-trending open-source tooling for AD CS detection has matured significantly since 2023. The following are recommended for any AD CS defense program.

### 5.1 Locksmith

**Repo**: `TrimarcJake/Locksmith` (Trimarc, Jake Krasnoff et al.)

Locksmith is a PowerShell module that audits AD CS for the full ESC1-ESC15 matrix and outputs a remediation-ready report. It is the defensive counterpart to Certipy's `find -vulnerable`.

```powershell
# Install Locksmith
Install-Module -Name Locksmith -Scope AllUsers -Force
# Or fetch latest from GitHub
git clone https://github.com/trimarcjake/Locksmith.git
Import-Module .\Locksmith\Locksmith.psd1

# Run a full audit
Invoke-Auditor -Mode 1
# Mode 1 = console summary
# Mode 2 = HTML report
# Mode 3 = CSV
# Mode 4 = full report with remediation scripts
```

Locksmith identifies:
- ESC1 (ENROLLEE_SUPPLIES_SUBJECT with Client Auth EKU)
- ESC4 (writable templates)
- ESC5 (writable CA / NTAuthCertificates)
- ESC6 (EDITF flag)
- ESC7 (ManageCA / ManageCertificates on non-admins)
- ESC8 (Web Enrollment exposed without EPA)
- ESC11 (ICPR without encryption enforcement)
- ESC13 (issuance policy to high-priv group mapping)
- ESC15 (lua application EKU)

### 5.2 Pascal-3nk4 / ADCSToolkit

**Repo**: `zynnnnnn/ADCSToolkit` and related forks

ADCSToolkit is a defensive toolkit focused on detecting issued-certificate anomalies and CA database forensics. It is especially useful for **post-incident response** to identify which issued certificates were used in the attack.

```powershell
# Install
git clone https://github.com/zynnnnnn/ADCSToolkit.git
Import-Module .\ADCSToolkit\ADCSToolkit.psd1

# Dump the CA database for forensic analysis
Get-ADCSCertDatabase -CAName "CORP-CA01-CA" -OutFile .\ca_db.csv

# Cross-reference PKINIT-presented certs with CA DB
Find-ADCSForgedCert -KerberosLogPath .\4624_evtx\ -CADatabase .\ca_db.csv
```

### 5.3 CSiquer / ADCSPwn2Detect

For runtime detection of relay activity against AD CS, several blue-team forks of ADCSPwn instrument the listener with honey-token URLs. Configure a fake `certsrv` endpoint with an EPA-enforced listener and alert on any client that hits the unprotected path.

### 5.4 Certify in Audit Mode

The offensive tool Certify (GhostPack) can be operated in an audit-only mode by defenders to baseline the ESC exposure of the enterprise. Schedule it weekly:

```powershell
# Schedule a weekly Certify audit
$action = New-ScheduledTaskAction -Execute "Certify.exe" -Argument "find /vulnerable /quiet"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
Register-ScheduledTask -TaskName "ADCS-EscAudit" -Action $action -Trigger $trigger -User "CORP\svc_adcsaudit" -Password 'REPLACE_WITH_YOUR_SERVICE_ACCOUNT_PASSWORD'
```

Pipe the output to the SIEM via a custom log forwarder. Compare week-over-week for drift.

### 5.5 PKI Health Matrix (custom)

For environments where commercial tooling is unavailable, the following PowerShell pipeline produces a CSV baseline of every template's ESC-relevant attributes:

```powershell
$templates = Get-ADObject -Filter {ObjectClass -eq "pKICertificateTemplate"} -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" -Properties *
$results = foreach ($t in $templates) {
    $acls = (Get-Acl "AD:$($t.DistinguishedName)").Access
    [PSCustomObject]@{
        Name = $t.Name
        ENROLLEE_SUPPLIES_SUBJECT = ($t."msPKI-Certificate-Name-Flag" -band 0x1) -ne 0
        EDITF = ""
        EKU = ($t.pKIExtendedKeyUsage) -join ";"
        EnrollmentACL = ($acls | Where-Object {$_.ActiveDirectoryRights -match "ExtendedRight" -and $_.ObjectType -eq "0e10c968-78fb-11d2-90d4-00c04f79dc55"} | Select-Object IdentityReference) -join ";"
        WriteACL = ($acls | Where-Object {$_.ActiveDirectoryRights -match "Write|GenericAll"} | Select-Object IdentityReference) -join ";"
        ManagerApproval = ($t."msPKI-Enrollment-Flag" -band 0x2) -ne 0
    }
}
$results | Export-Csv -NoTypeInformation -Path .\adcs_baseline.csv
```

---

## 6. Hardening Checklist

This section provides a concrete, actionable hardening checklist. Each item includes the exact command or GPO setting and the ESC class it mitigates.

### 6.1 Forest-Root Hardening

- [ ] **Set `StrongCertificateBindingEnforcement = 2` (Full Enforce) on every DC.** This is the single most impactful hardening step. It neutralises ESC9 and ESC10 and limits the blast radius of ESC1/ESC6.
  ```cmd
  reg add HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2 /f
  ```
  Deploy via GPO under `Computer Configuration > Policies > Administrative Templates > System > KDC > Strong certificate binding enforcement`.

- [ ] **Apply KB5014754 (May 2022)** and confirm it is in Full Enforce mode (post-November 2023). Check mode:
  ```cmd
  reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc\Parameters /v StrongCertificateBindingEnforcement
  ```

- [ ] **Apply CVE-2024-49019 patch (ESC15)** on all DCs and CAs. Check the build number against the Microsoft Security Update Guide.

- [ ] **Block MS-EFSRPC at the host firewall** on DCs (mitigates PetitPotam at the network layer as defense-in-depth):
  ```powershell
  New-NetFirewallRule -DisplayName "Block MS-EFSRPC" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block -Program "C:\Windows\System32\lsass.exe"
  ```
  Use a scoped rule that only blocks EFSRPC over SMB from non-DC hosts.

### 6.2 CA-Level Hardening

- [ ] **Remove `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` from every CA.** Mitigates ESC6.
  ```cmd
  certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTSSUBJECT2
  net stop certsvc && net start certsvc
  ```

- [ ] **Enforce RPC encryption on ICPR.** Mitigates ESC11.
  ```cmd
  certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICSPREQUEST
  net stop certsvc && net start certsvc
  ```

- [ ] **Restrict `ManageCA` and `ManageCertificates` to Domain Admins / Enterprise Admins.** Mitigates ESC7.
  ```powershell
  $ca = Get-CertificationAuthority "CORP-CA01-CA"
  $acl = Get-ACL "AD:$($ca.DistinguishedName)"
  $acl.Access | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl"} | ForEach-Object {
      # Remove non-admin principals
      if ($_.IdentityReference -notmatch "Domain Admins|Enterprise Admins|Administrators") {
          $acl.RemoveAccessRule($_) | Out-Null
      }
  }
  Set-ACL "AD:$($ca.DistinguishedName)" -AclObject $acl
  ```

- [ ] **Disable Web Enrollment unless explicitly required.** Mitigates ESC8.
  ```powershell
  Uninstall-WindowsFeature -Name ADCS-Web-Enrollment -IncludeManagementTools
  ```

- [ ] **If Web Enrollment is required, enforce Extended Protection for Authentication (EPA) / Channel Binding Tokens.** This blocks NTLM relay to the HTTP endpoint.
  ```powershell
  # In IIS Manager -> Application Pools -> DefaultAppPool -> Advanced Settings
  # OR via appcmd:
  C:\Windows\System32\inetsrv\appcmd.exe set config "Default Web Site/certsrv" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Allow" /commit:apphost
  ```
  Move `tokenChecking` to `Require` once compatibility is confirmed.

- [ ] **Require SMB signing on all CAs.** Prevents SMB relay to the CA itself.
  ```powershell
  Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
  ```

### 6.3 Template Hardening (per-template)

For each template:

- [ ] **Remove `ENROLLEE_SUPPLIES_SUBJECT` flag** from any template whose EKU includes Client Authentication, PKINIT Client, Smart Card Logon, or AnyPurpose. Mitigates ESC1.
  ```powershell
  $template = "CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
  $obj = Get-ADObject $template -Properties msPKI-Certificate-Name-Flag
  $newFlag = $obj."msPKI-Certificate-Name-Flag" -band (-bnot 0x1)
  Set-ADObject $template -Replace @{"msPKI-Certificate-Name-Flag" = $newFlag}
  ```

- [ ] **Remove AnyPurpose / no-EKU templates** unless they are explicitly required (e.g., code signing infrastructure). Mitigates ESC2.

- [ ] **Restrict PKINIT KDC EKU templates to Domain Controllers only.** The EKU OID is `1.3.6.1.5.2.3.5`. Mitigates ESC3 (KDC cert abuse).

- [ ] **Restrict Enrollment Agent EKU templates to narrowly-scoped service accounts.** The EKU OID is `1.3.6.1.4.1.311.20.2.1`. Mitigates ESC3 (Enrollment Agent chain).

- [ ] **Require manager approval on templates that issue high-priv certificates.** Set `msPKI-Enrollment-Flag` to include `CT_FLAG_PEND_ALL_REQUESTS` (0x2).

- [ ] **Remove `WriteProperty`, `WriteDacl`, `WriteOwner`, `GenericAll` from non-admin principals** on every template. Mitigates ESC4.

- [ ] **Remove the `lua application` EKU (`1.3.6.1.4.1.311.95.1.1`)** from all templates. Mitigates ESC15.

### 6.4 CA Private Key Hardening (Golden Certificate Defense)

- [ ] **Deploy the CA private key on an HSM.** This is the only reliable defense against Golden Certificate. The CA's private key never leaves the HSM boundary, so even a CA administrator with full filesystem access cannot extract it.
  - Supported HSM vendors: Thales Luna, YubiHSM 2 (for small deployments), AWS CloudHSM, Azure Dedicated HSM.
  - Configure via `certutil -csp "Microsoft Smart Card Key Storage Provider"` or vendor-specific CSP.

- [ ] **Use a three-tier hierarchy**: offline Root CA (powered off), online Policy CA, online Issuing CAs. Compromise of an Issuing CA does not grant forest-root trust.

- [ ] **Restrict CA database backups** to a small admin group. The CA database + CA private key together enable certificate forgery.

- [ ] **Enable CA database auditing at maximum verbosity.**
  ```cmd
  certutil -setreg CA\Auditfilter 127
  net stop certsvc && net start certsvc
  ```

---

## 7. ESC1-ESC15 Remediation Matrix

A one-glance matrix mapping each ESC class to its precondition, detection rule from this guide, and remediation step.

| ESC | Precondition (one-liner) | Detection Rule (Section) | Remediation (command/setting) | Verification |
|-----|--------------------------|--------------------------|-------------------------------|--------------|
| **ESC1** | `ENROLLEE_SUPPLIES_SUBJECT` + Client Auth EKU + requester can enroll | 3.4 SAN mismatch | Remove flag: `Set-ADObject -Replace @{"msPKI-Certificate-Name-Flag"=0}` | Locksmith audit shows 0 ESC1 templates |
| **ESC2** | Template has AnyPurpose / no EKU | 3.10 volume baseline | Remove template or restrict ACL to admins | Locksmith audit |
| **ESC3** | PKINIT KDC EKU + broad enrollment; OR Enrollment Agent chain | 3.4 + CA DB review | Restrict ACL on KDC template to Domain Controllers | Manual ACL review |
| **ESC4** | Writable template by non-admin | 3.6 PKI object modification | Remove write ACEs | `Get-ACL` review |
| **ESC5** | Writable PKI AD object (CA / NTAuth / etc.) | 3.6 | Remove write ACEs | Locksmith audit |
| **ESC6** | `EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` CA flag set | 3.4 SAN mismatch | `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTSSUBJECT2` | `certutil -getreg policy\EditFlags` |
| **ESC7** | `ManageCA` on non-admin | 3.6 | Restrict CA ACL to Domain Admins | CA ACL audit |
| **ESC8** | Web Enrollment exposed without EPA | 3.5 IIS NTLM | `Uninstall-WindowsFeature ADCS-Web-Enrollment` OR enforce EPA | `curl -k http://<ca>/certsrv/` returns 401 with CBT required |
| **ESC9** | `StrongCertificateBindingEnforcement = 1` (Audit) | 3.3 PKINIT TGT | `reg add ... /v StrongCertificateBindingEnforcement /d 2 /f` | Registry query |
| **ESC10** | Weak subjectSid mapping (Audit mode) | 3.3 | Same as ESC9 | Same as ESC9 |
| **ESC11** | ICPR accepts unauthenticated relay | 3.7 Anonymous ICPR bind | `certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICSPREQUEST` | `certutil -getreg CA\InterfaceFlags` |
| **ESC12** | `MachineCertificateEdition` misconfigured | 3.6 | Template re-creation | Manual template audit |
| **ESC13** | Issuance policy mapped to high-priv group | 3.6 | Remove issuance policy to group GPO mapping | Group Policy review |
| **ESC14** | Attacker-controllable AIA URL | 3.6 + AIA audit | Hardcode AIA to internal HTTPS endpoint | `pkiview.msc` |
| **ESC15** | `lua application` EKU present | 3.6 + template EKU audit | Apply CVE-2024-49019 patch; remove EKU | Patch level; Locksmith audit |

---

## 8. OPSEC Tradecraft for Authorized Operators

This section is intended for **authorized red team operators and penetration testers** working under a signed statement of work. The goal is to perform accurate, well-evidenced assessments without producing collateral noise that harms the client's security operations or causes alert fatigue in their SOC.

### 8.1 Pre-Engagement OPSEC

Before touching the client's PKI:

1. **Coordinate with the SOC.** Identify a point of contact in the client's security operations center. Provide engagement windows and the source IPs / accounts you will use. This allows them to baseline your activity and avoid false positives that waste analyst cycles.
2. **Confirm scope.** Get explicit written authorization for: certificate template enumeration, certificate enrollment against any template, and (if applicable) template/CA modification (ESC4/5/7). Many scopes exclude PKI modification because of the persistence risk.
3. **Agree on rollback.** For any template/CA modification, agree in writing on the rollback procedure and who is responsible if rollback fails. Prefer `certipy template -save-old` and store the JSON in your engagement vault.
4. **Decide on detection dry-runs.** Many mature clients want a detection validation run: you execute the technique, they confirm whether their SIEM fired. This is a value-add — offer it explicitly.

### 8.2 During-Engagement OPSEC

#### 8.2.1 Certipy Operational Discipline

Certipy is the standard tool, but its default output verbosity is loud. Recommended flags:

```bash
# Quiet output, write JSON to disk for offline analysis
certipy find -u 'CORP\svc_audit' -p 'REPLACE_WITH_YOUR_PASSWORD' -dc-ip 10.10.0.1 \
  -json -output /path/to/engagement/vault/ > /dev/null

# Read from cached JSON, do not re-hit LDAP
certipy find -json /path/to/engagement/vault/certipy_find.json -vulnerable
```

Notes:
- Certipy's LDAP queries hit the Configuration partition aggressively. A high-volume `find -vulnerable` against a large forest can produce tens of thousands of LDAP reads. Use `-ldap-filter` to scope.
- Avoid `find -bloodhound` in engagements where you do not have explicit BloodHound scope — it produces graph data that is operationally sensitive.

#### 8.2.2 Evading EDR Hooks on Windows Footholds

When running Certify / Rubeus / Whisker on a Windows foothold via Cobalt Strike `execute-assembly`:

- **ETW (Event Tracing for Windows) bypass**. Many EDRs hook ETW for .NET assembly load events. Coordinate with your engagement lead on whether an ETW patch is in scope. Never run未经授权的 ETW bypass.
- **In-memory execution**. Certify and Rubeus both run in-memory via `execute-assembly`. The assembly is loaded into the beacon's process — choose a sacrificial process with a benign PPID (e.g., `svchost.exe` spawned by `services.exe`).
- **OPSEC-safe process spawning**. Avoid spawning `cmd.exe` or `powershell.exe` from your beacon; many EDRs alert on this pattern. Use `execute-assembly` directly or BOFs (Beacon Object Files).
- **Use native tools when possible**. `certutil.exe` is signed by Microsoft and is on every Windows host. Prefer it over third-party tools where the operation can be expressed natively:
  ```cmd
  certutil -view -restrict "Disposition=20" -out "RequestID,RequesterName,SerialNumber"
  ```

#### 8.2.3 Certificate Chain Confusion Tactics

When PKINITing with an issued certificate, the resulting TGT will use the certificate's subject as the principal. Some defensive tools (older versions of MDI, custom SIEM rules) correlate PKINIT TGTs with smart-card user lists.

- **If your engagement allows**, request the certificate against a target whose smart-card enrollment is expected (e.g., a service account that has a documented smart card). The PKINIT TGT then appears in the "expected" list.
- **Avoid requesting Administrator's TGT directly** in environments with mature detection. Instead, PKINIT as a service account that has `GenericAll` on Administrator via BloodHound, then perform the escalation via standard AD techniques. This separates the PKINIT event from the privilege-escalation event.
- **Time-stagger PKINIT and credential use**. The classic error is to PKINIT at 14:00:01 and run `secretsdump` at 14:00:05. Mature correlation rules link these. Stagger by 10-30 minutes minimum.

#### 8.2.4 Lifecycle Hygiene — Certificate Cleanup After Use

Every certificate you issue during an engagement leaves a row in the CA database (`certsrv.edb`) with serial number, requester, and template. These rows persist indefinitely and will be discovered in any post-engagement audit.

Hygiene procedure:

1. **Document every issued certificate** in your engagement log: serial number, template, target UPN, timestamp.
2. **Revoke the certificate if you have CA Operator access** (ESC7 chain):
   ```cmd
   certutil -revoke <SerialNumber> "Cease of Operation"
   ```
   This adds the serial to the CRL but does not delete the issuance record. The certificate will fail validation on next use.
3. **If you have CA Database Administrator access**, the row can be archived (not deleted — CA DB does not support row deletion by design). Document this clearly.
4. **Hand off the certificate list to the client at the end of the engagement** so they can validate that no orphan certificates remain active.
5. **For Shadow Credentials**, always clean up the `msDS-KeyCredentialLink` value at the end of the engagement:
   ```bash
   pywhisker.py -d corp.local -u 'svc_audit' -p 'REPLACE_WITH_YOUR_PASSWORD' \
     --target 'DC01$' --action 'remove' --device-id REPLACE_WITH_YOUR_DEVICE_ID
   ```
   Never leave a Shadow Credential in place post-engagement — it survives password resets.

#### 8.2.5 NTLM Relay OPSEC

For ESC8 / ESC11 chains:

- **Use a single, low-volume relay listener.** Do not use `Coercer` in sweep mode against the entire domain — this triggers 4624 events across many hosts and is the single most common false-positive generator.
- **Target one host at a time.** PetitPotam the DC explicitly. The coercion event is unavoidable but is contained to a single source-target pair.
- **Choose a relay target with benign-looking source IP**. If your engagement VLAN is in the SOC's allowlist, your relay will not trip network-based detections.
- **Avoid relay to LDAPS / LDAP signing-required targets**. These fail and produce 4625 events that are easy to correlate with the relay window.

#### 8.2.6 Template Modification OPSEC (ESC4 / ESC5 / ESC7)

For template/CA modifications:

- **Always save the old state**. `certipy template -save-old` writes the original template configuration to a JSON file. Restore after the request.
- **Modify, request, restore in a single batch**. Do not leave the modified template in place for hours. A defender running a periodic audit during that window will detect the modification.
- **Use `OpCorrelationID` correlation**. AD object modifications carry an `OpCorrelationID` (Event 5136). A modify-request-restore batch will share a correlation ID, making the engagement trace cleaner.
- **Avoid creating new templates** unless explicitly authorized. New template creation (Event 5137) is louder than modification of an existing template.

### 8.3 Post-Engagement OPSEC

1. **Provide the SOC a timeline** of all engagement activities with timestamps. This lets them confirm their detection coverage and tune their rules.
2. **Validate that no persistence remains**. Re-enumerate the PKI post-engagement. Look for:
   - New templates you created and forgot to remove
   - Modified CA flags not restored
   - Active certificates with your engagement source IP
   - `msDS-KeyCredentialLink` values you wrote
3. **Hand off artifacts**. Provide the client with:
   - The CA database export of all certificates issued during the engagement
   - The list of templates modified and their before/after configurations
   - The list of all credentials compromised (for rotation)
4. **Schedule a re-test** to validate remediation.

### 8.4 Anti-Patterns (Avoid These)

- **Running `certipy find` with no flags against a 100K-user forest**. This produces a massive LDAP query burst that triggers anomaly detection and may impact DC performance.
- **Using `Coercer` in sweep mode** without coordination. This generates hundreds of NTLM auth events across the domain in minutes.
- **Leaving Shadow Credentials in place** at the end of the engagement. This is the #1 cause of post-engagement incidents.
- **PKINITing as `krbtgt`** for demonstration. The TGT this produces can forge further TGTs (Golden Ticket class). Use `Administrator` or a DC machine account for demonstrations instead.
- **Modifying the `krbtgt` template** or any template with PKINIT KDC EKU. Even temporarily, this exposes the domain to KDC impersonation.

---

## 9. Real-World Incident Post-Mortems

This section documents publicly disclosed incidents involving AD CS abuse. The goal is to ground the techniques in observed threat actor behavior so that defenders and operators understand the realistic use of these techniques.

### 9.1 PetitPotam (July 2021) -- Topotam Wormable Research

**Researcher**: Gilles Lionel (@topotam77)
**CVE**: CVE-2021-36942
**Patch**: August 10, 2021 Cumulative Update
**Original disclosure**: July 12, 2021 via Twitter PoC

PetitPotam was disclosed as a PoC on Twitter by Topotam in July 2021. The technique abuses the `MS-EFSRPC` `EfsRpcOpenFileRaw` method to coerce a target machine into authenticating to an attacker-controlled IP via NTLM. The original PoC required no authentication — any network-adjacent attacker could trigger a DC to authenticate to them.

The disclosure triggered a fire drill because:

1. **It was wormable in unpatched forests.** A single anonymous foothold could coerce every DC in turn, relaying each to AD CS for a DC cert.
2. **It combined cleanly with ESC8** (Web Enrollment relay) for an unauthenticated-to-Domain-Admin chain.
3. **The August 2021 patch only addressed anonymous coercion.** Authenticated coercion (any domain user) continued to work post-patch, leaving the technique viable for any attacker with a low-priv foothold.

**Detection indicators observed in the wild**:
- Event ID 4624 (anonymous logon type 3) from the DC to internal hosts
- Outbound SMB / MS-EFSRPC traffic from the DC to non-DC hosts
- Event ID 4768 (PKINIT TGT) for the DC machine account immediately after the coercion

**Post-mortem lesson**: PetitPotam demonstrated that **authentication coercion is a first-class escalation path** in AD. The patch mitigated the specific vector but the broader lesson — that DCs should never originate NTLM to internal hosts — remains under-appreciated.

### 9.2 Certifried (May 2022) -- Oliver Lyak / Yair Mizrahi Disclosure

**Researcher**: Yair Mizrahi (@yairmx8), Amplify Security, building on prior work by Oliver Lyak (@ly4k) on Certipy
**CVE**: CVE-2022-26923
**Patch**: May 10, 2022 Cumulative Update

Certifried exploits a logic flaw in how AD CS maps machine account attributes to certificate subjects. The CA uses the machine's `dNSHostName` attribute as the certificate's DNS Subject Alternative Name. By patching a newly-created machine account's `dNSHostName` to collide with a DC's hostname, an attacker obtains a certificate that authenticates as the DC.

The attack bypasses the post-KB5005413 strong-certificate-mapping hardening because the certificate is issued to the attacker's machine account, and the strong-mapping SID extension correctly matches that account — but the certificate's DNS SAN matches the DC, allowing PKINIT to authenticate as the DC via the Subject alternative name path.

**Patch details**: The May 2022 patch adds a `dNSHostName` collision check at the CA, rejecting requests where the `dNSHostName` collides with an existing computer's `dNSHostName` + SPN. The check is bypassable in configurations where the SPN check is not enforced, leading to ongoing research into Trust boundary bypasses.

**Threat actor usage**: Multiple ransomware operators used Certifried in 2022-2023 against unpatched environments. The combination of Certifried + PetitPotam-style relay provides redundant paths to DC impersonation, making it viable against partially-patched environments.

**Detection indicators**:
- Event ID 5136 (directory service object modified) on the `dNSHostName` attribute of a computer object
- Event ID 4886 / 4887 (certificate request / issued) for the Machine template by a recently-created machine account
- Event ID 4768 (PKINIT TGT) for a DC machine account originating from a non-DC source IP

### 9.3 Black Basta Ransomware (2022-2024)

Black Basta is a Russia-linked ransomware-as-a-service operation that emerged in early 2022. Multiple Mandiant and Microsoft threat intelligence reports document their use of AD CS abuse as part of the intrusion chain.

**Typical Black Basta AD CS playbook** (observed in 2022-2023 intrusions):

1. Initial access via Qakbot phishing or exploited VPN (FortiOS, Pulse Secure)
2. Cobalt Strike beacon deployment
3. AD CS discovery via `certify find /vulnerable`
4. ESC1 exploitation against an existing vulnerable Client Auth template
5. PKINIT for a Domain Admin TGT
6. DCSync for krbtgt
7. Lateral movement via PsExec / WMI to deploy ransomware

Black Basta's preference for ESC1 over ESC8 is notable: ESC1 is quieter (no coercion, no relay, single PKINIT event) and works in environments where Web Enrollment is disabled. Their consistent use of `Certify.exe` in-memory via Cobalt Strike `execute-assembly` is the canonical detection target.

**Detection opportunity**: Defenders who monitor for `Certify.exe` assembly load events (via ETW or EDR) can detect Black Basta's AD CS reconnaissance before exploitation. Microsoft Defender for Endpoint's `ASR rules` can block `Certify.exe` from non-trusted paths.

### 9.4 Akira Ransomware (2023-2024)

Akira is a ransomware operation that emerged in early 2023 and has consistently used AD CS abuse. Their typical pattern:

1. Initial access via compromised Cisco VPN (CVE-2023-20269) or SonicWall CVEs
2. LSASS dumping for initial credentials
3. BloodHound mapping for AD CS paths
4. **ESC8 exploitation via PetitPotam + ntlmrelayx** where Web Enrollment is exposed
5. **ESC4 exploitation** (template ACL modification) where writable templates exist
6. PKINIT for Domain Admin
7. Data exfiltration via rclone
8. Ransomware deployment

Akira's dual-use of both ESC8 and ESC4 demonstrates that they audit the environment and choose the path of least resistance. Their reliance on open-source tooling (ntlmrelayx, Certipy, Coercer) makes them highly detectable in environments with mature SIEM rules — but most victims lack such rules.

**Detection opportunity**: Akira frequently uses `Coercer` in sweep mode, which generates hundreds of NTLM auth events across the domain. This is a high-signal detection: any single host originating NTLM to many other hosts in a short window is anomalous.

### 9.5 Other Notable Operations

- **Cuba Ransomware** (2022-2023): Documented use of ESC1 against Microsoft SCCM-supplied templates. SCCM frequently deploys AD CS templates with `ENROLLEE_SUPPLIES_SUBJECT` for client auth, making it a consistent ESC1 target.
- **Royal / BlackSuit Ransomware** (2023-2024): Use of ESC7 (ManageCA abuse) to modify CA flags as part of the escalation chain. Less common but observed in intrusions where the initial foothold had elevated CA rights.
- **APT29 / Nobelium** (SolarWinds-related): Documented use of Golden Certificate (forged from CA private key extracted via supply chain compromise of a CA server). Demonstrates that nation-state operators will invest in CA private key extraction when the target justifies it.

### 9.6 Common Patterns Across Incidents

Analyzing the public incident data reveals:

1. **ESC1 and ESC8 are the workhorses**. Most ransomware operators use one of these two. ESC2-ESC7 and ESC9-ESC15 are less commonly used in the wild because they require more specific preconditions.
2. **Web Enrollment exposure is the highest-impact misconfiguration**. Every public incident involving AD CS relay (ESC8 / ESC11) required Web Enrollment to be enabled.
3. **Tooling is consistent**. Threat actors use the same open-source tools as red teams (Certipy, Certify, ntlmrelayx, Coercer). This means detection rules written for offensive tooling have direct production value.
4. **Time-to-exploitation is short**. In observed incidents, the time from initial access to PKINIT-as-Domain-Admin is measured in hours, not days. Detection must be real-time, not retrospective.

---

## 10. Continuous Improvement

### 10.1 Quarterly Audit Cadence

Run the following audit quarterly:

```powershell
# 1. Run Locksmith for ESC exposure
Invoke-Auditor -Mode 4 -OutputPath C:\Audit\Q1-2026\

# 2. Run PKI Health Matrix baseline
# (PowerShell script from Section 5.5)
.\Get-PKIHealthMatrix.ps1 | Export-Csv C:\Audit\Q1-2026\pki_baseline.csv

# 3. Run Certify in audit mode
.\Certify.exe find /vulnerable /quiet > C:\Audit\Q1-2026\certify.txt

# 4. Compare to last quarter
$last = Import-Csv C:\Audit\Q4-2025\pki_baseline.csv
$this = Import-Csv C:\Audit\Q1-2026\pki_baseline.csv
Compare-Object $last $this -Property Name, ENROLLEE_SUPPLIES_SUBJECT, WriteACL
```

### 10.2 Annual Third-Party Audit

Commission an annual PKI audit by an external party. The audit should:

- Re-run the Locksmith and Certify audits independently
- Sample-issue test certificates to validate PKINIT flow
- Validate HSM backing of the CA private key
- Review the CA database for anomalies (issuance spikes, unexpected requestors)
- Validate that all DCs are in Full Enforce mode
- Review template lifecycle (any templates created without change management?)

### 10.3 Tabletop Exercises

Run an annual tabletop that exercises the full AD CS kill chain:

1. **Purple team exercise**: Red team executes ESC1 → PKINIT → secretsdump; blue team validates that each step triggers the expected detection rule.
2. **Brown bag**: Walk the SOC through this guide. Ensure each analyst can interpret Events 4886, 4887, 4768, 4662, and 5136 in the AD CS context.
3. **Lessons learned**: After any real incident or false positive, update the detection rules in this guide and the remediation matrix in Section 7.

---

## 11. References

### 11.1 Microsoft Documentation

- **KB5005413: Machine Account protection** -- August 2021. https://support.microsoft.com/en-us/topic/kb5005413
- **KB5014754: KB5014754: Certificate-based authentication changes** -- May 2022. https://support.microsoft.com/en-us/topic/kb5014754
- **Strong Certificate Mapping November 2023 Full Enforce** -- https://learn.microsoft.com/en-us/windows-server/security/certificates-and-active-directory/
- **AD CS Event IDs reference** -- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l-event-ids
- **Microsoft Defender for Identity alerts** -- https://learn.microsoft.com/en-us/defender-for-identity/understanding-alerts

### 11.2 Open Source Detection Tools

- **Locksmith** -- Trimarc. https://github.com/TrimarcJake/Locksmith
- **ADCSToolkit** -- zynnnnnn. https://github.com/zynnnnnn/ADCSToolkit
- **PSPKI / PSPKIAudit** -- https://www.powershellgallery.com/packages/PSPKI
- **Certify** (audit-mode defender usage) -- GhostPack. https://github.com/GhostPack/Certify

### 11.3 Research Papers and Talks

- **Certified Pre-Owned: Abusing Active Directory Certificate Services** -- Schroeder, Christensen, Creel. SpecterOps. June 2021. https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf
- **Shadow Credentials: Abusing Key Trust Account Mapping for Takeover** -- Elad Shamir. September 2021. https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8221a53766ac
- **Certifried: Active Directory Domain Privilege Escalation (CVE-2022-26923)** -- Yair Mizrahi. May 2022. https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4
- **Topotam PetitPotam original disclosure** -- July 2021. https://github.com/topotam/PetitPotam
- **AD CS Attack Theory Update (ESC9-ESC15)** -- Oliver Lyak. Certipy documentation. https://github.com/ly4k/Certipy

### 11.4 Threat Intelligence Reports

- **Black Basta ransomware analysis** -- Mandiant M-Trends 2023, Microsoft DCU reports
- **Akira ransomware analysis** -- Sophos X-Ops 2023-2024, Microsoft Threat Intelligence
- **Cuba ransomware analysis** -- Mandiant, Cisco Talos 2023
- **Royal / BlackSuit ransomware analysis** -- CISA / FBI / MS-ISAC joint advisory AA23-061A

### 11.5 Detection Engineering References

- **Sigma rule repository** -- https://github.com/SigmaHQ/sigma
- **Microsoft Sentinel detection rules** -- https://github.com/Azure/Azure-Sentinel
- **Splunk Security Essentials** -- https://github.com/splunk/securityessentials

---

## 12. Conclusion

AD CS detection and hardening is a tractable problem. The fifteen ESC classes are well-documented; the detection telemetry exists in every Windows DC and CA; the open-source detection tooling (Locksmith, ADCSToolkit, PSPKIAudit) is mature; and the patch baseline is well-published.

The gap is operational discipline. Most enterprises have:

- CAs that are not forwarding their Security log to the SIEM
- Templates that were never audited after initial deployment
- Web Enrollment left enabled because no one remembers why it was enabled
- DCs in Audit mode rather than Full Enforce mode because someone was worried about breaking legacy applications

The single most impactful step is to move DCs to Full Enforce mode and forward the CA Security log. With those two changes, 80% of the ESC1-ESC15 attack surface becomes detectable and most of it becomes non-exploitable.

For authorized operators, the same detection landscape provides a clear contract: work within the engagement window, document every issued certificate, clean up every modification, and hand off artifacts at the end. The result is an engagement that validates detection coverage and produces evidence the client's SOC can use to improve their posture.

---

## Appendix A -- Quick Detection Reference Card

```
AD CS DETECTION QUICK REFERENCE
================================

HIGH-SIGNAL EVENTS (Tier 1)
  4662 with attribute 5cb47ed8-8b67-4947-b91e-5f6e0bbe2c1a
    -> Shadow Credentials write (pywhisker / Whisker)
  4624 ANONYMOUS LOGON type 3 from DC
    -> PetitPotam coercion
  4768 Pre_Authentication_Type=16 for privileged account
    -> PKINIT TGT abuse
  4887 SAN != Requester
    -> ESC1 / ESC6 certificate issuance

MEDIUM-SIGNAL EVENTS (Tier 2)
  5136 on CN=Certificate Templates
    -> ESC4 / ESC5 template modification
  5136 on dNSHostName of computer object
    -> Certifried
  IIS W3SVC logs to /certsrv/ from non-CryptoAPI agent
    -> ESC8 relay
  5136 / 4657 on CertSvc registry
    -> ESC6 / ESC11 CA flag modification

LOW-SIGNAL EVENTS (Tier 3)
  4886 volume spike
    -> Enumeration or batch enrollment
  PKINIT-presented serial not in CA DB
    -> Golden Certificate

CORRELATION WINDOWS
  PetitPotam (4624 anon) -> PKINIT (4768) -> secretsdump
    Expected window: < 5 minutes in real attacks
  Shadow Creds write (4662) -> PKINIT (4768)
    Expected window: 10 min to 24 hours
  ESC1 cert issue (4887) -> PKINIT (4768) -> secretsdump
    Expected window: < 2 minutes

RESPONSE
  1. Isolate the source host
  2. Revoke the issued certificate (if known)
  3. Reset the target account password
  4. Audit the CA database for related issuances
  5. Hunt for msDS-KeyCredentialLink across the domain
```

## Appendix B -- Hardening Quick Reference Card

```
AD CS HARDENING QUICK REFERENCE
================================

FOREST-ROOT
  [ ] StrongCertificateBindingEnforcement = 2 on all DCs
  [ ] KB5014754 in Full Enforce (post-Nov 2023)
  [ ] CVE-2024-49019 (ESC15) patch applied
  [ ] MS-EFSRPC blocked at DC host firewall (defense in depth)

CA SERVER
  [ ] EDITF_ATTRIBUTESUBJECTALTSSUBJECT2 removed
  [ ] IF_ENFORCEENCRYPTICSPREQUEST set on CA InterfaceFlags (ESC11)
  [ ] ManageCA / ManageCertificates restricted to Domain Admins
  [ ] Web Enrollment disabled OR EPA enforced
  [ ] SMB signing required
  [ ] CA private key on HSM
  [ ] CA database audit filter = 127 (maximum)
  [ ] CA Security log forwarded to SIEM

TEMPLATES (per template)
  [ ] ENROLLEE_SUPPLIES_SUBJECT removed from Client Auth templates
  [ ] AnyPurpose / no-EKU templates restricted to admins
  [ ] PKINIT KDC EKU template restricted to Domain Controllers
  [ ] Enrollment Agent EKU restricted to scoped service accounts
  [ ] Manager approval required on high-priv templates
  [ ] Write ACLs removed from non-admin principals
  [ ] lua application EKU removed

QUARTERLY AUDIT
  [ ] Locksmith report run and compared to prior quarter
  [ ] Certify audit-mode report run
  [ ] PKI Health Matrix baseline diff
  [ ] Any new templates reviewed for ESC exposure
```
