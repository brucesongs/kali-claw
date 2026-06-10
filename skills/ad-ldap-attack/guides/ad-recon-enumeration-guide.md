# AD Domain Reconnaissance and Enumeration Guide

## Introduction and Objective

Active Directory reconnaissance and enumeration is the foundational phase of any internal network penetration test targeting enterprise environments. Before executing credential attacks or lateral movement, the operator must thoroughly map the target domain infrastructure, identify attack surfaces, and prioritize targets based on the discovered information. This guide covers the complete reconnaissance and enumeration workflow using Kali Linux tools against Active Directory environments.

The primary objectives of AD reconnaissance are:

1. Identify the target domain name, domain controllers, and forest topology
2. Enumerate domain users, groups, computers, and organizational units
3. Discover Service Principal Names (SPNs) for Kerberos attack targeting
4. Map trust relationships between domains and forests
5. Identify security misconfigurations, weak permissions, and attack paths
6. Collect BloodHound data for graph-based attack path analysis

Understanding the AD environment thoroughly before attacking dramatically increases the success rate of subsequent credential attacks and lateral movement while reducing detection risk through targeted, informed operations.

This guide progresses from passive discovery through active enumeration to comprehensive data collection, following the methodology used in professional red team engagements. Each technique includes specific tool commands, expected output interpretation, and OPSEC considerations for stealth-conscious operations.

## Phase 1: Passive and Semi-Passive Discovery

### NetBIOS Discovery with nbtscan

NetBIOS scanning is a fast, low-noise technique for discovering Windows hosts and their domain membership without sending authentication traffic. The nbtscan tool queries the NetBIOS Name Service (UDP port 137) to retrieve host names, domain names, and logged-on user information.

```bash
# Scan the target subnet for NetBIOS responses
nbtscan 10.10.0.0/24

# Expected output format:
# IP address     NetBIOS Name    Server    User           MAC address
# ------------------------------------------------------------------------------
# 10.10.0.1      DC01            <server>  CORP           00:50:56:aa:bb:cc
# 10.10.0.5      FILESRV         <server>  CORP           00:50:56:aa:bb:cd
```

Key indicators to look for in nbtscan output:

- Domain names appearing in the "User" column reveal the AD domain (e.g., CORP)
- Hosts with names like DC01, DC02 typically indicate domain controllers
- The `<1C>` suffix in NetBIOS names indicates domain controller role
- The `<1B>` suffix indicates the domain master browser

### DNS Service Record Enumeration

Active Directory publishes service locations via DNS SRV records. Querying these records reveals domain controllers, global catalogs, and Kerberos KDCs without directly touching the target systems.

```bash
# Locate domain controllers via LDAP SRV record
nslookup -type=srv _ldap._tcp.dc._msdcs.corp.local

# Locate Kerberos KDC
nslookup -type=srv _kerberos._tcp.corp.local

# Locate global catalog servers
nslookup -type=srv _gc._tcp.corp.local

# Locate KDC for the specific domain
nslookup -type=srv _kerberos._tcp.dc._msdcs.corp.local
```

These queries return the hostnames and ports of domain infrastructure servers. Document all discovered DCs, their IP addresses, and roles for targeting in subsequent phases.

### Nmap Service Discovery

Targeted port scanning confirms which services are running on identified domain controllers and domain-joined systems. Focus on AD-critical ports:

```bash
# Targeted scan of domain controller
nmap -sV -sC -p 53,88,135,139,389,445,636,3268,3389 10.10.0.1

# Quick discovery of AD-related services across the subnet
nmap -sV --top-ports 20 10.10.0.0/24 --open
```

Critical ports and their significance:

| Port | Service | Significance |
|------|---------|-------------|
| 53 | DNS | May allow zone transfer for full domain enumeration |
| 88 | Kerberos | Authentication service, target for Kerberos attacks |
| 135 | RPC | Endpoint mapper for DCOM and RPC services |
| 389 | LDAP | Directory queries for full AD enumeration |
| 445 | SMB | File sharing, authentication, lateral movement |
| 636 | LDAPS | Encrypted LDAP queries |
| 3268 | Global Catalog | Forest-wide search capabilities |

## Phase 2: Active SMB and RPC Enumeration

### enum4linux and enum4linux-ng

Enum4linux automates SMB and NetBIOS enumeration using a combination of null sessions, RPC queries, and SMB protocol interactions. It extracts users, groups, shares, password policies, and OS information from target systems.

```bash
# Full enumeration against a domain controller
enum4linux -a 10.10.0.1

# With credentials for deeper enumeration
enum4linux -u 'corp\svc_user' -p 'Password123!' -a 10.10.0.1

# Enumerate only users
enum4linux -U 10.10.0.1

# Enumerate only shares
enum4linux -S 10.10.0.1
```

For a modern alternative with JSON output support:

```bash
# Full enum with JSON output
enum4linux-ng -A 10.10.0.1 -oJ enum_results.json

# Enumerate with authentication
enum4linux-ng -u 'corp\svc_user' -p 'Password123!' -A 10.10.0.1
```

### RPC Enumeration with rpcclient

Rpcclient provides granular access to Windows RPC interfaces for targeted enumeration. It excels at extracting detailed user properties, group memberships, and privilege information.

```bash
# Connect with null session
rpcclient -U "" 10.10.0.1

# Key commands within rpcclient session:
rpcclient $> enumdomusers        # List all domain users
rpcclient $> enumdomgroups       # List all domain groups
rpcclient $> querydominfo        # Domain information
rpcclient $> enumprivs           # Available privileges
rpcclient $> queryuser 0x1f4     # Query specific user by RID
rpcclient $> querygroupmem 0x200 # Query group members
rpcclient $> lookupnames admin   # Resolve name to SID
rpcclient $> lookupsids S-1-5-21-XXXX-XXXX-XXXX-500  # Resolve SID to name
```

The `enumdomusers` output reveals user RIDs, which can be enumerated sequentially to discover all accounts including disabled and hidden ones.

## Phase 3: LDAP Enumeration

### Direct LDAP Queries with ldapsearch

LDAP queries provide the most detailed and structured view of Active Directory objects. Any authenticated domain user can query the directory, making this a powerful enumeration technique that requires minimal privileges.

```bash
# Discover naming contexts (starting point)
ldapsearch -x -H ldap://10.10.0.1 -b "" -s base namingcontexts

# Enumerate all users with key attributes
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" "(objectClass=user)" \
  sAMAccountName displayName mail memberOf

# Find all service accounts (users with SPNs)
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# Find AS-REP Roastable users (pre-auth disabled)
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName

# Enumerate domain trust relationships
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" "(objectClass=trustedDomain)" \
  cn trustDirection trustType flatName

# Find accounts with constrained delegation
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" \
  "(&(objectClass=user)(msds-allowedtodelegateto=*))" \
  sAMAccountName msds-allowedtodelegateto

# Enumerate all computers and their OS
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\svc_ldap" -w 'Password123!' \
  -b "dc=corp,dc=local" "(objectClass=computer)" \
  cn operatingSystem dnshostname
```

### Comprehensive Domain Dump with ldapdomaindump

For rapid, comprehensive enumeration, ldapdomaindump exports the entire AD structure into structured formats for offline analysis.

```bash
# Full domain dump with HTML, JSON, and grepable output
ldapdomaindump -u 'CORP\svc_ldap' -p 'Password123!' 10.10.0.1

# Dump to a specific output directory
ldapdomaindump -u 'CORP\svc_ldap' -p 'Password123!' -o /tmp/ad_dump 10.10.0.1

# Use LDAPS for encrypted transport
ldapdomaindump -u 'CORP\svc_ldap' -p 'Password123!' -ldaps 10.10.0.1
```

The resulting HTML files provide a browsable view of all domain objects, while JSON files enable automated parsing and analysis.

### Advanced Enumeration with ldeep

Ldeep provides advanced LDAP operations including ACL extraction, delegation enumeration, and GPO analysis that go beyond basic ldapsearch capabilities.

```bash
# Full domain enumeration
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 all

# Extract ACLs for attack path analysis
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 acl

# Enumerate delegation configurations
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 delegations

# Enumerate GPOs
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 gpos

# Enumerate domain trusts
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 trusts

# Search for specific patterns
ldeep ldap -u svc_ldap -p 'Password123!' -d corp.local -s ldap://10.10.0.1 \
  search "(sAMAccountName=admin*)" sAMAccountName mail memberOf
```

## Phase 4: BloodHound Graph Analysis

### Data Collection with bloodhound-python

BloodHound is the most powerful AD attack path analysis tool available. It collects relationship data from Active Directory and visualizes hidden attack paths that are nearly impossible to identify through manual enumeration alone. The Python ingestor runs on Kali Linux without requiring .NET.

```bash
# Full data collection (all methods)
bloodhound-python -u 'svc_ldap' -p 'Password123!' -ns 10.10.0.1 -d corp.local -c All

# DC-only collection (no computer connections, stealthier)
bloodhound-python -u 'svc_ldap' -p 'Password123!' -ns 10.10.0.1 -d corp.local -c DCOnly

# Targeted collection methods
bloodhound-python -u 'svc_ldap' -p 'Password123!' -ns 10.10.0.1 -d corp.local \
  -c Group,LocalAdmin,Session,Trusts,ACL

# Collection with verbose output for debugging
bloodhound-python -u 'svc_ldap' -p 'Password123!' -ns 10.10.0.1 -d corp.local \
  -c All -v
```

### Analyzing BloodHound Data

After collecting data, import the JSON files into the BloodHound GUI and focus on these key analysis queries:

1. **Shortest Path to Domain Admins**: Identify the quickest escalation path from your current position to Domain Admin privileges.
2. **Find Principals with DCSync Rights**: Locate accounts with Replication privileges that can perform DCSync attacks.
3. **Kerberoastable Users**: Find service accounts with SPNs that can be targeted for Kerberoasting.
4. **AS-REP Roastable Users**: Identify accounts with pre-authentication disabled.
5. **Unconstrained Delegation**: Find computers where any user's ticket can be forwarded.
6. **Constrained Delegation**: Identify services that can impersonate users to other services.
7. **Owned Nodes**: Mark compromised accounts and trace paths from owned to high-value targets.
8. **Shortest Path to High Value Targets**: Map paths to specific critical systems identified during enumeration.

BloodHound's pre-built queries and custom Cypher queries enable deep analysis of AD relationship graphs, making it indispensable for professional AD assessments.

## Hands-on Practice Exercise

### Exercise: Complete AD Domain Enumeration

**Scenario**: You have gained access to a workstation on the internal network (IP: 10.10.0.100). Your objective is to enumerate the Active Directory domain and identify all attack surfaces.

**Step 1**: Discover the domain name and domain controllers.

```bash
nbtscan 10.10.0.0/24
nslookup -type=srv _ldap._tcp.dc._msdcs.corp.local
```

**Step 2**: Perform SMB enumeration.

```bash
enum4linux-ng -A 10.10.0.1 -oJ initial_enum.json
rpcclient -U "" 10.10.0.1 -c "enumdomusers; enumdomgroups"
```

**Step 3**: Perform LDAP enumeration with valid credentials.

```bash
ldapsearch -x -H ldap://10.10.0.1 -D "CORP\\guest" -w '' -b "dc=corp,dc=local" "(objectClass=user)" sAMAccountName
ldapdomaindump -u 'CORP\guest' -p '' -o /tmp/ad_dump 10.10.0.1
```

**Step 4**: Collect BloodHound data.

```bash
bloodhound-python -u 'guest' -p '' -ns 10.10.0.1 -d corp.local -c DCOnly
```

**Step 5**: Analyze collected data to identify:
- Total user count and high-value targets (Domain Admins, Enterprise Admins)
- Service accounts with SPNs (Kerberoast targets)
- Accounts with pre-auth disabled (AS-REP Roast targets)
- Trust relationships and cross-domain paths
- Delegation configurations and ACL misconfigurations

Document all findings in a structured format for the next phase of the engagement.

## References and Resources

- [BloodHound Documentation](https://bloodhound.readthedocs.io/) -- Official BloodHound usage guide and Cypher query reference
- [Impacket Documentation](https://www.secureauth.com/labs/open-source-tools/impacket) -- Impacket toolkit reference for all AD attack tools
- [Active Directory Security Wiki](https://adsecurity.org/) -- Comprehensive AD security research and attack technique reference by Sean Metcalf
- [MITRE ATT&CK - Domain Account Discovery (T1087.002)](https://attack.mitre.org/techniques/T1087/002/) -- MITRE framework reference for AD enumeration techniques
- [Harmj0y's Blog](https://blog.harmj0y.net/) -- seminal research on AD attacks, Kerberos exploitation, and PowerView usage
- [LDAP Query Basics for Pentesters](https://www.ired.team/) -- Red Team enumeration reference with practical LDAP query examples
- [SANS AD Attack and Defense](https://www.sans.org/white-papers/) -- SANS Institute research papers on Active Directory attack methodology
- [Microsoft LDAP Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-active-directory-logical-model) -- Official Microsoft documentation for understanding AD logical models and LDAP structure
