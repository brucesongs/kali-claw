# DNS Enumeration and Reconnaissance Guide

## Introduction

DNS enumeration is the foundational phase of any network assessment. DNS infrastructure maps hostnames to IP addresses and reveals the organization's digital footprint: web servers, mail servers, VPN gateways, development environments, and internal services. A single misconfigured nameserver that allows zone transfers can expose the entire infrastructure in seconds, saving attackers days of manual reconnaissance. This guide covers comprehensive DNS reconnaissance using dnsrecon, dnsenum, fierce, and dnswalk, progressing from passive lookups through active enumeration to full zone transfer exploitation.

Understanding DNS enumeration is essential because DNS records are often the first -- and sometimes only -- publicly visible information about an organization's internal infrastructure. Subdomain names frequently follow predictable patterns (dev, staging, vpn, mail, intranet, jenkins, gitlab) that reveal both the purpose and technology stack of each service. Combined with reverse DNS lookups on discovered IP ranges, a skilled operator can build a complete network map before sending a single port scan packet.

---

## Zone Transfer Exploitation

Zone transfers (AXFR) are the DNS protocol's mechanism for replicating zone data between primary and secondary nameservers. When a server allows AXFR from unauthorized sources, it returns the complete zone file containing every record.

```bash
# Attempt zone transfer against all nameservers
dnsrecon -d target.com -t axfr

# Manual attempt against a specific nameserver
dig axfr target.com @ns1.target.com

# Using dnsenum (includes zone transfer in full scan)
dnsenum --enum target.com
```

A successful zone transfer returns all A, AAAA, MX, CNAME, TXT, SRV, and NS records. TXT records often contain SPF policies, domain verification tokens, and sometimes accidentally exposed API keys or configuration data.

---

## Record Type Enumeration

When zone transfers fail, systematically query individual record types to build a partial picture.

```bash
# Enumerate standard record types
dig target.com A +noall +answer
dig target.com MX +noall +answer
dig target.com TXT +noall +answer
dig target.com NS +noall +answer
dig target.com SOA +noall +answer

# Service discovery through SRV records
dig _sip._tcp.target.com SRV +noall +answer
dig _ldap._tcp.target.com SRV +noall +answer
dig _kerberos._tcp.target.com SRV +noall +answer
dig _xmpp-server._tcp.target.com SRV +noall +answer
```

SRV records are particularly valuable in enterprise environments because Active Directory, SIP, LDAP, and XMPP services register SRV records by convention.

---

## Subdomain Brute Force

When passive enumeration is insufficient, brute force discovery tests thousands of potential subdomain names against the target's DNS servers.

```bash
# dnsrecon brute force with default wordlist
dnsrecon -d target.com -t brte -D /usr/share/wordlists/dnsrecon/namelist.txt

# fierce subdomain discovery with recursive traversal
fierce --domain target.com --subbrute

# dnsenum with custom wordlist and threading
dnsenum --enum target.com -f custom_wordlist.txt --threads 10
```

Effective brute force requires quality wordlists. Combine general purpose lists (SecLists, dnsrecon namelist) with organization-specific patterns derived from discovered subdomains. If `web01.target.com` exists, test `web02`, `web03`, `dev01`, `stg01`, and similar patterns.

---

## Reverse DNS Lookups

Reverse DNS maps IP addresses back to hostnames, revealing services that may not be discoverable through forward queries.

```bash
# dnsrecon reverse lookup on a range
dnsrecon -t rvl -r 192.168.1.0/24

# Manual reverse lookup
dig -x 192.168.1.1 +noall +answer

# Sweep an entire subnet
for i in $(seq 1 254); do
  result=$(dig +short -x 192.168.1.$i)
  [ -n "$result" ] && echo "192.168.1.$i -> $result"
done
```

Reverse lookups on IP ranges adjacent to discovered hosts often reveal internal naming conventions and additional infrastructure not visible through forward enumeration.

---

## DNS Zone Auditing with dnswalk

dnswalk verifies DNS zone configuration and identifies misconfigurations that could indicate security weaknesses.

```bash
# Full zone audit
dnswalk target.com.

# Output flags:
# GOOD  - delegation is correct
# BAD   - delegation mismatch
# WARN  - potential issue (missing glue records, CNAME pointing to CNAME)
# FAIL  - serious error (lame delegation, unreachable nameserver)
```

dnswalk checks delegation consistency, identifies lame delegations, detects missing glue records, and reports CNAME chains. These misconfigurations indicate operational issues that often correlate with broader security weaknesses.

---

## Bing and Search Engine Enumeration

dnsenum includes Google/Bing enumeration that discovers subdomains indexed by search engines, providing passive discovery that generates no direct queries against the target's DNS infrastructure.

```bash
# dnsenum includes search engine enumeration by default
dnsenum --enum target.com

# The tool queries search engines for "site:target.com"
# and extracts unique subdomains from results
```

This passive technique complements active brute force by finding subdomains referenced in search engine caches, linked documents, and historical archives that may no longer resolve but indicate past infrastructure.

---

## Operational Considerations

- Always test zone transfers against every nameserver individually -- organizations frequently have inconsistent configurations across primary and secondary servers
- Combine multiple tools (dnsrecon, dnsenum, fierce) to maximize coverage, as each tool uses different enumeration techniques and may find different results
- Record all discovered IP addresses and perform reverse lookups on adjacent ranges
- Cross-reference DNS findings with SSL certificate transparency logs (crt.sh) and passive DNS databases for additional subdomain discovery
- Preserve enumeration results for use in subsequent assessment phases (port scanning, vulnerability assessment)

---

## References

- dnsrecon GitHub: https://github.com/darkoperator/dnsrecon
- dnsenum documentation: https://github.com/fwaeytens/dnsenum
- fierce GitHub: https://github.com/mschwager/fierce
- dnswalk: https://sourceforge.net/projects/dnswalk/
- SecLists DNS wordlists: https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
- HackTricks DNS Pentesting: https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns
- RFC 1035 (DNS protocol specification): https://www.rfc-editor.org/rfc/rfc1035
